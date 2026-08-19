"""A forward proxy that reaches exactly one thing: the symbol server.

The analysis worker parses untrusted memory images, so it has no route out.
Volatility needs one anyway — it resolves a Windows image's kernel symbols by
fetching the matching PDB from Microsoft — and without that every windows.*
plugin fails and triage returns nothing.

This closes that gap without handing the worker the internet:

* only hosts on the allowlist are reachable; everything else is refused;
* plain http is re-issued upstream over https, because Volatility asks for
  http://msdl.microsoft.com/... and a PDB fetched in the clear is a binary an
  on-path attacker can choose, parsed in the container holding the evidence;
* CONNECT is tunnelled only for allowlisted hosts, and only to 443;
* every decision is logged.

Deliberately small: it is a security control, so it should be readable in one
sitting. No caching, no auth, no rewriting beyond the scheme upgrade.
"""
from __future__ import annotations

import logging
import os
import select
import socket
import ssl
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LISTEN_HOST = os.environ.get("SYMBOLPROXY_HOST", "0.0.0.0")  # noqa: S104 - container-internal
LISTEN_PORT = int(os.environ.get("SYMBOLPROXY_PORT", "3128"))
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get(
        "SYMBOLPROXY_ALLOWED_HOSTS",
        "msdl.microsoft.com,download.volatilityfoundation.org",
    ).split(",")
    if h.strip()
}
UPSTREAM_TIMEOUT_S = float(os.environ.get("SYMBOLPROXY_TIMEOUT_S", "120"))
# Set only when this host itself reaches the internet through a proxy (corporate
# egress). Deliberately NOT read from the ambient HTTP_PROXY: the worker points
# HTTP_PROXY at this service, and inheriting it would make the proxy chain back
# through itself.
UPSTREAM_PROXY = os.environ.get("SYMBOLPROXY_UPSTREAM_PROXY", "").strip()
MAX_BYTES = int(os.environ.get("SYMBOLPROXY_MAX_BYTES", str(512 * 1024 * 1024)))
CHUNK = 64 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("symbolproxy")


def host_allowed(host: str) -> bool:
    """Exact host match only. No suffix matching: 'evil-msdl.microsoft.com.attacker
    .example' must not pass, and neither should a subdomain we did not name."""
    return (host or "").split(":")[0].lower() in ALLOWED_HOSTS


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "memtriage-symbolproxy"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        logger.info("%s %s", self.client_address[0], fmt % args)

    def _refuse(self, host: str, reason: str = "not on the allowlist") -> None:
        logger.warning("DENY %s %s (%s)", self.command, host, reason)
        body = (
            f"memtriage-symbolproxy refused {host!r}: {reason}.\n"
            f"Allowed: {', '.join(sorted(ALLOWED_HOSTS))}\n"
        ).encode()
        self.send_response(403)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- plain HTTP: upgraded to HTTPS upstream ----------------------------

    def _proxy_http(self) -> None:
        parts = urlsplit(self.path)
        if not parts.netloc:
            self._refuse(self.path, "not an absolute-URI proxy request")
            return
        host = parts.hostname or ""
        if not host_allowed(host):
            self._refuse(host)
            return

        # Scheme upgrade. The port is dropped deliberately: we only ever talk to
        # the allowlisted host over standard TLS.
        target = f"https://{host}{parts.path or '/'}"
        if parts.query:
            target += f"?{parts.query}"
        logger.info("ALLOW %s %s -> %s", self.command, self.path, target)

        request = urllib.request.Request(target, method=self.command)
        request.add_header("User-Agent", self.headers.get("User-Agent", "memtriage"))
        proxies = ({"http": UPSTREAM_PROXY, "https": UPSTREAM_PROXY}
                   if UPSTREAM_PROXY else {})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies))
        try:
            with opener.open(request, timeout=UPSTREAM_TIMEOUT_S) as upstream:
                if not host_allowed(urlsplit(upstream.geturl()).hostname or ""):
                    self._refuse(upstream.geturl(), "redirected off the allowlist")
                    return
                self._relay(upstream)
        except urllib.error.HTTPError as exc:
            logger.warning("upstream %s for %s", exc.code, target)
            body = f"upstream returned {exc.code}\n".encode()
            self.send_response(exc.code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            logger.error("upstream failure for %s: %s", target, type(exc).__name__)
            self.send_error(502, "upstream fetch failed")

    def _relay(self, upstream) -> None:
        length = upstream.headers.get("Content-Length")
        if length and int(length) > MAX_BYTES:
            self._refuse(upstream.geturl(), "response exceeds the size cap")
            return
        self.send_response(200)
        for header in ("Content-Type", "Content-Length", "Last-Modified", "ETag"):
            value = upstream.headers.get(header)
            if value:
                self.send_header(header, value)
        if not length:
            self.send_header("Connection", "close")
        self.end_headers()

        sent = 0
        while True:
            chunk = upstream.read(CHUNK)
            if not chunk:
                break
            sent += len(chunk)
            if sent > MAX_BYTES:
                logger.error("aborting %s: exceeded the size cap", upstream.geturl())
                break
            self.wfile.write(chunk)

    # -- CONNECT: tunnelled, allowlisted, 443 only -------------------------

    def do_CONNECT(self) -> None:  # noqa: N802 - the method name is the protocol verb
        host, _, port = self.path.partition(":")
        if not host_allowed(host):
            self._refuse(host)
            return
        if port not in ("", "443"):
            self._refuse(host, f"port {port} is not permitted")
            return

        logger.info("ALLOW CONNECT %s:443", host)
        try:
            upstream = socket.create_connection((host, 443), timeout=UPSTREAM_TIMEOUT_S)
        except OSError as exc:
            logger.error("CONNECT to %s failed: %s", host, type(exc).__name__)
            self.send_error(502, "upstream connect failed")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        self._tunnel(self.connection, upstream)

    @staticmethod
    def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, UPSTREAM_TIMEOUT_S)
                if errored or not readable:
                    break
                for source in readable:
                    data = source.recv(CHUNK)
                    if not data:
                        return
                    (upstream if source is client else client).sendall(data)
        except OSError:
            pass
        finally:
            upstream.close()

    do_GET = _proxy_http
    do_HEAD = _proxy_http


def main() -> int:
    if not ALLOWED_HOSTS:
        logger.error("SYMBOLPROXY_ALLOWED_HOSTS is empty; refusing to start an open proxy")
        return 2
    logger.info("listening on %s:%s; allowlist: %s",
                LISTEN_HOST, LISTEN_PORT, ", ".join(sorted(ALLOWED_HOSTS)))
    logger.info("plain http is re-issued upstream over https (TLS %s)", ssl.OPENSSL_VERSION)
    if UPSTREAM_PROXY:
        logger.info("chaining upstream through %s", UPSTREAM_PROXY)
    ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

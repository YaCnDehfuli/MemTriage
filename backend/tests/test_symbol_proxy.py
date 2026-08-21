"""The symbol proxy's allowlist.

This is the one component that can reach outside the isolated worker, so the
host check is the whole security boundary and gets tested as such.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

PROXY = Path(__file__).resolve().parents[2] / "deploy" / "symbolproxy" / "proxy.py"


def _load(monkeypatch, allowed: str):
    """Import proxy.py fresh, since the allowlist is read at import time."""
    monkeypatch.setenv("SYMBOLPROXY_ALLOWED_HOSTS", allowed)
    spec = importlib.util.spec_from_file_location("symbolproxy_under_test", PROXY)
    module = importlib.util.module_from_spec(spec)
    sys.modules["symbolproxy_under_test"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def proxy(monkeypatch):
    return _load(monkeypatch, "msdl.microsoft.com,download.volatilityfoundation.org")


def test_allowlisted_hosts_pass(proxy):
    assert proxy.host_allowed("msdl.microsoft.com")
    assert proxy.host_allowed("download.volatilityfoundation.org")


def test_the_port_is_ignored_when_matching(proxy):
    assert proxy.host_allowed("msdl.microsoft.com:443")


def test_matching_is_case_insensitive(proxy):
    assert proxy.host_allowed("MSDL.Microsoft.COM")


def test_microsoft_blob_redirect_hosts_are_allowed(proxy):
    assert proxy.host_allowed("vsblobprodscussu5shard42.blob.core.windows.net")
    assert proxy.host_allowed("VSBlobProd.blob.core.windows.net:443")


@pytest.mark.parametrize(
    "host",
    [
        "evil.example",
        "",
        "localhost",
        "169.254.169.254",                       # cloud metadata
        "msdl.microsoft.com.attacker.example",   # suffix confusion
        "notmsdl.microsoft.com",                 # prefix confusion
        "sub.msdl.microsoft.com",                # unlisted subdomain
        "blob.core.windows.net",                 # bare suffix is not a host
        "blob.core.windows.net.attacker.example",
        "evil.blob.core.windows.net.attacker.example",
        "attacker.example#msdl.microsoft.com",
        "msdl.microsoft.com.",                   # trailing dot
    ],
)
def test_everything_else_is_refused(proxy, host):
    assert proxy.host_allowed(host) is False


def test_suffix_matching_is_not_used(proxy):
    """A suffix rule would let any domain ending in the allowed one through."""
    assert proxy.host_allowed("microsoft.com") is False
    assert proxy.host_allowed("x-msdl.microsoft.com") is False


def test_an_empty_allowlist_refuses_to_start(monkeypatch):
    module = _load(monkeypatch, "")
    assert set() == module.ALLOWED_HOSTS
    assert module.main() == 2, "an empty allowlist must not start an open proxy"


def test_allowlist_is_parsed_and_normalized(monkeypatch):
    module = _load(monkeypatch, " A.example , b.example ,, ")
    assert {"a.example", "b.example"} == module.ALLOWED_HOSTS


def test_upstream_proxy_is_not_inherited_from_the_ambient_environment(monkeypatch):
    """Reading HTTP_PROXY here would make the proxy chain back through itself."""
    monkeypatch.setenv("HTTP_PROXY", "http://symbolproxy:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://symbolproxy:3128")
    monkeypatch.delenv("SYMBOLPROXY_UPSTREAM_PROXY", raising=False)
    module = _load(monkeypatch, "msdl.microsoft.com")
    assert module.UPSTREAM_PROXY == ""


def test_upstream_proxy_is_used_when_explicitly_set(monkeypatch):
    monkeypatch.setenv("SYMBOLPROXY_UPSTREAM_PROXY", "http://corp-proxy:8080")
    module = _load(monkeypatch, "msdl.microsoft.com")
    assert module.UPSTREAM_PROXY == "http://corp-proxy:8080"


def test_defaults_cover_the_symbol_server(monkeypatch):
    monkeypatch.delenv("SYMBOLPROXY_ALLOWED_HOSTS", raising=False)
    spec = importlib.util.spec_from_file_location("symbolproxy_defaults", PROXY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert "msdl.microsoft.com" in module.ALLOWED_HOSTS

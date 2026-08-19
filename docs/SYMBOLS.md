# Volatility symbols for an offline worker

## Why this exists

Volatility 3 does not ship Windows kernel symbols. For each image it reads the
kernel's PDB GUID, downloads the matching `ntkrnlmp.pdb` from
`msdl.microsoft.com`, converts it to an ISF file, and caches it.

MemTriage's worker parses untrusted memory images, so it runs on an
`internal`-only Docker network with **no outbound access**. That download can
never succeed there, and the failure is not partial:

```
WARNING volatility3.framework.symbols.windows.pdbutil: Symbol file could not be
        downloaded from remote server
Unable to validate the plugin requirements: ['plugins.Modules.kernel.symbol_table_name']
```

`kernel.symbol_table_name` is required by **every** `windows.*` plugin. Without
it `pslist`, `malfind`, `netscan` and the rest all exit non-zero, the feature row
comes back empty, and the process inventory is empty — which on screen is
indistinguishable from a clean image. MemTriage now says so explicitly (the
triage record carries an `extraction` block, and `/api/health/deep` reports a
`volatility symbols` check), but the fix is to supply the symbols.

## Required VolMemLyzer version

The `components/volmemlyzer` submodule is pinned to a commit that carries the
symbol-directory support (`VolRunner(symbol_dirs=..., offline=...)`). Older
checkouts cannot forward those arguments to Volatility; MemTriage detects that,
logs it once, and carries on without them — so triage still runs, it just cannot
resolve symbols on a host with no outbound access.

After cloning, make sure the submodule is at the pinned commit:

```bash
git submodule update --init --recursive
```

## How the shipped stack solves this

The worker still has **no direct egress**. A `symbolproxy` service sits on both
networks and forwards to the symbol server *only*:

```
worker (internal only)  --HTTP_PROXY-->  symbolproxy  --https-->  msdl.microsoft.com
                                              |
                                              +--> anything else: 403, logged
```

`deploy/symbolproxy/proxy.py` is ~180 lines of standard library, because it is a
security control and should be readable in one sitting. It:

- allows only the hosts in `SYMBOLPROXY_ALLOWED_HOSTS` (exact match — no suffix
  matching, so `msdl.microsoft.com.attacker.example` is refused);
- **re-issues plain http upstream over https.** Volatility requests
  `http://msdl.microsoft.com/...`, and a PDB fetched in the clear is a binary an
  on-path attacker can choose, parsed in the container holding your evidence;
- tunnels `CONNECT` only for allowlisted hosts, and only to port 443;
- refuses redirects that leave the allowlist, caps response size, and logs every
  ALLOW and DENY;
- refuses to start at all if the allowlist is empty.

That is enough for Volatility to resolve symbols for any image automatically. The
pre-fetched `symbols/` directory below still takes precedence and remains the
right answer for genuinely air-gapped work.

To go fully offline, drop the `symbolproxy` service, remove the worker's
`HTTP_PROXY`/`HTTPS_PROXY`, and set `MEMTRIAGE_VOL_OFFLINE=true`.

## Producing them (air-gapped, or to pin a specific build)

On a machine **with** internet access and the same Volatility version the worker
uses:

```bash
python -m venv /tmp/volsym && /tmp/volsym/bin/pip install volatility3==2.28.0

# Any Windows plugin will trigger the download; windows.info is the cheapest.
/tmp/volsym/bin/vol -f /path/to/your/image.raw windows.info
```

Volatility writes the converted ISF under its symbol path, keyed by PDB name and
GUID:

```
~/.cache/volatility3/symbols/windows/ntkrnlmp.pdb/<GUID>-<age>.json.xz
```

Copy that `symbols/` tree into this repository's `symbols/` directory:

```bash
cp -r ~/.cache/volatility3/symbols/. /path/to/MemTriage/symbols/
```

The result should look like:

```
symbols/
  README.md
  windows/
    ntkrnlmp.pdb/
      9074FC2B82ED2B7E1CB3366B64BE62F9-1.json.xz
```

Then `docker compose -f deploy/docker-compose.yml up` — the directory is mounted
read-only at `/symbols`, and the worker passes it to Volatility as
`-s /symbols --offline`.

Symbols are per kernel build, so an image from a different host or patch level
needs its own. Repeat the step above for each; they accumulate in the directory.

### Bulk packs

The Volatility Foundation publishes prebuilt symbol packs:

```bash
curl -LO https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip -d symbols/
```

These are large and still may not contain a specific build, so the per-image
step above is the reliable route.

## Checking it worked

```bash
docker compose -f deploy/docker-compose.yml exec api \
  python -m memtriage.preflight
```

The `volatility symbols` line should read `ok` and name `/symbols`. After a
triage run, `triage.json` carries:

```json
"extraction": {
  "plugins_attempted": 62,
  "plugins_failed": 0,
  "degraded": false,
  "severity": "ok"
}
```

If plugins still fail, Volatility's own error for each one is written beside the
cached artifact as `<name>.json.stderr.txt` under the investigation's
`volmemlyzer/` directory.

## Why not just give the worker the internet

You can (`networks: [internal, edge]`, `MEMTRIAGE_VOL_OFFLINE=false`), and for a
throwaway lab it is fine. What you give up:

- **The fetch is cleartext.** Volatility's symbol server URL is
  `http://msdl.microsoft.com/download/symbols`, so without the proxy's scheme
  upgrade you are parsing a binary delivered over unauthenticated HTTP.
- **It becomes an exfiltration path.** The worker feeds attacker-controlled bytes
  to Capstone and pefile; those are the most plausible RCE surface in the stack.
  Contained today: no route out, dropped capabilities, no privilege escalation.
- **It discloses metadata.** The PDB GUID tells Microsoft, and anyone on path,
  which Windows build you are analysing and when.

The proxy keeps automatic symbols while removing all three, for one small
service. That is why it is the default.

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

## Producing them

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

## If you would rather allow egress

Give the worker a network with outbound access and leave `symbols/` empty:

```yaml
# deploy/docker-compose.yml
worker:
  networks: [internal, edge]
  environment:
    MEMTRIAGE_VOL_OFFLINE: "false"
```

This trades the isolation the worker was built for — it parses attacker-supplied
input — against convenience. Prefer pre-fetched symbols.

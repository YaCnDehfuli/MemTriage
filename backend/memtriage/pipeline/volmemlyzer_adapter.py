"""Adapter over the VolMemLyzer3 package (wrapped, never forked).

Triage builds on VolMemLyzer's two stable surfaces:

* ``Pipeline.run_extract_features`` — the ~520-feature aggregate IoC row (a flat
  ``plugin.metric`` dict), which is the dashboard's backbone.
* ``Pipeline.run_plugin_raw`` — raw Volatility ``-r=json`` records for the
  plugins we need per-object detail from: ``pslist`` (the process/PID inventory),
  ``malfind`` (injections), ``netscan`` (connections).

The Volatility-touching calls are thin; the record→view transforms are pure
functions so they can be unit-tested without Volatility or a memory image.
Nothing here is executed against the dump — records are parsed as data only.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .attack import map_techniques

# Names with no analyzable user VADs — excluded from VADViT selection.
_NON_ANALYZABLE = {"system", "registry", "memory compression", "secure system"}
_NON_ANALYZABLE_PIDS = {0, 4}


def _is_available() -> bool:
    try:
        import volmemlyzer  # noqa: F401
        return True
    except Exception:
        return False


def _g(rec: dict, *keys: str, default: Any = None) -> Any:
    """First present key among candidates (Volatility field-name drift guard)."""
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return default


def _load_records(path: str | None) -> list[dict]:
    """Load a Volatility -r=json artifact as a list of record dicts."""
    if not path or not Path(path).exists():
        return []
    try:
        data = json.loads(Path(path).read_text())
    except (ValueError, OSError):
        return []
    if isinstance(data, dict):
        data = data.get("rows") or data.get("records") or []
    return [r for r in data if isinstance(r, dict)]


# --------------------------------------------------------------------------
# Pure transforms (unit-testable with canned Volatility-shaped records)
# --------------------------------------------------------------------------

def injections_from_malfind(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        out.append({
            "pid": _g(r, "PID", "Pid", "pid", default=None),
            "process": _g(r, "Process", "ImageFileName", "process", default=""),
            "start": _g(r, "Start VPN", "Start", "VPN Start", "start", default=None),
            "protection": _g(r, "Protection", "protection", default=""),
            "vad_tag": _g(r, "Tag", "VadTag", "vad_tag", default=""),
            "hexdump": _g(r, "Hexdump", "hex_dump", default=""),
            "disasm": _g(r, "Disasm", "disasm", default=""),
        })
    return out


def network_from_netscan(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        out.append({
            "pid": _g(r, "PID", "Pid", "pid", default=None),
            "proto": _g(r, "Proto", "Protocol", "proto", default=""),
            "local_addr": _g(r, "LocalAddr", "Local Address", "local_addr", default=""),
            "local_port": _g(r, "LocalPort", "Local Port", "local_port", default=None),
            "foreign_addr": _g(r, "ForeignAddr", "Foreign Address", "foreign_addr", default=""),
            "foreign_port": _g(r, "ForeignPort", "Foreign Port", "foreign_port", default=None),
            "state": _g(r, "State", "state", default=""),
            "owner": _g(r, "Owner", "owner", default=""),
        })
    return out


def inventory_from_pslist(records: list[dict], suspicious_pids: set[int]) -> list[dict]:
    """Full process/PID inventory the analyst selects from."""
    out = []
    for r in records:
        pid = _g(r, "PID", "Pid", "pid")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        name = str(_g(r, "ImageFileName", "Name", "Process", "name", default="") or "")
        ppid_raw = _g(r, "PPID", "Ppid", "ppid")
        try:
            ppid = int(ppid_raw)
        except (TypeError, ValueError):
            ppid = None
        analyzable = pid not in _NON_ANALYZABLE_PIDS and name.strip().lower() not in _NON_ANALYZABLE
        flags = ["suspicious"] if pid in suspicious_pids else []
        out.append({
            "pid": pid,
            "name": name,
            "ppid": ppid,
            "risk": "suspicious" if pid in suspicious_pids else None,
            "flags": flags,
            "analyzable": analyzable,
        })
    out.sort(key=lambda p: p["pid"])
    return out


def dashboard_from(features_flat: dict, injections: list[dict],
                   network: list[dict], suspicious_processes: list[dict]) -> dict:
    dashboard = {
        "features": features_flat or {},
        "suspicious_processes": suspicious_processes,
        "injections": injections,
        "network": network,
        "persistence": [],  # richer persistence parsing lands in a later pass
        "attack_techniques": [],
    }
    dashboard["attack_techniques"] = map_techniques(dashboard)
    return dashboard


# --------------------------------------------------------------------------
# Volatility-touching orchestration (thin)
# --------------------------------------------------------------------------

def build_pipeline(vol_path: str | None, timeout_s: int):
    """Construct a VolMemLyzer Pipeline (lazy import; worker image only)."""
    from volmemlyzer.pipeline import Pipeline
    from volmemlyzer.plugins import build_registry
    from volmemlyzer.runner import VolRunner

    runner = VolRunner(vol_path=vol_path, default_timeout_s=timeout_s, default_renderer="json")
    return Pipeline(runner, build_registry())


def run_triage(image_path: str, artifacts_dir: str, *, vol_path: str | None,
               timeout_s: int) -> dict:
    """Run VolMemLyzer on one snapshot and return the triage view.

    Returns a dict with keys: features, dashboard, processes, vol_version.
    """
    from dataclasses import asdict

    from volmemlyzer.utilities import _flatten_dict

    pipe = build_pipeline(vol_path, timeout_s)

    # Aggregate IoC features (dashboard backbone).
    row = pipe.run_extract_features(image_path=image_path, artifacts_dir=artifacts_dir,
                                    use_cache=True)
    features_flat = _flatten_dict(asdict(row).get("features") or {})
    vol_version = getattr(row, "vol_version", None)

    # Per-object detail from raw plugin JSON.
    res = pipe.run_plugin_raw(image_path=image_path,
                              enable={"pslist", "malfind", "netscan"},
                              outdir=artifacts_dir, use_cache=True)
    plugins = res.artifacts.get("plugins", {}) if res and res.artifacts else {}
    injections = injections_from_malfind(_load_records(plugins.get("malfind")))
    network = network_from_netscan(_load_records(plugins.get("netscan")))
    pslist = _load_records(plugins.get("pslist"))

    suspicious_pids = {i["pid"] for i in injections if i.get("pid") is not None}
    inventory = inventory_from_pslist(pslist, suspicious_pids)
    suspicious_processes = [p for p in inventory if p["pid"] in suspicious_pids]

    return {
        "features": features_flat,
        "dashboard": dashboard_from(features_flat, injections, network, suspicious_processes),
        "processes": inventory,
        "vol_version": vol_version,
    }

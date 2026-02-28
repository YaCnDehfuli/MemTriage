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

from ..scoring import CONTEXT_PLUGINS, normalize_plugin_key, score_records
from .attack import map_techniques

# Names with no analyzable user VADs — excluded from VADViT selection.
_NON_ANALYZABLE = {"system", "registry", "memory compression", "secure system"}
_NON_ANALYZABLE_PIDS = {0, 4}

# Plugins the triage extractor caches raw JSON for, so the scoring engine can
# re-score from cache on every tuning change without re-running Volatility. Uses
# VolMemLyzer/Volatility plugin names (mapped to context keys on load).
TRIAGE_PLUGINS: tuple[str, ...] = (
    "pslist", "pstree", "psscan", "psxview", "cmdline", "malfind", "ldrmodules",
    "handles", "privileges", "threads", "netscan", "svcscan", "scheduled_tasks",
    "registry.userassist", "registry.hivelist", "registry.hivescan",
)


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


def _apply_scoring(dashboard: dict, processes: list[dict], scoring: dict) -> None:
    """Fold a scoring-engine result into the dashboard + process inventory.

    Pure transform, shared by first-pass triage and live re-scoring: it enriches
    each inventory row with the engine's per-PID verdict and rebuilds the
    engine-derived dashboard sections (scored objects, ATT&CK, risk summary).
    """
    process_risk = scoring["process_risk"]
    for item in processes:
        pr = process_risk.get(item["pid"])
        if pr:
            item["risk"] = pr["risk"]
            item["flags"] = list(pr["flags"])
            item["score"] = pr["score"]
            item["confidence"] = pr["confidence"]
            item["techniques"] = list(pr["techniques"])
        else:
            # Clear stale enrichment when a PID drops out on re-score.
            item["risk"] = None
            item["flags"] = []
            for k in ("score", "confidence", "techniques"):
                item.pop(k, None)

    scored = scoring["scored_objects"]
    name_by_pid = {p["pid"]: p.get("name", "") for p in processes}
    dashboard["scored_objects"] = scored
    dashboard["risk_summary"] = scoring["risk_summary"]
    dashboard["attack_techniques"] = scoring["attack_techniques"]
    dashboard["profile"] = scoring["profile"]
    dashboard["suspicious_processes"] = [
        {
            "pid": o["pid"],
            "name": name_by_pid.get(o["pid"], ""),
            "risk": o["risk"],
            "score": o["score"],
            "confidence": o["confidence"],
            "flags": [c["rule_id"] for c in o["contributions"]],
            "techniques": o["techniques"],
        }
        for o in scored if o["object_type"] == "process" and o["pid"] is not None
    ]
    dashboard["persistence"] = [o for o in scored if o["object_type"] == "persistence"]


def assemble_triage(features_flat: dict, records: dict[str, list[dict]], *,
                    vol_version: Any = None, profile: dict | None = None) -> dict:
    """Shape parsed plugin records into the triage view (pure, engine-scored).

    This is the whole non-Volatility half of triage — unit-testable with canned
    records and reused by ``/rescore``.
    """
    scoring = score_records(records, profile)
    injections = injections_from_malfind(records.get("malfind") or [])
    network = network_from_netscan(records.get("netscan") or [])
    inventory = inventory_from_pslist(records.get("pslist") or [],
                                      set(scoring["process_risk"].keys()))
    dashboard: dict = {
        "features": features_flat or {},
        "injections": injections,
        "network": network,
        "suspicious_processes": [],
        "persistence": [],
        "scored_objects": [],
        "risk_summary": {},
        "attack_techniques": [],
        "profile": {},
    }
    _apply_scoring(dashboard, inventory, scoring)
    return {
        "features": features_flat or {},
        "dashboard": dashboard,
        "processes": inventory,
        "profile": scoring["profile"],
        "vol_version": vol_version,
    }


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


def _registry_has(pipe, name: str) -> bool:
    try:
        return bool(pipe.registry.has(name))
    except Exception:  # noqa: BLE001 - be permissive about registry surface drift
        return True


def collect_records(pipe, image_path: str, artifacts_dir: str) -> tuple[dict, dict]:
    """Run the triage plugin set once and return (records_by_key, manifest).

    ``records_by_key`` is keyed by canonical context key; ``manifest`` maps that
    key to the cached artifact's filename so ``/rescore`` can reload it without
    touching Volatility.
    """
    requested = {p for p in TRIAGE_PLUGINS if _registry_has(pipe, p)}
    res = pipe.run_plugin_raw(image_path=image_path, enable=requested,
                              outdir=artifacts_dir, use_cache=True)
    plugins = res.artifacts.get("plugins", {}) if res and res.artifacts else {}

    records: dict[str, list[dict]] = {}
    manifest: dict[str, str] = {}
    for vml_name, path in plugins.items():
        key = normalize_plugin_key(vml_name)
        records[key] = _load_records(path)
        if path:
            manifest[key] = Path(path).name
    return records, manifest


def run_triage(image_path: str, artifacts_dir: str, *, vol_path: str | None,
               timeout_s: int, profile: dict | None = None) -> dict:
    """Run VolMemLyzer on one snapshot and return the scored triage view.

    Returns keys: features, dashboard, processes, profile, manifest, vol_version.
    """
    from dataclasses import asdict

    from volmemlyzer.utilities import _flatten_dict

    pipe = build_pipeline(vol_path, timeout_s)

    # Aggregate IoC features (dashboard backbone).
    row = pipe.run_extract_features(image_path=image_path, artifacts_dir=artifacts_dir,
                                    use_cache=True)
    features_flat = _flatten_dict(asdict(row).get("features") or {})
    vol_version = getattr(row, "vol_version", None)

    # Cache the full triage plugin set once; the scoring engine works off it.
    records, manifest = collect_records(pipe, image_path, artifacts_dir)

    view = assemble_triage(features_flat, records, vol_version=vol_version, profile=profile)
    view["manifest"] = manifest
    return view


def rescore_from_records(records: dict[str, list[dict]], features_flat: dict | None,
                         *, vol_version: Any = None, profile: dict | None = None) -> dict:
    """Re-score cached records under a new profile (no Volatility). Used by /rescore."""
    return assemble_triage(features_flat or {}, records, vol_version=vol_version,
                           profile=profile)

"""Adapter over the VolMemLyzer3 package (wrapped, never forked).

Triage builds on VolMemLyzer's two stable surfaces:

* ``Pipeline.run_extract_features`` — one selected-plugin pass that produces the
  aggregate IoC row and canonical raw JSON used by the dashboard, process
  inventory and scoring engine.
* ``Pipeline.run_plugin_raw`` — the manual suite's analyst-selected batch path.

The Volatility-touching calls are thin; the record→view transforms are pure
functions so they can be unit-tested without Volatility or a memory image.
Nothing here is executed against the dump — records are parsed as data only.
"""
from __future__ import annotations

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any

from ..scoring import normalize_plugin_key, score_records
from .attack import map_techniques

logger = logging.getLogger(__name__)

_CACHE_FAILURE_RE = re.compile(
    r"Traceback|ERROR|Exception|No suitable address space|failed", re.IGNORECASE
)

# Names with no analyzable user VADs — excluded from VADViT selection.
_NON_ANALYZABLE = {"system", "registry", "memory compression", "secure system"}

# Phase 1 is a fast, wide read of the image, not an adjudication. The rules are
# deliberately simple and hand-tuned, and they run over statistically-derived
# aggregate features plus a handful of per-object plugin outputs. Everything they
# surface is a lead. This statement travels with the data — into triage.json,
# every /rescore response, the consolidated result and the export — so it cannot
# be separated from the findings it qualifies.
TRIAGE_DISCLAIMER = {
    "headline": "Clues for review, not conclusions.",
    "summary": (
        "Phase 1 extracts structured, statistically significant features from the "
        "image and applies simple, tuned rules to them. Everything it surfaces is "
        "a lead for an analyst to confirm or dismiss — not an established fact, a "
        "detection, or an attribution."
    ),
    "points": [
        "The rules are basic and hand-tuned. They encode well-known indicators, "
        "not learned behaviour, and they carry no notion of ground truth.",
        "Scores and risk bands are relative ranking aids under the current "
        "profile. Re-tuning changes them; it does not change the underlying image.",
        "A high score means 'look here first'. A low score is not a clean bill of "
        "health — an absent indicator is only an indicator that did not fire.",
        "ATT&CK techniques are alignment for triage. They describe what an "
        "artifact resembles, not what was confirmed to have happened.",
        "Every value here is derived from an untrusted memory image and can be "
        "influenced by whatever produced that image.",
    ],
    "intent": (
        "The aim is a fast multi-view of one memory image, with the structured "
        "features an analyst needs to decide where to spend manual effort."
    ),
}
_NON_ANALYZABLE_PIDS = {0, 4}

# VolMemLyzer quick analysis (no --deep): structure walks only. Pool scanners
# stay out of this set so Light/Custom-quick cannot launch them by accident.
QUICK_TRIAGE_PLUGINS: tuple[str, ...] = (
    "info", "pslist", "pstree", "malfind", "scheduled_tasks",
    "registry.userassist", "registry.hivelist",
)

# A genuinely quick preset: linked-list/metadata reads only. Whole-image scans
# and internally repeated scans are deliberately absent, so choosing Light has
# a predictable material effect rather than being a cosmetic label.
LIGHT_TRIAGE_PLUGINS: tuple[str, ...] = (
    "info", "pslist", "pstree", "cmdline", "malfind", "privileges",
    "scheduled_tasks", "registry.userassist", "registry.hivelist",
)

# The full rule-engine evidence set. This includes whole-image scanners and the
# expensive psxview cross-check, so the UI labels it as potentially long-running.
DEEP_TRIAGE_PLUGINS: tuple[str, ...] = (
    "info", "pslist", "pstree", "psscan", "psxview", "cmdline", "malfind", "ldrmodules",
    "handles", "privileges", "threads", "netscan", "svcscan", "scheduled_tasks",
    "registry.userassist", "registry.hivelist", "registry.hivescan",
)

# Backwards-compatible name used by scoring/tests and older clients.
TRIAGE_PLUGINS = DEEP_TRIAGE_PLUGINS


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


def _plugin_records(records: dict[str, list[dict]], *names: str) -> list[dict]:
    for name in names:
        rows = records.get(name)
        if rows:
            return rows
    return []


def _overview_contribution(rule_id: str, title: str, weight: int, evidence: str,
                           technique_id: str, technique_name: str, tactic: str) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "weight": int(weight),
        "evidence": evidence,
        "mitre": {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
        },
        "severity": 3,
        "confidence": 0.75,
    }


def overview_scoring_from_records(records: dict[str, list[dict]], *,
                                  plugins: list[str] | tuple[str, ...] | None = None) -> dict:
    """Score cached plugin records with VolMemLyzer's bounded OverviewAnalysis.

    This is the live-triage path: 30-point ordinal evidence, not MemTriage's
    unbounded catalog sum. Pool-scan plugins are consulted only when they were
    actually selected for the run.
    """
    from volmemlyzer.analysis import OverviewAnalysis

    eng = OverviewAnalysis(min_risk="low")
    selected = {normalize_plugin_key(p) for p in (plugins or ())}
    objects: list[dict] = []
    process_risk: dict[int, dict] = {}

    def _remember_pid(obj: dict) -> None:
        pid = obj.get("pid")
        if pid is None:
            return
        pid = int(pid)
        previous = process_risk.get(pid)
        if previous is None or obj["score"] > previous["score"]:
            process_risk[pid] = {
                "risk": obj["risk"],
                "score": obj["score"],
                "confidence": obj["confidence"],
                "techniques": list(obj["techniques"]),
                "flags": [c["rule_id"] for c in obj["contributions"]],
            }

    census = eng._build_census(
        _plugin_records(records, "pslist"),
        _plugin_records(records, "pstree"),
    )
    psscan = _plugin_records(records, "psscan") if "psscan" in selected else None
    psxview = _plugin_records(records, "psxview") if "psxview" in selected else None
    captured_process_rows: list[tuple] = []
    _orig_score_map = OverviewAnalysis._score_map

    @classmethod
    def _capturing_score_map(cls, row, index):
        captured_process_rows.append(row)
        return _orig_score_map.__func__(cls, row, index)

    OverviewAnalysis._score_map = _capturing_score_map
    try:
        _summary, _susp = eng._score_processes(census, psscan, psxview)
    finally:
        OverviewAnalysis._score_map = _orig_score_map
    for pid, name, _ppid, score, flag_str, rationale in captured_process_rows:
        if int(score) < eng._threshold("process"):
            continue
        evidence = str(rationale).strip()
        flags = [flag.strip() for flag in str(flag_str).split(",") if flag.strip()]
        contribs = [_overview_contribution(
            (flags[0] if flags else "process"), "Process evidence", int(score),
            evidence or "—", "T1036", "Masquerading", "Defense Evasion",
        )]
        obj = {
            "object_type": "process",
            "key": str(pid),
            "label": f"{name} ({pid})",
            "pid": int(pid),
            "score": int(score),
            "score_max": OverviewAnalysis.MAX_RISK_SCORE,
            "risk": eng._risk_from_score(int(score)),
            "confidence": 0.75,
            "tactics": ["Defense Evasion"],
            "techniques": ["T1036"],
            "contributions": contribs,
        }
        objects.append(obj)
        _remember_pid(obj)

    # Presence-only would revive cache for an analysis the user excluded.
    if "malfind" in selected:
        regions: dict[tuple, dict] = {}
        for row in _plugin_records(records, "malfind"):
            score, flags, rationale = eng._score_injections(row)
            if score < eng._threshold("malfind"):
                continue
            pid = row.get("PID")
            start_vpn = row.get("Start VPN")
            region_key = (pid, start_vpn)
            finding = {
                "object_type": "injection",
                "key": f"{pid}:{start_vpn}",
                "label": f"{row.get('Process') or 'process'} ({pid})",
                "pid": int(pid) if pid is not None else None,
                "score": int(score),
                "score_max": OverviewAnalysis.MAX_RISK_SCORE,
                "risk": eng._risk_from_score(int(score)),
                "confidence": 0.75,
                "tactics": ["Defense Evasion"],
                "techniques": ["T1055"],
                "contributions": [_overview_contribution(
                    (str(flags).split(",")[0].strip() or "malfind"),
                    "Injection evidence", int(score), str(rationale),
                    "T1055", "Process Injection", "Defense Evasion",
                )],
            }
            previous = regions.get(region_key)
            if previous is None or finding["score"] > previous["score"]:
                regions[region_key] = finding
        for obj in regions.values():
            objects.append(obj)
            _remember_pid(obj)

    if "scheduled_tasks" in selected:
        for task in _plugin_records(records, "scheduled_tasks"):
            score, why = eng._score_scheduled_task(task)
            if score < eng._threshold("scheduled_tasks"):
                continue
            name = str(task.get("Task Name") or "")
            act = str(task.get("Action") or "")
            args = str(task.get("Action Arguments") or "")
            evidence = " | ".join([w for w in why if w]) if isinstance(why, list) else str(why)
            key = f"task:{(name.strip().lower() or act.strip().lower() or 'unknown')}"
            objects.append({
                "object_type": "persistence",
                "key": key,
                "label": f"{name} :: {act} {args}".strip(),
                "pid": None,
                "score": int(score),
                "score_max": OverviewAnalysis.MAX_RISK_SCORE,
                "risk": eng._risk_from_score(int(score)),
                "confidence": 0.75,
                "tactics": ["Persistence"],
                "techniques": ["T1053.005"],
                "contributions": [_overview_contribution(
                    "scheduled_task", "Scheduled task evidence", int(score),
                    evidence or "—", "T1053.005", "Scheduled Task/Job", "Persistence",
                )],
            })

    if "userassist" in selected:
        ua_tree = _plugin_records(records, "userassist", "registry.userassist")
        ua_vals = [r for r in eng._flatten_UA_with_context(ua_tree) if r.get("Type") == "Value"]
        for row in ua_vals:
            name = str(row.get("Name") or "")
            if name.startswith("UEME_") and not eng._seems_pathlike(name):
                continue
            score, why = eng._score_userassist_name(name)
            if score < eng._threshold("userassist") or not eng._seems_pathlike(name):
                continue
            evidence = " | ".join([w for w in why if w]) if isinstance(why, list) else str(why)
            objects.append({
                "object_type": "persistence",
                "key": f"ua:{name.strip().lower()}",
                "label": name,
                "pid": None,
                "score": int(score),
                "score_max": OverviewAnalysis.MAX_RISK_SCORE,
                "risk": eng._risk_from_score(int(score)),
                "confidence": 0.75,
                "tactics": ["Execution"],
                "techniques": ["T1204"],
                "contributions": [_overview_contribution(
                    "userassist", "UserAssist evidence", int(score),
                    evidence or "—", "T1204", "User Execution", "Execution",
                )],
            })

    objects.sort(key=lambda o: (o["score"], o["confidence"]), reverse=True)

    bands = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    types: dict[str, int] = {}
    attack: dict[str, dict] = {}
    for obj in objects:
        bands[obj["risk"]] = bands.get(obj["risk"], 0) + 1
        types[obj["object_type"]] = types.get(obj["object_type"], 0) + 1
        for contrib in obj["contributions"]:
            tid = contrib["mitre"]["technique_id"]
            entry = attack.setdefault(tid, {
                "technique_id": tid,
                "name": contrib["mitre"]["technique_name"],
                "tactic": contrib["mitre"]["tactic"],
                "object_count": 0,
                "evidence": contrib["evidence"],
            })
            entry["object_count"] += 1

    from ..scoring.profile import TuningProfile
    return {
        "scored_objects": objects,
        "attack_techniques": sorted(attack.values(), key=lambda t: t["object_count"], reverse=True),
        "risk_summary": {"total": len(objects), "by_risk": bands, "by_type": types},
        "profile": TuningProfile.from_preset("balanced").to_dict(),
        "process_risk": process_risk,
    }


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
        "disclaimer": TRIAGE_DISCLAIMER,
    }
    _apply_scoring(dashboard, inventory, scoring)
    dashboard["disclaimer"] = TRIAGE_DISCLAIMER
    return {
        "features": features_flat or {},
        "dashboard": dashboard,
        "processes": inventory,
        "profile": scoring["profile"],
        "vol_version": vol_version,
        "disclaimer": TRIAGE_DISCLAIMER,
    }


# --------------------------------------------------------------------------
# Volatility-touching orchestration (thin)
# --------------------------------------------------------------------------

def usable_symbol_dirs(candidates: list[str] | None, *, allow_empty: bool = False) -> list[str]:
    """Keep symbol directories that exist, optionally including empty caches.

    Passing a path that is not there is worse than passing nothing: Volatility
    accepts it silently and the run still fails, one layer further from the
    cause. Online symbol caches are deliberately allowed to start empty because
    Volatility populates them through the configured symbol proxy.
    """
    usable = []
    for candidate in candidates or []:
        # Path("") is the current directory, which would hand Volatility the
        # working directory as a symbol path.
        if not str(candidate).strip():
            continue
        path = Path(candidate)
        try:
            if allow_empty and not path.exists():
                path.mkdir(parents=True, exist_ok=True)
            if path.is_dir() and (allow_empty or any(path.iterdir())):
                usable.append(str(path))
        except OSError:
            continue
    return usable


def _valid_empty_json_cache(
    artifacts_dir: str, plugin_name: str, image_name: str,
) -> dict[str, Any] | None:
    """Recognize a valid no-findings JSON artifact the wrapped cache rejects.

    Volatility plugins commonly and legitimately return ``[]``. The pinned
    component historically treated that as a cache miss, which made empty,
    expensive scans rerun forever. Only that narrow case is relaxed here;
    corrupt/zero-byte output and artifacts with critical stderr remain misses.
    """
    path = Path(artifacts_dir) / f"{image_name}_{plugin_name}.json"
    if not valid_json_cache_artifact(path):
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        empty = payload == [] or (
            isinstance(payload, dict)
            and (payload.get("rows") == [] or payload.get("records") == [])
        )
        if not empty:
            return None
    except (OSError, ValueError):
        return None
    return {"ok": True, "path": str(path), "format": "json"}


def valid_json_cache_artifact(path: str | Path) -> bool:
    """Validate canonical JSON and its stderr using wrapped-cache semantics."""
    candidate = Path(path)
    try:
        if not candidate.is_file() or candidate.stat().st_size == 0:
            return False
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        valid_shape = isinstance(payload, list) or (
            isinstance(payload, dict)
            and (
                isinstance(payload.get("rows"), list)
                or isinstance(payload.get("records"), list)
            )
        )
        if not valid_shape:
            return False
        stderr_path = Path(f"{candidate}.stderr.txt")
        if stderr_path.is_file():
            stderr = stderr_path.read_text(encoding="utf-8", errors="replace")
            if _CACHE_FAILURE_RE.search(stderr):
                return False
    except (OSError, ValueError):
        return False
    return True


def build_pipeline(vol_path: str | None, timeout_s: int, *,
                   symbol_dirs: list[str] | None = None, offline: bool = False,
                   volmemlyzer_src: str | Path | None = None):
    """Construct a VolMemLyzer Pipeline (lazy import; worker image only).

    ``symbol_dirs``/``offline`` are only forwarded when the installed VolMemLyzer
    accepts them, so an older checkout of the submodule still works — it just
    cannot run offline.
    """
    import inspect

    if volmemlyzer_src:
        src = Path(volmemlyzer_src).expanduser().resolve()
        if not src.is_dir():
            raise FileNotFoundError(f"VolMemLyzer source directory not found: {src}")
        if str(src) not in sys.path:
            sys.path.insert(0, str(src))

    from volmemlyzer.pipeline import Pipeline
    from volmemlyzer.plugins import build_registry
    from volmemlyzer.runner import VolRunner

    class ObservableVolRunner(VolRunner):
        def run_plugin(self, memory_dump_path, plugin_specs, *args, **kwargs):
            # Pipeline's "Running" line is emitted when work enters the executor,
            # which may be hours before a worker slot is available. This line is
            # deliberately inside the worker call and therefore means executing.
            logging.getLogger("volmemlyzer.runner").info(
                "Executing plugin %s", plugin_specs.name
            )
            result = super().run_plugin(
                memory_dump_path, plugin_specs, *args, **kwargs,
            )
            # VolRunner writes a stderr companion when Volatility emits output,
            # but historically left an older companion in place after a clean
            # retry.  That stale ERROR/TIMEOUT text would make the fresh JSON
            # fail strict cache validation forever.
            if getattr(result, "rc", None) == 0 and not getattr(
                result, "stderr_path", None,
            ):
                output_path = getattr(result, "output_path", None)
                if output_path:
                    try:
                        Path(f"{output_path}.stderr.txt").unlink(missing_ok=True)
                    except OSError as exc:
                        logger.warning(
                            "Could not remove stale stderr for %s: %s",
                            plugin_specs.name, exc,
                        )
            return result

    class CacheAwarePipeline(Pipeline):
        def check_cache(
            self, artifacts_dir, plugin_name, image_name, *,
            require_format=None, strict=False,
        ):
            hit = super().check_cache(
                artifacts_dir, plugin_name, image_name,
                require_format=require_format, strict=strict,
            )
            if hit.get("ok") or require_format != "json":
                return hit
            return (
                _valid_empty_json_cache(artifacts_dir, plugin_name, image_name)
                or hit
            )

    kwargs: dict = {"vol_path": vol_path, "default_timeout_s": timeout_s,
                    "default_renderer": "json"}
    supported = set(inspect.signature(VolRunner.__init__).parameters)
    dirs = usable_symbol_dirs(symbol_dirs, allow_empty=True)
    if "symbol_dirs" in supported and dirs:
        kwargs["symbol_dirs"] = dirs
    if "offline" in supported and offline:
        kwargs["offline"] = True
    if dirs and "symbol_dirs" not in supported:
        logger.warning(
            "Symbol directories are configured (%s) but the installed VolMemLyzer "
            "cannot forward them to Volatility. Update the component, or Windows "
            "plugins will fail on a host without outbound access.", ", ".join(dirs))

    return CacheAwarePipeline(ObservableVolRunner(**kwargs), build_registry())


def _registry_has(pipe, name: str) -> bool:
    try:
        return bool(pipe.registry.has(name))
    except Exception:
        return True


def collect_records(
    pipe, image_path: str, artifacts_dir: str, *,
    plugins: list[str] | tuple[str, ...] | None = None,
    concurrency: int = 1, use_cache: bool = True,
) -> tuple[dict, dict, dict]:
    """Run the triage plugin set once and return (records, manifest, failures).

    ``records`` is keyed by canonical context key; ``manifest`` maps that key to
    the cached artifact's filename so ``/rescore`` can reload it without touching
    Volatility; ``failures`` names the plugins that produced nothing usable.
    """
    requested = {p for p in (plugins or TRIAGE_PLUGINS) if _registry_has(pipe, p)}
    res = pipe.run_plugin_raw(image_path=image_path, enable=requested,
                              outdir=artifacts_dir, concurrency=concurrency,
                              use_cache=use_cache)
    artifacts = (res.artifacts if res and res.artifacts else {}) or {}
    plugins = artifacts.get("plugins", {}) or {}
    failures = dict(artifacts.get("failed_plugins", {}) or {})

    records: dict[str, list[dict]] = {}
    manifest: dict[str, str] = {}
    for vml_name, path in plugins.items():
        key = normalize_plugin_key(vml_name)
        parsed = _load_records(path)
        records[key] = parsed
        if path and Path(path).exists():
            manifest[key] = Path(path).name
        if not parsed and key not in failures and not _has_content(path):
            failures[key] = "produced no parseable records"
    return records, manifest, failures


def records_from_feature_cache(
    pipe, image_path: str, artifacts_dir: str, plugins: list[str] | tuple[str, ...],
    failures: dict[str, str] | None = None,
) -> tuple[dict, dict, dict]:
    """Load the JSON files the feature pass just produced without a second run.

    ``run_extract_features`` already invokes every selected plugin and writes its
    canonical JSON. Asking ``run_plugin_raw`` for the same set immediately after
    that only adds a second cache traversal (and used to make the live log look as
    though triage ran everything twice).
    """
    failed = dict(failures or {})
    image_name = Path(image_path).name
    records: dict[str, list[dict]] = {}
    manifest: dict[str, str] = {}
    for name in plugins:
        if not _registry_has(pipe, name):
            continue
        spec, _extractor = pipe.registry.get(name)
        path = Path(artifacts_dir) / f"{image_name}_{spec.name}.json"
        key = normalize_plugin_key(name)
        parsed = _load_records(str(path))
        records[key] = parsed
        valid_json = valid_json_cache_artifact(path)
        if valid_json and name not in failed:
            manifest[key] = path.name
        elif name not in failed:
            failed[name] = "produced no parseable JSON output"
    return records, manifest, failed


def _has_content(path) -> bool:
    try:
        return bool(path) and Path(path).is_file() and Path(path).stat().st_size > 0
    except OSError:
        return False


def extraction_health(attempted: int, failures: dict) -> dict:
    """Summarize whether this run can be trusted, and say why when it cannot.

    Distinguishing "this image has no such artifacts" from "Volatility could not
    run" is the whole point: both otherwise arrive as an empty dashboard.
    """
    failed = len(failures)
    health = {
        "plugins_attempted": attempted,
        "plugins_failed": failed,
        "failed_plugins": dict(sorted(failures.items())),
        "degraded": failed > 0,
        "severity": "ok",
        "message": "",
    }
    if not failed:
        health["message"] = "All requested Volatility plugins produced output."
        return health

    blob = " ".join(str(v) for v in failures.values()).lower()
    symbols = "symbol" in blob
    widespread = attempted and failed >= max(3, int(attempted * 0.5))
    if widespread or symbols:
        health["severity"] = "critical"
        health["message"] = (
            f"{failed} of {attempted} Volatility plugins produced no output"
            + (", and the failures point at an unresolvable kernel symbol table. "
               "Windows plugins cannot run without one, so this triage is empty "
               "rather than clean. Supply pre-fetched symbols (see docs/SYMBOLS.md)."
               if symbols else
               ". Most plugins failing usually means one shared cause; check a "
               ".stderr.txt file beside the cached artifacts.")
        )
    else:
        health["severity"] = "warning"
        health["message"] = (
            f"{failed} of {attempted} Volatility plugins produced no output, so some "
            "features and evidence are missing from this triage."
        )
    return health


def _flatten_dict(d: dict, prefix: str = "", sep: str = ".") -> dict:
    """Flatten nested feature dicts. Local copy so mocked tests need no submodule."""
    flat: dict = {}
    for key, value in (d or {}).items():
        next_key = f"{prefix}{sep}{key}" if prefix else key
        if isinstance(value, dict):
            flat.update(_flatten_dict(value, next_key, sep))
        else:
            flat[next_key] = value
    return flat


def run_triage(image_path: str, artifacts_dir: str, *, vol_path: str | None,
               timeout_s: int, profile: dict | None = None,
               symbol_dirs: list[str] | None = None, offline: bool = False,
               volmemlyzer_src: str | Path | None = None,
               plugins: list[str] | tuple[str, ...] | None = None,
               concurrency: int = 4, use_cache: bool = True) -> dict:
    """Run VolMemLyzer on one snapshot and return the scored triage view.

    Returns keys: features, dashboard, processes, profile, manifest, vol_version,
    extraction.
    """
    from dataclasses import asdict

    pipe = build_pipeline(vol_path, timeout_s, symbol_dirs=symbol_dirs, offline=offline,
                          volmemlyzer_src=volmemlyzer_src)
    selected = tuple(dict.fromkeys(
        p.lower() for p in (plugins or DEEP_TRIAGE_PLUGINS) if _registry_has(pipe, p.lower())
    ))

    # Aggregate IoC features and canonical raw JSON in one selected, concurrent
    # pass. Light therefore never launches a plugin that belongs only to Deep.
    row = pipe.run_extract_features(image_path=image_path, artifacts_dir=artifacts_dir,
                                    enable=set(selected), concurrency=concurrency,
                                    use_cache=use_cache)
    features_flat = _flatten_dict(asdict(row).get("features") or {})
    vol_version = getattr(row, "vol_version", None)
    failures = dict(getattr(row, "failed_plugins", {}) or {})

    # The scoring engine consumes the same JSON the extractors just used.
    records, manifest, raw_failures = records_from_feature_cache(
        pipe, image_path, artifacts_dir, selected, failures)
    failures.update(raw_failures)

    health = extraction_health(len(selected), failures)
    if health["severity"] == "critical":
        logger.error("triage extraction degraded: %s", health["message"])
    elif health["degraded"]:
        logger.warning("triage extraction degraded: %s", health["message"])

    view = assemble_triage(features_flat, records, vol_version=vol_version, profile=profile)
    overview = overview_scoring_from_records(records, plugins=selected)
    _apply_scoring(view["dashboard"], view["processes"], overview)
    view["profile"] = overview["profile"]
    view["dashboard"]["scoring"] = {
        "kind": "bounded ordinal evidence",
        "maximum": 30,
        "not_a_probability": True,
    }
    view["manifest"] = manifest
    view["plugins"] = list(selected)
    view["extraction"] = health
    view["dashboard"]["extraction"] = health
    return view


def rescore_from_records(records: dict[str, list[dict]], features_flat: dict | None,
                         *, vol_version: Any = None, profile: dict | None = None) -> dict:
    """Re-score cached records under a new profile (no Volatility). Used by /rescore."""
    return assemble_triage(features_flat or {}, records, vol_version=vol_version,
                           profile=profile)

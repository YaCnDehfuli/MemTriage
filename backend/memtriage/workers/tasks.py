"""The pipeline tasks.

    run_triage(investigation_id)
        Phase 1. Hash each uploaded snapshot, run VolMemLyzer, and produce the
        IoC dashboard + the process/PID inventory the analyst picks from.

    run_process_analysis(analysis_id)
        Phase 2. For one selected PID: dump its VAD regions from every snapshot,
        consolidate (choose the snapshot with the most regions), render the
        VADViT grid, classify, and generate the attention overlay.

    run_plugins(plugin_run_id)
        Ad hoc, alongside the other two: run whichever Volatility plugin(s) the
        analyst picked, live, mirroring VolMemLyzer's own log output back to
        the browser as it runs rather than only reporting a final result.

Milestone 1 wires the control flow and the canonical output shapes; the
forensics/ML stages are clearly-marked scaffolds that later milestones fill in.
Dump-derived text is treated as untrusted and sanitized before it is persisted.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from celery.utils.log import get_task_logger
from sqlalchemy import select

from ..config import get_settings
from ..db import SessionLocal
from ..models import (
    AnalysisStatus,
    Dump,
    Investigation,
    InvestigationStatus,
    PluginRun,
    PluginRunStatus,
    ProcessAnalysis,
)
from ..pipeline.progress import (
    append_plugin_event,
    append_triage_event,
    set_plugin_run_state,
    set_state,
)
from ..scoring.profile import TuningProfile
from ..security.sanitize import sanitize_obj, sanitize_text
from ..storage import InvestigationPaths, ProcessPaths
from .celery_app import celery_app

logger = get_task_logger(__name__)
settings = get_settings()
TRIAGE_SCHEMA_VERSION = 2


# How many regions get the low-level treatment. The top-ranked one gets the full
# budget; the runners-up get enough to characterize them in the region list.
DEEP_DIVE_REGIONS = 1
SHALLOW_DIVE_REGIONS = 4


def _analyze_regions(ordered_regions: list, attention, ppaths) -> tuple[list[dict], dict]:
    """Rank every rendered region, then analyze the ones attention singled out."""
    manifest: list[dict] = []
    lowlevel: dict = {"regions": [], "summary": {}}
    if not ordered_regions:
        return manifest, lowlevel

    try:
        from ..lowlevel import Budget, analyze_region, build_manifest

        records = build_manifest(ordered_regions, attention, settings.grid_size)
        manifest = [r.to_dict() for r in records]
        ppaths.region_manifest.write_text(json.dumps(manifest, indent=2))
    except Exception:
        logger.exception("region manifest could not be built")
        return manifest, lowlevel

    by_patch = dict(enumerate(ordered_regions))
    analyses: list[dict] = []
    limit = DEEP_DIVE_REGIONS + SHALLOW_DIVE_REGIONS
    for position, record in enumerate(records[:limit]):
        region = by_patch.get(record.patch_index)
        if region is None:
            continue
        budget = Budget.deep() if position < DEEP_DIVE_REGIONS else Budget.shallow()
        try:
            raw = getattr(region, "data", None)
            data = b"" if raw is None else bytes(memoryview(raw))
            analyses.append(analyze_region(data, record.to_dict(), budget=budget,
                                           base_addr=record.addr_int))
        except Exception:
            logger.exception("region analysis failed for patch %s", record.patch_index)

    lowlevel = {
        "generated_at": datetime.now(UTC).isoformat(),
        "grid_size": settings.grid_size,
        "ranked_regions": len(manifest),
        "regions": analyses,
        "summary": _region_summary(analyses),
    }
    try:
        ppaths.lowlevel.write_text(json.dumps(lowlevel, indent=2))
    except OSError:
        logger.exception("could not persist the region analysis")
    return manifest, lowlevel


def _region_summary(analyses: list[dict]) -> dict:
    """One line the report and the LLM briefing can both use."""
    if not analyses:
        return {"analyzed": 0, "techniques": [], "highest_severity": "none"}
    techniques: set[str] = set()
    severities: list[str] = []
    for entry in analyses:
        summary = entry.get("summary", {})
        techniques.update(summary.get("techniques", []))
        severities.append(summary.get("highest_severity", "none"))
    order = ["none", "info", "low", "medium", "high", "critical"]
    highest = max(severities, key=lambda s: order.index(s) if s in order else 0)
    top = analyses[0].get("summary", {})
    return {
        "analyzed": len(analyses),
        "techniques": sorted(techniques),
        "highest_severity": highest,
        "top_region": top.get("headline", ""),
        "top_region_patterns": top.get("pattern_count", 0),
    }


def _analysis_notes(verdict, manifest: list[dict], lowlevel: dict) -> list[str]:
    notes = []
    if getattr(verdict, "placeholder", False):
        notes.append(
            "Classification came from an untrained structural placeholder: the "
            "family label is not a detection. Attention, region ranking and the "
            "low-level analysis below are unaffected by which weights are loaded."
        )
    elif not getattr(verdict, "model_loaded", False):
        notes.append(verdict.note or "No verdict was produced.")
    if manifest:
        notes.append(
            f"{len(manifest)} rendered regions ranked by attention; "
            f"{len(lowlevel.get('regions', []))} analyzed down to the instruction level."
        )
    notes.append(
        "Region indicators are properties of the bytes, not conclusions about "
        "the process. Corroborate against the phase-1 artifacts before acting."
    )
    return notes


def _sha256_streaming(path, chunk: int = 8 * 1024 * 1024) -> str:
    """Hash a dump in bounded chunks — never load a multi-GB image into RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _reusable_triage(paths: InvestigationPaths, primary_sha: str | None,
                     plugins: list[str]) -> dict | None:
    """Return an exact same-investigation triage hit, never a merely adjacent JSON."""
    if not primary_sha or not paths.triage.is_file():
        return None
    try:
        triage = json.loads(paths.triage.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(triage, dict):
        return None
    config = triage.get("triage_config") or {}
    if not isinstance(config, dict):
        return None
    dumps = triage.get("dumps") or []
    recorded_sha = dumps[0].get("sha256") if dumps and isinstance(dumps[0], dict) else None
    if recorded_sha != primary_sha:
        return None
    if config.get("schema_version") != TRIAGE_SCHEMA_VERSION:
        return None
    if list(config.get("plugins") or []) != list(plugins):
        return None
    extraction = triage.get("extraction")
    if not isinstance(extraction, dict):
        return None
    if (
        extraction.get("degraded") is not False
        or extraction.get("plugins_failed") != 0
        or bool(extraction.get("failed_plugins"))
        or extraction.get("plugins_attempted") != len(plugins)
    ):
        return None
    balanced = TuningProfile.from_preset("balanced").to_dict()
    if triage.get("profile") != balanced:
        return None
    return triage


def _matching_prior_investigations(
    session, inv: Investigation, primary_sha: str | None,
) -> list[Investigation]:
    if not primary_sha:
        return []
    return list(session.scalars(
        select(Investigation)
        .join(Dump, Dump.investigation_id == Investigation.id)
        .where(Dump.sha256 == primary_sha)
        .where(Dump.ordinal == 0)
        .where(Investigation.id != inv.id)
        .where(Investigation.status == InvestigationStatus.TRIAGED)
        .order_by(Investigation.updated_at.desc())
    ).all())


def _reusable_prior_triage(
    session, inv: Investigation, primary_sha: str | None, plugins: list[str],
) -> tuple[dict, str] | None:
    """Find a completed triage for the same primary bytes and exact plugin plan."""
    for source in _matching_prior_investigations(session, inv, primary_sha):
        triage = _reusable_triage(
            InvestigationPaths(source.id), primary_sha, plugins
        )
        if triage is not None:
            return triage, source.id
    return None


def _seed_prior_artifact_cache(
    session, inv: Investigation, paths: InvestigationPaths, primary_sha: str | None,
    plugins: list[str], on_event=None,
) -> str | None:
    """Copy matching canonical artifacts from a prior triage of the same bytes."""
    for source in _matching_prior_investigations(session, inv, primary_sha):
        copied = _copy_prior_artifacts(source.id, paths, plugins, on_event=on_event)
        if copied:
            return f"investigation:{source.id}"
    return None


def _copy_prior_artifacts(
    source_id: str, paths: InvestigationPaths, plugins: list[str], *, on_event=None,
) -> int:
    """Copy canonical raw JSON/stderr without linking two investigations."""
    source_dir = InvestigationPaths(source_id).volmemlyzer
    if not source_dir.is_dir():
        return 0
    copied = 0
    for plugin in plugins:
        for suffix in (".json", ".json.stderr.txt"):
            source_file = source_dir / f"dump_0_{plugin}{suffix}"
            target = paths.volmemlyzer / source_file.name
            if (
                source_file.is_file()
                and not target.exists()
                and _copy_cache_file(
                    source_file, target, source_id=source_id, plugin=plugin,
                    on_event=on_event,
                )
            ):
                copied += 1
    return copied


def _copy_cache_file(
    source: Path, target: Path, *, source_id: str, plugin: str, on_event=None,
) -> bool:
    """Copy one potentially huge cache file atomically with visible progress."""
    temporary = target.with_name(f"{target.name}.copying")
    try:
        total = source.stat().st_size
        if on_event is not None:
            on_event({
                "type": "cache_copy_started", "plugin": plugin,
                "artifact": source.name, "source": f"investigation:{source_id}",
                "size_bytes": total, "at": datetime.now(UTC).timestamp(),
            })
        copied = 0
        last_update = time.monotonic()
        with source.open("rb") as src, temporary.open("wb") as dst:
            while block := src.read(8 * 1024 * 1024):
                dst.write(block)
                copied += len(block)
                now = time.monotonic()
                if on_event is not None and now - last_update >= 5:
                    on_event({
                        "type": "cache_copy_progress", "plugin": plugin,
                        "artifact": source.name, "bytes_copied": copied,
                        "size_bytes": total, "at": datetime.now(UTC).timestamp(),
                    })
                    last_update = now
        shutil.copystat(source, temporary)
        temporary.replace(target)
        if on_event is not None:
            on_event({
                "type": "cache_copy_finished", "plugin": plugin,
                "artifact": source.name, "bytes_copied": copied,
                "size_bytes": total, "at": datetime.now(UTC).timestamp(),
            })
        return True
    except OSError:
        temporary.unlink(missing_ok=True)
        logger.warning("could not seed cached artifact %s", source)
        if on_event is not None:
            on_event({
                "type": "cache_copy_failed", "plugin": plugin,
                "artifact": source.name, "at": datetime.now(UTC).timestamp(),
            })
        return False


def _manifest_is_local(
    paths: InvestigationPaths, triage: dict, plugins: list[str],
) -> bool:
    """Confirm every rescore artifact named by a reused triage was copied."""
    from ..pipeline.volmemlyzer_adapter import valid_json_cache_artifact

    manifest = triage.get("artifacts") or {}
    if not isinstance(manifest, dict) or len(manifest) != len(set(plugins)):
        return False
    expected = {f"dump_0_{plugin}.json" for plugin in plugins}
    if {str(value) for value in manifest.values()} != expected:
        return False
    for basename in manifest.values():
        text = str(basename)
        if not text or Path(text).name != text:
            return False
        if not valid_json_cache_artifact(paths.volmemlyzer / text):
            return False
    return True


def _snapshot_plugin_artifact(
    paths: InvestigationPaths, run_id: str, plugin: str, source: Path,
) -> Path | None:
    """Copy shared plugin output to one immutable manual-run artifact."""
    if not source.is_file():
        return None
    destination = paths.volmemlyzer / f"pluginrun_{run_id}_{plugin}.json"
    if destination.is_file():
        return destination
    temporary = paths.volmemlyzer / f"{destination.name}.tmp"
    try:
        shutil.copy2(source, temporary)
        temporary.replace(destination)
    except OSError:
        temporary.unlink(missing_ok=True)
        logger.warning("could not snapshot manual plugin artifact %s", source)
        return None
    return destination


def _write_consolidated(inv: Investigation, session) -> None:
    """Rebuild result.json = triage + every completed process analysis."""
    paths = InvestigationPaths(inv.id)
    triage = json.loads(paths.triage.read_text()) if paths.triage.exists() else {}
    analyses = []
    for a in inv.analyses:
        p = ProcessPaths(inv.id, a.pid).result
        if p.exists():
            analyses.append(json.loads(p.read_text()))
    report = {
        "investigation_id": inv.id,
        "generated_at": datetime.now(UTC).isoformat(),
        "triage": triage,
        "process_analyses": analyses,
    }
    paths.result.write_text(json.dumps(report, indent=2))


def _finish_triage(session, inv: Investigation, paths: InvestigationPaths,
                   triage: dict, dumps: list[Dump]) -> None:
    """Persist one assembled or reused triage payload and its DB summary."""
    dashboard = triage.get("dashboard") or {}
    processes = triage.get("processes") or []
    paths.triage.write_text(json.dumps(sanitize_obj(triage), indent=2))
    inv.triage_path = str(paths.triage)
    inv.vol_version = (str(triage.get("vol_version") or ""))[:128] or None
    inv.process_count = len(processes)
    inv.summary = {
        "process_count": inv.process_count,
        "dumps": len(dumps),
        "flagged": len(dashboard.get("suspicious_processes") or []),
        "attack_techniques": len(dashboard.get("attack_techniques") or []),
        "risk_summary": dashboard.get("risk_summary", {}),
    }
    session.add(inv)
    session.commit()
    _write_consolidated(inv, session)


def _restore_cached_triage(
    session, inv: Investigation, paths: InvestigationPaths, triage: dict,
    dumps: list[Dump], plugins: list[str], *, source: str, message: str,
) -> None:
    """Adapt one exact cache hit to the current investigation and finish it."""
    inv.cache_source = source
    append_triage_event(session, inv, {
        "type": "cache_reused", "at": datetime.now(UTC).timestamp(),
        "source": source, "message": message,
    })
    for plugin in plugins:
        append_triage_event(session, inv, {
            "type": "plugin_cached", "plugin": plugin,
            "at": datetime.now(UTC).timestamp(), "source": source,
        })

    restored = dict(triage)
    restored["dumps"] = [
        {"ordinal": d.ordinal, "filename": d.original_filename,
         "size_bytes": d.size_bytes, "sha256": d.sha256}
        for d in dumps
    ]
    restored["triage_config"] = {
        "mode": inv.triage_mode, "plugins": plugins,
        "concurrency": inv.concurrency, "schema_version": TRIAGE_SCHEMA_VERSION,
    }
    restored["cache_source"] = source
    _finish_triage(session, inv, paths, restored, dumps)
    set_state(session, inv, status=InvestigationStatus.TRIAGED, stage="triaged",
              progress=100, message="Triage restored from matching analysis cache")


@celery_app.task(name="memtriage.run_triage", bind=True)
def run_triage(self, investigation_id: str, force: bool = False) -> str:
    session = SessionLocal()
    try:
        inv = session.get(Investigation, investigation_id)
        if inv is None:
            logger.error("run_triage: investigation %s not found", investigation_id)
            return "missing"

        paths = InvestigationPaths(investigation_id).ensure()
        from ..pipeline import volmemlyzer_adapter as vml

        selected = list(inv.requested_plugins or vml.DEEP_TRIAGE_PLUGINS)
        if "pslist" not in selected:
            selected.insert(0, "pslist")
        inv.requested_plugins = selected
        inv.triage_mode = inv.triage_mode or "deep"
        inv.concurrency = max(1, min(8, int(inv.concurrency or 4)))
        set_state(session, inv, status=InvestigationStatus.TRIAGING, stage="triaging",
                  message="Fingerprinting snapshots before Volatility 3 starts")

        # Uploads are hashed while streaming. Seeded/legacy rows may predate that,
        # so fill only the missing hashes rather than reading multi-GB files twice.
        dumps = sorted(inv.dumps, key=lambda d: d.ordinal)
        if not dumps:
            raise RuntimeError("No dump uploaded for this investigation")
        for d in dumps:
            if not d.sha256:
                d.sha256 = _sha256_streaming(paths.dump_path(d.ordinal))
        session.commit()
        primary_sha = dumps[0].sha256
        append_triage_event(session, inv, {
            "type": "plan",
            "at": datetime.now(UTC).timestamp(),
            "layers": [selected],
            "concurrency": inv.concurrency,
            "message": (
                f"Scheduled {len(selected)} plugin(s) with up to "
                f"{inv.concurrency} concurrent worker(s)."
            ),
        })

        def _cache_copy_event(event: dict) -> None:
            append_triage_event(session, inv, event)

        if not force:
            reused = _reusable_triage(paths, primary_sha, selected)
            if reused is not None and _manifest_is_local(paths, reused, selected):
                _restore_cached_triage(
                    session, inv, paths, reused, dumps, selected,
                    source="triage.json",
                    message="Existing triage.json matches this dump and plugin selection.",
                )
                return "triaged"
            if reused is not None:
                logger.warning(
                    "local triage matched but its raw artifact manifest was incomplete"
                )

            prior = _reusable_prior_triage(session, inv, primary_sha, selected)
            if prior is not None:
                reused, source_id = prior
                copied = _copy_prior_artifacts(
                    source_id, paths, selected, on_event=_cache_copy_event
                )
                if _manifest_is_local(paths, reused, selected):
                    source = f"investigation:{source_id}/triage.json"
                    _restore_cached_triage(
                        session, inv, paths, reused, dumps, selected,
                        source=source,
                        message=(
                            "A prior investigation has the same dump hash and plugin selection."
                        ),
                    )
                    return "triaged"
                logger.warning(
                    "prior triage %s matched but its raw artifact manifest was incomplete",
                    source_id,
                )
                if copied:
                    inv.cache_source = f"investigation:{source_id}"
                    append_triage_event(session, inv, {
                        "type": "cache_seeded", "at": datetime.now(UTC).timestamp(),
                        "source": inv.cache_source,
                        "message": (
                            "Reusable raw artifacts were copied; derived triage will be rebuilt."
                        ),
                    })

            seeded_from = _seed_prior_artifact_cache(
                session, inv, paths, primary_sha, selected,
                on_event=_cache_copy_event,
            )
            if seeded_from:
                inv.cache_source = seeded_from
                session.add(inv)
                session.commit()
                append_triage_event(session, inv, {
                    "type": "cache_seeded", "at": datetime.now(UTC).timestamp(),
                    "source": seeded_from,
                    "message": "Matching plugin artifacts were found for this dump hash.",
                })

        # VolMemLyzer runs on the primary (first) snapshot: aggregate IoC
        # features + per-object injections/network + the process/PID inventory.
        set_state(session, inv, stage="analyzing",
                  message=(f"Volatility 3 is starting {len(selected)} plugin(s) "
                           f"with {inv.concurrency} worker(s)"))

        primary = paths.dump_path(dumps[0].ordinal)
        from ..pipeline.plugin_runner import capture_plugin_events

        event_lock = threading.Lock()

        def _on_event(event: dict) -> None:
            # VolMemLyzer emits from a thread pool and the heartbeat has its own
            # thread. Serialize the JSON read-modify-write so no event is lost.
            with event_lock:
                event_session = SessionLocal()
                try:
                    current = event_session.get(Investigation, investigation_id)
                    if current is not None:
                        append_triage_event(event_session, current, event)
                finally:
                    event_session.close()

        with capture_plugin_events(_on_event) as capture:
            try:
                view = vml.run_triage(
                    str(primary), str(paths.volmemlyzer),
                    vol_path=settings.vol_path, timeout_s=settings.vol_timeout_s,
                    symbol_dirs=settings.vol_symbol_dirs,
                    offline=settings.vol_offline,
                    volmemlyzer_src=settings.volmemlyzer_src,
                    plugins=selected, concurrency=inv.concurrency, use_cache=not force,
                )
            except Exception as exc:
                reason = f"Triage stopped after {type(exc).__name__}"
                capture.ensure_terminal(
                    selected, failures=dict.fromkeys(selected, reason)
                )
                raise
            failed = ((view.get("extraction") or {}).get("failed_plugins") or {})
            successful = {name: "cached" for name in selected if name not in failed}
            capture.ensure_terminal(selected, failures=failed, artifacts=successful)

        session.refresh(inv)

        set_state(session, inv, stage="inventorying",
                  message="Building process/PID inventory")
        # A plugin that produced nothing must not take the whole triage down with
        # it, so read the adapter's output defensively.
        dashboard = view.get("dashboard") or {}
        processes = view.get("processes") or []
        triage = {
            "dumps": [
                {"ordinal": d.ordinal, "filename": d.original_filename,
                 "size_bytes": d.size_bytes, "sha256": d.sha256}
                for d in dumps
            ],
            "primary_dump_ordinal": dumps[0].ordinal,
            "vol_version": view.get("vol_version"),
            "dashboard": dashboard,
            "processes": processes,
            # Cached raw-artifact manifest + last profile → live re-scoring can
            # re-run the engine from disk without re-running Volatility.
            "artifacts": view.get("manifest", {}),
            "profile": view.get("profile") or dashboard.get("profile"),
            "disclaimer": view.get("disclaimer") or dashboard.get("disclaimer"),
            "extraction": view.get("extraction") or dashboard.get("extraction"),
            "triage_config": {
                "mode": inv.triage_mode, "plugins": selected,
                "concurrency": inv.concurrency,
                "schema_version": TRIAGE_SCHEMA_VERSION,
            },
            "cache_source": inv.cache_source,
        }
        _finish_triage(session, inv, paths, triage, dumps)
        set_state(session, inv, status=InvestigationStatus.TRIAGED, stage="triaged",
                  progress=100, message="Triage complete — select a process to analyze")
        return "triaged"

    except Exception as exc:
        logger.exception("run_triage failed for %s", investigation_id)
        inv = session.get(Investigation, investigation_id)
        if inv is not None:
            set_state(session, inv, status=InvestigationStatus.FAILED, stage="failed",
                      message="Triage failed",
                      error=sanitize_text(f"{type(exc).__name__}: {exc}", max_len=1000))
        logger.debug("traceback: %s", traceback.format_exc())
        return "failed"
    finally:
        session.close()


@celery_app.task(name="memtriage.run_process_analysis", bind=True)
def run_process_analysis(self, analysis_id: str) -> str:
    session = SessionLocal()
    try:
        a = session.get(ProcessAnalysis, analysis_id)
        if a is None:
            logger.error("run_process_analysis: analysis %s not found", analysis_id)
            return "missing"

        inv = session.get(Investigation, a.investigation_id)
        ppaths = ProcessPaths(a.investigation_id, a.pid).ensure()

        from ..pipeline import grid_render as gr
        from ..pipeline import region_dump as rd

        inv_paths = InvestigationPaths(a.investigation_id)
        dumps = sorted(inv.dumps, key=lambda d: d.ordinal) if inv else []

        # Dump the selected PID's VAD regions from every snapshot.
        set_state(session, a, status=AnalysisStatus.ANALYZING, stage="dumping",
                  message=f"Dumping VAD regions for PID {a.pid} across {len(dumps)} snapshot(s)")
        snapshots = []
        for d in dumps:
            snap_dir = ppaths.regions / f"snap_{d.ordinal}"
            regions = rd.dump_snapshot(
                str(inv_paths.dump_path(d.ordinal)), a.pid, str(snap_dir),
                vol_path=settings.vol_path, timeout_s=settings.vol_timeout_s)
            if len(regions) > settings.max_regions_per_process:
                regions = regions[:settings.max_regions_per_process]
            snapshots.append(rd.SnapshotRegions(ordinal=d.ordinal, regions=regions))

        # Consolidate: keep the snapshot with the most regions.
        set_state(session, a, stage="consolidating",
                  message="Selecting the snapshot with the most regions")
        chosen = rd.select_consolidated(snapshots) if snapshots else rd.SnapshotRegions(0, [])
        a.chosen_dump_ordinal = chosen.ordinal
        a.region_count = chosen.count

        # Render the VADViT grid image from the consolidated regions.
        set_state(session, a, stage="rendering", message="Rendering VADViT grid image")
        grid_available = bool(chosen.regions)
        if grid_available:
            gr.render_grid_png(chosen.regions, settings.patch_size, settings.grid_size,
                               str(ppaths.grid))

        # VADViT inference. Absent checkpoint / torch => model_loaded False and
        # NO fabricated verdict (the classifier degrades honestly).
        from ..pipeline import vadvit_model as vm

        set_state(session, a, stage="classifying", message="Classifying process")
        if grid_available:
            verdict = vm.get_classifier().classify(str(ppaths.grid))
        else:
            verdict = vm.Verdict.unavailable("No VAD regions to render/classify.")
        a.model_loaded = verdict.model_loaded
        a.verdict_family = verdict.family
        a.verdict_confidence = verdict.confidence

        # Attention overlay + patch->VAD attribution (architectural — works with
        # the placeholder weights too). Best-effort: degrades to no overlay.
        set_state(session, a, stage="explaining", message="Generating explanation")
        attention_png_ref = None
        attributions: list = []
        attention = None
        try:
            ordered = gr.order_regions(chosen.regions) if grid_available else []
        except Exception:
            logger.exception("region ordering failed; region panels will be empty")
            ordered = []
        if grid_available and verdict.model_loaded:
            try:
                attention = vm.get_classifier().attention_map(str(ppaths.grid))
            except Exception:
                attention = None
            if attention:
                from ..pipeline import explain as ex

                ex.render_attention_overlay(str(ppaths.grid), attention,
                                            settings.grid_size, str(ppaths.attention))
                attributions = sanitize_obj(
                    ex.attribution_table(attention, ordered, settings.grid_size))
                attention_png_ref = "attention"

        # Second half of the deep-dive: what is actually in the regions attention
        # ranked highest. Best-effort throughout — a failure here costs the region
        # panels, never the analysis.
        set_state(session, a, stage="regions",
                  message="Analyzing the highest-attention regions")
        manifest, lowlevel = _analyze_regions(ordered, attention, ppaths)

        analysis = {
            "analysis_id": a.id,
            "investigation_id": a.investigation_id,
            "pid": a.pid,
            "process_name": a.process_name,
            "chosen_dump_ordinal": a.chosen_dump_ordinal,
            "region_count": a.region_count,
            "verdict": verdict.to_dict(),
            "explainability": {
                "grid_png": "grid" if grid_available else None,
                "attention_png": attention_png_ref,
                "attributions": attributions,
                "region_count_ranked": len(manifest),
                "regions_analyzed": len(lowlevel.get("regions", [])),
            },
            "regions": manifest,
            "region_analysis_summary": lowlevel.get("summary", {}),
            "notes": _analysis_notes(verdict, manifest, lowlevel),
        }
        ppaths.result.write_text(json.dumps(analysis, indent=2))
        a.result_path = str(ppaths.result)

        if inv is not None:
            _write_consolidated(inv, session)

        set_state(session, a, status=AnalysisStatus.DONE, stage="done", progress=100,
                  message="Process analysis complete")
        return "done"

    except Exception as exc:
        logger.exception("run_process_analysis failed for %s", analysis_id)
        a = session.get(ProcessAnalysis, analysis_id)
        if a is not None:
            set_state(session, a, status=AnalysisStatus.FAILED, stage="failed",
                      message="Process analysis failed",
                      error=sanitize_text(f"{type(exc).__name__}: {exc}", max_len=1000))
        logger.debug("traceback: %s", traceback.format_exc())
        return "failed"
    finally:
        session.close()


@celery_app.task(name="memtriage.run_plugins", bind=True)
def run_plugins(self, plugin_run_id: str) -> str:
    session = SessionLocal()
    snapshot_executor: ThreadPoolExecutor | None = None
    requested_plugins: list[str] = []
    try:
        run = session.get(PluginRun, plugin_run_id)
        if run is None:
            logger.error("run_plugins: plugin run %s not found", plugin_run_id)
            return "missing"

        inv = session.get(Investigation, run.investigation_id)
        dumps = sorted(inv.dumps, key=lambda d: d.ordinal) if inv else []
        if not dumps:
            set_plugin_run_state(session, run, status=PluginRunStatus.FAILED, stage="failed",
                                 message="No dump uploaded for this investigation",
                                 error="No dump uploaded for this investigation")
            return "failed"

        paths = InvestigationPaths(run.investigation_id).ensure()
        image_path = str(paths.dump_path(dumps[0].ordinal))
        requested_plugins = list(run.requested_plugins or [])
        run_concurrency = run.concurrency

        set_plugin_run_state(session, run, status=PluginRunStatus.RUNNING, stage="running",
                             progress=0, message="Starting")
        session.close()
        session = None

        from ..pipeline import plugin_runner as pr
        from ..pipeline import volmemlyzer_adapter as vml

        event_lock = threading.Lock()
        snapshot_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="plugin-snapshot"
        )
        snapshot_futures: dict = {}

        def _snapshot_and_publish(plugin: str, candidate: Path) -> Path | None:
            snapshot = _snapshot_plugin_artifact(
                paths, plugin_run_id, plugin, candidate
            )
            if snapshot is None:
                return None
            with event_lock:
                artifact_session = SessionLocal()
                try:
                    current = artifact_session.get(PluginRun, plugin_run_id)
                    if current is not None:
                        artifacts = dict(current.artifacts or {})
                        artifacts[plugin] = snapshot.name
                        current.artifacts = artifacts
                        append_plugin_event(artifact_session, current, {
                            "type": "artifact_ready", "plugin": plugin,
                            "at": datetime.now(UTC).timestamp(),
                        })
                finally:
                    artifact_session.close()
            return snapshot

        def _on_event(event: dict) -> None:
            # Its own short-lived session: run_selected_plugins can call this
            # from multiple worker threads at once (concurrency > 1), and a
            # SQLAlchemy session is not safe to share across threads.
            with event_lock:
                s = SessionLocal()
                try:
                    r = s.get(PluginRun, plugin_run_id)
                    if r is not None:
                        append_plugin_event(s, r, event)
                        kind = event.get("type")
                        plugin = str(event.get("plugin") or "")
                        successful = (
                            kind in {"plugin_cached", "plugin_converted"}
                            or (kind == "plugin_finished" and event.get("ok"))
                        )
                        if plugin and successful and plugin not in snapshot_futures:
                            basename = (
                                f"{plugin}.json" if kind == "plugin_converted"
                                else f"dump_0_{plugin}.json"
                            )
                            candidate = paths.volmemlyzer / basename
                            snapshot_futures[plugin] = snapshot_executor.submit(
                                _snapshot_and_publish, plugin, candidate
                            )
                finally:
                    s.close()

        pipe = vml.build_pipeline(settings.vol_path, settings.vol_timeout_s,
                                  symbol_dirs=settings.vol_symbol_dirs,
                                  offline=settings.vol_offline,
                                  volmemlyzer_src=settings.volmemlyzer_src)
        result = pr.run_selected_plugins(
            pipe, image_path, str(paths.volmemlyzer), requested_plugins,
            run_concurrency, _on_event,
        )

        failed = dict(result.get("failed_plugins") or {})
        snapshots: dict[str, str] = {}
        if any(not future.done() for future in snapshot_futures.values()):
            status_session = SessionLocal()
            try:
                current = status_session.get(PluginRun, plugin_run_id)
                if current is not None:
                    set_plugin_run_state(
                        status_session, current, stage="snapshotting",
                        message="Preserving plugin outputs for run history",
                    )
            finally:
                status_session.close()

        for name, future in list(snapshot_futures.items()):
            try:
                snapshot = future.result()
            except Exception:
                logger.exception("manual plugin artifact snapshot failed for %s", name)
                snapshot = None
            if snapshot is not None:
                snapshots[name] = snapshot.name

        for name, artifact_path in (result.get("plugins") or {}).items():
            if name in failed or name in snapshots:
                continue
            candidate = paths.volmemlyzer / Path(str(artifact_path)).name
            future = snapshot_executor.submit(_snapshot_and_publish, name, candidate)
            try:
                snapshot = future.result()
            except Exception:
                logger.exception("manual plugin artifact snapshot failed for %s", name)
                snapshot = None
            if snapshot is None:
                reason = "Could not preserve plugin output for run history"
                failed[name] = reason
                _on_event({
                    "type": "plugin_failed", "plugin": name,
                    "explanation": reason,
                    "at": datetime.now(UTC).timestamp(), "synthetic": True,
                })
            else:
                snapshots[name] = snapshot.name

        snapshot_executor.shutdown(wait=True)
        snapshot_executor = None

        ok = len(snapshots)
        summary = (f"{ok} succeeded, {len(failed)} failed" if failed
                   else f"{ok} plugin(s) complete")

        session = SessionLocal()
        run = session.get(PluginRun, plugin_run_id)
        if run is not None:
            artifacts = dict(run.artifacts or {})
            artifacts.update(snapshots)
            run.artifacts = artifacts
            run.failed_plugins = sanitize_obj(failed, max_len=4096)
            session.add(run)
            set_plugin_run_state(session, run, status=PluginRunStatus.DONE, stage="done",
                                 progress=100, message=summary)
        return "done"

    except Exception as exc:
        logger.exception("run_plugins failed for %s", plugin_run_id)
        if session is None:
            session = SessionLocal()
        run = session.get(PluginRun, plugin_run_id)
        if run is not None:
            failures = dict(run.failed_plugins or {})
            terminal_plugins = {
                str(event.get("plugin")) for event in (run.events or [])
                if event.get("type") in {
                    "plugin_finished", "plugin_cached", "plugin_converted",
                    "plugin_unavailable", "plugin_failed",
                }
                and event.get("plugin")
            }
            for plugin in requested_plugins:
                if plugin in terminal_plugins:
                    continue
                explanation = (
                    f"Manual run stopped before completion ({type(exc).__name__})"
                )
                append_plugin_event(session, run, {
                    "type": "plugin_failed", "plugin": plugin,
                    "explanation": explanation,
                    "at": datetime.now(UTC).timestamp(), "synthetic": True,
                })
                failures[plugin] = explanation
            for event in run.events or []:
                plugin = str(event.get("plugin") or "")
                kind = event.get("type")
                if not plugin:
                    continue
                if kind in {"plugin_failed", "plugin_unavailable"}:
                    failures[plugin] = str(
                        event.get("explanation") or "Plugin run did not complete"
                    )
                elif kind == "plugin_finished" and not event.get("ok"):
                    failures[plugin] = f"vol exited {event.get('rc', '?')}"
            run.failed_plugins = sanitize_obj(failures, max_len=4096)
            set_plugin_run_state(session, run, status=PluginRunStatus.FAILED, stage="failed",
                                 message="Plugin run failed",
                                 error=sanitize_text(f"{type(exc).__name__}: {exc}", max_len=1000))
        logger.debug("traceback: %s", traceback.format_exc())
        return "failed"
    finally:
        if snapshot_executor is not None:
            snapshot_executor.shutdown(wait=True)
        if session is not None:
            session.close()

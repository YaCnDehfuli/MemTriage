"""The two pipeline tasks.

    run_triage(investigation_id)
        Phase 1. Hash each uploaded snapshot, run VolMemLyzer, and produce the
        IoC dashboard + the process/PID inventory the analyst picks from.

    run_process_analysis(analysis_id)
        Phase 2. For one selected PID: dump its VAD regions from every snapshot,
        consolidate (choose the snapshot with the most regions), render the
        VADViT grid, classify, and generate the attention overlay.

Milestone 1 wires the control flow and the canonical output shapes; the
forensics/ML stages are clearly-marked scaffolds that later milestones fill in.
Dump-derived text is treated as untrusted and sanitized before it is persisted.
"""
from __future__ import annotations

import hashlib
import json
import traceback
from datetime import datetime, timezone

from celery.utils.log import get_task_logger

from ..config import get_settings
from ..db import SessionLocal
from ..models import AnalysisStatus, Dump, Investigation, InvestigationStatus, ProcessAnalysis
from ..pipeline.progress import set_state
from ..security.sanitize import sanitize_obj, sanitize_text
from ..storage import InvestigationPaths, ProcessPaths
from .celery_app import celery_app

logger = get_task_logger(__name__)
settings = get_settings()


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

    by_patch = {index: region for index, region in enumerate(ordered_regions)}
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
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


def _write_consolidated(inv: Investigation, session) -> None:  # noqa: ANN001
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "triage": triage,
        "process_analyses": analyses,
    }
    paths.result.write_text(json.dumps(report, indent=2))


@celery_app.task(name="memtriage.run_triage", bind=True)
def run_triage(self, investigation_id: str) -> str:  # noqa: ANN001
    session = SessionLocal()
    try:
        inv = session.get(Investigation, investigation_id)
        if inv is None:
            logger.error("run_triage: investigation %s not found", investigation_id)
            return "missing"

        paths = InvestigationPaths(investigation_id).ensure()
        set_state(session, inv, status=InvestigationStatus.TRIAGING, stage="triaging",
                  message="Fingerprinting snapshots and extracting artifacts")

        # --- always-real: content hash of every uploaded snapshot ---
        dumps = sorted(inv.dumps, key=lambda d: d.ordinal)
        for d in dumps:
            d.sha256 = _sha256_streaming(paths.dump_path(d.ordinal))
        session.commit()

        # VolMemLyzer runs on the primary (first) snapshot: aggregate IoC
        # features + per-object injections/network + the process/PID inventory.
        set_state(session, inv, stage="analyzing",
                  message="Extracting IoC features and per-object artifacts")
        from ..pipeline import volmemlyzer_adapter as vml

        primary = paths.dump_path(dumps[0].ordinal)
        view = vml.run_triage(str(primary), str(paths.volmemlyzer),
                              vol_path=settings.vol_path, timeout_s=settings.vol_timeout_s)

        set_state(session, inv, stage="inventorying",
                  message="Building process/PID inventory")
        # A plugin that produced nothing must not take the whole triage down with
        # it, so read the adapter's output defensively.
        dashboard = view.get("dashboard") or {}
        processes = view.get("processes") or []
        # Every field here is dump-derived and attacker-controlled — sanitize the
        # whole structure before it is persisted or rendered.
        triage = sanitize_obj({
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
        })
        paths.triage.write_text(json.dumps(triage, indent=2))

        inv.triage_path = str(paths.triage)
        inv.vol_version = (str(view.get("vol_version")) or "")[:128] or None
        inv.process_count = len(processes)
        inv.summary = {
            "process_count": inv.process_count,
            "dumps": len(dumps),
            "flagged": len(dashboard.get("suspicious_processes") or []),
            "attack_techniques": len(dashboard.get("attack_techniques") or []),
            "risk_summary": dashboard.get("risk_summary", {}),
        }
        _write_consolidated(inv, session)
        set_state(session, inv, status=InvestigationStatus.TRIAGED, stage="triaged",
                  progress=100, message="Triage complete — select a process to analyze")
        return "triaged"

    except Exception as exc:  # noqa: BLE001
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
def run_process_analysis(self, analysis_id: str) -> str:  # noqa: ANN001
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
            except Exception:  # noqa: BLE001
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

    except Exception as exc:  # noqa: BLE001
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

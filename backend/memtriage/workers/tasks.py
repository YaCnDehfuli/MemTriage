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
            "dashboard": view["dashboard"],
            "processes": view["processes"],
        })
        paths.triage.write_text(json.dumps(triage, indent=2))

        inv.triage_path = str(paths.triage)
        inv.vol_version = (str(view.get("vol_version")) or "")[:128] or None
        inv.process_count = len(view["processes"])
        inv.summary = {
            "process_count": inv.process_count,
            "dumps": len(dumps),
            "flagged": len(view["dashboard"]["suspicious_processes"]),
            "attack_techniques": len(view["dashboard"]["attack_techniques"]),
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
        set_state(session, a, status=AnalysisStatus.ANALYZING, stage="dumping",
                  message=f"Dumping VAD regions for PID {a.pid} across snapshots")

        # TODO(M3): for each snapshot, `vol vadinfo --dump --pid <pid>`, then
        # categorize regions (exe/dll) by protection.
        set_state(session, a, stage="consolidating",
                  message="Selecting the snapshot with the most regions")
        # TODO(M3): consolidate — choose snapshot with max (exe+dll) region count.
        a.chosen_dump_ordinal = 0
        a.region_count = 0

        # TODO(M3): reproduce VADViT grid rendering (R/G/B channels).
        set_state(session, a, stage="rendering", message="Rendering VADViT grid image")

        # TODO(M4): VADViT inference. Absent checkpoint => model_loaded False and
        # NO fabricated verdict.
        set_state(session, a, stage="classifying", message="Classifying process")
        a.model_loaded = False

        # TODO(M5): attention overlay + patch->VAD attribution.
        set_state(session, a, stage="explaining", message="Generating explanation")

        analysis = {
            "analysis_id": a.id,
            "investigation_id": a.investigation_id,
            "pid": a.pid,
            "process_name": a.process_name,
            "chosen_dump_ordinal": a.chosen_dump_ordinal,
            "region_count": a.region_count,
            "verdict": {
                "model_loaded": False,
                "family": None,
                "confidence": None,
                "note": "VADViT checkpoint not mounted — verdict disabled.",
            },
            "explainability": {"grid_png": None, "attention_png": None, "attributions": []},
            "notes": ["Milestone 1 scaffold: dump/render/inference not yet wired."],
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

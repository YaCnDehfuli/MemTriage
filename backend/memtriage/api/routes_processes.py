"""Process inventory and per-process VADViT analysis.

After triage the analyst reads the process/PID inventory, picks a process, and
kicks off a VADViT deep-dive on it. Each analysis runs out-of-band and reports
progress just like triage does.
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_session
from ..models import (
    AnalysisStatus,
    Investigation,
    InvestigationStatus,
    ProcessAnalysis,
)
from ..schemas import AnalysisState, AnalyzeProcessRequest, ProcessListItem
from ..security.sanitize import sanitize_obj
from ..storage import InvestigationPaths
from ..workers.celery_app import celery_app

router = APIRouter(prefix="/api", tags=["processes"])


def _load_inventory(investigation_id: str) -> list[dict]:
    paths = InvestigationPaths(investigation_id)
    if not paths.triage.exists():
        return []
    triage = json.loads(paths.triage.read_text())
    # Sanitize on read too: process names come from an untrusted memory image.
    return sanitize_obj(triage.get("processes", []))


@router.get("/investigations/{investigation_id}/processes", response_model=list[ProcessListItem])
def list_processes(
    investigation_id: str, session: Session = Depends(get_session)
) -> list[ProcessListItem]:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.status != InvestigationStatus.TRIAGED:
        raise HTTPException(status_code=409, detail="Triage not complete")
    return [ProcessListItem(**p) for p in _load_inventory(investigation_id)]


@router.post("/investigations/{investigation_id}/processes/analyze", response_model=AnalysisState)
def analyze_process(
    investigation_id: str,
    body: AnalyzeProcessRequest,
    session: Session = Depends(get_session),
) -> AnalysisState:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.status != InvestigationStatus.TRIAGED:
        raise HTTPException(status_code=409, detail="Triage not complete")

    inventory = _load_inventory(investigation_id)
    name = ""
    if inventory:
        match = next((p for p in inventory if int(p.get("pid", -1)) == body.pid), None)
        if match is None:
            raise HTTPException(status_code=404, detail=f"PID {body.pid} not in inventory")
        name = str(match.get("name", ""))

    analysis = ProcessAnalysis(
        id=str(uuid.uuid4()),
        investigation_id=investigation_id,
        pid=body.pid,
        process_name=name,
        status=AnalysisStatus.QUEUED,
        stage="queued",
        message="Queued for VADViT analysis",
        progress=3,
    )
    session.add(analysis)
    session.commit()
    session.refresh(analysis)
    celery_app.send_task("memtriage.run_process_analysis", args=[analysis.id])
    return AnalysisState.from_orm_obj(analysis)


@router.get(
    "/investigations/{investigation_id}/analyses/{analysis_id}", response_model=AnalysisState
)
def get_analysis(
    investigation_id: str, analysis_id: str, session: Session = Depends(get_session)
) -> AnalysisState:
    a = session.get(ProcessAnalysis, analysis_id)
    if a is None or a.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisState.from_orm_obj(a)


@router.get(
    "/investigations/{investigation_id}/analyses", response_model=list[AnalysisState]
)
def list_analyses(
    investigation_id: str, session: Session = Depends(get_session)
) -> list[AnalysisState]:
    rows = session.scalars(
        select(ProcessAnalysis)
        .where(ProcessAnalysis.investigation_id == investigation_id)
        .order_by(ProcessAnalysis.created_at.desc())
    ).all()
    return [AnalysisState.from_orm_obj(a) for a in rows]

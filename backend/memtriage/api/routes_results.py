"""Consolidated report retrieval, export, and per-process artifact serving."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from ..db import get_session
from ..models import Investigation
from ..storage import InvestigationPaths, ProcessPaths, safe_within

router = APIRouter(prefix="/api", tags=["results"])

# The only per-process images we serve, mapped to their on-disk names.
_ARTIFACTS = {"grid": "grid", "attention": "attention"}


def _require_investigation(investigation_id: str, session: Session) -> Investigation:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return inv


@router.get("/investigations/{investigation_id}/result")
def get_result(investigation_id: str, session: Session = Depends(get_session)) -> JSONResponse:
    _require_investigation(investigation_id, session)
    paths = InvestigationPaths(investigation_id)
    if not paths.result.exists():
        raise HTTPException(status_code=409, detail="Result not ready")
    return JSONResponse(json.loads(paths.result.read_text()))


@router.get("/investigations/{investigation_id}/export")
def export_result(investigation_id: str, session: Session = Depends(get_session)) -> FileResponse:
    _require_investigation(investigation_id, session)
    paths = InvestigationPaths(investigation_id)
    if not paths.result.exists():
        raise HTTPException(status_code=409, detail="Result not ready")
    return FileResponse(paths.result, media_type="application/json",
                        filename=f"memtriage-{investigation_id}.json")


@router.get("/investigations/{investigation_id}/processes/{pid}/artifacts/{kind}")
def get_artifact(
    investigation_id: str, pid: int, kind: str, session: Session = Depends(get_session)
) -> FileResponse:
    _require_investigation(investigation_id, session)
    if kind not in _ARTIFACTS:
        raise HTTPException(status_code=404, detail="Unknown artifact kind")
    ppaths = ProcessPaths(investigation_id, pid)
    target = ppaths.grid if kind == "grid" else ppaths.attention
    # Defense in depth against traversal even though pid is an int and kind is gated.
    if not safe_within(ppaths.root, target) or not target.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(target, media_type="image/png")

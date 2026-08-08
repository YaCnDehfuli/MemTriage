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


def _read_json(path, missing: str) -> object:
    if not path.exists():
        raise HTTPException(status_code=404, detail=missing)
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        raise HTTPException(status_code=409, detail="Artifact is unreadable") from None


@router.get("/investigations/{investigation_id}/processes/{pid}/regions")
def get_region_manifest(
    investigation_id: str, pid: int, session: Session = Depends(get_session)
) -> JSONResponse:
    """Every patch-backed VAD region for this process, ranked by model attention."""
    _require_investigation(investigation_id, session)
    ppaths = ProcessPaths(investigation_id, pid)
    if not safe_within(ppaths.root, ppaths.region_manifest):
        raise HTTPException(status_code=404, detail="Region manifest not found")
    return JSONResponse(_read_json(
        ppaths.region_manifest,
        "No region manifest for this process — run the analysis first.",
    ))


@router.get("/investigations/{investigation_id}/processes/{pid}/lowlevel")
def get_lowlevel(
    investigation_id: str, pid: int, session: Session = Depends(get_session)
) -> JSONResponse:
    """Low-level deep-dives for the highest-attention regions."""
    _require_investigation(investigation_id, session)
    ppaths = ProcessPaths(investigation_id, pid)
    if not safe_within(ppaths.root, ppaths.lowlevel):
        raise HTTPException(status_code=404, detail="Region analysis not found")
    return JSONResponse(_read_json(
        ppaths.lowlevel,
        "No region analysis for this process — run the analysis first.",
    ))


@router.get("/investigations/{investigation_id}/processes/{pid}/lowlevel/{patch_index}")
def get_lowlevel_region(
    investigation_id: str, pid: int, patch_index: int,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """One region's deep-dive, by its patch index in the rendered grid."""
    _require_investigation(investigation_id, session)
    ppaths = ProcessPaths(investigation_id, pid)
    payload = _read_json(ppaths.lowlevel, "No region analysis for this process.")
    regions = payload.get("regions", []) if isinstance(payload, dict) else []
    match = next((r for r in regions if r.get("region", {}).get("patch_index") == patch_index),
                 None)
    if match is None:
        raise HTTPException(status_code=404,
                            detail=f"No analysis for patch {patch_index}")
    return JSONResponse(match)

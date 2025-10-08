"""Investigation lifecycle: create, add dump snapshots, start triage, inspect.

Uploading is split so each snapshot streams to disk on its own request — a 4GB+
dump is never buffered in memory, and an investigation can hold one atomic dump
or several interval snapshots. The homepage's single drag-and-drop orchestrates
create → add dump(s) → start triage under the hood.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal, get_session
from ..models import Dump, Investigation, InvestigationStatus
from ..schemas import InvestigationCreatedResponse, InvestigationState
from ..security.limits import SNIFF_BYTES, UploadRejected, sniff_reject, validate_extension
from ..security.sanitize import sanitize_text
from ..storage import InvestigationPaths, ensure_base_dirs
from ..workers.celery_app import celery_app

router = APIRouter(prefix="/api", tags=["investigations"])
settings = get_settings()


@router.post("/investigations", response_model=InvestigationCreatedResponse, status_code=201)
def create_investigation(session: Session = Depends(get_session)) -> InvestigationCreatedResponse:
    ensure_base_dirs()
    inv = Investigation(id=str(uuid.uuid4()), status=InvestigationStatus.RECEIVED,
                        stage="received", message="Awaiting dump snapshots")
    session.add(inv)
    session.commit()
    session.refresh(inv)
    InvestigationPaths(inv.id).ensure()
    return InvestigationCreatedResponse(
        investigation_id=inv.id, status=inv.status, dump_count=0, total_bytes=0
    )


@router.post("/investigations/{investigation_id}/dumps", status_code=201)
async def add_dump(
    investigation_id: str,
    request: Request,
    x_filename: str = Header(..., description="Original filename of the snapshot"),
) -> dict:
    session = SessionLocal()
    try:
        inv = session.get(Investigation, investigation_id)
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if inv.status != InvestigationStatus.RECEIVED:
            raise HTTPException(status_code=409, detail="Triage already started; no more dumps")
        if inv.dump_count >= settings.max_dumps_per_investigation:
            raise HTTPException(
                status_code=409,
                detail=f"At most {settings.max_dumps_per_investigation} snapshots per investigation.",
            )

        filename = sanitize_text(x_filename, max_len=512)
        try:
            validate_extension(filename)
        except UploadRejected as exc:
            raise HTTPException(status_code=415, detail=str(exc)) from exc

        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="Dump exceeds the size limit.")

        ordinal = inv.dump_count
        paths = InvestigationPaths(investigation_id).ensure()
        target = paths.dump_path(ordinal)

        total = 0
        sniffed = False
        try:
            with open(target, "wb") as out:
                async for chunk in request.stream():
                    if not chunk:
                        continue
                    if not sniffed:
                        try:
                            sniff_reject(chunk[:SNIFF_BYTES])
                        except UploadRejected as exc:
                            raise HTTPException(status_code=415, detail=str(exc)) from exc
                        sniffed = True
                    total += len(chunk)
                    if total > settings.max_upload_bytes:
                        raise HTTPException(status_code=413, detail="Dump exceeds the size limit.")
                    out.write(chunk)
        except HTTPException:
            target.unlink(missing_ok=True)
            raise
        except Exception as exc:  # noqa: BLE001
            target.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Upload failed while streaming.") from exc

        if total == 0:
            target.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Empty upload.")

        dump = Dump(id=str(uuid.uuid4()), investigation_id=investigation_id, ordinal=ordinal,
                    original_filename=filename, size_bytes=total)
        inv.dump_count += 1
        inv.total_bytes += total
        session.add_all([dump, inv])
        session.commit()
        return {"investigation_id": investigation_id, "ordinal": ordinal,
                "dump_count": inv.dump_count, "size_bytes": total}
    finally:
        session.close()


@router.post("/investigations/{investigation_id}/triage", response_model=InvestigationState)
def start_triage(
    investigation_id: str, session: Session = Depends(get_session)
) -> InvestigationState:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.dump_count < 1:
        raise HTTPException(status_code=409, detail="Add at least one dump before triage.")
    if inv.status != InvestigationStatus.RECEIVED:
        raise HTTPException(status_code=409, detail="Triage already started.")
    inv.stage = "queued"
    inv.message = "Queued for triage"
    inv.progress = 3
    session.add(inv)
    session.commit()
    session.refresh(inv)
    celery_app.send_task("memtriage.run_triage", args=[investigation_id])
    return InvestigationState.from_orm_obj(inv)


@router.get("/investigations/{investigation_id}", response_model=InvestigationState)
def get_investigation(
    investigation_id: str, session: Session = Depends(get_session)
) -> InvestigationState:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return InvestigationState.from_orm_obj(inv)


@router.get("/investigations", response_model=list[InvestigationState])
def list_investigations(
    limit: int = 25, session: Session = Depends(get_session)
) -> list[InvestigationState]:
    limit = max(1, min(100, limit))
    rows = session.scalars(
        select(Investigation).order_by(Investigation.created_at.desc()).limit(limit)
    ).all()
    return [InvestigationState.from_orm_obj(i) for i in rows]

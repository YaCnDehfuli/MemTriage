"""Investigation lifecycle: create, add dump snapshots, start triage, inspect.

Uploading is split so each snapshot streams to disk on its own request — a 4GB+
dump is never buffered in memory, and an investigation can hold one atomic dump
or several interval snapshots. The homepage's single drag-and-drop orchestrates
create → add dump(s) → start triage under the hood.
"""
from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import SessionLocal, get_session
from ..models import Dump, Investigation, InvestigationStatus, PluginRun, PluginRunStatus
from ..pipeline.plugin_runner import plugin_catalog
from ..pipeline.volmemlyzer_adapter import DEEP_TRIAGE_PLUGINS, LIGHT_TRIAGE_PLUGINS
from ..schemas import InvestigationCreatedResponse, InvestigationState, StartTriageRequest
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
    temporary = None
    try:
        inv = session.get(Investigation, investigation_id)
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        if inv.status != InvestigationStatus.RECEIVED:
            raise HTTPException(status_code=409, detail="Triage already started; no more dumps")
        if inv.dump_count >= settings.max_dumps_per_investigation:
            raise HTTPException(
                status_code=409,
                detail=(f"At most {settings.max_dumps_per_investigation} snapshots "
                        "per investigation."),
            )

        filename = sanitize_text(x_filename, max_len=512)
        try:
            validate_extension(filename)
        except UploadRejected as exc:
            raise HTTPException(status_code=415, detail=str(exc)) from exc

        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_upload_bytes:
            raise HTTPException(status_code=413, detail="Dump exceeds the size limit.")

        paths = InvestigationPaths(investigation_id).ensure()
        # Stream into a request-unique file first. The final ordinal is reserved
        # only after all bytes are safely on disk, under a short row lock; two
        # concurrent multi-GB uploads can therefore never write the same path.
        temporary = paths.dumps / f".upload_{uuid.uuid4().hex}.part"
        session.rollback()

        total = 0
        sniffed = False
        digest = hashlib.sha256()
        try:
            with open(temporary, "xb") as out:
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
                    digest.update(chunk)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Upload failed while streaming.") from exc

        if total == 0:
            raise HTTPException(status_code=400, detail="Empty upload.")

        # Atomically reserve the next ordinal only after streaming succeeds.
        # This is safe on both PostgreSQL and the SQLite development/test path,
        # and holds the write lock for only the final rename + metadata insert.
        new_count = session.scalar(
            update(Investigation)
            .where(Investigation.id == investigation_id)
            .where(Investigation.status == InvestigationStatus.RECEIVED)
            .where(Investigation.dump_count < settings.max_dumps_per_investigation)
            .values(
                dump_count=Investigation.dump_count + 1,
                total_bytes=Investigation.total_bytes + total,
            )
            .returning(Investigation.dump_count)
        )
        if new_count is None:
            session.rollback()
            current = session.get(Investigation, investigation_id)
            if current is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            if current.status != InvestigationStatus.RECEIVED:
                raise HTTPException(
                    status_code=409, detail="Triage already started; no more dumps"
                )
            raise HTTPException(
                status_code=409,
                detail=(f"At most {settings.max_dumps_per_investigation} snapshots "
                        "per investigation."),
            )

        ordinal = int(new_count) - 1
        target = paths.dump_path(ordinal)
        temporary.replace(target)
        temporary = None
        dump = Dump(id=str(uuid.uuid4()), investigation_id=investigation_id, ordinal=ordinal,
                    original_filename=filename, size_bytes=total, sha256=digest.hexdigest())
        session.add(dump)
        session.commit()
        return {"investigation_id": investigation_id, "ordinal": ordinal,
                "dump_count": int(new_count), "size_bytes": total}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        session.close()


@router.post("/investigations/{investigation_id}/triage", response_model=InvestigationState)
def start_triage(
    investigation_id: str,
    body: StartTriageRequest | None = None,
    session: Session = Depends(get_session),
) -> InvestigationState:
    body = body or StartTriageRequest()
    inv = session.scalars(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .with_for_update()
    ).one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.dump_count < 1:
        raise HTTPException(status_code=409, detail="Add at least one dump before triage.")
    if inv.status == InvestigationStatus.TRIAGING:
        raise HTTPException(status_code=409, detail="Triage is already running.")

    active_manual = session.scalars(
        select(PluginRun)
        .where(PluginRun.investigation_id == investigation_id)
        .where(PluginRun.status.in_([PluginRunStatus.QUEUED, PluginRunStatus.RUNNING]))
    ).first()
    if active_manual is not None:
        raise HTTPException(
            status_code=409,
            detail="A manual Volatility run is active; wait for it before starting triage.",
        )

    if body.mode == "light":
        requested = list(LIGHT_TRIAGE_PLUGINS)
    elif body.mode == "deep":
        requested = list(DEEP_TRIAGE_PLUGINS)
    else:
        known = {row["name"] for row in plugin_catalog()}
        requested = list(dict.fromkeys(
            p.strip().lower() for p in body.plugins if p.strip()
        ))
        if not requested:
            raise HTTPException(status_code=422, detail="Custom triage needs at least one plugin.")
        unknown = [p for p in requested if p not in known]
        if unknown:
            raise HTTPException(status_code=422,
                                detail=f"Unknown plugin(s): {', '.join(unknown)}")
        # The process inventory is built from pslist. Make that contract
        # server-owned so a custom plan cannot leave the inventory empty.
        if "pslist" not in requested:
            requested.insert(0, "pslist")

    inv.status = InvestigationStatus.TRIAGING
    inv.stage = "queued"
    inv.message = (f"Queued {body.mode} triage with {len(requested)} plugin(s)"
                   + (" (force refresh)" if body.force else ""))
    inv.progress = 3
    inv.error = None
    inv.triage_mode = body.mode
    inv.requested_plugins = requested
    inv.concurrency = body.concurrency
    inv.events = []
    inv.cache_source = None
    session.add(inv)
    session.commit()
    session.refresh(inv)
    try:
        celery_app.send_task("memtriage.run_triage", args=[investigation_id, body.force])
    except Exception as exc:
        inv.status = InvestigationStatus.FAILED
        inv.stage = "failed"
        inv.message = "Triage could not be queued"
        inv.error = sanitize_text(
            f"Queue submission failed ({type(exc).__name__})", max_len=1000
        )
        session.add(inv)
        session.commit()
        raise HTTPException(
            status_code=503,
            detail="Triage could not be queued; retry when the worker broker is available.",
        ) from exc
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

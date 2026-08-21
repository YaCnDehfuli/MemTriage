"""Manual Volatility suite inside the unified triage workbench.

Preset/custom triage builds the scored view, while these routes let an analyst
run and inspect any additional plugin without inventing another workflow stage.
Only an uploaded dump is required; triage and manual batches share the same
artifact cache but cannot execute over it at the same time.
"""
from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_session
from ..models import Investigation, PluginRun, PluginRunStatus
from ..pipeline.plugin_runner import plugin_catalog
from ..schemas import PluginRunState, RunPluginsRequest
from ..security.sanitize import sanitize_obj, sanitize_text
from ..storage import InvestigationPaths, safe_within
from ..workers.celery_app import celery_app

router = APIRouter(prefix="/api", tags=["plugins"])

MAX_CONCURRENCY = 8
MAX_RENDER_BYTES = 16 * 1024 * 1024


@router.get("/plugins/catalog")
def get_plugin_catalog() -> list[dict]:
    """Every plugin available to run, grouped for the picker. No investigation needed."""
    return plugin_catalog()


@router.post(
    "/investigations/{investigation_id}/plugins/run",
    response_model=PluginRunState,
    status_code=201,
)
def run_plugins(
    investigation_id: str,
    body: RunPluginsRequest,
    session: Session = Depends(get_session),
) -> PluginRunState:
    inv = session.scalars(
        select(Investigation)
        .where(Investigation.id == investigation_id)
        .with_for_update()
    ).one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.dump_count < 1:
        raise HTTPException(status_code=409, detail="Upload a dump before running a plugin.")
    if inv.status.value == "triaging":
        raise HTTPException(status_code=409,
                            detail="Triage is using Volatility; wait for it to finish.")
    active = session.scalars(
        select(PluginRun)
        .where(PluginRun.investigation_id == investigation_id)
        .where(PluginRun.status.in_([PluginRunStatus.QUEUED, PluginRunStatus.RUNNING]))
    ).first()
    if active is not None:
        raise HTTPException(status_code=409, detail="Another manual plugin run is active.")

    known = {row["name"] for row in plugin_catalog()}
    requested = list(dict.fromkeys(
        p.strip().lower() for p in body.plugins if p.strip()
    ))
    if not requested:
        raise HTTPException(status_code=422, detail="Select at least one plugin.")
    unknown = [p for p in requested if p not in known]
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown plugin(s): {', '.join(unknown)}")

    run = PluginRun(
        id=str(uuid.uuid4()),
        investigation_id=investigation_id,
        status=PluginRunStatus.QUEUED,
        stage="queued",
        message=f"Queued {len(requested)} plugin(s)",
        progress=0,
        requested_plugins=requested,
        concurrency=max(1, min(MAX_CONCURRENCY, body.concurrency)),
    )
    session.add(run)
    session.commit()
    session.refresh(run)
    try:
        celery_app.send_task("memtriage.run_plugins", args=[run.id])
    except Exception as exc:
        run.status = PluginRunStatus.FAILED
        run.stage = "failed"
        run.message = "Plugin run could not be queued"
        run.error = sanitize_text(
            f"Queue submission failed ({type(exc).__name__})", max_len=1000
        )
        session.add(run)
        session.commit()
        raise HTTPException(
            status_code=503,
            detail="Plugin run could not be queued; retry when the worker broker is available.",
        ) from exc
    return PluginRunState.from_orm_obj(run)


@router.get(
    "/investigations/{investigation_id}/plugins/runs/{run_id}", response_model=PluginRunState
)
def get_plugin_run(
    investigation_id: str, run_id: str, session: Session = Depends(get_session)
) -> PluginRunState:
    run = session.get(PluginRun, run_id)
    if run is None or run.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Plugin run not found")
    return PluginRunState.from_orm_obj(run)


@router.get(
    "/investigations/{investigation_id}/plugins/runs", response_model=list[PluginRunState]
)
def list_plugin_runs(
    investigation_id: str,
    limit: int = Query(default=25, ge=1, le=100),
    session: Session = Depends(get_session),
) -> list[PluginRunState]:
    rows = session.scalars(
        select(PluginRun)
        .where(PluginRun.investigation_id == investigation_id)
        .order_by(PluginRun.created_at.desc())
        .limit(limit)
    ).all()
    return [PluginRunState.from_orm_obj(r) for r in rows]


def _run_artifact(
    investigation_id: str, run_id: str, plugin: str, session: Session,
) -> tuple[PluginRun, Path]:
    run = session.get(PluginRun, run_id)
    if run is None or run.investigation_id != investigation_id:
        raise HTTPException(status_code=404, detail="Plugin run not found")
    if plugin not in (run.requested_plugins or []):
        raise HTTPException(status_code=404, detail="Plugin was not part of this run")
    basename = (run.artifacts or {}).get(plugin)
    if not basename:
        failure = (run.failed_plugins or {}).get(plugin)
        if failure:
            raise HTTPException(status_code=409, detail=f"Plugin produced no output: {failure}")
        raise HTTPException(status_code=409, detail="Plugin output is not ready")
    paths = InvestigationPaths(investigation_id)
    target = paths.volmemlyzer / Path(str(basename)).name
    if not safe_within(paths.volmemlyzer, target) or not target.is_file():
        raise HTTPException(status_code=404, detail="Plugin output not found")
    return run, target


def _tabular(payload: object) -> tuple[list[dict], object | None]:
    rows: object = payload
    if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
        rows = payload["rows"]
    elif isinstance(payload, dict) and isinstance(payload.get("records"), list):
        rows = payload["records"]
    elif isinstance(payload, dict):
        rows = [payload]
    if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
        return list(rows), None
    return [], payload


def _load_renderable_json(target: Path) -> object:
    """Load a bounded artifact for server-side preview/CSV rendering.

    The original JSON remains downloadable at any size. Rendering expands JSON
    into Python objects, so accepting an unbounded scanner result here would let
    one request exhaust the API process even though the eventual response is
    streamed.
    """
    try:
        size = target.stat().st_size
    except OSError:
        raise HTTPException(status_code=409, detail="Plugin output is unreadable") from None
    if size > MAX_RENDER_BYTES:
        limit_mib = MAX_RENDER_BYTES // (1024 * 1024)
        raise HTTPException(
            status_code=413,
            detail=(
                f"Preview and CSV rendering are limited to {limit_mib} MiB; "
                "download the original JSON instead."
            ),
        )
    try:
        return json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(status_code=409, detail="Plugin output is unreadable") from None


@router.get("/investigations/{investigation_id}/plugins/runs/{run_id}/outputs/{plugin}")
def preview_plugin_output(
    investigation_id: str,
    run_id: str,
    plugin: str,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=200, ge=1, le=1000),
    session: Session = Depends(get_session),
) -> JSONResponse:
    run, target = _run_artifact(investigation_id, run_id, plugin, session)
    payload = _load_renderable_json(target)
    rows, data = _tabular(payload)
    page = sanitize_obj(rows[offset:offset + limit], max_len=4096)
    columns = list(dict.fromkeys(str(key) for row in page for key in row))
    cached = any(
        e.get("plugin") == plugin and e.get("type") in {"plugin_cached", "plugin_converted"}
        for e in (run.events or [])
    )
    body = {
        "plugin": plugin,
        "format": "json",
        "columns": columns,
        "rows": page,
        "data": sanitize_obj(data, max_len=4096) if data is not None else None,
        "offset": offset,
        "limit": limit,
        "total": len(rows),
        "row_count": len(rows),
        "truncated": bool(rows and offset + len(page) < len(rows)),
        "cached": cached,
    }
    return JSONResponse(body)


def _csv_cell(value: object) -> str:
    if isinstance(value, dict | list):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = sanitize_text(value, max_len=32_768, collapse_ws=False)
    # Spreadsheet formula injection: downloaded evidence is data, never a formula.
    if text.startswith(("\t", "\r")) or text.lstrip().startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text


def _csv_stream(rows: list[dict], columns: list[str]) -> Iterator[str]:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([_csv_cell(column) for column in columns])
    yield buf.getvalue()
    for row in rows:
        buf.seek(0)
        buf.truncate(0)
        writer.writerow([_csv_cell(row.get(column)) for column in columns])
        yield buf.getvalue()


@router.get(
    "/investigations/{investigation_id}/plugins/runs/{run_id}/outputs/{plugin}/download"
)
def download_plugin_output(
    investigation_id: str,
    run_id: str,
    plugin: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    session: Session = Depends(get_session),
):
    _run, target = _run_artifact(investigation_id, run_id, plugin, session)
    if format == "json":
        return FileResponse(target, media_type="application/json",
                            filename=f"{plugin}.json")
    payload = _load_renderable_json(target)
    rows, _data = _tabular(payload)
    columns = list(dict.fromkeys(str(key) for row in rows for key in row))
    headers = {"Content-Disposition": f'attachment; filename="{plugin}.csv"'}
    return StreamingResponse(_csv_stream(rows, columns), media_type="text/csv; charset=utf-8",
                             headers=headers)

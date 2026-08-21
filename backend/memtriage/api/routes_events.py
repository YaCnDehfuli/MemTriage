"""Live progress over Server-Sent Events, for both triage and process analysis.

Each endpoint emits the current state immediately, then relays every Redis
pub/sub event the worker publishes until a terminal state or client disconnect.
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from ..config import get_settings
from ..models import Investigation, PluginRun, ProcessAnalysis
from ..pipeline.progress import analysis_channel, investigation_channel, plugin_run_channel
from ..schemas import AnalysisState, InvestigationState, PluginRunState

router = APIRouter(prefix="/api", tags=["events"])
settings = get_settings()

_INV_TERMINAL = {"triaged", "failed"}
_ANALYSIS_TERMINAL = {"done", "failed"}
_PLUGIN_RUN_TERMINAL = {"done", "failed"}


async def _stream(request: Request, initial_json: str, initial_status: str,
                  channel: str, terminal: set[str],
                  load_state: Callable[[], Any]) -> EventSourceResponse:
    async def event_gen():
        last_payload = initial_json
        yield {"event": "state", "data": initial_json}
        if initial_status in terminal:
            return
        conn = aioredis.from_url(settings.redis_url)
        pubsub = conn.pubsub()
        await pubsub.subscribe(channel)
        try:
            while True:
                if await request.is_disconnected():
                    break
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=15.0)
                if msg is None:
                    # Redis fan-out is best-effort, and a job may finish between
                    # the initial DB read and this subscription. Periodically
                    # reconcile against durable state so a healthy SSE socket
                    # cannot remain open forever after a missed terminal publish.
                    current = await asyncio.to_thread(load_state)
                    if current is not None:
                        payload = current.model_dump_json()
                        status = current.status.value
                        if payload != last_payload:
                            yield {"event": "state", "data": payload}
                            last_payload = payload
                        if status in terminal:
                            break
                    yield {"event": "ping", "data": "{}"}
                    continue
                data = msg["data"]
                payload = data.decode() if isinstance(data, bytes | bytearray) else str(data)
                yield {"event": "state", "data": payload}
                last_payload = payload
                try:
                    if json.loads(payload).get("status") in terminal:
                        break
                except (ValueError, AttributeError):
                    pass
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
            await conn.aclose()

    return EventSourceResponse(event_gen())


@router.get("/investigations/{investigation_id}/events")
async def investigation_events(investigation_id: str, request: Request) -> EventSourceResponse:
    def _load():
        from ..db import SessionLocal
        s = SessionLocal()
        try:
            inv = s.get(Investigation, investigation_id)
            return InvestigationState.from_orm_obj(inv) if inv else None
        finally:
            s.close()

    initial = await asyncio.to_thread(_load)
    if initial is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return await _stream(request, initial.model_dump_json(), initial.status.value,
                         investigation_channel(investigation_id), _INV_TERMINAL, _load)


@router.get("/investigations/{investigation_id}/analyses/{analysis_id}/events")
async def analysis_events(
    investigation_id: str, analysis_id: str, request: Request
) -> EventSourceResponse:
    def _load():
        from ..db import SessionLocal
        s = SessionLocal()
        try:
            a = s.get(ProcessAnalysis, analysis_id)
            if a is None or a.investigation_id != investigation_id:
                return None
            return AnalysisState.from_orm_obj(a)
        finally:
            s.close()

    initial = await asyncio.to_thread(_load)
    if initial is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return await _stream(request, initial.model_dump_json(), initial.status.value,
                         analysis_channel(analysis_id), _ANALYSIS_TERMINAL, _load)


@router.get("/investigations/{investigation_id}/plugins/runs/{run_id}/events")
async def plugin_run_events(
    investigation_id: str, run_id: str, request: Request
) -> EventSourceResponse:
    def _load():
        from ..db import SessionLocal
        s = SessionLocal()
        try:
            r = s.get(PluginRun, run_id)
            if r is None or r.investigation_id != investigation_id:
                return None
            return PluginRunState.from_orm_obj(r)
        finally:
            s.close()

    initial = await asyncio.to_thread(_load)
    if initial is None:
        raise HTTPException(status_code=404, detail="Plugin run not found")
    return await _stream(request, initial.model_dump_json(), initial.status.value,
                         plugin_run_channel(run_id), _PLUGIN_RUN_TERMINAL, _load)

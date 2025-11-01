"""Live progress over Server-Sent Events, for both triage and process analysis.

Each endpoint emits the current state immediately, then relays every Redis
pub/sub event the worker publishes until a terminal state or client disconnect.
"""
from __future__ import annotations

import asyncio
import json

import redis.asyncio as aioredis
from fastapi import APIRouter, HTTPException, Request
from sse_starlette.sse import EventSourceResponse

from ..config import get_settings
from ..models import Investigation, ProcessAnalysis
from ..pipeline.progress import analysis_channel, investigation_channel
from ..schemas import AnalysisState, InvestigationState

router = APIRouter(prefix="/api", tags=["events"])
settings = get_settings()

_INV_TERMINAL = {"triaged", "failed"}
_ANALYSIS_TERMINAL = {"done", "failed"}


async def _stream(request: Request, initial_json: str, initial_status: str,
                  channel: str, terminal: set[str]) -> EventSourceResponse:
    async def event_gen():
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
                    yield {"event": "ping", "data": "{}"}
                    continue
                data = msg["data"]
                payload = data.decode() if isinstance(data, (bytes, bytearray)) else str(data)
                yield {"event": "state", "data": payload}
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
                         investigation_channel(investigation_id), _INV_TERMINAL)


@router.get("/investigations/{investigation_id}/analyses/{analysis_id}/events")
async def analysis_events(
    investigation_id: str, analysis_id: str, request: Request
) -> EventSourceResponse:
    def _load():
        from ..db import SessionLocal
        s = SessionLocal()
        try:
            a = s.get(ProcessAnalysis, analysis_id)
            return AnalysisState.from_orm_obj(a) if a and a.investigation_id == investigation_id else None
        finally:
            s.close()

    initial = await asyncio.to_thread(_load)
    if initial is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return await _stream(request, initial.model_dump_json(), initial.status.value,
                         analysis_channel(analysis_id), _ANALYSIS_TERMINAL)

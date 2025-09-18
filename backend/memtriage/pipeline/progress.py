"""Progress: persist state to Postgres and fan out live events over Redis.

Works for both entities in the workflow — an Investigation (triage phase) and a
ProcessAnalysis (per-process VADViT phase). The worker calls :func:`set_state`
at each stage transition; that updates the durable row *and* publishes a JSON
event on a per-entity Redis channel that the SSE endpoints relay to the browser.
"""
from __future__ import annotations

import json
from typing import Any

import redis
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Investigation, ProcessAnalysis
from ..schemas import AnalysisState, InvestigationState

settings = get_settings()

# Cumulative % reached when each stage completes, per phase.
TRIAGE_STAGE_PROGRESS: dict[str, int] = {
    "received": 0,
    "triaging": 15,
    "analyzing": 55,     # per-object suspicion pass
    "inventorying": 85,  # building the process/PID inventory
    "triaged": 100,
}
ANALYSIS_STAGE_PROGRESS: dict[str, int] = {
    "queued": 0,
    "dumping": 20,       # vadinfo --dump across snapshots
    "consolidating": 40, # pick the snapshot with the most regions
    "rendering": 60,     # VADViT grid
    "classifying": 80,
    "explaining": 92,
    "done": 100,
}


def investigation_channel(inv_id: str) -> str:
    return f"memtriage:inv:{inv_id}"


def analysis_channel(analysis_id: str) -> str:
    return f"memtriage:analysis:{analysis_id}"


def _redis() -> redis.Redis:
    return redis.Redis.from_url(settings.redis_url)


def publish_event(channel: str, payload: dict[str, Any]) -> None:
    try:
        _redis().publish(channel, json.dumps(payload, default=str))
    except redis.RedisError:
        # Live updates are best-effort; the durable DB state is the source of
        # truth, so a transient pub/sub failure must not break the pipeline.
        pass


def set_state(
    session: Session,
    obj: Investigation | ProcessAnalysis,
    *,
    status: Any | None = None,
    stage: str | None = None,
    progress: int | None = None,
    message: str | None = None,
    error: str | None = None,
) -> None:
    """Update an Investigation or ProcessAnalysis row and publish a live event."""
    is_inv = isinstance(obj, Investigation)
    table = TRIAGE_STAGE_PROGRESS if is_inv else ANALYSIS_STAGE_PROGRESS

    if status is not None:
        obj.status = status
    if stage is not None:
        obj.stage = stage
        if progress is None and stage in table:
            progress = table[stage]
    if progress is not None:
        obj.progress = max(0, min(100, progress))
    if message is not None:
        obj.message = message
    if error is not None:
        obj.error = error

    session.add(obj)
    session.commit()
    session.refresh(obj)

    if is_inv:
        publish_event(investigation_channel(obj.id), InvestigationState.from_orm_obj(obj).model_dump())
    else:
        publish_event(analysis_channel(obj.id), AnalysisState.from_orm_obj(obj).model_dump())

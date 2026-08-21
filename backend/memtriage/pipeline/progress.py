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
from ..models import Investigation, PluginRun, ProcessAnalysis
from ..schemas import AnalysisState, InvestigationState, PluginRunState
from ..security.sanitize import sanitize_obj

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
    "classifying": 75,
    "explaining": 85,
    "regions": 94,       # low-level analysis of the highest-attention regions
    "done": 100,
}


def investigation_channel(inv_id: str) -> str:
    return f"memtriage:inv:{inv_id}"


def analysis_channel(analysis_id: str) -> str:
    return f"memtriage:analysis:{analysis_id}"


def plugin_run_channel(run_id: str) -> str:
    return f"memtriage:pluginrun:{run_id}"


# Event types that mean "this plugin is done" — see pipeline/plugin_runner.py.
# A cache hit never calls the runner, so it never logs "Finished"; it is its
# own terminal state, not a lesser one.
_PLUGIN_TERMINAL_EVENTS = {
    "plugin_finished", "plugin_cached", "plugin_converted", "plugin_unavailable",
    "plugin_failed",
}
_PLUGIN_LIFECYCLE_EVENTS = {
    "plugin_dispatched", "plugin_started", "plugin_failed_detail",
    "plugin_timeout", "artifact_ready",
}
_EVENT_LIMIT = 2000


def _retain_plugin_events(
    events: list[dict], requested_plugins: list[str] | set[str],
) -> list[dict]:
    """Cap noise without evicting the state needed to reconstruct plugin cards."""
    if len(events) <= _EVENT_LIMIT:
        return events

    requested = set(requested_plugins)
    plan_index: int | None = None
    latest_lifecycle: dict[tuple[str, str], int] = {}
    latest_terminal: dict[str, int] = {}
    for index, event in enumerate(events):
        kind = event.get("type")
        if kind == "plan":
            plan_index = index
        plugin = event.get("plugin")
        if plugin not in requested:
            continue
        if kind in _PLUGIN_LIFECYCLE_EVENTS:
            latest_lifecycle[(str(plugin), str(kind))] = index
        if kind in _PLUGIN_TERMINAL_EVENTS:
            latest_terminal[str(plugin)] = index

    keep = set(latest_lifecycle.values()) | set(latest_terminal.values())
    if plan_index is not None:
        keep.add(plan_index)
    remaining = max(0, _EVENT_LIMIT - len(keep))
    for index in range(len(events) - 1, -1, -1):
        if remaining == 0:
            break
        if index not in keep:
            keep.add(index)
            remaining -= 1
    return [event for index, event in enumerate(events) if index in keep]


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
        publish_event(investigation_channel(obj.id),
                      InvestigationState.from_orm_obj(obj).model_dump())
    else:
        publish_event(analysis_channel(obj.id), AnalysisState.from_orm_obj(obj).model_dump())


def set_plugin_run_state(
    session: Session,
    run: PluginRun,
    *,
    status: Any | None = None,
    stage: str | None = None,
    progress: int | None = None,
    message: str | None = None,
    error: str | None = None,
) -> None:
    """Coarse status transitions (queued/running/done/failed) for a plugin run.

    Same shape as :func:`set_state`; :func:`append_plugin_event` is the
    complementary fine-grained half, called once per live per-plugin event.
    """
    if status is not None:
        run.status = status
    if stage is not None:
        run.stage = stage
    if progress is not None:
        run.progress = max(0, min(100, progress))
    if message is not None:
        run.message = message
    if error is not None:
        run.error = error

    session.add(run)
    session.commit()
    session.refresh(run)
    publish_event(plugin_run_channel(run.id), PluginRunState.from_orm_obj(run).model_dump())


def append_triage_event(
    session: Session, inv: Investigation, event: dict[str, Any],
) -> None:
    """Persist and publish one fine-grained VolMemLyzer triage event."""
    clean = sanitize_obj(event, max_len=4096)
    events = list(inv.events or [])
    events.append(clean)
    inv.events = _retain_plugin_events(events, list(inv.requested_plugins or []))

    requested = set(inv.requested_plugins or [])
    if requested:
        done = {
            e["plugin"] for e in inv.events
            if e.get("type") in _PLUGIN_TERMINAL_EVENTS and e.get("plugin") in requested
        }
        # Hashing occupies the first 15%; inventory assembly starts at 85%.
        derived = 15 + round(70 * len(done) / len(requested))
        inv.progress = max(inv.progress, min(85, derived))

    kind = clean.get("type")
    if kind == "plugin_started":
        inv.message = f"Volatility 3: running {clean.get('plugin')}"
    elif kind == "plugin_dispatched":
        inv.message = f"Volatility 3: {clean.get('plugin')} is waiting for a worker"
    elif kind == "plugin_cached":
        inv.message = f"{clean.get('plugin')}: reused cached output"
        if not inv.cache_source:
            inv.cache_source = "local artifacts"
    elif kind == "plugin_finished":
        suffix = "complete" if clean.get("ok") else f"failed (exit {clean.get('rc')})"
        inv.message = f"{clean.get('plugin')}: {suffix}"
    elif kind in {"plugin_failed", "plugin_unavailable"}:
        inv.message = f"{clean.get('plugin')}: unavailable or failed; triage continues"
    elif kind == "cache_copy_started":
        inv.message = f"Copying cached {clean.get('plugin')} output"
    elif kind == "cache_copy_progress":
        copied = int(clean.get("bytes_copied") or 0)
        total = int(clean.get("size_bytes") or 0)
        percent = round(100 * copied / total) if total else 0
        inv.message = f"Copying cached {clean.get('plugin')} output ({percent}%)"
    elif kind == "cache_copy_finished":
        inv.message = f"Cached {clean.get('plugin')} output is ready"
    elif kind == "cache_copy_failed":
        inv.message = f"Could not copy cached {clean.get('plugin')} output; triage continues"
    elif kind == "heartbeat":
        active = clean.get("plugins") or []
        names = ", ".join(str(n) for n in active[:3])
        inv.message = (f"Volatility 3 is still working ({names})" if names
                       else "Volatility 3 is still working")

    session.add(inv)
    session.commit()
    session.refresh(inv)
    publish_event(investigation_channel(inv.id),
                  InvestigationState.from_orm_obj(inv).model_dump())


def append_plugin_event(session: Session, run: PluginRun, event: dict[str, Any]) -> None:
    """Append one normalized event from :mod:`pipeline.plugin_runner`, and
    recompute progress from it — derived (completed / requested), not a fixed
    stage table, since a run's length is whatever the analyst selected.
    """
    event = sanitize_obj(event, max_len=4096)
    events = list(run.events or [])
    events.append(event)
    # Bound growth on a big sweep (~56 plugins, each a structured event plus a
    # raw log line) — keep the newest, which is what a live console needs.
    run.events = _retain_plugin_events(events, list(run.requested_plugins or []))

    requested = set(run.requested_plugins or [])
    if requested:
        done = {e["plugin"] for e in run.events
                if e.get("type") in _PLUGIN_TERMINAL_EVENTS and e.get("plugin") in requested}
        run.progress = max(0, min(100, round(100 * len(done) / len(requested))))

    kind = event.get("type")
    if kind == "plugin_started":
        run.message = f"Running {event.get('plugin')}"
    elif kind == "plugin_dispatched":
        run.message = f"{event.get('plugin')} dispatched; waiting for a worker"
    elif kind == "layer_dispatched":
        n = len(event.get("plugins") or [])
        run.message = f"Dispatched {n} plugin(s) to run concurrently" if n > 1 \
            else f"Running {(event.get('plugins') or ['?'])[0]}"
    elif kind == "plugin_cached":
        run.message = f"{event.get('plugin')}: served from cache"
    elif kind == "artifact_ready":
        run.message = f"{event.get('plugin')} output is ready to view"
    elif kind == "plugin_finished" and not event.get("ok"):
        run.message = f"{event.get('plugin')} failed (rc={event.get('rc')})"
    elif kind in {"plugin_failed", "plugin_unavailable"}:
        run.message = f"{event.get('plugin')} unavailable or failed"
    elif kind == "heartbeat":
        active = event.get("plugins") or []
        run.message = (f"Volatility 3 is still working ({', '.join(active[:3])})" if active
                       else "Volatility 3 is still working")

    session.add(run)
    session.commit()
    session.refresh(run)
    publish_event(plugin_run_channel(run.id), PluginRunState.from_orm_obj(run).model_dump())

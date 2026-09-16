"""Pydantic request/response schemas exchanged with the frontend."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from .models import AnalysisStatus, InvestigationStatus, PluginRunStatus


class InvestigationCreatedResponse(BaseModel):
    """Returned immediately after dumps are accepted."""

    investigation_id: str
    status: InvestigationStatus
    dump_count: int
    total_bytes: int


class InvestigationState(BaseModel):
    """Current investigation state; also the SSE progress event shape."""

    investigation_id: str
    status: InvestigationStatus
    stage: str
    progress: int
    message: str
    error: str | None = None
    dump_count: int
    total_bytes: int
    process_count: int
    has_triage: bool = False
    summary: dict | None = None
    triage_mode: Literal["light", "deep", "custom"] = "deep"
    requested_plugins: list[str] = Field(default_factory=list)
    concurrency: int = 4
    events: list[dict] = Field(default_factory=list)
    cache_source: str | None = None
    # Only for a queued triage: what the worker is busy with instead.
    queue: dict | None = None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_orm_obj(cls, inv) -> InvestigationState:  # type: ignore[no-untyped-def]
        return cls(
            investigation_id=inv.id,
            status=inv.status,
            stage=inv.stage,
            progress=inv.progress,
            message=inv.message,
            error=inv.error,
            dump_count=inv.dump_count,
            total_bytes=inv.total_bytes,
            process_count=inv.process_count,
            has_triage=inv.triage_path is not None,
            summary=inv.summary,
            triage_mode=(inv.triage_mode or "deep"),
            requested_plugins=list(inv.requested_plugins or []),
            concurrency=inv.concurrency or 1,
            events=list(inv.events or []),
            cache_source=inv.cache_source,
            queue=_queue_context(inv),
            created_at=inv.created_at,
            updated_at=inv.updated_at,
        )


def _queue_context(inv) -> dict | None:  # type: ignore[no-untyped-def]
    """What a queued triage is waiting behind.

    The worker runs one Celery task at a time (``--concurrency=1`` in
    deploy/Dockerfile.worker), and a Deep triage's psxview can hold that slot for
    hours. Without this, a queued run shows a static "Queued" that is
    indistinguishable from a hang. Computed from the database rather than the
    broker, so it needs no broker introspection and stays correct across API
    replicas. Built from the row's own session, so every place that emits
    investigation state — including the live event stream — carries it.
    """
    if getattr(inv, "stage", None) != "queued":
        return None
    from sqlalchemy import select
    from sqlalchemy.orm import object_session

    from .models import Investigation, PluginRun, ProcessAnalysis

    session = object_session(inv)
    if session is None:
        return None
    since = inv.updated_at

    running: list[dict] = []
    for other in session.scalars(
        select(Investigation).where(
            Investigation.status == InvestigationStatus.TRIAGING,
            Investigation.stage != "queued",
            Investigation.id != inv.id,
        )
    ):
        running.append({
            "kind": "triage",
            "investigation_id": other.id,
            "mode": other.triage_mode,
            "message": other.message,
        })
    for analysis in session.scalars(
        select(ProcessAnalysis).where(ProcessAnalysis.status == AnalysisStatus.ANALYZING)
    ):
        running.append({
            "kind": "process_analysis",
            "investigation_id": analysis.investigation_id,
            "message": f"VADViT deep-dive of {analysis.process_name} (PID {analysis.pid})",
        })
    for run in session.scalars(
        select(PluginRun).where(PluginRun.status == PluginRunStatus.RUNNING)
    ):
        running.append({
            "kind": "plugin_run",
            "investigation_id": run.investigation_id,
            "message": run.message,
        })

    ahead = 0
    if since is not None:
        ahead += len(session.scalars(select(Investigation.id).where(
            Investigation.status == InvestigationStatus.TRIAGING,
            Investigation.stage == "queued",
            Investigation.id != inv.id,
            Investigation.updated_at < since,
        )).all())
        ahead += len(session.scalars(select(ProcessAnalysis.id).where(
            ProcessAnalysis.status == AnalysisStatus.QUEUED,
            ProcessAnalysis.created_at < since,
        )).all())
        ahead += len(session.scalars(select(PluginRun.id).where(
            PluginRun.status == PluginRunStatus.QUEUED,
            PluginRun.created_at < since,
        )).all())
    return {"running": running, "waiting_ahead": ahead}


class ProcessListItem(BaseModel):
    """One entry in the triage process/PID inventory the analyst chooses from."""

    pid: int
    name: str
    ppid: int | None = None
    risk: str | None = None       # engine risk band (Critical/High/Medium/Low), if any
    flags: list[str] = []         # ids of the rules that fired on this PID
    analyzable: bool = True       # false e.g. for System/Idle with no user VADs
    score: float | None = None    # engine score
    confidence: float | None = None
    techniques: list[str] = []    # aligned MITRE technique ids


class AnalyzeProcessRequest(BaseModel):
    """POST body when the analyst selects a process to run VADViT on."""

    pid: int


class StartTriageRequest(BaseModel):
    """How VolMemLyzer should build the triage view.

    Light/deep are server-owned presets so their meaning stays stable across
    clients. ``plugins`` is used only for custom mode.
    """

    mode: Literal["light", "deep", "custom"] = "deep"
    plugins: list[str] = Field(default_factory=list)
    concurrency: int = Field(default=4, ge=1, le=8)
    force: bool = False


class AnalysisState(BaseModel):
    """Per-process VADViT analysis state; also its SSE event shape."""

    analysis_id: str
    investigation_id: str
    pid: int
    process_name: str
    status: AnalysisStatus
    stage: str
    progress: int
    message: str
    error: str | None = None
    model_loaded: bool = False
    verdict_family: str | None = None
    verdict_confidence: float | None = None
    chosen_dump_ordinal: int | None = None
    region_count: int | None = None
    has_result: bool = False
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_orm_obj(cls, a) -> AnalysisState:  # type: ignore[no-untyped-def]
        return cls(
            analysis_id=a.id,
            investigation_id=a.investigation_id,
            pid=a.pid,
            process_name=a.process_name,
            status=a.status,
            stage=a.stage,
            progress=a.progress,
            message=a.message,
            error=a.error,
            model_loaded=a.model_loaded,
            verdict_family=a.verdict_family,
            verdict_confidence=a.verdict_confidence,
            chosen_dump_ordinal=a.chosen_dump_ordinal,
            region_count=a.region_count,
            has_result=a.result_path is not None,
            created_at=a.created_at,
            updated_at=a.updated_at,
        )


class RunPluginsRequest(BaseModel):
    """POST body to start an ad-hoc plugin run."""

    plugins: list[str]
    concurrency: int = Field(default=4, ge=1, le=8)


class PluginRunState(BaseModel):
    """Live state of one ad-hoc plugin run; also its SSE event shape.

    ``events`` accumulates as the run progresses — each entry is one normalized
    event from :mod:`memtriage.pipeline.plugin_runner` (a dispatched batch, a
    plugin finishing/being served from cache/failing, or a raw log line for the
    console mirror).
    """

    plugin_run_id: str
    investigation_id: str
    status: PluginRunStatus
    stage: str
    progress: int
    message: str
    error: str | None = None
    requested_plugins: list[str] = Field(default_factory=list)
    concurrency: int = 1
    events: list[dict] = Field(default_factory=list)
    available_outputs: list[str] = Field(default_factory=list)
    failed_plugins: dict[str, str] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_orm_obj(cls, r) -> PluginRunState:  # type: ignore[no-untyped-def]
        return cls(
            plugin_run_id=r.id,
            investigation_id=r.investigation_id,
            status=r.status,
            stage=r.stage,
            progress=r.progress,
            message=r.message,
            error=r.error,
            requested_plugins=list(r.requested_plugins or []),
            concurrency=r.concurrency,
            events=list(r.events or []),
            available_outputs=sorted((r.artifacts or {}).keys()),
            failed_plugins=dict(r.failed_plugins or {}),
            created_at=r.created_at,
            updated_at=r.updated_at,
        )

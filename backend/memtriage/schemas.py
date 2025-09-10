"""Pydantic request/response schemas exchanged with the frontend."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel

from .models import AnalysisStatus, InvestigationStatus


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
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_orm_obj(cls, inv) -> "InvestigationState":  # type: ignore[no-untyped-def]
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
            created_at=inv.created_at,
            updated_at=inv.updated_at,
        )


class ProcessListItem(BaseModel):
    """One entry in the triage process/PID inventory the analyst chooses from."""

    pid: int
    name: str
    ppid: int | None = None
    risk: str | None = None       # VolMemLyzer suspicion hint, if any
    flags: list[str] = []
    analyzable: bool = True       # false e.g. for System/Idle with no user VADs


class AnalyzeProcessRequest(BaseModel):
    """POST body when the analyst selects a process to run VADViT on."""

    pid: int


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
    def from_orm_obj(cls, a) -> "AnalysisState":  # type: ignore[no-untyped-def]
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

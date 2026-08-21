"""ORM models. Only investigation/analysis metadata is persisted here.

The workflow is two-phase and user-driven:

    Investigation  — one atomic dump OR up to 5 interval snapshots. VolMemLyzer
                     triage runs first and produces the IoC dashboard + the
                     process/PID inventory.
    ProcessAnalysis — created when the analyst selects a PID from the inventory.
                     VADViT assembles that process's VAD regions (across
                     snapshots), consolidates, classifies, and explains.
"""
from __future__ import annotations

import enum
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class InvestigationStatus(str, enum.Enum):
    RECEIVED = "received"      # dumps written to disk, triage not yet started
    TRIAGING = "triaging"      # VolMemLyzer running
    TRIAGED = "triaged"        # dashboard + process inventory ready for selection
    FAILED = "failed"


class AnalysisStatus(str, enum.Enum):
    QUEUED = "queued"
    ANALYZING = "analyzing"    # dumping/assembling/rendering/classifying/explaining
    DONE = "done"
    FAILED = "failed"


class PluginRunStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"        # VolMemLyzer executing the selected plugin set
    DONE = "done"
    FAILED = "failed"


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[InvestigationStatus] = mapped_column(
        Enum(InvestigationStatus, native_enum=False, length=16),
        default=InvestigationStatus.RECEIVED,
        index=True,
    )
    stage: Mapped[str] = mapped_column(String(64), default="received")
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    message: Mapped[str] = mapped_column(String(512), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    dump_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)

    # Triage outputs.
    process_count: Mapped[int] = mapped_column(Integer, default=0)
    triage_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    vol_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # The VolMemLyzer workbench configuration and its durable live transcript.
    # Keeping these on the investigation makes triage a capability of the triage
    # workspace, rather than inventing a second workflow stage just to track it.
    triage_mode: Mapped[str] = mapped_column(String(16), default="deep")
    requested_plugins: Mapped[list] = mapped_column(JSON, default=list)
    concurrency: Mapped[int] = mapped_column(Integer, default=4)
    events: Mapped[list] = mapped_column(JSON, default=list)
    cache_source: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    dumps: Mapped[list[Dump]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    analyses: Mapped[list[ProcessAnalysis]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )
    plugin_runs: Mapped[list[PluginRun]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )


class Dump(Base):
    """One uploaded memory snapshot belonging to an investigation."""

    __tablename__ = "dumps"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer, default=0)  # snapshot order
    original_filename: Mapped[str] = mapped_column(String(512))
    size_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    investigation: Mapped[Investigation] = relationship(back_populates="dumps")


class ProcessAnalysis(Base):
    """A VADViT deep-dive on one PID the analyst selected from the inventory."""

    __tablename__ = "process_analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    pid: Mapped[int] = mapped_column(Integer, index=True)
    process_name: Mapped[str] = mapped_column(String(260), default="")

    status: Mapped[AnalysisStatus] = mapped_column(
        Enum(AnalysisStatus, native_enum=False, length=16),
        default=AnalysisStatus.QUEUED,
        index=True,
    )
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(String(512), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Which snapshot was consolidated (index into dumps) and its region count.
    chosen_dump_ordinal: Mapped[int | None] = mapped_column(Integer, nullable=True)
    region_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Verdict summary (full detail in the on-disk analysis JSON).
    model_loaded: Mapped[bool] = mapped_column(default=False)
    verdict_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verdict_confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    result_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    investigation: Mapped[Investigation] = relationship(back_populates="analyses")


class PluginRun(Base):
    """An analyst-picked Volatility batch in the unified triage workbench.

    Preset/custom triage builds the scored dashboard; a ``PluginRun`` lets the
    analyst inspect any additional plugin concurrently in that same workspace.
    Both paths share the investigation's VolMemLyzer artifact cache.
    """

    __tablename__ = "plugin_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )

    status: Mapped[PluginRunStatus] = mapped_column(
        Enum(PluginRunStatus, native_enum=False, length=16),
        default=PluginRunStatus.QUEUED,
        index=True,
    )
    stage: Mapped[str] = mapped_column(String(64), default="queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(String(512), default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    requested_plugins: Mapped[list] = mapped_column(JSON, default=list)
    concurrency: Mapped[int] = mapped_column(Integer, default=1)

    # Every normalized event emitted so far (plugin_finished/cached/etc. — see
    # pipeline/plugin_runner.py). Small, capped entries; the raw stdout/stderr
    # stays on disk beside each plugin's cached artifact, same as triage.
    events: Mapped[list] = mapped_column(JSON, default=list)
    # Successful canonical JSON artifacts and failures are persisted when the
    # task finishes. API routes expose their contents/downloads without leaking
    # these server-local paths to the browser.
    artifacts: Mapped[dict] = mapped_column(JSON, default=dict)
    failed_plugins: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    investigation: Mapped[Investigation] = relationship(back_populates="plugin_runs")

"""The analyst layer: reading and writing the human judgement on a report.

Two rules govern everything here.

*The report follows the analyst's pins.* A row exists only for evidence the
analyst chose, from the page that shows it. With no pins at all the document is
the complete triage record, so an untouched investigation is never empty.

*Selection is disclosed, never silent.* A curated report states how many scored
objects its findings were chosen from, and an examiner artifact is relabelled
rather than deleted.
"""
from __future__ import annotations

import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..models import (
    ConfidenceLevel,
    Disposition,
    ReportEvidence,
    ReportNarration,
    ReportNarrative,
)
from ..security.sanitize import sanitize_text

# Narrative slots the analyst can write. Fixed: the document's structure is the
# tool's, not the model's or the analyst's.
NARRATIVE_SECTIONS = (
    "hypothesis",
    "executive_summary",
    "scope_objectives",
    "recommendations",
    "examiner_info",
)

EVIDENCE_KINDS = ("finding", "region", "stage")

# Analyst prose keeps its paragraph breaks and is not a table cell, so the
# sanitizer's defaults are wrong here twice over: collapse_ws would flatten the
# blank lines the templates split on, and the 2048-char default would silently
# truncate an executive summary mid-sentence.
NOTE_MAX_LEN = 20_000


def clean(value: str | None) -> str:
    return sanitize_text(value or "", max_len=NOTE_MAX_LEN, collapse_ws=False)


def get_evidence(session: Session, investigation_id: str) -> list[ReportEvidence]:
    return list(
        session.scalars(
            select(ReportEvidence)
            .where(ReportEvidence.investigation_id == investigation_id)
            .order_by(ReportEvidence.sort_order, ReportEvidence.created_at)
        )
    )


def upsert_evidence(
    session: Session,
    investigation_id: str,
    *,
    evidence_kind: str,
    ref: str,
    label: str = "",
    pid: int | None = None,
) -> ReportEvidence:
    """Fetch the pin for this evidence, creating it if absent."""
    row = session.scalar(
        select(ReportEvidence).where(
            ReportEvidence.investigation_id == investigation_id,
            ReportEvidence.evidence_kind == evidence_kind,
            ReportEvidence.ref == ref,
        )
    )
    if row is not None:
        return row
    row = ReportEvidence(
        id=str(uuid.uuid4()),
        investigation_id=investigation_id,
        evidence_kind=evidence_kind,
        ref=ref,
        label=sanitize_text(label, max_len=512),
        pid=pid,
    )
    session.add(row)
    session.flush()
    return row


def get_narratives(session: Session, investigation_id: str) -> dict[str, ReportNarrative]:
    rows = session.scalars(
        select(ReportNarrative).where(
            ReportNarrative.investigation_id == investigation_id
        )
    )
    return {r.section: r for r in rows}


def upsert_narrative(
    session: Session,
    investigation_id: str,
    section: str,
    content: str,
    source: str = "analyst",
) -> ReportNarrative:
    row = session.scalar(
        select(ReportNarrative).where(
            ReportNarrative.investigation_id == investigation_id,
            ReportNarrative.section == section,
        )
    )
    if row is None:
        row = ReportNarrative(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            section=section,
        )
        session.add(row)
    row.content = clean(content)
    row.source = "drafted" if source == "drafted" else "analyst"
    session.flush()
    return row


def get_narrations(session: Session, investigation_id: str) -> list[ReportNarration]:
    return list(
        session.scalars(
            select(ReportNarration)
            .where(ReportNarration.investigation_id == investigation_id)
            .order_by(ReportNarration.scope, ReportNarration.ref)
        )
    )


def replace_narrations(
    session: Session, investigation_id: str, narration
) -> int:
    """Store a fresh draft, replacing the previous one wholesale.

    Wholesale because a draft is one argument: passages written against last
    week's findings, merged with passages written against this week's, would
    read as a narrative the model never actually wrote, and the contradictions
    would sit next to the evidence rather than anywhere a reader would notice.
    """
    session.execute(
        delete(ReportNarration).where(
            ReportNarration.investigation_id == investigation_id
        )
    )
    rows = [
        *(("stage", ref, text) for ref, text in narration.stages.items()),
        *(("finding", ref, text) for ref, text in narration.findings.items()),
    ]
    for scope, ref, text in rows:
        session.add(ReportNarration(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            scope=scope,
            ref=ref,
            content=clean(text),
            provider=narration.provider,
            model=narration.model,
        ))
    session.flush()
    return len(rows)


def load_narration(session: Session, investigation_id: str) -> dict:
    """The stored draft, in the shape :func:`~.assembly.assemble` consumes."""
    rows = get_narrations(session, investigation_id)
    if not rows:
        return {}
    payload: dict = {"stages": {}, "findings": {}}
    for row in rows:
        bucket = payload["stages"] if row.scope == "stage" else payload["findings"]
        bucket[row.ref] = row.content
        # Every row of one draft carries the same author; last write wins and
        # they agree, because a draft is always stored wholesale.
        payload["provider"] = row.provider
        payload["model"] = row.model
        payload["drafted_at"] = row.updated_at.isoformat() if row.updated_at else None
    return payload


def clear_narrations(session: Session, investigation_id: str) -> int:
    result = session.execute(
        delete(ReportNarration).where(
            ReportNarration.investigation_id == investigation_id
        )
    )
    return int(result.rowcount or 0)


def load_analyst(session: Session, investigation_id: str) -> dict:
    """Build the ``analyst`` payload :func:`~.assembly.assemble` consumes.

    This is the seam between storage and rendering. The assembly layer never
    touches the ORM, so the document can still be produced from a plain dict in
    tests and from the database in production without either knowing about the
    other.
    """
    narratives = get_narratives(session, investigation_id)
    payload: dict = {
        section: narratives[section].content
        for section in NARRATIVE_SECTIONS
        if section in narratives and narratives[section].content
    }
    payload["narrative_sources"] = {
        section: row.source for section, row in narratives.items() if row.content
    }

    finding_notes: dict[str, str] = {}
    region_notes: dict[str, str] = {}
    stage_notes: dict[str, str] = {}
    pinned_findings: list[str] = []
    pinned_regions: list[str] = []
    dispositions: dict[str, str] = {}
    confidences: dict[str, str] = {}

    for row in get_evidence(session, investigation_id):
        bucket = {
            "finding": finding_notes,
            "region": region_notes,
            "stage": stage_notes,
        }.get(row.evidence_kind)
        if row.evidence_kind == "finding":
            pinned_findings.append(row.ref)
        elif row.evidence_kind == "region":
            pinned_regions.append(row.ref)
        if bucket is not None and row.analyst_note:
            bucket[row.ref] = row.analyst_note
        if row.disposition and row.disposition != Disposition.UNDETERMINED:
            dispositions[row.ref] = row.disposition.value
        if row.analyst_confidence:
            confidences[row.ref] = row.analyst_confidence.value

    payload.update({
        "finding_notes": finding_notes,
        "region_notes": region_notes,
        "stage_notes": stage_notes,
        "pinned_findings": pinned_findings,
        "pinned_regions": pinned_regions,
        "dispositions": dispositions,
        "confidences": confidences,
    })
    return payload


def coerce_confidence(value: str | None) -> ConfidenceLevel | None:
    if not value:
        return None
    try:
        return ConfidenceLevel(value)
    except ValueError:
        return None


def coerce_disposition(value: str | None) -> Disposition | None:
    if not value:
        return None
    try:
        return Disposition(value)
    except ValueError:
        return None

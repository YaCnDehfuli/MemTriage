"""The investigation report: preview JSON and the standalone HTML document.

Both audiences come out of one :func:`~..reporting.assembly.assemble` call, so
the in-app preview and the exported file can never disagree about a fact. The
preview is served as the *same* HTML in an iframe rather than re-rendered in
React, because a second renderer is a second thing to drift.

Phase 0: everything here is derived from triage and deep-dive output. No
persistence, no analyst input.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..assistant.errors import AssistantError
from ..assistant.providers import ProviderError
from ..db import get_session
from ..errors import MemTriageError, NotFound, UpstreamError, ValidationFailed
from ..models import Investigation, ReportEvidence
from ..reporting import assemble
from ..reporting import narration as narration_mod
from ..reporting.assembly import AUDIENCES, TECHNICAL
from ..reporting.curation import (
    EVIDENCE_KINDS,
    NARRATIVE_SECTIONS,
    clean,
    clear_narrations,
    coerce_confidence,
    coerce_disposition,
    get_evidence,
    get_narratives,
    load_analyst,
    load_narration,
    replace_narrations,
    upsert_evidence,
    upsert_narrative,
)
from ..reporting.render import render

router = APIRouter(prefix="/api", tags=["report"])


def _assistant_http(exc: AssistantError) -> MemTriageError:
    """The provider failure, in the shape the UI already handles.

    Mirrors routes_assistant._as_http deliberately: one drafting failure should
    not present differently from the same failure in the chat panel.
    """
    status = {
        "key_required": 400, "bad_request": 400, "bad_response": 502,
        "auth_failed": 401, "forbidden": 403, "unknown_model": 404,
        "rate_limited": 429, "too_large": 413, "sdk_missing": 501,
    }.get(exc.code)
    if status is not None:
        return MemTriageError(exc.message, status_code=status, code=exc.code)
    return UpstreamError(exc.message, code=exc.code)

# The global security_headers middleware applies `default-src 'none'` via
# setdefault, which would blank the document's embedded stylesheet. The report
# routes therefore set their own policy: self-hosted assets plus the inline
# <style> block the standalone requirement forces, and data: images so an
# exported file still renders with the app stopped. Nothing else is allowed —
# in particular no script, since the document has none and must never gain one.
REPORT_CSP = (
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "script-src 'none'; object-src 'none'; frame-ancestors 'self'"
)


class EvidenceUpsert(BaseModel):
    evidence_kind: str = Field(default="finding")
    ref: str = Field(max_length=512)
    label: str = Field(default="", max_length=512)
    pid: int | None = None


class EvidencePatch(BaseModel):
    analyst_note: str | None = None
    analyst_confidence: str | None = None
    disposition: str | None = None
    sort_order: int | None = None
    # The row's `version` as the client last saw it. Debounced note autosave and
    # a disposition change can land together; without this the later write
    # silently overwrites the earlier one.
    if_version: int | None = None


class NarrativePut(BaseModel):
    content: str = Field(default="", max_length=20_000)
    source: str = Field(default="analyst")


def _require(investigation_id: str, session: Session) -> Investigation:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise NotFound("Investigation not found")
    return inv


def _evidence_row(investigation_id: str, evidence_id: str, session: Session) -> ReportEvidence:
    row = session.get(ReportEvidence, evidence_id)
    if row is None or row.investigation_id != investigation_id:
        raise NotFound("Evidence not found")
    return row


def _evidence_json(row: ReportEvidence) -> dict:
    return {
        "id": row.id,
        "evidence_kind": row.evidence_kind,
        "ref": row.ref,
        "pid": row.pid,
        "label": row.label,
        "analyst_note": row.analyst_note,
        "analyst_confidence": (
            row.analyst_confidence.value if row.analyst_confidence else None
        ),
        "disposition": row.disposition.value if row.disposition else None,
        "sort_order": row.sort_order,
        "version": row.version,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _document(investigation_id: str, session: Session, audience: str):
    try:
        return assemble(
            investigation_id, session, audience=audience,
            analyst=load_analyst(session, investigation_id),
            narration=load_narration(session, investigation_id),
        )
    except LookupError:
        raise NotFound("Investigation not found") from None


def _audience(value: str) -> str:
    return value if value in AUDIENCES else TECHNICAL


@router.get("/investigations/{investigation_id}/report/preview")
def report_preview(
    investigation_id: str,
    audience: str = Query(TECHNICAL),
    session: Session = Depends(get_session),
) -> JSONResponse:
    """The assembled document as JSON — for callers that want the data, not the page."""
    doc = _document(investigation_id, session, _audience(audience))
    return JSONResponse(doc.to_dict())


@router.get("/investigations/{investigation_id}/report.html")
def report_html(
    investigation_id: str,
    audience: str = Query(TECHNICAL),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    """The standalone document. Save it, stop the app, and it still renders."""
    doc = _document(investigation_id, session, _audience(audience))
    response = HTMLResponse(render(doc))
    response.headers["Content-Security-Policy"] = REPORT_CSP
    # Overrides the global DENY so the in-app preview can iframe this exact
    # document; frame-ancestors above still restricts it to our own origin.
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


# --------------------------------------------------------------------------
# The analyst layer
# --------------------------------------------------------------------------

@router.get("/investigations/{investigation_id}/report/evidence")
def list_evidence(
    investigation_id: str, session: Session = Depends(get_session)
) -> JSONResponse:
    _require(investigation_id, session)
    return JSONResponse(
        [_evidence_json(r) for r in get_evidence(session, investigation_id)]
    )


@router.post("/investigations/{investigation_id}/report/evidence")
def create_evidence(
    investigation_id: str,
    payload: EvidenceUpsert,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """Idempotent by (kind, ref): returns the existing row rather than erroring."""
    _require(investigation_id, session)
    if payload.evidence_kind not in EVIDENCE_KINDS:
        raise ValidationFailed(f"Unknown evidence kind: {payload.evidence_kind}")
    if not payload.ref.strip():
        raise ValidationFailed("An evidence ref is required")
    row = upsert_evidence(
        session, investigation_id,
        evidence_kind=payload.evidence_kind, ref=payload.ref,
        label=payload.label, pid=payload.pid,
    )
    session.commit()
    return JSONResponse(_evidence_json(row))


@router.patch("/investigations/{investigation_id}/report/evidence/{evidence_id}")
def patch_evidence(
    investigation_id: str,
    evidence_id: str,
    payload: EvidencePatch,
    session: Session = Depends(get_session),
) -> JSONResponse:
    _require(investigation_id, session)
    row = _evidence_row(investigation_id, evidence_id, session)

    if payload.if_version is not None and payload.if_version != row.version:
        raise ValidationFailed(
            "This note changed elsewhere since you loaded it; reload before saving."
        )

    if payload.analyst_note is not None:
        row.analyst_note = clean(payload.analyst_note)
    if payload.analyst_confidence is not None:
        row.analyst_confidence = coerce_confidence(payload.analyst_confidence)
    if payload.disposition is not None:
        disposition = coerce_disposition(payload.disposition)
        if disposition is None:
            raise ValidationFailed(f"Unknown disposition: {payload.disposition}")
        row.disposition = disposition
    if payload.sort_order is not None:
        row.sort_order = payload.sort_order

    row.version = (row.version or 1) + 1
    session.commit()
    return JSONResponse(_evidence_json(row))


@router.delete("/investigations/{investigation_id}/report/evidence/{evidence_id}")
def delete_evidence(
    investigation_id: str, evidence_id: str, session: Session = Depends(get_session)
) -> JSONResponse:
    """Unpin this evidence, removing it and the analyst's notes from the report.

    The underlying finding comes from triage and is untouched; it simply stops
    being part of the analyst's selection.
    """
    _require(investigation_id, session)
    row = _evidence_row(investigation_id, evidence_id, session)
    session.delete(row)
    session.commit()
    return JSONResponse({"deleted": evidence_id})


@router.get("/investigations/{investigation_id}/report/narrative")
def list_narrative(
    investigation_id: str, session: Session = Depends(get_session)
) -> JSONResponse:
    _require(investigation_id, session)
    rows = get_narratives(session, investigation_id)
    return JSONResponse({
        section: {
            "content": rows[section].content if section in rows else "",
            "source": rows[section].source if section in rows else "analyst",
            "updated_at": (
                rows[section].updated_at.isoformat()
                if section in rows and rows[section].updated_at
                else None
            ),
        }
        for section in NARRATIVE_SECTIONS
    })


@router.put("/investigations/{investigation_id}/report/narrative/{section}")
def put_narrative(
    investigation_id: str,
    section: str,
    payload: NarrativePut,
    session: Session = Depends(get_session),
) -> JSONResponse:
    _require(investigation_id, session)
    if section not in NARRATIVE_SECTIONS:
        raise ValidationFailed(f"Unknown narrative section: {section}")
    row = upsert_narrative(session, investigation_id, section,
                           payload.content, payload.source)
    session.commit()
    return JSONResponse({
        "section": row.section, "content": row.content, "source": row.source,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    })


# --------------------------------------------------------------------------
# Drafted narrative
# --------------------------------------------------------------------------

DRAFT_CONSENT_NOTICE = (
    "Drafting forwards this report's findings — labels, process names, command "
    "lines, registry paths and rule evidence lifted from the memory image — to "
    "the provider you choose. Pick a local provider to keep it on this machine. "
    "Your API key is used for the request and is never stored or logged."
)


class NarrationDraft(BaseModel):
    provider: str
    model: str = ""
    api_key: str = Field(default="", max_length=512, repr=False)
    base_url: str | None = Field(default=None, max_length=512)
    # The summary lands in the executive_summary slot. Words a human typed
    # there are never replaced by this (see below); set this to overwrite a
    # previous *draft* in place, or false to leave the slot alone entirely.
    write_executive_summary: bool = True


@router.post("/investigations/{investigation_id}/report/narrative/draft")
def draft_narrative(
    investigation_id: str,
    payload: NarrationDraft,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """Draft the connective narrative for this report and store it.

    Stored rather than returned-and-forgotten because ``report.html`` is a plain
    GET that the preview iframes and the export saves: it cannot carry a key or
    wait on a provider. Drafting is therefore an explicit act with a result the
    analyst can inspect, re-run or clear — never something that happens silently
    on the way to rendering a page.

    The document is assembled first and the draft is validated against *that*
    document, so a passage can only ever attach to a finding that was really in
    the report the model was shown.
    """
    _require(investigation_id, session)
    doc = _document(investigation_id, session, TECHNICAL)

    try:
        narration = narration_mod.draft(
            doc,
            provider_id=payload.provider,
            model=payload.model,
            api_key=payload.api_key,
            base_url=payload.base_url,
        )
    except ProviderError as exc:
        raise ValidationFailed(str(exc)) from None
    except AssistantError as exc:
        raise _assistant_http(exc) from None

    stored = replace_narrations(session, investigation_id, narration)

    # The executive summary is the one slot drafting shares with the analyst.
    # A summary they typed is theirs and is never overwritten by a draft — they
    # would have no way to get it back, and a report that quietly replaced a
    # human's conclusion with a model's is the failure this whole feature is
    # built to avoid. A previous draft has no such claim.
    existing = get_narratives(session, investigation_id).get("executive_summary")
    summary_written = False
    if (
        narration.executive_summary
        and payload.write_executive_summary
        and (existing is None or not existing.content or existing.source == "drafted")
    ):
        upsert_narrative(session, investigation_id, "executive_summary",
                         narration.executive_summary, source="drafted")
        summary_written = True
    session.commit()

    return JSONResponse({
        "stored": stored,
        "provider": narration.provider,
        "model": narration.model,
        "executive_summary": narration.executive_summary,
        # False when the analyst's own summary was left in place; the drafted
        # text is still returned so they can read it and decide for themselves.
        "executive_summary_written": summary_written,
        "stages": narration.stages,
        "findings": narration.findings,
        # Refs the model invented or that no longer resolve. Reported rather
        # than hidden: a non-empty list means the draft is partly about a
        # document this one no longer is.
        "unmatched": narration.unmatched,
    })


@router.delete("/investigations/{investigation_id}/report/narrative/draft")
def clear_drafted_narrative(
    investigation_id: str, session: Session = Depends(get_session)
) -> JSONResponse:
    """Drop the drafted passages. The analyst's own words are untouched."""
    _require(investigation_id, session)
    removed = clear_narrations(session, investigation_id)
    session.commit()
    return JSONResponse({"removed": removed})

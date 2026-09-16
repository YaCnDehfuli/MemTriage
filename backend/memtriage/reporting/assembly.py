"""Assemble one investigation into a renderable document.

Pure with respect to the database and the filesystem: it reads, it never writes.
Both audiences come out of the same call so the technical and executive documents
can never disagree about a fact — they differ only in which sections they render
and how much of each they show.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..models import Investigation
from ..storage import InvestigationPaths, ProcessPaths
from . import exhibits as exhibits_mod
from . import narrative
from . import stages as stages_mod

TECHNICAL = "technical"
EXECUTIVE = "executive"
AUDIENCES = (TECHNICAL, EXECUTIVE)

# An executive document names only what an executive can act on. The cut is by
# risk band, not by count, so a quiet image produces a short summary rather than
# a padded one.
EXECUTIVE_RISK_BANDS = ("Critical", "High")
# Deep-dive regions shown per analysed process in the technical document.
MAX_REGIONS_PER_PROCESS = 12
# Full evidence exhibits are expensive to read, not to produce. The deep-dive
# only analyses a handful of regions per process anyway; this caps the document.
MAX_EXHIBITS = 4


@dataclass
class ReportDocument:
    """Everything both templates need, already ordered and pre-rendered."""

    investigation_id: str
    audience: str
    generated_at: str
    case: dict[str, Any] = field(default_factory=dict)
    custody: list[dict] = field(default_factory=list)
    method: dict[str, Any] = field(default_factory=dict)
    overview: str = ""
    stats: dict[str, Any] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    examiner_artifacts: list[dict] = field(default_factory=list)
    # Once the analyst pins anything, the document is exactly what they chose.
    curated: bool = False
    scored_total: int = 0
    # Identity for every scored object, independent of curation. The UI pins
    # from this; deriving it from `findings` would hide the pin control for
    # everything not yet pinned the moment the first pin lands.
    refs: list[dict] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)
    progression: str = ""
    exhibits: list[dict] = field(default_factory=list)
    analyst: dict[str, Any] = field(default_factory=dict)
    # Drafted prose, kept separate from `analyst` all the way to the template.
    narration: dict[str, Any] = field(default_factory=dict)
    attack: list[dict] = field(default_factory=list)
    deep_dives: list[dict] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    limitations: dict[str, Any] = field(default_factory=dict)
    sections: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "investigation_id": self.investigation_id,
            "audience": self.audience,
            "generated_at": self.generated_at,
            "case": self.case,
            "custody": self.custody,
            "method": self.method,
            "overview": self.overview,
            "stats": self.stats,
            "findings": self.findings,
            "examiner_artifacts": self.examiner_artifacts,
            "curated": self.curated,
            "scored_total": self.scored_total,
            "refs": self.refs,
            "stages": self.stages,
            "progression": self.progression,
            "exhibits": self.exhibits,
            "analyst": self.analyst,
            "narration": self.narration,
            "attack": self.attack,
            "deep_dives": self.deep_dives,
            "notices": self.notices,
            "limitations": self.limitations,
            "sections": self.sections,
        }


def _read_json(path: Path, default: Any) -> Any:
    """Never raise: a missing or malformed artifact degrades one section only."""
    try:
        if not path.is_file():
            return default
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _custody(inv: Investigation) -> list[dict]:
    """Chain of custody: every acquired snapshot, unconditionally, never curated.

    Completeness is what makes a provenance section credible, so this is not
    filtered by anything and a missing hash is stated rather than omitted.
    """
    rows = []
    for d in sorted(inv.dumps, key=lambda x: x.ordinal):
        rows.append({
            "ordinal": d.ordinal,
            "filename": d.original_filename,
            "size_bytes": d.size_bytes,
            "sha256": d.sha256 or "",
            "sha256_missing": not d.sha256,
        })
    return rows


def _method(inv: Investigation, triage: dict) -> dict:
    profile = (triage.get("profile") or {}) or (
        (triage.get("dashboard") or {}).get("profile") or {}
    )
    return {
        "vol_version": inv.vol_version or "",
        "triage_mode": inv.triage_mode,
        "requested_plugins": list(inv.requested_plugins or []),
        "plugin_count": len(inv.requested_plugins or []),
        "concurrency": inv.concurrency,
        "preset": profile.get("preset") or "",
        "confidence_floor": profile.get("confidence_floor"),
        "require_correlation": profile.get("require_correlation"),
        "risk_bands": profile.get("risk_bands") or {},
        "rule_overrides": profile.get("rule_overrides") or {},
    }


def _notices(inv: Investigation, dashboard: dict, deep_dives: list[dict]) -> list[str]:
    """Statements that change how every other section should be read.

    These are placed before the findings on purpose: a placeholder classifier or
    a degraded extraction invalidates conclusions drawn further down, and a
    reader who meets that caveat in an appendix has already been misled.
    """
    out: list[str] = []
    extraction = dashboard.get("extraction") or {}
    if extraction.get("degraded"):
        failed = int(extraction.get("plugins_failed") or 0)
        attempted = int(extraction.get("plugins_attempted") or 0)
        out.append(
            f"Extraction was degraded: {failed} of {attempted} plugins failed. "
            "Sections derived from the missing plugins are incomplete, and the "
            "absence of a finding here is not evidence that nothing is there."
        )
    if any(d.get("placeholder") for d in deep_dives):
        out.append(
            "At least one process was classified by an untrained placeholder "
            "model. A placeholder family label is not evidence of anything and "
            "must not be cited as a classification result."
        )
    if not inv.dumps:
        out.append("No acquisition record is attached to this investigation.")
    return out


def _deep_dive(inv_id: str, analysis_row) -> dict | None:
    data = _read_json(ProcessPaths(inv_id, analysis_row.pid).result, None)
    if not isinstance(data, dict):
        return None
    verdict = data.get("verdict") or {}
    explain = data.get("explainability") or {}
    regions = data.get("regions") or []
    ranked = sorted(
        (r for r in regions if isinstance(r, dict)),
        key=lambda r: r.get("attention") or 0,
        reverse=True,
    )[:MAX_REGIONS_PER_PROCESS]
    return {
        "analysis_id": data.get("analysis_id") or analysis_row.id,
        "pid": analysis_row.pid,
        "process_name": data.get("process_name") or analysis_row.process_name,
        "chosen_dump_ordinal": data.get("chosen_dump_ordinal"),
        "region_count": data.get("region_count"),
        "family": verdict.get("family"),
        "confidence": verdict.get("confidence"),
        "model_loaded": bool(verdict.get("model_loaded")),
        "placeholder": bool(verdict.get("placeholder")),
        "model_source": verdict.get("model_source") or "",
        "verdict_note": verdict.get("note") or "",
        "attribution_count": len(explain.get("attributions") or []),
        "regions": ranked,
        "regions_truncated": max(0, len(regions) - len(ranked)),
    }


def evidence_ref(obj: dict) -> str:
    """A stable, unique reference for one scored object.

    ``ScoredObject.key`` is not unique, and neither is ``(object_type, key)``:
    two different scheduled tasks both key as ``task:powershell`` because the key
    is derived from the interpreter, not the script path. Binding an analyst's
    note to that alone would attach one note to two unrelated findings — the
    exact misattribution this report must never produce. Folding in a digest of
    the label disambiguates them, because the label is what actually differs,
    and stays stable across re-scores (unlike a positional index).
    """
    object_type = str(obj.get("object_type") or "")
    key = str(obj.get("key") or "")
    digest = hashlib.sha256(str(obj.get("label") or "").encode()).hexdigest()[:8]
    return f"{object_type}|{key}|{digest}"


def _exhibits(inv_id: str, analysis_row) -> list[dict]:
    """Full evidence for the regions the deep-dive analysed down to instructions."""
    data = _read_json(ProcessPaths(inv_id, analysis_row.pid).lowlevel, None)
    if not isinstance(data, dict):
        return []
    out = []
    for entry in data.get("regions") or []:
        if not isinstance(entry, dict):
            continue
        out.append(exhibits_mod.build(
            entry, pid=analysis_row.pid,
            process_name=analysis_row.process_name or str(analysis_row.pid),
        ))
    return out


def _apply_curation(doc: ReportDocument) -> None:
    """Honour the analyst's selection and dispositions.

    Pins are strict. Before anything is pinned the document is the complete,
    uncurated triage record; once the analyst pins evidence, the report presents
    exactly that selection — findings and region exhibits alike — and says how
    many scored objects it was chosen from, so the selection is never mistaken
    for the whole image.

    Examiner artifacts are moved out of the attack narrative into their own
    section rather than deleted: a scheduled task that launches a sample after
    logon is real, correctly-scored persistence, and the error would be telling
    it as adversary activity, not recording it at all.
    """
    analyst = doc.analyst or {}
    pinned_findings = set(analyst.get("pinned_findings") or [])
    pinned_regions = set(analyst.get("pinned_regions") or [])
    doc.curated = bool(pinned_findings or pinned_regions)
    if doc.curated:
        doc.findings = [f for f in doc.findings if f["ref"] in pinned_findings]
        doc.exhibits = [e for e in doc.exhibits if e.get("ref") in pinned_regions]

    dispositions = analyst.get("dispositions") or {}
    confidences = analyst.get("confidences") or {}

    kept: list[dict] = []
    artifacts: list[dict] = []
    for f in doc.findings:
        ref = f["ref"]
        disposition = dispositions.get(ref)
        if disposition:
            f["disposition"] = disposition
        confidence = confidences.get(ref)
        if confidence:
            f["analyst_confidence"] = confidence
        if disposition == "examiner_artifact":
            artifacts.append(f)
        else:
            kept.append(f)

    doc.findings = kept
    doc.examiner_artifacts = artifacts


def _attach_notes(doc: ReportDocument) -> None:
    """Bind the analyst's notes onto the evidence they were written about.

    Notes are matched by the evidence's own stable key, never by position, so a
    re-scored or re-ordered document cannot silently move a note onto a
    different finding. A note whose key no longer resolves is dropped here and
    counted, rather than being rendered against the wrong evidence.
    """
    analyst = doc.analyst or {}
    finding_notes = analyst.get("finding_notes") or {}
    region_notes = analyst.get("region_notes") or {}
    stage_notes = analyst.get("stage_notes") or {}

    # A bare `key` is accepted as a convenience, but only when it resolves to
    # exactly one finding in this document; otherwise the note is dropped rather
    # than rendered against two findings at once.
    notable = [*doc.findings, *doc.examiner_artifacts]
    by_key: dict[str, int] = {}
    for f in notable:
        by_key[f["object"].get("key")] = by_key.get(f["object"].get("key"), 0) + 1

    matched = 0
    for f in notable:
        ref = f["ref"]
        key = f["object"].get("key")
        note = finding_notes.get(ref)
        if note is None and by_key.get(key) == 1:
            note = finding_notes.get(key)
        if note:
            f["analyst_note"] = note
            matched += 1
    for e in doc.exhibits:
        note = region_notes.get(e.get("ref")) or region_notes.get(e.get("addr"))
        if note:
            e["analyst_note"] = note
            matched += 1
    for s in doc.stages:
        note = stage_notes.get(s["tactic"])
        if note:
            s["analyst_note"] = note
            matched += 1

    expected = len(finding_notes) + len(region_notes) + len(stage_notes)
    doc.analyst["notes_attached"] = matched
    doc.analyst["notes_unmatched"] = max(0, expected - matched)


def _attach_narration(doc: ReportDocument) -> None:
    """Bind drafted passages onto the findings and stages they were written for.

    Matched by ref only — never by key and never by position. The draft is
    written against one rendering of the document, so a passage whose ref no
    longer resolves is dropped rather than slid onto its neighbour; re-scoring
    an investigation drops the stale passages instead of silently re-attributing
    them.
    """
    narration = doc.narration or {}
    finding_prose = narration.get("findings") or {}
    stage_prose = narration.get("stages") or {}
    if not (finding_prose or stage_prose):
        return

    attached = 0
    for f in doc.findings:
        prose = finding_prose.get(f["ref"])
        if prose:
            f["drafted_note"] = prose
            attached += 1
    for s in doc.stages:
        prose = stage_prose.get(s["tactic"])
        if prose:
            s["drafted_note"] = prose
            attached += 1
    doc.narration["attached"] = attached
    doc.narration["dropped"] = max(
        0, len(finding_prose) + len(stage_prose) - attached
    )


def _sections(audience: str, doc: ReportDocument) -> list[dict]:
    """Numbered table of contents.

    Print-to-PDF gives no page numbers, so the document is navigated by section
    number instead; the TOC is built from what actually rendered, never from a
    fixed list, so it can't advertise an empty section.
    """
    analyst = doc.analyst or {}
    candidates = [
        ("overview", "Overview", True),
        ("notices", "Reading this report", bool(doc.notices)),
        ("hypothesis", "Hypothesis", bool(analyst.get("hypothesis"))),
        ("custody", "Chain of custody", bool(doc.custody)),
        ("method", "Scope and methodology", audience == TECHNICAL),
        # The attack narrative replaces a flat findings list: the same findings,
        # told in ATT&CK-tactic order so the document reads as a progression.
        ("narrative", "Attack narrative", bool(doc.stages)),
        ("artifacts", "Collection artifacts", bool(doc.examiner_artifacts)),
        ("exhibits", "Evidence exhibits", bool(doc.exhibits) and audience == TECHNICAL),
        ("attack", "ATT&CK technique coverage", bool(doc.attack) and audience == TECHNICAL),
        ("deepdives", "Deep-dive observations", bool(doc.deep_dives) and audience == TECHNICAL),
        ("recommendations", "Recommendations", bool(analyst.get("recommendations"))),
        ("limitations", "Limitations", bool(doc.limitations)),
    ]
    return [
        {"id": sid, "number": i, "title": title}
        for i, (sid, title, include) in enumerate(
            [c for c in candidates if c[2]], start=1
        )
    ]


def assemble(
    investigation_id: str,
    session: Session,
    *,
    audience: str = TECHNICAL,
    analyst: dict | None = None,
    narration: dict | None = None,
) -> ReportDocument:
    """Build the document. Raises only if the investigation does not exist.

    ``analyst`` carries the human layer — hypothesis, per-stage and per-finding
    notes, recommendations, executive summary. It is passed in rather than read
    from the database because the persistence for it lands in the next phase;
    the shape here is the contract that phase has to satisfy.

    ``narration`` carries drafted prose from :mod:`.narration`, keyed by the same
    refs. It is a third parameter rather than a key inside ``analyst`` because
    the two must never merge: a reader has to be able to tell which sentences a
    human stands behind. Both are optional and the document renders without
    either.
    """
    if audience not in AUDIENCES:
        audience = TECHNICAL
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise LookupError(investigation_id)

    paths = InvestigationPaths(inv.id)
    triage = _read_json(paths.triage, {}) or {}
    dashboard = triage.get("dashboard") or {}

    scored = [o for o in (dashboard.get("scored_objects") or []) if isinstance(o, dict)]
    scored.sort(
        key=lambda o: (narrative.risk_rank(o.get("risk", "")), -(o.get("score") or 0))
    )
    # The overview always describes the *whole* scored set, even in the executive
    # document. Counting only what survived the filter would make the opening
    # sentence disagree with the risk bands it quotes from risk_summary.
    total_scored = len(scored)
    all_scored = list(scored)
    if audience == EXECUTIVE:
        scored = [o for o in scored if o.get("risk") in EXECUTIVE_RISK_BANDS]

    deep_dives = []
    collected_exhibits: list[dict] = []
    for row in sorted(inv.analyses, key=lambda a: a.pid):
        built = _deep_dive(inv.id, row)
        if built is not None:
            deep_dives.append(built)
        collected_exhibits.extend(_exhibits(inv.id, row))
    # With a placeholder checkpoint the attention ranking carries no signal, so
    # ordering exhibits by it would lead the report with noise. Fall back to a
    # ranking derived from the bytes themselves.
    placeholder = any(d.get("placeholder") for d in deep_dives)
    if placeholder:
        collected_exhibits.sort(key=exhibits_mod.forensic_rank, reverse=True)
    else:
        collected_exhibits.sort(key=lambda e: e.get("attention") or 0, reverse=True)
    for e in collected_exhibits:
        e["ranked_by"] = "measured properties" if placeholder else "model attention"
    pinned_regions = set((analyst or {}).get("pinned_regions") or [])
    if not pinned_regions:
        collected_exhibits = collected_exhibits[:MAX_EXHIBITS]

    attack = [t for t in (dashboard.get("attack_techniques") or []) if isinstance(t, dict)]
    doc = ReportDocument(
        investigation_id=inv.id,
        audience=audience,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        case={
            "investigation_id": inv.id,
            "status": getattr(inv.status, "value", str(inv.status)),
            "created_at": inv.created_at.isoformat(timespec="seconds")
            if inv.created_at
            else "",
            "updated_at": inv.updated_at.isoformat(timespec="seconds")
            if inv.updated_at
            else "",
            "dump_count": inv.dump_count,
            "total_bytes": inv.total_bytes,
            "process_count": inv.process_count,
        },
        custody=_custody(inv),
        method=_method(inv, triage),
        stats=dashboard.get("risk_summary") or {},
        findings=[dict(narrative.finding(o), ref=evidence_ref(o)) for o in scored],
        attack=attack,
        deep_dives=deep_dives,
        exhibits=collected_exhibits if audience == TECHNICAL else [],
        # Counted before the executive risk-band cut, so both audiences disclose
        # the same denominator for the analyst's selection.
        scored_total=total_scored,
        refs=[
            {"object_type": o.get("object_type"), "key": o.get("key"),
             "label": o.get("label"), "ref": evidence_ref(o)}
            for o in all_scored
        ],
        analyst=dict(analyst or {}),
        narration=dict(narration or {}),
        limitations=dashboard.get("disclaimer") or triage.get("disclaimer") or {},
    )
    _apply_curation(doc)
    doc.stages = stages_mod.group(doc.findings)
    doc.progression = stages_mod.progression_sentence(doc.stages)
    doc.overview = narrative.overview(doc.stats, total_scored, len(attack))
    doc.notices = _notices(inv, dashboard, deep_dives)
    _attach_notes(doc)
    _attach_narration(doc)
    if doc.narration.get("attached"):
        # Disclosed with the other statements that change how the document is
        # read, not in a footnote: a reader who cannot tell measured output from
        # generated prose is reading a different document than the one produced.
        author = doc.narration.get("model") or "a language model"
        via = doc.narration.get("provider")
        doc.notices.append(
            "Passages marked as drafted narrative were written by "
            f"{author}{f' via {via}' if via else ''} from the findings in this "
            "report. They explain and connect the evidence; they are not "
            "themselves evidence, and no measured value, score or ATT&CK "
            "mapping in this document came from them."
        )
    doc.sections = _sections(audience, doc)
    return doc

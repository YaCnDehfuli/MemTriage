"""Deterministic prose from the scoring engine's own explanations.

Every rule in :mod:`..scoring.catalog` already records an analyst-facing evidence
string that quotes the artifact it fired on ("svchost.exe running from
C:\\Users\\...; expected under C:\\Windows\\System32"). A readable findings section
is therefore a rendering problem, not a writing problem: group the contributions
back onto their object, order them by weight, and join them.

The vocabulary here is deliberately constrained to what docs/METHODOLOGY.md says
each phase can support — phase 1 produces *leads*, phase 2 produces *observations*,
and neither establishes that a host was compromised. Nothing in this module may
assert a conclusion the engine did not measure.
"""
from __future__ import annotations

RISK_ORDER = ("Critical", "High", "Medium", "Low")
_RISK_RANK = {r: i for i, r in enumerate(RISK_ORDER)}

# Phrasing per risk band. These describe the *engine's* output, not a verdict.
_RISK_PHRASE = {
    "Critical": "warrants immediate examination",
    "High": "warrants examination",
    "Medium": "is worth reviewing",
    "Low": "is recorded for completeness",
}

_OBJECT_NOUN = {
    "process": "process",
    "injection": "injected memory region",
    "connection": "network connection",
    "persistence": "persistence entry",
}


def risk_rank(risk: str) -> int:
    """Sort key: Critical first, unknown bands last."""
    return _RISK_RANK.get(str(risk), len(RISK_ORDER))


def object_noun(object_type: str) -> str:
    return _OBJECT_NOUN.get(str(object_type), str(object_type) or "object")


def headline(obj: dict) -> str:
    """One sentence placing the object, its band and how it scored."""
    noun = object_noun(obj.get("object_type", ""))
    risk = str(obj.get("risk") or "Low")
    phrase = _RISK_PHRASE.get(risk, "is recorded")
    score = obj.get("score")
    confidence = obj.get("confidence")
    parts = [f"This {noun} scored {risk} and {phrase}."]
    if isinstance(score, int | float):
        parts.append(f"Weighted score {score:g}.")
    if isinstance(confidence, int | float):
        parts.append(f"Aggregate source confidence {confidence * 100:.0f}%.")
    return " ".join(parts)


def reasons(contributions: list[dict]) -> list[str]:
    """Flatten the contributions back into a list of plain reasons.

    ``volmemlyzer_adapter`` joins several independent signals into one evidence
    field with " | " (see its network/persistence builders). Splitting on that
    separator recovers the original list so the prose reads as sentences rather
    than as a machine-delimited field. The separator is always spaced, so a bare
    pipe inside a path or a composite key is never split by accident.
    """
    out: list[str] = []
    for c in contributions:
        text = str(c.get("evidence") or "").strip()
        if not text:
            continue
        for part in text.split(" | "):
            part = part.strip().rstrip(".")
            if part:
                out.append(part)
    return out


def rationale(obj: dict) -> str:
    """Why the engine scored it that way, in the rules' own words."""
    contributions = obj.get("contributions") or []
    if not contributions:
        return (
            "No rule recorded a contribution for this object; it appears here "
            "because it was carried into the scored set by correlation."
        )
    count = len(contributions)
    lead = "One rule fired" if count == 1 else f"{count} independent rules fired"
    found = reasons(contributions)
    if not found:
        return f"{lead}, without a recorded evidence string."
    if len(found) == 1:
        return f"{lead}: {found[0]}."
    joined = "; ".join(found[:-1])
    return f"{lead}: {joined}; and {found[-1]}."


def techniques_sentence(obj: dict) -> str:
    """The ATT&CK mapping, named rather than listed as bare ids."""
    seen: dict[str, str] = {}
    for c in obj.get("contributions") or []:
        mitre = c.get("mitre") or {}
        tid = str(mitre.get("technique_id") or "").strip()
        if tid and tid not in seen:
            seen[tid] = str(mitre.get("technique_name") or "").strip()
    if not seen:
        return ""
    named = [f"{tid} ({name})" if name else tid for tid, name in seen.items()]
    return f"The behaviour maps to {', '.join(named)}."


def finding(obj: dict) -> dict:
    """One rendered finding: the object, plus the prose that explains it."""
    return {
        "object": obj,
        "headline": headline(obj),
        "rationale": rationale(obj),
        "techniques": techniques_sentence(obj),
    }


def overview(stats: dict, finding_count: int, technique_count: int) -> str:
    """The paragraph that opens both documents.

    Written to be true when nothing was found, which is the common case on a
    clean image and the one a generated summary usually gets wrong.
    """
    by_risk = (stats or {}).get("by_risk") or {}
    elevated = sum(int(by_risk.get(r, 0) or 0) for r in ("Critical", "High"))
    if finding_count == 0:
        return (
            "Triage completed and produced no scored objects. That is not a "
            "finding of absence: it means the rules in this catalogue did not "
            "fire on the artifacts extracted from this image."
        )
    bands = ", ".join(
        f"{int(by_risk.get(r, 0) or 0)} {r}" for r in RISK_ORDER if by_risk.get(r)
    )
    lead = (
        f"Triage scored {finding_count} object{'s' if finding_count != 1 else ''}"
        f"{f' ({bands})' if bands else ''}"
    )
    if technique_count:
        lead += (
            f", mapping to {technique_count} ATT&CK "
            f"technique{'s' if technique_count != 1 else ''}"
        )
    lead += "."
    if elevated:
        lead += (
            f" {elevated} object{'s' if elevated != 1 else ''} scored High or "
            "Critical."
        )
    else:
        lead += (
            " Nothing scored above Medium; the objects below are leads to rule "
            "out rather than indications of compromise."
        )
    return lead

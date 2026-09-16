"""Attack progression: the spine that turns a finding list into a narrative.

A real DFIR report organises findings by how the intrusion unfolded, not by
artifact type. MemTriage already has the ordering it needs for that: every rule
in the catalogue carries an ATT&CK tactic, and every scored object aggregates
its rules' tactics. Sorting those tactics into ATT&CK's own order produces the
attack progression deterministically, with no analyst input.

What this does *not* do is claim the stages happened in this order, or that they
are one campaign. It groups evidence under the stage each rule aligns with —
which is framework alignment, the same qualification pipeline/attack.py already
makes. The analyst's note is what turns alignment into a claim about sequence.
"""
from __future__ import annotations

from . import narrative

# ATT&CK enterprise tactic order. A finding's stage is the earliest tactic it
# aligns with, so an object tagged both Execution and Defense Evasion is told as
# part of the execution step rather than being repeated in two places.
TACTIC_ORDER: tuple[str, ...] = (
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
)
_TACTIC_RANK = {t: i for i, t in enumerate(TACTIC_ORDER)}

UNMAPPED = "Unmapped"

# What each stage means, in one line, for a reader who does not know ATT&CK.
# Only stages that actually have findings are ever rendered, so an unused entry
# costs nothing.
STAGE_BLURB: dict[str, str] = {
    "Reconnaissance": "Gathering information about the target before access.",
    "Resource Development": "Building or acquiring the infrastructure used in the intrusion.",
    "Initial Access": "How the intruder first got onto the host.",
    "Execution": "Attacker-controlled code being run on the host.",
    "Persistence": "Keeping access across reboots and logons.",
    "Privilege Escalation": "Obtaining higher permissions than were first held.",
    "Defense Evasion": "Avoiding detection by security controls and by an examiner.",
    "Credential Access": "Stealing account names, passwords or tokens.",
    "Discovery": "Surveying the host and the network from inside.",
    "Lateral Movement": "Moving from this host to others.",
    "Collection": "Gathering data of interest prior to exfiltration.",
    "Command and Control": "Communicating with attacker-operated infrastructure.",
    "Exfiltration": "Moving collected data out of the environment.",
    "Impact": "Disrupting, destroying or manipulating systems and data.",
    UNMAPPED: "Findings the rule catalogue did not align to an ATT&CK tactic.",
}


def _split(raw: str) -> list[str]:
    """One rule may name several tactics ("Defense Evasion, Privilege Escalation")."""
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


def tactics_of(obj: dict) -> list[str]:
    """Every tactic a scored object aligns with, deduplicated, in ATT&CK order."""
    seen: list[str] = []
    for raw in obj.get("tactics") or []:
        for tactic in _split(raw):
            if tactic in _TACTIC_RANK and tactic not in seen:
                seen.append(tactic)
    # Fall back to the contributions when the aggregate is absent or unrecognised.
    if not seen:
        for c in obj.get("contributions") or []:
            for tactic in _split((c.get("mitre") or {}).get("tactic")):
                if tactic in _TACTIC_RANK and tactic not in seen:
                    seen.append(tactic)
    return sorted(seen, key=lambda t: _TACTIC_RANK[t])


def stage_of(obj: dict) -> str:
    """The single stage this finding is told under: its earliest aligned tactic."""
    tactics = tactics_of(obj)
    return tactics[0] if tactics else UNMAPPED


def group(findings: list[dict]) -> list[dict]:
    """Bucket rendered findings into attack stages, in progression order.

    Only stages with findings are returned, so a light triage produces a short
    narrative rather than a page of empty headings.
    """
    buckets: dict[str, list[dict]] = {}
    for f in findings:
        buckets.setdefault(stage_of(f["object"]), []).append(f)

    stages = []
    for tactic in (*TACTIC_ORDER, UNMAPPED):
        items = buckets.get(tactic)
        if not items:
            continue
        items.sort(
            key=lambda f: (
                narrative.risk_rank(f["object"].get("risk", "")),
                -(f["object"].get("score") or 0),
            )
        )
        highest = min(
            (narrative.risk_rank(f["object"].get("risk", "")) for f in items),
            default=len(narrative.RISK_ORDER),
        )
        techniques: list[str] = []
        for f in items:
            for t in f["object"].get("techniques") or []:
                if t not in techniques:
                    techniques.append(t)
        stages.append({
            "tactic": tactic,
            "blurb": STAGE_BLURB.get(tactic, ""),
            "findings": items,
            "count": len(items),
            "techniques": techniques,
            "highest_risk": (
                narrative.RISK_ORDER[highest]
                if highest < len(narrative.RISK_ORDER)
                else ""
            ),
        })
    return stages


def progression_sentence(stages: list[dict]) -> str:
    """One line naming the stages evidence was found for, in order.

    Deliberately describes coverage, not causation — nothing here establishes
    that one stage led to the next. That claim is the analyst's to make.
    """
    named = [s["tactic"] for s in stages if s["tactic"] != UNMAPPED]
    if not named:
        return (
            "No finding aligned to an ATT&CK tactic, so no attack progression "
            "can be laid out from this triage alone."
        )
    if len(named) == 1:
        return (
            f"Evidence in this image aligns with a single stage, {named[0]}. "
            "A single stage is a lead, not a sequence."
        )
    return (
        "Evidence in this image aligns with "
        f"{' → '.join(named)}. "
        "These are framework alignments listed in ATT&CK order, not a "
        "demonstrated sequence; establishing that one stage led to the next "
        "requires the analyst's correlation and corroborating disk or network "
        "telemetry."
    )

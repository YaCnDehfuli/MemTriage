"""MITRE ATT&CK alignment for triage artifacts.

This maps *artifacts VolMemLyzer surfaces* to the ATT&CK techniques they align
with — it is framework alignment for an analyst, not a claim of confirmed
detection. Each entry carries the technique id, name, tactic, and the concrete
evidence (which artifact and how many) that triggered it.
"""
from __future__ import annotations


def _tech(tid: str, name: str, tactic: str, evidence: str) -> dict:
    return {"technique_id": tid, "name": name, "tactic": tactic, "evidence": evidence}


def map_techniques(dashboard: dict) -> list[dict]:
    """Derive aligned ATT&CK techniques from a triage dashboard."""
    out: list[dict] = []

    injections = dashboard.get("injections") or []
    if injections:
        out.append(_tech(
            "T1055", "Process Injection", "Defense Evasion, Privilege Escalation",
            f"{len(injections)} RWX/anomalous memory region(s) surfaced by malfind",
        ))

    suspicious = dashboard.get("suspicious_processes") or []
    if any("hollow" in " ".join(p.get("flags", [])).lower() for p in suspicious):
        out.append(_tech(
            "T1055.012", "Process Hollowing", "Defense Evasion, Privilege Escalation",
            "Process(es) flagged with hollowing indicators (image/VAD mismatch)",
        ))
    if any("masquerad" in " ".join(p.get("flags", [])).lower() for p in suspicious):
        out.append(_tech(
            "T1036", "Masquerading", "Defense Evasion",
            "Process name/path anomalies flagged during triage",
        ))

    if dashboard.get("network"):
        out.append(_tech(
            "T1071", "Application Layer Protocol", "Command and Control",
            f"{len(dashboard['network'])} active/suspect network connection(s) (netscan)",
        ))

    persistence = dashboard.get("persistence") or []
    if persistence:
        out.append(_tech(
            "T1547", "Boot or Logon Autostart Execution", "Persistence",
            f"{len(persistence)} autostart/persistence indicator(s)",
        ))
    if any("service" in str(i.get("kind", "")).lower() for i in persistence):
        out.append(_tech(
            "T1543.003", "Create or Modify System Process: Windows Service",
            "Persistence, Privilege Escalation", "Suspicious service registration",
        ))

    return out

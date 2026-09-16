"""Live tuning: re-score cached triage artifacts under a new profile.

The IoC table must update as the analyst moves the sensitivity preset or a
per-rule control — but re-running Volatility per slider move is impossible on a
multi-GB image. Triage therefore caches every plugin's raw JSON once; this
endpoint rebuilds the scoring context from that cache and re-runs the (pure)
engine in milliseconds, returning the new scored table plus a diff of what changed
so the UI can highlight it. The chosen profile is persisted per investigation.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..db import get_session
from ..models import Investigation, InvestigationStatus
from ..pipeline import volmemlyzer_adapter as vml
from ..scoring import diff_scored
from ..security.sanitize import sanitize_obj
from ..storage import InvestigationPaths

router = APIRouter(prefix="/api", tags=["scoring"])


class RescoreRequest(BaseModel):
    profile: dict | None = None


@router.post("/investigations/{investigation_id}/rescore")
def rescore(
    investigation_id: str,
    body: RescoreRequest,
    session: Session = Depends(get_session),
) -> dict:
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if inv.status != InvestigationStatus.TRIAGED:
        raise HTTPException(status_code=409, detail="Triage not complete")

    paths = InvestigationPaths(investigation_id)
    if not paths.triage.exists():
        raise HTTPException(status_code=409, detail="No triage artifacts to re-score")

    triage = json.loads(paths.triage.read_text())
    manifest = triage.get("artifacts") or {}
    if not manifest:
        raise HTTPException(
            status_code=409,
            detail="Triage predates cached artifacts; re-run triage to enable tuning.",
        )

    try:
        records = vml.load_cached_records(paths.volmemlyzer, manifest)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=(
                "A cached plugin artifact is missing or invalid; rerun triage "
                "to rebuild the evidence before re-scoring."
            ),
        ) from exc
    prev_scored = (triage.get("dashboard") or {}).get("scored_objects") or []
    features = (triage.get("dashboard") or {}).get("features") or {}

    view = vml.rescore_from_records(
        records, features, vol_version=triage.get("vol_version"), profile=body.profile,
        plugins=(triage.get("triage_config") or {}).get("plugins") or list(manifest),
    )
    new_dashboard = view["dashboard"]
    diff = diff_scored(prev_scored, new_dashboard["scored_objects"])

    # Persist the re-scored view + chosen profile (sanitized — artifact-derived).
    triage["dashboard"] = new_dashboard
    triage["processes"] = view["processes"]
    triage["profile"] = view["profile"]
    triage = sanitize_obj(triage)
    paths.triage.write_text(json.dumps(triage, indent=2))
    # result.json embeds a copy of the triage view and is what a reloaded page
    # reads; left alone, a reload would show scores from before this re-score.
    if paths.result.exists():
        try:
            bundle = json.loads(paths.result.read_text())
        except ValueError:
            bundle = None
        if isinstance(bundle, dict):
            bundle["triage"] = triage
            paths.result.write_text(json.dumps(bundle, indent=2))

    inv.summary = {
        **(inv.summary or {}),
        "flagged": len(new_dashboard["suspicious_processes"]),
        "attack_techniques": len(new_dashboard["attack_techniques"]),
        "risk_summary": new_dashboard.get("risk_summary", {}),
    }
    session.add(inv)
    session.commit()

    return sanitize_obj({
        "investigation_id": investigation_id,
        "profile": view["profile"],
        "risk_summary": new_dashboard["risk_summary"],
        "attack_techniques": new_dashboard["attack_techniques"],
        "scored_objects": new_dashboard["scored_objects"],
        "suspicious_processes": new_dashboard["suspicious_processes"],
        # The process inventory (Phase 1 → 2 · Select) enriches each row with
        # risk/score/confidence from this same re-score; without it here, that
        # step keeps showing the verdicts from the first triage run forever.
        "processes": view["processes"],
        "diff": diff,
        "disclaimer": new_dashboard.get("disclaimer"),
        "unevaluated_sources": new_dashboard.get("unevaluated_sources") or [],
    })

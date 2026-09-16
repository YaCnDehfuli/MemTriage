"""A queued triage must say what it is waiting behind.

The worker runs one task at a time, so a queued run can wait hours behind a Deep
triage. A bare "Queued" is indistinguishable from a hang.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from memtriage.db import SessionLocal
from memtriage.models import Investigation, InvestigationStatus


def _investigation(session, *, stage: str, message: str, updated_at: datetime) -> str:
    inv = Investigation(
        id=str(uuid.uuid4()), status=InvestigationStatus.TRIAGING, stage=stage,
        message=message, triage_mode="deep", updated_at=updated_at,
    )
    session.add(inv)
    session.commit()
    return inv.id


def test_a_queued_triage_names_the_running_job_and_its_place_in_line(client):
    now = datetime.now(UTC)
    session = SessionLocal()
    try:
        busy = _investigation(session, stage="analyzing", updated_at=now,
                              message="Volatility 3 is still working (psxview)")
        earlier = _investigation(session, stage="queued", message="Queued light triage",
                                 updated_at=now - timedelta(minutes=5))
        mine = _investigation(session, stage="queued", message="Queued light triage",
                              updated_at=now - timedelta(minutes=1))
    finally:
        session.close()

    queue = client.get(f"/api/investigations/{mine}").json()["queue"]
    running = {job["investigation_id"]: job for job in queue["running"]}
    assert busy in running
    assert running[busy]["message"] == "Volatility 3 is still working (psxview)"
    assert mine not in running and earlier not in running
    assert queue["waiting_ahead"] >= 1, "the run queued five minutes earlier is ahead"

    # The earlier run is not behind the later one.
    earlier_queue = client.get(f"/api/investigations/{earlier}").json()["queue"]
    assert earlier_queue["waiting_ahead"] < queue["waiting_ahead"]


def test_a_running_triage_carries_no_queue_context(client):
    session = SessionLocal()
    try:
        running = _investigation(session, stage="analyzing", message="working",
                                 updated_at=datetime.now(UTC))
    finally:
        session.close()
    assert client.get(f"/api/investigations/{running}").json()["queue"] is None

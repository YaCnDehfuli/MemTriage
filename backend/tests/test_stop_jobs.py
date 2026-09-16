"""Stopping triage and manual plugin runs, from the API through the worker task.

The mid-run tests use a stand-in Volatility pass that launches a real
long-running process, because the failure being prevented is a job that keeps
its processes — and the worker's only slot — after the analyst asked it to stop.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime, timedelta

from memtriage.db import SessionLocal
from memtriage.models import Investigation, InvestigationStatus, PluginRun, PluginRunStatus


def _investigation(client) -> str:
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    r = client.post(f"/api/investigations/{inv_id}/dumps", content=b"x" * 64,
                    headers={"X-Filename": "mem.raw"})
    assert r.status_code == 201
    return inv_id


def _update(model, row_id: str, **values) -> None:
    session = SessionLocal()
    try:
        row = session.get(model, row_id)
        for key, value in values.items():
            setattr(row, key, value)
        session.commit()
    finally:
        session.close()


def _row(model, row_id: str):
    session = SessionLocal()
    try:
        row = session.get(model, row_id)
        session.expunge(row)
        return row
    finally:
        session.close()


def _dead(pid: int, timeout: float = 15.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                return True
        except ChildProcessError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
        time.sleep(0.05)
    return False


# --------------------------------------------------------------------------
# API: triage
# --------------------------------------------------------------------------

def test_starting_triage_issues_a_fresh_token_and_sends_it(client, monkeypatch):
    from memtriage.workers import celery_app as ca

    sent: list[list] = []
    monkeypatch.setattr(ca.celery_app, "send_task", lambda name, args: sent.append(args))
    inv_id = _investigation(client)
    _update(Investigation, inv_id, cancel_requested=True)

    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})
    first = _row(Investigation, inv_id)
    assert first.cancel_requested is False, "a new run must not inherit an old stop"
    assert sent[-1] == [inv_id, False, first.triage_token]


def test_stopping_a_queued_triage_finishes_it_immediately(client):
    inv_id = _investigation(client)
    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})

    body = client.post(f"/api/investigations/{inv_id}/triage/stop").json()
    assert body["status"] == "received" and body["stage"] == "stopped"
    assert body["message"].startswith("Triage stopped before it started")
    row = _row(Investigation, inv_id)
    assert row.triage_token is None, "the queued message must become stale"
    assert row.cancel_requested is True, "kept, in case the worker took it this instant"


def test_a_running_triage_with_a_live_worker_is_asked_to_stop(client):
    inv_id = _investigation(client)
    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})
    _update(Investigation, inv_id, stage="analyzing", worker_seen_at=datetime.now(UTC))

    body = client.post(f"/api/investigations/{inv_id}/triage/stop").json()
    assert body["status"] == "triaging" and body["stage"] == "stopping"
    assert _row(Investigation, inv_id).cancel_requested is True


def test_a_running_triage_whose_worker_died_is_finished_by_the_api(client):
    inv_id = _investigation(client)
    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})
    _update(Investigation, inv_id, stage="analyzing",
            worker_seen_at=datetime.now(UTC) - timedelta(minutes=30))

    body = client.post(f"/api/investigations/{inv_id}/triage/stop").json()
    assert body["status"] == "received" and body["stage"] == "stopped"
    assert "no worker" in body["message"]


def test_stopping_returns_to_previous_results_when_they_exist(client):
    from memtriage.storage import InvestigationPaths

    inv_id = _investigation(client)
    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})
    InvestigationPaths(inv_id).ensure().triage.write_text("{}")

    body = client.post(f"/api/investigations/{inv_id}/triage/stop").json()
    assert body["status"] == "triaged"
    assert "previous results" in body["message"]


def test_stopping_when_nothing_is_running_is_a_conflict(client):
    inv_id = _investigation(client)
    assert client.post(f"/api/investigations/{inv_id}/triage/stop").status_code == 409
    assert client.post("/api/investigations/nope/triage/stop").status_code == 404


# --------------------------------------------------------------------------
# Worker: triage
# --------------------------------------------------------------------------

def test_a_stale_queued_message_never_runs(client):
    from memtriage.workers.tasks import run_triage

    inv_id = _investigation(client)
    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})
    token = _row(Investigation, inv_id).triage_token

    # The analyst restarted: a newer token replaced this message's.
    _update(Investigation, inv_id, triage_token="newer")
    assert run_triage.apply(args=[inv_id, False, token]).get() == "superseded"
    assert _row(Investigation, inv_id).stage == "queued", "a stale message changes nothing"


def test_a_running_triage_kills_volatility_and_ends_stopped(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    started: dict[str, int] = {}

    def fake_triage(*args, **kwargs):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        started["pid"] = proc.pid
        proc.wait(timeout=60)
        return {"dashboard": {}, "processes": [], "extraction": {"failed_plugins": {}}}

    monkeypatch.setattr(vml, "run_triage", fake_triage)
    inv_id = _investigation(client)
    client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light", "force": True})
    token = _row(Investigation, inv_id).triage_token

    result: dict[str, str] = {}
    task = threading.Thread(
        target=lambda: result.update(value=run_triage.apply(args=[inv_id, True, token]).get()),
    )
    task.start()
    deadline = time.monotonic() + 30
    while "pid" not in started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert "pid" in started, "the fake Volatility pass never started"

    _update(Investigation, inv_id, cancel_requested=True)
    task.join(timeout=60)

    assert not task.is_alive(), "the task must return once stopped"
    assert result["value"] == "stopped"
    assert _dead(started["pid"]), "the Volatility process must not outlive the stop"
    row = _row(Investigation, inv_id)
    assert row.status == InvestigationStatus.RECEIVED and row.stage == "stopped"
    assert row.cancel_requested is False
    assert any(e.get("type") == "stopped" for e in row.events)


# --------------------------------------------------------------------------
# API + worker: manual plugin runs
# --------------------------------------------------------------------------

def _plugin_run(client, inv_id: str) -> str:
    _update(Investigation, inv_id, status=InvestigationStatus.TRIAGED)
    r = client.post(f"/api/investigations/{inv_id}/plugins/run",
                    json={"plugins": ["windows.pslist"], "concurrency": 1})
    if r.status_code != 201:
        catalog = client.get("/api/plugins/catalog").json()
        r = client.post(f"/api/investigations/{inv_id}/plugins/run",
                        json={"plugins": [catalog[0]["name"]], "concurrency": 1})
    assert r.status_code == 201, r.text
    return r.json()["plugin_run_id"]


def test_stopping_a_queued_plugin_run_cancels_it(client):
    inv_id = _investigation(client)
    run_id = _plugin_run(client, inv_id)
    body = client.post(f"/api/investigations/{inv_id}/plugins/runs/{run_id}/stop").json()
    assert body["status"] == "cancelled" and body["message"] == "Stopped before it started"

    # A cancelled run frees the investigation for the next one.
    assert client.post(f"/api/investigations/{inv_id}/plugins/runs/{run_id}/stop").status_code == 409
    assert client.post(f"/api/investigations/other/plugins/runs/{run_id}/stop").status_code == 404


def test_a_running_plugin_run_kills_volatility_and_ends_cancelled(client, monkeypatch):
    from memtriage.pipeline import plugin_runner as pr
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_plugins

    started: dict[str, int] = {}

    def fake_run(pipe, image_path, outdir, names, concurrency, on_event):
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        started["pid"] = proc.pid
        proc.wait(timeout=60)
        return {"plugins": {}, "failed_plugins": dict.fromkeys(names, "vol exited -15")}

    monkeypatch.setattr(pr, "run_selected_plugins", fake_run)
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: object())
    inv_id = _investigation(client)
    run_id = _plugin_run(client, inv_id)

    result: dict[str, str] = {}
    task = threading.Thread(
        target=lambda: result.update(value=run_plugins.apply(args=[run_id]).get()),
    )
    task.start()
    deadline = time.monotonic() + 30
    while "pid" not in started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert "pid" in started

    # The API decides live vs dead from the watcher's liveness write.
    assert _row(PluginRun, run_id).worker_seen_at is not None
    body = client.post(f"/api/investigations/{inv_id}/plugins/runs/{run_id}/stop").json()
    assert body["stage"] == "stopping"
    task.join(timeout=60)

    assert result["value"] == "stopped"
    assert _dead(started["pid"])
    row = _row(PluginRun, run_id)
    assert row.status == PluginRunStatus.CANCELLED
    assert row.message.startswith("Stopped by the analyst")

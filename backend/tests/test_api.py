"""API plumbing tests: health, multi-dump upload validation, and the two-phase
(triage → process selection → VADViT analysis) investigation lifecycle."""


def _new_investigation(client) -> str:
    resp = client.post("/api/investigations")
    assert resp.status_code == 201
    return resp.json()["investigation_id"]


def _add_dump(client, inv_id, content=b"RAWMEMORYIMAGE-not-a-deny-magic", name="mem.raw"):
    return client.post(
        f"/api/investigations/{inv_id}/dumps", content=content, headers={"X-Filename": name}
    )


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["service"] == "MemTriage"


def test_dump_rejects_bad_extension(client):
    inv_id = _new_investigation(client)
    resp = _add_dump(client, inv_id, content=b"MZ\x90 nope", name="sample.exe")
    assert resp.status_code == 415


def test_dump_rejects_archive_magic(client):
    inv_id = _new_investigation(client)
    resp = _add_dump(client, inv_id, content=b"PK\x03\x04zip", name="dump.raw")
    assert resp.status_code == 415


def test_dump_rejects_empty(client):
    inv_id = _new_investigation(client)
    resp = _add_dump(client, inv_id, content=b"", name="dump.raw")
    assert resp.status_code == 400


def test_dump_enforces_size_cap(client, monkeypatch):
    from memtriage.api import routes_investigations

    monkeypatch.setattr(routes_investigations.settings, "max_upload_bytes", 8)
    inv_id = _new_investigation(client)
    resp = _add_dump(client, inv_id, content=b"way more than eight bytes here")
    assert resp.status_code == 413


def test_dump_cap_per_investigation(client, monkeypatch):
    from memtriage.api import routes_investigations

    monkeypatch.setattr(routes_investigations.settings, "max_dumps_per_investigation", 2)
    inv_id = _new_investigation(client)
    assert _add_dump(client, inv_id, name="s0.raw").status_code == 201
    assert _add_dump(client, inv_id, name="s1.raw").status_code == 201
    # third snapshot exceeds the cap
    assert _add_dump(client, inv_id, name="s2.raw").status_code == 409


def test_full_two_phase_lifecycle(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_process_analysis, run_triage

    # Mock the Volatility boundary (no volmemlyzer/memory image in unit tests).
    monkeypatch.setattr(vml, "run_triage", lambda *a, **k: {
        "features": {}, "vol_version": None, "processes": [],
        "dashboard": {"features": {}, "suspicious_processes": [], "injections": [],
                      "network": [], "persistence": [], "attack_techniques": []},
    })

    # Phase 0: create + upload two interval snapshots.
    inv_id = _new_investigation(client)
    assert _add_dump(client, inv_id, name="snap0.raw").json()["ordinal"] == 0
    assert _add_dump(client, inv_id, name="snap1.raw").json()["dump_count"] == 2

    # Start triage (broker stubbed) then run it synchronously.
    started = client.post(f"/api/investigations/{inv_id}/triage")
    assert started.status_code == 200
    assert started.json()["stage"] == "queued"
    run_triage.apply(args=[inv_id])

    state = client.get(f"/api/investigations/{inv_id}").json()
    assert state["status"] == "triaged"
    assert state["has_triage"] is True

    # Process inventory endpoint works (empty scaffold in M1).
    procs = client.get(f"/api/investigations/{inv_id}/processes")
    assert procs.status_code == 200
    assert procs.json() == []

    # Phase 2: select a process and run its analysis synchronously.
    sel = client.post(
        f"/api/investigations/{inv_id}/processes/analyze", json={"pid": 1337}
    )
    assert sel.status_code == 200
    analysis_id = sel.json()["analysis_id"]
    assert sel.json()["status"] == "queued"
    run_process_analysis.apply(args=[analysis_id])

    a = client.get(f"/api/investigations/{inv_id}/analyses/{analysis_id}").json()
    assert a["status"] == "done"
    assert a["model_loaded"] is False  # no checkpoint => never a fake verdict

    # Consolidated result includes triage + the process analysis.
    result = client.get(f"/api/investigations/{inv_id}/result").json()
    assert "triage" in result
    assert len(result["process_analyses"]) == 1


def test_processes_require_triage(client):
    inv_id = _new_investigation(client)
    _add_dump(client, inv_id)
    # Triage not run yet.
    assert client.get(f"/api/investigations/{inv_id}/processes").status_code == 409


def test_unknown_investigation_is_404(client):
    assert client.get("/api/investigations/does-not-exist").status_code == 404

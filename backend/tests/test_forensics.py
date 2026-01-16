"""VolMemLyzer adapter transforms, ATT&CK mapping, and the wired triage task."""
from memtriage.pipeline import attack
from memtriage.pipeline.volmemlyzer_adapter import (
    dashboard_from,
    injections_from_malfind,
    inventory_from_pslist,
    network_from_netscan,
)


def test_inventory_marks_suspicious_and_non_analyzable_and_sorts():
    records = [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 1234, "PPID": 600, "ImageFileName": "evil.exe"},
        {"PID": 800, "PPID": 600, "ImageFileName": "explorer.exe"},
    ]
    inv = inventory_from_pslist(records, suspicious_pids={1234})
    by_pid = {p["pid"]: p for p in inv}
    assert by_pid[4]["analyzable"] is False          # System has no user VADs
    assert by_pid[1234]["risk"] == "suspicious"
    assert "suspicious" in by_pid[1234]["flags"]
    assert by_pid[800]["analyzable"] is True and by_pid[800]["risk"] is None
    assert [p["pid"] for p in inv] == [4, 800, 1234]  # sorted by pid


def test_injections_tolerates_field_name_drift():
    out = injections_from_malfind([
        {"PID": 1234, "Process": "evil.exe", "Protection": "PAGE_EXECUTE_READWRITE"},
    ])
    assert out[0]["pid"] == 1234
    assert out[0]["protection"] == "PAGE_EXECUTE_READWRITE"


def test_network_parsing():
    out = network_from_netscan([
        {"PID": 5, "Proto": "TCPv4", "LocalAddr": "10.0.0.1", "LocalPort": 50000,
         "ForeignAddr": "1.2.3.4", "ForeignPort": 443, "State": "ESTABLISHED"},
    ])
    assert out[0]["foreign_addr"] == "1.2.3.4"
    assert out[0]["state"] == "ESTABLISHED"


def test_attack_mapping_from_signals():
    techs = attack.map_techniques({
        "injections": [{"pid": 1}],
        "network": [{"pid": 2}],
        "suspicious_processes": [{"flags": ["possible hollowing"]}],
        "persistence": [],
    })
    ids = {t["technique_id"] for t in techs}
    assert {"T1055", "T1071", "T1055.012"} <= ids


def test_dashboard_from_includes_features_and_attack():
    d = dashboard_from({"malfind.ninjections": 3}, injections=[{"pid": 1}],
                       network=[], suspicious_processes=[])
    assert d["features"]["malfind.ninjections"] == 3
    assert any(t["technique_id"] == "T1055" for t in d["attack_techniques"])


def test_triage_task_wires_adapter_and_sanitizes(client, monkeypatch):
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"RAWMEM",
                headers={"X-Filename": "m.raw"})

    from memtriage.pipeline import volmemlyzer_adapter as vml

    def fake_run_triage(image_path, artifacts_dir, *, vol_path, timeout_s):
        return {
            "features": {"pslist.nproc": 42},
            "dashboard": {
                "features": {"pslist.nproc": 42},
                "suspicious_processes": [{"pid": 1337, "name": "evil", "flags": ["suspicious"]}],
                "injections": [{"pid": 1337, "process": "evil", "protection": "PAGE_EXECUTE_READWRITE"}],
                "network": [],
                "persistence": [],
                "attack_techniques": [
                    {"technique_id": "T1055", "name": "Process Injection",
                     "tactic": "Defense Evasion", "evidence": "1 region"},
                ],
            },
            # control char in a process name must be stripped before render
            "processes": [{"pid": 1337, "name": "evil\x00<script>", "ppid": 4,
                           "risk": "suspicious", "flags": ["suspicious"], "analyzable": True}],
            "vol_version": "Volatility 3 Framework 2.26.2",
        }

    monkeypatch.setattr(vml, "run_triage", fake_run_triage)

    from memtriage.workers.tasks import run_triage
    run_triage.apply(args=[inv_id])

    state = client.get(f"/api/investigations/{inv_id}").json()
    assert state["status"] == "triaged"
    assert state["process_count"] == 1

    procs = client.get(f"/api/investigations/{inv_id}/processes").json()
    assert procs[0]["pid"] == 1337
    assert "\x00" not in procs[0]["name"]  # sanitized

    result = client.get(f"/api/investigations/{inv_id}/result").json()
    techs = result["triage"]["dashboard"]["attack_techniques"]
    assert techs[0]["technique_id"] == "T1055"

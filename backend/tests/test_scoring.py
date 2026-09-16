"""Scoring engine: per-rule fire/quiet, correlation, presets, the hardened
heuristics (byte-pattern bug fixes), and the live /rescore endpoint (diff +
persistence + sanitization)."""
import json

from memtriage.scoring import diff_scored, score_records
from volmemlyzer.scoring import heuristics as H
from memtriage.storage import InvestigationPaths

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _fired(out: dict, pid: int) -> set[str]:
    return set(out["process_risk"].get(pid, {}).get("flags", []))


def _conn_flags(out: dict) -> set[str]:
    flags = set()
    for o in out["scored_objects"]:
        if o["object_type"] == "connection":
            flags.update(c["rule_id"] for c in o["contributions"])
    return flags


def _persist_flags(out: dict) -> set[str]:
    flags = set()
    for o in out["scored_objects"]:
        if o["object_type"] == "persistence":
            flags.update(c["rule_id"] for c in o["contributions"])
    return flags


# --------------------------------------------------------------------------
# hardened heuristics — the byte-pattern bug fixes
# --------------------------------------------------------------------------

def test_hexdump_parsing_both_layouts():
    plain = "4d 5a 90 00 41 42"
    voly = "0x1f0000  4d 5a 90 00 41 42 43 44 45 46 47 48 49 4a 4b 4c   MZ..ABCDEFGHIJKL"
    assert H.hexdump_to_bytes(plain)[:2] == b"MZ"
    assert H.hexdump_to_bytes(voly)[:2] == b"MZ"
    # the address token is not mistaken for data
    assert H.hexdump_to_bytes(voly)[0] == 0x4D


def test_shellcode_signatures_fire_and_stay_quiet():
    nop = H.hexdump_to_bytes("90 90 90 90 90 90 90 90 c3")
    assert "NOP sled" in H.shellcode_signals(nop)
    meta = H.hexdump_to_bytes("fc e8 82 00 00 00 60 89")
    assert H.shellcode_signals(meta)                      # metasploit prologue
    benign = bytes(range(0, 32))                          # ordered bytes, no sig
    assert H.shellcode_signals(benign) == []


def test_pe_header_and_rwx_helpers():
    assert H.has_pe_header(b"MZ\x90\x00")
    assert not H.has_pe_header(b"ELF")
    assert H.protection_is_rwx("PAGE_EXECUTE_READWRITE")
    assert not H.protection_is_rwx("PAGE_READONLY")


def test_path_classification():
    assert H.not_system_path(r"C:\Users\a\AppData\Local\Temp\x.exe")
    assert not H.not_system_path(r"C:\Windows\System32\svchost.exe")
    assert H.is_suspicious_path(r"C:\Users\a\Downloads\x.exe")
    assert not H.is_suspicious_path(r"C:\Windows\System32\x.exe")


# --------------------------------------------------------------------------
# masquerading / core-process integrity (T1036)
# --------------------------------------------------------------------------

def _svchost(pid, ppid, path, name="svchost.exe"):
    return ({"PID": pid, "PPID": ppid, "ImageFileName": name},
            {"PID": pid, "Args": path})


def test_core_process_wrong_path_fires_and_quiet():
    ps, cmd = _svchost(1337, 600, r"C:\Users\a\AppData\Local\Temp\svchost.exe")
    mal = score_records({"pslist": [ps], "cmdline": [cmd]})
    assert "core_proc_wrong_path" in _fired(mal, 1337)

    ps2, cmd2 = _svchost(900, 600, r"C:\Windows\System32\svchost.exe")
    good = score_records({"pslist": [ps2], "cmdline": [cmd2]})
    assert "core_proc_wrong_path" not in _fired(good, 900)


def test_core_process_wrong_parent():
    recs = {
        "pslist": [
            {"PID": 600, "PPID": 500, "ImageFileName": "explorer.exe"},
            {"PID": 700, "PPID": 600, "ImageFileName": "lsass.exe"},  # lsass under explorer
        ],
        "cmdline": [{"PID": 700, "Args": r"C:\Windows\System32\lsass.exe"}],
    }
    out = score_records(recs)
    assert "core_proc_wrong_parent" in _fired(out, 700)


def test_illegal_singleton_instances():
    recs = {"pslist": [
        {"PID": 700, "PPID": 600, "ImageFileName": "lsass.exe"},
        {"PID": 701, "PPID": 600, "ImageFileName": "lsass.exe"},
    ], "cmdline": [
        {"PID": 700, "Args": r"C:\Windows\System32\lsass.exe"},
        {"PID": 701, "Args": r"C:\Windows\System32\lsass.exe"},
    ]}
    out = score_records(recs)
    assert "core_proc_illegal_instances" in _fired(out, 700)
    assert "core_proc_illegal_instances" in _fired(out, 701)


def test_masquerade_name_near_miss():
    recs = {"pslist": [{"PID": 42, "PPID": 600, "ImageFileName": "scvhost.exe"}]}
    out = score_records(recs)
    assert "core_proc_masquerade_name" in _fired(out, 42)


# --------------------------------------------------------------------------
# discovery + injection (T1014 / T1055)
# --------------------------------------------------------------------------

def test_hidden_process_psscan_only():
    recs = {
        "pslist": [{"PID": 10, "PPID": 4, "ImageFileName": "a.exe"}],
        "psscan": [{"PID": 10, "PPID": 4, "ImageFileName": "a.exe"},
                   {"PID": 999, "PPID": 4, "ImageFileName": "hidden.exe"}],
    }
    out = score_records(recs)
    assert "hidden_process" in _fired(out, 999)
    assert "hidden_process" not in _fired(out, 10)


def test_malfind_rules_fire_on_rwx_pe_shellcode():
    recs = {
        "pslist": [{"PID": 1000, "PPID": 600, "ImageFileName": "app.exe"}],
        "malfind": [{
            "PID": 1000, "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1,
            "File output": "Disabled", "Start VPN": "0x50000",
            "Hexdump": "4d 5a 90 90 90 90 90 90 90 90 90 90 c3 00 00 00",
        }],
    }
    fired = _fired(score_records(recs), 1000)
    assert {"malfind_rwx_private", "malfind_pe_header", "malfind_shellcode"} <= fired


def test_malfind_quiet_on_benign_region():
    recs = {
        "pslist": [{"PID": 1000, "PPID": 600, "ImageFileName": "app.exe"}],
        "malfind": [{
            "PID": 1000, "Protection": "PAGE_READONLY", "PrivateMemory": 0,
            "Start VPN": "0x50000", "Hexdump": "00 01 02 03 04 05 06 07",
        }],
    }
    assert _fired(score_records(recs), 1000) == set()


def test_ldrmodules_unlinked_dll():
    recs = {
        "pslist": [{"PID": 1000, "PPID": 600, "ImageFileName": "app.exe"}],
        "ldrmodules": [{"PID": 1000, "InLoad": False, "MappedPath": r"C:\x\evil.dll"}],
    }
    assert "ldrmodules_unlinked" in _fired(score_records(recs), 1000)


# --------------------------------------------------------------------------
# lineage / credential / privilege
# --------------------------------------------------------------------------

def test_lolbin_from_office():
    recs = {"pslist": [
        {"PID": 500, "PPID": 400, "ImageFileName": "winword.exe"},
        {"PID": 501, "PPID": 500, "ImageFileName": "powershell.exe"},
    ]}
    out = score_records(recs)
    assert "lolbin_from_office" in _fired(out, 501)
    assert "lolbin_from_office" not in _fired(out, 500)


def test_lsass_handle_from_nonsystem():
    recs = {
        "pslist": [{"PID": 1500, "PPID": 600, "ImageFileName": "grabber.exe"}],
        "handles": [{"PID": 1500, "Process": "grabber.exe", "Type": "Process",
                     "Name": "lsass.exe", "GrantedAccess": "0x1410"}],
    }
    assert "lsass_handle" in _fired(score_records(recs), 1500)


def test_token_sedebug_enabled():
    recs = {
        "pslist": [{"PID": 1500, "PPID": 600, "ImageFileName": "tool.exe"}],
        "privileges": [{"PID": 1500, "Privilege": "SeDebugPrivilege",
                        "Attributes": "Present,Enabled"}],
    }
    assert "token_sedebug" in _fired(score_records(recs), 1500)


# --------------------------------------------------------------------------
# network / persistence
# --------------------------------------------------------------------------

def test_network_bad_port_fires_and_common_port_quiet():
    bad = {"netscan": [{"PID": 1, "Proto": "TCPv4", "LocalAddr": "10.0.0.5",
                        "LocalPort": 50000, "ForeignAddr": "93.184.216.34",
                        "ForeignPort": 4444, "State": "ESTABLISHED", "Owner": "x.exe"}]}
    assert "net_bad_port" in _conn_flags(score_records(bad))

    ok = {"netscan": [{"PID": 1, "Proto": "TCPv4", "LocalAddr": "10.0.0.5",
                       "LocalPort": 50000, "ForeignAddr": "93.184.216.34",
                       "ForeignPort": 443, "State": "ESTABLISHED", "Owner": "chrome.exe"}]}
    assert _conn_flags(score_records(ok)) == set()


def test_scheduled_task_and_hive_orphan():
    task = {"scheduled_tasks": [{"Task Name": "Upd", "Action": "powershell.exe",
                                 "Action Arguments": "-nop -w hidden -enc AAAA"}]}
    assert "scheduled_task_suspicious" in _persist_flags(score_records(task))

    hive = {"hivelist": [{"Offset": 100}], "hivescan": [{"Offset": 100}, {"Offset": 200}]}
    assert "hive_orphan" in _persist_flags(score_records(hive))


# --------------------------------------------------------------------------
# correlation, confidence, presets, overrides
# --------------------------------------------------------------------------

def test_correlation_escalates_multisignal_object():
    recs = {
        "pslist": [{"PID": 2000, "PPID": 600, "ImageFileName": "svc.exe"}],
        "malfind": [{"PID": 2000, "Protection": "PAGE_EXECUTE_READWRITE",
                     "PrivateMemory": 1, "Start VPN": "0x9000", "Hexdump": "00 11 22 33"}],
        "ldrmodules": [{"PID": 2000, "InLoad": False, "MappedPath": r"C:\x\a.dll"}],
        "threads": [{"PID": 2000, "StartAddress": "0x9010", "Owner": ""}],
    }
    out = score_records(recs)
    proc = next(o for o in out["scored_objects"] if o["pid"] == 2000)
    corr = [c for c in proc["contributions"] if c["rule_id"].startswith("corr_")]
    assert corr, "correlation should fire on a multi-signal object"
    assert proc["risk"] == "Critical"
    assert proc["confidence"] >= 0.9


def test_confidence_rises_with_independent_corroboration():
    """The retired bounded scorer pinned confidence at 0.75 for every finding and
    0.9 for any corroborated one — two possible values in the whole product.
    The merged engine derives it by noisy-OR over the rules that fired, so a
    second independent signal moves it by an amount that depends on the rules."""
    lone = score_records({
        "pslist": [{"PID": 900, "PPID": 600, "ImageFileName": "svchost.exe"}],
        "cmdline": [{"PID": 900, "Process": "svchost.exe",
                     "Args": r"C:\Users\v\AppData\Local\Temp\svchost.exe"}],
    })
    corroborated = score_records({
        "pslist": [{"PID": 900, "PPID": 600, "ImageFileName": "svchost.exe"}],
        "cmdline": [{"PID": 900, "Process": "svchost.exe",
                     "Args": r"C:\Users\v\AppData\Local\Temp\svchost.exe"}],
        "malfind": [{"PID": 900, "Process": "svchost.exe", "Start VPN": 4096,
                     "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1,
                     "Hexdump": "4d 5a 90 00 03 00 00 00"}],
    })
    lone_c = lone["process_risk"][900]["confidence"]
    corr_c = corroborated["process_risk"][900]["confidence"]
    assert corr_c > lone_c
    # Not a two-valued step function any more.
    assert {lone_c, corr_c} != {0.75, 0.9}


def test_confidence_floor_suppresses():
    recs = {"pslist": [{"PID": 10, "PPID": 4, "ImageFileName": "a.exe"}],
            "psscan": [{"PID": 10, "PPID": 4, "ImageFileName": "a.exe"},
                       {"PID": 999, "PPID": 4, "ImageFileName": "hidden.exe"}]}
    # A high floor drops the lone (single-rule) hidden-process signal.
    high_floor = score_records(recs, {"preset": "balanced", "confidence_floor": 0.95})
    assert all(o["pid"] != 999 for o in high_floor["scored_objects"])
    normal = score_records(recs, {"preset": "balanced"})
    assert any(o["pid"] == 999 for o in normal["scored_objects"])


def test_preset_scaling_and_require_correlation():
    ps, cmd = _svchost(1337, 600, r"C:\Users\a\Downloads\svchost.exe")
    aggressive = score_records({"pslist": [ps], "cmdline": [cmd]}, {"preset": "aggressive"})
    conservative = score_records({"pslist": [ps], "cmdline": [cmd]}, {"preset": "conservative"})
    assert len(aggressive["scored_objects"]) >= len(conservative["scored_objects"])

    # require_correlation drops a single-signal object.
    lone = score_records({"netscan": [{"PID": 1, "Proto": "TCPv4", "LocalAddr": "10.0.0.5",
                          "LocalPort": 5, "ForeignAddr": "93.184.216.34", "ForeignPort": 4444,
                          "State": "ESTABLISHED", "Owner": "x.exe"}]},
                         {"preset": "balanced", "require_correlation": True})
    assert lone["scored_objects"] == []


def test_rule_override_disable():
    recs = {"pslist": [{"PID": 42, "PPID": 600, "ImageFileName": "scvhost.exe"}]}
    off = score_records(recs, {"preset": "aggressive",
                               "rule_overrides": {"core_proc_masquerade_name": {"enabled": False}}})
    assert "core_proc_masquerade_name" not in _fired(off, 42)


def test_diff_reports_changes():
    a = score_records({"netscan": [{"PID": 1, "Proto": "TCPv4", "LocalAddr": "10.0.0.5",
                       "LocalPort": 5, "ForeignAddr": "93.184.216.34", "ForeignPort": 4444,
                       "State": "ESTABLISHED", "Owner": "x.exe"}]}, {"preset": "conservative"})
    b = score_records({"netscan": [{"PID": 1, "Proto": "TCPv4", "LocalAddr": "10.0.0.5",
                       "LocalPort": 5, "ForeignAddr": "93.184.216.34", "ForeignPort": 4444,
                       "State": "ESTABLISHED", "Owner": "x.exe"}]}, {"preset": "aggressive"})
    d = diff_scored(a["scored_objects"], b["scored_objects"])
    assert set(d) == {"appeared", "disappeared", "changed"}


# --------------------------------------------------------------------------
# live /rescore endpoint — diff, persistence, sanitization
# --------------------------------------------------------------------------

_CACHED = {
    "pslist": [
        {"PID": 600, "PPID": 500, "ImageFileName": "services.exe"},
        # control char in the name must be sanitized in the response
        {"PID": 1337, "PPID": 600, "ImageFileName": "svchost\x00.exe"},
    ],
    "cmdline": [{"PID": 1337, "Args": r"C:\Users\a\AppData\Local\Temp\svchost.exe"}],
    "malfind": [{"PID": 1337, "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1,
                 "File output": "Disabled", "Start VPN": "0x50000",
                 "Hexdump": "4d 5a 90 90 90 90 90 90 90 90 90 90"}],
    "netscan": [{"PID": 1337, "Proto": "TCPv4", "LocalAddr": "10.0.0.5", "LocalPort": 5,
                 "ForeignAddr": "93.184.216.34", "ForeignPort": 4444,
                 "State": "ESTABLISHED", "Owner": "svchost.exe"}],
}


def _fake_triage_factory():
    from memtriage.pipeline import volmemlyzer_adapter as vml

    def fake_run_triage(image_path, artifacts_dir, *, vol_path, timeout_s,
                        profile=None, **kwargs):
        from pathlib import Path
        manifest = {}
        for key, recs in _CACHED.items():
            fname = f"{key}.json"
            Path(artifacts_dir, fname).write_text(json.dumps(recs))
            manifest[key] = fname
        view = vml.assemble_triage({"pslist.nproc": 2}, _CACHED, vol_version="vol3",
                                   profile=profile)
        view["manifest"] = manifest
        return view

    return vml, fake_run_triage


def _triaged_investigation(client, monkeypatch):
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"RAWMEM",
                headers={"X-Filename": "m.raw"})
    vml, fake = _fake_triage_factory()
    monkeypatch.setattr(vml, "run_triage", fake)
    from memtriage.workers.tasks import run_triage
    run_triage.apply(args=[inv_id])
    return inv_id


def test_triage_scored_inventory_is_enriched(client, monkeypatch):
    inv_id = _triaged_investigation(client, monkeypatch)
    procs = client.get(f"/api/investigations/{inv_id}/processes").json()
    evil = next(p for p in procs if p["pid"] == 1337)
    assert evil["risk"] in {"Critical", "High", "Medium", "Low"}
    assert evil["flags"]                                   # rule ids attached
    assert "\x00" not in evil["name"]                      # sanitized


def test_rescore_endpoint_diff_persist_and_sanitize(client, monkeypatch):
    inv_id = _triaged_investigation(client, monkeypatch)

    # Balanced was stored by triage; re-score aggressive then conservative.
    r_agg = client.post(f"/api/investigations/{inv_id}/rescore",
                        json={"profile": {"preset": "aggressive"}})
    assert r_agg.status_code == 200
    agg = r_agg.json()
    assert agg["profile"]["preset"] == "aggressive"
    assert set(agg["diff"]) == {"appeared", "disappeared", "changed"}
    # control char never leaks through the scored view
    assert "\x00" not in json.dumps(agg)

    r_con = client.post(f"/api/investigations/{inv_id}/rescore",
                        json={"profile": {"preset": "conservative"}})
    con = r_con.json()
    assert len(con["scored_objects"]) <= len(agg["scored_objects"])

    # profile is persisted on the investigation's triage.json
    triage = json.loads(InvestigationPaths(inv_id).triage.read_text())
    assert triage["profile"]["preset"] == "conservative"
    # ...and in result.json, which a reloaded page reads.
    result = client.get(f"/api/investigations/{inv_id}/result").json()
    assert result["triage"]["profile"]["preset"] == "conservative"


def test_rescore_stays_on_the_bounded_triage_scale(client, monkeypatch):
    """Every preset re-scores with the triage scorer, so no score leaves 0..30."""
    inv_id = _triaged_investigation(client, monkeypatch)
    by_preset = {}
    for preset in ("aggressive", "conservative", "balanced"):
        body = client.post(f"/api/investigations/{inv_id}/rescore",
                           json={"profile": {"preset": preset}}).json()
        for obj in body["scored_objects"]:
            assert obj["score_max"] == 30
            assert 0 <= obj["score"] <= 30
        by_preset[preset] = {o["key"]: o["score"] for o in body["scored_objects"]}
    # A preset moves cut-offs, never the score an object earns.
    for key, score in by_preset["conservative"].items():
        assert by_preset["aggressive"].get(key) == score
    assert set(by_preset["conservative"]) <= set(by_preset["balanced"]) <= set(by_preset["aggressive"])


def test_rescore_rejects_a_corrupt_cached_artifact(client, monkeypatch):
    inv_id = _triaged_investigation(client, monkeypatch)
    paths = InvestigationPaths(inv_id)
    triage = json.loads(paths.triage.read_text())
    artifact = next(iter(triage["artifacts"].values()))
    paths.volmemlyzer.joinpath(artifact).write_text("not-json")

    response = client.post(
        f"/api/investigations/{inv_id}/rescore",
        json={"profile": {"preset": "aggressive"}},
    )

    assert response.status_code == 409
    assert "missing or invalid" in response.json()["error"]["message"]
    persisted = json.loads(paths.triage.read_text())
    assert persisted["profile"]["preset"] == "balanced"


def test_rescore_requires_triage(client):
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    r = client.post(f"/api/investigations/{inv_id}/rescore", json={"profile": {}})
    assert r.status_code == 409


def test_inventory_reports_a_verdict_for_every_evaluated_process():
    """The inventory is the census, not the shortlist.

    It used to carry risk only for processes that cleared the surfacing floor;
    every other row had its score and confidence deleted and rendered as a bare
    dash. That made "the rules ran and nothing fired" indistinguishable from
    "this was never evaluated" — a distinction docs/METHODOLOGY.md insists on.
    """
    records = {
        "pslist": [
            {"PID": 4, "PPID": 0, "ImageFileName": "System"},
            {"PID": 600, "PPID": 4, "ImageFileName": "smss.exe"},
            # Wrong path for a core process: scores, and should surface.
            {"PID": 900, "PPID": 600, "ImageFileName": "svchost.exe",
             "Path": r"C:\Users\v\AppData\Local\Temp\svchost.exe"},
        ],
        "pstree": [],
    }
    out = score_records(records, plugins=("pslist", "pstree"))
    risk = out["process_risk"]

    # Every process the scorer evaluated has a verdict, not just the flagged one.
    assert set(risk) == {4, 600, 900}
    assert {v["state"] for v in risk.values()} <= {"scored", "no_indicator_fired"}

    quiet = risk[4]
    assert quiet["state"] == "no_indicator_fired"
    assert quiet["risk"] is None and quiet["flags"] == []

    # Plugins nobody selected are reported as a gap in the run, once — not as a
    # blank cell on every row.
    gaps = set(out["unevaluated_sources"])
    assert {"malfind", "handles", "netscan"} <= gaps
    assert "pslist" not in gaps


def test_inventory_rows_say_which_kind_of_blank_they_are():
    """_apply_scoring must label the three cases distinctly."""
    from memtriage.pipeline import volmemlyzer_adapter as vml

    processes = [{"pid": 1, "flags": [], "risk": None},
                 {"pid": 2, "flags": [], "risk": None},
                 {"pid": 3, "flags": ["stale"], "risk": "High", "score": 9.0}]
    scoring = {
        "process_risk": {
            1: {"state": "scored", "risk": "Medium", "score": 11, "confidence": 0.9,
                "techniques": ["T1036"], "flags": ["core_proc_wrong_path"]},
            2: {"state": "no_indicator_fired", "risk": None, "score": 0,
                "confidence": None, "techniques": [], "flags": []},
        },
        "scored_objects": [], "risk_summary": {}, "attack_techniques": [], "profile": {},
        "unevaluated_sources": ["handles"],
    }
    dashboard: dict = {}
    vml._apply_scoring(dashboard, processes, scoring)

    assert processes[0]["evaluation"] == "scored"
    assert processes[1]["evaluation"] == "no_indicator_fired"
    # PID 3 dropped out of the scoring entirely: stale enrichment must not persist.
    assert processes[2]["evaluation"] == "not_evaluated"
    assert processes[2]["flags"] == [] and "score" not in processes[2]
    assert dashboard["unevaluated_sources"] == ["handles"]


def test_a_process_named_by_two_findings_keeps_both_sets_of_flags():
    """An injected region and a process anomaly on one PID are both inventory
    flags. The row used to keep only the higher-scoring object's rule ids and
    silently drop the other's."""
    records = {
        "pslist": [{"PID": 900, "PPID": 600, "ImageFileName": "svchost.exe"}],
        "cmdline": [{"PID": 900, "Process": "svchost.exe",
                     "Args": r"C:\Users\v\AppData\Local\Temp\svchost.exe"}],
        "malfind": [{"PID": 900, "Process": "svchost.exe", "Start VPN": 4096,
                     "Protection": "PAGE_EXECUTE_READWRITE", "PrivateMemory": 1,
                     "Hexdump": "4d 5a 90 00 03 00 00 00"}],
    }
    out = score_records(records, plugins=("pslist", "cmdline", "malfind"))
    entry = out["process_risk"][900]
    assert entry["state"] == "scored"
    # Union of what fired, not just the strongest object's contributions.
    assert len(entry["flags"]) >= 2

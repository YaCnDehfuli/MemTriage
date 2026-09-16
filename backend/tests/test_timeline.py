"""Timeline and correlation, against the captured 2580_5 artifacts.

The assertions are facts about that image: malware.exe (2580) was launched by a
PowerShell process running C:\\Workspace\\log_pid.ps1 — the action of a scheduled
task created the same second — and msedge.exe (6344), which looks orphaned in
pslist, has a parent (msedgedriver.exe) that only psscan still records.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from memtriage.pipeline import volmemlyzer_adapter as vml
from memtriage.pipeline.timeline import build_timeline
from memtriage.reporting.assembly import evidence_ref

FIXTURES = Path(__file__).parent / "fixtures" / "dumps_2580_5"
ARTIFACTS = {
    "info": "info", "pslist": "pslist", "pstree": "pstree", "psscan": "psscan",
    "psxview": "psxview", "malfind": "malfind", "netscan": "netscan",
    "scheduled_tasks": "scheduled_tasks", "userassist": "registry.userassist",
    "hivelist": "registry.hivelist", "hivescan": "registry.hivescan",
}


@pytest.fixture(scope="module")
def records():
    return {key: vml._load_records(str(FIXTURES / f"2580_5.vmem_{name}.json"))
            for key, name in ARTIFACTS.items()}


@pytest.fixture(scope="module")
def scored(records):
    """Scored the way run_triage scores, so labels and keys are the real ones."""
    view = vml.assemble_triage({}, records, plugins=tuple(vml.DEEP_TRIAGE_PLUGINS))
    return view["dashboard"]["scored_objects"]


@pytest.fixture(scope="module")
def timeline(records, scored):
    return build_timeline(records, scored)


def _process(timeline, pid):
    live = [p for p in timeline["processes"].values() if p["pid"] == pid]
    assert live, f"PID {pid} missing from the process census"
    return live[0]


def test_malware_lineage_runs_back_through_the_task_scheduler_host(timeline):
    procs = timeline["processes"]
    malware = _process(timeline, 2580)
    chain = [(procs[a]["pid"], procs[a]["name"].lower()) for a in malware["ancestors"]]
    assert chain[:4] == [(3768, "powershell.exe"), (1232, "svchost.exe"),
                         (640, "services.exe"), (588, "wininit.exe")]
    assert "log_pid.ps1" in procs[malware["parent_id"]]["cmd"]


def test_psscan_recovers_the_parent_pslist_cannot_see(timeline):
    procs = timeline["processes"]
    edge = _process(timeline, 6344)
    parent = procs[edge["parent_id"]]
    assert parent["pid"] == 5332 and parent["name"].startswith("msedgedriver")
    assert edge["parent_recovered"] is True
    assert "pslist" not in parent["sources"] and parent["exited"]


def test_a_task_links_to_the_process_whose_command_line_runs_its_action(timeline):
    task = next(e for e in timeline["events"]
                if e["kind"] == "task_created" and "log_pid.ps1" in e["detail"])
    linked = [link for link in task["links"] if link["type"] == "command_line"]
    assert [timeline["processes"][link["process_id"]]["pid"] for link in linked] == [3768]


def test_a_bare_word_task_argument_never_links_by_substring(timeline):
    """A task argument like "SYSTEM" is a substring of "system32"; that is not identity."""
    for event in timeline["events"]:
        for link in event["links"]:
            if link["type"] == "command_line":
                assert "\\" in event["detail"] or "/" in event["detail"], event["detail"]


def test_events_carry_the_same_ref_the_report_pins(timeline, scored):
    malware_obj = next(o for o in scored if o["object_type"] == "process" and o["pid"] == 2580)
    start = next(e for e in timeline["events"]
                 if e["kind"] == "process_start" and e["pid"] == 2580)
    assert evidence_ref(malware_obj) in [f["ref"] for f in start["findings"]]
    # Medium, not High: the engine scores 2580 on what it can actually read here
    # — RWX private memory (8.4) plus a PEB loader walk (4.8) — and this fixture
    # carries no cmdline artifact, so the path and lineage rules have nothing to
    # evaluate. Both contributions are attributed to T1055 by the rules that
    # fired, rather than to the per-category constant the old scorer applied.
    assert start["risk"] == "Medium" and start["relevant"]


def test_relevance_is_identity_not_timing(timeline):
    events = timeline["events"]
    relevant = [e for e in events if e["relevant"]]
    assert 0 < len(relevant) < len(events) / 5, "relevance must actually narrow the view"

    # The flagged lineage is in; a service host's listening sockets are not,
    # even though that host is an ancestor of malware.exe.
    svchost_sockets = [e for e in events if e["kind"] == "connection" and e["pid"] == 1232]
    assert svchost_sockets and not any(e["relevant"] for e in svchost_sockets)
    assert any(e["kind"] == "process_start" and e["pid"] == 1232 and e["relevant"]
               for e in events)


def test_duplicate_facts_collapse_to_one_event(timeline):
    keys = [(e["kind"], e["at"], e["pid"], e["detail"]) for e in timeline["events"]]
    assert len(keys) == len(set(keys))


def test_events_are_in_time_order_and_sources_are_reported(timeline):
    times = [e["at"] for e in timeline["events"]]
    assert times == sorted(times)
    assert set(timeline["sources"]["present"]) >= {"pslist", "psscan", "netscan"}


def test_a_light_triage_says_which_sources_it_lacks(records, scored):
    light = {k: v for k, v in records.items() if k not in ("psscan", "netscan")}
    tl = build_timeline(light, scored)
    assert {"psscan", "netscan"} <= set(tl["sources"]["missing"])
    edge = next(p for p in tl["processes"].values() if p["pid"] == 6344)
    assert edge["parent_id"] is None, "without psscan the parent is genuinely unknown"


def test_a_reused_pid_is_two_processes_not_one():
    records = {"pslist": [
        {"PID": 900, "PPID": 4, "ImageFileName": "first.exe",
         "CreateTime": "2024-01-01T10:00:00+00:00", "ExitTime": "2024-01-01T10:05:00+00:00"},
        {"PID": 900, "PPID": 4, "ImageFileName": "second.exe",
         "CreateTime": "2024-01-01T11:00:00+00:00", "ExitTime": None},
        {"PID": 901, "PPID": 900, "ImageFileName": "child.exe",
         "CreateTime": "2024-01-01T11:30:00+00:00", "ExitTime": None},
    ]}
    tl = build_timeline(records, [])
    instances = [p for p in tl["processes"].values() if p["pid"] == 900]
    assert len(instances) == 2
    child = next(p for p in tl["processes"].values() if p["pid"] == 901)
    assert tl["processes"][child["parent_id"]]["name"] == "second.exe", \
        "a child belongs to the instance of its PID that existed when it started"


def test_placeholder_timestamps_are_not_events():
    records = {"pslist": [{"PID": 7, "PPID": 4, "ImageFileName": "x.exe",
                           "CreateTime": "1601-01-01T00:00:00+00:00", "ExitTime": None}]}
    assert build_timeline(records, [])["events"] == []


def test_timeline_endpoint_serves_a_triaged_investigation(client, monkeypatch):
    from memtriage.pipeline.fixture_seed import seed_investigation_from_dumps
    from memtriage.workers import tasks

    monkeypatch.setattr(tasks.settings, "vol_offline", True)
    monkeypatch.setattr(tasks.settings, "vol_timeout_s", 5)
    monkeypatch.setattr(tasks.settings, "vol_symbol_dirs", [])
    image = FIXTURES / "2580_5.vmem"
    if not image.is_file():
        image.write_bytes(b"\x00" * 4096)

    investigation = seed_investigation_from_dumps(FIXTURES)["investigation_id"]
    body = client.get(f"/api/investigations/{investigation}/timeline").json()
    assert any(e["pid"] == 2580 and e["relevant"] for e in body["events"])
    assert client.get("/api/investigations/nope/timeline").status_code == 404

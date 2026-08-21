"""Ad hoc plugin runs: the catalog, the log-to-event normalizer, and the
run_plugins task end to end (against a fake Pipeline that logs the way the
real volmemlyzer package does, so the same event-capture code path is
exercised without needing volatility3 installed for the test suite)."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from memtriage.pipeline.plugin_runner import (
    CATEGORY_PROCESS,
    CATEGORY_REGISTRY,
    CATEGORY_SCANNERS,
    PluginEventCapture,
    plugin_catalog,
    run_selected_plugins,
)


def test_catalog_covers_known_plugins_and_categories():
    rows = plugin_catalog()
    by_name = {r["name"]: r for r in rows}
    assert {"pslist", "netscan", "registry.userassist", "filescan"} <= set(by_name)
    assert by_name["pslist"]["category"] == CATEGORY_PROCESS
    assert by_name["registry.userassist"]["category"] == CATEGORY_REGISTRY
    assert by_name["netscan"]["category"] == CATEGORY_SCANNERS
    # TRIAGE_PLUGINS membership is surfaced so the UI can offer a "triage set" preset.
    assert by_name["pslist"]["in_triage_set"] is True
    assert by_name["filescan"]["in_triage_set"] is False


def _capture(*log_calls):
    events = []
    handler = PluginEventCapture(events.append)
    vlog = logging.getLogger("volmemlyzer")
    prev = vlog.level
    vlog.addHandler(handler)
    vlog.setLevel(logging.INFO)
    try:
        for logger_name, level, msg, args in log_calls:
            logging.getLogger(logger_name).log(level, msg, *args)
    finally:
        vlog.removeHandler(handler)
        vlog.setLevel(prev)
    return events


def test_finished_line_is_the_terminal_signal():
    events = _capture(
        ("volmemlyzer.runner", logging.INFO, "Finished %s rc=%s in %.2fs", ("pslist", 0, 1.5)),
    )
    structured = [e for e in events if e["type"] != "log"]
    assert structured == [
        {"type": "plugin_finished", "plugin": "pslist", "rc": 0, "duration_s": 1.5,
         "ok": True, "at": structured[0]["at"]},
    ]


def test_submission_and_worker_execution_are_distinct_events():
    events = _capture(
        ("volmemlyzer.pipeline", logging.INFO, "Running plugin %s", ("pslist",)),
        ("volmemlyzer.runner", logging.INFO, "Executing plugin %s", ("pslist",)),
    )
    assert [event["type"] for event in events if event["type"] != "log"] == [
        "plugin_dispatched", "plugin_started",
    ]


def test_cache_hit_has_no_started_or_finished_event():
    events = _capture(
        ("volmemlyzer.pipeline", logging.INFO,
         "Using the cached %s plugin output in the %s directory. Re-run avoided",
         ("pslist", "/tmp/out")),
    )
    structured = [e for e in events if e["type"] != "log"]
    assert len(structured) == 1
    assert structured[0]["type"] == "plugin_cached"
    assert structured[0]["plugin"] == "pslist"


def test_concurrent_layer_line_is_parsed_without_relying_on_log_args():
    # This one is built with str.format() before logging (see plugins.py), so
    # record.args is empty and record.msg is already the substituted text.
    events = _capture(
        ("volmemlyzer.pipeline", logging.INFO,
         "Running plugins: <<{}>> in paralell".format(", ".join(
             ["pslist", "netscan", "malfind"])),
         ()),
    )
    structured = [e for e in events if e["type"] != "log"]
    assert structured[0] == {
        "type": "layer_dispatched", "plugins": ["pslist", "netscan", "malfind"],
        "at": structured[0]["at"],
    }


def test_timeout_still_reaches_a_finished_event():
    events = _capture(
        ("volmemlyzer.runner", logging.ERROR, "Plugin %s timed out after %ss",
         ("handles", 90)),
        ("volmemlyzer.runner", logging.INFO, "Finished %s rc=%s in %.2fs",
         ("handles", 124, 90.0)),
    )
    kinds = [e["type"] for e in events if e["type"] != "log"]
    assert kinds == ["plugin_timeout", "plugin_finished"]
    finished = next(e for e in events if e["type"] == "plugin_finished")
    assert finished["ok"] is False
    assert finished["rc"] == 124


def test_debug_lines_are_excluded_by_default_level():
    events = _capture(
        ("volmemlyzer.runner", logging.DEBUG, "Command: %s", ("vol -f x windows.pslist",)),
    )
    assert events == []


class _FakeRegistry:
    def topo_layers(self, selected):
        # One dependency-respecting layer per plugin, deterministic order.
        return [{name} for name in sorted(selected)]


class _FakePipe:
    """Stands in for volmemlyzer.pipeline.Pipeline: logs the way the real
    package does, so run_selected_plugins' event capture is exercised for
    real without needing volatility3 installed for the test suite."""

    def __init__(self, *, write_files: bool = False):
        self.registry = _FakeRegistry()
        self.calls = []
        self.write_files = write_files

    def run_plugin_raw(self, *, image_path, enable, outdir, concurrency, use_cache):
        self.calls.append({"enable": set(enable), "concurrency": concurrency})
        plog = logging.getLogger("volmemlyzer.pipeline")
        rlog = logging.getLogger("volmemlyzer.runner")
        plugins, failed = {}, {}
        for name in sorted(enable):
            if name == "pslist":
                plog.info("Using the cached %s plugin output in the %s directory. "
                          "Re-run avoided", name, outdir)
                plugins[name] = f"{outdir}/{name}.json"
            elif name == "netscan":
                plog.info("Running plugin %s", name)
                rlog.info("Executing plugin %s", name)
                rlog.info("Finished %s rc=%s in %.2fs", name, 0, 2.5)
                plugins[name] = f"{outdir}/{name}.json"
            else:  # a plugin that fails
                plog.info("Running plugin %s", name)
                rlog.info("Executing plugin %s", name)
                rlog.error("Plugin %s failed (rc=%s). %s", name, 1, "no symbols")
                rlog.info("Finished %s rc=%s in %.2fs", name, 1, 0.4)
                failed[name] = "vol exited 1"

        if self.write_files:
            for artifact in plugins.values():
                Path(artifact).write_text("[]")

        class _Result:
            pass

        r = _Result()
        r.artifacts = {"plugins": plugins, "failed_plugins": failed}
        return r


def test_run_selected_plugins_end_to_end_against_a_fake_pipeline():
    events = []
    pipe = _FakePipe()
    result = run_selected_plugins(
        pipe, "/data/dump_0", "/data/volmemlyzer", ["pslist", "netscan", "malfind"], 2,
        events.append,
    )
    assert result == {
        "plugins": {"netscan": "/data/volmemlyzer/netscan.json",
                    "pslist": "/data/volmemlyzer/pslist.json"},
        "failed_plugins": {"malfind": "vol exited 1"},
    }
    kinds = [e["type"] for e in events]
    assert kinds[0] == "plan"
    assert events[0]["layers"] == [["malfind"], ["netscan"], ["pslist"]]
    assert "plugin_cached" in kinds  # pslist
    assert "plugin_dispatched" in kinds
    assert "plugin_started" in kinds
    assert "plugin_finished" in kinds  # netscan (ok) and malfind (failed)
    finished = [e for e in events if e["type"] == "plugin_finished"]
    assert {e["plugin"]: e["ok"] for e in finished} == {"netscan": True, "malfind": False}
    assert pipe.calls == [{"enable": {"pslist", "netscan", "malfind"}, "concurrency": 2}]


def test_raised_manual_batch_marks_every_nonterminal_plugin_failed():
    class _RaisingPipe:
        registry = _FakeRegistry()

        def run_plugin_raw(self, **_kwargs):
            raise RuntimeError("runner unavailable")

    events = []
    with pytest.raises(RuntimeError, match="runner unavailable"):
        run_selected_plugins(
            _RaisingPipe(), "/data/dump_0", "/data/volmemlyzer",
            ["pslist", "netscan"], 2, events.append,
        )

    failed = [event for event in events if event["type"] == "plugin_failed"]
    assert {event["plugin"] for event in failed} == {"pslist", "netscan"}


def test_event_retention_keeps_plan_and_plugin_terminals_beyond_2000_events():
    from memtriage.pipeline.progress import _retain_plugin_events

    events = [
        {"type": "plan", "layers": [["pslist", "handles"]]},
        {"type": "plugin_cached", "plugin": "pslist"},
        {"type": "plugin_timeout", "plugin": "handles", "timeout_s": 86_400},
        {"type": "plugin_finished", "plugin": "handles", "ok": False, "rc": 124},
    ]
    events.extend(
        {"type": "heartbeat", "at": index, "plugins": ["handles"]}
        for index in range(2_100)
    )

    retained = _retain_plugin_events(events, ["pslist", "handles"])
    assert len(retained) == 2_000
    assert retained[0]["type"] == "plan"
    assert any(
        event.get("type") == "plugin_cached" and event.get("plugin") == "pslist"
        for event in retained
    )
    assert any(event.get("type") == "plugin_timeout" for event in retained)
    assert any(
        event.get("type") == "plugin_finished" and event.get("plugin") == "handles"
        for event in retained
    )


# --------------------------------------------------------------------------
# API + task wiring
# --------------------------------------------------------------------------


def test_catalog_route(client):
    resp = client.get("/api/plugins/catalog")
    assert resp.status_code == 200
    names = {row["name"] for row in resp.json()}
    assert "pslist" in names and "netscan" in names


def test_run_rejects_unknown_plugin(client):
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"x" * 32,
               headers={"X-Filename": "mem.raw"})
    resp = client.post(f"/api/investigations/{inv_id}/plugins/run",
                       json={"plugins": ["not_a_real_plugin"], "concurrency": 1})
    assert resp.status_code == 422


def test_run_requires_a_dump(client):
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    resp = client.post(f"/api/investigations/{inv_id}/plugins/run",
                       json={"plugins": ["pslist"], "concurrency": 1})
    assert resp.status_code == 409


def test_manual_enqueue_failure_is_terminal_and_allows_retry(client, monkeypatch):
    from memtriage.api import routes_plugins

    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(
        f"/api/investigations/{inv_id}/dumps", content=b"x" * 32,
        headers={"X-Filename": "mem.raw"},
    )

    def fail_enqueue(*_args, **_kwargs):
        raise ConnectionError("broker offline")

    monkeypatch.setattr(routes_plugins.celery_app, "send_task", fail_enqueue)
    failed = client.post(
        f"/api/investigations/{inv_id}/plugins/run", json={"plugins": ["pslist"]},
    )
    assert failed.status_code == 503
    history = client.get(
        f"/api/investigations/{inv_id}/plugins/runs?limit=1"
    ).json()
    assert history[0]["status"] == "failed"

    monkeypatch.setattr(routes_plugins.celery_app, "send_task", lambda *_a, **_k: None)
    assert client.post(
        f"/api/investigations/{inv_id}/plugins/run", json={"plugins": ["pslist"]},
    ).status_code == 201


def test_run_plugins_task_end_to_end(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_plugins

    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"x" * 32,
               headers={"X-Filename": "mem.raw"})

    fake_pipe = _FakePipe(write_files=True)
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: fake_pipe)

    created = client.post(f"/api/investigations/{inv_id}/plugins/run",
                          json={"plugins": ["pslist", "netscan", "malfind"], "concurrency": 2})
    assert created.status_code == 201
    run_id = created.json()["plugin_run_id"]

    run_plugins.apply(args=[run_id])

    state = client.get(f"/api/investigations/{inv_id}/plugins/runs/{run_id}").json()
    assert state["status"] == "done"
    assert state["progress"] == 100
    assert fake_pipe.calls  # the fake pipeline really was invoked
    kinds = [e["type"] for e in state["events"]]
    assert "plan" in kinds
    assert "plugin_cached" in kinds
    assert "plugin_finished" in kinds
    assert "artifact_ready" in kinds

    history = client.get(f"/api/investigations/{inv_id}/plugins/runs").json()
    assert [r["plugin_run_id"] for r in history] == [run_id]


def test_raised_manual_task_persists_terminal_failures(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_plugins

    class _RaisingPipe:
        registry = _FakeRegistry()

        def run_plugin_raw(self, **_kwargs):
            raise RuntimeError("runner unavailable")

    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(
        f"/api/investigations/{inv_id}/dumps", content=b"x" * 32,
        headers={"X-Filename": "mem.raw"},
    )
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: _RaisingPipe())
    created = client.post(
        f"/api/investigations/{inv_id}/plugins/run",
        json={"plugins": ["pslist", "netscan"], "concurrency": 2},
    ).json()

    assert run_plugins.apply(args=[created["plugin_run_id"]]).get() == "failed"
    state = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{created['plugin_run_id']}"
    ).json()
    assert state["status"] == "failed"
    assert set(state["failed_plugins"]) == {"pslist", "netscan"}


def test_pipeline_build_failure_marks_requested_plugins_terminal(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_plugins

    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(
        f"/api/investigations/{inv_id}/dumps", content=b"x" * 32,
        headers={"X-Filename": "mem.raw"},
    )
    def fail_build(*_args, **_kwargs):
        raise RuntimeError("cannot build")

    monkeypatch.setattr(vml, "build_pipeline", fail_build)
    created = client.post(
        f"/api/investigations/{inv_id}/plugins/run",
        json={"plugins": ["pslist", "netscan"]},
    ).json()

    assert run_plugins.apply(args=[created["plugin_run_id"]]).get() == "failed"
    state = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{created['plugin_run_id']}"
    ).json()
    assert state["status"] == "failed"
    assert set(state["failed_plugins"]) == {"pslist", "netscan"}
    assert {
        event["plugin"] for event in state["events"]
        if event["type"] == "plugin_failed"
    } == {"pslist", "netscan"}

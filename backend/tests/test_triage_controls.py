"""Selectable triage, live Volatility state, cache reuse, and output serving."""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import select


def _new_with_dump(client, content: bytes | None = None) -> str:
    content = content or (b"MEM-" + uuid.uuid4().bytes)
    inv_id = client.post("/api/investigations").json()["investigation_id"]
    response = client.post(
        f"/api/investigations/{inv_id}/dumps", content=content,
        headers={"X-Filename": "memory.raw"},
    )
    assert response.status_code == 201
    return inv_id


def _empty_view(plugins=None) -> dict:
    from memtriage.scoring.profile import TuningProfile

    profile = TuningProfile.from_preset("balanced").to_dict()
    return {
        "features": {}, "dashboard": {"profile": profile}, "processes": [],
        "profile": profile,
        "manifest": {}, "vol_version": "test-vol", "plugins": list(plugins or []),
        "extraction": {"plugins_attempted": len(plugins or []), "plugins_failed": 0,
                       "failed_plugins": {}, "degraded": False, "severity": "ok",
                       "message": "ok"},
    }


def test_catalog_marks_light_and_deep_presets(client):
    by_name = {row["name"]: row for row in client.get("/api/plugins/catalog").json()}
    assert by_name["pslist"]["in_light_set"] is True
    assert by_name["pslist"]["in_deep_set"] is True
    assert by_name["psxview"]["in_light_set"] is False
    assert by_name["psxview"]["in_deep_set"] is True
    assert by_name["filescan"]["in_deep_set"] is False


def test_legacy_schema_additions_include_dump_hash_and_run_state():
    from memtriage.db import _ADDITIVE_COLUMNS

    assert ("sha256", "VARCHAR(64)") in _ADDITIVE_COLUMNS["dumps"]
    assert ("events", "JSON") in _ADDITIVE_COLUMNS["investigations"]
    assert ("artifacts", "JSON") in _ADDITIVE_COLUMNS["plugin_runs"]


def test_start_triage_persists_the_server_owned_light_plan(client, monkeypatch):
    from memtriage.api import routes_investigations as routes
    from memtriage.pipeline.volmemlyzer_adapter import LIGHT_TRIAGE_PLUGINS

    inv_id = _new_with_dump(client)
    sent = []
    monkeypatch.setattr(routes.celery_app, "send_task",
                        lambda name, args: sent.append((name, args)))
    response = client.post(
        f"/api/investigations/{inv_id}/triage",
        json={"mode": "light", "plugins": ["filescan"], "concurrency": 2,
              "force": True},
    )
    assert response.status_code == 200
    state = response.json()
    assert state["status"] == "triaging"
    assert state["triage_mode"] == "light"
    assert state["requested_plugins"] == list(LIGHT_TRIAGE_PLUGINS)
    assert state["concurrency"] == 2
    assert sent == [("memtriage.run_triage", [inv_id, True])]


def test_enqueue_failure_is_visible_and_does_not_permanently_block_triage(
    client, monkeypatch,
):
    from memtriage.api import routes_investigations as routes

    inv_id = _new_with_dump(client)

    def fail_enqueue(*_args, **_kwargs):
        raise ConnectionError("broker offline")

    monkeypatch.setattr(routes.celery_app, "send_task", fail_enqueue)
    failed = client.post(f"/api/investigations/{inv_id}/triage", json={"mode": "light"})
    assert failed.status_code == 503
    assert client.get(f"/api/investigations/{inv_id}").json()["status"] == "failed"

    monkeypatch.setattr(routes.celery_app, "send_task", lambda *_a, **_k: None)
    assert client.post(
        f"/api/investigations/{inv_id}/triage", json={"mode": "light"}
    ).status_code == 200


def test_custom_triage_validates_its_selection(client):
    inv_id = _new_with_dump(client)
    empty = client.post(f"/api/investigations/{inv_id}/triage",
                        json={"mode": "custom", "plugins": []})
    assert empty.status_code == 422
    unknown = client.post(f"/api/investigations/{inv_id}/triage",
                          json={"mode": "custom", "plugins": ["not-real"]})
    assert unknown.status_code == 422


def test_custom_triage_always_includes_pslist(client, monkeypatch):
    from memtriage.api import routes_investigations as routes

    inv_id = _new_with_dump(client)
    monkeypatch.setattr(routes.celery_app, "send_task", lambda *_a, **_k: None)
    response = client.post(
        f"/api/investigations/{inv_id}/triage",
        json={"mode": "custom", "plugins": ["filescan"]},
    )
    assert response.status_code == 200
    assert response.json()["requested_plugins"] == ["pslist", "filescan"]


def test_triage_and_manual_runs_cannot_overlap(client):
    triaging = _new_with_dump(client)
    assert client.post(f"/api/investigations/{triaging}/triage",
                       json={"mode": "custom", "plugins": ["pslist"]}).status_code == 200
    assert client.post(f"/api/investigations/{triaging}/plugins/run",
                       json={"plugins": ["pslist"]}).status_code == 409

    manual = _new_with_dump(client)
    assert client.post(f"/api/investigations/{manual}/plugins/run",
                       json={"plugins": ["pslist"]}).status_code == 201
    assert client.post(f"/api/investigations/{manual}/triage",
                       json={"mode": "light"}).status_code == 409


@dataclass
class _FeatureRow:
    image_name: str = "dump_0"
    features: dict = field(default_factory=lambda: {"pslist.nproc": 1})
    image_hash: str = "quick"
    vol_version: str = "test-vol"
    failed_plugins: dict = field(default_factory=dict)


class _Registry:
    def has(self, name):
        return name in {"pslist", "pstree", "psxview"}

    def get(self, name):
        return SimpleNamespace(name=name), object()


class _SelectedPipe:
    def __init__(self):
        self.registry = _Registry()
        self.calls = []

    def run_extract_features(self, *, image_path, enable, concurrency, artifacts_dir,
                             use_cache):
        self.calls.append({"enable": set(enable), "concurrency": concurrency,
                           "use_cache": use_cache})
        rows = {
            "pslist": [{"PID": 7, "PPID": 4, "ImageFileName": "demo.exe"}],
            "pstree": [], "psxview": [],
        }
        for name in enable:
            Path(artifacts_dir, f"{Path(image_path).name}_{name}.json").write_text(
                json.dumps(rows[name]))
        return _FeatureRow()


def test_adapter_runs_only_the_selected_plugins_with_requested_concurrency(tmp_path,
                                                                            monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml

    image = tmp_path / "dump_0"
    image.write_bytes(b"x")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    pipe = _SelectedPipe()
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: pipe)

    view = vml.run_triage(
        str(image), str(artifacts), vol_path=None, timeout_s=1,
        plugins=["pslist", "pstree"], concurrency=3, use_cache=False,
    )
    assert pipe.calls == [{"enable": {"pslist", "pstree"}, "concurrency": 3,
                           "use_cache": False}]
    assert view["plugins"] == ["pslist", "pstree"]
    assert [p["pid"] for p in view["processes"]] == [7]
    assert not (artifacts / "dump_0_psxview.json").exists()


def test_triage_task_streams_plugin_events_and_hash_was_computed_on_upload(client,
                                                                            monkeypatch):
    from memtriage.db import SessionLocal
    from memtriage.models import Dump
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    inv_id = _new_with_dump(client)
    with SessionLocal() as session:
        dump = session.scalars(select(Dump).where(Dump.investigation_id == inv_id)).one()
        assert dump.sha256 and len(dump.sha256) == 64

    client.post(f"/api/investigations/{inv_id}/triage",
                json={"mode": "custom", "plugins": ["pslist"], "concurrency": 1})

    def fake(*_args, plugins=None, **_kwargs):
        logging.getLogger("volmemlyzer.pipeline").info("Running plugin %s", "pslist")
        logging.getLogger("volmemlyzer.runner").info("Executing plugin %s", "pslist")
        logging.getLogger("volmemlyzer.runner").info(
            "Finished %s rc=%s in %.2fs", "pslist", 0, 0.25)
        return _empty_view(plugins)

    monkeypatch.setattr(vml, "run_triage", fake)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    state = client.get(f"/api/investigations/{inv_id}").json()
    kinds = [event["type"] for event in state["events"]]
    plan = next(event for event in state["events"] if event["type"] == "plan")
    assert plan["layers"] == [["pslist"]]
    assert plan["concurrency"] == 1
    assert "plugin_dispatched" in kinds
    assert "plugin_started" in kinds
    assert "plugin_finished" in kinds
    assert "log" in kinds


def test_raised_triage_marks_every_nonterminal_plugin_failed(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    inv_id = _new_with_dump(client)
    client.post(
        f"/api/investigations/{inv_id}/triage",
        json={"mode": "custom", "plugins": ["pslist", "netscan"], "concurrency": 2},
    )

    def raise_run(*_args, **_kwargs):
        raise RuntimeError("pipeline unavailable")

    monkeypatch.setattr(vml, "run_triage", raise_run)
    assert run_triage.apply(args=[inv_id]).get() == "failed"
    state = client.get(f"/api/investigations/{inv_id}").json()
    assert state["status"] == "failed"
    failed = [event for event in state["events"] if event["type"] == "plugin_failed"]
    assert {event["plugin"] for event in failed} == {"pslist", "netscan"}


def test_exact_triage_json_is_reused_unless_force_is_true(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import run_triage

    inv_id = _new_with_dump(client)
    calls = []

    def fake(_image, artifacts_dir, *, plugins=None, **_kwargs):
        calls.append(list(plugins or []))
        manifest = {}
        for plugin in plugins or []:
            artifact = Path(artifacts_dir, f"dump_0_{plugin}.json")
            artifact.write_text("[]")
            Path(f"{artifact}.stderr.txt").unlink(missing_ok=True)
            manifest[plugin] = artifact.name
        view = _empty_view(plugins)
        view["manifest"] = manifest
        return view

    monkeypatch.setattr(vml, "run_triage", fake)
    body = {"mode": "custom", "plugins": ["pslist"], "concurrency": 1}
    client.post(f"/api/investigations/{inv_id}/triage", json=body)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    assert len(calls) == 1

    client.post(f"/api/investigations/{inv_id}/triage", json=body)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    assert len(calls) == 1
    state = client.get(f"/api/investigations/{inv_id}").json()
    assert state["cache_source"] == "triage.json"
    plans = [event for event in state["events"] if event["type"] == "plan"]
    assert plans == [{
        "type": "plan", "at": plans[0]["at"], "layers": [["pslist"]],
        "concurrency": 1,
        "message": "Scheduled 1 plugin(s) with up to 1 concurrent worker(s).",
    }]
    cached = [e["plugin"] for e in state["events"] if e["type"] == "plugin_cached"]
    assert cached == ["pslist"]

    artifact = InvestigationPaths(inv_id).volmemlyzer / "dump_0_pslist.json"
    artifact.write_text("{")
    client.post(f"/api/investigations/{inv_id}/triage", json=body)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    assert len(calls) == 2

    Path(f"{artifact}.stderr.txt").write_text("ERROR: plugin failed")
    client.post(f"/api/investigations/{inv_id}/triage", json=body)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    assert len(calls) == 3

    client.post(f"/api/investigations/{inv_id}/triage", json={**body, "force": True})
    assert run_triage.apply(args=[inv_id, True]).get() == "triaged"
    assert len(calls) == 4


def test_old_triage_schema_is_rebuilt_instead_of_reused(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import run_triage

    content = b"old-schema-cross-cache-" + uuid.uuid4().bytes
    source = _new_with_dump(client, content)
    calls = []

    def fake(*_args, plugins=None, **_kwargs):
        calls.append(list(plugins or []))
        return _empty_view(plugins)

    monkeypatch.setattr(vml, "run_triage", fake)
    body = {"mode": "custom", "plugins": ["pslist"]}
    client.post(f"/api/investigations/{source}/triage", json=body)
    assert run_triage.apply(args=[source]).get() == "triaged"

    path = InvestigationPaths(source).triage
    stale = json.loads(path.read_text())
    stale["triage_config"]["schema_version"] = 1
    path.write_text(json.dumps(stale))
    target = _new_with_dump(client, content)
    client.post(f"/api/investigations/{target}/triage", json=body)
    assert run_triage.apply(args=[target]).get() == "triaged"
    assert calls == [["pslist"], ["pslist"]]


def test_degraded_triage_is_retried_instead_of_becoming_a_sticky_cache(
    client, monkeypatch,
):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    inv_id = _new_with_dump(client)
    calls = []

    def degraded(*_args, plugins=None, **_kwargs):
        calls.append(list(plugins or []))
        view = _empty_view(plugins)
        view["extraction"] = {
            "plugins_attempted": 1,
            "plugins_failed": 1,
            "failed_plugins": {"pslist": "symbols unavailable"},
            "degraded": True,
            "severity": "critical",
            "message": "failed",
        }
        return view

    monkeypatch.setattr(vml, "run_triage", degraded)
    body = {"mode": "custom", "plugins": ["pslist"]}
    client.post(f"/api/investigations/{inv_id}/triage", json=body)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    client.post(f"/api/investigations/{inv_id}/triage", json=body)
    assert run_triage.apply(args=[inv_id]).get() == "triaged"
    assert calls == [["pslist"], ["pslist"]]


def test_tuned_scores_are_rebuilt_with_default_profile_on_new_triage(
    client, monkeypatch,
):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import run_triage

    content = b"tuned-profile-cross-cache-" + uuid.uuid4().bytes
    source = _new_with_dump(client, content)
    calls = []

    def fake(*_args, plugins=None, **_kwargs):
        calls.append(list(plugins or []))
        return _empty_view(plugins)

    monkeypatch.setattr(vml, "run_triage", fake)
    body = {"mode": "custom", "plugins": ["pslist"]}
    client.post(f"/api/investigations/{source}/triage", json=body)
    assert run_triage.apply(args=[source]).get() == "triaged"

    path = InvestigationPaths(source).triage
    tuned = json.loads(path.read_text())
    tuned["profile"]["preset"] = "aggressive"
    path.write_text(json.dumps(tuned))
    target = _new_with_dump(client, content)
    client.post(f"/api/investigations/{target}/triage", json=body)
    assert run_triage.apply(args=[target]).get() == "triaged"
    assert calls == [["pslist"], ["pslist"]]


def test_matching_sha_seeds_a_prior_investigations_artifacts(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import run_triage

    content = b"same-primary-" + uuid.uuid4().bytes
    source = _new_with_dump(client, content)

    def source_run(_image, artifacts_dir, *, plugins=None, **_kwargs):
        Path(artifacts_dir, "dump_0_pslist.json").write_text("[]")
        return _empty_view(plugins)

    monkeypatch.setattr(vml, "run_triage", source_run)
    body = {"mode": "custom", "plugins": ["pslist"]}
    client.post(f"/api/investigations/{source}/triage", json=body)
    assert run_triage.apply(args=[source]).get() == "triaged"

    target = _new_with_dump(client, content)

    def target_run(_image, artifacts_dir, *, plugins=None, **_kwargs):
        assert Path(artifacts_dir, "dump_0_pslist.json").read_text() == "[]"
        return _empty_view(plugins)

    monkeypatch.setattr(vml, "run_triage", target_run)
    target_body = {"mode": "custom", "plugins": ["pslist", "pstree"]}
    client.post(f"/api/investigations/{target}/triage", json=target_body)
    assert run_triage.apply(args=[target]).get() == "triaged"
    state = client.get(f"/api/investigations/{target}").json()
    assert state["cache_source"] == f"investigation:{source}"
    event_types = {event["type"] for event in state["events"]}
    assert {"cache_copy_started", "cache_copy_finished", "cache_seeded"} <= event_types
    assert InvestigationPaths(target).volmemlyzer.joinpath("dump_0_pslist.json").is_file()


def test_matching_sha_and_plugin_plan_reuses_prior_complete_triage(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    content = b"same-complete-triage-" + uuid.uuid4().bytes
    source = _new_with_dump(client, content)
    body = {"mode": "custom", "plugins": ["pslist", "netscan"], "concurrency": 2}
    calls = []

    def source_run(_image, artifacts_dir, *, plugins=None, **_kwargs):
        calls.append(list(plugins or []))
        manifest = {}
        for plugin in plugins or []:
            artifact = Path(artifacts_dir, f"dump_0_{plugin}.json")
            artifact.write_text("[]")
            manifest[plugin] = artifact.name
        view = _empty_view(plugins)
        view["manifest"] = manifest
        return view

    monkeypatch.setattr(vml, "run_triage", source_run)
    client.post(f"/api/investigations/{source}/triage", json=body)
    assert run_triage.apply(args=[source]).get() == "triaged"

    target = _new_with_dump(client, content)
    client.post(f"/api/investigations/{target}/triage", json=body)
    assert run_triage.apply(args=[target]).get() == "triaged"
    assert calls == [["pslist", "netscan"]]

    state = client.get(f"/api/investigations/{target}").json()
    source_name = f"investigation:{source}/triage.json"
    assert state["cache_source"] == source_name
    from memtriage.storage import InvestigationPaths
    target_artifacts = InvestigationPaths(target).volmemlyzer
    assert (target_artifacts / "dump_0_pslist.json").is_file()
    assert (target_artifacts / "dump_0_netscan.json").is_file()
    event_types = {event["type"] for event in state["events"]}
    assert {"cache_copy_started", "cache_copy_finished", "cache_reused"} <= event_types
    assert [
        event["plugin"] for event in state["events"]
        if event["type"] == "plugin_cached"
    ] == ["pslist", "netscan"]


def test_process_enqueue_failure_is_terminal_and_allows_retry(client, monkeypatch):
    from memtriage.api import routes_processes
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_triage

    inv_id = _new_with_dump(client)
    monkeypatch.setattr(vml, "run_triage", lambda *a, plugins=None, **k: _empty_view(plugins))
    client.post(
        f"/api/investigations/{inv_id}/triage",
        json={"mode": "custom", "plugins": ["pslist"]},
    )
    run_triage.apply(args=[inv_id])

    def fail_enqueue(*_args, **_kwargs):
        raise ConnectionError("broker offline")

    monkeypatch.setattr(routes_processes.celery_app, "send_task", fail_enqueue)
    failed = client.post(
        f"/api/investigations/{inv_id}/processes/analyze", json={"pid": 4242},
    )
    assert failed.status_code == 503
    analyses = client.get(f"/api/investigations/{inv_id}/analyses").json()
    assert analyses[0]["status"] == "failed"

    monkeypatch.setattr(routes_processes.celery_app, "send_task", lambda *_a, **_k: None)
    retried = client.post(
        f"/api/investigations/{inv_id}/processes/analyze", json={"pid": 4242},
    )
    assert retried.status_code == 200
    assert retried.json()["status"] == "queued"


class _OutputPipe:
    registry = SimpleNamespace(topo_layers=lambda selected: [set(selected)])

    def run_plugin_raw(self, *, image_path, enable, outdir, concurrency, use_cache):
        from volmemlyzer.core import ActionResult

        plugin = next(iter(enable))
        path = Path(outdir, f"{Path(image_path).name}_{plugin}.json")
        path.write_text(json.dumps({"records": [
            {"PID": 1, "Command": "=1+1", "Bad\x00Key": "x"},
            {"PID": 2, "Command": "safe"},
        ]}))
        logging.getLogger("volmemlyzer.pipeline").info("Running plugin %s", plugin)
        logging.getLogger("volmemlyzer.runner").info("Executing plugin %s", plugin)
        logging.getLogger("volmemlyzer.runner").info(
            "Finished %s rc=%s in %.2fs", plugin, 0, 0.1)
        return ActionResult(artifacts={"plugins": {plugin: str(path)}, "failed_plugins": {}})


class _ConvertedOutputPipe:
    registry = SimpleNamespace(topo_layers=lambda selected: [set(selected)])

    def run_plugin_raw(self, *, image_path, enable, outdir, concurrency, use_cache):
        from volmemlyzer.core import ActionResult

        plugin = next(iter(enable))
        path = Path(outdir, f"{plugin}.json")
        path.write_text(json.dumps([{"PID": 7, "Source": "converted"}]))
        logging.getLogger("volmemlyzer.pipeline").info(
            "Converted %s: %s -> %s via %s. Re-run avoided",
            plugin, "csv", "json", "csv",
        )
        return ActionResult(artifacts={"plugins": {plugin: str(path)}, "failed_plugins": {}})


def test_converted_manual_output_is_snapshotted_from_its_actual_path(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers.tasks import run_plugins

    inv_id = _new_with_dump(client)
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: _ConvertedOutputPipe())
    created = client.post(
        f"/api/investigations/{inv_id}/plugins/run", json={"plugins": ["pslist"]},
    ).json()
    run_id = created["plugin_run_id"]
    assert run_plugins.apply(args=[run_id]).get() == "done"
    state = client.get(f"/api/investigations/{inv_id}/plugins/runs/{run_id}").json()
    assert state["available_outputs"] == ["pslist"]
    assert any(event["type"] == "artifact_ready" for event in state["events"])
    preview = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist"
    ).json()
    assert preview["rows"] == [{"PID": 7, "Source": "converted"}]


def test_manual_output_preview_and_safe_downloads(client, monkeypatch):
    from memtriage.api import routes_plugins
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import run_plugins

    inv_id = _new_with_dump(client)
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: _OutputPipe())
    created = client.post(f"/api/investigations/{inv_id}/plugins/run",
                          json={"plugins": ["pslist"], "concurrency": 1}).json()
    run_id = created["plugin_run_id"]
    assert run_plugins.apply(args=[run_id]).get() == "done"

    # Manual history points at an immutable run snapshot, not the shared cache
    # file that a later force-triage may overwrite.
    InvestigationPaths(inv_id).volmemlyzer.joinpath("dump_0_pslist.json").write_text(
        json.dumps([{"PID": 999}])
    )

    state = client.get(f"/api/investigations/{inv_id}/plugins/runs/{run_id}").json()
    assert state["available_outputs"] == ["pslist"]
    preview = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist?limit=1"
    ).json()
    assert preview["columns"] == ["PID", "Command", "BadKey"]
    assert set(preview["rows"][0]) == {"PID", "Command", "BadKey"}
    assert preview["total"] == preview["row_count"] == 2
    assert preview["truncated"] is True

    json_download = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist/download"
    )
    assert json_download.status_code == 200
    assert "attachment" in json_download.headers["content-disposition"]
    csv_download = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist/download?format=csv"
    )
    assert csv_download.status_code == 200
    assert "'=1+1" in csv_download.text

    monkeypatch.setattr(routes_plugins, "MAX_RENDER_BYTES", 1)
    assert client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist"
    ).status_code == 413
    assert client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist/download?format=csv"
    ).status_code == 413
    assert client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{run_id}/outputs/pslist/download"
    ).status_code == 200


def test_snapshot_failure_overrides_a_successful_plugin_card(client, monkeypatch):
    from memtriage.pipeline import volmemlyzer_adapter as vml
    from memtriage.workers import tasks

    inv_id = _new_with_dump(client)
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: _OutputPipe())
    monkeypatch.setattr(tasks, "_snapshot_plugin_artifact", lambda *a, **k: None)
    created = client.post(
        f"/api/investigations/{inv_id}/plugins/run",
        json={"plugins": ["pslist"], "concurrency": 1},
    ).json()

    assert tasks.run_plugins.apply(args=[created["plugin_run_id"]]).get() == "done"
    state = client.get(
        f"/api/investigations/{inv_id}/plugins/runs/{created['plugin_run_id']}"
    ).json()
    assert state["available_outputs"] == []
    assert "pslist" in state["failed_plugins"]
    terminals = [
        event for event in state["events"]
        if event.get("plugin") == "pslist"
        and event["type"] in {"plugin_finished", "plugin_failed"}
    ]
    assert terminals[-1]["type"] == "plugin_failed"

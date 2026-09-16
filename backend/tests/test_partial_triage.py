"""Salvaging a triage from a run that stopped or failed part-way.

A stop three plugins from the end used to discard everything the run produced.
These pin the two halves of doing better: the finished plugins are scored, and
the result can never be mistaken for complete coverage.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from memtriage.pipeline import volmemlyzer_adapter as vml

FIXTURES = Path(__file__).parent / "fixtures" / "dumps_2580_5"
# The fixture artifacts, named as the adapter expects: <image>_<plugin>.json
ARTIFACTS = {
    "pslist": "pslist", "pstree": "pstree", "malfind": "malfind",
    "scheduled_tasks": "scheduled_tasks", "netscan": "netscan",
}
IMAGE = "2580_5.vmem"


class _Spec:
    def __init__(self, name: str) -> None:
        self.name = name


class _Registry:
    """Stands in for VolMemLyzer's registry: names and their artifact basenames."""

    def __init__(self, known: set[str]) -> None:
        self._known = known

    def has(self, name: str) -> bool:
        return name in self._known

    def get(self, name: str):
        return _Spec(name), None


class _Pipe:
    def __init__(self, known: set[str]) -> None:
        self.registry = _Registry(known)


@pytest.fixture
def halted_run(tmp_path, monkeypatch):
    """An artifacts dir holding only the plugins that finished before the stop."""
    artifacts = tmp_path / "volmemlyzer"
    artifacts.mkdir()
    finished = ("pslist", "pstree", "malfind")
    for plugin in finished:
        src = FIXTURES / f"2580_5.vmem_{ARTIFACTS[plugin]}.json"
        (artifacts / f"{IMAGE}_{plugin}.json").write_text(src.read_text())
    # netscan never ran; scheduled_tasks was killed mid-write and left a stub
    # that is not parseable JSON.
    (artifacts / f"{IMAGE}_scheduled_tasks.json").write_text('[{"Task Name": "trunc')
    requested = ["pslist", "pstree", "malfind", "scheduled_tasks", "netscan"]
    monkeypatch.setattr(vml, "build_pipeline",
                        lambda *a, **k: _Pipe(set(requested)))
    return artifacts, requested, finished


def _salvage(artifacts, requested):
    return vml.salvage_triage(
        str(artifacts.parent / IMAGE), str(artifacts),
        vol_path=None, timeout_s=60, plugins=requested)


def test_the_plugins_that_finished_still_produce_a_triage(halted_run):
    artifacts, requested, finished = halted_run
    view = _salvage(artifacts, requested)
    assert view is not None
    assert view["processes"], "pslist finished, so there must be an inventory"
    assert sorted(view["completed_plugins"]) == sorted(finished)


def test_a_plugin_that_never_ran_is_unevaluated_not_silent(halted_run):
    """The distinction the whole thing rests on: no evidence read vs nothing found.

    netscan was requested and never ran, so its rules must be reported as having
    had nothing to read. Were the requested set handed to the engine instead of
    the completed one, they would read as rules that ran and found no C2.
    """
    artifacts, requested, _ = halted_run
    view = _salvage(artifacts, requested)
    assert "netscan" in view["dashboard"]["unevaluated_sources"]


def test_a_truncated_artifact_is_not_counted_as_evidence(halted_run):
    """Killed mid-write leaves a file that exists and is useless."""
    artifacts, requested, _ = halted_run
    view = _salvage(artifacts, requested)
    assert "scheduled_tasks" not in view["completed_plugins"]
    assert "scheduled_tasks" in view["extraction"]["failed_plugins"]


def test_the_shortfall_is_reported_as_degraded(halted_run):
    artifacts, requested, finished = halted_run
    view = _salvage(artifacts, requested)
    health = view["extraction"]
    assert health["degraded"] is True
    assert health["plugins_attempted"] == len(requested)
    assert health["plugins_failed"] == len(requested) - len(finished)


def test_nothing_usable_on_disk_salvages_nothing(tmp_path, monkeypatch):
    """No evidence must stay no triage, rather than an empty one that looks real."""
    artifacts = tmp_path / "volmemlyzer"
    artifacts.mkdir()
    monkeypatch.setattr(vml, "build_pipeline", lambda *a, **k: _Pipe({"pslist"}))
    assert vml.salvage_triage(str(tmp_path / IMAGE), str(artifacts),
                              vol_path=None, timeout_s=60, plugins=["pslist"]) is None


def test_salvage_reads_only_what_is_on_disk(halted_run, monkeypatch):
    """It must never reach for Volatility: the run it is rescuing already failed."""
    artifacts, requested, _ = halted_run
    monkeypatch.setattr(
        vml, "run_symbol_resilient",
        lambda *a, **k: pytest.fail("salvage must not run plugins"))
    assert _salvage(artifacts, requested) is not None


# --- the reuse guard -------------------------------------------------------

def test_a_partial_triage_is_never_reused_as_a_complete_one(tmp_path):
    """Otherwise the next run silently inherits the coverage gap."""
    from memtriage.scoring import TuningProfile
    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import TRIAGE_SCHEMA_VERSION, _reusable_triage

    paths = InvestigationPaths("abc")
    paths.triage.parent.mkdir(parents=True, exist_ok=True)
    # Everything else a reusable triage needs, so only the partial flag differs.
    payload = {
        "dumps": [{"sha256": "deadbeef"}],
        "extraction": {"degraded": False, "plugins_failed": 0,
                       "failed_plugins": {}, "plugins_attempted": 1},
        "profile": TuningProfile.from_preset("balanced").to_dict(),
        "triage_config": {"plugins": ["pslist"], "schema_version": TRIAGE_SCHEMA_VERSION,
                          "partial": True},
    }
    paths.triage.write_text(json.dumps(payload))
    try:
        assert _reusable_triage(paths, "deadbeef", ["pslist"]) is None
        # The same payload without the partial flag is reusable, so the guard
        # above is what rejected it and not some unrelated mismatch.
        payload["triage_config"].pop("partial")
        paths.triage.write_text(json.dumps(payload))
        assert _reusable_triage(paths, "deadbeef", ["pslist"]) is not None
    finally:
        paths.triage.unlink(missing_ok=True)


# --- presets ---------------------------------------------------------------

def test_light_is_exactly_the_measured_fast_set():
    """The preset and the picker's cost label must not disagree."""
    from memtriage.pipeline.plugin_runner import _PLUGINS

    fast = {name for name, (_c, cost, _d) in _PLUGINS.items() if cost == "fast"}
    assert set(vml.LIGHT_TRIAGE_PLUGINS) == fast


def test_deep_covers_everything_light_does():
    assert set(vml.LIGHT_TRIAGE_PLUGINS) <= set(vml.DEEP_TRIAGE_PLUGINS)


def test_deep_adds_the_scanners_light_leaves_out():
    added = set(vml.DEEP_TRIAGE_PLUGINS) - set(vml.LIGHT_TRIAGE_PLUGINS)
    assert {"psscan", "psxview", "netscan", "handles", "registry.hivescan"} <= added


def test_no_preset_carries_a_duplicate():
    for preset in (vml.LIGHT_TRIAGE_PLUGINS, vml.DEEP_TRIAGE_PLUGINS):
        assert len(preset) == len(set(preset))


def test_a_plugin_that_never_started_is_not_blamed_for_bad_output(halted_run):
    """"Produced no parseable output" is a claim about a plugin that ran."""
    artifacts, requested, _ = halted_run
    failed = _salvage(artifacts, requested)["extraction"]["failed_plugins"]
    assert failed["netscan"] == "did not run before the triage halted"
    assert "parseable" in failed["scheduled_tasks"]

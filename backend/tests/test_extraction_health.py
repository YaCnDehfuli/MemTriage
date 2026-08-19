"""An empty triage must say whether the image was clean or Volatility could not run.

These cover the MemTriage half of the symbol failure: forwarding symbol
directories to VolMemLyzer only when it supports them, and turning plugin
failures into something the analyst sees.
"""
from __future__ import annotations

from memtriage.pipeline import volmemlyzer_adapter as vml

# --------------------------------------------------------------------------
# symbol directories
# --------------------------------------------------------------------------

def test_only_populated_symbol_dirs_are_used(tmp_path):
    populated = tmp_path / "good"
    (populated / "windows").mkdir(parents=True)
    (populated / "windows" / "ntkrnlmp.json.xz").write_bytes(b"x")
    empty = tmp_path / "empty"
    empty.mkdir()

    usable = vml.usable_symbol_dirs([
        str(populated), str(empty), str(tmp_path / "missing"), "",
    ])
    assert usable == [str(populated)]


def test_no_symbol_dirs_configured_is_not_an_error():
    assert vml.usable_symbol_dirs(None) == []
    assert vml.usable_symbol_dirs([]) == []


def _fake_volmemlyzer(monkeypatch, *, supports_symbols: bool):
    """Stand in for the installed VolMemLyzer, with or without the patch."""
    import sys
    import types

    captured: dict = {}

    if supports_symbols:
        class VolRunner:
            def __init__(self, vol_path=None, default_timeout_s=None,
                         default_renderer="json", symbol_dirs=None, offline=False):
                captured.update(symbol_dirs=symbol_dirs, offline=offline)
    else:
        class VolRunner:
            def __init__(self, vol_path=None, default_timeout_s=None,
                         default_renderer="json"):
                captured.update(symbol_dirs=None, offline=None)

    class Pipeline:
        def __init__(self, runner, registry):
            self.runner, self.registry = runner, registry

    for name, attrs in {
        "volmemlyzer.runner": {"VolRunner": VolRunner},
        "volmemlyzer.pipeline": {"Pipeline": Pipeline},
        "volmemlyzer.plugins": {"build_registry": lambda: object()},
    }.items():
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        monkeypatch.setitem(sys.modules, name, module)
    return captured


def test_symbol_dirs_are_forwarded_when_supported(monkeypatch, tmp_path):
    symbols = tmp_path / "symbols"
    (symbols / "windows").mkdir(parents=True)
    (symbols / "windows" / "k.json.xz").write_bytes(b"x")
    captured = _fake_volmemlyzer(monkeypatch, supports_symbols=True)

    vml.build_pipeline(None, 60, symbol_dirs=[str(symbols)], offline=True)
    assert captured["symbol_dirs"] == [str(symbols)]
    assert captured["offline"] is True


def test_an_older_volmemlyzer_still_works_but_warns(monkeypatch, tmp_path, caplog):
    symbols = tmp_path / "symbols"
    (symbols / "windows").mkdir(parents=True)
    (symbols / "windows" / "k.json.xz").write_bytes(b"x")
    _fake_volmemlyzer(monkeypatch, supports_symbols=False)

    with caplog.at_level("WARNING"):
        vml.build_pipeline(None, 60, symbol_dirs=[str(symbols)], offline=True)
    assert "cannot forward them" in caplog.text


# --------------------------------------------------------------------------
# extraction health
# --------------------------------------------------------------------------

def test_a_clean_run_is_not_degraded():
    health = vml.extraction_health(62, {})
    assert health["degraded"] is False
    assert health["severity"] == "ok"
    assert health["plugins_failed"] == 0


def test_a_few_failures_are_a_warning():
    health = vml.extraction_health(62, {"modules": "vol exited 1"})
    assert health["severity"] == "warning"
    assert health["degraded"] is True
    assert "some features and evidence are missing" in health["message"]


def test_widespread_failure_is_critical():
    failures = {f"plugin{i}": "vol exited 1" for i in range(40)}
    health = vml.extraction_health(62, failures)
    assert health["severity"] == "critical"
    assert "one shared cause" in health["message"]


def test_symbol_failures_name_the_cause_and_the_fix():
    failures = {
        "pslist": "vol exited 1; see /data/x_pslist.json.stderr.txt",
        "modules": "Symbol file could not be downloaded from remote server",
    }
    health = vml.extraction_health(62, failures)
    assert health["severity"] == "critical"
    assert "kernel symbol table" in health["message"]
    assert "empty rather than clean" in health["message"]
    assert "docs/SYMBOLS.md" in health["message"]


def test_failed_plugins_are_reported_sorted():
    health = vml.extraction_health(3, {"b": "x", "a": "y"})
    assert list(health["failed_plugins"]) == ["a", "b"]


# --------------------------------------------------------------------------
# the health block reaches the persisted triage record
# --------------------------------------------------------------------------

def test_triage_record_carries_extraction_health(client, monkeypatch):
    import json

    from memtriage.storage import InvestigationPaths
    from memtriage.workers.tasks import run_triage

    inv_id = client.post("/api/investigations").json()["investigation_id"]
    client.post(f"/api/investigations/{inv_id}/dumps", content=b"x" * 64,
                headers={"X-Filename": "mem.raw"})

    health = vml.extraction_health(62, {"pslist": "Symbol file could not be downloaded"})
    monkeypatch.setattr(vml, "run_triage", lambda *a, **k: {
        "features": {}, "dashboard": {}, "processes": [], "profile": {},
        "manifest": {}, "vol_version": "Volatility 3 Framework 2.28.0",
        "extraction": health,
    })
    run_triage.apply(args=[inv_id])

    record = json.loads(InvestigationPaths(inv_id).triage.read_text())
    assert record["extraction"]["severity"] == "critical"
    assert "kernel symbol table" in record["extraction"]["message"]


def test_symbols_diagnostic_reports_missing_and_present(monkeypatch, tmp_path):
    from memtriage import diagnostics

    settings = diagnostics.get_settings()
    monkeypatch.setattr(settings, "vol_symbol_dirs", [str(tmp_path / "nope")])
    check = diagnostics.check_symbols()
    assert check.status == diagnostics.MISSING
    assert "SYMBOLS.md" in check.remediation

    good = tmp_path / "symbols" / "windows" / "ntkrnlmp.pdb"
    good.mkdir(parents=True)
    (good / "ABC-1.json.xz").write_bytes(b"x")
    monkeypatch.setattr(settings, "vol_symbol_dirs", [str(tmp_path / "symbols")])
    assert diagnostics.check_symbols().status == diagnostics.OK


def test_symbols_diagnostic_when_nothing_is_configured(monkeypatch):
    from memtriage import diagnostics

    monkeypatch.setattr(diagnostics.get_settings(), "vol_symbol_dirs", [])
    check = diagnostics.check_symbols()
    assert check.status == diagnostics.MISSING
    assert "no symbol directories configured" in check.detail

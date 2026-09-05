"""Seeding a real Investigation from captured VolMemLyzer artifacts, and
proving the real (unmocked) volmemlyzer_adapter -> scoring engine path runs
against them: this is what makes the triage step live from Dumps/, without
re-running Volatility against a multi-GB image every time.

Needs volatility3 importable (a hard project dependency — see
backend/requirements.txt) so VolRunner can resolve a `vol` command; offline
mode and a short timeout keep the handful of plugins NOT covered by the
trimmed fixture (this repo ships a tiny stand-in image, not a real one) fast
and deterministic instead of hanging on symbol downloads.
"""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures" / "dumps_2580_5"
STANDIN_IMAGE = FIXTURES / "2580_5.vmem"
STANDIN_SIZE = 4096


@pytest.fixture(autouse=True)
def _offline_and_fast(monkeypatch):
    from memtriage.workers import tasks

    monkeypatch.setattr(tasks.settings, "vol_offline", True)
    monkeypatch.setattr(tasks.settings, "vol_timeout_s", 5)
    monkeypatch.setattr(tasks.settings, "vol_symbol_dirs", [])


@pytest.fixture(autouse=True)
def _standin_image():
    """*.vmem is gitignored, so CI has the cached JSON but not the 4 KiB stand-in."""
    if not STANDIN_IMAGE.is_file():
        STANDIN_IMAGE.write_bytes(b"\x00" * STANDIN_SIZE)


def test_seeds_real_rows_and_copies_cached_artifacts(client):
    from memtriage.pipeline.fixture_seed import seed_investigation_from_dumps

    summary = seed_investigation_from_dumps(FIXTURES, run=False)
    # 11 plugins x (json + stderr), minus the one oversized stderr the fixture
    # deliberately excludes (info.json.stderr.txt — see the fixture directory).
    assert summary["artifacts_copied"] == 21
    assert summary["dump_size_bytes"] == 4096

    inv = client.get(f"/api/investigations/{summary['investigation_id']}").json()
    assert inv["dump_count"] == 1
    assert inv["total_bytes"] == 4096


def test_live_triage_from_cached_artifacts_produces_a_populated_dashboard(client):
    pytest.importorskip("volmemlyzer")
    from memtriage.pipeline.fixture_seed import seed_investigation_from_dumps

    summary = seed_investigation_from_dumps(FIXTURES)

    assert summary["task_result"] == "triaged"
    # The cached plugins carry real findings (this is the actual scoring engine,
    # not a mock) — a genuinely empty dashboard here would mean the cache-hit
    # path silently broke, not that the image is clean.
    assert summary["risk_summary"].get("total", 0) > 0
    assert summary["suspicious_processes"] > 0
    assert summary["attack_techniques"] > 0
    assert summary["persistence"] > 0
    assert summary["process_count"] > 0

    # extraction_health() now measures only the selected Deep preset. This
    # trimmed fixture covers 11 of its 17 plugins, so the missing six report an
    # honest degraded warning while the cached results still populate the
    # dashboard. Light/Custom runs likewise measure only what was requested.
    extraction = summary["extraction"]
    assert extraction["degraded"] is True
    assert extraction["severity"] == "warning"

    inv = client.get(f"/api/investigations/{summary['investigation_id']}").json()
    assert inv["status"] == "triaged"
    assert inv["process_count"] > 0

    result = client.get(f"/api/investigations/{summary['investigation_id']}/result").json()
    assert result["triage"]["dashboard"]["risk_summary"]["total"] > 0

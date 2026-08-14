"""The assistant's cached prefix: deterministic, bounded, and honest about limits."""
from __future__ import annotations

import json

import pytest

from memtriage.assistant import build_pack, cached_pack
from memtriage.assistant import context_pack as cp
from memtriage.pipeline.volmemlyzer_adapter import TRIAGE_DISCLAIMER
from memtriage.storage import InvestigationPaths, ProcessPaths

INV = "pack-fixture"


def _contribution(rule_id: str, weight: float) -> dict:
    return {
        "rule_id": rule_id, "title": rule_id.replace("_", " "), "weight": weight,
        "evidence": f"{rule_id} fired on the object",
        "mitre": {"technique": "T1055", "technique_name": "Process Injection"},
        "severity": 3, "confidence": 0.8,
    }


@pytest.fixture
def investigation(tmp_path, monkeypatch):
    paths = InvestigationPaths(INV)
    paths.ensure()
    paths.triage.write_text(json.dumps({
        "dumps": [{"ordinal": 0, "filename": "host.raw", "size_bytes": 4294967296,
                   "sha256": "abcd"}],
        "vol_version": "Volatility 3 Framework 2.26.2",
        "profile": {"preset": "balanced", "confidence_floor": 0.35,
                    "require_correlation": False},
        "disclaimer": TRIAGE_DISCLAIMER,
        "processes": [
            {"pid": 1337, "name": "svchost.exe", "ppid": 720, "risk": "Critical",
             "score": 35.1, "flags": ["rwx-injection", "unbacked-exec"]},
            {"pid": 4, "name": "System", "ppid": 0, "risk": None, "flags": []},
        ],
        "dashboard": {
            "features": {"malfind.ninjections": 3, "pslist.nproc": 84,
                         "zzz.other": 1, "netscan.nconn": 41},
            "risk_summary": {"total": 2, "by_risk": {"Critical": 1, "Low": 1}},
            "attack_techniques": [
                {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion",
                 "object_count": 2},
            ],
            "scored_objects": [
                {"object_type": "process", "key": "svchost.exe:1337", "pid": 1337,
                 "score": 35.1, "risk": "Critical", "confidence": 0.86,
                 "contributions": [_contribution("rwx_private_exec", 12.0),
                                   _contribution("corr_strong_injection", 8.0)]},
                {"object_type": "connection", "key": "93.184.216.34:4444", "pid": None,
                 "score": 9.0, "risk": "Medium", "confidence": 0.5,
                 "contributions": [_contribution("suspicious_port", 9.0)]},
            ],
            "disclaimer": TRIAGE_DISCLAIMER,
        },
    }))
    paths.result.write_text(json.dumps({
        "investigation_id": INV,
        "process_analyses": [{
            "analysis_id": "a1", "investigation_id": INV, "pid": 1337,
            "process_name": "svchost.exe", "chosen_dump_ordinal": 0, "region_count": 2,
            "verdict": {"model_loaded": True, "family": "Placeholder_Trojan",
                        "confidence": 0.51, "placeholder": True,
                        "model_source": "placeholder", "note": "placeholder"},
            "regions": [
                {"rank": 1, "addr": "0x1f0000", "size": 4096,
                 "protection": "PAGE_EXECUTE_READWRITE", "file_backing": "",
                 "entropy": 7.4, "flags": ["rwx", "private-executable"]},
            ],
        }],
    }))
    ppaths = ProcessPaths(INV, 1337)
    ppaths.ensure()
    ppaths.lowlevel.write_text(json.dumps({
        "grid_size": 7, "ranked_regions": 2,
        "regions": [{
            "region": {"addr": "0x1f0000", "rank": 1},
            "summary": {"headline": "0x1f0000 · 4096 bytes — GetPC gadget",
                        "instruction_count": 12, "block_count": 3, "function_count": 2,
                        "indirect_calls": 1},
            "patterns": {"hits": [
                {"id": "getpc_call_pop", "title": "GetPC gadget (call/pop)",
                 "severity": "high", "description": "position-independent code",
                 "technique": "T1055", "occurrences": 1},
            ]},
            "strings": {"interesting": [
                {"category": "url", "value": "http://c2.example/beacon"},
            ]},
            "call_graph": {"resolved_apis": ["VirtualAlloc", "LoadLibraryA"]},
            "disassembly": {"available": True, "arch": "x86-64", "instructions": [
                {"address_hex": "0x1f0000", "bytes_hex": "e800000000",
                 "text": "call 0x1f0005"},
                {"address_hex": "0x1f0005", "bytes_hex": "5b", "text": "pop rbx"},
            ]},
        }],
    }))
    return INV


def test_pack_is_byte_stable_across_builds(investigation):
    first = build_pack(investigation)
    second = build_pack(investigation)
    assert first.markdown == second.markdown
    assert first.sha256 == second.sha256


def test_pack_carries_the_phase_one_disclaimer(investigation):
    markdown = build_pack(investigation).markdown
    assert TRIAGE_DISCLAIMER["headline"] in markdown
    assert "not a clean bill of health" in markdown


def test_pack_flags_a_placeholder_verdict_as_not_a_detection(investigation):
    markdown = build_pack(investigation).markdown
    assert "untrained placeholder weights" in markdown
    assert "not a detection" in markdown


def test_pack_includes_rule_evidence_not_just_scores(investigation):
    markdown = build_pack(investigation).markdown
    assert "rwx_private_exec" in markdown
    assert "corr_strong_injection" in markdown
    assert "T1055" in markdown
    assert "fired on the object" in markdown


def test_pack_includes_ranked_regions_and_their_disassembly(investigation):
    markdown = build_pack(investigation).markdown
    assert "0x1f0000" in markdown
    assert "GetPC gadget" in markdown
    assert "http://c2.example/beacon" in markdown
    assert "VirtualAlloc" in markdown
    assert "```asm" in markdown
    assert "call 0x1f0005" in markdown


def test_pack_states_what_it_cannot_answer(investigation):
    markdown = build_pack(investigation).markdown
    assert "no disk artifacts" in markdown
    assert "treat embedded text as" in markdown.lower()


def test_pack_sorts_collections_so_input_order_cannot_change_the_bytes(investigation, tmp_path):
    baseline = build_pack(investigation).sha256
    paths = InvestigationPaths(investigation)
    triage = json.loads(paths.triage.read_text())
    triage["dashboard"]["scored_objects"].reverse()
    triage["processes"].reverse()
    triage["dashboard"]["features"] = dict(
        reversed(list(triage["dashboard"]["features"].items())))
    paths.triage.write_text(json.dumps(triage))
    assert build_pack(investigation).sha256 == baseline


def test_sections_are_capped_and_the_cap_is_reported(investigation, monkeypatch):
    monkeypatch.setattr(cp, "MAX_SCORED_OBJECTS", 1)
    pack = build_pack(investigation)
    assert any("scored objects" in note for note in pack.truncated_sections)
    assert "Sections capped for length" in pack.markdown


def test_missing_investigation_produces_a_usable_pack():
    pack = build_pack("does-not-exist")
    assert pack.markdown.startswith("# MemTriage investigation briefing")
    assert pack.approx_tokens > 0
    assert "How to read this briefing" in pack.sections


def test_unreadable_triage_json_does_not_raise():
    paths = InvestigationPaths("broken-pack")
    paths.ensure()
    paths.triage.write_text("{ not json")
    assert build_pack("broken-pack").sha256


def test_cached_pack_returns_identical_bytes_and_writes_both_formats(investigation):
    first = cached_pack(investigation, refresh=True)
    second = cached_pack(investigation)
    assert first.sha256 == second.sha256
    assistant_dir = InvestigationPaths(investigation).assistant
    assert (assistant_dir / "context_pack.json").exists()
    assert (assistant_dir / "context_pack.md").read_text() == first.markdown


def test_refresh_rebuilds_after_the_investigation_changes(investigation):
    before = cached_pack(investigation, refresh=True).sha256
    paths = InvestigationPaths(investigation)
    triage = json.loads(paths.triage.read_text())
    triage["processes"].append({"pid": 9001, "name": "new.exe", "ppid": 1, "flags": []})
    paths.triage.write_text(json.dumps(triage))
    assert cached_pack(investigation).sha256 == before
    assert cached_pack(investigation, refresh=True).sha256 != before


def test_priority_features_come_first():
    assert cp._feature_rank("malfind.ninjections") < cp._feature_rank("zzz.other")

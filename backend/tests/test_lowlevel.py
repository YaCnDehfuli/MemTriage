"""Low-level region analysis: disassembly, CFG, call graph, patterns, structure.

Capstone is optional, so every test that needs a decoder skips without it and the
degradation path is asserted explicitly instead.
"""
from __future__ import annotations

import numpy as np
import pytest

from memtriage.lowlevel import Budget, analyze_region, build_manifest
from memtriage.lowlevel import callgraph as cg
from memtriage.lowlevel import cfg as cfgmod
from memtriage.lowlevel import disasm as dis
from memtriage.lowlevel import manifest as mf
from memtriage.lowlevel import patterns as pat
from memtriage.lowlevel import strings_extract as sx
from memtriage.lowlevel import structure as st

needs_capstone = pytest.mark.skipif(
    not dis.capstone_available(), reason="capstone is not installed"
)

# push rbp; mov rbp,rsp; sub rsp,0x20; test eax,eax; je +5; add eax,1; jmp +3;
# or eax,-1; leave; ret  -> a diamond with a join block.
DIAMOND = bytes.fromhex("554889e54883ec2085c0740583c001eb0383c8ffc9c3")
# call $+5 ; pop rbx  -> the classic GetPC gadget
GETPC = bytes.fromhex("e8000000005b")
LOOP = bytes.fromhex("8a0630074647" "75f8" "c3")  # mov/xor/inc/inc + backward jne


class FakeRegion:
    def __init__(self, addr, data, protection="PAGE_EXECUTE_READWRITE",
                 category="exe", tag="VadS", file_backing="", private=True):
        self.addr = addr
        self.data = np.frombuffer(data, dtype=np.uint8)
        self.protection = protection
        self.category = category
        self.tag = tag
        self.file_backing = file_backing
        self.private = private
        self.end_addr = addr + len(data)
        self.snapshot_ordinal = 0


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------

def test_manifest_ranks_by_attention_and_keeps_grid_position():
    regions = [FakeRegion(0x1000, b"a" * 16), FakeRegion(0x2000, b"b" * 16),
               FakeRegion(0x3000, b"c" * 16)]
    records = build_manifest(regions, [0.1, 0.9, 0.5] + [0.0] * 46, 7)
    assert [r.addr for r in records] == ["0x2000", "0x3000", "0x1000"]
    assert [r.rank for r in records] == [1, 2, 3]
    by_patch = {r.patch_index: r for r in records}
    assert (by_patch[0].row, by_patch[0].col) == (0, 0)
    assert (by_patch[2].row, by_patch[2].col) == (0, 2)


def test_manifest_without_attention_still_covers_every_region():
    regions = [FakeRegion(0x1000, b"a" * 8), FakeRegion(0x2000, b"b" * 8)]
    records = build_manifest(regions, None, 7)
    assert len(records) == 2
    assert all(r.attention == 0.0 for r in records)


def test_manifest_truncates_to_the_grid():
    regions = [FakeRegion(0x1000 + i, b"x" * 4) for i in range(80)]
    assert len(build_manifest(regions, None, 7)) == 49


def test_manifest_flags_describe_the_allocation():
    private_rwx = build_manifest([FakeRegion(0x1000, b"MZ" + b"\x00" * 32)], None, 7)[0]
    assert {"rwx", "private-executable", "no-file-backing", "mz-header"} <= set(private_rwx.flags)

    mapped = build_manifest(
        [FakeRegion(0x1000, b"\x00" * 64, protection="PAGE_EXECUTE_READ",
                    file_backing=r"\Windows\System32\ntdll.dll", private=False)], None, 7)[0]
    assert "rwx" not in mapped.flags and "no-file-backing" not in mapped.flags
    assert mapped.executable is True and mapped.writable is False


def test_manifest_hashes_and_measures_entropy():
    record = build_manifest([FakeRegion(0x1000, b"AAAA" * 64)], None, 7)[0]
    assert len(record.sha256) == 64
    assert record.entropy == 0.0
    assert record.size == 256


def test_attention_normalization_handles_a_flat_vector():
    assert mf._normalized([0.5] * 49, 49) == [0.0] * 49
    assert mf._normalized(None, 4) == [0.0] * 4
    assert mf._normalized([0.0, 1.0], 4) == [0.0, 1.0, 0.0, 0.0]


# --------------------------------------------------------------------------
# disassembly
# --------------------------------------------------------------------------

def test_disassembly_reports_why_it_is_unavailable(monkeypatch):
    monkeypatch.setattr(dis, "capstone_available", lambda: False)
    listing = dis.disassemble(DIAMOND, 0x1000)
    assert listing.available is False
    assert "capstone" in listing.reason.lower()
    assert listing.to_dict()["instruction_count"] == 0


def test_empty_region_is_not_an_error():
    assert dis.disassemble(b"", 0x1000).available is False


@needs_capstone
def test_disassembly_recovers_instructions_and_classifies_control_flow():
    listing = dis.disassemble(DIAMOND, 0x1000)
    assert listing.available is True
    assert listing.coverage == pytest.approx(1.0)
    kinds = [i.kind for i in listing.instructions]
    assert "cjump" in kinds and "jump" in kinds and "ret" in kinds
    branch = next(i for i in listing.instructions if i.kind == "cjump")
    assert branch.target is not None and branch.target > branch.address


@needs_capstone
def test_direct_targets_outside_the_region_are_not_claimed():
    # call to a far absolute address: no target inside this region
    listing = dis.disassemble(bytes.fromhex("e800000f00c3"), 0x1000)
    calls = [i for i in listing.instructions if i.kind == "call"]
    assert all(c.target is None for c in calls)


@needs_capstone
def test_architecture_is_detected_and_can_be_forced():
    assert dis.detect_arch(DIAMOND) in (dis.X86, dis.X64)
    assert dis.disassemble(DIAMOND, 0, arch=dis.X86).arch == dis.X86
    assert dis.disassemble(DIAMOND, 0, arch=dis.X64).arch == dis.X64


@needs_capstone
def test_budget_caps_the_bytes_and_instructions_decoded():
    listing = dis.disassemble(b"\x90" * 4096, 0, budget=Budget(max_bytes=64,
                                                              max_instructions=10))
    assert listing.analyzed_bytes == 64
    assert listing.truncated is True
    assert len(listing.instructions) <= 10


def test_entry_candidates_include_the_pe_entry_point():
    header = bytearray(b"MZ" + b"\x00" * 0x3E)
    header[0x3C:0x40] = (0x40).to_bytes(4, "little")
    header += b"PE\x00\x00" + b"\x00" * 0x40
    header[0x40 + 0x28:0x40 + 0x2C] = (0x120).to_bytes(4, "little")
    assert 0x1000 + 0x120 in dis.entry_candidates(bytes(header), 0x1000)


# --------------------------------------------------------------------------
# control flow
# --------------------------------------------------------------------------

def test_cfg_reports_the_disassembler_reason_when_unavailable(monkeypatch):
    monkeypatch.setattr(dis, "capstone_available", lambda: False)
    graph = cfgmod.build_cfg(dis.disassemble(DIAMOND, 0x1000))
    assert graph.available is False and "capstone" in graph.reason.lower()


@needs_capstone
def test_cfg_splits_a_diamond_into_four_blocks():
    graph = cfgmod.build_cfg(dis.disassemble(DIAMOND, 0x1000))
    assert graph.available is True
    assert len(graph.blocks) == 4
    kinds = {(e.source, e.target): e.kind for e in graph.edges}
    assert ("fallthrough" in kinds.values()) and ("taken" in kinds.values())
    assert graph.entry_block == 0
    # Both arms of the branch reach the same join block.
    targets = {e.target for e in graph.edges}
    assert len(targets) == 3


@needs_capstone
def test_cfg_layers_flow_forward_from_the_entry():
    graph = cfgmod.build_cfg(dis.disassemble(DIAMOND, 0x1000))
    layers = {b.id: b.layer for b in graph.blocks}
    assert layers[graph.entry_block] == 0
    assert max(layers.values()) >= 1
    within = [(b.layer, b.order) for b in graph.blocks]
    assert len(set(within)) == len(within)


@needs_capstone
def test_cfg_dot_export_names_every_block():
    graph = cfgmod.build_cfg(dis.disassemble(DIAMOND, 0x1000))
    dot = cfgmod.to_dot(graph)
    assert dot.startswith("digraph cfg {")
    for block in graph.blocks:
        assert f"b{block.id} [" in dot


@needs_capstone
def test_cfg_respects_the_block_budget():
    code = bytes.fromhex("c3") * 400
    graph = cfgmod.build_cfg(dis.disassemble(code, 0), Budget(max_blocks=16))
    assert len(graph.blocks) <= 16 and graph.truncated is True


# --------------------------------------------------------------------------
# call graph
# --------------------------------------------------------------------------

@needs_capstone
def test_callgraph_links_a_direct_call_to_its_target():
    code = bytes.fromhex("e800000000" + "c3" + "c3")
    graph = cg.build_callgraph(dis.disassemble(code, 0x1000), code)
    assert graph.available is True
    assert graph.edges, "the direct call should produce an edge"
    assert graph.indirect_calls == 0


@needs_capstone
def test_callgraph_counts_indirect_calls_instead_of_dropping_them():
    code = bytes.fromhex("ffd0" "ffd3" "ffd1" "ffd2" "c3")
    graph = cg.build_callgraph(dis.disassemble(code, 0x1000), code)
    assert graph.indirect_calls >= 4


def test_callgraph_surfaces_notable_api_names_from_the_bytes():
    data = b"junk\x00VirtualAlloc\x00CreateRemoteThread\x00NotAnApiNameHere\x00"
    names = cg.candidate_api_names(data)
    assert names == ["VirtualAlloc", "CreateRemoteThread"]


def test_callgraph_degrades_with_the_listing(monkeypatch):
    monkeypatch.setattr(dis, "capstone_available", lambda: False)
    graph = cg.build_callgraph(dis.disassemble(DIAMOND, 0x1000), DIAMOND)
    assert graph.available is False and graph.to_dict()["node_count"] == 0


# --------------------------------------------------------------------------
# patterns
# --------------------------------------------------------------------------

def test_getpc_gadget_is_flagged_without_a_disassembler():
    hits = {h.id: h for h in pat.scan_bytes(b"\x00" * 8 + GETPC + b"\x00" * 8)}
    assert "getpc_call_pop" in hits
    assert hits["getpc_call_pop"].severity == "high"
    assert hits["getpc_call_pop"].technique == "T1055"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"\x64\xa1\x30\x00\x00\x00", "peb_walk_x86"),
        (b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00", "peb_walk_x64"),
        (b"\x90" * 24, "nop_sled"),
        (b"\xc1\xcf\x0d", "api_hash_ror13"),
        (b"http://evil.example/payload", "http_c2"),
        (b"powershell -enc AAAABBBB", "powershell_encoded"),
        (b"w00tw00t", "egg_hunter"),
        (b"ReflectiveLoader", "reflective_loader"),
        (rb"Software\Microsoft\Windows\CurrentVersion\Run", "runkey_persistence"),
    ],
)
def test_byte_rules_match_their_signature(payload, expected):
    assert expected in {h.id for h in pat.scan_bytes(payload)}


def test_rules_with_a_minimum_occurrence_need_more_than_one_hit():
    assert "sysenter_stub" not in {h.id for h in pat.scan_bytes(b"\x0f\x34")}
    assert "sysenter_stub" in {h.id for h in pat.scan_bytes(b"\x0f\x34\x90\x0f\x34")}


def test_allocation_properties_are_flagged_independently_of_content():
    hits = {h.id for h in pat.region_context_hits(
        {"protection": "PAGE_EXECUTE_READWRITE", "private": True, "entropy": 7.9})}
    assert {"rwx_region", "private_executable", "high_entropy_region"} <= hits

    benign = {h.id for h in pat.region_context_hits(
        {"protection": "PAGE_READONLY", "private": False, "entropy": 3.0})}
    assert benign == set()


def test_scan_sorts_by_severity_and_notes_skipped_instruction_checks(monkeypatch):
    monkeypatch.setattr(dis, "capstone_available", lambda: False)
    report = pat.scan(GETPC + b"\x90" * 24, dis.disassemble(GETPC, 0),
                      {"protection": "PAGE_READONLY", "private": False})
    assert report.instruction_scan is False
    assert "capstone" in report.note.lower()
    severities = [pat.SEVERITY_ORDER[h.severity] for h in report.hits]
    assert severities == sorted(severities, reverse=True)
    assert report.to_dict()["highest_severity"] == report.hits[0].severity


def test_scan_of_empty_bytes_reports_nothing_rather_than_failing():
    report = pat.scan(b"", None, {})
    assert report.hits == [] and report.to_dict()["highest_severity"] == "none"


@needs_capstone
def test_instruction_rules_find_a_decoder_loop():
    listing = dis.disassemble(LOOP, 0x1000, arch=dis.X86)
    hits = {h.id for h in pat.scan_instructions(listing)}
    assert "decoder_loop" in hits


# --------------------------------------------------------------------------
# structure and strings
# --------------------------------------------------------------------------

def test_entropy_profile_separates_a_packed_span():
    import os

    data = b"\x00" * 4096 + os.urandom(4096)
    profile = st.entropy_profile(data, Budget(entropy_windows=32))
    assert profile.peak > 7.0
    assert profile.peak_offset >= len(data) // 2 - profile.window_bytes
    assert 0.0 < profile.high_entropy_ratio <= 1.0


def test_entropy_of_uniform_bytes_is_zero():
    assert st.entropy_of(b"A" * 1024) == 0.0
    assert st.entropy_profile(b"").overall == 0.0


def test_histogram_and_printable_ratio():
    assert sum(st.byte_histogram(b"AB" * 50)) == 100
    assert st.printable_ratio(b"hello") == 1.0
    assert st.printable_ratio(b"\x00\x01\x02\x03") == 0.0


def test_hexdump_rows_carry_offset_address_and_ascii():
    rows = st.hexdump(b"ABCDEFGH", base_addr=0x400000, width=4)
    assert len(rows) == 2
    assert rows[0]["address"] == "0x400000" and rows[0]["ascii"] == "ABCD"
    assert rows[1]["offset"] == 4


def test_pe_parser_reports_absence_plainly():
    header = st.parse_pe(b"not a pe file at all")
    assert header.present is False and "MZ" in header.reason


def test_minimal_pe_reader_extracts_the_header():
    data = bytearray(b"MZ" + b"\x00" * 0x3E)
    data[0x3C:0x40] = (0x40).to_bytes(4, "little")
    data += b"PE\x00\x00"
    data += (0x8664).to_bytes(2, "little")      # machine
    data += (1).to_bytes(2, "little")           # section count
    data += (0x60000000).to_bytes(4, "little")  # timestamp
    data += b"\x00" * 8
    data += (0xE0).to_bytes(2, "little")        # optional header size
    data += (0x2000).to_bytes(2, "little")      # characteristics: DLL
    data += (0x20B).to_bytes(2, "little") + b"\x00" * 14
    data += (0x1500).to_bytes(4, "little")      # entry point
    data += b"\x00" * 256
    header = st._parse_pe_minimal(bytes(data))
    assert header.present is True
    assert header.machine == "x86-64" and header.is_dll is True
    assert header.entry_point == "0x1500" and header.parser == "builtin"


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("http://example.com/a", "url"),
        ("10.0.0.1:8080", "ipv4"),
        (r"C:\Windows\Temp\x.exe", "windows-path"),
        (r"\\host\share\file", "unc-path"),
        ("HKEY_LOCAL_MACHINE\\Software", "registry"),
        ("kernel32.dll", "dll"),
        ("powershell.exe -nop", "command"),
        ("plain words here", "text"),
    ],
)
def test_string_classification(value, category):
    assert sx.classify(value) == category


def test_strings_prefer_interesting_ones_when_capped():
    padding = b"\x00".join(b"padding%03d" % i for i in range(50))
    data = padding + b"\x00http://c2.example/beacon\x00"
    report = sx.extract_strings(data, Budget(max_strings=3))
    assert report.truncated is True
    assert any(s.category == "url" for s in report.strings)


def test_strings_are_sanitized_and_bucketed():
    report = sx.extract_strings(b"clean\x00http://a.example/x\x00")
    assert report.by_category.get("url") == 1
    assert all("\x00" not in s.value for s in report.strings)
    assert report.to_dict()["interesting"]


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

def test_analyze_region_returns_every_panel():
    report = analyze_region(GETPC + b"\x90" * 32 + b"http://c2.example/x\x00",
                            {"addr": "0x400000", "addr_int": 0x400000,
                             "protection": "PAGE_EXECUTE_READWRITE", "private": True,
                             "size": 60, "entropy": 5.0})
    assert set(report) == {"region", "structure", "disassembly", "control_flow",
                           "call_graph", "strings", "patterns", "summary"}
    assert report["summary"]["pattern_count"] > 0
    assert "not conclusions" in report["summary"]["caveat"].lower()
    assert report["summary"]["headline"].startswith("0x400000")


def test_analyze_region_survives_a_failing_analyzer(monkeypatch):
    monkeypatch.setattr("memtriage.lowlevel.report.extract_strings",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    report = analyze_region(GETPC, {"addr": "0x1000", "addr_int": 0x1000, "size": 6})
    assert report["strings"]["error"] == "RuntimeError"
    assert report["patterns"]["hit_count"] >= 1


def test_analyze_region_handles_an_empty_region():
    report = analyze_region(b"", {"addr": "0x0", "addr_int": 0, "size": 0})
    assert report["structure"]["size"] == 0
    assert report["disassembly"]["available"] is False


def test_shallow_budget_is_smaller_than_the_deep_one():
    deep, shallow = Budget.deep(), Budget.shallow()
    assert shallow.max_bytes < deep.max_bytes
    assert shallow.max_instructions < deep.max_instructions

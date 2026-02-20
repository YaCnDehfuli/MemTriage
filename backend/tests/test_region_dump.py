"""Region categorization, cross-snapshot consolidation, and record parsing."""
import numpy as np

from memtriage.pipeline.grid_render import Region
from memtriage.pipeline.region_dump import (
    SnapshotRegions,
    categorize,
    regions_from_records,
    select_consolidated,
)


def _r(addr):
    return Region(addr=addr, tag="Vad", protection="PAGE_EXECUTE_READWRITE",
                  category="exe", data=np.zeros(4, dtype=np.uint8))


def test_categorize_rules():
    assert categorize("PAGE_EXECUTE_READWRITE", None) == "exe"      # private exec (injected)
    assert categorize("PAGE_EXECUTE_READ", r"C:\Windows\ntdll.dll") == "dll"
    assert categorize("PAGE_EXECUTE_WRITECOPY", "foo.DLL") == "dll"  # case-insensitive
    assert categorize("PAGE_READWRITE", None) is None               # heap/stack excluded
    assert categorize(None, None) is None


def test_select_consolidated_picks_most_regions():
    snaps = [
        SnapshotRegions(0, [_r(1)]),
        SnapshotRegions(1, [_r(1), _r(2), _r(3)]),
        SnapshotRegions(2, [_r(1), _r(2)]),
    ]
    assert select_consolidated(snaps).ordinal == 1


def test_select_consolidated_ties_go_to_latest():
    snaps = [SnapshotRegions(0, [_r(1)]), SnapshotRegions(1, [_r(9)])]
    assert select_consolidated(snaps).ordinal == 1


def test_regions_from_records_reads_dmp_and_filters(tmp_path):
    (tmp_path / "exec.dmp").write_bytes(b"\x00\x01\x02\x03")
    records = [
        # executable, private -> exe, dmp present
        {"Protection": "PAGE_EXECUTE_READWRITE", "File": None, "Tag": "VadS",
         "Start VPN": 0x1000, "File output": "exec.dmp"},
        # non-executable -> skipped
        {"Protection": "PAGE_READWRITE", "File": None, "Tag": "Vad",
         "Start VPN": 0x2000, "File output": "heap.dmp"},
        # executable dll but dmp missing on disk -> skipped
        {"Protection": "PAGE_EXECUTE_READ", "File": "a.dll", "Tag": "Vad",
         "Start VPN": 0x3000, "File output": "missing.dmp"},
        # dump disabled -> skipped
        {"Protection": "PAGE_EXECUTE_READ", "File": None, "Tag": "Vad",
         "Start VPN": 0x4000, "File output": "Disabled"},
    ]
    regs = regions_from_records(records, tmp_path)
    assert len(regs) == 1
    assert regs[0].category == "exe"
    assert regs[0].addr == 0x1000
    assert list(regs[0].data) == [0, 1, 2, 3]

"""Dump a selected process's VAD regions and consolidate across snapshots.

For a chosen PID, MemTriage runs Volatility 3 ``windows.vadinfo --pid <pid>
--dump`` on each snapshot (this is the region-byte extraction VolMemLyzer does
NOT do), categorizes each region exe/dll by its protection + backing file
(matching VADViT's ``region_divider``), and consolidates by keeping the snapshot
with the most regions (matching VADViT's ``dump_selector``). Regions are read as
opaque bytes only — never executed.

The Volatility subprocess call is thin and lazily invoked (worker image only);
the categorization/consolidation/record-parsing logic is pure and unit-tested.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from .grid_render import Region


@dataclass
class SnapshotRegions:
    ordinal: int
    regions: list[Region] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.regions)


def _field(rec: dict, *keys: str, default=None):
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return default


def _as_int(value) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def categorize(protection: str | None, file_field: str | None) -> str | None:
    """exe / dll for grid-eligible regions; None for heap/stack (excluded).

    Executable regions backed by a .dll are 'dll'; other executable regions
    (the process image + private/injected executable memory) are 'exe'. This is
    the operational form of VADViT's region_divider, which additionally used the
    known malware filename during training (not available here).
    """
    if "execute" not in (protection or "").lower():
        return None
    return "dll" if ".dll" in (file_field or "").lower() else "exe"


def regions_from_records(records: list[dict], dump_dir: Path) -> list[Region]:
    """Turn vadinfo --dump JSON rows + on-disk .dmp files into grid Regions."""
    out: list[Region] = []
    for rec in records:
        category = categorize(_field(rec, "Protection"), _field(rec, "File"))
        if category is None:
            continue
        out_name = _field(rec, "File output", "FileOutput")
        if not out_name or str(out_name).lower() in {"disabled", "error outputting file"}:
            continue
        dmp = dump_dir / str(out_name)
        if not dmp.exists():
            continue
        addr = _as_int(_field(rec, "Start VPN", "Start", default=0)) or 0
        data = np.frombuffer(dmp.read_bytes(), dtype=np.uint8)
        out.append(Region(
            addr=addr,
            tag=str(_field(rec, "Tag", default="")),
            protection=str(_field(rec, "Protection", default="")),
            category=category,
            data=data,
        ))
    return out


def select_consolidated(snapshots: list[SnapshotRegions]) -> SnapshotRegions:
    """Choose the snapshot with the most regions (ties -> latest, per dump_selector)."""
    chosen = snapshots[0]
    best = -1
    for snap in snapshots:
        if snap.count >= best:
            best = snap.count
            chosen = snap
    return chosen


def _vol_command(vol_path: str | None, image_path: str, pid: int, out_dir: str) -> list[str]:
    vol = vol_path or "vol"
    return [vol, "-q", "-r", "json", "-o", out_dir, "-f", image_path,
            "windows.vadinfo", "--pid", str(pid), "--dump"]


def dump_snapshot(image_path: str, pid: int, out_dir: str, *, vol_path: str | None,
                  timeout_s: int) -> list[Region]:
    """Run vadinfo --dump for one PID on one snapshot and parse its regions."""
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(  # noqa: S603 — args are built here, never shell
        _vol_command(vol_path, image_path, pid, out_dir),
        capture_output=True, text=True, timeout=timeout_s, check=False,
    )
    try:
        records = json.loads(proc.stdout or "[]")
    except ValueError:
        records = []
    if isinstance(records, dict):
        records = records.get("rows") or records.get("records") or []
    return regions_from_records([r for r in records if isinstance(r, dict)], Path(out_dir))

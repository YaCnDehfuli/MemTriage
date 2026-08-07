"""The ranked region manifest.

``attribution_table`` in the explain pipeline answers "which patches got the most
attention" for the overlay; this builds the fuller record the deep-dive needs —
every patch-backed region, in attention order, with the provenance the grid
itself discards.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass, field

import numpy as np


@dataclass
class RegionRecord:
    patch_index: int
    row: int
    col: int
    rank: int
    attention: float
    addr: str
    addr_int: int
    end_addr: str | None
    size: int
    tag: str
    protection: str
    category: str
    file_backing: str
    private: bool
    snapshot_ordinal: int | None
    sha256: str
    entropy: float
    executable: bool
    writable: bool
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def shannon_entropy(data: np.ndarray) -> float:
    if data is None or len(data) == 0:
        return 0.0
    counts = np.bincount(np.asarray(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    return float(-np.sum(probabilities * np.log2(probabilities)))


def _digest(data: np.ndarray) -> str:
    if data is None or len(data) == 0:
        return ""
    return hashlib.sha256(np.asarray(data, dtype=np.uint8).tobytes()).hexdigest()


def region_flags(region) -> list[str]:
    """Coarse properties an analyst reads before any instruction is decoded."""
    protection = (getattr(region, "protection", "") or "").upper()
    flags: list[str] = []
    executable = "EXECUTE" in protection
    writable = "WRITE" in protection or "READWRITE" in protection
    if executable and writable:
        flags.append("rwx")
    if executable and getattr(region, "private", False):
        flags.append("private-executable")
    if not getattr(region, "file_backing", ""):
        flags.append("no-file-backing")
    data = getattr(region, "data", None)
    if data is not None and len(data) >= 2 and int(data[0]) == 0x4D and int(data[1]) == 0x5A:
        flags.append("mz-header")
    if data is not None and len(data) and shannon_entropy(data[: 64 * 1024]) > 7.2:
        flags.append("high-entropy")
    if str(getattr(region, "tag", "")) == "VadS":
        flags.append("vad-short")
    return flags


def build_manifest(ordered_regions: list, attention: list[float] | None,
                   grid_size: int) -> list[RegionRecord]:
    """One record per patch-backed region, ranked by attention (highest first).

    ``ordered_regions`` is the grid's own ordering, so index i is patch i. When
    no attention vector is available every region still gets a record — the rank
    then follows the grid order.
    """
    total_patches = grid_size * grid_size
    count = min(len(ordered_regions), total_patches)
    scores = _normalized(attention, total_patches)

    records: list[RegionRecord] = []
    for index in range(count):
        region = ordered_regions[index]
        row, col = divmod(index, grid_size)
        data = getattr(region, "data", None)
        protection = (getattr(region, "protection", "") or "")
        addr = int(getattr(region, "addr", 0) or 0)
        end = getattr(region, "end_addr", None)
        records.append(RegionRecord(
            patch_index=index,
            row=row,
            col=col,
            rank=0,
            attention=round(float(scores[index]), 6),
            addr=hex(addr),
            addr_int=addr,
            end_addr=hex(int(end)) if isinstance(end, int) else None,
            size=int(len(data)) if data is not None else 0,
            tag=str(getattr(region, "tag", "")),
            protection=protection,
            category=str(getattr(region, "category", "")),
            file_backing=str(getattr(region, "file_backing", "")),
            private=bool(getattr(region, "private", not getattr(region, "file_backing", ""))),
            snapshot_ordinal=getattr(region, "snapshot_ordinal", None),
            sha256=_digest(data),
            entropy=round(shannon_entropy(data) if data is not None else 0.0, 4),
            executable="EXECUTE" in protection.upper(),
            writable="WRITE" in protection.upper(),
            flags=region_flags(region),
        ))

    records.sort(key=lambda r: (-r.attention, r.patch_index))
    for rank, record in enumerate(records, start=1):
        record.rank = rank
    return records


def _normalized(attention: list[float] | None, total_patches: int) -> list[float]:
    """Min-max the attention vector to 0-1, padded/truncated to the grid."""
    if not attention:
        return [0.0] * total_patches
    values = [float(v) for v in attention[:total_patches]]
    values += [0.0] * (total_patches - len(values))
    if not any(math.isfinite(v) for v in values):
        return [0.0] * total_patches
    finite = [v for v in values if math.isfinite(v)]
    low, high = min(finite), max(finite)
    span = high - low
    if span <= 0:
        return [0.0] * total_patches
    return [((v - low) / span) if math.isfinite(v) else 0.0 for v in values]

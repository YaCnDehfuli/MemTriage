"""Byte-level structure: entropy profile, histogram, PE headers, hexdump.

None of this needs a disassembler, so it is what remains when capstone is absent
or the region simply is not code. The entropy profile is the fastest way to see
a packed or encrypted span inside an otherwise ordinary region, and the PE reader
answers whether a private, executable region is carrying a mapped image.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field

from ..security.sanitize import sanitize_text
from .budget import Budget

_MACHINE = {0x014C: "i386", 0x8664: "x86-64", 0x01C0: "arm", 0xAA64: "arm64"}
_SUBSYSTEM = {1: "native", 2: "gui", 3: "console", 9: "wince", 16: "boot-application"}
_DLL_CHARACTERISTICS = {
    0x0040: "dynamic-base", 0x0080: "force-integrity", 0x0100: "nx-compatible",
    0x0200: "no-isolation", 0x0400: "no-seh", 0x0800: "no-bind",
    0x1000: "app-container", 0x2000: "wdm-driver", 0x8000: "terminal-server-aware",
}


@dataclass
class EntropyProfile:
    overall: float
    window_bytes: int
    windows: list[float] = field(default_factory=list)
    peak: float = 0.0
    peak_offset: int = 0
    high_entropy_ratio: float = 0.0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["peak_offset_hex"] = hex(self.peak_offset)
        return data


@dataclass
class PEHeader:
    present: bool
    reason: str = ""
    machine: str = ""
    is_dll: bool = False
    entry_point: str = ""
    image_base: str = ""
    timestamp: int = 0
    subsystem: str = ""
    characteristics: list[str] = field(default_factory=list)
    sections: list[dict] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    parser: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def entropy_of(data) -> float:
    if data is None or len(data) == 0:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


def entropy_profile(data: bytes, budget: Budget | None = None) -> EntropyProfile:
    """Windowed entropy across the region, at a fixed number of windows."""
    budget = budget or Budget()
    if not data:
        return EntropyProfile(overall=0.0, window_bytes=0)
    windows = max(1, min(budget.entropy_windows, len(data)))
    window_bytes = max(1, len(data) // windows)
    values: list[float] = []
    for index in range(windows):
        chunk = data[index * window_bytes:(index + 1) * window_bytes]
        if not chunk:
            break
        values.append(round(entropy_of(chunk), 4))
    peak = max(values, default=0.0)
    return EntropyProfile(
        overall=round(entropy_of(data[: 1 << 20]), 4),
        window_bytes=window_bytes,
        windows=values,
        peak=peak,
        peak_offset=values.index(peak) * window_bytes if values else 0,
        high_entropy_ratio=round(
            sum(1 for v in values if v > 7.2) / len(values), 4) if values else 0.0,
    )


def byte_histogram(data: bytes, buckets: int = 32) -> list[int]:
    """Byte-value distribution, bucketed so it can be drawn as a bar chart."""
    if not data:
        return [0] * buckets
    width = max(1, 256 // buckets)
    counts = [0] * buckets
    for byte in data:
        counts[min(byte // width, buckets - 1)] += 1
    return counts


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return round(printable / len(data), 4)


def hexdump(data: bytes, offset: int = 0, length: int | None = None,
            base_addr: int = 0, width: int = 16) -> list[dict]:
    """Classic offset / bytes / ASCII rows, as data rather than pre-rendered text."""
    if not data:
        return []
    end = len(data) if length is None else min(len(data), offset + length)
    rows: list[dict] = []
    for start in range(max(offset, 0), end, width):
        chunk = data[start:start + width]
        rows.append({
            "offset": start,
            "address": hex(base_addr + start),
            "bytes": chunk.hex(),
            "ascii": "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk),
        })
    return rows


def parse_pe(data: bytes) -> PEHeader:
    """PE headers via pefile when available, else a minimal built-in reader."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return PEHeader(present=False, reason="No MZ signature at the start of the region.")
    try:
        import pefile
    except Exception:
        return _parse_pe_minimal(data)
    try:
        pe = pefile.PE(data=bytes(data), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception as exc:
        fallback = _parse_pe_minimal(data)
        if not fallback.present:
            fallback.reason = f"PE headers present but unparsable ({type(exc).__name__})."
        return fallback

    characteristics = [
        name for bit, name in _DLL_CHARACTERISTICS.items()
        if pe.OPTIONAL_HEADER.DllCharacteristics & bit
    ]
    sections = [{
        "name": sanitize_text(s.Name.decode("ascii", "ignore").rstrip("\x00"), max_len=16),
        "virtual_address": hex(s.VirtualAddress),
        "virtual_size": int(s.Misc_VirtualSize),
        "raw_size": int(s.SizeOfRawData),
        "entropy": round(entropy_of(s.get_data()[: 1 << 18]), 4),
        "characteristics": hex(int(s.Characteristics)),
    } for s in pe.sections[:32]]
    imports = [
        sanitize_text(entry.dll.decode("ascii", "ignore"), max_len=64)
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:64] if entry.dll
    ]
    header = PEHeader(
        present=True,
        machine=_MACHINE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)),
        is_dll=bool(pe.FILE_HEADER.Characteristics & 0x2000),
        entry_point=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        image_base=hex(pe.OPTIONAL_HEADER.ImageBase),
        timestamp=int(pe.FILE_HEADER.TimeDateStamp),
        subsystem=_SUBSYSTEM.get(pe.OPTIONAL_HEADER.Subsystem,
                                 str(pe.OPTIONAL_HEADER.Subsystem)),
        characteristics=characteristics,
        sections=sections,
        imported_dlls=imports,
        parser="pefile",
    )
    pe.close()
    return header


def _parse_pe_minimal(data: bytes) -> PEHeader:
    """Enough of the header to answer 'is a PE mapped here, and what is it'."""
    try:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset <= 0 or pe_offset + 0x18 > len(data):
            return PEHeader(present=False, reason="MZ signature but no reachable PE header.")
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return PEHeader(present=False, reason="MZ signature without a PE header.")
        machine = int.from_bytes(data[pe_offset + 4:pe_offset + 6], "little")
        section_count = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
        timestamp = int.from_bytes(data[pe_offset + 8:pe_offset + 12], "little")
        characteristics = int.from_bytes(data[pe_offset + 22:pe_offset + 24], "little")
        optional_size = int.from_bytes(data[pe_offset + 20:pe_offset + 22], "little")
        optional = pe_offset + 24
        magic = int.from_bytes(data[optional:optional + 2], "little")
        entry = int.from_bytes(data[optional + 16:optional + 20], "little")
        if magic == 0x20B:
            image_base = int.from_bytes(data[optional + 24:optional + 32], "little")
        else:
            image_base = int.from_bytes(data[optional + 28:optional + 32], "little")

        sections = []
        table = optional + optional_size
        for index in range(min(section_count, 32)):
            start = table + index * 40
            if start + 40 > len(data):
                break
            name = data[start:start + 8].decode("ascii", "ignore").rstrip("\x00")
            sections.append({
                "name": sanitize_text(name, max_len=16),
                "virtual_address": hex(int.from_bytes(data[start + 12:start + 16], "little")),
                "virtual_size": int.from_bytes(data[start + 8:start + 12], "little"),
                "raw_size": int.from_bytes(data[start + 16:start + 20], "little"),
                "entropy": 0.0,
                "characteristics": hex(int.from_bytes(data[start + 36:start + 40], "little")),
            })
        return PEHeader(
            present=True,
            machine=_MACHINE.get(machine, hex(machine)),
            is_dll=bool(characteristics & 0x2000),
            entry_point=hex(entry),
            image_base=hex(image_base),
            timestamp=timestamp,
            characteristics=[],
            sections=sections,
            parser="builtin",
            reason="pefile is not installed; showing the built-in header read.",
        )
    except (IndexError, ValueError) as exc:
        return PEHeader(present=False, reason=f"PE header unreadable ({type(exc).__name__}).")

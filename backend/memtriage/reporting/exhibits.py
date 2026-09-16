"""Region-level evidence exhibits.

The deep-dive already analyses the highest-attention VAD regions down to the
instruction level and writes the result to ``processes/<pid>/lowlevel.json``.
This turns one of those analyses into a citable exhibit: what the region is,
what makes it anomalous, and the specific measurements behind that — entropy,
PE structure, pattern hits, and a short disassembly extract.

An exhibit is bounded on purpose. A report that inlines 300 instructions is not
more evidential than one that inlines 12 and says where the rest is.
"""
from __future__ import annotations

MAX_PATTERNS = 6
MAX_OFFSETS = 6

# Ranking weights for the model-independent ordering below.
_SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3}
_FLAG_WEIGHT = {
    "rwx": 30,                 # writable and executable at once
    "private-executable": 20,  # executable with nothing backing it on disk
    "no-file-backing": 10,
}
MAX_INSTRUCTIONS = 14
MAX_STRINGS = 6
MAX_IMPORTS = 10


def _entropy_reading(structure: dict) -> dict:
    entropy = structure.get("entropy") or {}
    return {
        "overall": entropy.get("overall"),
        "peak": entropy.get("peak"),
        "peak_offset": entropy.get("peak_offset_hex") or "",
        "high_ratio": entropy.get("high_entropy_ratio"),
        "printable_ratio": structure.get("printable_ratio"),
        "analyzed_bytes": structure.get("analyzed_bytes"),
        "truncated": bool(structure.get("truncated")),
    }


def _pe_reading(structure: dict) -> dict | None:
    pe = structure.get("pe") or {}
    if not pe.get("present"):
        return None
    return {
        "machine": pe.get("machine") or "",
        "is_dll": bool(pe.get("is_dll")),
        "entry_point": pe.get("entry_point") or "",
        "image_base": pe.get("image_base") or "",
        "subsystem": pe.get("subsystem") or "",
        "characteristics": list(pe.get("characteristics") or []),
        "sections": [
            {
                "name": s.get("name") or "",
                "size": s.get("virtual_size") or s.get("raw_size") or s.get("size"),
                "entropy": s.get("entropy"),
                "characteristics": s.get("characteristics") or "",
            }
            for s in (pe.get("sections") or [])
        ],
        "imported_dlls": list(pe.get("imported_dlls") or [])[:MAX_IMPORTS],
        "import_overflow": max(0, len(pe.get("imported_dlls") or []) - MAX_IMPORTS),
    }


def _disassembly(block: dict) -> dict:
    if not block.get("available"):
        return {"available": False, "reason": block.get("reason") or "", "instructions": []}
    instructions = block.get("instructions") or []
    return {
        "available": True,
        "reason": "",
        "arch": block.get("arch") or "",
        "coverage": block.get("coverage"),
        "truncated": bool(block.get("truncated")),
        "instructions": [
            {
                "address": i.get("address_hex") or "",
                "bytes": i.get("bytes_hex") or "",
                "text": i.get("text") or f"{i.get('mnemonic', '')} {i.get('op_str', '')}".strip(),
            }
            for i in instructions[:MAX_INSTRUCTIONS]
        ],
        "shown": min(len(instructions), MAX_INSTRUCTIONS),
        "total": block.get("instruction_count") or len(instructions),
    }


def build(analysis: dict, *, pid: int, process_name: str) -> dict:
    """One exhibit from one entry of lowlevel.json's ``regions``."""
    region = analysis.get("region") or {}
    summary = analysis.get("summary") or {}
    structure = analysis.get("structure") or {}

    hits = (analysis.get("patterns") or {}).get("hits") or []
    patterns = [
        {
            "id": p.get("id") or "",
            "title": p.get("title") or "",
            "severity": p.get("severity") or "",
            "description": p.get("description") or "",
            "technique": p.get("technique") or "",
            "technique_name": p.get("technique_name") or "",
            "occurrences": p.get("occurrences"),
            # Offsets are what make a pattern checkable rather than asserted:
            # a reader can go to that byte in the region and see it.
            "offsets": list(p.get("offsets") or [])[:MAX_OFFSETS],
            "offset_overflow": max(0, len(p.get("offsets") or []) - MAX_OFFSETS),
        }
        for p in hits[:MAX_PATTERNS]
    ]
    found = (analysis.get("strings") or {}).get("interesting") or []
    strings = [
        {
            "value": s.get("value") or "",
            "category": s.get("category") or "",
            "encoding": s.get("encoding") or "",
            "offset": s.get("offset_hex") or "",
        }
        for s in found[:MAX_STRINGS]
    ]

    return {
        # Content-addressed, like the pin the analyst makes in the deep-dive:
        # re-analysing a PID overwrites its artifacts in place, so an address or
        # patch index could silently name a different region afterwards.
        "ref": f"{pid}|{region.get('sha256') or ''}",
        "pid": pid,
        "process_name": process_name,
        "addr": region.get("addr") or "",
        "size": region.get("size"),
        "protection": region.get("protection") or "",
        "category": region.get("category") or "",
        "sha256": region.get("sha256") or "",
        "attention": region.get("attention"),
        "executable": bool(region.get("executable")),
        "writable": bool(region.get("writable")),
        "file_backing": region.get("file_backing") or "",
        "headline": summary.get("headline") or "",
        "caveat": summary.get("caveat") or "",
        "highest_severity": summary.get("highest_severity") or "",
        "techniques": list(summary.get("techniques") or []),
        "instruction_count": summary.get("instruction_count"),
        "block_count": summary.get("block_count"),
        "function_count": summary.get("function_count"),
        "indirect_calls": summary.get("indirect_calls"),
        "region_entropy": region.get("entropy"),
        "flags": list(region.get("flags") or []),
        "entropy": _entropy_reading(structure),
        "pe": _pe_reading(structure),
        "patterns": patterns,
        "pattern_overflow": max(0, len(hits) - MAX_PATTERNS),
        "pattern_severity": (analysis.get("patterns") or {}).get("highest_severity") or "",
        "strings": strings,
        "string_overflow": max(0, len(found) - MAX_STRINGS),
        "disassembly": _disassembly(analysis.get("disassembly") or {}),
    }


def forensic_rank(exhibit: dict) -> float:
    """Order exhibits by measured properties rather than model attention.

    The classifier's attention decides which regions get analysed, and that
    ranking is only as meaningful as the checkpoint behind it. With the
    untrained placeholder weights it carries no signal at all, so a report that
    leads with "the region the model looked at" would be leading with noise.

    This orders by things that are true of the bytes regardless of any model:
    the severity of the pattern hits, protection flags that are anomalous on
    their own (RWX, executable with no file backing), and how much code is
    actually there. Used whenever the verdict came from a placeholder.
    """
    score = 0.0
    for p in exhibit.get("patterns") or []:
        score += _SEVERITY_WEIGHT.get(str(p.get("severity") or "").lower(), 0)
    for flag in exhibit.get("flags") or []:
        score += _FLAG_WEIGHT.get(str(flag).lower(), 0)
    if exhibit.get("instruction_count"):
        # Code density matters, but must not let a large benign region outrank a
        # small, unambiguously anomalous one.
        score += min(float(exhibit["instruction_count"]) / 50.0, 10.0)
    if (exhibit.get("strings") or []) and any(
        s.get("category") == "url" for s in exhibit["strings"]
    ):
        score += 15
    return score

"""Assemble one region's deep-dive.

Each analyzer is called behind its own guard, so a failure in the disassembler
costs the instruction listing and nothing else: the structure, strings and
pattern panels still render. The result is a plain dict, written to disk next to
the analysis and served to the UI as-is.
"""
from __future__ import annotations

import logging

from ..security.sanitize import sanitize_obj
from .budget import Budget
from .callgraph import build_callgraph
from .cfg import build_cfg
from .disasm import disassemble
from .patterns import scan
from .strings_extract import extract_strings
from .structure import byte_histogram, entropy_profile, hexdump, parse_pe, printable_ratio

logger = logging.getLogger(__name__)


def _guard(name: str, fn, fallback):
    try:
        return fn()
    except Exception as exc:
        logger.warning("region analysis: %s failed (%s)", name, type(exc).__name__)
        return fallback(exc)


def analyze_region(data: bytes, meta: dict, *, budget: Budget | None = None,
                   base_addr: int | None = None) -> dict:
    """Every representation MemTriage can derive from one region's bytes."""
    budget = budget or Budget()
    data = bytes(data or b"")
    window = data[: budget.max_bytes]
    base = base_addr if base_addr is not None else int(meta.get("addr_int", 0) or 0)

    listing = _guard(
        "disassembly",
        lambda: disassemble(window, base, budget=budget),
        lambda exc: _unavailable_listing(exc),
    )
    control_flow = _guard(
        "control flow",
        lambda: build_cfg(listing, budget).to_dict(),
        lambda exc: {"available": False,
                     "reason": f"Control-flow reconstruction failed ({type(exc).__name__})."},
    )
    calls = _guard(
        "call graph",
        lambda: build_callgraph(listing, window, budget).to_dict(),
        lambda exc: {"available": False,
                     "reason": f"Call-graph reconstruction failed ({type(exc).__name__})."},
    )
    strings = _guard(
        "strings",
        lambda: extract_strings(data, budget).to_dict(),
        lambda exc: {"total_found": 0, "strings": [], "interesting": [], "by_category": {},
                     "error": type(exc).__name__},
    )
    patterns = _guard(
        "patterns",
        lambda: scan(data, listing, meta).to_dict(),
        lambda exc: {"hits": [], "hit_count": 0, "highest_severity": "none",
                     "note": f"Pattern scan failed ({type(exc).__name__})."},
    )
    structure = _guard(
        "structure",
        lambda: {
            "size": len(data),
            "analyzed_bytes": len(window),
            "truncated": len(data) > len(window),
            "entropy": entropy_profile(data, budget).to_dict(),
            "histogram": byte_histogram(window),
            "printable_ratio": printable_ratio(window),
            "pe": parse_pe(data).to_dict(),
            "hexdump": hexdump(data, 0, budget.max_hexdump_bytes, base),
        },
        lambda exc: {"size": len(data), "error": type(exc).__name__},
    )

    report = {
        "region": meta,
        "structure": structure,
        "disassembly": listing.to_dict() if hasattr(listing, "to_dict") else listing,
        "control_flow": control_flow,
        "call_graph": calls,
        "strings": strings,
        "patterns": patterns,
        "summary": _summarize(meta, listing, control_flow, calls, patterns, structure),
    }
    return sanitize_obj(report, max_len=4096)


def _unavailable_listing(exc: Exception):
    from .disasm import Listing

    return Listing.unavailable(f"Disassembly failed ({type(exc).__name__}).")


def _summarize(meta: dict, listing, control_flow: dict, calls: dict,
               patterns: dict, structure: dict) -> dict:
    hits = patterns.get("hits", [])
    top = hits[0] if hits else None
    entropy = structure.get("entropy", {}) or {}
    return {
        "headline": _headline(meta, top),
        "highest_severity": patterns.get("highest_severity", "none"),
        "pattern_count": len(hits),
        "techniques": sorted({h["technique"] for h in hits if h.get("technique")}),
        "instruction_count": getattr(listing, "instructions", None) and len(listing.instructions)
        or 0,
        "block_count": control_flow.get("block_count", 0),
        "function_count": calls.get("node_count", 0),
        "indirect_calls": calls.get("indirect_calls", 0),
        "entropy": entropy.get("overall", 0.0),
        "pe_present": bool((structure.get("pe") or {}).get("present")),
        "caveat": ("Indicators, not conclusions. Every item below is a property of "
                   "the bytes in this region; deciding what it means is the "
                   "analyst's call."),
    }


def _headline(meta: dict, top: dict | None) -> str:
    where = meta.get("addr", "?")
    size = meta.get("size", 0)
    protection = meta.get("protection", "unknown protection")
    base = f"{where} · {size} bytes · {protection}"
    if top:
        return f"{base} — highest-severity indicator: {top['title']}"
    return f"{base} — no known pattern matched"

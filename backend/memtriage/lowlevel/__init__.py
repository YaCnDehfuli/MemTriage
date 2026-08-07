"""Low-level analysis of the VAD regions VADViT's attention singles out.

The model tells us *where* to look; this package answers *what is there*. For a
ranked region it recovers an instruction listing, basic blocks and a control-flow
graph, a call graph with resolved API names, byte-level structure (entropy,
histogram, PE headers, hexdump), extracted strings, and a catalogue of known
in-memory code patterns.

Every analyzer is independently guarded: capstone may be absent, the bytes may
not be code at all, and a region may be hundreds of megabytes. Each one returns
an explicit "unavailable" record rather than raising, and each is bounded by an
explicit budget.
"""
from .budget import Budget
from .manifest import RegionRecord, build_manifest

__all__ = ["Budget", "RegionRecord", "build_manifest"]

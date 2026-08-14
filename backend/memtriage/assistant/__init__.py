"""Phase 3: turn an investigation into a briefing an LLM can answer questions against.

The pack is built once, cached, and reused as the stable prefix of every request
in a conversation. Nothing here measures anything new — it is a faithful,
size-bounded restatement of what phases 1 and 2 already produced, including their
caveats, so the model inherits the same limits the analyst has.
"""
from .context_pack import ContextPack, build_pack, cached_pack

__all__ = ["ContextPack", "build_pack", "cached_pack"]

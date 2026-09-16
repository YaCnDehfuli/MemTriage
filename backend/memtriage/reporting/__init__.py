"""Report assembly and rendering.

Phase 0 of the report feature: a complete investigation document built only from
what triage and the deep-dive already produced. No analyst input, no curation and
no persistence are involved here — those layer on top in later phases without
changing this package's contract.
"""
from .assembly import ReportDocument, assemble

__all__ = ["ReportDocument", "assemble"]

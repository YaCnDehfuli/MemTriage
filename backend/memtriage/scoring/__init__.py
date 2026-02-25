"""MemTriage explainable scoring engine.

A tunable, correlation-aware detection engine that re-scores cached triage
artifacts in milliseconds. The public surface is intentionally small:

* :func:`score_records` — parsed plugin records + a profile → explained verdicts;
* :func:`diff_scored` — what changed between two scorings (live-tuning feedback);
* :class:`TuningProfile` — the analyst-facing configuration (presets + per-rule);
* :data:`CONTEXT_PLUGINS` — the plugin set triage caches for re-scoring.
"""
from .profile import TuningProfile
from .service import (
    CONTEXT_PLUGINS,
    diff_scored,
    normalize_plugin_key,
    score_records,
)

__all__ = [
    "score_records",
    "diff_scored",
    "normalize_plugin_key",
    "TuningProfile",
    "CONTEXT_PLUGINS",
]

"""MemTriage's view of the scoring engine.

The engine itself lives in :mod:`volmemlyzer.scoring`, next to the extraction
that produces the records it reads. It used to be duplicated here, which is how
MemTriage ended up running two scorers over one image and shipping the output of
the one with no per-rule ATT&CK attribution.

MemTriage keeps the analyst-facing surface — presets, the tuning UI, when a
cached triage may be reused — and none of the detection logic.
"""
from volmemlyzer.scoring import (
    CONTEXT_PLUGINS,
    MAX_RISK_SCORE,
    TuningProfile,
    diff_scored,
    normalize_plugin_key,
    score_records,
)

__all__ = [
    "CONTEXT_PLUGINS",
    "MAX_RISK_SCORE",
    "TuningProfile",
    "diff_scored",
    "normalize_plugin_key",
    "score_records",
]

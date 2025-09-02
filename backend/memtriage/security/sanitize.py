"""Sanitize dump-derived artifact metadata before storage/render.

Process names, command lines, module paths, registry values, network endpoints
and raw strings all come straight out of an attacker-controlled memory image.
The React frontend escapes by default, but we defend in depth on the server:
strip control characters, neutralize null bytes, collapse whitespace for table
cells, and cap length to prevent both stored-XSS and UI/DoS via oversized fields.
"""
from __future__ import annotations

import re
from typing import Any

# C0/C1 control characters excluding common whitespace we normalize separately.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_WS_RE = re.compile(r"\s+")

DEFAULT_MAX_LEN = 2048
TRUNCATION_MARK = "…[truncated]"


def sanitize_text(
    value: Any,
    *,
    max_len: int = DEFAULT_MAX_LEN,
    collapse_ws: bool = True,
) -> str:
    """Return a render-safe string for a single artifact field.

    - coerces to ``str``
    - removes control characters (incl. NUL) that could smuggle payloads or
      break terminals/log sinks
    - optionally collapses runs of whitespace (good for one-line table cells)
    - caps length with an explicit truncation marker
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL_RE.sub("", text)
    if collapse_ws:
        text = _WS_RE.sub(" ", text).strip()
    if len(text) > max_len:
        text = text[: max_len - len(TRUNCATION_MARK)] + TRUNCATION_MARK
    return text


def sanitize_obj(obj: Any, *, max_len: int = DEFAULT_MAX_LEN, _depth: int = 0) -> Any:
    """Recursively sanitize a JSON-like structure of extracted artifacts.

    Strings are cleaned; numbers/bools/None pass through; dict keys are also
    sanitized (short cap) since some plugins surface attacker-influenced keys.
    Recursion depth is bounded to avoid pathological nesting.
    """
    if _depth > 32:
        return "…[max depth]"
    if isinstance(obj, str):
        return sanitize_text(obj, max_len=max_len)
    if isinstance(obj, bool) or obj is None or isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, dict):
        return {
            sanitize_text(str(k), max_len=128): sanitize_obj(
                v, max_len=max_len, _depth=_depth + 1
            )
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [sanitize_obj(v, max_len=max_len, _depth=_depth + 1) for v in obj]
    # Unknown/opaque type: stringify and clean.
    return sanitize_text(obj, max_len=max_len)

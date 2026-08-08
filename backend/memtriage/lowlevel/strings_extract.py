"""String extraction and classification.

ASCII and UTF-16LE runs, bucketed into the categories an analyst triages by —
URLs, hosts, addresses, filesystem and registry paths, API names, commands,
base64-looking blobs. Everything is sanitized before it leaves this module: the
bytes come from an untrusted memory image and end up in a browser and an export.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from ..security.sanitize import sanitize_text
from .budget import Budget

_ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("url", re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)),
    ("ipv4", re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d{1,5})?$")),
    ("unc-path", re.compile(r"^\\\\[^\\]+\\")),
    ("windows-path", re.compile(r"^[a-z]:\\", re.I)),
    ("registry", re.compile(r"^(HKEY_|HKLM|HKCU|\\REGISTRY\\)", re.I)),
    ("dll", re.compile(r"^[\w.-]+\.(dll|sys|exe)$", re.I)),
    ("command", re.compile(r"(cmd\.exe|powershell|rundll32|regsvr32|wscript|mshta)", re.I)),
    ("domain", re.compile(r"^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}$", re.I)),
    ("base64", re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")),
    ("guid", re.compile(r"^\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}\}?$", re.I)),
)

INTERESTING = {"url", "ipv4", "unc-path", "registry", "command", "domain", "base64"}


@dataclass
class ExtractedString:
    offset: int
    encoding: str  # ascii | utf-16le
    category: str
    value: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["offset_hex"] = hex(self.offset)
        return data


@dataclass
class StringReport:
    total_found: int = 0
    truncated: bool = False
    strings: list[ExtractedString] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_found": self.total_found,
            "truncated": self.truncated,
            "by_category": self.by_category,
            "interesting": [s.to_dict() for s in self.strings if s.category in INTERESTING],
            "strings": [s.to_dict() for s in self.strings],
        }


def classify(value: str) -> str:
    for name, pattern in _PATTERNS:
        if pattern.search(value):
            return name
    return "text"


def extract_strings(data: bytes, budget: Budget | None = None) -> StringReport:
    """Pull printable runs out of a region. Never raises."""
    budget = budget or Budget()
    report = StringReport()
    if not data:
        return report
    try:
        found: list[ExtractedString] = []
        for match in _ASCII_RE.finditer(data):
            found.append(_make(match.start(), match.group().decode("ascii", "ignore"), "ascii"))
        for match in _UTF16_RE.finditer(data):
            text = match.group().decode("utf-16-le", "ignore")
            found.append(_make(match.start(), text, "utf-16le"))
    except Exception:
        return report

    report.total_found = len(found)
    # Interesting first, then longest: a 400-string cap should not be spent on
    # padding when there is a C2 URL further down the region.
    found.sort(key=lambda s: (s.category not in INTERESTING, -len(s.value), s.offset))
    report.truncated = len(found) > budget.max_strings
    report.strings = found[: budget.max_strings]
    counts: dict[str, int] = {}
    for item in found:
        counts[item.category] = counts.get(item.category, 0) + 1
    report.by_category = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
    return report


def _make(offset: int, raw: str, encoding: str) -> ExtractedString:
    value = sanitize_text(raw, max_len=512)
    return ExtractedString(offset=offset, encoding=encoding,
                           category=classify(value), value=value)

"""Low-level detection primitives, self-contained and unit-testable.

These are the hardened replacements for the VolMemLyzer scorers that this engine
ports. In particular they fix the two byte-pattern bugs called out in the port
plan:

* the original hexdump check built regex-shaped byte literals (``b"\\xe8[\\x00-
  \\xff]{4}"``) and matched them with ``in`` — so those "patterns" only matched
  when the file literally contained the bytes ``[`` ``\\`` ``x`` … and never fired
  on real shellcode. Here the raw region bytes are recovered and matched with
  ``re.search(..., re.DOTALL)`` against genuine shellcode byte signatures.
* the original disassembly check matched ``push ebp`` / ``call|jmp .*`` — patterns
  present in essentially all code — producing constant false positives. That
  heuristic is dropped entirely in favour of the byte-signature scan below.

The helpers are pure Python (no NumPy/Volatility) so the whole scoring package
imports cleanly in the API process and the test environment.
"""
from __future__ import annotations

import math
import re
from collections import Counter

# --- path classification -------------------------------------------------

_SYSTEM_ROOTS = (
    r"\windows",
    r"\program files",
    r"\program files (x86)",
    r"\programdata\microsoft",
)
_SUSPICIOUS_TOKENS = (
    r"\temp\\",
    r"\tmp\\",
    r"\downloads\\",
    r"\appdata\\",
    r"\desktop\\",
    r"\users\public\\",
    r"\$recycle.bin\\",
    r"\perflogs\\",
)


def _norm(path: str) -> str:
    return (path or "").replace("/", "\\").strip().strip('"').lower()


def not_system_path(path: str) -> bool:
    """True if ``path`` is a real path that does not live under a system root."""
    p = _norm(path)
    if not p:
        return False
    # Only judge things that look like absolute Windows paths.
    if not re.match(r"^[a-z]:\\", p) and not p.startswith("\\"):
        return False
    return not any(root in p for root in _SYSTEM_ROOTS)


def is_suspicious_path(path: str) -> bool:
    """User-writable / staging locations attackers favour."""
    p = _norm(path)
    if not not_system_path(p):
        return False
    return any(tok.replace("\\\\", "\\") in p for tok in _SUSPICIOUS_TOKENS)


def char_entropy(s: str) -> float:
    if not s:
        return 0.0
    cnt, n = Counter(s), len(s)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def is_non_ascii(s: str) -> bool:
    return any(ord(ch) > 127 for ch in (s or ""))


# --- memory-region byte analysis ----------------------------------------

_ADDR_RE = re.compile(r"^(?:0x[0-9a-fA-F]+|[0-9a-fA-F]{6,})$")
_BYTE_RE = re.compile(r"^[0-9a-fA-F]{2}$")


def hexdump_to_bytes(hexdump: str, max_bytes: int = 4096) -> bytes:
    """Recover the raw bytes from a malfind ``Hexdump`` field.

    Handles both the multi-line Volatility layout ``<addr>  <16 hex bytes>  <ascii>``
    and a plain whitespace-separated hex string. The trailing ASCII gutter is
    ignored by only taking the leading run of two-hex-digit tokens on each line.
    """
    out = bytearray()
    for line in (hexdump or "").splitlines() or [hexdump or ""]:
        toks = line.split()
        if not toks:
            continue
        cap: int | None = None
        if _ADDR_RE.match(toks[0]):
            toks = toks[1:]
            cap = 16  # Volatility renders 16 bytes/line before the ASCII gutter
        n = 0
        for t in toks:
            if _BYTE_RE.match(t) and (cap is None or n < cap):
                out.append(int(t, 16))
                n += 1
            else:
                break
        if len(out) >= max_bytes:
            break
    return bytes(out[:max_bytes])


def has_pe_header(data: bytes) -> bool:
    """Reflective/injected PE: an ``MZ`` DOS header at the start of a region."""
    return len(data) >= 2 and data[0] == 0x4D and data[1] == 0x5A


# Genuine shellcode byte signatures, matched against recovered region bytes.
_SHELLCODE_SIGNATURES: tuple[tuple[str, bytes], ...] = (
    ("NOP sled", rb"\x90{8,}"),
    ("Metasploit block prologue (cld; call)", rb"\xfc\xe8.{2}\x00\x00"),
    ("call $+5 GetPC / pop", rb"\xe8\x00\x00\x00\x00[\x58-\x5f]"),
    ("fnstenv GetPC", rb"\xd9[\xf0-\xff]?\xd9\x74\x24\xf4"),
    ("PEB access via fs:[0x30] (x86)", rb"\x64\xa1\x30\x00\x00\x00"),
    ("PEB access via gs (x64)", rb"\x65\x48\x8b"),
    ("SEH walk fs:[0]", rb"\x64\x8b[\x0d\x1d\x25\x35]\x00\x00\x00\x00"),
)


def shellcode_signals(data: bytes) -> list[str]:
    """Return the names of shellcode signatures present in ``data`` (may be empty)."""
    found: list[str] = []
    for name, pattern in _SHELLCODE_SIGNATURES:
        if re.search(pattern, data, re.DOTALL):
            found.append(name)
    return found


def protection_is_rwx(protection: str) -> bool:
    """PAGE_EXECUTE_READWRITE (or any EXECUTE+WRITE) — the classic injection mark."""
    p = (protection or "").upper()
    return "EXECUTE" in p and ("WRITECOPY" in p or "READWRITE" in p or "WRITE" in p)

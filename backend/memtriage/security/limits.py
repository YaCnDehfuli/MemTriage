"""Upload validation and DoS controls.

Memory images are frequently raw captures with no reliable magic bytes, so we
validate by an extension allowlist plus a *denylist* of container/executable
magics we never want to ingest (archives that could auto-extract, or PE/ELF
executables masquerading as a dump). Size is capped by streaming enforcement in
the upload route; this module owns the type checks.
"""
from __future__ import annotations

from pathlib import PurePosixPath

from ..config import get_settings

settings = get_settings()


class UploadRejected(ValueError):
    """Raised when an upload fails a validation check (mapped to HTTP 4xx)."""


# Leading bytes we refuse outright. Keyed by a human-readable label.
_DENY_MAGICS: dict[str, bytes] = {
    "zip/office/jar": b"PK\x03\x04",
    "gzip": b"\x1f\x8b",
    "bzip2": b"BZh",
    "xz": b"\xfd7zXZ\x00",
    "rar": b"Rar!\x1a\x07",
    "7zip": b"7z\xbc\xaf\x27\x1c",
    "pdf": b"%PDF-",
    "windows-pe": b"MZ",
    "java-class": b"\xca\xfe\xba\xbe",
}

# Minimum bytes we need to make a sniffing decision.
SNIFF_BYTES = 16


def validate_extension(filename: str) -> str:
    """Return the lowercased extension if allowed, else raise UploadRejected."""
    name = PurePosixPath(filename).name
    ext = PurePosixPath(name).suffix.lower()
    if not ext:
        raise UploadRejected(
            "Upload has no file extension; expected a memory image such as "
            f"{', '.join(settings.allowed_extensions)}."
        )
    if ext not in settings.allowed_extensions:
        raise UploadRejected(
            f"Extension '{ext}' is not an accepted memory-image type. Allowed: "
            f"{', '.join(settings.allowed_extensions)}."
        )
    return ext


def sniff_reject(head: bytes) -> None:
    """Reject known container/executable magics. No-op for raw memory dumps."""
    for label, magic in _DENY_MAGICS.items():
        if head.startswith(magic):
            raise UploadRejected(
                f"Upload looks like a {label} file, not a raw memory image. "
                "Archives and executables are refused as a safety measure."
            )

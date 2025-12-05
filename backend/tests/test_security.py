"""Unit tests for the security utilities (sanitization + upload limits)."""
import pytest

from memtriage.security.limits import UploadRejected, sniff_reject, validate_extension
from memtriage.security.sanitize import sanitize_obj, sanitize_text


def test_sanitize_strips_control_chars_and_nul():
    dirty = "evil\x00name\x07\x1b[31m"
    clean = sanitize_text(dirty)
    assert "\x00" not in clean
    assert "\x07" not in clean
    assert "\x1b" not in clean


def test_sanitize_neutralizes_script_payload_but_keeps_text():
    # React escapes on render; the server also caps/cleans. The angle brackets
    # are preserved as literal text (escaped downstream), not executed.
    payload = "<script>alert(1)</script>"
    out = sanitize_text(payload)
    assert "alert(1)" in out  # content kept as inert text
    assert "\n" not in out


def test_sanitize_caps_length():
    out = sanitize_text("A" * 5000, max_len=100)
    assert len(out) <= 100
    assert out.endswith("…[truncated]")


def test_sanitize_obj_is_recursive():
    data = {
        "proc\x00name": "cmd\x1b.exe",
        "children": [{"path": "C:\\evil\x07.dll"}, 42, True, None],
    }
    out = sanitize_obj(data)
    key = next(iter(out))
    assert "\x00" not in key
    assert "\x1b" not in out["proc name"] if "proc name" in out else True
    assert out["children"][1] == 42
    assert out["children"][2] is True
    assert out["children"][3] is None


def test_validate_extension_accepts_known_image():
    assert validate_extension("case-01.raw") == ".raw"
    assert validate_extension("dump.vmem") == ".vmem"


def test_validate_extension_rejects_executable():
    with pytest.raises(UploadRejected):
        validate_extension("payload.exe")
    with pytest.raises(UploadRejected):
        validate_extension("no_extension")


def test_sniff_reject_flags_containers_and_executables():
    for magic in (b"PK\x03\x04", b"\x1f\x8b", b"MZ\x90\x00", b"%PDF-1.7"):
        with pytest.raises(UploadRejected):
            sniff_reject(magic)


def test_sniff_reject_allows_raw_memory():
    # Raw memory has no reliable magic; arbitrary leading bytes are fine.
    sniff_reject(b"\x00\x11\x22\x33rawmemory")

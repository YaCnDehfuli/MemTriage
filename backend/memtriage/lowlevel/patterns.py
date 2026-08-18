"""Known in-memory code and data patterns.

Two families of check, deliberately kept apart:

* **byte patterns** — fixed sequences and statistical properties, so they work
  with no disassembler at all;
* **instruction patterns** — sequences over the recovered listing, which need
  capstone and are skipped cleanly without it.

Each hit carries severity, evidence offsets and an ATT&CK technique where one
applies. These are indicators, not verdicts: a GetPC gadget in a JIT region and a
GetPC gadget in a private RWX allocation look identical here, and the surrounding
region metadata is what separates them.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field

from .disasm import Listing

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class PatternHit:
    id: str
    title: str
    severity: str
    description: str
    technique: str = ""
    technique_name: str = ""
    occurrences: int = 0
    offsets: list[str] = field(default_factory=list)
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PatternReport:
    hits: list[PatternHit] = field(default_factory=list)
    instruction_scan: bool = False
    note: str = ""

    def to_dict(self) -> dict:
        return {
            "instruction_scan": self.instruction_scan,
            "note": self.note,
            "hit_count": len(self.hits),
            "highest_severity": self.hits[0].severity if self.hits else "none",
            "hits": [h.to_dict() for h in self.hits],
        }


@dataclass
class _ByteRule:
    id: str
    title: str
    severity: str
    description: str
    pattern: bytes | re.Pattern[bytes]
    technique: str = ""
    technique_name: str = ""
    min_occurrences: int = 1


BYTE_RULES: tuple[_ByteRule, ...] = (
    _ByteRule(
        "peb_walk_x86", "PEB walk (32-bit)", "high",
        "Reads the Process Environment Block via fs:[0x30] — the standard way "
        "position-independent code locates loaded modules without imports.",
        re.compile(rb"\x64\xa1\x30\x00\x00\x00|\x64\x8b\x0d\x30\x00\x00\x00"
                   rb"|\x64\x8b\x15\x30\x00\x00\x00|\x64\x8b\x35\x30\x00\x00\x00"),
        "T1106", "Native API",
    ),
    _ByteRule(
        "peb_walk_x64", "PEB walk (64-bit)", "high",
        "Reads the PEB via gs:[0x60], the 64-bit equivalent of the fs:[0x30] walk.",
        re.compile(rb"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
                   rb"|\x65\x48\x8b[\x0c\x14\x1c\x34\x3c]\x25\x60\x00\x00\x00"),
        "T1106", "Native API",
    ),
    _ByteRule(
        "getpc_call_pop", "GetPC gadget (call/pop)", "high",
        "A zero-displacement call followed by a pop recovers the instruction "
        "pointer — position-independent shellcode locating its own data.",
        re.compile(rb"\xe8\x00\x00\x00\x00[\x58-\x5f]"),
        "T1055", "Process Injection",
    ),
    _ByteRule(
        "getpc_fnstenv", "GetPC gadget (fnstenv)", "high",
        "The fnstenv FPU trick recovers the instruction pointer without a call, "
        "historically used to evade call/pop signatures.",
        re.compile(rb"\xd9[\xee\xd0]\xd9\x74\x24\xf4"),
        "T1027", "Obfuscated Files or Information",
    ),
    _ByteRule(
        "api_hash_ror13", "API hashing (ROR-13)", "high",
        "The ROR-13 export-name hash constant appears — imports are resolved by "
        "hash so no readable API name is present in the region.",
        re.compile(rb"\xc1\xcf\x0d|\xc1\xca\x0d"),
        "T1027", "Obfuscated Files or Information",
    ),
    _ByteRule(
        "heavens_gate", "Heaven's Gate transition", "critical",
        "A far call/jump through selector 0x33 switches a 32-bit process into "
        "64-bit mode, a common way to bypass user-mode hooks.",
        re.compile(rb"\x9a[\s\S]{4}\x33\x00|\xea[\s\S]{4}\x33\x00"),
        "T1055.012", "Process Hollowing",
    ),
    _ByteRule(
        "nop_sled", "NOP sled", "medium",
        "A long run of single-byte NOPs, typically padding to an exploit or "
        "shellcode landing zone.",
        re.compile(rb"\x90{16,}"),
        "T1055", "Process Injection",
    ),
    _ByteRule(
        "int3_padding", "Breakpoint padding run", "low",
        "A long run of int3 bytes. Normal between compiler-emitted functions; "
        "noted because it also marks scratch space in injected buffers.",
        re.compile(rb"\xcc{32,}"),
    ),
    _ByteRule(
        "syscall_stub", "Direct syscall stub", "high",
        "mov eax, <number> followed by syscall — the ntdll stub shape, which in "
        "private memory means the process is issuing syscalls without ntdll.",
        re.compile(rb"\xb8[\s\S]{4}\x0f\x05|\x4c\x8b\xd1\xb8[\s\S]{4}\x0f\x05"),
        "T1106", "Native API",
    ),
    _ByteRule(
        "sysenter_stub", "sysenter stub", "medium",
        "A 32-bit sysenter transition, the older direct kernel-entry shape.",
        re.compile(rb"\x0f\x34"),
        "T1106", "Native API",
        min_occurrences=2,
    ),
    _ByteRule(
        "mz_in_memory", "Embedded PE image", "medium",
        "An MZ/PE header inside the region. Expected for a mapped module; in "
        "private memory it means an image was written there by the process.",
        re.compile(rb"MZ[\s\S]{58}[\s\S]{4}PE\x00\x00"),
        "T1055.002", "Portable Executable Injection",
    ),
    _ByteRule(
        "reflective_loader", "Reflective loading strings", "high",
        "Names associated with manual PE loading appear in the region.",
        re.compile(rb"ReflectiveLoader|LoadRemoteLibraryR|_ReflectiveLoader@4"),
        "T1620", "Reflective Code Loading",
    ),
    _ByteRule(
        "egg_hunter", "Egg-hunter tag", "high",
        "A repeated 8-byte tag of the shape egg-hunter shellcode searches memory "
        "for once a small first stage has landed.",
        re.compile(rb"(w00tw00t|W00TW00T|\x54\x30\x30\x57\x54\x30\x30\x57)"),
        "T1055", "Process Injection",
    ),
    _ByteRule(
        "powershell_encoded", "Encoded PowerShell command", "high",
        "A PowerShell invocation with an encoded command payload.",
        re.compile(rb"(?i)powershell[^\x00]{0,64}(-e |-enc|-encodedcommand)"),
        "T1059.001", "PowerShell",
    ),
    _ByteRule(
        "http_c2", "Embedded HTTP endpoint", "medium",
        "A URL is present in the region — worth correlating with the network "
        "artifacts surfaced during triage.",
        re.compile(rb"https?://[\x21-\x7e]{4,}"),
        "T1071.001", "Web Protocols",
    ),
    _ByteRule(
        "runkey_persistence", "Run-key path", "medium",
        "A registry Run key path appears in the region.",
        re.compile(rb"(?i)Software\\\\?Microsoft\\\\?Windows\\\\?CurrentVersion\\\\?Run"),
        "T1547.001", "Registry Run Keys / Startup Folder",
    ),
)


def _sample_evidence(data: bytes, offset: int, span: int = 16) -> str:
    return data[offset:offset + span].hex()


def scan_bytes(data: bytes, limit_per_rule: int = 12) -> list[PatternHit]:
    hits: list[PatternHit] = []
    if not data:
        return hits
    for rule in BYTE_RULES:
        try:
            pattern = rule.pattern
            matches = list(pattern.finditer(data)) if hasattr(pattern, "finditer") else []
        except Exception:  # noqa: S112 — one malformed rule must not stop the scan
            continue
        if len(matches) < rule.min_occurrences:
            continue
        offsets = [m.start() for m in matches[:limit_per_rule]]
        hits.append(PatternHit(
            id=rule.id,
            title=rule.title,
            severity=rule.severity,
            description=rule.description,
            technique=rule.technique,
            technique_name=rule.technique_name,
            occurrences=len(matches),
            offsets=[hex(o) for o in offsets],
            evidence=_sample_evidence(data, offsets[0]) if offsets else "",
        ))
    return hits


def scan_instructions(listing: Listing) -> list[PatternHit]:
    """Sequence-level checks that need the decoded listing."""
    hits: list[PatternHit] = []
    instructions = listing.instructions
    if not instructions:
        return hits

    xor_loops: list[int] = []
    stack_strings: list[int] = []
    indirect_calls: list[int] = []
    window: list = []
    for insn in instructions:
        window.append(insn)
        if len(window) > 6:
            window.pop(0)
        if insn.kind == "cjump" and insn.target is not None and insn.target <= insn.address:
            body = [w.mnemonic for w in window]
            if any(m in {"xor", "add", "sub", "rol", "ror", "not"} for m in body) and \
                    any(m in {"mov", "movzx", "movsx", "lodsb", "stosb"} for m in body):
                xor_loops.append(insn.address)
        if insn.mnemonic == "mov" and "[" in insn.op_str and (
                "rsp" in insn.op_str or "esp" in insn.op_str or "rbp" in insn.op_str) and \
                insn.op_str.rstrip().endswith(tuple("0123456789abcdef")) and "0x" in insn.op_str:
            stack_strings.append(insn.address)
        if insn.kind == "call" and insn.target is None:
            indirect_calls.append(insn.address)

    if xor_loops:
        hits.append(PatternHit(
            id="decoder_loop", title="In-place decoder loop", severity="high",
            description=("A backward branch around arithmetic on moved bytes — the "
                         "shape of a self-decoding or string-deobfuscating stub."),
            technique="T1140", technique_name="Deobfuscate/Decode Files or Information",
            occurrences=len(xor_loops), offsets=[hex(a) for a in xor_loops[:12]],
        ))
    if len(stack_strings) >= 8:
        hits.append(PatternHit(
            id="stack_strings", title="Stack-constructed strings", severity="medium",
            description=("Many immediate stores into the stack frame — strings built "
                         "at runtime so they never appear in the region's bytes."),
            technique="T1027", technique_name="Obfuscated Files or Information",
            occurrences=len(stack_strings), offsets=[hex(a) for a in stack_strings[:12]],
        ))
    if len(indirect_calls) >= 4:
        hits.append(PatternHit(
            id="indirect_call_heavy", title="Predominantly indirect calls", severity="medium",
            description=("Most calls go through a register or memory operand, which is "
                         "what dynamically resolved imports look like."),
            technique="T1027", technique_name="Obfuscated Files or Information",
            occurrences=len(indirect_calls), offsets=[hex(a) for a in indirect_calls[:12]],
        ))
    return hits


def region_context_hits(meta: dict) -> list[PatternHit]:
    """Properties of the allocation itself, independent of its contents."""
    hits: list[PatternHit] = []
    protection = str(meta.get("protection", "")).upper()
    private = bool(meta.get("private", False))
    executable = "EXECUTE" in protection
    writable = "WRITE" in protection

    if executable and writable:
        hits.append(PatternHit(
            id="rwx_region", title="Writable and executable region", severity="high",
            description=("The allocation is both writable and executable. Legitimate "
                         "code is rarely both; JIT runtimes are the usual exception."),
            technique="T1055", technique_name="Process Injection",
            occurrences=1, evidence=protection,
        ))
    if executable and private:
        hits.append(PatternHit(
            id="private_executable", title="Executable private memory", severity="high",
            description=("Executable memory with no backing file on disk — code that "
                         "cannot be attributed to a module the loader mapped."),
            technique="T1055.001", technique_name="Dynamic-link Library Injection",
            occurrences=1, evidence=protection,
        ))
    entropy = float(meta.get("entropy", 0) or 0)
    if entropy > 7.2:
        hits.append(PatternHit(
            id="high_entropy_region", title="High-entropy contents", severity="medium",
            description=(f"Region entropy is {entropy:.2f}, consistent with packed, "
                         "compressed or encrypted data rather than plain code."),
            technique="T1027.002", technique_name="Software Packing",
            occurrences=1, evidence=f"entropy={entropy:.2f}",
        ))
    return hits


def scan(data: bytes, listing: Listing | None = None, meta: dict | None = None) -> PatternReport:
    """Run every applicable check. Never raises."""
    report = PatternReport()
    hits: list[PatternHit] = []
    try:
        hits.extend(region_context_hits(meta or {}))
        hits.extend(scan_bytes(data))
        if listing is not None and listing.available:
            report.instruction_scan = True
            hits.extend(scan_instructions(listing))
        elif listing is not None:
            report.note = ("Instruction-level checks were skipped: " + listing.reason)
    except Exception as exc:
        report.note = f"Pattern scan stopped early ({type(exc).__name__})."

    hits.sort(key=lambda h: (-SEVERITY_ORDER.get(h.severity, 0), h.id))
    report.hits = hits
    return report

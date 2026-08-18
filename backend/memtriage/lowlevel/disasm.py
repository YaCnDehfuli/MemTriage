"""Instruction recovery for a dumped region.

Two passes, in the order a reverse engineer would run them:

* **recursive descent** from a set of entry candidates, following direct branches
  and calls — accurate, and the basis for the control-flow and call graphs;
* **linear sweep** over whatever recursion never reached, so the listing still
  covers the region rather than stopping at the first indirect jump.

The architecture is not recorded anywhere in a VAD dump, so both x86 and x86-64
are decoded and scored; the mode that decodes further with fewer nonsense
instructions wins. Capstone is imported lazily and its absence is reported, not
raised — the rest of the deep-dive (structure, strings, byte patterns) does not
need it.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .budget import Budget

X86 = "x86"
X64 = "x86-64"

# Instructions that end a basic block, split by how control leaves it.
_RETURNS = {"ret", "retf", "iret", "iretd", "iretq"}
_UNCONDITIONAL = {"jmp", "ljmp"}
_CALLS = {"call", "lcall"}
_HALTS = {"hlt", "ud2", "int3"}
_INTERRUPTS = {"int", "into", "syscall", "sysenter", "sysexit", "sysret"}


@dataclass
class Instruction:
    address: int
    size: int
    bytes_hex: str
    mnemonic: str
    op_str: str
    kind: str = "normal"      # normal | call | jump | cjump | ret | halt | syscall
    target: int | None = None  # direct branch/call target when statically known

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {self.op_str}".strip()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["address_hex"] = hex(self.address)
        data["text"] = self.text
        return data


@dataclass
class Listing:
    available: bool
    arch: str = ""
    reason: str = ""
    base_addr: int = 0
    analyzed_bytes: int = 0
    truncated: bool = False
    instructions: list[Instruction] = field(default_factory=list)
    entry_points: list[int] = field(default_factory=list)
    invalid_bytes: int = 0
    coverage: float = 0.0

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "arch": self.arch,
            "reason": self.reason,
            "base_addr": hex(self.base_addr),
            "analyzed_bytes": self.analyzed_bytes,
            "truncated": self.truncated,
            "invalid_bytes": self.invalid_bytes,
            "coverage": round(self.coverage, 4),
            "entry_points": [hex(a) for a in self.entry_points],
            "instruction_count": len(self.instructions),
            "instructions": [i.to_dict() for i in self.instructions],
        }

    @classmethod
    def unavailable(cls, reason: str) -> Listing:
        return cls(available=False, reason=reason)


def capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        return True
    except Exception:
        return False


def _classify(mnemonic: str) -> str:
    if mnemonic in _RETURNS:
        return "ret"
    if mnemonic in _CALLS:
        return "call"
    if mnemonic in _UNCONDITIONAL:
        return "jump"
    if mnemonic.startswith("j"):
        return "cjump"
    if mnemonic in _HALTS:
        return "halt"
    if mnemonic in _INTERRUPTS:
        return "syscall"
    return "normal"


def _direct_target(mnemonic: str, op_str: str, base: int, length: int) -> int | None:
    """A branch target only counts when capstone printed an absolute address."""
    if _classify(mnemonic) not in {"call", "jump", "cjump"}:
        return None
    operand = op_str.strip()
    if not operand.startswith("0x"):
        return None
    try:
        target = int(operand, 16)
    except ValueError:
        return None
    return target if base <= target < base + length else None


def _md(arch: str):
    import capstone

    mode = capstone.CS_MODE_64 if arch == X64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.skipdata = False
    return md


def _score(data: bytes, arch: str, sample: int = 8192) -> float:
    """How plausible is this architecture: decoded bytes minus obvious nonsense."""
    try:
        md = _md(arch)
    except Exception:
        return 0.0
    window = data[:sample]
    decoded = 0
    suspicious = 0
    count = 0
    for insn in md.disasm(window, 0):
        decoded += insn.size
        count += 1
        if insn.mnemonic in {"(bad)", "ud2"} or insn.mnemonic.startswith("."):
            suspicious += 1
        if count >= 2048:
            break
    if not window:
        return 0.0
    return (decoded / len(window)) - (suspicious / max(count, 1))


def detect_arch(data: bytes, hint: str = "") -> str:
    if hint in (X86, X64):
        return hint
    if not capstone_available():
        return X64
    return X64 if _score(data, X64) >= _score(data, X86) else X86


def entry_candidates(data: bytes, base_addr: int) -> list[int]:
    """Plausible starts: the region head, a PE entry point, and function prologues."""
    entries = [base_addr]
    if len(data) > 0x40 and data[:2] == b"MZ":
        entry = _pe_entry_rva(data)
        if entry is not None:
            entries.append(base_addr + entry)

    prologues = (b"\x55\x8b\xec", b"\x55\x48\x89\xe5", b"\x48\x83\xec", b"\x48\x89\x5c\x24")
    for prologue in prologues:
        offset = data.find(prologue)
        seen = 0
        while offset != -1 and seen < 8:
            entries.append(base_addr + offset)
            seen += 1
            offset = data.find(prologue, offset + 1)
    ordered: list[int] = []
    for address in entries:
        if address not in ordered:
            ordered.append(address)
    return ordered


def _pe_entry_rva(data: bytes) -> int | None:
    try:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if pe_offset <= 0 or pe_offset + 0x30 > len(data):
            return None
        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return None
        return int.from_bytes(data[pe_offset + 0x28:pe_offset + 0x2C], "little")
    except (IndexError, ValueError):
        return None


def disassemble(data: bytes, base_addr: int = 0, *, arch: str = "",
                budget: Budget | None = None) -> Listing:
    """Recover an instruction listing. Never raises; reports why it could not."""
    budget = budget or Budget()
    if not data:
        return Listing.unavailable("Region has no bytes to decode.")
    if not capstone_available():
        return Listing.unavailable(
            "Capstone is not installed, so no instruction listing, control-flow "
            "graph or call graph can be produced. `pip install capstone` enables "
            "them; byte structure, strings and pattern matching are unaffected."
        )

    window = bytes(data[: budget.max_bytes])
    truncated = len(data) > len(window)
    resolved = detect_arch(window, arch)

    try:
        md = _md(resolved)
    except Exception as exc:
        return Listing.unavailable(f"Capstone could not be initialized ({type(exc).__name__}).")

    decoded: dict[int, Instruction] = {}
    entries = entry_candidates(window, base_addr)
    try:
        _recursive_descent(md, window, base_addr, entries, decoded, budget)
        _linear_fill(md, window, base_addr, decoded, budget)
    except Exception as exc:
        if not decoded:
            return Listing.unavailable(f"Decoding failed ({type(exc).__name__}).")

    instructions = [decoded[a] for a in sorted(decoded)]
    covered = sum(i.size for i in instructions)
    return Listing(
        available=True,
        arch=resolved,
        base_addr=base_addr,
        analyzed_bytes=len(window),
        truncated=truncated,
        instructions=instructions,
        entry_points=entries,
        invalid_bytes=max(len(window) - covered, 0),
        coverage=covered / len(window) if window else 0.0,
    )


def _decode_one(md, window: bytes, base_addr: int, address: int) -> Instruction | None:
    offset = address - base_addr
    if offset < 0 or offset >= len(window):
        return None
    for insn in md.disasm(window[offset:offset + 16], address, count=1):
        mnemonic = insn.mnemonic
        return Instruction(
            address=insn.address,
            size=insn.size,
            bytes_hex=insn.bytes.hex(),
            mnemonic=mnemonic,
            op_str=insn.op_str,
            kind=_classify(mnemonic),
            target=_direct_target(mnemonic, insn.op_str, base_addr, len(window)),
        )
    return None


def _recursive_descent(md, window: bytes, base_addr: int, entries: list[int],
                       decoded: dict[int, Instruction], budget: Budget) -> None:
    pending = list(entries)
    while pending and len(decoded) < budget.max_instructions:
        address = pending.pop()
        while len(decoded) < budget.max_instructions:
            if address in decoded:
                break
            insn = _decode_one(md, window, base_addr, address)
            if insn is None:
                break
            decoded[address] = insn
            if insn.target is not None and insn.target not in decoded:
                pending.append(insn.target)
            if insn.kind in {"ret", "halt"}:
                break
            if insn.kind == "jump":
                break
            address = insn.address + insn.size


def _linear_fill(md, window: bytes, base_addr: int, decoded: dict[int, Instruction],
                 budget: Budget) -> None:
    """Sweep the gaps recursion never entered so the listing still covers the region."""
    if len(decoded) >= budget.max_instructions:
        return
    for insn in md.disasm(window, base_addr):
        if len(decoded) >= budget.max_instructions:
            return
        if insn.address in decoded:
            continue
        decoded[insn.address] = Instruction(
            address=insn.address,
            size=insn.size,
            bytes_hex=insn.bytes.hex(),
            mnemonic=insn.mnemonic,
            op_str=insn.op_str,
            kind=_classify(insn.mnemonic),
            target=_direct_target(insn.mnemonic, insn.op_str, base_addr, len(window)),
        )

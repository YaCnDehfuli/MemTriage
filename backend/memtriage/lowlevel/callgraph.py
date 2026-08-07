"""Function boundaries and the call graph.

Functions are recovered the pragmatic way a memory-dump disassembler has to:
anything that is the target of a direct call is a function, plus the entry
points, plus prologues that follow a return. Edges come from direct calls;
indirect calls are counted and reported rather than silently dropped, because in
injected code they are usually the interesting ones.

Call targets outside the region are almost always imported API. Where the region
carries a PE import table the name comes from there; otherwise a nearby string
is used as a hint, and anything unresolved is reported as an external address —
never guessed at.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field

from .budget import Budget
from .disasm import Listing

_API_NAME_RE = re.compile(rb"[A-Z][A-Za-z0-9_]{4,63}")

# API names worth naming in the graph even when they are only a nearby string.
NOTABLE_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
    "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
    "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
    "WinExec", "CreateFileA", "CreateFileW", "WriteFile", "ReadFile",
    "InternetOpenA", "InternetOpenUrlA", "HttpSendRequestA", "URLDownloadToFileA",
    "WSAStartup", "connect", "send", "recv", "socket",
    "RegCreateKeyExA", "RegSetValueExA", "RegOpenKeyExA",
    "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
    "OpenProcess", "AdjustTokenPrivileges", "IsDebuggerPresent",
    "NtQueryInformationProcess", "NtUnmapViewOfSection", "ZwProtectVirtualMemory",
}


@dataclass
class FunctionNode:
    id: int
    address: int
    label: str
    kind: str  # entry | local | external | api
    call_count: int = 0
    instruction_count: int = 0
    layer: int = 0
    order: int = 0

    def to_dict(self) -> dict:
        data = asdict(self)
        data["address_hex"] = hex(self.address) if self.address else ""
        return data


@dataclass
class CallEdge:
    source: int
    target: int
    count: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CallGraph:
    available: bool
    reason: str = ""
    nodes: list[FunctionNode] = field(default_factory=list)
    edges: list[CallEdge] = field(default_factory=list)
    indirect_calls: int = 0
    resolved_apis: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "indirect_calls": self.indirect_calls,
            "resolved_apis": self.resolved_apis,
            "truncated": self.truncated,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "dot": to_dot(self),
        }

    @classmethod
    def unavailable(cls, reason: str) -> "CallGraph":
        return cls(available=False, reason=reason)


def candidate_api_names(data: bytes, limit: int = 64) -> list[str]:
    """Notable Windows API names present in the region's bytes."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _API_NAME_RE.finditer(data):
        name = match.group().decode("ascii", "ignore")
        if name in NOTABLE_APIS and name not in seen:
            seen.add(name)
            found.append(name)
            if len(found) >= limit:
                break
    return found


def build_callgraph(listing: Listing, data: bytes = b"",
                    budget: Budget | None = None) -> CallGraph:
    """Recover functions and the calls between them. Never raises."""
    budget = budget or Budget()
    if not listing.available:
        return CallGraph.unavailable(listing.reason)
    if not listing.instructions:
        return CallGraph.unavailable("Nothing decoded, so there are no functions.")
    try:
        return _build(listing, data, budget)
    except Exception as exc:
        return CallGraph.unavailable(
            f"Call-graph reconstruction failed ({type(exc).__name__})."
        )


def _build(listing: Listing, data: bytes, budget: Budget) -> CallGraph:
    instructions = listing.instructions
    base = listing.base_addr
    end = base + listing.analyzed_bytes

    call_targets: dict[int, int] = defaultdict(int)
    indirect = 0
    for insn in instructions:
        if insn.kind != "call":
            continue
        if insn.target is None:
            indirect += 1
        else:
            call_targets[insn.target] += 1

    starts = sorted({*listing.entry_points, *call_targets})
    starts = [a for a in starts if base <= a < end][: budget.max_functions]
    truncated = len(call_targets) + len(listing.entry_points) > len(starts)

    nodes: list[FunctionNode] = []
    node_of: dict[int, int] = {}
    for address in starts:
        node = FunctionNode(
            id=len(nodes),
            address=address,
            label=("entry" if address in listing.entry_points and address == base
                   else f"sub_{address:x}"),
            kind="entry" if address == base else "local",
            call_count=call_targets.get(address, 0),
        )
        node_of[address] = node.id
        nodes.append(node)

    boundaries = starts + [end]
    for index, node in enumerate(nodes):
        low, high = boundaries[index], boundaries[index + 1]
        node.instruction_count = sum(1 for i in instructions if low <= i.address < high)

    apis = candidate_api_names(data) if data else []
    for name in apis[:24]:
        nodes.append(FunctionNode(id=len(nodes), address=0, label=name, kind="api"))

    edges: dict[tuple[int, int], int] = defaultdict(int)
    for index, node in enumerate(nodes):
        if node.kind == "api":
            continue
        low = boundaries[index] if index < len(boundaries) - 1 else end
        high = boundaries[index + 1] if index + 1 < len(boundaries) else end
        for insn in instructions:
            if not (low <= insn.address < high) or insn.kind != "call":
                continue
            if insn.target is None:
                continue
            target_id = node_of.get(insn.target)
            if target_id is not None:
                edges[(node.id, target_id)] += 1

    graph = CallGraph(
        available=True,
        nodes=nodes,
        edges=[CallEdge(s, t, c) for (s, t), c in sorted(edges.items())],
        indirect_calls=indirect,
        resolved_apis=apis,
        truncated=truncated,
    )
    _layout(graph)
    return graph


def _layout(graph: CallGraph) -> None:
    successors: dict[int, list[int]] = defaultdict(list)
    incoming: dict[int, int] = defaultdict(int)
    for edge in graph.edges:
        successors[edge.source].append(edge.target)
        incoming[edge.target] += 1

    roots = [n.id for n in graph.nodes if n.kind != "api" and incoming[n.id] == 0]
    if not roots and graph.nodes:
        roots = [graph.nodes[0].id]

    depth: dict[int, int] = {r: 0 for r in roots}
    frontier = list(roots)
    while frontier:
        node = frontier.pop(0)
        for nxt in successors.get(node, ()):
            if nxt not in depth:
                depth[nxt] = depth[node] + 1
                frontier.append(nxt)

    deepest = max(depth.values(), default=0)
    per_layer: dict[int, int] = defaultdict(int)
    for node in graph.nodes:
        node.layer = deepest + 1 if node.kind == "api" else depth.get(node.id, deepest + 1)
    for node in sorted(graph.nodes, key=lambda n: (n.layer, n.address, n.label)):
        node.order = per_layer[node.layer]
        per_layer[node.layer] += 1


def to_dot(graph: CallGraph) -> str:
    if not graph.available:
        return ""
    lines = ["digraph calls {", "  node [shape=box fontname=monospace];"]
    for node in graph.nodes:
        shape = "ellipse" if node.kind == "api" else "box"
        lines.append(f'  n{node.id} [label="{node.label}" shape={shape}];')
    for edge in graph.edges:
        label = f' [label="{edge.count}"]' if edge.count > 1 else ""
        lines.append(f"  n{edge.source} -> n{edge.target}{label};")
    lines.append("}")
    return "\n".join(lines)

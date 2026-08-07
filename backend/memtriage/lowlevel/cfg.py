"""Basic blocks and the control-flow graph.

Blocks are cut at the two boundaries that define them: an instruction that
transfers control ends a block, and an instruction that is the target of one
starts a block. Edges are typed so the UI can draw a taken branch differently
from a fallthrough.

Layout is computed here rather than in the browser: a BFS from the entry assigns
each block a layer, blocks are ordered within their layer, and the coordinates
that come out feed a plain SVG. That keeps the frontend free of a graph library
and gives the same picture in the JSON export.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field

from .budget import Budget
from .disasm import Instruction, Listing

_TERMINATORS = {"call", "jump", "cjump", "ret", "halt"}


@dataclass
class BasicBlock:
    id: int
    start: int
    end: int
    instruction_count: int
    terminator: str
    layer: int = 0
    order: int = 0
    label: str = ""
    branch_target: int | None = None
    instructions: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["start_hex"] = hex(self.start)
        data["end_hex"] = hex(self.end)
        return data


@dataclass
class Edge:
    source: int
    target: int
    kind: str  # taken | fallthrough | jump

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ControlFlowGraph:
    available: bool
    reason: str = ""
    blocks: list[BasicBlock] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    entry_block: int | None = None
    truncated: bool = False
    loops: int = 0
    unreachable_blocks: int = 0

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "reason": self.reason,
            "entry_block": self.entry_block,
            "truncated": self.truncated,
            "loops": self.loops,
            "unreachable_blocks": self.unreachable_blocks,
            "block_count": len(self.blocks),
            "edge_count": len(self.edges),
            "blocks": [b.to_dict() for b in self.blocks],
            "edges": [e.to_dict() for e in self.edges],
            "dot": to_dot(self),
        }

    @classmethod
    def unavailable(cls, reason: str) -> "ControlFlowGraph":
        return cls(available=False, reason=reason)


def _leaders(instructions: list[Instruction]) -> set[int]:
    if not instructions:
        return set()
    by_address = {i.address: i for i in instructions}
    leaders = {instructions[0].address}
    for insn in instructions:
        following = insn.address + insn.size
        if insn.kind in _TERMINATORS and following in by_address:
            leaders.add(following)
        if insn.target is not None and insn.target in by_address:
            leaders.add(insn.target)
    return leaders


def build_cfg(listing: Listing, budget: Budget | None = None) -> ControlFlowGraph:
    """Cut the listing into basic blocks and connect them. Never raises."""
    budget = budget or Budget()
    if not listing.available:
        return ControlFlowGraph.unavailable(listing.reason)
    instructions = listing.instructions
    if not instructions:
        return ControlFlowGraph.unavailable("Nothing decoded, so there are no blocks.")

    try:
        return _build(instructions, budget)
    except Exception as exc:
        return ControlFlowGraph.unavailable(
            f"Control-flow reconstruction failed ({type(exc).__name__})."
        )


def _build(instructions: list[Instruction], budget: Budget) -> ControlFlowGraph:
    leaders = _leaders(instructions)

    blocks: list[BasicBlock] = []
    block_of: dict[int, int] = {}
    current: list[Instruction] = []

    def close(block_instructions: list[Instruction]) -> None:
        if not block_instructions:
            return
        first, last = block_instructions[0], block_instructions[-1]
        block = BasicBlock(
            id=len(blocks),
            start=first.address,
            end=last.address + last.size,
            instruction_count=len(block_instructions),
            terminator=last.kind,
            label=hex(first.address),
            branch_target=last.target,
            instructions=[i.to_dict() for i in block_instructions],
        )
        for insn in block_instructions:
            block_of[insn.address] = block.id
        blocks.append(block)

    for insn in instructions:
        if current and insn.address in leaders:
            close(current)
            current = []
        current.append(insn)
        if insn.kind in _TERMINATORS:
            close(current)
            current = []
        if len(blocks) >= budget.max_blocks:
            break
    close(current)

    truncated = len(blocks) >= budget.max_blocks
    blocks = blocks[: budget.max_blocks]
    valid = {b.id for b in blocks}

    edges: list[Edge] = []
    seen: set[tuple[int, int, str]] = set()

    def link(source: int, target_address: int, kind: str) -> None:
        target = block_of.get(target_address)
        if target is None or source not in valid or target not in valid:
            return
        key = (source, target, kind)
        if key in seen:
            return
        seen.add(key)
        edges.append(Edge(source, target, kind))

    for block in blocks:
        terminator = block.terminator
        if terminator in {"cjump", "call", "normal"}:
            link(block.id, block.end, "fallthrough")
        if terminator in {"cjump", "jump"} and block.branch_target is not None:
            link(block.id, block.branch_target,
                 "taken" if terminator == "cjump" else "jump")

    entry_block = blocks[0].id if blocks else None
    _layout(blocks, edges, entry_block)
    reachable = {b.id for b in blocks if b.layer >= 0}
    return ControlFlowGraph(
        available=True,
        blocks=blocks,
        edges=edges,
        entry_block=entry_block,
        truncated=truncated,
        loops=_count_back_edges(blocks, edges),
        unreachable_blocks=len(blocks) - len(reachable),
    )


def _layout(blocks: list[BasicBlock], edges: list[Edge], entry: int | None) -> None:
    """Assign each block a layer (BFS depth) and a position within it."""
    successors: dict[int, list[int]] = defaultdict(list)
    for edge in edges:
        successors[edge.source].append(edge.target)

    depth: dict[int, int] = {}
    queue: deque[int] = deque()
    if entry is not None:
        depth[entry] = 0
        queue.append(entry)
    while queue:
        node = queue.popleft()
        for nxt in successors.get(node, ()):
            if nxt not in depth:
                depth[nxt] = depth[node] + 1
                queue.append(nxt)

    # Blocks recursion never reached still need a place: order them after the
    # deepest reachable layer, by address, so nothing is silently dropped.
    fallback = max(depth.values(), default=0) + 1
    for block in blocks:
        block.layer = depth.get(block.id, fallback)

    per_layer: dict[int, int] = defaultdict(int)
    for block in sorted(blocks, key=lambda b: (b.layer, b.start)):
        block.order = per_layer[block.layer]
        per_layer[block.layer] += 1


def _count_back_edges(blocks: list[BasicBlock], edges: list[Edge]) -> int:
    layer = {b.id: b.layer for b in blocks}
    return sum(1 for e in edges if layer.get(e.target, 0) <= layer.get(e.source, 0)
               and e.target != e.source) + sum(1 for e in edges if e.target == e.source)


def to_dot(graph: ControlFlowGraph) -> str:
    """Graphviz source, so the same graph can be rendered outside the app."""
    if not graph.available:
        return ""
    lines = ["digraph cfg {", "  node [shape=box fontname=monospace];"]
    for block in graph.blocks:
        lines.append(f'  b{block.id} [label="{block.label}\\n{block.instruction_count} insn"];')
    styles = {"taken": "solid", "fallthrough": "dashed", "jump": "bold"}
    for edge in graph.edges:
        lines.append(
            f'  b{edge.source} -> b{edge.target} [style={styles.get(edge.kind, "solid")}];'
        )
    lines.append("}")
    return "\n".join(lines)

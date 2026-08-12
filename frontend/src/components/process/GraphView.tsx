import { useMemo } from "react";
import type { CallNode, CfgBlock, CfgEdge, RegionAnalysis } from "../../types";
import { Chip } from "../primitives";
import { Unavailable } from "./Disassembly";

const NODE_W = 132;
const NODE_H = 40;
const GAP_X = 28;
const GAP_Y = 56;

interface Placed {
  id: number;
  x: number;
  y: number;
  label: string;
  sub: string;
  tone: string;
}

const EDGE_STYLE: Record<string, { stroke: string; dash?: string }> = {
  taken: { stroke: "var(--edge-taken)" },
  fallthrough: { stroke: "var(--edge-fall)", dash: "4 3" },
  jump: { stroke: "var(--edge-jump)" },
  call: { stroke: "var(--edge-taken)" },
};

function layout<T extends { layer: number; order: number }>(
  items: T[],
  toPlaced: (item: T, x: number, y: number) => Placed,
): { placed: Placed[]; width: number; height: number } {
  const perLayer = new Map<number, number>();
  items.forEach((i) => perLayer.set(i.layer, (perLayer.get(i.layer) ?? 0) + 1));
  const widest = Math.max(1, ...perLayer.values());
  const width = widest * (NODE_W + GAP_X) + GAP_X;
  const layers = Math.max(1, ...items.map((i) => i.layer + 1));
  const height = layers * (NODE_H + GAP_Y) + GAP_Y;

  const placed = items.map((item) => {
    const count = perLayer.get(item.layer) ?? 1;
    const rowWidth = count * (NODE_W + GAP_X) - GAP_X;
    const x = (width - rowWidth) / 2 + item.order * (NODE_W + GAP_X);
    const y = GAP_Y / 2 + item.layer * (NODE_H + GAP_Y);
    return toPlaced(item, x, y);
  });
  return { placed, width, height };
}

function Edges({
  edges,
  byId,
}: {
  edges: { source: number; target: number; kind?: string }[];
  byId: Map<number, Placed>;
}) {
  return (
    <>
      {edges.map((edge, index) => {
        const from = byId.get(edge.source);
        const to = byId.get(edge.target);
        if (!from || !to) return null;
        const style = EDGE_STYLE[edge.kind ?? "call"] ?? EDGE_STYLE.call;
        const x1 = from.x + NODE_W / 2;
        const y1 = from.y + NODE_H;
        const x2 = to.x + NODE_W / 2;
        const y2 = to.y;
        // A back edge (a loop) bows out to the side so it is not hidden under
        // the forward path it runs alongside.
        const backwards = y2 <= y1;
        const path = backwards
          ? `M ${x1} ${y1} C ${x1 + 90} ${y1 + 30}, ${x2 + 90} ${y2 - 30}, ${x2} ${y2}`
          : `M ${x1} ${y1} C ${x1} ${y1 + 26}, ${x2} ${y2 - 26}, ${x2} ${y2}`;
        return (
          <path
            key={`${edge.source}-${edge.target}-${index}`}
            d={path}
            fill="none"
            stroke={style.stroke}
            strokeWidth={1.3}
            strokeDasharray={style.dash}
            markerEnd="url(#arrow)"
          />
        );
      })}
    </>
  );
}

function Canvas({
  width,
  height,
  placed,
  edges,
  onSelect,
}: {
  width: number;
  height: number;
  placed: Placed[];
  edges: { source: number; target: number; kind?: string }[];
  onSelect?(id: number): void;
}) {
  const byId = useMemo(() => new Map(placed.map((p) => [p.id, p])), [placed]);
  return (
    <div
      className="overflow-auto rounded-md border border-ink-700/60 bg-ink-900/40"
      style={{
        // Tokens keep the edge colours in one place and readable on this surface.
        ["--edge-taken" as string]: "#38c6d9",
        ["--edge-fall" as string]: "#5b6b80",
        ["--edge-jump" as string]: "#e7c14b",
      }}
    >
      <svg width={width} height={height} role="img" className="block min-w-full">
        <defs>
          <marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7"
                  markerHeight="7" orient="auto">
            <path d="M0,0 L8,4 L0,8 z" fill="#5b6b80" />
          </marker>
        </defs>
        <Edges edges={edges} byId={byId} />
        {placed.map((node) => (
          <g
            key={node.id}
            transform={`translate(${node.x},${node.y})`}
            onClick={() => onSelect?.(node.id)}
            className={onSelect ? "cursor-pointer" : undefined}
          >
            <rect
              width={NODE_W}
              height={NODE_H}
              rx={6}
              fill="#141c28"
              stroke={node.tone}
              strokeWidth={1.2}
            />
            <text x={NODE_W / 2} y={17} textAnchor="middle" fontSize="11"
                  fontFamily="ui-monospace, monospace" fill="#e6ecf3">
              {node.label}
            </text>
            <text x={NODE_W / 2} y={31} textAnchor="middle" fontSize="10"
                  fontFamily="ui-monospace, monospace" fill="#7688a0">
              {node.sub}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

export function ControlFlowGraph({
  analysis,
  onSelectBlock,
}: {
  analysis: RegionAnalysis;
  onSelectBlock?(block: CfgBlock): void;
}) {
  const graph = analysis.control_flow;
  const { placed, width, height } = useMemo(
    () =>
      layout<CfgBlock>(graph.blocks ?? [], (block, x, y) => ({
        id: block.id,
        x,
        y,
        label: block.label,
        sub: `${block.instruction_count} insn · ${block.terminator}`,
        tone: block.terminator === "ret" ? "#5b8def"
          : block.terminator === "call" ? "#38c6d9" : "#293648",
      })),
    [graph.blocks],
  );

  if (!graph.available) return <Unavailable reason={graph.reason} />;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone="mono">{graph.block_count} blocks</Chip>
        <Chip tone="mono">{graph.edge_count} edges</Chip>
        {graph.loops > 0 && <Chip tone="accent">{graph.loops} back edge(s)</Chip>}
        {graph.unreachable_blocks > 0 && (
          <Chip tone="mono">{graph.unreachable_blocks} unreached</Chip>
        )}
        {graph.truncated && <Chip tone="mono">truncated at the block budget</Chip>}
      </div>
      <Canvas
        width={width}
        height={height}
        placed={placed}
        edges={graph.edges as CfgEdge[]}
        onSelect={(id) => {
          const block = graph.blocks.find((b) => b.id === id);
          if (block) onSelectBlock?.(block);
        }}
      />
      <Legend
        items={[
          ["#38c6d9", "taken / call"],
          ["#5b6b80", "fallthrough"],
          ["#e7c14b", "unconditional jump"],
        ]}
      />
    </div>
  );
}

export function CallGraph({ analysis }: { analysis: RegionAnalysis }) {
  const graph = analysis.call_graph;
  const { placed, width, height } = useMemo(
    () =>
      layout<CallNode>(graph.nodes ?? [], (node, x, y) => ({
        id: node.id,
        x,
        y,
        label: node.label,
        sub: node.kind === "api" ? "imported api" : `${node.instruction_count} insn`,
        tone: node.kind === "api" ? "#f2994a" : node.kind === "entry" ? "#38c6d9" : "#293648",
      })),
    [graph.nodes],
  );

  if (!graph.available) return <Unavailable reason={graph.reason} />;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Chip tone="mono">{graph.node_count} functions</Chip>
        <Chip tone="mono">{graph.edge_count} calls</Chip>
        {graph.indirect_calls > 0 && (
          <Chip tone="accent">{graph.indirect_calls} indirect</Chip>
        )}
      </div>
      {graph.indirect_calls > 0 && (
        <p className="text-[12px] text-mist-400">
          Indirect calls go through a register or memory operand, so their target is not
          statically known — the shape of dynamically resolved imports. They are counted
          here rather than drawn.
        </p>
      )}
      <Canvas width={width} height={height} placed={placed} edges={graph.edges} />
      {graph.resolved_apis.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {graph.resolved_apis.map((name) => (
            <Chip key={name} tone="mono">{name}</Chip>
          ))}
        </div>
      )}
      <Legend items={[["#38c6d9", "entry"], ["#293648", "local function"], ["#f2994a", "api name"]]} />
    </div>
  );
}

function Legend({ items }: { items: [string, string][] }) {
  return (
    <div className="flex flex-wrap gap-4">
      {items.map(([color, label]) => (
        <span key={label} className="flex items-center gap-1.5 text-[11px] text-mist-400">
          <span className="h-2 w-4 rounded-sm" style={{ background: color }} />
          {label}
        </span>
      ))}
    </div>
  );
}

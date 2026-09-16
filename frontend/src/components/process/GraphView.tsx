import { useMemo, type KeyboardEvent } from "react";
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

// Dash pattern differs per edge kind too, not just color — so the kind
// still reads for a color-blind viewer or a printed/grayscale copy.
const EDGE_STYLE: Record<string, { stroke: string; dash?: string }> = {
  taken: { stroke: "var(--edge-taken)" },
  fallthrough: { stroke: "var(--edge-fall)", dash: "4 3" },
  jump: { stroke: "var(--edge-jump)", dash: "1 4" },
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
      className="overflow-auto rounded-md border border-surface-700/60 bg-surface-900/40"
      style={{
        // Tokens keep the edge colours in one place and readable on this surface.
        ["--edge-taken" as string]: "#8bafa0",
        ["--edge-fall" as string]: "#5b6b80",
        ["--edge-jump" as string]: "#a17f16",
      }}
    >
      <svg
        width={width}
        height={height}
        aria-label={onSelect ? "Block graph, nodes are selectable" : "Graph"}
        className="block min-w-full"
      >
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
            className={onSelect ? "graph-node cursor-pointer" : undefined}
            {...(onSelect
              ? {
                  role: "button",
                  tabIndex: 0,
                  "aria-label": `${node.label}, ${node.sub}`,
                  onKeyDown: (e: KeyboardEvent) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      onSelect(node.id);
                    }
                  },
                }
              : {})}
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
        tone: block.terminator === "ret" ? "#3f63b8"
          : block.terminator === "call" ? "#8bafa0" : "#293648",
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
          ["#8bafa0", "taken / call"],
          ["#5b6b80", "fallthrough"],
          ["#a17f16", "unconditional jump"],
        ]}
      />
      <GraphTable
        rows={graph.blocks.map((b) => ({
          id: String(b.id),
          label: b.label,
          detail: `${b.instruction_count} insn · ${b.terminator}`,
          targets: (graph.edges as CfgEdge[])
            .filter((e) => e.source === b.id)
            .map((e) => graph.blocks.find((x) => x.id === e.target)?.label ?? e.target)
            .join(", "),
        }))}
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
        tone: node.kind === "api" ? "#bd6a1e" : node.kind === "entry" ? "#8bafa0" : "#293648",
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
        <p className="text-[12px] text-ink-400">
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
      <Legend items={[["#8bafa0", "entry"], ["#293648", "local function"], ["#bd6a1e", "api name"]]} />
      <GraphTable
        rows={graph.nodes.map((n) => ({
          id: String(n.id),
          label: n.label,
          detail: n.kind === "api" ? "imported api" : `${n.kind} · ${n.instruction_count} insn`,
          targets: graph.edges
            .filter((e) => e.source === n.id)
            .map((e) => graph.nodes.find((x) => x.id === e.target)?.label ?? e.target)
            .join(", "),
        }))}
      />
    </div>
  );
}

/** A plain-text equivalent of the graph, for anyone who cannot use — or would
 * rather not use — the SVG layout. */
function GraphTable({
  rows,
}: {
  rows: { id: string; label: string; detail: string; targets: string }[];
}) {
  return (
    <details className="rounded-md border border-surface-700/60">
      <summary className="cursor-pointer px-3 py-2 text-[12px] font-medium text-ink-200">
        View as table
      </summary>
      <div className="max-h-64 overflow-auto border-t border-surface-700/60">
        <table className="w-full text-left text-[11px]">
          <thead className="sticky top-0 bg-surface-850 uppercase tracking-wider text-ink-400">
            <tr className="border-b border-surface-700/60">
              <th className="px-3 py-1.5">Node</th>
              <th className="px-3 py-1.5">Detail</th>
              <th className="px-3 py-1.5">Goes to</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b border-surface-800/60">
                <td className="px-3 py-1.5 font-mono text-ink-100">{row.label}</td>
                <td className="px-3 py-1.5 text-ink-300">{row.detail}</td>
                <td className="px-3 py-1.5 font-mono text-ink-400">{row.targets || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function Legend({ items }: { items: [string, string][] }) {
  return (
    <div className="flex flex-wrap gap-4">
      {items.map(([color, label]) => (
        <span key={label} className="flex items-center gap-1.5 text-[11px] text-ink-400">
          <span className="h-2 w-4 rounded-sm" style={{ background: color }} />
          {label}
        </span>
      ))}
    </div>
  );
}

import { useState } from "react";
import { useApp } from "../../state/store";
import { pct } from "../../lib/format";
import { Chip, Panel, RiskBadge } from "../primitives";

export function InventoryView() {
  const { processes, selectProcess } = useApp();
  const [q, setQ] = useState("");
  const [flaggedOnly, setFlaggedOnly] = useState(false);

  const rows = processes
    .filter((p) => (flaggedOnly ? !!p.risk : true))
    .filter((p) => (q ? `${p.name} ${p.pid}`.toLowerCase().includes(q.toLowerCase()) : true))
    .sort((a, b) => (b.score ?? -1) - (a.score ?? -1) || a.pid - b.pid);

  return (
    <div className="space-y-5">
      <header>
        <div className="eyebrow">Phase 1 → 2 · Select</div>
        <h1 className="text-lg font-semibold text-mist-100">Process inventory</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist-400">
          Every process the census surfaced, ranked by engine score. Pick one to run the VADViT
          deep-dive. Non-analyzable system processes (no user VADs) are marked.
        </p>
      </header>

      <Panel
        eyebrow="Census"
        title={`${processes.length} processes`}
        className="overflow-hidden"
        right={
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-[11px] text-mist-400">
              <input
                type="checkbox"
                className="accent-accent"
                checked={flaggedOnly}
                onChange={(e) => setFlaggedOnly(e.target.checked)}
              />
              Flagged only
            </label>
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Filter name / PID"
              className="w-40 rounded-md border border-ink-600 bg-ink-900 px-2 py-1 text-xs text-mist-200 placeholder:text-mist-400 focus:border-accent/50 focus:outline-none"
            />
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-ink-700/60 text-left text-[11px] uppercase tracking-wider text-mist-400">
                <th className="px-4 py-2">PID</th>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">PPID</th>
                <th className="px-3 py-2">Risk</th>
                <th className="px-3 py-2">Score</th>
                <th className="px-3 py-2">Signals</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr key={p.pid} className="border-b border-ink-800/70 hover:bg-ink-800/40">
                  <td className="px-4 py-2.5 font-mono text-mist-200">{p.pid}</td>
                  <td className="px-3 py-2.5 text-mist-100">
                    {p.name}
                    {!p.analyzable && (
                      <span className="ml-2 text-[10px] uppercase tracking-wide text-mist-400">
                        no user VADs
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[12px] text-mist-400">{p.ppid ?? "—"}</td>
                  <td className="px-3 py-2.5">
                    <RiskBadge risk={p.risk} />
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[12px] text-mist-300">
                    {p.score != null ? p.score.toFixed(1) : "—"}
                    {p.confidence != null && (
                      <span className="ml-1 text-mist-400">({pct(p.confidence)})</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex max-w-xs flex-wrap gap-1">
                      {p.flags.slice(0, 3).map((f) => (
                        <Chip key={f} tone="mono">
                          {f}
                        </Chip>
                      ))}
                      {p.flags.length > 3 && <Chip>+{p.flags.length - 3}</Chip>}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <button
                      className="btn-ghost text-xs disabled:opacity-30"
                      disabled={!p.analyzable}
                      onClick={() => selectProcess(p.pid)}
                    >
                      Analyze →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

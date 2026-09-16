import { useState } from "react";
import { useApp } from "../../state/store";
import { pct } from "../../lib/format";
import { Chip, Panel, RiskBadge } from "../primitives";
import { EvidenceToggle } from "../report/EvidenceToggle";
import { useReport } from "../../state/reportStore";

export function InventoryView() {
  const { processes, selectProcess, unevaluatedSources } = useApp();
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
        <h1 className="text-lg font-semibold text-ink-100">Process inventory</h1>
        <p className="mt-1 max-w-2xl text-sm text-ink-400">
          Every process the census surfaced, ranked by engine score. Pick one to run the VADViT
          deep-dive. Non-analyzable system processes (no user VADs) are marked.
        </p>
        <p className="mt-1 max-w-2xl text-[12px] text-ink-400">
          A process is flagged only when a scored finding names its PID — a process or injection
          finding. UserAssist and scheduled-task findings describe a program or task, not a running
          process, so they stay in the VolMemLyzer table and are not flags here.
        </p>
        {unevaluatedSources.length > 0 && (
          <p className="mt-1 max-w-2xl text-[12px] text-risk-medium">
            Not evaluated: {unevaluatedSources.join(", ")}. Rules reading{" "}
            {unevaluatedSources.length === 1 ? "this plugin" : "these plugins"} had no evidence to
            read and could not fire for any process — that is not the same as those checks passing.
          </p>
        )}
      </header>

      <Panel
        eyebrow="Census"
        title={`${processes.length} processes`}
        className="overflow-hidden"
        right={
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
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
              className="w-40 rounded-md border border-surface-600 bg-surface-900 px-2 py-1 text-xs text-ink-200 placeholder:text-ink-400 focus:border-accent/50 focus:outline-none"
            />
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-surface-700/60 text-left text-[11px] uppercase tracking-wider text-ink-400">
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
                <tr key={p.pid} className="border-b border-surface-800/70 hover:bg-surface-800/40">
                  <td className="px-4 py-2.5 font-mono text-ink-200">{p.pid}</td>
                  <td className="px-3 py-2.5 text-ink-100">
                    {p.name}
                    {!p.analyzable && (
                      <span className="ml-2 text-[10px] uppercase tracking-wide text-ink-400">
                        no user VADs
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[12px] text-ink-400">{p.ppid ?? "—"}</td>
                  <td className="px-3 py-2.5">
                    {p.risk ? <RiskBadge risk={p.risk} /> : <span className="text-ink-400">—</span>}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[12px] text-ink-300">
                    {p.score != null ? p.score.toFixed(1) : "n/a"}
                    {p.confidence != null && (
                      <span className="ml-1 text-ink-400">({pct(p.confidence)})</span>
                    )}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex max-w-xs flex-wrap gap-1">
                      {p.flags.length > 0 ? (
                        <>
                          {p.flags.slice(0, 3).map((f) => (
                            <Chip key={f} tone="mono">
                              {f}
                            </Chip>
                          ))}
                          {p.flags.length > 3 && <Chip>+{p.flags.length - 3}</Chip>}
                        </>
                      ) : (
                        <span className="text-[11px] text-ink-400">
                          {p.evaluation === "not_evaluated"
                            ? "not evaluated"
                            : "no indicator fired"}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <div className="flex items-center justify-end gap-1">
                      <ProcessPin pid={p.pid} />
                      <button
                        className="btn-ghost text-xs disabled:opacity-30"
                        disabled={!p.analyzable}
                        onClick={() => selectProcess(p.pid)}
                      >
                        Analyze
                      </button>
                    </div>
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


/**
 * Pin a process to the report from the inventory.
 *
 * Only processes the scoring engine actually surfaced can be pinned: the
 * report's identity for a finding comes from the assembled document, and a
 * process with no scored object has no finding to attach a note to.
 */
function ProcessPin({ pid }: { pid: number }) {
  const { refForProcess } = useReport();
  const found = refForProcess(pid);
  if (!found) return null;
  return <EvidenceToggle evidenceRef={found.ref} label={found.label} pid={pid} compact />;
}

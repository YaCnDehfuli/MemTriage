import { useApp } from "../../state/store";
import { RISK_ORDER } from "../../lib/format";
import { EmptyState, Panel, RiskBadge } from "../primitives";

export function ReportView() {
  const { scored, riskSummary, attack, analysis, triage, investigationId, demo } = useApp();

  if (!triage) return <EmptyState title="Nothing to report yet" hint="Run triage first." />;

  const top = scored.slice(0, 6);
  const exportHref =
    demo || !investigationId ? undefined : `/api/investigations/${investigationId}/export`;

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <div className="eyebrow">Report</div>
          <h1 className="text-lg font-semibold text-mist-100">Investigation summary</h1>
          <p className="mt-1 text-sm text-mist-400">
            Consolidated findings — triage posture, aligned techniques, and the VADViT verdict.
          </p>
        </div>
        {exportHref ? (
          <a className="btn-accent text-xs" href={exportHref} target="_blank" rel="noreferrer">
            Export JSON ↓
          </a>
        ) : (
          <span className="btn-ghost cursor-default text-xs opacity-60">Export (live only)</span>
        )}
      </header>

      <div className="grid gap-5 sm:grid-cols-3">
        {RISK_ORDER.map((r) => (
          <Panel key={r}>
            <div className="flex items-center justify-between px-4 py-3">
              <RiskBadge risk={r} />
              <span className="font-mono text-2xl font-semibold text-mist-100">
                {riskSummary?.by_risk[r] ?? 0}
              </span>
            </div>
          </Panel>
        ))}
        <Panel>
          <div className="flex items-center justify-between px-4 py-3">
            <span className="text-[11px] uppercase tracking-wide text-mist-400">Techniques</span>
            <span className="font-mono text-2xl font-semibold text-accent">{attack.length}</span>
          </div>
        </Panel>
      </div>

      <Panel eyebrow="Findings" title="Top indicators">
        <ul className="divide-y divide-ink-800/70">
          {top.map((o) => (
            <li key={o.key} className="flex items-center gap-3 px-4 py-2.5">
              <RiskBadge risk={o.risk} />
              <span className="font-mono text-[13px] text-mist-100">{o.label}</span>
              <span className="ml-auto flex flex-wrap gap-1">
                {o.techniques.map((t) => (
                  <span
                    key={t}
                    className="rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-mist-400 ring-1 ring-inset ring-ink-600"
                  >
                    {t}
                  </span>
                ))}
              </span>
            </li>
          ))}
        </ul>
      </Panel>

      {analysis && (
        <Panel eyebrow="VADViT verdict" title={`${analysis.process_name} (PID ${analysis.pid})`}>
          <div className="flex flex-wrap items-center gap-4 px-4 py-3 text-sm">
            <span className="text-mist-300">
              Family:{" "}
              <b className="text-mist-100">{analysis.verdict.family ?? "— not loaded —"}</b>
            </span>
            {analysis.verdict.placeholder && (
              <span className="rounded bg-risk-medium/10 px-2 py-0.5 text-[11px] text-risk-medium ring-1 ring-inset ring-risk-medium/30">
                placeholder model
              </span>
            )}
            <span className="ml-auto text-[11px] text-mist-400">
              {analysis.explainability.attributions.length} attention attributions
            </span>
          </div>
        </Panel>
      )}
    </div>
  );
}

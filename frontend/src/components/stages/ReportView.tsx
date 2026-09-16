import { useApp } from "../../state/store";
import { ExtractionNotice } from "../triage/ExtractionNotice";
import { bytes, RISK_ORDER } from "../../lib/format";
import { EmptyState, Panel, RiskBadge } from "../primitives";

export function ReportView() {
  const {
    scored, riskSummary, attack, analysis, triage, investigationId,
    profile, disclaimer, triageProgress, pluginRun,
  } = useApp();

  if (!triage) return <EmptyState title="Nothing to report yet" hint="Run triage first." />;

  const top = scored.slice(0, 6);
  const exportHref =
    !investigationId ? undefined : `/api/investigations/${investigationId}/export`;
  const requestedPlugins = triageProgress?.requested_plugins ?? pluginRun?.requested_plugins ?? [];

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <div className="eyebrow">Report</div>
          <h1 className="text-lg font-semibold text-ink-100">Investigation summary</h1>
          <p className="mt-1 text-sm text-ink-400">
            Investigation record — acquisition, method, scored evidence, and interpretation
            boundaries.
          </p>
        </div>
        {exportHref ? (
          <a className="btn-accent text-xs" href={exportHref} target="_blank" rel="noreferrer">
            Export JSON
          </a>
        ) : (
          <span className="btn-ghost cursor-default text-xs opacity-60">Export (live only)</span>
        )}
      </header>

      <ExtractionNotice health={triage?.dashboard?.extraction} />

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel eyebrow="Provenance" title="Acquisition">
          <table className="w-full text-[12px]">
            <thead>
              <tr className="border-b border-surface-700/60 text-left text-[10px] uppercase tracking-wider text-ink-400">
                <th className="px-4 py-1.5">#</th>
                <th className="px-3 py-1.5">Filename</th>
                <th className="px-3 py-1.5">Size</th>
                <th className="px-3 py-1.5">SHA-256</th>
              </tr>
            </thead>
            <tbody>
              {triage.dumps.map((d) => (
                <tr key={d.ordinal} className="border-b border-surface-800/60 last:border-0">
                  <td className="px-4 py-1.5 font-mono text-ink-300">{d.ordinal}</td>
                  <td className="px-3 py-1.5 text-ink-100">{d.filename}</td>
                  <td className="px-3 py-1.5 font-mono text-ink-300">{bytes(d.size_bytes)}</td>
                  <td
                    className="max-w-[1px] truncate px-3 py-1.5 font-mono text-ink-400"
                    title={d.sha256}
                  >
                    {d.sha256}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {triage.vol_version && (
            <p className="border-t border-surface-800/60 px-4 py-2 text-[11px] text-ink-400">
              Volatility {triage.vol_version}
            </p>
          )}
        </Panel>

        <Panel eyebrow="Method" title="Scoring profile & coverage">
          <dl className="space-y-1.5 px-4 py-3 text-[12px]">
            <MethodRow k="Sensitivity preset" v={profile?.preset ?? "—"} />
            <MethodRow
              k="Confidence floor"
              v={profile ? `${(profile.confidence_floor * 100).toFixed(0)}%` : "—"}
            />
            <MethodRow
              k="Correlation required"
              v={profile?.require_correlation ? "yes" : "no"}
            />
            <MethodRow
              k="Triage coverage"
              v={triageProgress?.triage_mode ? `${triageProgress.triage_mode} (${requestedPlugins.length} plugins)` : `${requestedPlugins.length} plugin(s)`}
            />
            <MethodRow
              k="Model checkpoint"
              v={
                !analysis
                  ? "not analyzed yet"
                  : !analysis.verdict.model_loaded
                    ? "not loaded"
                    : analysis.verdict.placeholder
                      ? "placeholder (untrained)"
                      : "trained"
              }
            />
          </dl>
        </Panel>
      </div>

      <div className="grid gap-5 sm:grid-cols-3">
        {RISK_ORDER.map((r) => (
          <Panel key={r}>
            <div className="flex items-center justify-between px-4 py-3">
              <RiskBadge risk={r} />
              <span className="font-mono text-2xl font-semibold text-ink-100">
                {riskSummary?.by_risk[r] ?? 0}
              </span>
            </div>
          </Panel>
        ))}
        <Panel>
          <div className="flex items-center justify-between px-4 py-3">
            <span className="text-[11px] uppercase tracking-wide text-ink-400">Techniques</span>
            <span className="font-mono text-2xl font-semibold text-accent-soft">{attack.length}</span>
          </div>
        </Panel>
      </div>

      <Panel eyebrow="Findings" title="Top indicators">
        <ul className="divide-y divide-surface-800/70">
          {top.map((o) => (
            <li key={o.key} className="flex items-center gap-3 px-4 py-2.5">
              <RiskBadge risk={o.risk} />
              <span className="font-mono text-[13px] text-ink-100">{o.label}</span>
              <span className="ml-auto flex flex-wrap gap-1">
                {o.techniques.map((t) => (
                  <span
                    key={t}
                    className="rounded bg-surface-800 px-1.5 py-0.5 font-mono text-[11px] text-ink-400 ring-1 ring-inset ring-surface-600"
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
        <Panel eyebrow="Model classification" title={`${analysis.process_name} (PID ${analysis.pid})`}>
          <div className="flex flex-wrap items-center gap-4 px-4 py-3 text-sm">
            <span className="text-ink-300">
              Family:{" "}
              <b className="text-ink-100">{analysis.verdict.family ?? "— not loaded —"}</b>
            </span>
            {analysis.verdict.placeholder && (
              <span className="rounded bg-risk-medium/10 px-2 py-0.5 text-[11px] text-risk-medium ring-1 ring-inset ring-risk-medium/30">
                placeholder model
              </span>
            )}
            <span className="ml-auto text-[11px] text-ink-400">
              {analysis.explainability.attributions.length} attention attributions
            </span>
          </div>
        </Panel>
      )}

      {disclaimer && (
        <Panel eyebrow="Interpretation boundaries" title={disclaimer.headline}>
          <div className="space-y-3 px-4 py-4">
            <p className="text-[13px] text-ink-300">{disclaimer.summary}</p>
            {disclaimer.points.length > 0 && (
              <ul className="space-y-1.5 text-[12px] text-ink-300">
                {disclaimer.points.map((point) => (
                  <li key={point} className="flex gap-2">
                    <span aria-hidden className="mt-0.5 text-ink-400">·</span>
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>
      )}
    </div>
  );
}

function MethodRow({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-surface-800/60 py-1 last:border-0">
      <dt className="text-ink-400">{k}</dt>
      <dd className="font-mono text-ink-200">{v}</dd>
    </div>
  );
}

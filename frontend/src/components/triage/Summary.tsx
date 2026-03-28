import type { AttackTechnique, RiskSummary } from "../../types";
import { RISK_ORDER } from "../../lib/format";
import { Panel } from "../primitives";

export function RiskSummaryPanel({ summary }: { summary: RiskSummary | null }) {
  const by = summary?.by_risk ?? {};
  const total = summary?.total ?? 0;
  return (
    <Panel eyebrow="Posture" title="Risk summary">
      <div className="grid grid-cols-4 gap-px overflow-hidden rounded-b-lg bg-ink-700/40">
        {RISK_ORDER.map((r) => (
          <div key={r} className="bg-ink-850 px-3 py-4 text-center">
            <div
              className={`font-mono text-2xl font-semibold ${
                {
                  Critical: "text-risk-critical",
                  High: "text-risk-high",
                  Medium: "text-risk-medium",
                  Low: "text-risk-low",
                }[r]
              }`}
            >
              {by[r] ?? 0}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-mist-400">{r}</div>
          </div>
        ))}
      </div>
      <div className="px-4 py-2 text-center text-[11px] text-mist-400">
        {total} indicator{total === 1 ? "" : "s"} surfaced across processes, connections & persistence
      </div>
    </Panel>
  );
}

export function AttackPanel({ techniques }: { techniques: AttackTechnique[] }) {
  return (
    <Panel eyebrow="Framework alignment" title="MITRE ATT&CK">
      {techniques.length === 0 ? (
        <div className="px-4 py-6 text-center text-xs text-mist-400">No techniques aligned.</div>
      ) : (
        <ul className="divide-y divide-ink-800/70">
          {techniques.map((t) => (
            <li key={t.technique_id} className="flex items-start gap-3 px-4 py-2.5">
              <span className="mt-0.5 rounded bg-ink-800 px-1.5 py-0.5 font-mono text-[11px] text-accent ring-1 ring-inset ring-ink-600">
                {t.technique_id}
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[13px] font-medium text-mist-100">{t.name}</div>
                <div className="text-[11px] text-mist-400">{t.tactic}</div>
              </div>
              <span className="shrink-0 font-mono text-[11px] text-mist-400">
                {t.object_count}×
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="border-t border-ink-800/70 px-4 py-2 text-[10px] text-mist-400">
        Alignment for triage, not confirmed detection.
      </p>
    </Panel>
  );
}

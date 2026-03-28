import { useApp } from "../../state/store";
import { Panel } from "../primitives";
import { IoCTable } from "../triage/IoCTable";
import { AttackPanel, RiskSummaryPanel } from "../triage/Summary";
import { TuningBar } from "../triage/TuningBar";

export function TriageView() {
  const { scored, profile, riskSummary, attack, diff, rescore, selectProcess, loading } = useApp();

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <div className="eyebrow">Phase 1 · VolMemLyzer</div>
          <h1 className="text-lg font-semibold text-mist-100">Triage overview</h1>
          <p className="mt-1 max-w-2xl text-sm text-mist-400">
            An explainable, correlation-aware engine scores the extracted artifacts. Move the
            sensitivity controls and the table re-scores from cache in milliseconds — expand any
            row to see exactly which rules fired and why.
          </p>
        </div>
      </header>

      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <Panel
          eyebrow="Indicators of compromise"
          title="Scored objects"
          className="overflow-hidden"
          right={
            loading ? <span className="text-[11px] text-mist-400">scoring…</span> : undefined
          }
        >
          <TuningBar profile={profile} onChange={rescore} />
          <IoCTable objects={scored} diff={diff} onInspectProcess={selectProcess} />
        </Panel>

        <div className="space-y-5">
          <RiskSummaryPanel summary={riskSummary} />
          <AttackPanel techniques={attack} />
        </div>
      </div>
    </div>
  );
}

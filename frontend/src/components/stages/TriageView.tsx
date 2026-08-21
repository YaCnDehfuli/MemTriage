import { useApp } from "../../state/store";
import { EmptyState, Panel } from "../primitives";
import { ExtractionNotice } from "../triage/ExtractionNotice";
import { FeatureExplorer } from "../triage/FeatureExplorer";
import { IoCTable } from "../triage/IoCTable";
import { AttackPanel, RiskSummaryPanel } from "../triage/Summary";
import { TuningBar } from "../triage/TuningBar";
import { VolatilityWorkbench } from "../triage/VolatilityWorkbench";

export function TriageView() {
  const { scored, profile, riskSummary, attack, diff, rescore, selectProcess,
    loading, triage, triageProgress } = useApp();

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <div className="eyebrow">Phase 1 · VolMemLyzer</div>
          <h1 className="text-lg font-semibold text-mist-100">VolMemLyzer workbench</h1>
          <p className="mt-1 max-w-2xl text-sm text-mist-400">
            Control automated triage coverage, run the manual Volatility suite, follow every
            plugin live, and inspect the resulting artifacts and extracted features in one place.
          </p>
        </div>
      </header>

      <VolatilityWorkbench />

      {triage ? (
        <>
          <ExtractionNotice health={triage.dashboard?.extraction} />

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

          <FeatureExplorer features={triage.dashboard?.features ?? {}} />
        </>
      ) : (
        <Panel eyebrow="Triage results" title="Indicators and extracted features">
          <EmptyState
            title={triageProgress?.status === "failed" ? "Triage did not complete" : "No triage results yet"}
            hint="Configure and start triage above. Results appear here without leaving this page."
          />
        </Panel>
      )}
    </div>
  );
}

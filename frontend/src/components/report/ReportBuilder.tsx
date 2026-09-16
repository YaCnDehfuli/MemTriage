import { useState } from "react";

import { useRovingTabs } from "../../lib/a11y";
import { useReport } from "../../state/reportStore";
import { EmptyState, Panel, RiskBadge } from "../primitives";
import { DraftNarrativePanel } from "./DraftNarrativePanel";
import { EvidenceToggle } from "./EvidenceToggle";
import { FindingCard } from "./FindingCard";
import { NarrativePanel } from "./NarrativePanel";
import { ReportPreview } from "./ReportPreview";

const TABS = ["evidence", "narrative", "preview"] as const;
type Tab = (typeof TABS)[number];

const TAB_LABEL: Record<Tab, string> = {
  evidence: "Evidence & findings",
  narrative: "Narrative",
  preview: "Preview & export",
};

/**
 * The analyst's workspace over a report that already exists.
 *
 * Nothing here has to be assembled from nothing: the document is complete
 * before the analyst touches it, and this is where they correct it — excluding
 * noise, separating collection artifacts from adversary activity, and adding
 * the judgement the rule engine cannot supply.
 */
export function ReportBuilder() {
  const { doc, evidenceByRef, loading, error, saving, refresh, setNote } = useReport();
  const [tab, setTab] = useState<Tab>("evidence");

  // Only pinned evidence is annotated here. The Report page is for adding
  // judgement to a chosen subset, not for re-reading the whole triage table —
  // that table already exists one page back, and duplicating it here made this
  // page a restatement of the previous ones.
  const pinnedStages = (doc?.stages ?? [])
    .map((stage) => ({
      ...stage,
      findings: stage.findings.filter((f) => evidenceByRef.has(f.ref)),
    }))
    .filter((stage) => stage.findings.length > 0);
  const pinnedArtifacts = (doc?.examiner_artifacts ?? []).filter((f) =>
    evidenceByRef.has(f.ref),
  );
  const pinnedRegions = (doc?.exhibits ?? []).filter((e) => evidenceByRef.has(e.ref));
  const pinnedCount =
    pinnedStages.reduce((n, s) => n + s.findings.length, 0) +
    pinnedArtifacts.length +
    pinnedRegions.length;
  const { getTabProps, tabListProps, getPanelProps } = useRovingTabs(
    TABS,
    tab,
    setTab,
    "report-builder",
  );

  if (loading && !doc) {
    return <EmptyState title="Assembling the report…" />;
  }
  if (!doc) {
    return (
      <EmptyState
        title="No report yet"
        hint={error ?? "Run triage first; the report is built from its output."}
      />
    );
  }

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded border border-risk-high/40 bg-risk-high/10 px-3 py-2 text-[12px] text-risk-high">
          {error}{" "}
          <button type="button" className="underline" onClick={() => void refresh()}>
            Reload
          </button>
        </div>
      )}

      <div className="flex items-center gap-3">
        <div {...tabListProps} className="flex gap-1">
          {TABS.map((id) => (
            <button
              key={id}
              {...getTabProps(id)}
              type="button"
              className={`rounded px-3 py-1.5 text-[12px] ${
                tab === id
                  ? "bg-surface-800 text-ink-100"
                  : "text-ink-400 hover:text-ink-200"
              }`}
            >
              {TAB_LABEL[id]}
            </button>
          ))}
        </div>
        <span className="ml-auto text-[11px] text-ink-400">
          {saving > 0 ? "Saving…" : "Saved"}
        </span>
      </div>

      <div {...getPanelProps("evidence")} hidden={tab !== "evidence"}>
        <div className="space-y-4">
          <p className="text-[12px] text-ink-400">{doc.progression}</p>
          {pinnedCount === 0 ? (
            <EmptyState
              title="Nothing pinned yet"
              hint="Add evidence from the pages that show it — the scored table in VolMemLyzer, the process inventory, or a region in the VADViT deep-dive. Pinned evidence is what the report's narrative is built around; the full scored set still appears in the document on its own."
            />
          ) : null}

          {pinnedStages.map((stage) => (
            <Panel
              key={stage.tactic}
              eyebrow={`${stage.findings.length} pinned`}
              title={stage.tactic}
              right={stage.highest_risk ? <RiskBadge risk={stage.highest_risk as never} /> : null}
            >
              <div className="space-y-3 px-4 py-3">
                <p className="text-[11px] text-ink-400">{stage.blurb}</p>
                {stage.findings.map((f) => (
                  <FindingCard key={f.ref} finding={f} />
                ))}
              </div>
            </Panel>
          ))}
          {pinnedRegions.length > 0 && (
            <Panel eyebrow="Pinned from the VADViT deep-dive" title="Memory regions">
              <div className="space-y-3 px-4 py-3">
                {pinnedRegions.map((region) => {
                  const label = `${region.addr} · ${region.protection}`;
                  return (
                    <div
                      key={region.ref}
                      className="rounded border border-surface-700 bg-surface-900 p-3"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-[13px] font-medium text-ink-100">
                          {region.addr}
                        </span>
                        <span className="font-mono text-[11px] text-ink-400">
                          {region.process_name} · PID {region.pid}
                        </span>
                        <span className="ml-auto">
                          <EvidenceToggle
                            evidenceKind="region"
                            evidenceRef={region.ref}
                            label={label}
                            pid={region.pid}
                          />
                        </span>
                      </div>
                      <p className="mt-1.5 text-[12px] text-ink-300">{region.headline}</p>
                      <textarea
                        className="mt-2 w-full rounded border border-surface-600 bg-surface-950 px-2 py-1.5 text-[12px] text-ink-200 placeholder:text-ink-400"
                        rows={2}
                        placeholder="What this region shows — the instructions, strings or entropy that make it evidence."
                        value={evidenceByRef.get(region.ref)?.analyst_note ?? ""}
                        onChange={(e) => setNote(region.ref, label, e.target.value)}
                      />
                    </div>
                  );
                })}
              </div>
            </Panel>
          )}
          {pinnedArtifacts.length > 0 && (
            <Panel
              eyebrow="Attributed to collection"
              title="Collection artifacts"
            >
              <div className="space-y-3 px-4 py-3">
                <p className="text-[11px] text-ink-400">
                  Real, correctly-scored findings caused by the acquisition process
                  itself. They stay in the report, told apart from adversary activity.
                </p>
                {pinnedArtifacts.map((f) => (
                  <FindingCard key={f.ref} finding={f} />
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>

      <div {...getPanelProps("narrative")} hidden={tab !== "narrative"}>
        <div className="mb-4">
          <DraftNarrativePanel />
        </div>
        <NarrativePanel />
      </div>

      <div {...getPanelProps("preview")} hidden={tab !== "preview"}>
        {tab === "preview" && <ReportPreview />}
      </div>
    </div>
  );
}

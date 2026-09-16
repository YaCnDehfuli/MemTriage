import { useMemo, useState } from "react";
import type { LowLevelReport, RegionRecord } from "../../types";
import { useRovingTabs } from "../../lib/a11y";
import { Chip, EmptyState, Panel } from "../primitives";
import { Disassembly } from "./Disassembly";
import { CallGraph, ControlFlowGraph } from "./GraphView";
import { HexDump, Patterns, Strings, Structure } from "./RegionPanels";
import { RegionList } from "./RegionList";
import { EvidenceToggle } from "../report/EvidenceToggle";
import { regionRef } from "../../lib/evidenceRef";

const TABS = ["disasm", "cfg", "calls", "patterns", "strings", "structure", "hex"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = {
  disasm: "Disassembly",
  cfg: "Control flow",
  calls: "Call graph",
  patterns: "Patterns",
  strings: "Strings",
  structure: "Structure",
  hex: "Hex",
};

/**
 * Phase 2, second half. The model ranked the regions; this shows what is in the
 * ones it ranked highest, in the forms a reverse engineer would ask for.
 */
export function RegionDeepDive({
  regions,
  lowlevel,
  pid,
}: {
  regions: RegionRecord[];
  lowlevel: LowLevelReport | null;
  /** Needed to identify a region: patch_index is only unique within one manifest. */
  pid: number;
}) {
  const analyses = lowlevel?.regions ?? [];
  const analyzed = useMemo(
    () => new Set(analyses.map((a) => a.region.patch_index)),
    [analyses],
  );
  const [selected, setSelected] = useState<number | null>(
    analyses[0]?.region.patch_index ?? null,
  );
  const [tab, setTab] = useState<Tab>("disasm");
  const { getTabProps, tabListProps, getPanelProps } = useRovingTabs(
    TABS,
    tab,
    setTab,
    "region-deepdive",
  );

  const current = analyses.find((a) => a.region.patch_index === selected) ?? analyses[0];

  if (!regions.length && !analyses.length) {
    return (
      <Panel eyebrow="Phase 2 · Region analysis" title="Highest-attention regions">
        <EmptyState
          title="No region analysis for this process"
          hint="Regions are ranked once the model produces an attention map. Re-run the analysis if this process was analyzed before region analysis was added."
        />
      </Panel>
    );
  }

  return (
    <Panel
      eyebrow="Phase 2 · Region analysis"
      title="Attention-ranked VAD regions"
      right={
        <div className="flex items-center gap-2">
          {lowlevel && (
            <span className="font-mono text-[11px] text-ink-400">
              {lowlevel.ranked_regions} ranked · {analyses.length} analyzed
            </span>
          )}
          {current && (
            <EvidenceToggle
              evidenceKind="region"
              evidenceRef={regionRef(pid, current.region.sha256)}
              label={`${current.region.addr} · ${current.region.protection}`}
              pid={pid}
            />
          )}
        </div>
      }
    >
      <div className="grid gap-0 lg:grid-cols-[260px_1fr_280px]">
        <div className="max-h-[720px] overflow-y-auto border-b border-surface-800/70 lg:border-b-0 lg:border-r">
          <RegionList
            regions={regions}
            analyzed={analyzed}
            selected={current?.region.patch_index ?? null}
            onSelect={(patchIndex) => setSelected(patchIndex)}
          />
        </div>

        {!current ? (
          <div className="lg:col-span-2">
            <EmptyState
              title="Nothing analyzed yet"
              hint="The highest-ranked regions are analyzed down to the instruction level once attention is available."
            />
          </div>
        ) : (
          <>
            <div className="min-w-0 border-b border-surface-800/70 p-4 lg:border-b-0 lg:border-r">
              <div
                {...tabListProps}
                aria-label="Region representation"
                className="flex flex-wrap gap-1"
              >
                {TABS.map((id) => (
                  <button
                    key={id}
                    type="button"
                    {...getTabProps(id)}
                    className={`rounded-md px-2.5 py-1 text-[12px] transition-colors ${
                      tab === id
                        ? "bg-accent/15 text-accent-soft ring-1 ring-inset ring-accent/30"
                        : "text-ink-300 hover:bg-surface-800"
                    }`}
                  >
                    {TAB_LABEL[id]}
                  </button>
                ))}
              </div>

              <div className="mt-3">
                {TABS.map((id) => (
                  <div key={id} {...getPanelProps(id)} hidden={tab !== id}>
                    {tab === id && (
                      <>
                        {id === "disasm" && <Disassembly analysis={current} />}
                        {id === "cfg" && <ControlFlowGraph analysis={current} />}
                        {id === "calls" && <CallGraph analysis={current} />}
                        {id === "patterns" && <Patterns analysis={current} />}
                        {id === "strings" && <Strings analysis={current} />}
                        {id === "structure" && <Structure analysis={current} />}
                        {id === "hex" && <HexDump analysis={current} />}
                      </>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="p-4">
              <Inspector analysis={current} />
            </div>
          </>
        )}
      </div>
    </Panel>
  );
}

/** Facts that hold regardless of which representation tab is open — kept
 * visible instead of buried inside its own "Overview" tab. */
function Inspector({ analysis }: { analysis: LowLevelReport["regions"][number] }) {
  const s = analysis.summary;
  const r = analysis.region;
  return (
    <div className="space-y-4">
      <div>
        <div className="eyebrow mb-1.5">This region</div>
        <div className="font-mono text-[12px] leading-relaxed text-ink-100">
          {s.headline}
        </div>
        <p className="mt-1 text-[11px] text-ink-400">{s.caveat}</p>
      </div>

      <dl className="space-y-1">
        <Row k="Instructions" v={s.instruction_count.toLocaleString()} />
        <Row k="Blocks" v={String(s.block_count)} />
        <Row k="Functions" v={String(s.function_count)} />
        <Row k="Indirect calls" v={String(s.indirect_calls)} />
        <Row k="Indicators" v={String(s.pattern_count)} />
      </dl>

      <dl className="space-y-1 border-t border-surface-800/60 pt-3">
        <Row k="Address range" v={`${r.addr} – ${r.end_addr ?? "?"}`} />
        <Row k="Protection" v={r.protection || "unknown"} />
        <Row k="VAD tag" v={r.tag || "—"} />
        <Row k="Backing file" v={r.file_backing || "private memory"} />
        <Row k="Snapshot" v={r.snapshot_ordinal === null ? "—" : `#${r.snapshot_ordinal}`} />
        <Row
          k="SHA-256"
          v={r.sha256 ? `${r.sha256.slice(0, 32)}…` : "—"}
          full={r.sha256 || undefined}
        />
      </dl>

      {s.techniques.length > 0 && (
        <div className="border-t border-surface-800/60 pt-3">
          <div className="eyebrow mb-1.5">ATT&CK techniques touched</div>
          <div className="flex flex-wrap gap-1.5">
            {s.techniques.map((t) => <Chip key={t} tone="mono">{t}</Chip>)}
          </div>
          <p className="mt-1.5 text-[11px] text-ink-400">
            Alignment for triage, not confirmed detection.
          </p>
        </div>
      )}
    </div>
  );
}

function Row({ k, v, full }: { k: string; v: string; full?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-surface-800/60 py-1">
      <dt className="text-[12px] text-ink-400">{k}</dt>
      <dd className="truncate font-mono text-[12px] text-ink-200" title={full ?? v}>
        {v}
      </dd>
    </div>
  );
}

import { useMemo, useState } from "react";
import type { LowLevelReport, RegionRecord } from "../../types";
import { Chip, EmptyState, Panel } from "../primitives";
import { Disassembly } from "./Disassembly";
import { CallGraph, ControlFlowGraph } from "./GraphView";
import { HexDump, Patterns, Strings, Structure } from "./RegionPanels";
import { RegionList } from "./RegionList";

const TABS = [
  ["overview", "Overview"],
  ["disasm", "Disassembly"],
  ["cfg", "Control flow"],
  ["calls", "Call graph"],
  ["patterns", "Patterns"],
  ["strings", "Strings"],
  ["structure", "Structure"],
  ["hex", "Hex"],
] as const;

type Tab = (typeof TABS)[number][0];

/**
 * Phase 2, second half. The model ranked the regions; this shows what is in the
 * ones it ranked highest, in the forms a reverse engineer would ask for.
 */
export function RegionDeepDive({
  regions,
  lowlevel,
}: {
  regions: RegionRecord[];
  lowlevel: LowLevelReport | null;
}) {
  const analyses = lowlevel?.regions ?? [];
  const analyzed = useMemo(
    () => new Set(analyses.map((a) => a.region.patch_index)),
    [analyses],
  );
  const [selected, setSelected] = useState<number | null>(
    analyses[0]?.region.patch_index ?? null,
  );
  const [tab, setTab] = useState<Tab>("overview");

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
      title="What the model was looking at"
      right={
        lowlevel ? (
          <span className="font-mono text-[11px] text-mist-400">
            {lowlevel.ranked_regions} ranked · {analyses.length} analyzed
          </span>
        ) : undefined
      }
    >
      <div className="grid gap-0 lg:grid-cols-[280px_1fr]">
        <div className="max-h-[720px] overflow-y-auto border-b border-ink-800/70 lg:border-b-0 lg:border-r">
          <RegionList
            regions={regions}
            analyzed={analyzed}
            selected={current?.region.patch_index ?? null}
            onSelect={(patchIndex) => {
              setSelected(patchIndex);
              setTab("overview");
            }}
          />
        </div>

        <div className="min-w-0 p-4">
          {!current ? (
            <EmptyState
              title="Nothing analyzed yet"
              hint="The highest-ranked regions are analyzed down to the instruction level once attention is available."
            />
          ) : (
            <div className="space-y-4">
              <div>
                <div className="font-mono text-[12px] text-mist-100">
                  {current.summary.headline}
                </div>
                <p className="mt-1 text-[12px] text-mist-400">{current.summary.caveat}</p>
              </div>

              <div className="flex flex-wrap gap-1">
                {TABS.map(([id, label]) => (
                  <button
                    key={id}
                    onClick={() => setTab(id)}
                    className={`rounded-md px-2.5 py-1 text-[12px] transition-colors ${
                      tab === id
                        ? "bg-accent/15 text-accent ring-1 ring-inset ring-accent/30"
                        : "text-mist-300 hover:bg-ink-800"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {tab === "overview" && <Overview analysis={current} />}
              {tab === "disasm" && <Disassembly analysis={current} />}
              {tab === "cfg" && <ControlFlowGraph analysis={current} />}
              {tab === "calls" && <CallGraph analysis={current} />}
              {tab === "patterns" && <Patterns analysis={current} />}
              {tab === "strings" && <Strings analysis={current} />}
              {tab === "structure" && <Structure analysis={current} />}
              {tab === "hex" && <HexDump analysis={current} />}
            </div>
          )}
        </div>
      </div>
    </Panel>
  );
}

function Overview({ analysis }: { analysis: LowLevelReport["regions"][number] }) {
  const s = analysis.summary;
  const r = analysis.region;
  return (
    <div className="space-y-4">
      <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-5">
        <Fact label="Instructions" value={String(s.instruction_count)} />
        <Fact label="Basic blocks" value={String(s.block_count)} />
        <Fact label="Functions" value={String(s.function_count)} />
        <Fact label="Indirect calls" value={String(s.indirect_calls)} />
        <Fact label="Indicators" value={String(s.pattern_count)} />
      </div>

      <dl className="grid gap-x-6 gap-y-1.5 sm:grid-cols-2">
        <Row k="Address range" v={`${r.addr} – ${r.end_addr ?? "?"}`} />
        <Row k="Protection" v={r.protection || "unknown"} />
        <Row k="VAD tag" v={r.tag || "—"} />
        <Row k="Backing file" v={r.file_backing || "private memory"} />
        <Row k="Snapshot" v={r.snapshot_ordinal === null ? "—" : `#${r.snapshot_ordinal}`} />
        <Row k="SHA-256" v={r.sha256 ? `${r.sha256.slice(0, 32)}…` : "—"} />
      </dl>

      {s.techniques.length > 0 && (
        <div>
          <div className="eyebrow mb-1.5">ATT&CK techniques touched</div>
          <div className="flex flex-wrap gap-1.5">
            {s.techniques.map((t) => <Chip key={t} tone="mono">{t}</Chip>)}
          </div>
          <p className="mt-1.5 text-[11px] text-mist-400">
            Alignment for triage, not confirmed detection.
          </p>
        </div>
      )}
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-ink-700/60 px-3 py-2">
      <div className="eyebrow">{label}</div>
      <div className="mt-0.5 font-mono text-[15px] text-mist-100">{value}</div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-ink-800/60 py-1">
      <dt className="text-[12px] text-mist-400">{k}</dt>
      <dd className="truncate font-mono text-[12px] text-mist-200">{v}</dd>
    </div>
  );
}

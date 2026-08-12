import type { RegionRecord } from "../../types";
import { bytes, pct } from "../../lib/format";
import { Chip, Meter } from "../primitives";

const FLAG_TONE: Record<string, string> = {
  rwx: "text-risk-critical ring-risk-critical/30",
  "private-executable": "text-risk-high ring-risk-high/30",
  "mz-header": "text-risk-medium ring-risk-medium/30",
  "high-entropy": "text-risk-medium ring-risk-medium/30",
};

/** Every rendered VAD region, in the order the model's attention ranked them. */
export function RegionList({
  regions,
  analyzed,
  selected,
  onSelect,
}: {
  regions: RegionRecord[];
  analyzed: Set<number>;
  selected: number | null;
  onSelect(patchIndex: number): void;
}) {
  if (!regions.length) {
    return (
      <div className="px-4 py-8 text-center text-[13px] text-mist-400">
        No regions were rendered for this process.
      </div>
    );
  }
  return (
    <ul className="divide-y divide-ink-800/70">
      {regions.map((r) => {
        const isSelected = r.patch_index === selected;
        const hasAnalysis = analyzed.has(r.patch_index);
        return (
          <li key={r.patch_index}>
            <button
              onClick={() => hasAnalysis && onSelect(r.patch_index)}
              disabled={!hasAnalysis}
              title={hasAnalysis
                ? undefined
                : "Only the highest-ranked regions are analyzed down to the instruction level."}
              className={`w-full px-4 py-3 text-left transition-colors ${
                isSelected ? "bg-accent/10" : hasAnalysis ? "hover:bg-ink-800/50" : "opacity-55"
              }`}
            >
              <div className="flex items-baseline justify-between gap-3">
                <span className="font-mono text-[12px] text-mist-100">{r.addr}</span>
                <span className="shrink-0 font-mono text-[11px] text-mist-400">
                  #{r.rank} · {pct(r.attention)}
                </span>
              </div>
              <div className="mt-1.5">
                <Meter value={r.attention} tone="risk" />
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <Chip tone={r.category === "exe" ? "accent" : "default"}>{r.category}</Chip>
                <span className="font-mono text-[11px] text-mist-400">{bytes(r.size)}</span>
                <span className="font-mono text-[11px] text-mist-400">H={r.entropy.toFixed(2)}</span>
                {r.flags.map((f) => (
                  <span
                    key={f}
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] ring-1 ring-inset ${
                      FLAG_TONE[f] ?? "text-mist-400 ring-ink-600"
                    }`}
                  >
                    {f}
                  </span>
                ))}
              </div>
              <div className="mt-1 truncate font-mono text-[11px] text-mist-400">
                {r.file_backing || "private memory · no backing file"}
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

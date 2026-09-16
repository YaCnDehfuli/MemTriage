import { useApp } from "../state/store";
import type { Stage } from "../types";
import { bytes } from "../lib/format";
import { ThemeToggle } from "./ThemeToggle";

const STAGES: { id: Stage; label: string; hint: string }[] = [
  { id: "ingest", label: "Ingest", hint: "Dump snapshots" },
  { id: "triage", label: "VolMemLyzer", hint: "Triage · manual suite" },
  { id: "inventory", label: "Process inventory", hint: "Select a PID" },
  { id: "deepdive", label: "VADViT deep-dive", hint: "Grid · attention · regions" },
  { id: "report", label: "Report", hint: "Findings · export" },
];

type StageState = "not-started" | "active" | "complete" | "warning";

const STATUS_LABEL: Record<StageState, string> = {
  "not-started": "Not started",
  active: "In progress",
  complete: "Complete",
  warning: "Failed",
};

/**
 * The whole workflow, as one horizontal strip: the investigation pipeline up
 * top where it is always visible, instead of a tall sidebar competing with
 * the analysis surfaces for width. Scrolls horizontally on narrow viewports
 * rather than hiding behind a drawer.
 */
export function TopNav() {
  const {
    stage, setStage, triage, riskSummary, investigationId,
    uploads, triageProgress, selectedPid, analysis, analysisProgress,
  } = useApp();

  const statusOf = (id: Stage): StageState => {
    switch (id) {
      case "ingest":
        if (triage && triage.dumps.length > 0) return "complete";
        if (uploads.some((u) => u.status === "uploading")) return "active";
        return "not-started";
      case "triage":
        if (triageProgress?.status === "failed") return "warning";
        if (triage) return "complete";
        if (triageProgress && triageProgress.status !== "received") return "active";
        return "not-started";
      case "inventory":
        if (selectedPid != null) return "complete";
        if (triage) return "active";
        return "not-started";
      case "deepdive":
        if (analysisProgress?.status === "failed") return "warning";
        if (analysis) return "complete";
        if (analysisProgress) return "active";
        return "not-started";
      case "report":
        return triage ? "active" : "not-started";
      default:
        return "not-started";
    }
  };

  return (
    <header className="border-b border-surface-700/70 bg-surface-900/60 backdrop-blur">
      <div className="relative flex items-center">
        <nav
          className="flex min-w-0 flex-1 gap-1.5 overflow-x-auto px-4 py-3.5 lg:justify-center"
          aria-label="Investigation workflow"
        >
          {STAGES.map((s, i) => {
          const active = stage === s.id;
          const status = statusOf(s.id);
          return (
            <button
              key={s.id}
              onClick={() => setStage(s.id)}
              className={`flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2.5 text-left transition-colors ${
                active ? "bg-surface-800 ring-1 ring-inset ring-surface-600" : "hover:bg-surface-850"
              }`}
            >
              <span
                title={STATUS_LABEL[status]}
                className={`grid h-6 w-6 shrink-0 place-items-center rounded-full text-[11px] font-semibold ring-1 ring-inset ${
                  active
                    ? "bg-accent/20 text-accent-soft ring-accent/40"
                    : status === "warning"
                      ? "bg-risk-critical/15 text-risk-critical ring-risk-critical/40"
                      : status === "complete"
                        ? "bg-surface-700 text-ink-300 ring-surface-600"
                        : "bg-surface-850 text-ink-400 ring-surface-700"
                }`}
              >
                {status === "warning" && !active
                  ? "!"
                  : status === "complete" && !active
                    ? "✓"
                    : status === "active" && !active
                      ? <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-accent" />
                      : i + 1}
              </span>
              <span className="min-w-0">
                <span
                  className={`block whitespace-nowrap text-sm font-medium ${active ? "text-ink-100" : "text-ink-300"}`}
                >
                  {s.label}
                </span>
                <span className="hidden whitespace-nowrap text-[11px] text-ink-400 sm:block">
                  {status === "warning" ? "Failed — see the panel for details" : s.hint}
                </span>
              </span>
            </button>
          );
        })}
        </nav>

        <div className="flex shrink-0 items-center border-l border-surface-700/60 pl-3 pr-4">
          <ThemeToggle />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-surface-800/60 px-4 py-2 text-[11px] text-ink-400">
        <span className="flex shrink-0 items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${investigationId ? "bg-accent" : "bg-surface-600"}`}
          />
          {investigationId ? "Investigation connected" : "No investigation yet"}
        </span>
        {triage && (
          <>
            <span>{triage.dumps.length} snapshot{triage.dumps.length === 1 ? "" : "s"}</span>
            <span>{bytes(triage.dumps.reduce((a, d) => a + d.size_bytes, 0))} imaged</span>
            <span>{triage.processes.length} processes</span>
            <span>{riskSummary?.total ?? 0} leads surfaced</span>
          </>
        )}
        <span className="hidden md:ml-auto md:inline">
          Triage aid, not EDR/AV — analyst-facing, MITRE ATT&amp;CK aligned.
        </span>
      </div>
    </header>
  );
}

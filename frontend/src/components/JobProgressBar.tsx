import type { JobProgress } from "../state/store";
import { Meter } from "./primitives";

const LABELS: Record<string, string> = {
  received: "Received",
  triaging: "Hashing snapshots",
  analyzing: "Running Volatility plugins",
  inventorying: "Building the process inventory",
  triaged: "Triage complete",
  queued: "Queued",
  dumping: "Dumping VAD regions",
  consolidating: "Choosing the richest snapshot",
  rendering: "Rendering the VADViT grid",
  classifying: "Classifying",
  explaining: "Mapping attention back to regions",
  regions: "Analyzing the highest-attention regions",
  done: "Complete",
  failed: "Failed",
};

/** Live stage readout for a long-running job, fed by SSE with a polling fallback. */
export function JobProgressBar({ job }: { job: JobProgress | null }) {
  if (!job) return null;
  const failed = job.status === "failed";
  const label = LABELS[job.stage] ?? job.stage;
  return (
    <div className="space-y-2" role="status" aria-live="polite">
      <div className="flex items-baseline justify-between gap-3">
        <span className={`text-[13px] ${failed ? "text-risk-critical" : "text-ink-200"}`}>
          {label}
        </span>
        <span className="font-mono text-[11px] text-ink-400">{job.progress}%</span>
      </div>
      <Meter value={job.progress / 100} tone={failed ? "risk" : "accent"} progress label={label} />
      {job.message && <p className="text-[12px] text-ink-400">{job.message}</p>}
      {failed && job.error && <p className="text-[12px] text-risk-critical">{job.error}</p>}
    </div>
  );
}

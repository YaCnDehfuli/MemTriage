import type { JobProgress } from "../state/store";
import { Meter } from "./primitives";

const LABELS: Record<string, string> = {
  received: "Preparing image",
  triaging: "Preparing image",
  analyzing: "Running Volatility plugins",
  inventorying: "Building investigation",
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
  stopping: "Stopping",
  stopped: "Stopped",
};

const PLUGIN_DONE = new Set([
  "plugin_finished", "plugin_cached", "plugin_converted", "plugin_unavailable", "plugin_failed",
]);

const VOLATILITY_STAGES = new Set([
  "received", "queued", "triaging", "analyzing", "inventorying", "stopping",
]);

/** Live stage readout for a long-running job, fed by SSE with a polling fallback. */
export function JobProgressBar({
  job,
  pluginsCompleted,
  pluginsTotal,
  currentPlugin,
  volatility = false,
  eta,
}: {
  job: JobProgress | null;
  pluginsCompleted?: number;
  pluginsTotal?: number;
  currentPlugin?: string | null;
  volatility?: boolean;
  eta?: string;
}) {
  if (!job) return null;
  const failed = job.status === "failed";
  const running = job.status === "triaging" || job.status === "queued"
    || job.status === "analyzing" || job.stage === "stopping";
  const label = LABELS[job.stage] ?? job.stage;
  const pluginTotal = pluginsTotal && pluginsTotal > 0 ? pluginsTotal : 0;
  const measurable = pluginTotal > 0 && (pluginsCompleted ?? 0) > 0;
  const showPercent = measurable || (!running && job.progress > 0);
  const longRunning = volatility && running && VOLATILITY_STAGES.has(job.stage);
  const status = pluginTotal > 0
    ? `${pluginsCompleted ?? 0}/${pluginTotal} plugins`
    : showPercent
      ? `${job.progress}%`
      : running
        ? (eta ? `in progress · ${eta}` : "in progress")
        : `${job.progress}%`;

  return (
    <div className="space-y-2" role="status" aria-live="polite">
      <div className="flex items-baseline justify-between gap-3">
        <span className={`text-[13px] ${failed ? "text-risk-critical" : "text-ink-200"}`}>
          {label}
          {currentPlugin ? <span className="text-ink-400"> · {currentPlugin}</span> : null}
        </span>
        <span className="shrink-0 font-mono text-[11px] text-ink-400">{status}</span>
      </div>
      <Meter
        value={job.progress / 100}
        tone={failed ? "risk" : "accent"}
        progress
        indeterminate={running && !measurable && !failed}
        label={label}
      />
      {longRunning && (
        <p className="text-[12px] text-ink-400">
          Volatility can take several minutes. This updates as each plugin finishes;
          the percentage is only shown once plugin completion is known.
        </p>
      )}
      {job.message && <p className="text-[12px] text-ink-400">{job.message}</p>}
      {failed && job.error && <p className="text-[12px] text-risk-critical">{job.error}</p>}
    </div>
  );
}

export function pluginCompletion(events: { type: string; plugin?: string }[], requested: string[]): number {
  if (!requested.length) return 0;
  const done = new Set(
    events
      .filter((event) => PLUGIN_DONE.has(event.type) && event.plugin && requested.includes(event.plugin))
      .map((event) => event.plugin as string),
  );
  return done.size;
}

export function currentPluginName(events: { type: string; plugin?: string }[]): string | null {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const event = events[index];
    if ((event.type === "plugin_started" || event.type === "plugin_dispatched") && event.plugin) {
      return event.plugin;
    }
  }
  return null;
}

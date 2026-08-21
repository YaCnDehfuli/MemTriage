import { useMemo } from "react";
import type { PluginEvent } from "../../types";

type Status = "queued" | "dispatched" | "running" | "done" | "cached" | "timed_out" | "failed";

interface Derived {
  name: string;
  status: Status;
  detail: string;
}

const DOT: Record<Status, string> = {
  queued: "bg-ink-600",
  dispatched: "bg-accent animate-pulse",
  running: "bg-accent animate-pulse",
  done: "bg-accent",
  cached: "bg-mist-300",
  timed_out: "bg-risk-high",
  failed: "bg-risk-critical",
};

const CARD: Record<Status, string> = {
  queued: "border-ink-700/60 bg-ink-900/30 text-mist-400",
  dispatched: "border-accent/30 bg-accent/5 text-mist-100",
  running: "border-accent/40 bg-accent/10 text-mist-100",
  done: "border-ink-700/60 bg-ink-900/40 text-mist-100",
  cached: "border-ink-700/60 bg-ink-900/40 text-mist-200",
  timed_out: "border-risk-high/30 bg-risk-high/5 text-mist-100",
  failed: "border-risk-critical/30 bg-risk-critical/5 text-mist-100",
};

const LABEL: Record<Status, string> = {
  queued: "queued",
  dispatched: "dispatched",
  running: "running",
  done: "done",
  cached: "cached",
  timed_out: "timed out",
  failed: "failed",
};

/**
 * Derives each requested plugin's current visible status from the raw event
 * log. A cache hit deliberately goes straight to "cached" with no "running"
 * step because the runner is never invoked for it. A plugin may be dispatched
 * before its per-plugin start event arrives.
 */
function derive(requested: string[], events: PluginEvent[]): Derived[] {
  const state = new Map<string, Derived>(
    requested.map((name) => [name, { name, status: "queued", detail: "" }]),
  );
  for (const e of events) {
    if (e.type === "layer_dispatched") {
      for (const name of e.plugins ?? []) {
        const cur = state.get(name);
        if (cur?.status === "queued") state.set(name, { ...cur, status: "dispatched" });
      }
    } else if (e.type === "plugin_dispatched" && e.plugin && state.has(e.plugin)) {
      const current = state.get(e.plugin)!;
      if (current.status === "queued") {
        state.set(e.plugin, { ...current, status: "dispatched", detail: "waiting for a worker" });
      }
    } else if (e.type === "plugin_started" && e.plugin && state.has(e.plugin)) {
      state.set(e.plugin, { name: e.plugin, status: "running", detail: "" });
    } else if (e.type === "plugin_cached" && e.plugin && state.has(e.plugin)) {
      state.set(e.plugin, { name: e.plugin, status: "cached", detail: "served from cache" });
    } else if (e.type === "plugin_converted" && e.plugin && state.has(e.plugin)) {
      state.set(e.plugin, { name: e.plugin, status: "cached", detail: "converted from cache" });
    } else if (e.type === "plugin_timeout" && e.plugin && state.has(e.plugin)) {
      state.set(e.plugin, {
        name: e.plugin,
        status: "timed_out",
        detail: typeof e.timeout_s === "number" ? `after ${e.timeout_s}s` : "timeout reached",
      });
    } else if (e.type === "plugin_finished" && e.plugin && state.has(e.plugin)) {
      const current = state.get(e.plugin)!;
      state.set(e.plugin, {
        name: e.plugin,
        status: e.ok ? "done" : current.status === "timed_out" ? "timed_out" : "failed",
        detail: e.ok
          ? (typeof e.duration_s === "number" ? `${e.duration_s.toFixed(2)}s` : "complete")
          : (current.detail || `exit ${e.rc ?? "?"}`),
      });
    } else if (e.type === "plugin_failed_detail" && e.plugin) {
      const cur = state.get(e.plugin);
      if (cur && cur.status !== "done") state.set(e.plugin, { ...cur, detail: e.explanation ?? cur.detail });
    } else if ((e.type === "plugin_failed" || e.type === "plugin_unavailable") && e.plugin) {
      const cur = state.get(e.plugin);
      if (cur) {
        state.set(e.plugin, {
          ...cur,
          status: "failed",
          detail: e.explanation ?? (e.type === "plugin_unavailable" ? "unavailable" : "failed"),
        });
      }
    }
  }
  return requested.map((n) => state.get(n)!);
}

export function PluginStatusGrid({
  requested,
  events,
}: {
  requested: string[];
  events: PluginEvent[];
}) {
  const planEvent = useMemo(() => events.find((e) => e.type === "plan"), [events]);
  const plan = planEvent?.layers ?? [requested];
  const derived = useMemo(() => derive(requested, events), [requested, events]);
  const byName = useMemo(() => new Map(derived.map((d) => [d.name, d])), [derived]);

  return (
    <div className="space-y-4">
      {plan.map((layer, i) => (
        <div key={i}>
          <div className="mb-1.5 flex items-center gap-2">
            <span className="eyebrow">Batch {i + 1}</span>
            {layer.length > 1 && (
              <span className="rounded bg-ink-800 px-1.5 py-0.5 text-[10px] text-mist-400 ring-1 ring-inset ring-ink-600">
                {planEvent?.concurrency && planEvent.concurrency > 1
                  ? `up to ${Math.min(planEvent.concurrency, layer.length)} concurrent`
                  : "dependency group"}
              </span>
            )}
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
            {layer.map((name) => {
              const d = byName.get(name) ?? { name, status: "queued" as Status, detail: "" };
              return (
                <div
                  key={name}
                  className={`rounded-md border px-2.5 py-2 transition-colors ${CARD[d.status]}`}
                >
                  <div className="flex items-center gap-1.5">
                    <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${DOT[d.status]}`} />
                    <span className="min-w-0 flex-1 truncate font-mono text-[12px]">{name}</span>
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[10px] text-mist-400">
                    <span className="uppercase tracking-wide">{LABEL[d.status]}</span>
                    {d.detail && <span className="font-mono">{d.detail}</span>}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

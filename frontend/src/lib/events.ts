import type { AnalysisState, InvestigationState, PluginRunState } from "../types";

type Listener<T> = (state: T) => void;

export interface Subscription {
  close(): void;
}

const TERMINAL_INVESTIGATION = new Set(["triaged", "failed"]);
const TERMINAL_ANALYSIS = new Set(["done", "failed"]);
const TERMINAL_PLUGIN_RUN = new Set(["done", "failed"]);

/**
 * Follow a long-running job.
 *
 * The API streams state over SSE, while a lightweight poll reads the durable
 * state in parallel. The poll closes the small subscribe/snapshot race around a
 * very fast cache hit and also covers a dropped Redis publish; SSE remains the
 * low-latency path for every live plugin event.
 */
function follow<T extends { status: string }>(
  streamUrl: string,
  pollUrl: string,
  terminal: Set<string>,
  onState: Listener<T>,
  onError?: (message: string) => void,
  pollMs = 2500,
): Subscription {
  let closed = false;
  let polling = false;
  let source: EventSource | null = null;
  let timer: number | null = null;

  const finish = (state: T) => {
    if (closed) return;
    onState(state);
    if (terminal.has(state.status)) close();
  };

  const poll = async () => {
    if (closed || polling) return;
    polling = true;
    try {
      const res = await fetch(pollUrl);
      if (!res.ok || closed) return;
      const state = (await res.json()) as T;
      // SSE may have delivered the terminal state while this request was in
      // flight. Never let an older poll overwrite that terminal update.
      if (!closed) finish(state);
    } catch {
      /* transient: the next tick tries again */
    } finally {
      polling = false;
    }
  };

  const startPolling = () => {
    if (closed || timer !== null) return;
    timer = window.setInterval(() => void poll(), pollMs);
    void poll();
  };

  function close() {
    closed = true;
    source?.close();
    source = null;
    if (timer !== null) {
      window.clearInterval(timer);
      timer = null;
    }
  }

  if (typeof EventSource !== "undefined") {
    try {
      source = new EventSource(streamUrl);
      source.addEventListener("state", (event) => {
        try {
          finish(JSON.parse((event as MessageEvent).data) as T);
        } catch {
          onError?.("Received an unreadable progress event.");
        }
      });
      source.onerror = () => {
        source?.close();
        source = null;
        startPolling();
      };
    } catch {
      startPolling();
    }
  } else {
    startPolling();
  }

  // A healthy SSE connection can still have missed a publish just before it
  // subscribed. Keep checking the durable row until either path sees a terminal
  // state; startPolling() is idempotent, so the onerror path can call it too.
  startPolling();

  return { close };
}

export function followInvestigation(
  base: string,
  id: string,
  onState: Listener<InvestigationState>,
  onError?: (message: string) => void,
): Subscription {
  return follow(
    `${base}/api/investigations/${id}/events`,
    `${base}/api/investigations/${id}`,
    TERMINAL_INVESTIGATION,
    onState,
    onError,
  );
}

export function followAnalysis(
  base: string,
  id: string,
  analysisId: string,
  onState: Listener<AnalysisState>,
  onError?: (message: string) => void,
): Subscription {
  return follow(
    `${base}/api/investigations/${id}/analyses/${analysisId}/events`,
    `${base}/api/investigations/${id}/analyses/${analysisId}`,
    TERMINAL_ANALYSIS,
    onState,
    onError,
  );
}

export function followPluginRun(
  base: string,
  id: string,
  runId: string,
  onState: Listener<PluginRunState>,
  onError?: (message: string) => void,
): Subscription {
  return follow(
    `${base}/api/investigations/${id}/plugins/runs/${runId}/events`,
    `${base}/api/investigations/${id}/plugins/runs/${runId}`,
    TERMINAL_PLUGIN_RUN,
    onState,
    onError,
    // Events can arrive in a tight burst (a concurrent layer finishing at
    // once); SSE carries them live and the 2.5s durable poll closes any gaps.
  );
}

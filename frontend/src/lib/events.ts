import type { AnalysisState, InvestigationState } from "../types";

type Listener<T> = (state: T) => void;

export interface Subscription {
  close(): void;
}

const TERMINAL_INVESTIGATION = new Set(["triaged", "failed"]);
const TERMINAL_ANALYSIS = new Set(["done", "failed"]);

/**
 * Follow a long-running job.
 *
 * The API streams state over SSE, but a proxy that buffers, a browser that has
 * run out of connections, or a plain network blip all end the stream silently.
 * Rather than leave the UI frozen on "queued", every subscription falls back to
 * polling the same state endpoint, and keeps polling until the job reaches a
 * terminal state or the caller closes it.
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
  let source: EventSource | null = null;
  let timer: number | null = null;

  const finish = (state: T) => {
    onState(state);
    if (terminal.has(state.status)) close();
  };

  const poll = async () => {
    if (closed) return;
    try {
      const res = await fetch(pollUrl);
      if (res.ok) finish((await res.json()) as T);
    } catch {
      /* transient: the next tick tries again */
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

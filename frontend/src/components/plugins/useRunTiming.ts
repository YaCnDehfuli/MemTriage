import { useEffect, useRef, useState } from "react";
import type { PluginEvent } from "../../types";

function duration(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours) return `${hours}h ${minutes}m ${secs}s`;
  if (minutes) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

/**
 * Keeps a visibly-live clock even when a Volatility scanner emits no log
 * lines — whole-image scanners can legitimately run for hours with a quiet
 * log, so this is what tells the analyst the job hasn't actually stopped.
 * Compute-only: the caller decides where to render the strings, since a
 * dedicated box for this cost more scroll than the numbers were worth.
 */
export function useRunTiming(events: PluginEvent[], running: boolean, runId?: string | number) {
  const mountedAt = useRef(Date.now());
  const [now, setNow] = useState(Date.now());

  // Re-anchor on a new run instead of keeping the previous run's mount
  // time — without this a rerun briefly shows elapsed time inherited from
  // whenever the page first loaded, until its first event self-corrects it.
  useEffect(() => {
    mountedAt.current = Date.now();
  }, [runId]);

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  const firstAt = events[0]?.at ? events[0].at * 1000 : mountedAt.current;
  const lastAt = events.length ? events[events.length - 1].at * 1000 : null;
  const elapsedUntil = running ? now : (lastAt ?? now);

  return {
    elapsed: duration((elapsedUntil - firstAt) / 1000),
    lastActivity: lastAt ? duration((now - lastAt) / 1000) : null,
  };
}

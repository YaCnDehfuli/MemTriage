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

/** Keeps a visibly-live clock even when a Volatility scanner emits no log lines. */
export function RunTiming({ events, running }: { events: PluginEvent[]; running: boolean }) {
  const mountedAt = useRef(Date.now());
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    if (!running) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [running]);

  const firstAt = events[0]?.at ? events[0].at * 1000 : mountedAt.current;
  const lastAt = events.length ? events[events.length - 1].at * 1000 : null;
  const elapsedUntil = running ? now : (lastAt ?? now);

  return (
    <div className="space-y-2 rounded-md border border-ink-700/60 bg-ink-900/30 px-3 py-2.5">
      <div className="flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-mist-400">
        <span>Elapsed {duration((elapsedUntil - firstAt) / 1000)}</span>
        <span>
          {lastAt ? `Last activity ${duration((now - lastAt) / 1000)} ago` : "Awaiting first activity"}
        </span>
        {running && <span className="text-accent">job active</span>}
      </div>
      <p className="text-[11px] leading-relaxed text-mist-400">
        Whole-image scanners can legitimately run for hours and, on very large dumps, up to a
        day. A quiet log does not mean the job has stopped.
      </p>
    </div>
  );
}

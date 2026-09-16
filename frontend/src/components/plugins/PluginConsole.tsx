import { useEffect, useRef } from "react";
import type { PluginEvent } from "../../types";

const LEVEL_CLASS: Record<string, string> = {
  ERROR: "text-risk-critical",
  WARNING: "text-risk-medium",
  INFO: "text-ink-300",
  DEBUG: "text-ink-400",
};

function timestamp(at: number): string {
  return new Date(at * 1000).toLocaleTimeString(undefined, { hour12: false });
}

/** A live, terminal-styled mirror of every VolMemLyzer log line as it runs. */
export function PluginConsole({ events }: { events: PluginEvent[] }) {
  const lines = events.filter((e) => e.type === "log");
  const consoleRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const followingRef = useRef(true);

  useEffect(() => {
    const el = consoleRef.current;
    if (!el) return;
    const onScroll = () => {
      followingRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 32;
    };
    el.addEventListener("scroll", onScroll);
    return () => el.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const el = consoleRef.current;
    // Only snap to the newest line if the analyst was already reading the
    // live edge — scrolling up to read earlier output should not be undone.
    if (el && followingRef.current) el.scrollTop = el.scrollHeight;
  }, [lines.length]);

  return (
    <div ref={consoleRef} className="h-[420px] overflow-y-auto rounded-md border border-surface-700/60 bg-surface-950 p-3 font-mono text-[12px] leading-relaxed">
      {lines.length === 0 ? (
        <p className="text-ink-400">Waiting for output…</p>
      ) : (
        lines.map((e, i) => (
          <div key={i} className="whitespace-pre-wrap break-all">
            <span className="text-ink-400">[{timestamp(e.at)}]</span>{" "}
            <span className={LEVEL_CLASS[e.level ?? "INFO"] ?? "text-ink-300"}>
              {(e.level ?? "INFO").padEnd(7)}
            </span>{" "}
            <span className="text-ink-400">{e.logger?.replace("volmemlyzer.", "")}:</span>{" "}
            <span className="text-ink-200">{e.line}</span>
          </div>
        ))
      )}
      <div ref={bottomRef} />
    </div>
  );
}

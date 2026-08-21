import { useEffect, useRef } from "react";
import type { PluginEvent } from "../../types";

const LEVEL_CLASS: Record<string, string> = {
  ERROR: "text-risk-critical",
  WARNING: "text-risk-medium",
  INFO: "text-mist-300",
  DEBUG: "text-mist-400",
};

function timestamp(at: number): string {
  return new Date(at * 1000).toLocaleTimeString(undefined, { hour12: false });
}

/** A live, terminal-styled mirror of every VolMemLyzer log line as it runs. */
export function PluginConsole({ events }: { events: PluginEvent[] }) {
  const lines = events.filter((e) => e.type === "log");
  const consoleRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const consoleElement = consoleRef.current;
    if (consoleElement) consoleElement.scrollTop = consoleElement.scrollHeight;
  }, [lines.length]);

  return (
    <div ref={consoleRef} className="h-[420px] overflow-y-auto rounded-md border border-ink-700/60 bg-ink-950 p-3 font-mono text-[12px] leading-relaxed">
      {lines.length === 0 ? (
        <p className="text-mist-400">Waiting for output…</p>
      ) : (
        lines.map((e, i) => (
          <div key={i} className="whitespace-pre-wrap break-all">
            <span className="text-mist-500">[{timestamp(e.at)}]</span>{" "}
            <span className={LEVEL_CLASS[e.level ?? "INFO"] ?? "text-mist-300"}>
              {(e.level ?? "INFO").padEnd(7)}
            </span>{" "}
            <span className="text-mist-400">{e.logger?.replace("volmemlyzer.", "")}:</span>{" "}
            <span className="text-mist-200">{e.line}</span>
          </div>
        ))
      )}
      <div ref={bottomRef} />
    </div>
  );
}

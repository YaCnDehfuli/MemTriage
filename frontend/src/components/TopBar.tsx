import { useApp } from "../state/store";

export function TopBar() {
  const { demo, setDemo, investigationId } = useApp();
  return (
    <header className="flex items-center justify-between border-b border-ink-700/70 bg-ink-900/70 px-5 py-3 backdrop-blur">
      <div className="flex items-center gap-3">
        <div className="grid h-8 w-8 place-items-center rounded-md bg-accent/15 text-accent ring-1 ring-inset ring-accent/30">
          <span className="font-mono text-sm font-bold">M</span>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-mist-100">MemTriage</span>
            <span className="rounded bg-ink-800 px-1.5 py-0.5 text-[10px] uppercase tracking-wider text-mist-400 ring-1 ring-inset ring-ink-600">
              Memory Forensics Triage
            </span>
          </div>
          <div className="text-[11px] text-mist-400">
            VolMemLyzer triage · explainable scoring · VADViT deep-dive
          </div>
        </div>
      </div>

      <div className="flex items-center gap-3">
        {investigationId && (
          <span className="hidden font-mono text-[11px] text-mist-400 sm:inline">
            {investigationId}
          </span>
        )}
        <div className="flex items-center rounded-md bg-ink-800 p-0.5 ring-1 ring-inset ring-ink-600">
          <button
            className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
              demo ? "bg-accent/20 text-accent" : "text-mist-400 hover:text-mist-200"
            }`}
            onClick={() => setDemo(true)}
          >
            Demo
          </button>
          <button
            className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
              !demo ? "bg-accent/20 text-accent" : "text-mist-400 hover:text-mist-200"
            }`}
            onClick={() => setDemo(false)}
          >
            Live
          </button>
        </div>
      </div>
    </header>
  );
}

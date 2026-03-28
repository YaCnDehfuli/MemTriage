import { useApp } from "../state/store";
import type { Stage } from "../types";
import { bytes } from "../lib/format";

const STAGES: { id: Stage; label: string; hint: string }[] = [
  { id: "ingest", label: "Ingest", hint: "Dump snapshots" },
  { id: "triage", label: "Triage overview", hint: "IoC table · tuning" },
  { id: "inventory", label: "Process inventory", hint: "Select a PID" },
  { id: "deepdive", label: "VADViT deep-dive", hint: "Grid · attention" },
  { id: "report", label: "Report", hint: "Findings · export" },
];

export function LeftRail() {
  const { stage, setStage, triage, demo, riskSummary } = useApp();
  const done = (id: Stage) =>
    (id === "ingest" || id === "triage") && !!triage;

  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-ink-700/70 bg-ink-900/40 px-3 py-4 md:flex">
      <div className="eyebrow px-2 pb-2">Investigation</div>
      <nav className="flex flex-col gap-1">
        {STAGES.map((s, i) => {
          const active = stage === s.id;
          return (
            <button
              key={s.id}
              onClick={() => setStage(s.id)}
              className={`group flex items-start gap-3 rounded-md px-2.5 py-2 text-left transition-colors ${
                active ? "bg-ink-800 ring-1 ring-inset ring-ink-600" : "hover:bg-ink-850"
              }`}
            >
              <span
                className={`mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full text-[11px] font-semibold ring-1 ring-inset ${
                  active
                    ? "bg-accent/20 text-accent ring-accent/40"
                    : done(s.id)
                      ? "bg-ink-700 text-mist-300 ring-ink-600"
                      : "bg-ink-850 text-mist-400 ring-ink-700"
                }`}
              >
                {done(s.id) && !active ? "✓" : i + 1}
              </span>
              <span className="min-w-0">
                <span
                  className={`block text-sm font-medium ${active ? "text-mist-100" : "text-mist-300"}`}
                >
                  {s.label}
                </span>
                <span className="block truncate text-[11px] text-mist-400">{s.hint}</span>
              </span>
            </button>
          );
        })}
      </nav>

      <div className="mt-auto space-y-3 px-1 pt-6">
        {triage && (
          <div className="rounded-md border border-ink-700/60 bg-ink-850/60 p-3">
            <div className="eyebrow mb-2">Evidence</div>
            <dl className="space-y-1 text-[12px]">
              <Row k="Snapshots" v={String(triage.dumps.length)} />
              <Row
                k="Imaged"
                v={bytes(triage.dumps.reduce((a, d) => a + d.size_bytes, 0))}
              />
              <Row k="Processes" v={String(triage.processes.length)} />
              <Row k="IoCs surfaced" v={String(riskSummary?.total ?? 0)} />
            </dl>
          </div>
        )}
        <div className="flex items-center gap-2 px-1 text-[11px] text-mist-400">
          <span
            className={`h-1.5 w-1.5 rounded-full ${demo ? "bg-risk-medium" : "bg-accent"}`}
          />
          {demo ? "Demo data (no backend)" : "Live backend"}
        </div>
        <p className="px-1 text-[10px] leading-relaxed text-mist-400">
          Triage aid, not EDR/AV. Findings are analyst-facing and MITRE ATT&CK aligned.
        </p>
      </div>
    </aside>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex items-center justify-between">
      <dt className="text-mist-400">{k}</dt>
      <dd className="font-mono text-mist-200">{v}</dd>
    </div>
  );
}

import { useApp } from "../../state/store";
import { bytes } from "../../lib/format";
import { Panel } from "../primitives";

export function IngestView() {
  const { triage, demo, setStage } = useApp();
  return (
    <div className="space-y-5">
      <header>
        <div className="eyebrow">Phase 0 · Ingest</div>
        <h1 className="text-lg font-semibold text-mist-100">Memory image intake</h1>
        <p className="mt-1 max-w-2xl text-sm text-mist-400">
          One atomic dump, or up to five interval snapshots of the same host. Snapshots stream to
          disk — a multi-GB image is never buffered in memory — and are fingerprinted (SHA-256)
          before analysis.
        </p>
      </header>

      <div className="grid gap-5 lg:grid-cols-[1fr_320px]">
        <Panel eyebrow="Snapshots" title="Provided evidence" className="overflow-hidden">
          {triage ? (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-ink-700/60 text-left text-[11px] uppercase tracking-wider text-mist-400">
                  <th className="px-4 py-2">#</th>
                  <th className="px-3 py-2">Filename</th>
                  <th className="px-3 py-2">Size</th>
                  <th className="px-3 py-2">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {triage.dumps.map((d) => (
                  <tr key={d.ordinal} className="border-b border-ink-800/70">
                    <td className="px-4 py-2.5 font-mono text-mist-300">{d.ordinal}</td>
                    <td className="px-3 py-2.5 text-mist-100">{d.filename}</td>
                    <td className="px-3 py-2.5 font-mono text-[12px] text-mist-300">
                      {bytes(d.size_bytes)}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[12px] text-mist-400">{d.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-6 py-12 text-center text-sm text-mist-400">
              No snapshots yet.
            </div>
          )}
        </Panel>

        <Panel eyebrow="Pipeline" title="What happens next">
          <ol className="space-y-3 px-4 py-4 text-[13px] text-mist-300">
            {[
              ["Extract", "VolMemLyzer runs the triage plugin set once; raw JSON is cached."],
              ["Score", "The tunable engine scores every object with traceable evidence."],
              ["Select", "Pick a process from the inventory to deep-dive."],
              ["Classify", "VADViT renders its VAD grid, classifies, and overlays attention."],
            ].map(([t, d], i) => (
              <li key={t} className="flex gap-3">
                <span className="mt-0.5 grid h-5 w-5 shrink-0 place-items-center rounded-full bg-ink-800 text-[11px] font-semibold text-accent ring-1 ring-inset ring-ink-600">
                  {i + 1}
                </span>
                <span>
                  <b className="text-mist-100">{t}.</b> {d}
                </span>
              </li>
            ))}
          </ol>
          <div className="border-t border-ink-800/70 px-4 py-3">
            <button className="btn-accent w-full justify-center" onClick={() => setStage("triage")}>
              {demo ? "View triage overview →" : "Go to triage →"}
            </button>
          </div>
        </Panel>
      </div>
    </div>
  );
}

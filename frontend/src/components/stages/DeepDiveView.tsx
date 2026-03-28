import { useApp } from "../../state/store";
import { pct } from "../../lib/format";
import { Chip, EmptyState, Meter, Panel } from "../primitives";
import { GridViewer } from "../process/GridViewer";
import { VerdictPanel } from "../process/VerdictPanel";

export function DeepDiveView() {
  const { analysis, selectedPid, client, investigationId, setStage } = useApp();

  if (!analysis) {
    return (
      <Panel eyebrow="Phase 2 · VADViT" title="Process deep-dive">
        <EmptyState
          title={selectedPid ? `Analyzing PID ${selectedPid}…` : "No process selected"}
          hint="Choose a process from the inventory to render its VAD grid, classify it, and attribute the model's attention back to VAD regions."
        />
        <div className="flex justify-center pb-6">
          <button className="btn-ghost text-xs" onClick={() => setStage("inventory")}>
            ← Back to inventory
          </button>
        </div>
      </Panel>
    );
  }

  const id = investigationId ?? "demo-investigation";
  const gridUrl = client.artifactUrl(id, analysis.pid, "grid");
  const attnUrl = analysis.explainability.attention_png
    ? client.artifactUrl(id, analysis.pid, "attention")
    : null;

  return (
    <div className="space-y-5">
      <header className="flex items-end justify-between">
        <div>
          <div className="eyebrow">Phase 2 · VADViT deep-dive</div>
          <h1 className="text-lg font-semibold text-mist-100">
            {analysis.process_name}{" "}
            <span className="font-mono text-mist-400">(PID {analysis.pid})</span>
          </h1>
          <p className="mt-1 text-sm text-mist-400">
            Consolidated from snapshot #{analysis.chosen_dump_ordinal} ·{" "}
            {analysis.region_count} VAD regions rendered.
          </p>
        </div>
        <button className="btn-ghost text-xs" onClick={() => setStage("inventory")}>
          ← Inventory
        </button>
      </header>

      <div className="grid gap-5 lg:grid-cols-[360px_1fr]">
        <Panel eyebrow="Explainability" title="Region grid & attention">
          <div className="p-4">
            <GridViewer gridUrl={gridUrl} attentionUrl={attnUrl} />
          </div>
        </Panel>

        <div className="space-y-5">
          <VerdictPanel verdict={analysis.verdict} />

          <Panel eyebrow="Attribution" title="Attention → VAD regions">
            {analysis.explainability.attributions.length === 0 ? (
              <EmptyState title="No attention attribution" hint="Requires the model + a rendered grid." />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-ink-700/60 text-left text-[11px] uppercase tracking-wider text-mist-400">
                    <th className="px-4 py-2">Patch</th>
                    <th className="px-3 py-2">VAD address</th>
                    <th className="px-3 py-2">Region</th>
                    <th className="w-40 px-3 py-2">Attention</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.explainability.attributions.map((a) => (
                    <tr key={a.patch_index} className="border-b border-ink-800/70">
                      <td className="px-4 py-2 font-mono text-[12px] text-mist-400">
                        r{a.row}·c{a.col}
                      </td>
                      <td className="px-3 py-2 font-mono text-[12px] text-mist-200">
                        {a.region_addr}
                      </td>
                      <td className="px-3 py-2">
                        <Chip tone={a.category === "exe" ? "accent" : "default"}>{a.category}</Chip>
                      </td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <Meter value={a.attention} tone="risk" />
                          <span className="w-10 text-right font-mono text-[11px] text-mist-400">
                            {pct(a.attention)}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            <p className="border-t border-ink-800/70 px-4 py-2 text-[10px] text-mist-400">
              Patches the classifier weighted most, mapped back to concrete VAD regions in this
              process.
            </p>
          </Panel>
        </div>
      </div>
    </div>
  );
}

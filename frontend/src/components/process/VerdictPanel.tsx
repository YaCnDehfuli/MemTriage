import { useState } from "react";
import type { Verdict } from "../../types";
import { pct } from "../../lib/format";
import { ModelAccessForm } from "../ModelAccessForm";
import { Meter, Panel } from "../primitives";

export function VerdictPanel({ verdict }: { verdict: Verdict }) {
  const [requesting, setRequesting] = useState(false);

  if (!verdict.model_loaded) {
    return (
      <Panel eyebrow="VADViT" title="Classification">
        <div className="px-4 py-6">
          <div className="inline-flex items-center gap-2 rounded-md bg-ink-800 px-2.5 py-1 text-xs text-mist-300 ring-1 ring-inset ring-ink-600">
            <span className="h-1.5 w-1.5 rounded-full bg-risk-none" />
            Model not loaded
          </div>
          <p className="mt-3 text-sm text-mist-400">{verdict.note}</p>
          <button className="btn-ghost mt-3 text-[12px]" onClick={() => setRequesting(true)}>
            Request the trained weights
          </button>
        </div>
        {requesting && <ModelAccessForm onClose={() => setRequesting(false)} />}
      </Panel>
    );
  }

  const ranked = Object.entries(verdict.probabilities).sort((a, b) => b[1] - a[1]);
  return (
    <Panel eyebrow="VADViT" title="Classification">
      <div className="px-4 py-4">
        {verdict.placeholder && (
          <div className="mb-3 rounded-md border border-risk-medium/30 bg-risk-medium/10 px-3 py-2 text-[12px] text-risk-medium">
            <p>
              <b>Untrained structural placeholder.</b> This family label is not a detection
              and carries no information. The attention map, the region ranking and the
              low-level analysis below are architectural — they describe real memory
              regardless of which weights are loaded.
            </p>
            <button
              className="btn-ghost mt-2 text-[11px]"
              onClick={() => setRequesting(true)}
            >
              Request the trained weights →
            </button>
          </div>
        )}
        <div className="flex items-baseline justify-between">
          <div className="text-xl font-semibold text-mist-100">{verdict.family}</div>
          <div className="font-mono text-sm text-mist-300">{pct(verdict.confidence)}</div>
        </div>
        <div className="mt-4 space-y-2">
          {ranked.map(([fam, p], i) => (
            <div key={fam} className="grid grid-cols-[120px_1fr_44px] items-center gap-2">
              <span
                className={`truncate text-[12px] ${i === 0 ? "text-mist-100" : "text-mist-400"}`}
                title={fam}
              >
                {fam}
              </span>
              <Meter value={p} />
              <span className="text-right font-mono text-[11px] text-mist-400">{pct(p)}</span>
            </div>
          ))}
        </div>
      </div>
      {requesting && <ModelAccessForm onClose={() => setRequesting(false)} />}
    </Panel>
  );
}

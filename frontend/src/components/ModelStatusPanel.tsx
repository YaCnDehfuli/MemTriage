import { useEffect, useState } from "react";
import { useApp } from "../state/store";
import type { ModelState } from "../types";
import { Panel } from "./primitives";

const SOURCE_LABEL: Record<ModelState["active_source"], string> = {
  trained: "Bundled trained model",
  uploaded: "Operator-supplied model",
  placeholder: "Untrained test model",
  none: "Model unavailable",
};

export function ModelStatusPanel() {
  const { client } = useApp();
  const [model, setModel] = useState<ModelState | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void client.getModelState()
      .then((state) => { if (!cancelled) setModel(state); })
      .catch((e: Error) => { if (!cancelled) setError(e.message); });
    return () => { cancelled = true; };
  }, [client]);

  return (
    <Panel eyebrow="VADViT" title="Process classification">
      <div className="px-4 py-3 text-sm text-ink-300">
        {model ? (
          <>
            <p className="font-medium text-ink-100">{SOURCE_LABEL[model.active_source]}</p>
            <p className="mt-1 text-ink-400">{model.note}</p>
            <p className="mt-1 text-ink-400">
              Select a process after triage to see classification probabilities,
              attention, and the regions selected for analysis.
            </p>
          </>
        ) : <p>{error ?? "Checking the model…"}</p>}
      </div>
    </Panel>
  );
}

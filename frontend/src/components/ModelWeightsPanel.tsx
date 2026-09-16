import { useEffect, useRef, useState } from "react";
import { useApp } from "../state/store";
import type { ModelState } from "../types";

const MB = 1024 * 1024;

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * MB) return `${(bytes / (1024 * MB)).toFixed(2)} GB`;
  if (bytes >= MB) return `${(bytes / MB).toFixed(1)} MB`;
  return `${(bytes / 1024).toFixed(0)} KB`;
}

const SOURCE_LABEL: Record<ModelState["active_source"], string> = {
  trained: "Trained weights",
  uploaded: "Your weights",
  placeholder: "Untrained placeholder",
};

const SOURCE_TONE: Record<ModelState["active_source"], string> = {
  trained: "bg-risk-none",
  uploaded: "bg-risk-low",
  placeholder: "bg-risk-medium",
};

/**
 * Install VADViT weights into a running deployment.
 *
 * The trained checkpoint is released by the author on request, so whoever
 * obtains it still needs a way to use it. Mounting a volume means host shell
 * access and a stack restart; this does not. The file is loaded with
 * `weights_only=True` into a fixed architecture, so it is treated as data.
 *
 * Deliberately says which weights are active at all times: a family label from
 * an untrained placeholder and one from a trained model look identical, and the
 * difference is the whole question of whether the label means anything.
 */
export function ModelWeightsPanel({ onChanged }: { onChanged?(model: ModelState): void }) {
  const { client } = useApp();
  const [model, setModel] = useState<ModelState | null>(null);
  const [checkpoint, setCheckpoint] = useState<File | null>(null);
  const [labels, setLabels] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const checkpointInput = useRef<HTMLInputElement>(null);
  const labelsInput = useRef<HTMLInputElement>(null);

  const refresh = (next: ModelState) => {
    setModel(next);
    onChanged?.(next);
  };

  useEffect(() => {
    let cancelled = false;
    void client
      .getModelState()
      .then((m) => !cancelled && setModel(m))
      .catch((e: Error) => !cancelled && setError(e.message));
    return () => {
      cancelled = true;
    };
  }, [client]);

  const reset = () => {
    setCheckpoint(null);
    setLabels(null);
    if (checkpointInput.current) checkpointInput.current.value = "";
    if (labelsInput.current) labelsInput.current.value = "";
  };

  const pickCheckpoint = (file: File | null) => {
    setError(null);
    setNotice(null);
    if (file && model && file.size > model.max_upload_bytes) {
      setError(
        `That file is ${formatBytes(file.size)}; the limit is ${formatBytes(
          model.max_upload_bytes,
        )}.`,
      );
      setCheckpoint(null);
      return;
    }
    setCheckpoint(file);
  };

  const upload = async () => {
    if (!checkpoint) return;
    setError(null);
    setNotice(null);
    setProgress(0);
    try {
      const result = await client.uploadModelWeights(checkpoint, labels, setProgress);
      refresh(result.model);
      setNotice(
        `Installed ${formatBytes(result.size_bytes)} of weights` +
          (result.labels_stored ? " and class labels." : ".") +
          " New analyses will use them; results already produced are unchanged.",
      );
      reset();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setProgress(null);
    }
  };

  const remove = async () => {
    setError(null);
    setNotice(null);
    try {
      const result = await client.deleteModelWeights();
      refresh(result.model);
      setNotice("Removed the uploaded weights.");
    } catch (e) {
      setError((e as Error).message);
    }
  };

  if (!model) {
    return (
      <div className="px-4 py-4 text-sm text-ink-400">
        {error ?? "Checking which weights are loaded…"}
      </div>
    );
  }

  const busy = progress !== null;

  return (
    <div className="px-4 py-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="inline-flex items-center gap-2 rounded-md bg-surface-800 px-2.5 py-1 text-xs text-ink-200 ring-1 ring-inset ring-surface-600">
          <span className={`h-1.5 w-1.5 rounded-full ${SOURCE_TONE[model.active_source]}`} />
          {SOURCE_LABEL[model.active_source]}
        </span>
        {!model.runtime_available && (
          <span className="text-[11px] text-ink-400">
            PyTorch is not importable in this process; the worker loads the weights.
          </span>
        )}
      </div>
      <p className="mt-3 text-sm text-ink-400">{model.note}</p>

      {model.uploaded_weights && (
        <div className="mt-3 rounded-md bg-surface-800 px-3 py-2 text-[12px] text-ink-300 ring-1 ring-inset ring-surface-600">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="font-mono">{model.uploaded_weights.filename}</span>
            <span className="text-ink-400">
              {formatBytes(model.uploaded_weights.size_bytes)} ·{" "}
              {new Date(model.uploaded_weights.uploaded_at).toLocaleString()}
            </span>
          </div>
          <div className="mt-1 text-ink-400">
            {model.uploaded_weights.labels_uploaded
              ? "Class labels supplied with the checkpoint."
              : `Using the default class labels: ${model.labels.slice(0, 3).join(", ")}…`}
          </div>
          {model.uploaded_weights.superseded_by_mount && (
            <div className="mt-1 text-risk-medium">
              A checkpoint mounted by this deployment takes precedence, so these
              uploaded weights are stored but not in use.
            </div>
          )}
          <button className="btn-ghost mt-2 text-[11px]" onClick={() => void remove()} disabled={busy}>
            Remove uploaded weights
          </button>
        </div>
      )}

      <div className="mt-4 space-y-3 border-t border-surface-700 pt-4">
        <div>
          <label
            htmlFor="model-checkpoint"
            className="block text-[12px] font-medium text-ink-200"
          >
            VADViT checkpoint (.pt)
          </label>
          <p className="mt-0.5 text-[11px] text-ink-400">
            A <code className="font-mono">state_dict</code> for{" "}
            <code className="font-mono">{model.expected_filename}</code>, up to{" "}
            {formatBytes(model.max_upload_bytes)}. Loaded as data only
            (<code className="font-mono">weights_only</code>), never executed.
          </p>
          <input
            id="model-checkpoint"
            ref={checkpointInput}
            type="file"
            accept=".pt"
            disabled={busy}
            onChange={(e) => pickCheckpoint(e.target.files?.[0] ?? null)}
            className="mt-2 block w-full text-[12px] text-ink-300 file:mr-3 file:rounded-md file:border-0 file:bg-surface-700 file:px-3 file:py-1.5 file:text-[12px] file:text-ink-100 hover:file:bg-surface-600"
          />
        </div>

        <div>
          <label htmlFor="model-labels" className="block text-[12px] font-medium text-ink-200">
            Class labels (labels.json) — optional
          </label>
          <p className="mt-0.5 text-[11px] text-ink-400">
            A JSON array of {model.labels.length} class names, in the model&apos;s output
            order. Without it the families are shown by index.
          </p>
          <input
            id="model-labels"
            ref={labelsInput}
            type="file"
            accept=".json,application/json"
            disabled={busy}
            onChange={(e) => setLabels(e.target.files?.[0] ?? null)}
            className="mt-2 block w-full text-[12px] text-ink-300 file:mr-3 file:rounded-md file:border-0 file:bg-surface-700 file:px-3 file:py-1.5 file:text-[12px] file:text-ink-100 hover:file:bg-surface-600"
          />
        </div>

        {busy && (
          <div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-700">
              <div
                className="h-full bg-risk-low transition-[width]"
                style={{ width: `${Math.round((progress ?? 0) * 100)}%` }}
              />
            </div>
            <p className="mt-1 text-[11px] text-ink-400">
              Uploading… {Math.round((progress ?? 0) * 100)}%
            </p>
          </div>
        )}

        {error && (
          <p role="alert" className="text-[12px] text-risk-high">
            {error}
          </p>
        )}
        {notice && !error && <p className="text-[12px] text-risk-none">{notice}</p>}

        <button className="btn" onClick={() => void upload()} disabled={!checkpoint || busy}>
          {busy ? "Uploading…" : "Install weights"}
        </button>
      </div>
    </div>
  );
}

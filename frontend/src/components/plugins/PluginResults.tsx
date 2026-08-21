import { useEffect, useMemo, useState } from "react";
import type { ApiClient } from "../../api/client";
import type { PluginOutputPreview, PluginRunState } from "../../types";
import { EmptyState, Panel } from "../primitives";

function valueText(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function outputPlugins(run: PluginRunState): string[] {
  if (Array.isArray(run.available_outputs)) {
    const durable = new Set(run.available_outputs);
    return run.requested_plugins.filter((plugin) => durable.has(plugin));
  }
  // Older responses do not carry the durable manifest. Event derivation
  // remains a compatibility fallback, not the source of truth for live runs.
  const available = new Set<string>();
  for (const event of run.events) {
    if (!event.plugin) continue;
    if (event.type === "plugin_cached" || event.type === "plugin_converted") {
      available.add(event.plugin);
    } else if (event.type === "plugin_finished") {
      if (event.ok) available.add(event.plugin);
      else available.delete(event.plugin);
    }
  }
  return run.requested_plugins.filter((plugin) => available.has(plugin));
}

export function PluginResults({
  client,
  investigationId,
  run,
}: {
  client: ApiClient;
  investigationId: string;
  run: PluginRunState;
}) {
  const available = useMemo(() => outputPlugins(run), [run]);
  const [selected, setSelected] = useState(available[0] ?? "");
  const [preview, setPreview] = useState<PluginOutputPreview | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selected || !available.includes(selected)) {
      setSelected(available[0] ?? "");
      setOffset(0);
    }
  }, [available, selected]);

  useEffect(() => {
    if (!selected) {
      setPreview(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    void client.getPluginOutput(investigationId, run.plugin_run_id, selected, offset, 200)
      .then((result) => {
        if (!cancelled) setPreview(result);
      })
      .catch((reason: unknown) => {
        if (!cancelled) {
          setPreview(null);
          setError(reason instanceof Error ? reason.message : String(reason));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [client, investigationId, offset, run.plugin_run_id, selected]);

  const columns = useMemo(() => {
    if (!preview) return [];
    if (preview.columns?.length) return preview.columns;
    const names = new Set<string>();
    for (const row of preview.rows ?? []) Object.keys(row).forEach((name) => names.add(name));
    return [...names];
  }, [preview]);

  return (
    <Panel
      eyebrow="Plugin output"
      title="Pretty results"
      className="overflow-hidden"
      right={selected ? (
        <div className="flex gap-2">
          <a
            className="btn-ghost text-[11px]"
            href={client.pluginOutputDownloadUrl(investigationId, run.plugin_run_id, selected, "json")}
            download={`${selected}.json`}
          >
            JSON ↓
          </a>
          {preview ? (
            <a
              className="btn-ghost text-[11px]"
              href={client.pluginOutputDownloadUrl(investigationId, run.plugin_run_id, selected, "csv")}
              download={`${selected}.csv`}
            >
              CSV ↓
            </a>
          ) : (
            <span className="btn-ghost cursor-not-allowed text-[11px] opacity-50" title="CSV is available when the server can render this artifact">
              CSV unavailable
            </span>
          )}
        </div>
      ) : undefined}
    >
      {available.length === 0 ? (
        <EmptyState
          title={run.status === "running" || run.status === "queued" ? "Waiting for the first result…" : "No previewable output"}
          hint="Results appear when the run publishes its durable output manifest."
        />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 border-b border-ink-700/60 px-4 py-3">
            <label className="eyebrow" htmlFor="plugin-output-select">Plugin</label>
            <select
              id="plugin-output-select"
              value={selected}
              onChange={(event) => {
                setSelected(event.target.value);
                setOffset(0);
              }}
              className="min-w-52 rounded-md border border-ink-600 bg-ink-950 px-2.5 py-1.5 font-mono text-[12px] text-mist-200 outline-none focus:border-accent/50"
            >
              {available.map((plugin) => <option key={plugin}>{plugin}</option>)}
            </select>
            {preview && (
              <div className="ml-auto flex flex-wrap gap-2 text-[10px] text-mist-400">
                <span>{preview.row_count} row{preview.row_count === 1 ? "" : "s"}</span>
                {preview.rows.length > 0 && (
                  <span>
                    showing {(preview.offset ?? offset) + 1}–
                    {(preview.offset ?? offset) + preview.rows.length}
                  </span>
                )}
                {preview.cached && <span className="text-accent">cached</span>}
                {preview.truncated && <span className="text-risk-medium">preview truncated</span>}
              </div>
            )}
          </div>

          {loading ? (
            <div className="px-4 py-8 text-center text-[12px] text-mist-400">Loading preview…</div>
          ) : error ? (
            <div className="px-4 py-4 text-[12px] text-risk-critical">{error}</div>
          ) : !preview ? null : preview.rows.length === 0 && preview.data !== null && preview.data !== undefined ? (
            <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-all px-4 py-3 font-mono text-[11px] leading-relaxed text-mist-300">
              {JSON.stringify(preview.data, null, 2)}
            </pre>
          ) : preview.rows.length === 0 ? (
            <EmptyState title="Plugin returned no rows" />
          ) : (
            <div>
              <div className="max-h-[420px] overflow-auto">
                <table className="min-w-full whitespace-nowrap text-left text-[11px]">
                <thead className="sticky top-0 bg-ink-850 uppercase tracking-wider text-mist-400">
                  <tr className="border-b border-ink-700/60">
                    {columns.map((column) => <th key={column} className="px-3 py-2">{column}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {preview.rows.map((row, index) => (
                    <tr key={index} className="border-b border-ink-800/70">
                      {columns.map((column) => (
                        <td key={column} className="max-w-80 overflow-hidden text-ellipsis px-3 py-2 font-mono text-mist-300">
                          {valueText(row[column])}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
                </table>
              </div>
              {(offset > 0 || preview.truncated) && (
                <div className="flex items-center justify-end gap-2 border-t border-ink-700/60 px-4 py-3">
                  <button
                    type="button"
                    className="btn-ghost text-[11px]"
                    disabled={loading || offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - 200))}
                  >
                    ← Previous
                  </button>
                  <button
                    type="button"
                    className="btn-ghost text-[11px]"
                    disabled={loading || !preview.truncated}
                    onClick={() => setOffset(offset + preview.rows.length)}
                  >
                    Next →
                  </button>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

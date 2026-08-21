import { useMemo, useState } from "react";
import { EmptyState, Panel } from "../primitives";

interface FeatureRow {
  key: string;
  source: string;
  feature: string;
  value: unknown;
}

function splitFeature(key: string): Pick<FeatureRow, "source" | "feature"> {
  const dot = key.lastIndexOf(".");
  return dot < 0
    ? { source: "general", feature: key }
    : { source: key.slice(0, dot), feature: key.slice(dot + 1) };
}

function renderValue(value: unknown): string {
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

function csvCell(value: unknown): string {
  const raw = renderValue(value);
  // Dump-derived text is untrusted. Neutralize spreadsheet formulas before
  // quoting so opening the CSV cannot execute a cell supplied by the image.
  const text = /^\s*[=+\-@]/.test(raw) ? `'${raw}` : raw;
  return `"${text.replace(/"/g, '""')}"`;
}

function download(name: string, mime: string, contents: string) {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function FeatureExplorer({ features }: { features: Record<string, unknown> }) {
  const [query, setQuery] = useState("");
  const rows = useMemo<FeatureRow[]>(
    () => Object.entries(features).sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({
      key,
      ...splitFeature(key),
      value,
    })),
    [features],
  );
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((row) =>
      `${row.key} ${renderValue(row.value)}`.toLowerCase().includes(needle));
  }, [query, rows]);

  const downloadJson = () =>
    download("volmemlyzer-features.json", "application/json", JSON.stringify(features, null, 2));
  const downloadCsv = () => {
    const body = [
      "source,feature,value",
      ...rows.map((row) => [csvCell(row.source), csvCell(row.feature), csvCell(row.value)].join(",")),
    ].join("\n");
    download("volmemlyzer-features.csv", "text/csv;charset=utf-8", body);
  };

  return (
    <Panel
      eyebrow="Feature extraction"
      title={`${rows.length} VolMemLyzer features`}
      className="overflow-hidden"
      right={
        <div className="flex gap-2">
          <button className="btn-ghost text-[11px]" disabled={rows.length === 0} onClick={downloadJson}>
            JSON ↓
          </button>
          <button className="btn-ghost text-[11px]" disabled={rows.length === 0} onClick={downloadCsv}>
            CSV ↓
          </button>
        </div>
      }
    >
      <div className="border-b border-ink-700/60 px-4 py-3">
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Search feature, plugin, or value…"
          className="w-full rounded-md border border-ink-600 bg-ink-950 px-3 py-2 text-[12px] text-mist-100 outline-none placeholder:text-mist-500 focus:border-accent/50"
        />
      </div>
      {filtered.length === 0 ? (
        <EmptyState
          title={rows.length ? "No matching features" : "No extracted features"}
          hint={rows.length ? "Try a different search." : "Feature values appear after triage completes."}
        />
      ) : (
        <div className="max-h-[440px] overflow-auto">
          <table className="w-full text-left text-[12px]">
            <thead className="sticky top-0 bg-ink-850 text-[10px] uppercase tracking-wider text-mist-400">
              <tr className="border-b border-ink-700/60">
                <th className="px-4 py-2">Source</th>
                <th className="px-3 py-2">Feature</th>
                <th className="px-3 py-2">Value</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((row) => (
                <tr key={row.key} className="border-b border-ink-800/70">
                  <td className="whitespace-nowrap px-4 py-2 font-mono text-mist-400">{row.source}</td>
                  <td className="px-3 py-2 font-mono text-mist-200">{row.feature}</td>
                  <td className="max-w-md break-all px-3 py-2 font-mono text-mist-300">
                    {renderValue(row.value)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

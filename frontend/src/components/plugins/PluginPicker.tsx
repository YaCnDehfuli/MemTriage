import { useMemo, useState } from "react";
import type { PluginCatalogEntry } from "../../types";
import { Chip } from "../primitives";

const COST_LABEL: Record<string, string> = { fast: "fast", scan: "scan", heavy: "heavy" };
const COST_TONE: Record<string, string> = {
  fast: "text-mist-400 ring-ink-600",
  scan: "text-risk-medium ring-risk-medium/30",
  heavy: "text-risk-high ring-risk-high/30",
};

export function PluginPicker({
  catalog,
  onRun,
  starting,
  blocked = false,
  blockedReason,
}: {
  catalog: PluginCatalogEntry[];
  onRun: (plugins: string[], concurrency: number) => void;
  starting: boolean;
  blocked?: boolean;
  blockedReason?: string;
}) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [concurrency, setConcurrency] = useState(4);

  const byCategory = useMemo(() => {
    const groups = new Map<string, PluginCatalogEntry[]>();
    for (const entry of catalog) {
      const list = groups.get(entry.category) ?? [];
      list.push(entry);
      groups.set(entry.category, list);
    }
    return [...groups.entries()];
  }, [catalog]);

  const lightSet = useMemo(() => catalog.filter((p) => p.in_light_set).map((p) => p.name),
    [catalog]);
  const deepSet = useMemo(() => catalog.filter((p) => p.in_deep_set).map((p) => p.name),
    [catalog]);

  const toggle = (name: string) =>
    setSelected((cur) => {
      const next = new Set(cur);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const toggleCategory = (entries: PluginCatalogEntry[]) =>
    setSelected((cur) => {
      const names = entries.map((e) => e.name);
      const allOn = names.every((n) => cur.has(n));
      const next = new Set(cur);
      names.forEach((n) => (allOn ? next.delete(n) : next.add(n)));
      return next;
    });

  return (
    <fieldset className="space-y-4 px-4 py-4" disabled={starting || blocked}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="eyebrow">Presets</span>
        <button className="btn-ghost text-xs" onClick={() => setSelected(new Set(lightSet))}>
          Light ({lightSet.length})
        </button>
        <button className="btn-ghost text-xs" onClick={() => setSelected(new Set(deepSet))}>
          Deep ({deepSet.length})
        </button>
        <button className="btn-ghost text-xs"
          onClick={() => setSelected(new Set(catalog.map((p) => p.name)))}>
          Everything ({catalog.length})
        </button>
        <button className="btn-ghost text-xs" onClick={() => setSelected(new Set())}>
          Clear
        </button>
        <span className="ml-auto font-mono text-[11px] text-mist-400">
          {selected.size} selected
        </span>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {byCategory.map(([category, entries]) => {
          const allOn = entries.every((e) => selected.has(e.name));
          return (
            <div key={category} className="rounded-md border border-ink-700/60 bg-ink-900/30">
              <button
                onClick={() => toggleCategory(entries)}
                className="flex w-full items-center justify-between border-b border-ink-700/60 px-3 py-2 text-left"
              >
                <span className="text-[12px] font-semibold text-mist-200">{category}</span>
                <span className="font-mono text-[10px] text-accent">
                  {allOn ? "clear" : "select all"}
                </span>
              </button>
              <ul className="max-h-64 space-y-0.5 overflow-y-auto p-2">
                {entries.map((entry) => (
                  <li key={entry.name}>
                    <label className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-ink-800/60">
                      <input
                        type="checkbox"
                        className="accent-accent"
                        checked={selected.has(entry.name)}
                        onChange={() => toggle(entry.name)}
                      />
                      <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-mist-200">
                        {entry.name}
                      </span>
                      <span
                        className={`shrink-0 rounded px-1 py-0.5 text-[9px] uppercase ring-1 ring-inset ${COST_TONE[entry.cost]}`}
                      >
                        {COST_LABEL[entry.cost]}
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-4 rounded-md border border-ink-700/60 bg-ink-900/30 px-4 py-3">
        <div className="flex items-center gap-3">
          <span className="eyebrow">Concurrency</span>
          <input
            type="range"
            min={1}
            max={8}
            step={1}
            value={concurrency}
            onChange={(e) => setConcurrency(Number(e.target.value))}
            className="w-36 accent-accent"
          />
          <span className="w-24 font-mono text-xs text-mist-300">
            {concurrency === 1 ? "sequential" : `${concurrency} workers`}
          </span>
        </div>
        <p className="text-[11px] text-mist-400">
          Independent plugins in the same dependency batch run at once, up to this many at a time.
        </p>
        <button
          className="btn-accent ml-auto"
          disabled={selected.size === 0 || starting || blocked}
          onClick={() => onRun([...selected], concurrency)}
        >
          {starting ? "Starting…" : blocked ? "Volatility busy…" : `Run ${selected.size || ""} plugin${selected.size === 1 ? "" : "s"} →`}
        </button>
      </div>
      {blockedReason && <p className="text-[11px] text-risk-medium">{blockedReason}</p>}
      {selected.size > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {[...selected].sort().map((n) => (
            <Chip key={n} tone="mono">{n}</Chip>
          ))}
        </div>
      )}
    </fieldset>
  );
}

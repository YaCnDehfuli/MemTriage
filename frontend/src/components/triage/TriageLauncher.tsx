import { useEffect, useMemo, useRef, useState } from "react";
import type { PluginCatalogEntry, TriageMode, TriageOptions } from "../../types";

const COST_TONE: Record<PluginCatalogEntry["cost"], string> = {
  fast: "text-mist-400 ring-ink-600",
  scan: "text-risk-medium ring-risk-medium/30",
  heavy: "text-risk-high ring-risk-high/30",
};

const MODE_COPY: Record<TriageMode, { label: string; hint: string }> = {
  light: { label: "Light", hint: "Fast essentials" },
  deep: { label: "Deep", hint: "Broad evidence" },
  custom: { label: "Custom", hint: "Choose plugins" },
};

function preset(catalog: PluginCatalogEntry[], mode: "light" | "deep"): Set<string> {
  return new Set(
    catalog.filter((entry) => mode === "light" ? entry.in_light_set : entry.in_deep_set)
      .map((entry) => entry.name),
  );
}

export function TriageLauncher({
  catalog,
  disabled,
  disabledLabel,
  starting,
  hasInvestigation,
  onRun,
}: {
  catalog: PluginCatalogEntry[];
  disabled: boolean;
  disabledLabel?: string;
  starting: boolean;
  hasInvestigation: boolean;
  onRun(options: TriageOptions): Promise<void>;
}) {
  const [mode, setMode] = useState<TriageMode>("light");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [concurrency, setConcurrency] = useState(4);
  const [force, setForce] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    if (!initialized.current && catalog.length > 0) {
      initialized.current = true;
      setSelected(preset(catalog, "light"));
    }
  }, [catalog]);

  const byCategory = useMemo(() => {
    const groups = new Map<string, PluginCatalogEntry[]>();
    for (const entry of catalog) {
      const entries = groups.get(entry.category) ?? [];
      entries.push(entry);
      groups.set(entry.category, entries);
    }
    return [...groups.entries()];
  }, [catalog]);

  const chooseMode = (next: TriageMode) => {
    setMode(next);
    if (next === "light" || next === "deep") setSelected(preset(catalog, next));
  };

  const toggle = (name: string) => {
    setMode("custom");
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const toggleCategory = (entries: PluginCatalogEntry[]) => {
    setMode("custom");
    setSelected((current) => {
      const next = new Set(current);
      const allSelected = entries.every((entry) => next.has(entry.name));
      for (const entry of entries) {
        if (allSelected) next.delete(entry.name);
        else next.add(entry.name);
      }
      return next;
    });
  };

  const locked = disabled || starting;

  return (
    <div className="space-y-4 px-4 py-4">
      <div className="grid gap-2 sm:grid-cols-3">
        {(Object.keys(MODE_COPY) as TriageMode[]).map((choice) => (
          <button
            key={choice}
            type="button"
            disabled={locked}
            onClick={() => chooseMode(choice)}
            className={`rounded-md border px-3 py-3 text-left transition-colors disabled:opacity-50 ${
              mode === choice
                ? "border-accent/40 bg-accent/10 ring-1 ring-inset ring-accent/20"
                : "border-ink-700/60 bg-ink-900/30 hover:bg-ink-800/60"
            }`}
          >
            <span className={`block text-sm font-semibold ${mode === choice ? "text-accent" : "text-mist-200"}`}>
              {MODE_COPY[choice].label}
            </span>
            <span className="mt-0.5 block text-[11px] text-mist-400">
              {MODE_COPY[choice].hint}
              {choice !== "custom" && ` · ${preset(catalog, choice).size} plugins`}
            </span>
          </button>
        ))}
      </div>

      <details className="rounded-md border border-ink-700/60 bg-ink-900/20" open={mode === "custom"}>
        <summary className="cursor-pointer px-3 py-2.5 text-[12px] font-medium text-mist-200">
          Plugin selection <span className="ml-2 font-mono text-mist-400">{selected.size} selected</span>
        </summary>
        <div className="grid gap-3 border-t border-ink-700/60 p-3 sm:grid-cols-2 lg:grid-cols-3">
          {byCategory.map(([category, entries]) => {
            const allSelected = entries.every((entry) => selected.has(entry.name));
            return (
              <div key={category} className="rounded-md border border-ink-700/60 bg-ink-950/30">
                <button
                  type="button"
                  disabled={locked}
                  onClick={() => toggleCategory(entries)}
                  className="flex w-full items-center justify-between border-b border-ink-700/60 px-3 py-2 text-left disabled:opacity-50"
                >
                  <span className="text-[12px] font-semibold text-mist-200">{category}</span>
                  <span className="font-mono text-[10px] text-accent">
                    {allSelected ? "clear" : "select all"}
                  </span>
                </button>
                <ul className="max-h-52 overflow-y-auto p-2">
                  {entries.map((entry) => (
                    <li key={entry.name}>
                      <label className="flex items-center gap-2 rounded px-1.5 py-1 hover:bg-ink-800/60">
                        <input
                          type="checkbox"
                          className="accent-accent"
                          checked={selected.has(entry.name)}
                          disabled={locked}
                          onChange={() => toggle(entry.name)}
                        />
                        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-mist-200">
                          {entry.name}
                        </span>
                        <span className={`rounded px-1 py-0.5 text-[9px] uppercase ring-1 ring-inset ${COST_TONE[entry.cost]}`}>
                          {entry.cost}
                        </span>
                      </label>
                      {entry.deps.length > 0 && (
                        <div className="pb-1 pl-7 font-mono text-[9px] text-mist-500">
                          needs {entry.deps.join(", ")}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      </details>

      <div className="grid gap-4 rounded-md border border-ink-700/60 bg-ink-900/30 p-3 lg:grid-cols-[1fr_1fr_auto] lg:items-end">
        <label className="block">
          <span className="eyebrow">Concurrency</span>
          <div className="mt-2 flex items-center gap-3">
            <input
              type="range"
              min={1}
              max={8}
              step={1}
              value={concurrency}
              disabled={locked}
              onChange={(event) => setConcurrency(Number(event.target.value))}
              className="w-36 accent-accent"
            />
            <span className="font-mono text-xs text-mist-300">
              {concurrency === 1 ? "sequential" : `${concurrency} workers`}
            </span>
          </div>
        </label>

        <div>
          <div className="eyebrow">Artifact policy</div>
          <div className="mt-2 flex gap-2">
            <button
              type="button"
              disabled={locked}
              className={force ? "btn-ghost text-xs" : "btn-accent text-xs"}
              onClick={() => setForce(false)}
            >
              Prefer cache
            </button>
            <button
              type="button"
              disabled={locked}
              className={force ? "btn-accent text-xs" : "btn-ghost text-xs"}
              onClick={() => setForce(true)}
            >
              Force refresh
            </button>
          </div>
          <p className="mt-1.5 text-[10px] text-mist-400">
            {force ? "Ignore compatible cached analysis and rerun Volatility." : "Reuse compatible analysis and run only missing work."}
          </p>
        </div>

        <button
          className="btn-accent justify-center"
          disabled={locked || !hasInvestigation || selected.size === 0}
          onClick={() => onRun({ mode, plugins: [...selected], concurrency, force })}
        >
          {starting ? "Starting…" : disabled ? (disabledLabel ?? "Triage running…") : `Run ${MODE_COPY[mode].label} triage →`}
        </button>
      </div>

      {!hasInvestigation && (
        <p className="text-[11px] text-risk-medium">Upload at least one memory image before starting triage.</p>
      )}
      {mode === "custom" && selected.size > 0 && !selected.has("pslist") && (
        <p className="text-[11px] text-risk-medium">
          This selection omits pslist, so guided triage cannot build the process inventory or deep-dive targets.
          Omitted plugins also leave their feature families unavailable.
        </p>
      )}
    </div>
  );
}

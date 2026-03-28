import { useState } from "react";
import type { TuningProfile } from "../../types";

const PRESETS: { id: TuningProfile["preset"]; label: string; hint: string }[] = [
  { id: "conservative", label: "Conservative", hint: "High-confidence only" },
  { id: "balanced", label: "Balanced", hint: "Research-backed default" },
  { id: "aggressive", label: "Aggressive", hint: "Surface weak signals" },
];

export function TuningBar({
  profile,
  onChange,
}: {
  profile: TuningProfile | null;
  onChange: (patch: Partial<TuningProfile>) => void;
}) {
  const [advanced, setAdvanced] = useState(false);
  const preset = profile?.preset ?? "balanced";

  return (
    <div className="border-b border-ink-700/60 bg-ink-900/40 px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <span className="eyebrow">Sensitivity</span>
        <div className="flex rounded-md bg-ink-850 p-0.5 ring-1 ring-inset ring-ink-600">
          {PRESETS.map((p) => (
            <button
              key={p.id}
              title={p.hint}
              onClick={() => onChange({ preset: p.id })}
              className={`rounded px-3 py-1.5 text-xs font-medium transition-colors ${
                preset === p.id ? "bg-accent/20 text-accent" : "text-mist-400 hover:text-mist-200"
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        <label className="ml-1 flex items-center gap-2 text-xs text-mist-300">
          <input
            type="checkbox"
            className="accent-accent"
            checked={profile?.require_correlation ?? false}
            onChange={(e) => onChange({ preset, require_correlation: e.target.checked })}
          />
          Require correlation
        </label>

        <button className="btn-ghost ml-auto text-xs" onClick={() => setAdvanced((v) => !v)}>
          {advanced ? "Hide" : "Advanced"} controls
        </button>
      </div>

      {advanced && profile && (
        <div className="mt-3 grid gap-4 rounded-md border border-ink-700/50 bg-ink-850/50 p-3 sm:grid-cols-2">
          <div>
            <div className="eyebrow mb-2">Confidence floor</div>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={0}
                max={0.9}
                step={0.05}
                value={profile.confidence_floor}
                onChange={(e) =>
                  onChange({ preset, confidence_floor: Number(e.target.value) })
                }
                className="w-full accent-accent"
              />
              <span className="w-12 text-right font-mono text-xs text-mist-300">
                {(profile.confidence_floor * 100).toFixed(0)}%
              </span>
            </div>
            <p className="mt-1 text-[11px] text-mist-400">
              Suppress objects whose corroborated confidence is below this.
            </p>
          </div>
          <div>
            <div className="eyebrow mb-2">Risk-band cut-offs</div>
            <div className="flex flex-wrap gap-2 font-mono text-[11px] text-mist-300">
              {Object.entries(profile.risk_bands).map(([k, v]) => (
                <span key={k} className="rounded bg-ink-800 px-2 py-1 ring-1 ring-inset ring-ink-600">
                  {k} ≥ {v}
                </span>
              ))}
            </div>
            <p className="mt-1 text-[11px] text-mist-400">
              Per-category surfacing thresholds & rule weights re-score from cache — no
              Volatility re-run.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

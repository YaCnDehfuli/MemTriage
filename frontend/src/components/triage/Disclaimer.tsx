import { useState } from "react";
import type { TriageDisclaimer } from "../../types";

const FALLBACK: TriageDisclaimer = {
  headline: "Clues for review, not conclusions.",
  summary:
    "Phase 1 extracts structured, statistically significant features from the image " +
    "and applies simple, tuned rules to them. Everything it surfaces is a lead for an " +
    "analyst to confirm or dismiss — not an established fact, a detection, or an " +
    "attribution.",
  points: [],
  intent: "",
};

/**
 * Phase 1's boundary, stated where the findings are read rather than in a footer.
 * The text comes from the backend so the API, the UI and the export cannot drift.
 */
export function TriageDisclaimer({ disclaimer }: { disclaimer?: TriageDisclaimer | null }) {
  const [open, setOpen] = useState(false);
  const d = disclaimer ?? FALLBACK;
  return (
    <div className="rounded-lg border border-accent/25 bg-accent/5 px-4 py-3">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className="text-[13px] font-semibold text-accent">{d.headline}</span>
        <span className="min-w-0 flex-1 text-[12px] text-mist-300">{d.summary}</span>
        {(d.points?.length ?? 0) > 0 && (
          <button className="btn-ghost shrink-0 text-[11px]" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide detail" : "What this means"}
          </button>
        )}
      </div>
      {open && (
        <>
          <ul className="mt-3 space-y-1.5">
            {d.points.map((point) => (
              <li key={point} className="flex gap-2 text-[12px] text-mist-300">
                <span aria-hidden className="mt-0.5 text-mist-400">·</span>
                <span>{point}</span>
              </li>
            ))}
          </ul>
          {d.intent && <p className="mt-2 text-[12px] text-mist-400">{d.intent}</p>}
        </>
      )}
    </div>
  );
}

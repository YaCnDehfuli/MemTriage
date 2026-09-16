import {
  NARRATIVE_HINT,
  NARRATIVE_LABEL,
  NARRATIVE_SECTIONS,
  useReport,
} from "../../state/reportStore";

/**
 * The narrative slots. The structure is fixed by the tool — the analyst supplies
 * words for it, never headings of their own. That is what keeps every generated
 * report the same professional shape.
 */
export function NarrativePanel() {
  const { narrative, setNarrative } = useReport();

  return (
    <div className="space-y-4">
      {NARRATIVE_SECTIONS.map((section) => {
        const entry = narrative[section];
        return (
          <div key={section} className="rounded border border-surface-700 bg-surface-900 p-3">
            <div className="flex items-baseline justify-between gap-3">
              <label
                htmlFor={`narrative-${section}`}
                className="text-[13px] font-medium text-ink-100"
              >
                {NARRATIVE_LABEL[section]}
              </label>
              {entry?.source === "drafted" && (
                <span className="text-[10px] uppercase tracking-wide text-accent-soft">
                  drafted · analyst-reviewed
                </span>
              )}
            </div>
            <p className="mt-0.5 text-[11px] text-ink-400">{NARRATIVE_HINT[section]}</p>
            <textarea
              id={`narrative-${section}`}
              className="mt-2 w-full rounded border border-surface-600 bg-surface-950 px-2 py-1.5 text-[12px] leading-relaxed text-ink-200"
              rows={section === "examiner_info" ? 2 : 5}
              value={entry?.content ?? ""}
              onChange={(e) => setNarrative(section, e.target.value)}
            />
          </div>
        );
      })}
    </div>
  );
}

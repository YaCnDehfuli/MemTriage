import { useEffect, useRef, useState } from "react";
import { useReport } from "../../state/reportStore";
import type { EvidenceKind } from "../../types";

type Feedback = { tone: "ok" | "error"; text: string } | null;

const FEEDBACK_MS = 2500;

/**
 * Pin a piece of evidence to the report, from wherever the analyst is looking
 * at it.
 *
 * Selecting evidence belongs on the page that shows it — the scored table, the
 * process inventory, a region's disassembly — not on a Report page that
 * re-lists everything. Pinned items are what the report's narrative is built
 * around; the full scored set still appears in the document on its own, so
 * pinning nothing never produces an empty report.
 *
 * Every click answers: the star shows it is saving, then says it was added or
 * removed, or says why it failed. A silent control is indistinguishable from a
 * broken one.
 *
 * The note is written here too. Pinning opens a small box anchored to the star,
 * so the analyst records what the evidence means while still looking at it —
 * rather than losing the thread of the ranked findings and rebuilding the
 * context later on the Report page. The same note field is still editable there;
 * this is the second entry point to one value, not a second value.
 */
export function EvidenceToggle({
  evidenceKind = "finding",
  evidenceRef,
  label,
  pid = null,
  compact = false,
}: {
  evidenceKind?: EvidenceKind;
  evidenceRef: string;
  label: string;
  pid?: number | null;
  compact?: boolean;
}) {
  const { evidenceByRef, pin, unpin, setNote } = useReport();
  const row = evidenceByRef.get(evidenceRef);
  const pinned = Boolean(row);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [noteOpen, setNoteOpen] = useState(false);
  const wrapRef = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (feedback?.tone !== "ok") return;
    const timer = window.setTimeout(() => setFeedback(null), FEEDBACK_MS);
    return () => window.clearTimeout(timer);
  }, [feedback]);

  // Dismiss on Escape or a click elsewhere. The note itself is already saved by
  // then — setNote writes through on a debounce — so closing never discards it.
  useEffect(() => {
    if (!noteOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setNoteOpen(false);
    };
    const onDown = (e: MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) setNoteOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onDown);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onDown);
    };
  }, [noteOpen]);

  const toggle = async () => {
    // A pinned star opens its note instead of silently unpinning: the note is
    // the reason most analysts click it a second time, and losing written text
    // to a stray click is worse than needing one more click to remove.
    if (pinned && !noteOpen) {
      setNoteOpen(true);
      return;
    }
    setBusy(true);
    setFeedback(null);
    const failure = pinned && row
      ? await unpin(row.id)
      : await pin({ evidenceKind, ref: evidenceRef, label, pid });
    setBusy(false);
    setNoteOpen(!failure && !pinned);
    setFeedback(failure
      ? { tone: "error", text: `Not saved: ${failure}` }
      : { tone: "ok", text: pinned ? "Removed from report" : "Added to report" });
  };

  return (
    <span ref={wrapRef} className="relative inline-flex shrink-0 items-center gap-1.5">
      {feedback && (
        <span
          role={feedback.tone === "error" ? "alert" : "status"}
          title={feedback.text}
          className={`max-w-[12rem] truncate text-[11px] ${
            feedback.tone === "error" ? "text-risk-critical" : "text-accent-soft"
          }`}
        >
          {feedback.text}
        </span>
      )}
      <button
        type="button"
        aria-pressed={pinned}
        aria-busy={busy}
        aria-expanded={pinned ? noteOpen : undefined}
        disabled={busy}
        title={pinned ? `Note on ${label}` : `Add ${label} to report`}
        onClick={(e) => {
          e.stopPropagation();
          void toggle();
        }}
        className={`btn-ghost shrink-0 ${compact ? "px-1.5 py-0.5 text-[11px]" : "text-xs"} ${
          pinned ? "text-accent-soft" : "text-ink-400"
        }`}
      >
        <span aria-hidden className={busy ? "animate-pulse" : undefined}>{pinned ? "★" : "☆"}</span>
        {!compact && <span className="ml-1">{busy ? "Saving…" : pinned ? "In report" : "Add"}</span>}
      </button>

      {noteOpen && pinned && (
        <div
          role="group"
          aria-label={`Note on ${label}`}
          className="absolute right-0 top-full z-30 mt-1 w-64 rounded-md border border-surface-600 bg-surface-900 p-2 shadow-lg"
        >
          <textarea
            autoFocus
            rows={3}
            value={row?.analyst_note ?? ""}
            onChange={(e) => setNote(evidenceRef, label, e.target.value)}
            placeholder="What this means here — the parent process, whether it is expected on this host, what would confirm it."
            className="w-full resize-y rounded border border-surface-600 bg-surface-950 px-2 py-1 text-[12px] text-ink-200 placeholder:text-ink-400 focus:border-accent/50 focus:outline-none"
          />
          <div className="mt-1.5 flex items-center justify-between">
            <button
              type="button"
              className="btn-ghost text-[11px] text-risk-critical"
              onClick={() => {
                setNoteOpen(false);
                void toggle();
              }}
            >
              Remove from report
            </button>
            <button
              type="button"
              className="btn-ghost text-[11px]"
              onClick={() => setNoteOpen(false)}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </span>
  );
}

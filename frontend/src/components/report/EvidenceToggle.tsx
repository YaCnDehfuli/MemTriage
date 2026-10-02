import { useCallback, useEffect, useId, useRef, useState } from "react";
import { useReport } from "../../state/reportStore";
import type { EvidenceKind } from "../../types";
import { EvidenceNoteEditor } from "./EvidenceNoteEditor";

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
 * The note is written here too. Pinning opens a writing panel near the star,
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
  const { evidenceByRef, pin, unpin, setNote, saving, error } = useReport();
  const row = evidenceByRef.get(evidenceRef);
  const pinned = Boolean(row);
  const [busy, setBusy] = useState(false);
  const [feedback, setFeedback] = useState<Feedback>(null);
  const [noteOpen, setNoteOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const editorId = useId();
  const closeNote = useCallback(() => setNoteOpen(false), []);

  useEffect(() => {
    if (feedback?.tone !== "ok") return;
    const timer = window.setTimeout(() => setFeedback(null), FEEDBACK_MS);
    return () => window.clearTimeout(timer);
  }, [feedback]);

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
    <span className="relative inline-flex shrink-0 items-center gap-1.5">
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
        ref={buttonRef}
        type="button"
        aria-pressed={pinned}
        aria-busy={busy}
        aria-expanded={pinned ? noteOpen : undefined}
        aria-haspopup="dialog"
        aria-controls={noteOpen ? editorId : undefined}
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
        <EvidenceNoteEditor
          id={editorId}
          anchor={buttonRef}
          label={label}
          note={row?.analyst_note ?? ""}
          saving={saving > 0}
          error={error}
          busy={busy}
          onChange={(value) => setNote(evidenceRef, label, value)}
          onClose={closeNote}
          onRemove={() => void toggle()}
        />
      )}
    </span>
  );
}

import { useLayoutEffect, useRef, useState, type RefObject } from "react";
import { createPortal } from "react-dom";

import { NoteTextarea } from "./NoteTextarea";

/** Render outside tables and scrolling panels so the editor cannot be clipped. */
export function EvidenceNoteEditor({
  id,
  anchor,
  label,
  note,
  saving,
  error,
  busy,
  onChange,
  onClose,
  onRemove,
}: {
  id: string;
  anchor: RefObject<HTMLButtonElement>;
  label: string;
  note: string;
  saving: boolean;
  error: string | null;
  busy: boolean;
  onChange: (value: string) => void;
  onClose: () => void;
  onRemove: () => void;
}) {
  const panelRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState({ top: 12, left: 12 });

  useLayoutEffect(() => {
    const panel = panelRef.current;
    const button = anchor.current;
    if (!panel || !button) return;
    const place = () => {
      const bounds = button.getBoundingClientRect();
      const width = panel.offsetWidth;
      const height = panel.offsetHeight;
      const below = bounds.bottom + 10;
      const above = bounds.top - height - 10;
      const top = below + height <= window.innerHeight - 12 ? below : above;
      setPosition({
        top: Math.max(12, Math.min(top, window.innerHeight - height - 12)),
        left: Math.max(12, Math.min(bounds.right - width, window.innerWidth - width - 12)),
      });
    };
    const observer = new ResizeObserver(place);
    observer.observe(panel);
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [anchor]);

  useLayoutEffect(() => {
    const onDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!panelRef.current?.contains(target) && !anchor.current?.contains(target)) onClose();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      onClose();
      anchor.current?.focus();
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [anchor, onClose]);

  return createPortal(
    <div
      ref={panelRef}
      id={id}
      role="dialog"
      aria-modal="false"
      aria-labelledby={`${id}-title`}
      className="fixed z-[60] flex max-h-[calc(100dvh-24px)] w-[min(512px,calc(100vw-24px))] flex-col overflow-hidden rounded-lg border border-surface-600 bg-surface-900 text-left shadow-xl"
      style={position}
      onClick={(event) => event.stopPropagation()}
    >
      <div className="shrink-0 border-b border-surface-700 px-3 py-2">
        <h2 id={`${id}-title`} className="text-sm font-semibold text-ink-100">Evidence note</h2>
        <p className="mt-1 truncate font-mono text-[12px] text-ink-400" title={label}>{label}</p>
      </div>
      <div className="min-h-0 overflow-y-auto p-3">
        <NoteTextarea
          label={`Note on ${label}`}
          autoFocus
          rows={6}
          value={note}
          onChange={onChange}
          placeholder="Record the observation, its significance, and what supports or limits the interpretation."
        />
      </div>
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-t border-surface-700 px-3 py-2">
        <button type="button" disabled={busy} className="btn-ghost text-xs text-risk-critical" onClick={onRemove}>
          Remove from report
        </button>
        <span role={error ? "alert" : "status"} className={`min-w-0 flex-1 text-[12px] ${error ? "text-risk-critical" : "text-ink-400"}`}>
          {error || (saving ? "Saving…" : "Notes save automatically")}
        </span>
        <button
          type="button"
          className="btn-accent text-sm"
          onClick={() => {
            onClose();
            anchor.current?.focus();
          }}
        >
          Done
        </button>
      </div>
    </div>,
    document.body,
  );
}

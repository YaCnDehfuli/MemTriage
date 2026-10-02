import { useLayoutEffect, useRef } from "react";

/** A writing field that expands before it asks the analyst to scroll. */
export function NoteTextarea({
  value,
  onChange,
  label,
  placeholder,
  autoFocus = false,
  rows = 4,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  placeholder: string;
  autoFocus?: boolean;
  rows?: number;
}) {
  const ref = useRef<HTMLTextAreaElement>(null);

  useLayoutEffect(() => {
    const field = ref.current;
    if (!field) return;
    const resize = () => {
      const previousScroll = field.scrollTop;
      const style = window.getComputedStyle(field);
      const padding = parseFloat(style.paddingTop) + parseFloat(style.paddingBottom) + 2;
      const limit = Math.min(280, window.innerHeight * 0.4);
      const minimum = Math.min(rows * parseFloat(style.lineHeight) + padding, limit);
      field.style.height = "0px";
      field.style.height = `${Math.min(Math.max(field.scrollHeight, minimum), limit)}px`;
      field.scrollTop = previousScroll;
    };
    resize();
    let width = field.clientWidth;
    const observer = new ResizeObserver(() => {
      if (field.clientWidth === width) return;
      width = field.clientWidth;
      resize();
    });
    observer.observe(field);
    window.addEventListener("resize", resize);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", resize);
    };
  }, [value, rows]);

  return (
    <textarea
      ref={ref}
      aria-label={label}
      autoFocus={autoFocus}
      rows={rows}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      placeholder={placeholder}
      className="note-textarea block w-full resize-none rounded-lg border border-surface-600 bg-surface-950 px-3 py-3 text-left text-[14px] font-normal leading-6 text-ink-200 placeholder:text-ink-400 focus:border-accent"
    />
  );
}

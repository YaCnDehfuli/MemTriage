import { useEffect, useRef, type KeyboardEvent as ReactKeyboardEvent } from "react";

/**
 * Correct ARIA tablist semantics + arrow-key roving focus for a horizontal
 * tab strip, without pulling in a component library for it.
 */
export function useRovingTabs<T extends string>(
  ids: readonly T[],
  active: T,
  setActive: (id: T) => void,
  scope: string,
) {
  const refs = useRef<Partial<Record<T, HTMLButtonElement | null>>>({});

  const move = (next: T) => {
    setActive(next);
    refs.current[next]?.focus();
  };

  const getTabProps = (id: T) => ({
    ref: (el: HTMLButtonElement | null) => {
      refs.current[id] = el;
    },
    role: "tab" as const,
    id: `${scope}-tab-${id}`,
    "aria-selected": active === id,
    "aria-controls": `${scope}-panel-${id}`,
    tabIndex: active === id ? 0 : -1,
    onClick: () => setActive(id),
    onKeyDown: (e: ReactKeyboardEvent) => {
      const idx = ids.indexOf(active);
      if (e.key === "ArrowRight" || e.key === "ArrowDown") {
        e.preventDefault();
        move(ids[(idx + 1) % ids.length]);
      } else if (e.key === "ArrowLeft" || e.key === "ArrowUp") {
        e.preventDefault();
        move(ids[(idx - 1 + ids.length) % ids.length]);
      } else if (e.key === "Home") {
        e.preventDefault();
        move(ids[0]);
      } else if (e.key === "End") {
        e.preventDefault();
        move(ids[ids.length - 1]);
      }
    },
  });

  const tabListProps = { role: "tablist" as const };

  const getPanelProps = (id: T) => ({
    role: "tabpanel" as const,
    id: `${scope}-panel-${id}`,
    "aria-labelledby": `${scope}-tab-${id}`,
  });

  return { getTabProps, tabListProps, getPanelProps };
}

const FOCUSABLE = 'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

/**
 * Traps Tab focus inside a dialog while it's open, moves focus in on open,
 * restores it to the trigger on close, and closes on Escape. Attach the
 * returned ref to the dialog's outermost element.
 */
export function useFocusTrap<T extends HTMLElement>(active: boolean, onClose?: () => void) {
  const ref = useRef<T>(null);
  const triggerRef = useRef<Element | null>(null);

  useEffect(() => {
    if (!active) return;
    triggerRef.current = document.activeElement;
    const container = ref.current;
    const focusable = () => Array.from(container?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? []);
    focusable()[0]?.focus();

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && onClose) {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const items = focusable();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      (triggerRef.current as HTMLElement | null)?.focus?.();
    };
  }, [active, onClose]);

  return ref;
}

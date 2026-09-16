import type { ReactNode } from "react";
import type { Risk } from "../types";

const RISK_CLASS: Record<string, string> = {
  Critical: "bg-risk-critical/15 text-risk-critical ring-risk-critical/30",
  High: "bg-risk-high/15 text-risk-high ring-risk-high/30",
  Medium: "bg-risk-medium/15 text-risk-medium ring-risk-medium/30",
  Low: "bg-risk-low/15 text-risk-low ring-risk-low/30",
};

export function RiskBadge({ risk }: { risk: Risk | null | undefined }) {
  const cls = RISK_CLASS[risk ?? ""] ?? "bg-risk-none/15 text-risk-none ring-risk-none/30";
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ring-inset ${cls}`}
    >
      {risk ?? "—"}
    </span>
  );
}

export function Chip({ children, tone = "default" }: { children: ReactNode; tone?: "default" | "accent" | "mono" }) {
  const cls =
    tone === "accent"
      ? "bg-accent/10 text-accent-soft ring-accent/25"
      : tone === "mono"
        ? "bg-surface-800 text-ink-300 ring-surface-600 font-mono text-[11px]"
        : "bg-surface-800 text-ink-300 ring-surface-600";
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] ring-1 ring-inset ${cls}`}>
      {children}
    </span>
  );
}

/**
 * `risk` scales hue with severity and must stay reserved for values that are
 * actually risk scores. `neutral` is for confidence/attention: magnitude
 * shown as intensity of one hue, not borrowed severity color. `progress`
 * exposes real progressbar semantics — pass it only for literal job/upload
 * completion, not for confidence or attention measurements.
 */
export function Meter({
  value,
  tone = "accent",
  progress = false,
  label,
}: {
  value: number;
  tone?: "accent" | "risk" | "neutral";
  progress?: boolean;
  label?: string;
}) {
  const pctv = Math.max(0, Math.min(1, value)) * 100;
  const color =
    tone === "risk"
      ? value > 0.8
        ? "bg-risk-critical"
        : value > 0.6
          ? "bg-risk-high"
          : "bg-risk-medium"
      : tone === "neutral"
        ? "bg-ink-300"
        : "bg-accent";
  return (
    <div
      className="h-1.5 w-full overflow-hidden rounded-full bg-surface-700"
      role={progress ? "progressbar" : undefined}
      aria-valuemin={progress ? 0 : undefined}
      aria-valuemax={progress ? 100 : undefined}
      aria-valuenow={progress ? Math.round(pctv) : undefined}
      aria-label={progress ? label : undefined}
    >
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pctv}%` }} />
    </div>
  );
}

export function Panel({
  title,
  eyebrow,
  right,
  children,
  className = "",
}: {
  title?: string;
  eyebrow?: string;
  right?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || right) && (
        <header className="panel-head">
          <div>
            {eyebrow && <div className="eyebrow">{eyebrow}</div>}
            {title && <h2 className="text-sm font-semibold text-ink-100">{title}</h2>}
          </div>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function EmptyState({ icon = "◈", title, hint }: { icon?: string; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      <div className="text-2xl text-surface-500">{icon}</div>
      <div className="text-sm font-medium text-ink-300">{title}</div>
      {hint && <div className="max-w-sm text-xs text-ink-400">{hint}</div>}
    </div>
  );
}

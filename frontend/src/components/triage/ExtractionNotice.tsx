import { useState } from "react";
import type { ExtractionHealth } from "../../types";

/**
 * When Volatility could not run, the dashboard is empty for a reason that has
 * nothing to do with the image. Without this the two look identical, and an
 * empty result reads as a clean one.
 */
export function ExtractionNotice({ health }: { health?: ExtractionHealth | null }) {
  const [open, setOpen] = useState(false);
  if (!health || !health.degraded) return null;

  const critical = health.severity === "critical";
  const failed = Object.entries(health.failed_plugins ?? {});

  return (
    <div
      role="alert"
      className={`rounded-lg px-4 py-3 ring-1 ring-inset ${
        critical
          ? "bg-risk-critical/10 ring-risk-critical/30"
          : "bg-risk-medium/10 ring-risk-medium/30"
      }`}
    >
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span
          className={`text-[13px] font-semibold ${
            critical ? "text-risk-critical" : "text-risk-medium"
          }`}
        >
          {critical ? "Extraction failed — these results are not trustworthy" : "Partial extraction"}
        </span>
        <span className="min-w-0 flex-1 text-[12px] text-mist-300">{health.message}</span>
        {failed.length > 0 && (
          <button className="btn-ghost shrink-0 text-[11px]" onClick={() => setOpen((v) => !v)}>
            {open ? "Hide plugins" : `${failed.length} plugin${failed.length > 1 ? "s" : ""}`}
          </button>
        )}
      </div>

      {critical && (
        <p className="mt-2 text-[12px] text-mist-300">
          An empty dashboard here means Volatility produced nothing, not that the image is
          clean. Do not read the absence of findings as a result.
        </p>
      )}

      {open && failed.length > 0 && (
        <ul className="mt-3 space-y-1">
          {failed.map(([name, why]) => (
            <li key={name} className="flex gap-2 font-mono text-[11px]">
              <span className="shrink-0 text-mist-200">{name}</span>
              <span className="min-w-0 break-all text-mist-400">{why}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

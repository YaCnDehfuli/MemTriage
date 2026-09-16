import { useState } from "react";

import { useApp } from "../../state/store";

type Audience = "technical" | "executive";

/**
 * The preview is an iframe of the *same* document the export serves — not a
 * React re-render of its JSON. Two renderers over one data source drift; this
 * cannot, because there is only one renderer.
 */
export function ReportPreview() {
  const { client, investigationId } = useApp();
  const [audience, setAudience] = useState<Audience>("technical");

  if (!investigationId) return null;
  const src = client.reportHtmlUrl(investigationId, audience);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex rounded border border-surface-600">
          {(["technical", "executive"] as Audience[]).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={audience === value}
              onClick={() => setAudience(value)}
              className={`px-3 py-1 text-[12px] capitalize ${
                audience === value
                  ? "bg-surface-800 text-ink-100"
                  : "text-ink-400 hover:text-ink-200"
              }`}
            >
              {value}
            </button>
          ))}
        </div>
        <a className="btn-accent text-xs" href={src} target="_blank" rel="noreferrer">
          Open for printing
        </a>
        <span className="text-[11px] text-ink-400">
          Print → Save as PDF. Untick “Headers and footers”, tick “Background graphics”.
        </span>
      </div>

      <iframe
        title={`${audience} report preview`}
        src={src}
        className="h-[70vh] w-full rounded border border-surface-700 bg-white"
      />
    </div>
  );
}

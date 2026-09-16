import { Fragment, useState } from "react";
import type { Diff, ScoredObject } from "../../types";
import { Chip, Meter, RiskBadge } from "../primitives";
import { pct } from "../../lib/format";
import { EvidenceToggle } from "../report/EvidenceToggle";
import { useReport } from "../../state/reportStore";

const TYPE_LABEL: Record<string, string> = {
  process: "Process",
  injection: "Injection",
  connection: "Connection",
  persistence: "Persistence",
};

export function IoCTable({
  objects,
  diff,
  onInspectProcess,
}: {
  objects: ScoredObject[];
  diff: Diff | null;
  onInspectProcess?: (pid: number) => void;
}) {
  const [open, setOpen] = useState<string | null>(
    objects[0] ? `${objects[0].object_type}|${objects[0].key}` : null,
  );
  const changed = new Set((diff?.changed ?? []).map((c) => `${c.object_type}|${c.key}`));
  const appeared = new Set((diff?.appeared ?? []).map((c) => `${c.object_type}|${c.key}`));

  if (!objects.length)
    return (
      <div className="px-4 py-10 text-center text-sm text-ink-400">
        No indicators cross the current thresholds. Loosen the sensitivity to surface weaker
        signals.
      </div>
    );

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-surface-700/60 text-left text-[11px] uppercase tracking-wider text-ink-400">
            <th className="px-4 py-2 font-semibold">Object</th>
            <th className="px-3 py-2 font-semibold">Type</th>
            <th className="px-3 py-2 font-semibold">Risk</th>
            <th className="px-3 py-2 font-semibold">Score</th>
            <th className="w-40 px-3 py-2 font-semibold">Confidence</th>
            <th className="px-3 py-2 font-semibold">ATT&CK</th>
            <th className="w-10 px-3 py-2 font-semibold">
              <span className="sr-only">Add to report</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {objects.map((o) => {
            const id = `${o.object_type}|${o.key}`;
            const isOpen = open === id;
            return (
              <Fragment key={id}>
                <tr
                  className={`border-b border-surface-800/70 transition-colors hover:bg-surface-800/50 ${
                    isOpen ? "bg-surface-800/40" : ""
                  }`}
                >
                  <td className="px-4 py-2.5">
                    <button
                      type="button"
                      aria-expanded={isOpen}
                      aria-controls={`ioc-detail-${id}`}
                      onClick={() => setOpen(isOpen ? null : id)}
                      className="flex w-full items-center gap-2 rounded text-left"
                    >
                      <span className={`text-surface-500 transition-transform ${isOpen ? "rotate-90" : ""}`}>
                        ›
                      </span>
                      <span className="font-mono text-[13px] text-ink-100">{o.label}</span>
                      {appeared.has(id) && <Chip tone="accent">new</Chip>}
                      {changed.has(id) && <Chip tone="accent">changed</Chip>}
                    </button>
                  </td>
                  <td className="px-3 py-2.5 text-[12px] text-ink-300">
                    {TYPE_LABEL[o.object_type]}
                  </td>
                  <td className="px-3 py-2.5">
                    <RiskBadge risk={o.risk} />
                  </td>
                  <td className="px-3 py-2.5 font-mono text-[13px] text-ink-200">
                    {o.score_max != null
                      ? `${Math.round(o.score)}/${o.score_max}`
                      : o.score.toFixed(1)}
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex items-center gap-2">
                      <Meter value={o.confidence} tone="neutral" />
                      <span className="w-11 shrink-0 text-right font-mono text-[11px] text-ink-400">
                        {pct(o.confidence)}
                      </span>
                    </div>
                  </td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {o.techniques.slice(0, 3).map((t) => (
                        <Chip key={t} tone="mono">
                          {t}
                        </Chip>
                      ))}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-right">
                    <ReportPin objectType={o.object_type} objectKey={o.key} label={o.label} pid={o.pid} />
                  </td>
                </tr>
                {isOpen && (
                  <tr id={`ioc-detail-${id}`} className="border-b border-surface-800/70 bg-surface-900/40">
                    <td colSpan={7} className="px-4 py-3">
                      <div className="mb-2 flex items-center justify-between">
                        <div className="eyebrow">Why this fired — {o.contributions.length} signal(s)</div>
                        {o.pid != null && onInspectProcess && o.object_type === "process" && (
                          <button className="btn-accent" onClick={() => onInspectProcess(o.pid!)}>
                            Deep-dive PID {o.pid}
                          </button>
                        )}
                      </div>
                      <div className="space-y-1.5">
                        {o.contributions.map((c) => (
                          <div
                            key={c.rule_id + c.evidence}
                            className="grid grid-cols-[auto_1fr_auto] items-start gap-3 rounded-md border border-surface-700/50 bg-surface-850/60 px-3 py-2"
                          >
                            <Chip tone="mono">{c.mitre.technique_id}</Chip>
                            <div className="min-w-0">
                              <div className="text-[13px] font-medium text-ink-100">
                                {c.title}
                                {c.rule_id.startsWith("corr_") && (
                                  <span className="ml-2 text-accent-soft">◆ correlation</span>
                                )}
                              </div>
                              <div className="text-[12px] leading-relaxed text-ink-400">
                                {c.evidence}
                              </div>
                              <div className="mt-0.5 text-[11px] text-ink-400">
                                {c.mitre.tactic} · {c.mitre.technique_name}
                              </div>
                            </div>
                            <div className="text-right">
                              <div className="font-mono text-[13px] text-ink-200">+{c.weight.toFixed(1)}</div>
                              <div className="text-[10px] uppercase tracking-wide text-ink-400">
                                conf {pct(c.confidence)}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}


/**
 * Pin a scored object to the report from the table the analyst is reading.
 * Renders nothing until the report document is loaded, because the ref it needs
 * is defined by the backend, not recomputed here.
 */
function ReportPin({
  objectType,
  objectKey,
  label,
  pid,
}: {
  objectType: string;
  objectKey: string;
  label: string;
  pid: number | null;
}) {
  const { refForObject } = useReport();
  const evidenceRef = refForObject(objectType, objectKey, label);
  if (!evidenceRef) return null;
  return <EvidenceToggle evidenceRef={evidenceRef} label={label} pid={pid} compact />;
}

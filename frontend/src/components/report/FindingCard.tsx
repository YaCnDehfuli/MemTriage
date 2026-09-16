import { RiskBadge } from "../primitives";
import { EvidenceToggle } from "./EvidenceToggle";
import {
  CONFIDENCE_LABEL,
  DISPOSITION_LABEL,
  useReport,
} from "../../state/reportStore";
import type { ConfidenceLevel, Disposition, ReportFinding } from "../../types";

const DISPOSITIONS: Disposition[] = [
  "undetermined",
  "attacker_activity",
  "examiner_artifact",
  "benign",
];

const CONFIDENCES: ConfidenceLevel[] = [
  "confirmed",
  "high_confidence",
  "medium_confidence",
  "low_confidence",
  "insufficient_evidence",
];

/**
 * One finding, with the three things only the analyst can supply: what it is,
 * how sure they are, and what it means in this environment.
 */
export function FindingCard({ finding }: { finding: ReportFinding }) {
  const { evidenceByRef, setNote, setDisposition, setConfidence } = useReport();

  const row = evidenceByRef.get(finding.ref);
  const label = finding.object.label;
  const disposition = (row?.disposition ?? "undetermined") as Disposition;
  const note = row?.analyst_note ?? "";

  return (
    <div className="rounded border border-surface-700 bg-surface-900 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <RiskBadge risk={finding.object.risk} />
        <span className="font-mono text-[13px] font-medium text-ink-100">{label}</span>
        {finding.object.pid !== null && (
          <span className="font-mono text-[11px] text-ink-400">
            PID {finding.object.pid}
          </span>
        )}
        <span className="ml-auto">
          <EvidenceToggle
            evidenceRef={finding.ref}
            label={label}
            pid={finding.object.pid}
          />
        </span>
      </div>

      <p className="mt-1.5 text-[12px] text-ink-300">{finding.rationale}</p>
      {finding.techniques && (
        <p className="mt-1 text-[11px] text-ink-400">{finding.techniques}</p>
      )}

      <div className="mt-2.5 flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
          Disposition
          <select
            className="rounded border border-surface-600 bg-surface-800 px-1.5 py-1 text-[11px] text-ink-200"
            value={disposition}
            onChange={(e) =>
              void setDisposition(finding.ref, label, e.target.value as Disposition)
            }
          >
            {DISPOSITIONS.map((d) => (
              <option key={d} value={d}>
                {DISPOSITION_LABEL[d]}
              </option>
            ))}
          </select>
        </label>

        <label className="flex items-center gap-1.5 text-[11px] text-ink-400">
          Confidence
          <select
            className="rounded border border-surface-600 bg-surface-800 px-1.5 py-1 text-[11px] text-ink-200"
            value={row?.analyst_confidence ?? ""}
            onChange={(e) =>
              void setConfidence(
                finding.ref,
                label,
                (e.target.value || null) as ConfidenceLevel | null,
              )
            }
          >
            <option value="">— engine score —</option>
            {CONFIDENCES.map((c) => (
              <option key={c} value={c}>
                {CONFIDENCE_LABEL[c]}
              </option>
            ))}
          </select>
        </label>

        {disposition === "examiner_artifact" && (
          <span className="text-[11px] text-ink-400">
            Kept in the report, told apart from attacker activity.
          </span>
        )}
      </div>

      <textarea
        className="mt-2 w-full rounded border border-surface-600 bg-surface-950 px-2 py-1.5 text-[12px] text-ink-200 placeholder:text-ink-400"
        rows={note ? 3 : 2}
        placeholder="What this means here — the parent process, whether it is expected on this host, what would confirm it."
        value={note}
        onChange={(e) => setNote(finding.ref, label, e.target.value)}
      />
    </div>
  );
}

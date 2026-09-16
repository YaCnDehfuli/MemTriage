import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import type {
  ConfidenceLevel,
  Disposition,
  EvidenceKind,
  NarrativeEntry,
  NarrativeSection,
  ReportDocument,
  ReportEvidence,
} from "../types";
import { useApp } from "./store";

/**
 * The analyst layer's state, deliberately kept out of `AppState`.
 *
 * That provider's value is a single `useMemo` over everything, so any change
 * there re-renders every `useApp()` consumer. Note keystrokes and disposition
 * toggles are frequent; folding them in would re-render the whole live-triage
 * tree on each one. A separate provider scopes those re-renders to the report.
 */

export const NARRATIVE_SECTIONS: NarrativeSection[] = [
  "hypothesis",
  "scope_objectives",
  "executive_summary",
  "recommendations",
  "examiner_info",
];

export const NARRATIVE_LABEL: Record<NarrativeSection, string> = {
  hypothesis: "Hypothesis",
  scope_objectives: "Scope & objectives",
  executive_summary: "Executive summary",
  recommendations: "Recommendations",
  examiner_info: "Examiner information",
};

export const NARRATIVE_HINT: Record<NarrativeSection, string> = {
  hypothesis:
    "What you believe happened, stated as a hypothesis under test. Name what would confirm or refute it.",
  scope_objectives:
    "What this examination covered, what it did not, and what question it was asked to answer.",
  executive_summary:
    "Plain business language for a non-technical reader. No technique IDs, no tool names.",
  recommendations: "Concrete next steps a responder can act on.",
  examiner_info: "Examiner name, organisation, and the date of examination.",
};

export const DISPOSITION_LABEL: Record<Disposition, string> = {
  undetermined: "Undetermined",
  attacker_activity: "Attacker activity",
  examiner_artifact: "Collection artifact",
  benign: "Benign",
};

export const CONFIDENCE_LABEL: Record<ConfidenceLevel, string> = {
  confirmed: "Confirmed",
  high_confidence: "High confidence",
  medium_confidence: "Medium confidence",
  low_confidence: "Low confidence",
  insufficient_evidence: "Insufficient evidence",
};

interface ReportContextValue {
  doc: ReportDocument | null;
  evidenceByRef: Map<string, ReportEvidence>;
  narrative: Record<NarrativeSection, NarrativeEntry>;
  loading: boolean;
  error: string | null;
  saving: number;
  refresh: () => Promise<void>;
  /** The backend's ref for a scored object, or null if it is not in the document. */
  refForObject: (objectType: string, key: string, label: string) => string | null;
  /** The report's ref and label for a process, matched on PID alone. */
  refForProcess: (pid: number) => { ref: string; label: string } | null;
  pin: (item: {
    evidenceKind: EvidenceKind;
    ref: string;
    label: string;
    pid: number | null;
  }) => Promise<string | null>;
  /** Both resolve to the failure message, or null once the change is saved. */
  unpin: (evidenceId: string) => Promise<string | null>;
  setNote: (ref: string, label: string, note: string) => void;
  setDisposition: (ref: string, label: string, value: Disposition) => Promise<void>;
  setConfidence: (
    ref: string,
    label: string,
    value: ConfidenceLevel | null,
  ) => Promise<void>;
  setNarrative: (section: NarrativeSection, content: string) => void;
}

const ReportContext = createContext<ReportContextValue | null>(null);

const EMPTY_NARRATIVE = {} as Record<NarrativeSection, NarrativeEntry>;
const NOTE_DEBOUNCE_MS = 600;

export function ReportProvider({ children }: { children: ReactNode }) {
  const { client, investigationId, triage, scored } = useApp();

  const [doc, setDoc] = useState<ReportDocument | null>(null);
  const [evidence, setEvidence] = useState<ReportEvidence[]>([]);
  const [narrative, setNarrativeState] =
    useState<Record<NarrativeSection, NarrativeEntry>>(EMPTY_NARRATIVE);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(0);

  // One timer per field, so editing a note and a narrative section at the same
  // time does not have one debounce cancel the other's pending save.
  const timers = useRef<Record<string, number>>({});

  // The backend is the single source of truth for evidence identity. Hashing
  // labels in the browser as well would be a second definition of `ref` that can
  // drift from the backend's, and a drifted ref binds a note to nothing — or to
  // the wrong finding. `doc.refs` covers every scored object, not just what the
  // curated document renders, so unpinned findings keep their pin control.
  const refIndex = useMemo(() => {
    const map = new Map<string, string>();
    for (const r of doc?.refs ?? []) {
      map.set(`${r.object_type}|${r.key}|${r.label}`, r.ref);
    }
    return map;
  }, [doc]);

  // A PID identifies a process uniquely within one image, so the inventory needs
  // no label match: its names come from pslist ("SearchHost.exe") while the
  // scorer labels them from the census ("searchhost.exe (5292)").
  const processRefs = useMemo(() => {
    const map = new Map<string, { ref: string; label: string }>();
    for (const r of doc?.refs ?? []) {
      if (r.object_type === "process" && !map.has(r.key)) map.set(r.key, { ref: r.ref, label: r.label });
    }
    return map;
  }, [doc]);

  const refForProcess = useCallback(
    (pid: number) => processRefs.get(String(pid)) ?? null,
    [processRefs],
  );

  const refForObject = useCallback(
    (objectType: string, key: string, label: string) =>
      refIndex.get(`${objectType}|${key}|${label}`) ?? null,
    [refIndex],
  );

  const evidenceByRef = useMemo(() => {
    const map = new Map<string, ReportEvidence>();
    for (const row of evidence) map.set(row.ref, row);
    return map;
  }, [evidence]);

  /** Re-assemble the document only. Grouping lives on the server, so a change
   *  that moves a finding between sections — excluding it, or calling it a
   *  collection artifact — is not visible until the document is rebuilt. Notes
   *  do not restructure anything and deliberately skip this. */
  const refreshDoc = useCallback(async () => {
    if (!investigationId) return;
    try {
      setDoc(await client.getReport(investigationId, "technical"));
    } catch {
      /* the row itself saved; leave the last good document on screen */
    }
  }, [client, investigationId]);

  const refresh = useCallback(async () => {
    if (!investigationId) return;
    setLoading(true);
    setError(null);
    try {
      const [document, rows, sections] = await Promise.all([
        client.getReport(investigationId, "technical"),
        client.listReportEvidence(investigationId),
        client.getNarrative(investigationId),
      ]);
      setDoc(document);
      setEvidence(rows);
      setNarrativeState(sections);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load the report.");
    } finally {
      setLoading(false);
    }
  }, [client, investigationId]);

  useEffect(() => {
    if (!investigationId) {
      setDoc(null);
      setEvidence([]);
      setNarrativeState(EMPTY_NARRATIVE);
      return;
    }
    void refresh();
    // The document is assembled from triage output, so it must reload whenever
    // that output changes: triage finishing, being restored from cache, or being
    // re-scored. Keyed on the investigation alone, it was fetched before triage
    // existed and never again — leaving every pin control without an identity.
  }, [investigationId, triage, scored, refresh]);

  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const id of Object.values(pending)) window.clearTimeout(id);
    };
  }, []);

  /** Get (or lazily create) the evidence row backing one finding. */
  const rowFor = useCallback(
    async (ref: string, label: string): Promise<ReportEvidence> => {
      const existing = evidenceByRef.get(ref);
      if (existing) return existing;
      if (!investigationId) throw new Error("No investigation loaded.");
      const created = await client.upsertReportEvidence(investigationId, { ref, label });
      setEvidence((rows) =>
        rows.some((r) => r.id === created.id) ? rows : [...rows, created],
      );
      return created;
    },
    [client, evidenceByRef, investigationId],
  );

  const pin = useCallback(
    async (item: {
      evidenceKind: EvidenceKind;
      ref: string;
      label: string;
      pid: number | null;
    }) => {
      if (!investigationId) return "No investigation loaded.";
      setSaving((n) => n + 1);
      try {
        const created = await client.upsertReportEvidence(investigationId, {
          evidence_kind: item.evidenceKind,
          ref: item.ref,
          label: item.label,
          pid: item.pid,
        });
        setEvidence((rows) =>
          rows.some((r) => r.id === created.id) ? rows : [...rows, created],
        );
        await refreshDoc();
        return null;
      } catch (err) {
        const message = err instanceof Error ? err.message : "Could not add to the report.";
        setError(message);
        return message;
      } finally {
        setSaving((n) => n - 1);
      }
    },
    [client, investigationId, refreshDoc],
  );

  const unpin = useCallback(
    async (evidenceId: string) => {
      if (!investigationId) return "No investigation loaded.";
      setSaving((n) => n + 1);
      try {
        await client.deleteReportEvidence(investigationId, evidenceId);
        setEvidence((rows) => rows.filter((r) => r.id !== evidenceId));
        await refreshDoc();
        return null;
      } catch (err) {
        const message = err instanceof Error ? err.message : "Could not remove.";
        setError(message);
        return message;
      } finally {
        setSaving((n) => n - 1);
      }
    },
    [client, investigationId, refreshDoc],
  );

  const applyPatch = useCallback(
    async (
      ref: string,
      label: string,
      body: Parameters<typeof client.patchReportEvidence>[2],
      restructures = false,
    ) => {
      if (!investigationId) return;
      setSaving((n) => n + 1);
      try {
        const row = await rowFor(ref, label);
        const updated = await client.patchReportEvidence(investigationId, row.id, {
          ...body,
          if_version: row.version,
        });
        setEvidence((rows) => rows.map((r) => (r.id === updated.id ? updated : r)));
        setError(null);
        if (restructures) await refreshDoc();
      } catch (err) {
        // A rejected write means someone else changed this row. Reloading is the
        // honest response: silently retrying would discard their edit.
        setError(
          err instanceof Error
            ? `${err.message} Reloading the report.`
            : "Could not save.",
        );
        void refresh();
      } finally {
        setSaving((n) => n - 1);
      }
    },
    [client, investigationId, refresh, refreshDoc, rowFor],
  );

  const debounce = useCallback((key: string, run: () => void) => {
    window.clearTimeout(timers.current[key]);
    timers.current[key] = window.setTimeout(run, NOTE_DEBOUNCE_MS);
  }, []);

  const setNote = useCallback(
    (ref: string, label: string, note: string) => {
      // Optimistic locally so typing stays responsive; the write is debounced.
      setEvidence((rows) =>
        rows.map((r) => (r.ref === ref ? { ...r, analyst_note: note } : r)),
      );
      debounce(`note:${ref}`, () => {
        void applyPatch(ref, label, { analyst_note: note });
      });
    },
    [applyPatch, debounce],
  );

  const setDisposition = useCallback(
    (ref: string, label: string, value: Disposition) =>
      applyPatch(ref, label, { disposition: value }, true),
    [applyPatch],
  );

  const setConfidence = useCallback(
    (ref: string, label: string, value: ConfidenceLevel | null) =>
      applyPatch(ref, label, { analyst_confidence: value }),
    [applyPatch],
  );

  const setNarrative = useCallback(
    (section: NarrativeSection, content: string) => {
      setNarrativeState((current) => ({
        ...current,
        [section]: { ...(current[section] ?? { source: "analyst", updated_at: null }), content },
      }));
      debounce(`narrative:${section}`, () => {
        if (!investigationId) return;
        setSaving((n) => n + 1);
        client
          .putNarrative(investigationId, section, content)
          .catch((err: unknown) =>
            setError(err instanceof Error ? err.message : "Could not save."),
          )
          .finally(() => setSaving((n) => n - 1));
      });
    },
    [client, debounce, investigationId],
  );

  const value = useMemo<ReportContextValue>(
    () => ({
      doc,
      evidenceByRef,
      narrative,
      loading,
      error,
      saving,
      refresh,
      refForObject,
      refForProcess,
      pin,
      unpin,
      setNote,
      setDisposition,
      setConfidence,
      setNarrative,
    }),
    [
      doc, evidenceByRef, narrative, loading, error, saving, refresh, refForObject, refForProcess,
      pin, unpin, setNote, setDisposition, setConfidence, setNarrative,
    ],
  );

  return <ReportContext.Provider value={value}>{children}</ReportContext.Provider>;
}

export function useReport(): ReportContextValue {
  const ctx = useContext(ReportContext);
  if (!ctx) throw new Error("useReport must be used inside <ReportProvider>");
  return ctx;
}

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
import { ApiError, createLiveClient, type ApiClient } from "../api/client";
import { createDemoClient } from "../demo/fixtures";
import { followAnalysis, followInvestigation, type Subscription } from "../lib/events";
import type {
  AnalysisResult,
  AttackTechnique,
  Diff,
  TriageDisclaimer as TriageDisclaimerType,
  LowLevelReport,
  ProcessItem,
  RiskSummary,
  ScoredObject,
  Stage,
  Triage,
  TuningProfile,
} from "../types";

export interface JobProgress {
  status: string;
  stage: string;
  progress: number;
  message: string;
  error?: string | null;
}

export interface UploadItem {
  name: string;
  size: number;
  progress: number;
  status: "pending" | "uploading" | "done" | "failed";
  error?: string;
}

interface AppState {
  demo: boolean;
  client: ApiClient;
  stage: Stage;
  loading: boolean;
  error: string | null;
  retryLast: (() => Promise<void>) | null;
  investigationId: string | null;
  triage: Triage | null;
  processes: ProcessItem[];
  scored: ScoredObject[];
  profile: TuningProfile | null;
  riskSummary: RiskSummary | null;
  attack: AttackTechnique[];
  disclaimer: TriageDisclaimerType | null;
  diff: Diff | null;
  selectedPid: number | null;
  analysis: AnalysisResult | null;
  lowlevel: LowLevelReport | null;
  triageProgress: JobProgress | null;
  analysisProgress: JobProgress | null;
  uploads: UploadItem[];
}

interface AppActions {
  setDemo(demo: boolean): void;
  setStage(stage: Stage): void;
  bootstrap(): Promise<void>;
  rescore(profile: Partial<TuningProfile>): Promise<void>;
  selectProcess(pid: number): Promise<void>;
  uploadDumps(files: File[]): Promise<void>;
  startTriage(): Promise<void>;
  clearError(): void;
}

const Ctx = createContext<(AppState & AppActions) | null>(null);

const DEMO_ID = "demo-investigation";

function message(e: unknown): string {
  if (e instanceof ApiError) {
    return e.requestId ? `${e.message} (request ${e.requestId})` : e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [demo, setDemoFlag] = useState(true);
  const [stage, setStage] = useState<Stage>("triage");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [retryLast, setRetryLast] = useState<(() => Promise<void>) | null>(null);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [triage, setTriage] = useState<Triage | null>(null);
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [scored, setScored] = useState<ScoredObject[]>([]);
  const [profile, setProfile] = useState<TuningProfile | null>(null);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [attack, setAttack] = useState<AttackTechnique[]>([]);
  const [disclaimer, setDisclaimer] = useState<TriageDisclaimerType | null>(null);
  const [diff, setDiff] = useState<Diff | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [lowlevel, setLowlevel] = useState<LowLevelReport | null>(null);
  const [triageProgress, setTriageProgress] = useState<JobProgress | null>(null);
  const [analysisProgress, setAnalysisProgress] = useState<JobProgress | null>(null);
  const [uploads, setUploads] = useState<UploadItem[]>([]);

  const subscriptions = useRef<Subscription[]>([]);

  useEffect(() => () => {
    subscriptions.current.forEach((s) => s.close());
    subscriptions.current = [];
  }, []);

  const track = useCallback((subscription: Subscription) => {
    subscriptions.current.push(subscription);
  }, []);

  const client = useMemo<ApiClient>(
    () => (demo ? createDemoClient() : createLiveClient()),
    [demo],
  );

  const fail = useCallback((e: unknown, retry?: () => Promise<void>) => {
    setError(message(e));
    setRetryLast(() => retry ?? null);
  }, []);

  const clearError = useCallback(() => {
    setError(null);
    setRetryLast(null);
  }, []);

  const applyTriage = useCallback((t: Triage) => {
    setTriage(t);
    setProcesses(t.processes ?? []);
    setScored(t.dashboard?.scored_objects ?? []);
    setProfile(t.dashboard?.profile ?? null);
    setRiskSummary(t.dashboard?.risk_summary ?? null);
    setAttack(t.dashboard?.attack_techniques ?? []);
    setDisclaimer(t.dashboard?.disclaimer ?? null);
  }, []);

  const loadResult = useCallback(
    async (id: string) => {
      const res = await client.getResult(id);
      setInvestigationId(res.investigation_id);
      applyTriage(res.triage);
      return res;
    },
    [client, applyTriage],
  );

  const bootstrap = useCallback(async () => {
    setLoading(true);
    clearError();
    try {
      const id = investigationId ?? (await client.createInvestigation()).investigation_id;
      const res = await loadResult(id);
      if (res.process_analyses[0]) setAnalysis(res.process_analyses[0]);
    } catch (e) {
      fail(e, bootstrap);
    } finally {
      setLoading(false);
    }
  }, [client, investigationId, loadResult, fail, clearError]);

  const uploadDumps = useCallback(
    async (files: File[]) => {
      if (!files.length) return;
      clearError();
      setUploads(files.map((f) => ({
        name: f.name, size: f.size, progress: 0, status: "pending" as const,
      })));
      setLoading(true);
      try {
        const id = investigationId ?? (await client.createInvestigation()).investigation_id;
        setInvestigationId(id);
        for (let index = 0; index < files.length; index += 1) {
          const file = files[index];
          const mark = (patch: Partial<UploadItem>) =>
            setUploads((current) =>
              current.map((item, i) => (i === index ? { ...item, ...patch } : item)));
          mark({ status: "uploading" });
          try {
            await client.addDump(id, file, (fraction) =>
              mark({ progress: Math.round(fraction * 100) }));
            mark({ status: "done", progress: 100 });
          } catch (e) {
            mark({ status: "failed", error: message(e) });
            throw e;
          }
        }
      } catch (e) {
        fail(e);
      } finally {
        setLoading(false);
      }
    },
    [client, investigationId, fail, clearError],
  );

  const startTriage = useCallback(async () => {
    if (!investigationId) {
      fail(new Error("Upload at least one memory image before starting triage."));
      return;
    }
    clearError();
    setStage("triage");
    try {
      const state = await client.startTriage(investigationId);
      setTriageProgress(state);
      track(followInvestigation("", investigationId, (next) => {
        setTriageProgress(next);
        if (next.status === "triaged") void loadResult(investigationId).catch(fail);
        if (next.status === "failed") fail(new Error(next.error ?? "Triage failed."));
      }));
    } catch (e) {
      fail(e, startTriage);
    }
  }, [client, investigationId, loadResult, fail, clearError, track]);

  const rescore = useCallback(
    async (patch: Partial<TuningProfile>) => {
      if (!investigationId && !demo) return;
      const id = investigationId ?? DEMO_ID;
      try {
        const r = await client.rescore(id, patch);
        setScored(r.scored_objects);
        setProfile(r.profile);
        setRiskSummary(r.risk_summary);
        setAttack(r.attack_techniques);
        if (r.disclaimer) setDisclaimer(r.disclaimer);
        setDiff(r.diff);
      } catch (e) {
        fail(e, () => rescore(patch));
      }
    },
    [client, investigationId, demo, fail],
  );

  const loadAnalysis = useCallback(
    async (id: string, pid: number) => {
      const res = await client.getResult(id);
      const found = res.process_analyses.find((a) => a.pid === pid) ?? res.process_analyses[0];
      if (found) setAnalysis(found);
      try {
        setLowlevel(await client.getLowLevel(id, pid));
      } catch {
        // The region deep-dive is additive: its absence is a quieter panel, not
        // a failed analysis.
        setLowlevel(null);
      }
    },
    [client],
  );

  const selectProcess = useCallback(
    async (pid: number) => {
      setSelectedPid(pid);
      setStage("deepdive");
      setAnalysis(null);
      setLowlevel(null);
      setAnalysisProgress(null);
      clearError();
      const id = investigationId ?? DEMO_ID;
      try {
        const state = await client.analyzeProcess(id, pid);
        setAnalysisProgress(state);
        if (state.status === "done") {
          await loadAnalysis(id, pid);
          return;
        }
        track(followAnalysis("", id, state.analysis_id, (next) => {
          setAnalysisProgress(next);
          if (next.status === "done") void loadAnalysis(id, pid).catch(fail);
          if (next.status === "failed") {
            fail(new Error(next.error ?? `Analysis of PID ${pid} failed.`));
          }
        }));
      } catch (e) {
        fail(e, () => selectProcess(pid));
      }
    },
    [client, investigationId, loadAnalysis, fail, clearError, track],
  );

  const setDemo = useCallback((d: boolean) => {
    subscriptions.current.forEach((s) => s.close());
    subscriptions.current = [];
    setDemoFlag(d);
    setInvestigationId(null);
    setTriage(null);
    setProcesses([]);
    setProfile(null);
    setRiskSummary(null);
    setAttack([]);
    setDisclaimer(null);
    setAnalysis(null);
    setLowlevel(null);
    setScored([]);
    setDiff(null);
    setSelectedPid(null);
    setTriageProgress(null);
    setAnalysisProgress(null);
    setUploads([]);
    setError(null);
    setRetryLast(null);
    setStage(d ? "triage" : "ingest");
  }, []);

  const value = useMemo(
    () => ({
      demo, client, stage, loading, error, retryLast, investigationId, triage, processes,
      scored, profile, riskSummary, attack, disclaimer, diff, selectedPid, analysis, lowlevel,
      triageProgress, analysisProgress, uploads,
      setDemo, setStage, bootstrap, rescore, selectProcess, uploadDumps, startTriage,
      clearError,
    }),
    [demo, client, stage, loading, error, retryLast, investigationId, triage, processes,
      scored, profile, riskSummary, attack, disclaimer, diff, selectedPid, analysis, lowlevel,
      triageProgress, analysisProgress, uploads,
      setDemo, bootstrap, rescore, selectProcess, uploadDumps, startTriage, clearError],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}

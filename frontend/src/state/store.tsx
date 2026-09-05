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
import { followAnalysis, followInvestigation, followPluginRun, type Subscription } from "../lib/events";
import type {
  AnalysisResult,
  AttackTechnique,
  Diff,
  TriageDisclaimer as TriageDisclaimerType,
  InvestigationState,
  LowLevelReport,
  PluginCatalogEntry,
  PluginRunState,
  ProcessItem,
  RiskSummary,
  ScoredObject,
  Stage,
  Triage,
  TriageOptions,
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
  triageProgress: InvestigationState | null;
  triageStarting: boolean;
  analysisProgress: JobProgress | null;
  uploads: UploadItem[];
  pluginCatalog: PluginCatalogEntry[];
  pluginRun: PluginRunState | null;
  pluginRunStarting: boolean;
}

interface AppActions {
  setStage(stage: Stage): void;
  bootstrap(): Promise<void>;
  rescore(profile: Partial<TuningProfile>): Promise<void>;
  selectProcess(pid: number): Promise<void>;
  uploadDumps(files: File[]): Promise<void>;
  startTriage(options: TriageOptions): Promise<void>;
  clearError(): void;
  loadPluginCatalog(): Promise<void>;
  runPlugins(plugins: string[], concurrency: number): Promise<void>;
  restoreLatestPluginRun(): Promise<void>;
  newPluginRun(): void;
}

const Ctx = createContext<(AppState & AppActions) | null>(null);

function message(e: unknown): string {
  if (e instanceof ApiError) {
    return e.requestId ? `${e.message} (request ${e.requestId})` : e.message;
  }
  return e instanceof Error ? e.message : String(e);
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [stage, setStage] = useState<Stage>("ingest");
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
  const [triageProgress, setTriageProgress] = useState<InvestigationState | null>(null);
  const [triageStarting, setTriageStarting] = useState(false);
  const [analysisProgress, setAnalysisProgress] = useState<JobProgress | null>(null);
  const [uploads, setUploads] = useState<UploadItem[]>([]);
  const [pluginCatalog, setPluginCatalog] = useState<PluginCatalogEntry[]>([]);
  const [pluginRun, setPluginRun] = useState<PluginRunState | null>(null);
  const [pluginRunStarting, setPluginRunStarting] = useState(false);

  const subscriptions = useRef<Subscription[]>([]);

  useEffect(() => () => {
    subscriptions.current.forEach((s) => s.close());
    subscriptions.current = [];
  }, []);

  const track = useCallback((subscription: Subscription) => {
    subscriptions.current.push(subscription);
  }, []);

  const client = useMemo<ApiClient>(() => createLiveClient(), []);

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

  useEffect(() => {
    const id = new URLSearchParams(window.location.search).get("investigation");
    if (!id) return;
    let cancelled = false;
    (async () => {
      setLoading(true);
      clearError();
      try {
        setInvestigationId(id);
        const state = await client.getInvestigation(id);
        if (cancelled) return;
        setTriageProgress(state);
        const res = await loadResult(id);
        if (cancelled) return;
        const existing = res.process_analyses[0];
        if (existing) {
          setAnalysis(existing);
          setSelectedPid(existing.pid);
          try {
            setLowlevel(await client.getLowLevel(id, existing.pid));
          } catch {
            setLowlevel(null);
          }
        }
      } catch (e) {
        if (!cancelled) fail(e);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [client, loadResult, fail, clearError]);

  const bootstrap = useCallback(async () => {
    setLoading(true);
    clearError();
    try {
      const id = investigationId ?? (await client.createInvestigation()).investigation_id;
      const res = await loadResult(id);
      setTriageProgress(await client.getInvestigation(id));
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

  const startTriage = useCallback(async (options: TriageOptions) => {
    if (!investigationId) {
      fail(new Error("Upload at least one memory image before starting triage."));
      return;
    }
    clearError();
    setStage("triage");
    setTriageStarting(true);
    try {
      const state = await client.startTriage(investigationId, options);
      // The accepted request defines a new evidence scope. Do not render the
      // previous run's scores/features beneath live activity for a different
      // Light/Deep/Custom plan; the result is repopulated only at completion.
      setTriage(null);
      setProcesses([]);
      setScored([]);
      setProfile(null);
      setRiskSummary(null);
      setAttack([]);
      setDisclaimer(null);
      setDiff(null);
      setTriageProgress(state);
      if (state.status === "triaged") {
        await loadResult(investigationId);
        return;
      }
      if (state.status === "failed") {
        fail(new Error(state.error ?? "Triage failed."));
        return;
      }
      track(followInvestigation("", investigationId, (next) => {
        setTriageProgress(next);
        if (next.status === "triaged") void loadResult(investigationId).catch(fail);
        if (next.status === "failed") fail(new Error(next.error ?? "Triage failed."));
      }));
    } catch (e) {
      fail(e, () => startTriage(options));
    } finally {
      setTriageStarting(false);
    }
  }, [client, investigationId, loadResult, fail, clearError, track]);

  const loadPluginCatalog = useCallback(async () => {
    try {
      setPluginCatalog(await client.getPluginCatalog());
    } catch (e) {
      fail(e, loadPluginCatalog);
    }
  }, [client, fail]);

  const runPlugins = useCallback(
    async (plugins: string[], concurrency: number) => {
      if (!investigationId) {
        fail(new Error("Upload a memory image before running a plugin."));
        return;
      }
      clearError();
      setPluginRunStarting(true);
      try {
        const state = await client.runPlugins(investigationId, plugins, concurrency);
        setPluginRun(state);
        if (state.status !== "done" && state.status !== "failed") {
          track(followPluginRun("", investigationId, state.plugin_run_id, setPluginRun));
        }
      } catch (e) {
        fail(e, () => runPlugins(plugins, concurrency));
      } finally {
        setPluginRunStarting(false);
      }
    },
    [client, investigationId, fail, clearError, track],
  );

  const restoreLatestPluginRun = useCallback(async () => {
    if (!investigationId) return;
    try {
      const [latest] = await client.listPluginRuns(investigationId);
      setPluginRun(latest ?? null);
      if (latest && latest.status !== "done" && latest.status !== "failed") {
        track(followPluginRun("", investigationId, latest.plugin_run_id, setPluginRun));
      }
    } catch (e) {
      fail(e, restoreLatestPluginRun);
    }
  }, [client, investigationId, fail, track]);

  const newPluginRun = useCallback(() => setPluginRun(null), []);

  const rescore = useCallback(
    async (patch: Partial<TuningProfile>) => {
      if (!investigationId) return;
      const id = investigationId;
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
    [client, investigationId, fail],
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
      if (!investigationId) {
        fail(new Error("Select an investigation before analyzing a process."));
        return;
      }
      const id = investigationId;
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

  const value = useMemo(
    () => ({
      client, stage, loading, error, retryLast, investigationId, triage, processes,
      scored, profile, riskSummary, attack, disclaimer, diff, selectedPid, analysis, lowlevel,
      triageProgress, triageStarting, analysisProgress, uploads, pluginCatalog, pluginRun, pluginRunStarting,
      setStage, bootstrap, rescore, selectProcess, uploadDumps, startTriage,
      clearError, loadPluginCatalog, runPlugins, restoreLatestPluginRun, newPluginRun,
    }),
    [client, stage, loading, error, retryLast, investigationId, triage, processes,
      scored, profile, riskSummary, attack, disclaimer, diff, selectedPid, analysis, lowlevel,
      triageProgress, triageStarting, analysisProgress, uploads, pluginCatalog, pluginRun, pluginRunStarting,
      setStage, bootstrap, rescore, selectProcess, uploadDumps, startTriage, clearError,
      loadPluginCatalog, runPlugins, restoreLatestPluginRun, newPluginRun],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}

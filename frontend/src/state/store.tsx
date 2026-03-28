import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { createLiveClient, type ApiClient } from "../api/client";
import { createDemoClient } from "../demo/fixtures";
import type {
  AnalysisResult,
  AttackTechnique,
  Diff,
  ProcessItem,
  RiskSummary,
  ScoredObject,
  Stage,
  Triage,
  TuningProfile,
} from "../types";

interface AppState {
  demo: boolean;
  client: ApiClient;
  stage: Stage;
  loading: boolean;
  error: string | null;
  investigationId: string | null;
  triage: Triage | null;
  processes: ProcessItem[];
  scored: ScoredObject[];
  profile: TuningProfile | null;
  riskSummary: RiskSummary | null;
  attack: AttackTechnique[];
  diff: Diff | null;
  selectedPid: number | null;
  analysis: AnalysisResult | null;
}

interface AppActions {
  setDemo(demo: boolean): void;
  setStage(stage: Stage): void;
  bootstrap(): Promise<void>;
  rescore(profile: Partial<TuningProfile>): Promise<void>;
  selectProcess(pid: number): Promise<void>;
}

const Ctx = createContext<(AppState & AppActions) | null>(null);

export function AppProvider({ children }: { children: ReactNode }) {
  const [demo, setDemoFlag] = useState(true);
  const [stage, setStage] = useState<Stage>("triage");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [investigationId, setInvestigationId] = useState<string | null>(null);
  const [triage, setTriage] = useState<Triage | null>(null);
  const [processes, setProcesses] = useState<ProcessItem[]>([]);
  const [scored, setScored] = useState<ScoredObject[]>([]);
  const [profile, setProfile] = useState<TuningProfile | null>(null);
  const [riskSummary, setRiskSummary] = useState<RiskSummary | null>(null);
  const [attack, setAttack] = useState<AttackTechnique[]>([]);
  const [diff, setDiff] = useState<Diff | null>(null);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);

  const client = useMemo<ApiClient>(
    () => (demo ? createDemoClient() : createLiveClient()),
    [demo],
  );

  const applyTriage = useCallback((t: Triage) => {
    setTriage(t);
    setProcesses(t.processes);
    setScored(t.dashboard.scored_objects);
    setProfile(t.dashboard.profile);
    setRiskSummary(t.dashboard.risk_summary);
    setAttack(t.dashboard.attack_techniques);
  }, []);

  const bootstrap = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await client.getResult(
        investigationId ?? (await client.createInvestigation()).investigation_id,
      );
      setInvestigationId(res.investigation_id);
      applyTriage(res.triage);
      if (res.process_analyses[0]) setAnalysis(res.process_analyses[0]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, [client, investigationId, applyTriage]);

  const rescore = useCallback(
    async (patch: Partial<TuningProfile>) => {
      if (!investigationId && !demo) return;
      const id = investigationId ?? "demo-investigation";
      try {
        const r = await client.rescore(id, patch);
        setScored(r.scored_objects);
        setProfile(r.profile);
        setRiskSummary(r.risk_summary);
        setAttack(r.attack_techniques);
        setDiff(r.diff);
      } catch (e) {
        setError((e as Error).message);
      }
    },
    [client, investigationId, demo],
  );

  const selectProcess = useCallback(
    async (pid: number) => {
      setSelectedPid(pid);
      setStage("deepdive");
      try {
        const id = investigationId ?? "demo-investigation";
        await client.analyzeProcess(id, pid);
        const res = await client.getResult(id);
        const found = res.process_analyses.find((a) => a.pid === pid) ?? res.process_analyses[0];
        if (found) setAnalysis(found);
      } catch (e) {
        setError((e as Error).message);
      }
    },
    [client, investigationId],
  );

  const setDemo = useCallback((d: boolean) => {
    setDemoFlag(d);
    setInvestigationId(null);
    setTriage(null);
    setAnalysis(null);
    setScored([]);
    setDiff(null);
  }, []);

  const value = useMemo(
    () => ({
      demo, client, stage, loading, error, investigationId, triage, processes,
      scored, profile, riskSummary, attack, diff, selectedPid, analysis,
      setDemo, setStage, bootstrap, rescore, selectProcess,
    }),
    [demo, client, stage, loading, error, investigationId, triage, processes,
      scored, profile, riskSummary, attack, diff, selectedPid, analysis,
      setDemo, bootstrap, rescore, selectProcess],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useApp() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useApp must be used within AppProvider");
  return ctx;
}

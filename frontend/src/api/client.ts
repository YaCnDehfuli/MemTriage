import type {
  AnalysisState,
  InvestigationState,
  ProcessItem,
  RescoreResponse,
  Triage,
  TuningProfile,
} from "../types";

export interface ConsolidatedResult {
  investigation_id: string;
  triage: Triage;
  process_analyses: import("../types").AnalysisResult[];
}

export interface ApiClient {
  demo: boolean;
  createInvestigation(): Promise<{ investigation_id: string }>;
  addDump(id: string, file: File): Promise<{ ordinal: number; dump_count: number }>;
  startTriage(id: string): Promise<InvestigationState>;
  getInvestigation(id: string): Promise<InvestigationState>;
  getResult(id: string): Promise<ConsolidatedResult>;
  listProcesses(id: string): Promise<ProcessItem[]>;
  rescore(id: string, profile: Partial<TuningProfile>): Promise<RescoreResponse>;
  analyzeProcess(id: string, pid: number): Promise<AnalysisState>;
  getAnalysis(id: string, analysisId: string): Promise<AnalysisState>;
  artifactUrl(id: string, pid: number, kind: "grid" | "attention"): string;
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* keep statusText */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return (await res.json()) as T;
}

export function createLiveClient(base = ""): ApiClient {
  const api = `${base}/api`;
  return {
    demo: false,
    async createInvestigation() {
      return json(await fetch(`${api}/investigations`, { method: "POST" }));
    },
    async addDump(id, file) {
      return json(
        await fetch(`${api}/investigations/${id}/dumps`, {
          method: "POST",
          headers: { "X-Filename": file.name },
          body: file,
        }),
      );
    },
    async startTriage(id) {
      return json(await fetch(`${api}/investigations/${id}/triage`, { method: "POST" }));
    },
    async getInvestigation(id) {
      return json(await fetch(`${api}/investigations/${id}`));
    },
    async getResult(id) {
      return json(await fetch(`${api}/investigations/${id}/result`));
    },
    async listProcesses(id) {
      return json(await fetch(`${api}/investigations/${id}/processes`));
    },
    async rescore(id, profile) {
      return json(
        await fetch(`${api}/investigations/${id}/rescore`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ profile }),
        }),
      );
    },
    async analyzeProcess(id, pid) {
      return json(
        await fetch(`${api}/investigations/${id}/processes/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ pid }),
        }),
      );
    },
    async getAnalysis(id, analysisId) {
      return json(await fetch(`${api}/investigations/${id}/analyses/${analysisId}`));
    },
    artifactUrl(id, pid, kind) {
      return `${api}/investigations/${id}/processes/${pid}/artifacts/${kind}`;
    },
  };
}

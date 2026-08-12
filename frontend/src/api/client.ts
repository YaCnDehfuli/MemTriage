import type {
  AnalysisState,
  InvestigationState,
  LowLevelReport,
  ModelAccessPolicy,
  ModelAccessRequest,
  ModelAccessResponse,
  ProcessItem,
  RegionRecord,
  RescoreResponse,
  Triage,
  TuningProfile,
} from "../types";

export interface ConsolidatedResult {
  investigation_id: string;
  triage: Triage;
  process_analyses: import("../types").AnalysisResult[];
}

export type UploadProgress = (fraction: number) => void;

export interface ApiClient {
  demo: boolean;
  createInvestigation(): Promise<{ investigation_id: string }>;
  addDump(
    id: string,
    file: File,
    onProgress?: UploadProgress,
  ): Promise<{ ordinal: number; dump_count: number }>;
  startTriage(id: string): Promise<InvestigationState>;
  getInvestigation(id: string): Promise<InvestigationState>;
  getResult(id: string): Promise<ConsolidatedResult>;
  listProcesses(id: string): Promise<ProcessItem[]>;
  rescore(id: string, profile: Partial<TuningProfile>): Promise<RescoreResponse>;
  analyzeProcess(id: string, pid: number): Promise<AnalysisState>;
  getAnalysis(id: string, analysisId: string): Promise<AnalysisState>;
  artifactUrl(id: string, pid: number, kind: "grid" | "attention"): string;
  getRegions(id: string, pid: number): Promise<RegionRecord[]>;
  getLowLevel(id: string, pid: number): Promise<LowLevelReport>;
  getModelAccessPolicy(): Promise<ModelAccessPolicy>;
  requestModelAccess(body: ModelAccessRequest): Promise<ModelAccessResponse>;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code = "http_error",
    readonly requestId = "",
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function failure(res: Response): Promise<ApiError> {
  let message = res.statusText || "Request failed";
  let code = "http_error";
  try {
    const body = await res.json();
    const envelope = body?.error;
    if (envelope) {
      message = envelope.message ?? message;
      code = envelope.code ?? code;
    } else if (body?.detail) {
      message = typeof body.detail === "string" ? body.detail : message;
    }
  } catch {
    /* non-JSON body: keep the status text */
  }
  return new ApiError(res.status, message, code, res.headers.get("X-Request-ID") ?? "");
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw await failure(res);
  return (await res.json()) as T;
}

export function createLiveClient(base = ""): ApiClient {
  const api = `${base}/api`;
  return {
    demo: false,
    async createInvestigation() {
      return json(await fetch(`${api}/investigations`, { method: "POST" }));
    },
    addDump(id, file, onProgress) {
      // fetch cannot report upload progress; a multi-gigabyte image without a
      // progress bar looks like a hang, so this one call uses XHR.
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", `${api}/investigations/${id}/dumps`);
        xhr.setRequestHeader("X-Filename", file.name);
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable) onProgress?.(event.loaded / event.total);
        };
        xhr.onload = () => {
          let body: Record<string, unknown> = {};
          try {
            body = JSON.parse(xhr.responseText);
          } catch {
            /* fall through to the status-based message */
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            onProgress?.(1);
            resolve(body as { ordinal: number; dump_count: number });
            return;
          }
          const envelope = body.error as { message?: string; code?: string } | undefined;
          reject(new ApiError(
            xhr.status,
            envelope?.message ?? (body.detail as string) ?? xhr.statusText ?? "Upload failed",
            envelope?.code ?? "http_error",
            xhr.getResponseHeader("X-Request-ID") ?? "",
          ));
        };
        xhr.onerror = () => reject(new ApiError(0, "Upload failed: the connection dropped."));
        xhr.onabort = () => reject(new ApiError(0, "Upload cancelled."));
        xhr.send(file);
      });
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
    async getRegions(id, pid) {
      return json(await fetch(`${api}/investigations/${id}/processes/${pid}/regions`));
    },
    async getLowLevel(id, pid) {
      return json(await fetch(`${api}/investigations/${id}/processes/${pid}/lowlevel`));
    },
    async getModelAccessPolicy() {
      return json(await fetch(`${api}/model-access`));
    },
    async requestModelAccess(body) {
      return json(
        await fetch(`${api}/model-access-requests`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    },
  };
}

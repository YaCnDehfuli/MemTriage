import type {
  AnalysisState,
  AssistantCatalogue,
  ChatReply,
  ChatTurn,
  ContextPackSummary,
  GeneratedScript,
  InvestigationState,
  LowLevelReport,
  ModelAccessPolicy,
  ModelAccessRequest,
  ModelAccessResponse,
  PluginCatalogEntry,
  PluginOutputFormat,
  PluginOutputPreview,
  PluginRunState,
  ProcessItem,
  RegionRecord,
  RescoreResponse,
  Triage,
  TriageOptions,
  TuningProfile,
} from "../types";

export interface ConsolidatedResult {
  investigation_id: string;
  triage: Triage;
  process_analyses: import("../types").AnalysisResult[];
}

export type UploadProgress = (fraction: number) => void;

export interface ApiClient {
  createInvestigation(): Promise<{ investigation_id: string }>;
  addDump(
    id: string,
    file: File,
    onProgress?: UploadProgress,
  ): Promise<{ ordinal: number; dump_count: number }>;
  startTriage(id: string, options: TriageOptions): Promise<InvestigationState>;
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
  getPluginCatalog(): Promise<PluginCatalogEntry[]>;
  runPlugins(id: string, plugins: string[], concurrency: number): Promise<PluginRunState>;
  getPluginRun(id: string, runId: string): Promise<PluginRunState>;
  listPluginRuns(id: string): Promise<PluginRunState[]>;
  getPluginOutput(
    id: string,
    runId: string,
    plugin: string,
    offset?: number,
    limit?: number,
  ): Promise<PluginOutputPreview>;
  pluginOutputDownloadUrl(
    id: string,
    runId: string,
    plugin: string,
    format: PluginOutputFormat,
  ): string;
  getAssistantProviders(): Promise<AssistantCatalogue>;
  getContextPack(id: string, refresh?: boolean): Promise<ContextPackSummary>;
  askAssistant(id: string, body: AssistantChatRequest): Promise<ChatReply>;
  generateScript(
    id: string,
    body: { provider: string; model?: string; language: string },
  ): Promise<GeneratedScript>;
}

export interface AssistantChatRequest {
  provider: string;
  model: string;
  api_key: string;
  messages: ChatTurn[];
  refresh_context?: boolean;
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
    async startTriage(id, options) {
      return json(
        await fetch(`${api}/investigations/${id}/triage`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(options),
        }),
      );
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
    async getPluginCatalog() {
      return json(await fetch(`${api}/plugins/catalog`));
    },
    async runPlugins(id, plugins, concurrency) {
      return json(
        await fetch(`${api}/investigations/${id}/plugins/run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ plugins, concurrency }),
        }),
      );
    },
    async getPluginRun(id, runId) {
      return json(await fetch(`${api}/investigations/${id}/plugins/runs/${runId}`));
    },
    async listPluginRuns(id) {
      // The workbench restores only the most recent run; do not transfer every
      // historical run's durable event transcript just to select its first row.
      return json(await fetch(`${api}/investigations/${id}/plugins/runs?limit=1`));
    },
    async getPluginOutput(id, runId, plugin, offset = 0, limit = 200) {
      return json(
        await fetch(
          `${api}/investigations/${id}/plugins/runs/${runId}/outputs/${encodeURIComponent(plugin)}?offset=${offset}&limit=${limit}`,
        ),
      );
    },
    pluginOutputDownloadUrl(id, runId, plugin, format) {
      const output = `${api}/investigations/${id}/plugins/runs/${runId}/outputs/${encodeURIComponent(plugin)}`;
      return `${output}/download?format=${encodeURIComponent(format)}`;
    },
    async getAssistantProviders() {
      return json(await fetch(`${api}/assistant/providers`));
    },
    async getContextPack(id, refresh = false) {
      return json(
        await fetch(`${api}/investigations/${id}/assistant/context?refresh=${refresh}`),
      );
    },
    async askAssistant(id, body) {
      return json(
        await fetch(`${api}/investigations/${id}/assistant/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    },
    async generateScript(id, body) {
      return json(
        await fetch(`${api}/investigations/${id}/assistant/script`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    },
  };
}

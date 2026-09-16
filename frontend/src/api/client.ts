import type {
  AnalysisState,
  AssistantProviders,
  DraftNarrativeRequest,
  DraftedNarrative,
  Disposition,
  ConfidenceLevel,
  NarrativeEntry,
  NarrativeSection,
  ReportDocument,
  ReportEvidence,
  Timeline,
  InvestigationState,
  LowLevelReport,
  ModelAccessPolicy,
  ModelAccessRequest,
  ModelAccessResponse,
  ModelState,
  ModelUploadResult,
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
  stopTriage(id: string): Promise<InvestigationState>;
  stopPluginRun(id: string, runId: string): Promise<PluginRunState>;
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
  getModelState(): Promise<ModelState>;
  uploadModelWeights(
    checkpoint: File,
    labels: File | null,
    onProgress?: (fraction: number) => void,
  ): Promise<ModelUploadResult>;
  deleteModelWeights(): Promise<{ removed: boolean; model: ModelState }>;
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

  getTimeline(id: string): Promise<Timeline>;
  getReport(id: string, audience?: "technical" | "executive"): Promise<ReportDocument>;
  reportHtmlUrl(id: string, audience: "technical" | "executive"): string;
  listReportEvidence(id: string): Promise<ReportEvidence[]>;
  upsertReportEvidence(
    id: string,
    body: { ref: string; label?: string; pid?: number | null; evidence_kind?: string },
  ): Promise<ReportEvidence>;
  patchReportEvidence(
    id: string,
    evidenceId: string,
    body: {
      analyst_note?: string;
      analyst_confidence?: ConfidenceLevel | null;
      disposition?: Disposition;
      if_version?: number;
    },
  ): Promise<ReportEvidence>;
  deleteReportEvidence(id: string, evidenceId: string): Promise<{ deleted: string }>;
  listAssistantProviders(): Promise<AssistantProviders>;
  listProviderModels(body: {
    provider: string;
    api_key?: string;
    base_url?: string | null;
  }): Promise<{ provider: string; models: string[] }>;
  draftNarrative(id: string, body: DraftNarrativeRequest): Promise<DraftedNarrative>;
  clearDraftedNarrative(id: string): Promise<{ removed: number }>;
  getNarrative(id: string): Promise<Record<NarrativeSection, NarrativeEntry>>;
  putNarrative(
    id: string,
    section: NarrativeSection,
    content: string,
    source?: "analyst" | "drafted",
  ): Promise<{ section: string; content: string; source: string }>;
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
    async stopTriage(id) {
      return json(await fetch(`${api}/investigations/${id}/triage/stop`, { method: "POST" }));
    },
    async stopPluginRun(id, runId) {
      return json(
        await fetch(`${api}/investigations/${id}/plugins/runs/${runId}/stop`, { method: "POST" }),
      );
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
    async getModelState() {
      return json(await fetch(`${api}/model`));
    },
    uploadModelWeights(checkpoint, labels, onProgress) {
      // XHR, not fetch: a checkpoint is hundreds of megabytes and fetch cannot
      // report upload progress, which is the same reason addDump uses it.
      const body = new FormData();
      body.append("checkpoint", checkpoint);
      if (labels) body.append("labels", labels);
      return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", `${api}/model/weights`);
        xhr.upload.onprogress = (event) => {
          if (event.lengthComputable && onProgress) onProgress(event.loaded / event.total);
        };
        xhr.onload = () => {
          let parsed: unknown = null;
          try {
            parsed = JSON.parse(xhr.responseText);
          } catch {
            parsed = null;
          }
          if (xhr.status >= 200 && xhr.status < 300) {
            resolve(parsed as ModelUploadResult);
            return;
          }
          const detail =
            (parsed as { error?: { message?: string }; detail?: string } | null)?.error
              ?.message ??
            (parsed as { detail?: string } | null)?.detail ??
            `Upload failed (HTTP ${xhr.status})`;
          reject(new Error(detail));
        };
        xhr.onerror = () => reject(new Error("Upload failed: network error"));
        xhr.send(body);
      });
    },
    async deleteModelWeights() {
      return json(await fetch(`${api}/model/weights`, { method: "DELETE" }));
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

    async getTimeline(id) {
      return json(await fetch(`${api}/investigations/${id}/timeline`));
    },
    async getReport(id, audience = "technical") {
      return json(
        await fetch(`${api}/investigations/${id}/report/preview?audience=${audience}`),
      );
    },
    reportHtmlUrl(id, audience) {
      return `${api}/investigations/${id}/report.html?audience=${audience}`;
    },
    async listReportEvidence(id) {
      return json(await fetch(`${api}/investigations/${id}/report/evidence`));
    },
    async upsertReportEvidence(id, body) {
      return json(
        await fetch(`${api}/investigations/${id}/report/evidence`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ evidence_kind: "finding", ...body }),
        }),
      );
    },
    async patchReportEvidence(id, evidenceId, body) {
      return json(
        await fetch(`${api}/investigations/${id}/report/evidence/${evidenceId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    },
    async deleteReportEvidence(id, evidenceId) {
      return json(
        await fetch(`${api}/investigations/${id}/report/evidence/${evidenceId}`, {
          method: "DELETE",
        }),
      );
    },
    async listAssistantProviders() {
      return json(await fetch(`${api}/assistant/providers`));
    },
    async listProviderModels(body) {
      return json(
        await fetch(`${api}/assistant/models`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    },
    async draftNarrative(id, body) {
      return json(
        await fetch(`${api}/investigations/${id}/report/narrative/draft`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }),
      );
    },
    async clearDraftedNarrative(id) {
      return json(
        await fetch(`${api}/investigations/${id}/report/narrative/draft`, {
          method: "DELETE",
        }),
      );
    },
    async getNarrative(id) {
      return json(await fetch(`${api}/investigations/${id}/report/narrative`));
    },
    async putNarrative(id, section, content, source = "analyst") {
      return json(
        await fetch(`${api}/investigations/${id}/report/narrative/${section}`, {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ content, source }),
        }),
      );
    },
  };
}

// Shapes mirrored from the FastAPI backend (schemas.py + scoring/pipeline output).

export type Risk = "Critical" | "High" | "Medium" | "Low";
export type Stage = "ingest" | "triage" | "inventory" | "deepdive" | "report";
export type TriageMode = "light" | "deep" | "custom";

export interface TriageOptions {
  mode: TriageMode;
  plugins: string[];
  concurrency: number;
  force: boolean;
}

export interface InvestigationState {
  investigation_id: string;
  status: "received" | "triaging" | "triaged" | "failed";
  stage: string;
  progress: number;
  message: string;
  error?: string | null;
  dump_count: number;
  total_bytes: number;
  process_count: number;
  has_triage: boolean;
  summary?: RiskSummaryEnvelope | null;
  triage_mode: TriageMode;
  requested_plugins: string[];
  concurrency: number;
  events: PluginEvent[];
  cache_source: string | null;
  /** Present only while queued: what the single analysis worker is busy with. */
  queue?: QueueContext | null;
}

export interface QueueContext {
  running: {
    kind: "triage" | "process_analysis" | "plugin_run";
    investigation_id: string;
    mode?: string;
    message: string;
  }[];
  waiting_ahead: number;
}

export interface RiskSummaryEnvelope {
  process_count?: number;
  dumps?: number;
  flagged?: number;
  attack_techniques?: number;
  risk_summary?: RiskSummary;
}

export interface RiskSummary {
  total: number;
  by_risk: Record<string, number>;
  by_type: Record<string, number>;
}

export interface Mitre {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface Contribution {
  rule_id: string;
  title: string;
  weight: number;
  evidence: string;
  mitre: Mitre;
  severity: number;
  confidence: number;
}

export interface ScoredObject {
  object_type: "process" | "injection" | "connection" | "persistence";
  key: string;
  label: string;
  pid: number | null;
  score: number;
  score_max?: number;
  risk: Risk;
  confidence: number;
  tactics: string[];
  techniques: string[];
  contributions: Contribution[];
}

export interface AttackTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  object_count: number;
  evidence: string;
}

export interface TuningProfile {
  preset: "conservative" | "balanced" | "aggressive";
  risk_bands: Record<string, number>;
  confidence_floor: number;
  category_thresholds: Record<string, number>;
  require_correlation: boolean;
  rule_overrides: Record<string, { enabled?: boolean; weight?: number }>;
}

export interface ExtractionHealth {
  plugins_attempted: number;
  plugins_failed: number;
  failed_plugins: Record<string, string>;
  degraded: boolean;
  severity: "ok" | "warning" | "critical";
  message: string;
}

export interface TriageDisclaimer {
  headline: string;
  summary: string;
  points: string[];
  intent: string;
}

export interface Dashboard {
  features: Record<string, unknown>;
  injections: unknown[];
  network: unknown[];
  suspicious_processes: unknown[];
  persistence: ScoredObject[];
  scored_objects: ScoredObject[];
  risk_summary: RiskSummary;
  attack_techniques: AttackTechnique[];
  profile: TuningProfile;
  disclaimer?: TriageDisclaimer;
  extraction?: ExtractionHealth;
  /** Selected-plan gaps: rules reading these plugins could not fire for any process. */
  unevaluated_sources?: string[];
}

export interface Triage {
  dumps: { ordinal: number; filename: string; size_bytes: number; sha256: string }[];
  vol_version?: string | null;
  dashboard: Dashboard;
  processes: ProcessItem[];
  profile: TuningProfile;
}

/**
 * What the scoring engine did with this process.
 *
 * An empty risk cell is ambiguous on its own, so the verdict says which of the
 * three it is: a real score, a rule pass that fired nothing, or a process the
 * scorer never evaluated.
 */
export type ProcessEvaluation = "scored" | "no_indicator_fired" | "not_evaluated";

export interface ProcessItem {
  pid: number;
  name: string;
  ppid?: number | null;
  risk?: Risk | null;
  flags: string[];
  analyzable: boolean;
  score?: number | null;
  confidence?: number | null;
  techniques: string[];
  evaluation?: ProcessEvaluation;
}

export interface Diff {
  appeared: { object_type: string; key: string; label: string; risk: Risk; score: number }[];
  disappeared: { object_type: string; key: string; label: string; risk: Risk; score: number }[];
  changed: {
    object_type: string;
    key: string;
    label: string;
    score_from: number;
    score_to: number;
    risk_from: Risk;
    risk_to: Risk;
  }[];
}

export interface RescoreResponse {
  investigation_id: string;
  disclaimer?: TriageDisclaimer;
  profile: TuningProfile;
  risk_summary: RiskSummary;
  attack_techniques: AttackTechnique[];
  scored_objects: ScoredObject[];
  suspicious_processes: unknown[];
  processes: ProcessItem[];
  diff: Diff;
  unevaluated_sources?: string[];
}

export interface Verdict {
  model_loaded: boolean;
  family: string | null;
  confidence: number | null;
  probabilities: Record<string, number>;
  placeholder: boolean;
  note: string;
  model_source?: "trained" | "uploaded" | "placeholder" | "none";
}

export interface Attribution {
  patch_index: number;
  row: number;
  col: number;
  attention: number;
  region_addr: string;
  category: string;
}

/** One patch-backed VAD region, ranked by how much attention it drew. */
export interface RegionRecord {
  patch_index: number;
  row: number;
  col: number;
  rank: number;
  attention: number;
  addr: string;
  addr_int: number;
  end_addr: string | null;
  size: number;
  tag: string;
  protection: string;
  category: string;
  file_backing: string;
  private: boolean;
  snapshot_ordinal: number | null;
  sha256: string;
  entropy: number;
  executable: boolean;
  writable: boolean;
  flags: string[];
}

export interface Instruction {
  address: number;
  address_hex: string;
  size: number;
  bytes_hex: string;
  mnemonic: string;
  op_str: string;
  text: string;
  kind: string;
  target: number | null;
}

export interface CfgBlock {
  id: number;
  start: number;
  start_hex: string;
  end_hex: string;
  instruction_count: number;
  terminator: string;
  layer: number;
  order: number;
  label: string;
  branch_target: number | null;
  instructions: Instruction[];
}

export interface CfgEdge {
  source: number;
  target: number;
  kind: "taken" | "fallthrough" | "jump";
}

export interface CallNode {
  id: number;
  address: number;
  address_hex: string;
  label: string;
  kind: "entry" | "local" | "external" | "api";
  call_count: number;
  instruction_count: number;
  layer: number;
  order: number;
}

export interface PatternHit {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  technique: string;
  technique_name: string;
  occurrences: number;
  offsets: string[];
  evidence: string;
}

export interface ExtractedString {
  offset: number;
  offset_hex: string;
  encoding: string;
  category: string;
  value: string;
}

export interface HexRow {
  offset: number;
  address: string;
  bytes: string;
  ascii: string;
}

export interface PeSection {
  name: string;
  virtual_address: string;
  virtual_size: number;
  raw_size: number;
  entropy: number;
  characteristics: string;
}

/** Everything MemTriage derives from one region's bytes. */
export interface RegionAnalysis {
  region: RegionRecord;
  summary: {
    headline: string;
    highest_severity: string;
    pattern_count: number;
    techniques: string[];
    instruction_count: number;
    block_count: number;
    function_count: number;
    indirect_calls: number;
    entropy: number;
    pe_present: boolean;
    caveat: string;
  };
  structure: {
    size: number;
    analyzed_bytes: number;
    truncated: boolean;
    entropy: {
      overall: number;
      windows: number[];
      peak: number;
      peak_offset_hex: string;
      window_bytes: number;
      high_entropy_ratio: number;
    };
    histogram: number[];
    printable_ratio: number;
    pe: {
      present: boolean;
      reason: string;
      machine: string;
      is_dll: boolean;
      entry_point: string;
      image_base: string;
      timestamp: number;
      subsystem: string;
      characteristics: string[];
      parser: string;
      sections: PeSection[];
      imported_dlls: string[];
    };
    hexdump: HexRow[];
    error?: string;
  };
  disassembly: {
    available: boolean;
    arch: string;
    reason: string;
    base_addr: string;
    analyzed_bytes: number;
    truncated: boolean;
    invalid_bytes: number;
    coverage: number;
    entry_points: string[];
    instruction_count: number;
    instructions: Instruction[];
  };
  control_flow: {
    available: boolean;
    reason: string;
    entry_block: number | null;
    truncated: boolean;
    loops: number;
    unreachable_blocks: number;
    block_count: number;
    edge_count: number;
    blocks: CfgBlock[];
    edges: CfgEdge[];
    dot: string;
  };
  call_graph: {
    available: boolean;
    reason: string;
    indirect_calls: number;
    resolved_apis: string[];
    truncated: boolean;
    node_count: number;
    edge_count: number;
    nodes: CallNode[];
    edges: { source: number; target: number; count: number }[];
    dot: string;
  };
  strings: {
    total_found: number;
    truncated: boolean;
    by_category: Record<string, number>;
    interesting: ExtractedString[];
    strings: ExtractedString[];
    error?: string;
  };
  patterns: {
    instruction_scan: boolean;
    note: string;
    hit_count: number;
    highest_severity: string;
    hits: PatternHit[];
  };
}

export interface LowLevelReport {
  generated_at: string;
  grid_size: number;
  ranked_regions: number;
  regions: RegionAnalysis[];
  summary: {
    analyzed: number;
    techniques: string[];
    highest_severity: string;
    top_region?: string;
    top_region_patterns?: number;
  };
}

export interface AnalysisResult {
  analysis_id: string;
  pid: number;
  process_name: string;
  chosen_dump_ordinal: number | null;
  region_count: number | null;
  verdict: Verdict;
  explainability: {
    grid_png: string | null;
    attention_png: string | null;
    attributions: Attribution[];
    region_count_ranked?: number;
    regions_analyzed?: number;
  };
  regions?: RegionRecord[];
  region_analysis_summary?: LowLevelReport["summary"];
  notes?: string[];
}

export interface AnalysisState {
  analysis_id: string;
  investigation_id: string;
  pid: number;
  process_name: string;
  status: "queued" | "analyzing" | "done" | "failed";
  stage: string;
  progress: number;
  message: string;
  model_loaded: boolean;
  verdict_family: string | null;
  verdict_confidence: number | null;
  region_count: number | null;
  has_result: boolean;
  error?: string | null;
}

// --- Shared VolMemLyzer triage/manual-run surfaces ---

export interface PluginCatalogEntry {
  name: string;
  category: string;
  cost: "fast" | "scan" | "heavy";
  deps: string[];
  in_light_set: boolean;
  in_deep_set: boolean;
  /** Kept while older cached catalogues are upgraded. */
  in_triage_set?: boolean;
}

/**
 * One normalized live event. `type` selects which of the optional fields are
 * present — mirrors backend/memtriage/pipeline/plugin_runner.py. One behavior
 * worth designing around is that a cache hit is `plugin_cached`, not
 * `plugin_finished`, because the runner is never invoked for it.
 */
export interface PluginEvent {
  type:
    | "plan"
    | "layer_dispatched"
    | "plugin_dispatched"
    | "plugin_started"
    | "plugin_finished"
    | "plugin_cached"
    | "plugin_converted"
    | "plugin_failed_detail"
    | "plugin_failed"
    | "plugin_unavailable"
    | "plugin_timeout"
    | "run_summary"
    | "heartbeat"
    | "cache_reused"
    | "cache_seeded"
    | "cache_copy_started"
    | "cache_copy_progress"
    | "cache_copy_finished"
    | "cache_copy_failed"
    | "artifact_ready"
    | "log";
  at: number;
  layers?: string[][];
  concurrency?: number;
  plugins?: string[];
  plugin?: string;
  rc?: number;
  ok?: boolean;
  duration_s?: number;
  explanation?: string;
  timeout_s?: number;
  from_format?: string;
  to_format?: string;
  failed?: number;
  attempted?: number;
  plugin_names?: string;
  level?: string;
  logger?: string;
  line?: string;
  elapsed_s?: number;
  message?: string;
  source?: string;
  artifact?: string;
  size_bytes?: number;
  bytes_copied?: number;
  synthetic?: boolean;
}

export interface PluginRunState {
  plugin_run_id: string;
  investigation_id: string;
  status: "queued" | "running" | "done" | "failed" | "cancelled";
  stage: string;
  progress: number;
  message: string;
  error?: string | null;
  requested_plugins: string[];
  concurrency: number;
  events: PluginEvent[];
  available_outputs: string[];
  failed_plugins: Record<string, string>;
}

export type PluginOutputFormat = "json" | "csv";

export interface PluginOutputPreview {
  plugin: string;
  format: string;
  columns: string[];
  rows: Array<Record<string, unknown>>;
  row_count: number;
  truncated: boolean;
  cached: boolean;
  data?: unknown | null;
  offset?: number;
  limit?: number;
  total?: number;
}

export interface ModelAccessPolicy {
  contact: string;
  intended_use_options: { value: string; label: string }[];
  policy: string;
  terms: string;
  model: ModelState;
}

/** Which weights this deployment is actually running, and what an upload needs. */
export interface ModelState {
  active_source: "trained" | "uploaded" | "placeholder";
  trained_weights_present: boolean;
  uploaded_weights_present: boolean;
  uploaded_weights: {
    filename: string;
    size_bytes: number;
    uploaded_at: string;
    labels_uploaded: boolean;
    /** Stored, but a mounted checkpoint outranks it. */
    superseded_by_mount: boolean;
  } | null;
  placeholder_active: boolean;
  placeholder_cached: boolean;
  auto_placeholder: boolean;
  runtime_available: boolean;
  labels: string[];
  max_upload_bytes: number;
  expected_filename: string;
  contact: string;
  note: string;
}

export interface ModelUploadResult {
  stored: boolean;
  size_bytes: number;
  labels_stored: boolean;
  model: ModelState;
}

export interface ModelAccessRequest {
  full_name: string;
  email: string;
  organization: string;
  role: string;
  country: string;
  intended_use: string;
  project_description: string;
  expected_publication: string;
  agrees_to_terms: boolean;
}

export interface ModelAccessResponse {
  request_id: string;
  submitted_at: string;
  contact: string;
  email_subject: string;
  email_body: string;
  mailto: string;
  note: string;
}

// --- Report / evidence curation -------------------------------------------

export type ConfidenceLevel =
  | "confirmed"
  | "high_confidence"
  | "medium_confidence"
  | "low_confidence"
  | "insufficient_evidence";

/** What the analyst concluded a finding *is*. */
export type Disposition =
  | "undetermined"
  | "attacker_activity"
  | "examiner_artifact"
  | "benign";

export type EvidenceKind = "finding" | "region" | "stage";

export type NarrativeSection =
  | "hypothesis"
  | "executive_summary"
  | "scope_objectives"
  | "recommendations"
  | "examiner_info";

export interface ReportEvidence {
  id: string;
  evidence_kind: EvidenceKind;
  /** The report's stable identity for this evidence — never the raw scored key. */
  ref: string;
  pid: number | null;
  label: string;
  analyst_note: string;
  analyst_confidence: ConfidenceLevel | null;
  disposition: Disposition | null;
  sort_order: number;
  /** Optimistic-concurrency token; send it back with the next write. */
  version: number;
  updated_at: string | null;
}

export interface NarrativeEntry {
  content: string;
  source: "analyst" | "drafted";
  updated_at: string | null;
}

export interface ReportFinding {
  ref: string;
  object: ScoredObject;
  headline: string;
  rationale: string;
  techniques: string;
  analyst_note?: string;
  /** Prose a model wrote about this finding. Never merged with analyst_note:
   *  a reader has to be able to tell which sentences a human stands behind. */
  drafted_note?: string;
  disposition?: Disposition;
  analyst_confidence?: ConfidenceLevel;
}

export interface ReportStage {
  tactic: string;
  blurb: string;
  findings: ReportFinding[];
  count: number;
  techniques: string[];
  highest_risk: string;
  analyst_note?: string;
  drafted_note?: string;
}

/** One memory region as the document renders it (subset of the backend exhibit). */
export interface ReportExhibit {
  ref: string;
  pid: number;
  process_name: string;
  addr: string;
  protection: string;
  headline: string;
  analyst_note?: string;
}

export interface ReportDocument {
  investigation_id: string;
  audience: "technical" | "executive";
  generated_at: string;
  overview: string;
  progression: string;
  findings: ReportFinding[];
  examiner_artifacts: ReportFinding[];
  /** True once the analyst has pinned anything: the document is then their selection. */
  curated: boolean;
  scored_total: number;
  /** Identity for every scored object, independent of what the document renders. */
  refs: { object_type: string; key: string; label: string; ref: string }[];
  stages: ReportStage[];
  exhibits: ReportExhibit[];
  notices: string[];
  sections: { id: string; number: number; title: string }[];
  /** Present once a narrative has been drafted; `attached` counts the passages
   *  that bound to evidence still in this document. */
  narration?: {
    stages?: Record<string, string>;
    findings?: Record<string, string>;
    provider?: string;
    model?: string;
    drafted_at?: string | null;
    attached?: number;
    dropped?: number;
  };
}

// --- Timeline / correlation -------------------------------------------------

export type TimelineEventKind =
  | "process_start"
  | "process_exit"
  | "connection"
  | "task_created"
  | "task_last_success"
  | "task_last_run"
  | "program_run";

export interface TimelineFinding {
  ref: string;
  risk: Risk;
  label: string;
  object_type: string;
}

export interface TimelineEvent {
  id: string;
  at: string;
  kind: TimelineEventKind;
  source: string;
  detail: string;
  process_id: string | null;
  pid: number | null;
  name: string;
  findings: TimelineFinding[];
  links: { type: string; text: string; process_id?: string }[];
  reasons: string[];
  relevant: boolean;
  risk: Risk | null;
}

export interface TimelineProcess {
  id: string;
  pid: number;
  ppid: number | null;
  name: string;
  created: string | null;
  exited: string | null;
  cmd: string;
  path: string;
  sources: string[];
  parent_id: string | null;
  parent_recovered: boolean;
  children_ids: string[];
  unlinked: boolean;
  ancestors: string[];
  findings: TimelineFinding[];
  risk: Risk | null;
}

export interface Timeline {
  events: TimelineEvent[];
  processes: Record<string, TimelineProcess>;
  flagged: string[];
  sources: { present: string[]; missing: string[] };
}


/** One provider the drafted narrative (or the assistant) may be sent to. */
export interface AssistantProvider {
  id: string;
  label: string;
  default_model: string;
  models: string[];
  needs_key: boolean;
  local?: boolean;
  note?: string;
}

export interface AssistantProviders {
  providers: AssistantProvider[];
  custom_endpoints_enabled: boolean;
  consent_notice: string;
}

export interface DraftNarrativeRequest {
  provider: string;
  model?: string;
  api_key?: string;
  base_url?: string | null;
  write_executive_summary?: boolean;
}

export interface DraftedNarrative {
  stored: number;
  provider: string;
  model: string;
  executive_summary: string;
  stages: Record<string, string>;
  findings: Record<string, string>;
  /** Refs the model returned that this document does not contain. */
  unmatched: string[];
}

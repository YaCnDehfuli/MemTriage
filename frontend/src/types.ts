// Shapes mirrored from the FastAPI backend (schemas.py + scoring/pipeline output).

export type Risk = "Critical" | "High" | "Medium" | "Low";
export type Stage = "ingest" | "triage" | "inventory" | "deepdive" | "report";

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
  object_type: "process" | "connection" | "persistence";
  key: string;
  label: string;
  pid: number | null;
  score: number;
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
}

export interface Triage {
  dumps: { ordinal: number; filename: string; size_bytes: number; sha256: string }[];
  vol_version?: string | null;
  dashboard: Dashboard;
  processes: ProcessItem[];
  profile: TuningProfile;
}

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
  profile: TuningProfile;
  risk_summary: RiskSummary;
  attack_techniques: AttackTechnique[];
  scored_objects: ScoredObject[];
  suspicious_processes: unknown[];
  diff: Diff;
}

export interface Verdict {
  model_loaded: boolean;
  family: string | null;
  confidence: number | null;
  probabilities: Record<string, number>;
  placeholder: boolean;
  note: string;
  model_source?: "trained" | "placeholder" | "none";
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

export interface ModelAccessPolicy {
  contact: string;
  intended_use_options: { value: string; label: string }[];
  policy: string;
  terms: string;
  model: {
    trained_weights_present: boolean;
    placeholder_active: boolean;
    placeholder_cached: boolean;
    auto_placeholder: boolean;
    runtime_available: boolean;
    contact: string;
    note: string;
  };
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

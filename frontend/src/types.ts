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
}

export interface Attribution {
  patch_index: number;
  row: number;
  col: number;
  attention: number;
  region_addr: string;
  category: string;
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
  };
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
}

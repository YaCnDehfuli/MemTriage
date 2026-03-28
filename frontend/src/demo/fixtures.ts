// Demo mode: realistic canned data so the entire flow — ingest → triage → tuning
// → inventory → VADViT deep-dive → report — is clickable with no backend,
// Volatility or PyTorch. Kept isolated here so it can be removed wholesale.
import type { ApiClient, ConsolidatedResult } from "../api/client";
import type {
  AnalysisResult,
  AttackTechnique,
  Diff,
  ProcessItem,
  RescoreResponse,
  ScoredObject,
  Triage,
  TuningProfile,
} from "../types";

const band = (score: number, bands: Record<string, number>) =>
  score >= bands.critical
    ? "Critical"
    : score >= bands.high
      ? "High"
      : score >= bands.medium
        ? "Medium"
        : "Low";

const PRESETS = {
  conservative: {
    bands: { critical: 26, high: 18, medium: 12 },
    thresholds: { process: 9, connection: 8, persistence: 5 },
    floor: 0.55,
  },
  balanced: {
    bands: { critical: 20, high: 14, medium: 9 },
    thresholds: { process: 4, connection: 5, persistence: 2 },
    floor: 0.35,
  },
  aggressive: {
    bands: { critical: 16, high: 11, medium: 6 },
    thresholds: { process: 3, connection: 4, persistence: 1 },
    floor: 0.2,
  },
} as const;

type Preset = keyof typeof PRESETS;

// Master object list (pre-surfacing). Each carries a base score + confidence;
// re-scoring just re-bands and re-filters these by the active preset.
const MASTER: ScoredObject[] = [
  {
    object_type: "process",
    key: "1337",
    label: "svchost.exe (1337)",
    pid: 1337,
    score: 35.1,
    confidence: 0.997,
    risk: "Critical",
    tactics: ["Defense Evasion", "Credential Access"],
    techniques: ["T1036", "T1055", "T1003.001"],
    contributions: [
      c("corr_strong_injection", "Corroborated code injection", 8, 0.92, "T1055", "Process Injection", "Defense Evasion", "malfind RWX + unlinked DLL corroborate on this PID"),
      c("core_proc_wrong_path", "Core process wrong image path", 10.8, 0.9, "T1036", "Masquerading", "Defense Evasion", "svchost.exe running from C:\\Users\\alice\\AppData\\Local\\Temp\\svchost.exe; expected under \\windows\\system32"),
      c("malfind_rwx_private", "RWX private memory region", 8.4, 0.7, "T1055", "Process Injection", "Defense Evasion", "RWX private region at 0x1f0000 (PAGE_EXECUTE_READWRITE)"),
      c("ldrmodules_unlinked", "Unlinked / hidden DLL", 5.6, 0.7, "T1055", "Process Injection", "Defense Evasion", "C:\\Users\\alice\\evil.dll unlinked from the InLoad module list"),
      c("lsass_handle", "Handle to lsass.exe", 9, 0.75, "T1003.001", "LSASS Memory", "Credential Access", "svchost.exe holds a handle to lsass.exe (access 0x1410)"),
    ],
  },
  {
    object_type: "process",
    key: "4102",
    label: "rundll32.exe (4102)",
    pid: 4102,
    score: 13.6,
    confidence: 0.86,
    risk: "Medium",
    tactics: ["Execution"],
    techniques: ["T1059"],
    contributions: [
      c("lolbin_from_office", "Office spawned a script interpreter", 9.6, 0.8, "T1059", "Command and Scripting Interpreter", "Execution", "winword.exe spawned rundll32.exe"),
      c("suspicious_process_path", "Image in user-writable path", 2.5, 0.5, "T1036", "Masquerading", "Defense Evasion", "Image in user-writable/staging path (C:\\Users\\alice\\Downloads\\r.dll)"),
    ],
  },
  {
    object_type: "process",
    key: "988",
    label: "hidden.exe (988)",
    pid: 988,
    score: 6.0,
    confidence: 0.75,
    risk: "Low",
    tactics: ["Defense Evasion"],
    techniques: ["T1014"],
    contributions: [
      c("hidden_process", "Hidden / unlinked process", 6, 0.75, "T1014", "Rootkit", "Defense Evasion", "Present in psscan pool scan but absent from the pslist EPROCESS walk"),
    ],
  },
  {
    object_type: "connection",
    key: "TCPv4|10.0.0.5:50210|93.184.216.34:4444",
    label: "TCPv4 10.0.0.5:50210 → 93.184.216.34:4444",
    pid: 1337,
    score: 9.0,
    confidence: 0.75,
    risk: "Medium",
    tactics: ["Command and Control"],
    techniques: ["T1571"],
    contributions: [
      c("net_bad_port", "Known implant/C2 destination port", 9, 0.75, "T1571", "Non-Standard Port", "Command and Control", "Known implant/C2 destination port 4444 to 93.184.216.34"),
    ],
  },
  {
    object_type: "persistence",
    key: "task:updater",
    label: "\\Microsoft\\Windows\\Updater",
    pid: null,
    score: 5.6,
    confidence: 0.7,
    risk: "Low",
    tactics: ["Persistence"],
    techniques: ["T1053.005"],
    contributions: [
      c("scheduled_task_suspicious", "Suspicious scheduled task", 5.6, 0.7, "T1053.005", "Scheduled Task", "Persistence", "Updater: Obfuscated/remote-content command; LOLBIN action [powershell.exe -nop -w hidden -enc …]"),
    ],
  },
];

function c(
  rule_id: string,
  title: string,
  weight: number,
  confidence: number,
  tid: string,
  tname: string,
  tactic: string,
  evidence: string,
) {
  return {
    rule_id,
    title,
    weight,
    evidence,
    mitre: { technique_id: tid, technique_name: tname, tactic },
    severity: Math.min(4, Math.round(weight / 3)),
    confidence,
  };
}

function surface(preset: Preset): ScoredObject[] {
  const p = PRESETS[preset];
  return MASTER.filter(
    (o) =>
      o.score >= (p.thresholds as Record<string, number>)[o.object_type] &&
      o.confidence >= p.floor,
  )
    .map((o) => ({ ...o, risk: band(o.score, p.bands) as ScoredObject["risk"] }))
    .sort((a, b) => b.score - a.score);
}

function riskSummary(objs: ScoredObject[]) {
  const by_risk: Record<string, number> = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const by_type: Record<string, number> = {};
  for (const o of objs) {
    by_risk[o.risk]++;
    by_type[o.object_type] = (by_type[o.object_type] ?? 0) + 1;
  }
  return { total: objs.length, by_risk, by_type };
}

function attack(objs: ScoredObject[]): AttackTechnique[] {
  const agg = new Map<string, AttackTechnique>();
  for (const o of objs)
    for (const ct of o.contributions) {
      const e = agg.get(ct.mitre.technique_id) ?? {
        technique_id: ct.mitre.technique_id,
        name: ct.mitre.technique_name,
        tactic: ct.mitre.tactic,
        object_count: 0,
        evidence: ct.evidence,
      };
      e.object_count++;
      agg.set(ct.mitre.technique_id, e);
    }
  return [...agg.values()].sort((a, b) => b.object_count - a.object_count);
}

function profileOf(preset: Preset): TuningProfile {
  const p = PRESETS[preset];
  return {
    preset,
    risk_bands: p.bands,
    confidence_floor: p.floor,
    category_thresholds: p.thresholds,
    require_correlation: false,
    rule_overrides: {},
  };
}

const PROCESSES: ProcessItem[] = [
  { pid: 4, name: "System", ppid: 0, analyzable: false, flags: [], techniques: [] },
  { pid: 600, name: "services.exe", ppid: 500, analyzable: true, flags: [], techniques: [] },
  { pid: 640, name: "lsass.exe", ppid: 500, analyzable: true, flags: [], techniques: [] },
  { pid: 812, name: "explorer.exe", ppid: 780, analyzable: true, flags: [], techniques: [] },
  { pid: 900, name: "winword.exe", ppid: 812, analyzable: true, flags: [], techniques: [] },
  { pid: 988, name: "hidden.exe", ppid: 4, analyzable: true, risk: "Low", score: 6.0, confidence: 0.75, flags: ["hidden_process"], techniques: ["T1014"] },
  { pid: 1337, name: "svchost.exe", ppid: 600, analyzable: true, risk: "Critical", score: 35.1, confidence: 0.997, flags: ["core_proc_wrong_path", "malfind_rwx_private", "ldrmodules_unlinked", "lsass_handle"], techniques: ["T1036", "T1055", "T1003.001"] },
  { pid: 4102, name: "rundll32.exe", ppid: 900, analyzable: true, risk: "Medium", score: 13.6, confidence: 0.86, flags: ["lolbin_from_office"], techniques: ["T1059"] },
];

function gridSvg(): string {
  const cells: string[] = [];
  let seed = 7;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (let r = 0; r < 7; r++)
    for (let col = 0; col < 7; col++) {
      const filled = r * 7 + col < 30;
      const R = filled ? 40 + Math.floor(rnd() * 90) : 8;
      const G = filled ? Math.floor(rnd() * 220) : 8;
      const B = filled ? Math.floor(rnd() * 220) : 12;
      cells.push(`<rect x="${col * 32}" y="${r * 32}" width="32" height="32" fill="rgb(${R},${G},${B})"/>`);
    }
  return `<svg xmlns='http://www.w3.org/2000/svg' width='224' height='224'>${cells.join("")}</svg>`;
}

function attentionSvg(): string {
  const hot = [8, 9, 15, 16, 23]; // patches the model attended to
  const blobs = hot
    .map((i) => {
      const cx = (i % 7) * 32 + 16;
      const cy = Math.floor(i / 7) * 32 + 16;
      return `<circle cx='${cx}' cy='${cy}' r='34' fill='url(#m)' opacity='0.85'/>`;
    })
    .join("");
  return `<svg xmlns='http://www.w3.org/2000/svg' width='224' height='224'>
    <defs><radialGradient id='m'>
      <stop offset='0%' stop-color='rgb(252,253,191)'/>
      <stop offset='45%' stop-color='rgb(229,80,100)'/>
      <stop offset='100%' stop-color='rgb(20,10,40)' stop-opacity='0'/>
    </radialGradient></defs>
    <rect width='224' height='224' fill='rgb(10,14,22)'/>${gridSvg().replace(/^<svg[^>]*>|<\/svg>$/g, "")}${blobs}</svg>`;
}

const dataUri = (svg: string) => `data:image/svg+xml,${encodeURIComponent(svg)}`;

const ANALYSIS: AnalysisResult = {
  analysis_id: "demo-analysis",
  pid: 1337,
  process_name: "svchost.exe",
  chosen_dump_ordinal: 2,
  region_count: 30,
  verdict: {
    model_loaded: true,
    family: "Placeholder_Trojan",
    confidence: 0.514,
    probabilities: {
      Benign: 0.061,
      Placeholder_Backdoor: 0.079,
      Placeholder_Downloader: 0.044,
      Placeholder_Dropper: 0.052,
      Placeholder_Keylogger: 0.038,
      Placeholder_Ransomware: 0.066,
      Placeholder_Rootkit: 0.048,
      Placeholder_Trojan: 0.514,
      Placeholder_Worm: 0.098,
    },
    placeholder: true,
    note: "Structural placeholder model — the family label is NOT a real detection.",
  },
  explainability: {
    grid_png: "grid",
    attention_png: "attention",
    attributions: [
      { patch_index: 8, row: 1, col: 1, attention: 1.0, region_addr: "0x1f0000", category: "exe" },
      { patch_index: 9, row: 1, col: 2, attention: 0.91, region_addr: "0x210000", category: "exe" },
      { patch_index: 16, row: 2, col: 2, attention: 0.73, region_addr: "0x7ffb1200000", category: "dll" },
      { patch_index: 15, row: 2, col: 1, attention: 0.66, region_addr: "0x7ffb0f40000", category: "dll" },
      { patch_index: 23, row: 3, col: 2, attention: 0.51, region_addr: "0x7ffb0a10000", category: "dll" },
    ],
  },
};

function demoTriage(preset: Preset): Triage {
  const objs = surface(preset);
  return {
    dumps: [
      { ordinal: 0, filename: "host-t0.raw", size_bytes: 4294967296, sha256: "a1b2…9f0c" },
      { ordinal: 1, filename: "host-t1.raw", size_bytes: 4294967296, sha256: "77de…12ab" },
      { ordinal: 2, filename: "host-t2.raw", size_bytes: 4294967296, sha256: "c0ff…ee01" },
    ],
    vol_version: "Volatility 3 Framework 2.26.2",
    dashboard: {
      features: { "pslist.nproc": 84, "malfind.ninjections": 3, "netscan.nconn": 41 },
      injections: [],
      network: [],
      suspicious_processes: [],
      persistence: objs.filter((o) => o.object_type === "persistence"),
      scored_objects: objs,
      risk_summary: riskSummary(objs),
      attack_techniques: attack(objs),
      profile: profileOf(preset),
    },
    processes: PROCESSES,
    profile: profileOf(preset),
  };
}

export function createDemoClient(): ApiClient {
  let lastSurfaced: ScoredObject[] = surface("balanced");
  const id = "demo-investigation";
  return {
    demo: true,
    async createInvestigation() {
      return { investigation_id: id };
    },
    async addDump() {
      return { ordinal: 0, dump_count: 3 };
    },
    async startTriage() {
      return investigationState();
    },
    async getInvestigation() {
      return investigationState();
    },
    async getResult(): Promise<ConsolidatedResult> {
      return { investigation_id: id, triage: demoTriage("balanced"), process_analyses: [ANALYSIS] };
    },
    async listProcesses() {
      return PROCESSES;
    },
    async rescore(_id, profile): Promise<RescoreResponse> {
      const preset = (profile.preset ?? "balanced") as Preset;
      const objs = surface(preset);
      const diff = computeDiff(lastSurfaced, objs);
      lastSurfaced = objs;
      return {
        investigation_id: id,
        profile: profileOf(preset),
        risk_summary: riskSummary(objs),
        attack_techniques: attack(objs),
        scored_objects: objs,
        suspicious_processes: [],
        diff,
      };
    },
    async analyzeProcess(_id, pid) {
      return { ...analysisState(), pid };
    },
    async getAnalysis() {
      return analysisState();
    },
    artifactUrl(_id, _pid, kind) {
      return dataUri(kind === "grid" ? `<svg xmlns='http://www.w3.org/2000/svg' width='224' height='224'><rect width='224' height='224' fill='rgb(10,14,22)'/>${gridSvg().replace(/^<svg[^>]*>|<\/svg>$/g, "")}</svg>` : attentionSvg());
    },
  };

  function investigationState() {
    return {
      investigation_id: id,
      status: "triaged" as const,
      stage: "triaged",
      progress: 100,
      message: "Triage complete — select a process to analyze",
      dump_count: 3,
      total_bytes: 3 * 4294967296,
      process_count: PROCESSES.length,
      has_triage: true,
      summary: { risk_summary: riskSummary(lastSurfaced) },
    };
  }
  function analysisState() {
    return {
      analysis_id: "demo-analysis",
      investigation_id: id,
      pid: 1337,
      process_name: "svchost.exe",
      status: "done" as const,
      stage: "done",
      progress: 100,
      message: "Process analysis complete",
      model_loaded: true,
      verdict_family: "Placeholder_Trojan",
      verdict_confidence: 0.514,
      region_count: 30,
      has_result: true,
    };
  }
}

function computeDiff(prev: ScoredObject[], cur: ScoredObject[]): Diff {
  const idx = (o: ScoredObject) => `${o.object_type}|${o.key}`;
  const pm = new Map(prev.map((o) => [idx(o), o]));
  const cm = new Map(cur.map((o) => [idx(o), o]));
  return {
    appeared: cur
      .filter((o) => !pm.has(idx(o)))
      .map((o) => ({ object_type: o.object_type, key: o.key, label: o.label, risk: o.risk, score: o.score })),
    disappeared: prev
      .filter((o) => !cm.has(idx(o)))
      .map((o) => ({ object_type: o.object_type, key: o.key, label: o.label, risk: o.risk, score: o.score })),
    changed: cur
      .filter((o) => pm.has(idx(o)) && pm.get(idx(o))!.risk !== o.risk)
      .map((o) => ({
        object_type: o.object_type,
        key: o.key,
        label: o.label,
        score_from: pm.get(idx(o))!.score,
        score_to: o.score,
        risk_from: pm.get(idx(o))!.risk,
        risk_to: o.risk,
      })),
  };
}

export { demoTriage };

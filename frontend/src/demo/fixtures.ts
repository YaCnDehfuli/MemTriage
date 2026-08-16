// Demo mode: realistic canned data so the entire flow — ingest → triage → tuning
// → inventory → VADViT deep-dive → report — is clickable with no backend,
// Volatility or PyTorch. Kept isolated here so it can be removed wholesale.
import type { ApiClient, ConsolidatedResult } from "../api/client";
import type {
  AnalysisResult,
  AssistantCatalogue,
  AttackTechnique,
  ContextPackSummary,
  Diff,
  Instruction,
  LowLevelReport,
  ModelAccessPolicy,
  ProcessItem,
  RegionAnalysis,
  RegionRecord,
  RescoreResponse,
  ScoredObject,
  Triage,
  TriageDisclaimer,
  TuningProfile,
} from "../types";

const DEMO_DISCLAIMER: TriageDisclaimer = {
  headline: "Clues for review, not conclusions.",
  summary:
    "Phase 1 extracts structured, statistically significant features from the image and " +
    "applies simple, tuned rules to them. Everything it surfaces is a lead for an analyst " +
    "to confirm or dismiss — not an established fact, a detection, or an attribution.",
  points: [
    "The rules are basic and hand-tuned. They encode well-known indicators, not learned " +
      "behaviour, and they carry no notion of ground truth.",
    "Scores and risk bands are relative ranking aids under the current profile. Re-tuning " +
      "changes them; it does not change the underlying image.",
    "A high score means 'look here first'. A low score is not a clean bill of health — an " +
      "absent indicator is only an indicator that did not fire.",
    "ATT&CK techniques are alignment for triage. They describe what an artifact resembles, " +
      "not what was confirmed to have happened.",
    "Every value here is derived from an untrusted memory image and can be influenced by " +
      "whatever produced that image.",
  ],
  intent:
    "The aim is a fast multi-view of one memory image, with the structured features an " +
    "analyst needs to decide where to spend manual effort.",
};

const DEMO_PROVIDERS: AssistantCatalogue = {
  custom_endpoints_enabled: false,
  consent_notice:
    "Sending a question forwards the briefing — memory-derived metadata, region " +
    "addresses, disassembly and extracted strings — to the provider you choose. Pick a " +
    "local provider to keep it on this machine. Your API key is used for the request " +
    "and is never stored or logged.",
  suggested_questions: [
    "What are the three strongest leads in this image, and what would confirm each?",
    "Walk me through the highest-attention region: what does its code appear to do?",
    "Which findings could plausibly be benign, and what would tell them apart?",
    "What is missing from this briefing that I would need to reach a conclusion?",
    "Summarize this investigation as a handover note for the next analyst.",
  ],
  providers: [
    { id: "anthropic", label: "Anthropic", transport: "anthropic",
      base_url: "https://api.anthropic.com", default_model: "claude-opus-5",
      models: ["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"],
      key_env: "ANTHROPIC_API_KEY", docs_url: "https://docs.claude.com/en/api/overview",
      prompt_cache: "explicit", needs_key: true, local: false,
      note: "The briefing is sent as a cached system block, so repeat questions " +
        "re-read it from cache rather than re-sending it." },
    { id: "openai", label: "OpenAI", transport: "openai",
      base_url: "https://api.openai.com/v1", default_model: "gpt-4.1",
      models: ["gpt-4.1", "gpt-4.1-mini", "o4-mini"], key_env: "OPENAI_API_KEY",
      docs_url: "https://platform.openai.com/docs/api-reference/chat",
      prompt_cache: "automatic", needs_key: true, local: false, note: "" },
    { id: "groq", label: "Groq", transport: "openai",
      base_url: "https://api.groq.com/openai/v1",
      default_model: "llama-3.3-70b-versatile",
      models: ["llama-3.3-70b-versatile", "llama-3.1-8b-instant"],
      key_env: "GROQ_API_KEY", docs_url: "https://console.groq.com/docs/api-reference",
      prompt_cache: "none", needs_key: true, local: false, note: "" },
    { id: "ollama", label: "Ollama (local)", transport: "openai",
      base_url: "http://localhost:11434/v1", default_model: "llama3.1",
      models: ["llama3.1", "qwen2.5"], key_env: "",
      docs_url: "https://docs.ollama.com/openai", prompt_cache: "none",
      needs_key: false, local: true,
      note: "Runs on the analyst's own machine, so the briefing never leaves the host." },
  ],
};

const DEMO_CONTEXT: ContextPackSummary = {
  investigation_id: "demo-investigation",
  sha256: "9f2c41ab7d5e0c38b6142f9e07ad5c31882be0f4a17d69c530be71f2ac48d905",
  approx_tokens: 3120,
  sections: ["How to read this briefing", "Evidence", "Risk posture (phase 1)",
             "Scored objects (phase 1 leads)", "Process inventory",
             "Statistical features", "Process deep-dives (phase 2)",
             "Scope of this briefing"],
  truncated_sections: [],
  consent_notice:
    "Demo mode never sends anything. In live mode the briefing below is what would " +
    "be forwarded to your chosen provider.",
  markdown: [
    "# MemTriage investigation briefing",
    "",
    "Investigation: `demo-investigation`",
    "",
    "## How to read this briefing",
    "",
    "**Phase 1 — Clues for review, not conclusions.**",
    "",
    "Phase 1 extracts structured, statistically significant features from the image",
    "and applies simple, tuned rules to them. Everything it surfaces is a lead.",
    "",
    "## Evidence",
    "",
    "- Snapshots: 3",
    "- Volatility: Volatility 3 Framework 2.26.2",
    "",
    "## Scored objects (phase 1 leads)",
    "",
    "### process · svchost.exe:1337",
    "score=35.1 risk=Critical confidence=0.86 pid=1337",
    "- `rwx_private_exec` (+12.0, conf 0.9) [T1055 Process Injection]: private RWX region",
    "",
    "## Process deep-dives (phase 2)",
    "",
    "### PID 1337 — svchost.exe",
    "",
    "- Classifier: `Placeholder_Trojan` at 0.514 (weights: placeholder)",
    "  - **The classifier ran on untrained placeholder weights. This family label is",
    "    not a detection and must not be reported as one.**",
    "",
    "#### Region `0x1f0000` (rank 1)",
    "",
    "0x1f0000 · 40960 bytes · PAGE_EXECUTE_READWRITE — GetPC gadget (call/pop)",
    "",
    "## Scope of this briefing",
    "",
    "- It contains no disk artifacts, no network capture, no host baseline and no timeline.",
  ].join("\n"),
};

function demoAnswer(question: string): string {
  const q = question.toLowerCase();
  if (q.includes("region") || q.includes("assembly") || q.includes("code")) {
    return [
      "The highest-ranked region is `0x1f0000` in PID 1337 — 40 KB of private,",
      "writable-and-executable memory with no backing file.",
      "",
      "Its first instructions are a zero-displacement `call` followed by `pop rbx`,",
      "which recovers the instruction pointer, then a read of `gs:[0x60]` to reach the",
      "PEB. After that there is a short loop that XORs bytes in place. That sequence is",
      "the standard opening of position-independent code that resolves its own imports",
      "and decodes its own payload.",
      "",
      "What this does *not* establish: none of it proves malice. A JIT region can",
      "contain byte-identical gadgets. What makes this one worth your time is the",
      "combination — RWX, no backing file, a decoder loop, and an embedded URL that",
      "matches the phase-1 connection finding.",
      "",
      "Next step: compare `93.184.216.34:4444` against your network telemetry, and",
      "check whether PID 1337's parent is a normal service host on this build.",
      "",
      "_(Demo mode: this is a canned answer. Switch to Live and supply a key to ask a",
      "real model.)_",
    ].join("\n");
  }
  if (q.includes("missing") || q.includes("conclu")) {
    return [
      "This briefing contains one memory image and nothing else. To reach a",
      "conclusion you would need at minimum:",
      "",
      "- disk artifacts for the paths named in the region strings",
      "- network telemetry covering the connection to 93.184.216.34:4444",
      "- a baseline for what this host's svchost instances normally look like",
      "- the trained VADViT weights, since the current family label came from an",
      "  untrained placeholder and carries no information",
      "",
      "_(Demo mode: canned answer.)_",
    ].join("\n");
  }
  return [
    "Three leads, strongest first:",
    "",
    "1. **PID 1337 (svchost.exe)** — score 35.1, Critical. Private RWX memory with a",
    "   GetPC gadget and a decoder loop. Confirm by dumping the region and checking",
    "   whether the decoded bytes resolve imports by hash.",
    "2. **93.184.216.34:4444** — an outbound connection on an unusual port, owned by",
    "   the same PID. Confirm against network telemetry for the same window.",
    "3. **`\\Microsoft\\Windows\\Updater` scheduled task** — persistence-shaped.",
    "   Confirm by reading the task XML from disk.",
    "",
    "All three are leads from simple tuned rules, not detections.",
    "",
    "_(Demo mode: this is a canned answer. Switch to Live and supply a key to ask a",
    "real model.)_",
  ].join("\n");
}

const DEMO_MODEL_ACCESS: ModelAccessPolicy = {
  contact: "yasindeh@yorku.ca",
  intended_use_options: [
    { value: "research", label: "Academic research" },
    { value: "education", label: "Teaching or coursework" },
    { value: "thesis", label: "Thesis or dissertation" },
    { value: "evaluation", label: "Evaluation / benchmarking" },
    { value: "commercial", label: "Commercial use" },
    { value: "other", label: "Other" },
  ],
  policy:
    "The trained VADViT checkpoint is the output of university research and is not " +
    "distributed with this application. MemTriage runs an untrained structural " +
    "placeholder in its place, so every stage of the pipeline still works — but a " +
    "placeholder family label is not a detection. To use the trained weights, send " +
    "the author a short description of your intended use and they will follow up " +
    "directly.",
  terms:
    "Requested weights are for the stated use only, are not redistributed, and any " +
    "published result that relies on them cites the VADViT work.",
  model: {
    trained_weights_present: false,
    placeholder_active: true,
    placeholder_cached: true,
    auto_placeholder: true,
    runtime_available: true,
    contact: "yasindeh@yorku.ca",
    note:
      "Untrained structural placeholder — this family label is NOT a detection. " +
      "The attention map and region analysis below are architectural and still " +
      "describe real memory; the class name is not evidence of anything.",
  },
};

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


// ---- phase 2: ranked regions and one worked low-level example -------------

const DEMO_REGIONS: RegionRecord[] = [
  {
    patch_index: 8, row: 1, col: 1, rank: 1, attention: 1.0,
    addr: "0x1f0000", addr_int: 0x1f0000, end_addr: "0x1fa000", size: 40960,
    tag: "VadS", protection: "PAGE_EXECUTE_READWRITE", category: "exe",
    file_backing: "", private: true, snapshot_ordinal: 2,
    sha256: "3f1a9c4e77b0d2158ac6e0f39b7d4412c8a05e6b1d93f70ac2e5849b6d1fa037",
    entropy: 6.94, executable: true, writable: true,
    flags: ["rwx", "private-executable", "no-file-backing", "high-entropy", "vad-short"],
  },
  {
    patch_index: 9, row: 1, col: 2, rank: 2, attention: 0.91,
    addr: "0x210000", addr_int: 0x210000, end_addr: "0x214000", size: 16384,
    tag: "VadS", protection: "PAGE_EXECUTE_READWRITE", category: "exe",
    file_backing: "", private: true, snapshot_ordinal: 2,
    sha256: "b74c05e918d2af36105c7de24a8b93f16e0d5a7c4b2189fe36d0c5a17b94e2d8",
    entropy: 7.41, executable: true, writable: true,
    flags: ["rwx", "private-executable", "no-file-backing", "mz-header", "high-entropy"],
  },
  {
    patch_index: 16, row: 2, col: 2, rank: 3, attention: 0.73,
    addr: "0x7ffb1200000", addr_int: 0x7ffb1200000, end_addr: "0x7ffb1290000", size: 589824,
    tag: "Vad", protection: "PAGE_EXECUTE_WRITECOPY", category: "dll",
    file_backing: "\\Windows\\System32\\ntdll.dll", private: false, snapshot_ordinal: 2,
    sha256: "5c22ab90e1d4736f8a05be1793c26d40f8e17b5a90cd3e2418fb6740a9c5312e",
    entropy: 6.12, executable: true, writable: false, flags: [],
  },
  {
    patch_index: 15, row: 2, col: 1, rank: 4, attention: 0.66,
    addr: "0x7ffb0f40000", addr_int: 0x7ffb0f40000, end_addr: "0x7ffb0fd0000", size: 585728,
    tag: "Vad", protection: "PAGE_EXECUTE_WRITECOPY", category: "dll",
    file_backing: "\\Windows\\System32\\kernel32.dll", private: false, snapshot_ordinal: 2,
    sha256: "9d17f2c0b6a34e58193d7c02af61b8e5407d29ca31f6b840e2c95d7a061bf3c4",
    entropy: 5.87, executable: true, writable: false, flags: [],
  },
  {
    patch_index: 23, row: 3, col: 2, rank: 5, attention: 0.51,
    addr: "0x7ffb0a10000", addr_int: 0x7ffb0a10000, end_addr: "0x7ffb0a48000", size: 229376,
    tag: "Vad", protection: "PAGE_EXECUTE_WRITECOPY", category: "dll",
    file_backing: "\\Windows\\System32\\ws2_32.dll", private: false, snapshot_ordinal: 2,
    sha256: "1e83b45097d2c6fa3810b7e5924dc0136af7285be09c41d7fa625390e8b7145c",
    entropy: 5.44, executable: true, writable: false, flags: [],
  },
];

function insn(
  address: number, bytesHex: string, mnemonic: string, opStr: string, kind = "normal",
  target: number | null = null,
): Instruction {
  return {
    address, address_hex: `0x${address.toString(16)}`, size: bytesHex.length / 2,
    bytes_hex: bytesHex, mnemonic, op_str: opStr, text: `${mnemonic} ${opStr}`.trim(),
    kind, target,
  };
}

const DEMO_INSTRUCTIONS: Instruction[] = [
  insn(0x1f0000, "e800000000", "call", "0x1f0005", "call", 0x1f0005),
  insn(0x1f0005, "5b", "pop", "rbx"),
  insn(0x1f0006, "4881eb05000000", "sub", "rbx, 5"),
  insn(0x1f000d, "65488b042560000000", "mov", "rax, qword ptr gs:[0x60]"),
  insn(0x1f0016, "488b4018", "mov", "rax, qword ptr [rax + 0x18]"),
  insn(0x1f001a, "488b4020", "mov", "rax, qword ptr [rax + 0x20]"),
  insn(0x1f001e, "4885c0", "test", "rax, rax"),
  insn(0x1f0021, "0f8443000000", "je", "0x1f006a", "cjump", 0x1f006a),
  insn(0x1f0027, "8a0c03", "mov", "cl, byte ptr [rbx + rax]"),
  insn(0x1f002a, "80f13c", "xor", "cl, 0x3c"),
  insn(0x1f002d, "880c03", "mov", "byte ptr [rbx + rax], cl"),
  insn(0x1f0030, "48ffc0", "inc", "rax"),
  insn(0x1f0033, "483d00100000", "cmp", "rax, 0x1000"),
  insn(0x1f0039, "72ec", "jb", "0x1f0027", "cjump", 0x1f0027),
  insn(0x1f003b, "c1cf0d", "ror", "edi, 0xd"),
  insn(0x1f003e, "e827000000", "call", "0x1f006a", "call", 0x1f006a),
  insn(0x1f0043, "4889c1", "mov", "rcx, rax"),
  insn(0x1f0046, "ffd0", "call", "rax", "call"),
  insn(0x1f0048, "4885c0", "test", "rax, rax"),
  insn(0x1f004b, "751d", "jne", "0x1f006a", "cjump", 0x1f006a),
  insn(0x1f004d, "4831c0", "xor", "rax, rax"),
  insn(0x1f0050, "eb18", "jmp", "0x1f006a", "jump", 0x1f006a),
  insn(0x1f006a, "c3", "ret", "", "ret"),
];

const DEMO_REGION_ANALYSIS: RegionAnalysis = {
  region: DEMO_REGIONS[0],
  summary: {
    headline:
      "0x1f0000 · 40960 bytes · PAGE_EXECUTE_READWRITE — highest-severity indicator: " +
      "GetPC gadget (call/pop)",
    highest_severity: "high",
    pattern_count: 6,
    techniques: ["T1027", "T1055", "T1055.001", "T1071.001", "T1106", "T1140"],
    instruction_count: DEMO_INSTRUCTIONS.length,
    block_count: 5,
    function_count: 4,
    indirect_calls: 1,
    entropy: 6.94,
    pe_present: false,
    caveat:
      "Indicators, not conclusions. Every item below is a property of the bytes in " +
      "this region; deciding what it means is the analyst's call.",
  },
  structure: {
    size: 40960,
    analyzed_bytes: 40960,
    truncated: false,
    entropy: {
      overall: 6.94,
      windows: Array.from({ length: 48 }, (_, i) =>
        Number((i < 12 ? 4.1 + i * 0.12 : i < 34 ? 7.6 + Math.sin(i) * 0.15 : 5.2).toFixed(2))),
      peak: 7.78,
      peak_offset_hex: "0x4c00",
      window_bytes: 853,
      high_entropy_ratio: 0.46,
    },
    histogram: Array.from({ length: 32 }, (_, i) => 600 + Math.round(Math.sin(i / 3) * 220 + i * 9)),
    printable_ratio: 0.21,
    pe: {
      present: false,
      reason: "No MZ signature at the start of the region.",
      machine: "", is_dll: false, entry_point: "", image_base: "", timestamp: 0,
      subsystem: "", characteristics: [], parser: "", sections: [], imported_dlls: [],
    },
    hexdump: [
      { offset: 0, address: "0x1f0000", bytes: "e8000000005b4881eb050000006548 8b04".replace(/ /g, ""), ascii: "....[H......eH.." },
      { offset: 16, address: "0x1f0010", bytes: "2560000000488b4018488b40204885", ascii: "%`...H.@.H.@ H." },
      { offset: 32, address: "0x1f0020", bytes: "c00f84430000008a0c0380f13c880c", ascii: "...C..........<." },
      { offset: 48, address: "0x1f0030", bytes: "0348ffc0483d0010000072ecc1cf0d", ascii: ".H..H=....r....." },
    ],
  },
  disassembly: {
    available: true,
    arch: "x86-64",
    reason: "",
    base_addr: "0x1f0000",
    analyzed_bytes: 40960,
    truncated: false,
    invalid_bytes: 0,
    coverage: 0.98,
    entry_points: ["0x1f0000"],
    instruction_count: DEMO_INSTRUCTIONS.length,
    instructions: DEMO_INSTRUCTIONS,
  },
  control_flow: {
    available: true,
    reason: "",
    entry_block: 0,
    truncated: false,
    loops: 1,
    unreachable_blocks: 0,
    block_count: 5,
    edge_count: 6,
    blocks: [
      { id: 0, start: 0x1f0000, start_hex: "0x1f0000", end_hex: "0x1f0027", instruction_count: 8,
        terminator: "cjump", layer: 0, order: 0, label: "0x1f0000", branch_target: 0x1f006a,
        instructions: DEMO_INSTRUCTIONS.slice(0, 8) },
      { id: 1, start: 0x1f0027, start_hex: "0x1f0027", end_hex: "0x1f003b", instruction_count: 6,
        terminator: "cjump", layer: 1, order: 0, label: "0x1f0027", branch_target: 0x1f0027,
        instructions: DEMO_INSTRUCTIONS.slice(8, 14) },
      { id: 2, start: 0x1f003b, start_hex: "0x1f003b", end_hex: "0x1f0043", instruction_count: 2,
        terminator: "call", layer: 2, order: 0, label: "0x1f003b", branch_target: 0x1f006a,
        instructions: DEMO_INSTRUCTIONS.slice(14, 16) },
      { id: 3, start: 0x1f0043, start_hex: "0x1f0043", end_hex: "0x1f0052", instruction_count: 6,
        terminator: "jump", layer: 3, order: 0, label: "0x1f0043", branch_target: 0x1f006a,
        instructions: DEMO_INSTRUCTIONS.slice(16, 22) },
      { id: 4, start: 0x1f006a, start_hex: "0x1f006a", end_hex: "0x1f006b", instruction_count: 1,
        terminator: "ret", layer: 4, order: 0, label: "0x1f006a", branch_target: null,
        instructions: DEMO_INSTRUCTIONS.slice(22) },
    ],
    edges: [
      { source: 0, target: 1, kind: "fallthrough" },
      { source: 0, target: 4, kind: "taken" },
      { source: 1, target: 1, kind: "taken" },
      { source: 1, target: 2, kind: "fallthrough" },
      { source: 2, target: 3, kind: "fallthrough" },
      { source: 3, target: 4, kind: "jump" },
    ],
    dot: "digraph cfg { b0 -> b1; b0 -> b4; b1 -> b1; b1 -> b2; b2 -> b3; b3 -> b4; }",
  },
  call_graph: {
    available: true,
    reason: "",
    indirect_calls: 1,
    resolved_apis: ["VirtualAlloc", "LoadLibraryA", "GetProcAddress", "CreateRemoteThread"],
    truncated: false,
    node_count: 8,
    edge_count: 4,
    nodes: [
      { id: 0, address: 0x1f0000, address_hex: "0x1f0000", label: "entry", kind: "entry",
        call_count: 0, instruction_count: 14, layer: 0, order: 0 },
      { id: 1, address: 0x1f0005, address_hex: "0x1f0005", label: "sub_1f0005", kind: "local",
        call_count: 1, instruction_count: 9, layer: 1, order: 0 },
      { id: 2, address: 0x1f006a, address_hex: "0x1f006a", label: "sub_1f006a", kind: "local",
        call_count: 2, instruction_count: 1, layer: 1, order: 1 },
      { id: 3, address: 0x1f0043, address_hex: "0x1f0043", label: "sub_1f0043", kind: "local",
        call_count: 0, instruction_count: 6, layer: 2, order: 0 },
      { id: 4, address: 0, address_hex: "", label: "VirtualAlloc", kind: "api",
        call_count: 0, instruction_count: 0, layer: 3, order: 0 },
      { id: 5, address: 0, address_hex: "", label: "LoadLibraryA", kind: "api",
        call_count: 0, instruction_count: 0, layer: 3, order: 1 },
      { id: 6, address: 0, address_hex: "", label: "GetProcAddress", kind: "api",
        call_count: 0, instruction_count: 0, layer: 3, order: 2 },
      { id: 7, address: 0, address_hex: "", label: "CreateRemoteThread", kind: "api",
        call_count: 0, instruction_count: 0, layer: 3, order: 3 },
    ],
    edges: [
      { source: 0, target: 1, count: 1 },
      { source: 0, target: 2, count: 1 },
      { source: 1, target: 2, count: 1 },
      { source: 2, target: 3, count: 1 },
    ],
    dot: "digraph calls { n0 -> n1; n0 -> n2; n1 -> n2; n2 -> n3; }",
  },
  strings: {
    total_found: 118,
    truncated: false,
    by_category: { text: 96, url: 2, "windows-path": 6, dll: 8, ipv4: 2, command: 2, base64: 2 },
    interesting: [
      { offset: 0x2a10, offset_hex: "0x2a10", encoding: "ascii", category: "url",
        value: "http://cdn.update-delivery.example/gate.php" },
      { offset: 0x2a48, offset_hex: "0x2a48", encoding: "ascii", category: "ipv4",
        value: "93.184.216.34:4444" },
      { offset: 0x2b00, offset_hex: "0x2b00", encoding: "utf-16le", category: "command",
        value: "powershell -nop -w hidden -enc SQBFAFgA" },
      { offset: 0x2c20, offset_hex: "0x2c20", encoding: "ascii", category: "registry",
        value: "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    ],
    strings: [
      { offset: 0x2a10, offset_hex: "0x2a10", encoding: "ascii", category: "url",
        value: "http://cdn.update-delivery.example/gate.php" },
      { offset: 0x2a48, offset_hex: "0x2a48", encoding: "ascii", category: "ipv4",
        value: "93.184.216.34:4444" },
      { offset: 0x2b00, offset_hex: "0x2b00", encoding: "utf-16le", category: "command",
        value: "powershell -nop -w hidden -enc SQBFAFgA" },
      { offset: 0x2c20, offset_hex: "0x2c20", encoding: "ascii", category: "registry",
        value: "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
      { offset: 0x3110, offset_hex: "0x3110", encoding: "ascii", category: "dll",
        value: "kernel32.dll" },
      { offset: 0x3120, offset_hex: "0x3120", encoding: "ascii", category: "dll",
        value: "ws2_32.dll" },
      { offset: 0x31d0, offset_hex: "0x31d0", encoding: "ascii", category: "windows-path",
        value: "C:\\Users\\Public\\svc32.tmp" },
      { offset: 0x3240, offset_hex: "0x3240", encoding: "ascii", category: "text",
        value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" },
    ],
  },
  patterns: {
    instruction_scan: true,
    note: "",
    hit_count: 6,
    highest_severity: "high",
    hits: [
      { id: "getpc_call_pop", title: "GetPC gadget (call/pop)", severity: "high",
        description:
          "A zero-displacement call followed by a pop recovers the instruction pointer — " +
          "position-independent shellcode locating its own data.",
        technique: "T1055", technique_name: "Process Injection", occurrences: 1,
        offsets: ["0x0"], evidence: "e8000000005b4881eb0500" },
      { id: "peb_walk_x64", title: "PEB walk (64-bit)", severity: "high",
        description: "Reads the PEB via gs:[0x60], the 64-bit equivalent of the fs:[0x30] walk.",
        technique: "T1106", technique_name: "Native API", occurrences: 1,
        offsets: ["0xd"], evidence: "65488b042560000000" },
      { id: "api_hash_ror13", title: "API hashing (ROR-13)", severity: "high",
        description:
          "The ROR-13 export-name hash constant appears — imports are resolved by hash so " +
          "no readable API name is present in the region.",
        technique: "T1027", technique_name: "Obfuscated Files or Information", occurrences: 3,
        offsets: ["0x3b", "0x1a40", "0x1a9c"], evidence: "c1cf0d" },
      { id: "private_executable", title: "Executable private memory", severity: "high",
        description:
          "Executable memory with no backing file on disk — code that cannot be attributed " +
          "to a module the loader mapped.",
        technique: "T1055.001", technique_name: "Dynamic-link Library Injection",
        occurrences: 1, offsets: [], evidence: "PAGE_EXECUTE_READWRITE" },
      { id: "decoder_loop", title: "In-place decoder loop", severity: "high",
        description:
          "A backward branch around arithmetic on moved bytes — the shape of a self-decoding " +
          "or string-deobfuscating stub.",
        technique: "T1140", technique_name: "Deobfuscate/Decode Files or Information",
        occurrences: 1, offsets: ["0x39"], evidence: "" },
      { id: "http_c2", title: "Embedded HTTP endpoint", severity: "medium",
        description:
          "A URL is present in the region — worth correlating with the network artifacts " +
          "surfaced during triage.",
        technique: "T1071.001", technique_name: "Web Protocols", occurrences: 2,
        offsets: ["0x2a10"], evidence: "687474703a2f2f63646e" },
    ],
  },
};

const DEMO_SECOND_REGION: RegionAnalysis = {
  ...DEMO_REGION_ANALYSIS,
  region: DEMO_REGIONS[1],
  summary: {
    ...DEMO_REGION_ANALYSIS.summary,
    headline:
      "0x210000 · 16384 bytes · PAGE_EXECUTE_READWRITE — highest-severity indicator: " +
      "Embedded PE image",
    pattern_count: 4,
    pe_present: true,
    entropy: 7.41,
  },
  structure: {
    ...DEMO_REGION_ANALYSIS.structure,
    size: 16384,
    analyzed_bytes: 16384,
    pe: {
      present: true,
      reason: "",
      machine: "x86-64",
      is_dll: true,
      entry_point: "0x1420",
      image_base: "0x180000000",
      timestamp: 1751328000,
      subsystem: "gui",
      characteristics: ["dynamic-base", "nx-compatible"],
      parser: "pefile",
      sections: [
        { name: ".text", virtual_address: "0x1000", virtual_size: 8192, raw_size: 8192,
          entropy: 6.62, characteristics: "0x60000020" },
        { name: ".rdata", virtual_address: "0x3000", virtual_size: 2048, raw_size: 2048,
          entropy: 4.91, characteristics: "0x40000040" },
        { name: ".data", virtual_address: "0x4000", virtual_size: 1024, raw_size: 512,
          entropy: 7.83, characteristics: "0xc0000040" },
      ],
      imported_dlls: ["kernel32.dll", "advapi32.dll", "ws2_32.dll"],
    },
  },
  patterns: {
    ...DEMO_REGION_ANALYSIS.patterns,
    hit_count: 4,
    hits: DEMO_REGION_ANALYSIS.patterns.hits.slice(0, 4),
  },
};

const DEMO_LOWLEVEL: LowLevelReport = {
  generated_at: "2026-08-16T14:22:05+00:00",
  grid_size: 7,
  ranked_regions: 5,
  regions: [DEMO_REGION_ANALYSIS, DEMO_SECOND_REGION],
  summary: {
    analyzed: 2,
    techniques: ["T1027", "T1055", "T1055.001", "T1071.001", "T1106", "T1140"],
    highest_severity: "high",
    top_region: DEMO_REGION_ANALYSIS.summary.headline,
    top_region_patterns: 6,
  },
};

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
    model_source: "placeholder",
    note:
      "Untrained structural placeholder — this family label is NOT a detection. " +
      "The attention map and region analysis below are architectural and still " +
      "describe real memory; the class name is not evidence of anything.",
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
    region_count_ranked: 5,
    regions_analyzed: 2,
  },
  regions: DEMO_REGIONS,
  region_analysis_summary: {
    analyzed: 2,
    techniques: ["T1055", "T1055.001", "T1071.001", "T1106", "T1140"],
    highest_severity: "high",
    top_region: "0x1f0000 · 40960 bytes · PAGE_EXECUTE_READWRITE — highest-severity indicator: GetPC gadget (call/pop)",
    top_region_patterns: 6,
  },
  notes: [
    "Classification came from an untrained structural placeholder: the family " +
      "label is not a detection. Attention, region ranking and the low-level " +
      "analysis below are unaffected by which weights are loaded.",
    "5 rendered regions ranked by attention; 2 analyzed down to the instruction level.",
    "Region indicators are properties of the bytes, not conclusions about the " +
      "process. Corroborate against the phase-1 artifacts before acting.",
  ],
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
      disclaimer: DEMO_DISCLAIMER,
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
        disclaimer: DEMO_DISCLAIMER,
      };
    },
    async analyzeProcess(_id, pid) {
      return { ...analysisState(), pid };
    },
    async getAnalysis() {
      return analysisState();
    },
    async getRegions() {
      return DEMO_REGIONS;
    },
    async getLowLevel() {
      return DEMO_LOWLEVEL;
    },
    async getModelAccessPolicy() {
      return DEMO_MODEL_ACCESS;
    },
    async requestModelAccess(body) {
      const subject =
        `VADViT trained-model access request — ${body.full_name} (${body.organization})`;
      const text = [
        "Request id: demo-0000",
        "",
        `Name:          ${body.full_name}`,
        `Email:         ${body.email}`,
        `Organization:  ${body.organization}`,
        `Role:          ${body.role}`,
        `Country:       ${body.country || "-"}`,
        `Intended use:  ${body.intended_use}`,
        `Publication:   ${body.expected_publication || "-"}`,
        "",
        "What the model would be used for:",
        body.project_description,
      ].join("\n");
      return {
        request_id: "demo-0000",
        submitted_at: new Date().toISOString(),
        contact: DEMO_MODEL_ACCESS.contact,
        email_subject: subject,
        email_body: text,
        mailto:
          `mailto:${DEMO_MODEL_ACCESS.contact}?subject=${encodeURIComponent(subject)}` +
          `&body=${encodeURIComponent(text)}`,
        note: "Demo mode: nothing was recorded. Copy the message to reach the author.",
      };
    },
    async getAssistantProviders() {
      return DEMO_PROVIDERS;
    },
    async getContextPack() {
      return DEMO_CONTEXT;
    },
    async askAssistant(_id, body) {
      const question = body.messages[body.messages.length - 1]?.content ?? "";
      return {
        text: demoAnswer(question),
        model: body.model || "demo-model",
        provider: body.provider,
        stop_reason: "end_turn",
        usage: {
          input_tokens: DEMO_CONTEXT.approx_tokens,
          output_tokens: 220,
          cache_read_input_tokens: DEMO_CONTEXT.approx_tokens,
          cache_creation_input_tokens: null,
        },
        context: {
          sha256: DEMO_CONTEXT.sha256,
          approx_tokens: DEMO_CONTEXT.approx_tokens,
          sections: DEMO_CONTEXT.sections,
          truncated_sections: [],
          prompt_cache: "explicit",
        },
      };
    },
    async generateScript(_id, body) {
      return {
        provider: body.provider,
        model: body.model || "demo-model",
        language: body.language,
        filename: body.language === "curl" ? "memtriage_ask.sh" : "memtriage_ask.py",
        briefing_filename: "memtriage_briefing.md",
        briefing: DEMO_CONTEXT.markdown ?? "",
        script:
          "# Demo mode returns a placeholder. Switch to Live to generate a script\n" +
          "# wired to your provider and this investigation's briefing.\n",
        instructions:
          "Demo mode does not generate a runnable script. Switch to Live to get one.",
      };
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

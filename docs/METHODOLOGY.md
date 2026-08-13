# How MemTriage reaches its conclusions — and what it does not conclude

MemTriage runs three phases over one memory image. They differ in what they can
support, and the difference matters more than the output of any one of them.

| Phase | What it does | What its output is |
|---|---|---|
| 1 · Triage | VolMemLyzer-backed extraction, then simple tuned rules over the result | **Leads.** Ranked places to look |
| 2 · Deep-dive | VADViT renders a process's VAD regions, classifies, and attention ranks them; the top regions are analyzed to the instruction level | **Observations.** Properties of specific bytes |
| 3 · Assistant | A structured briefing of phases 1 and 2, answered against by an LLM of the analyst's choosing | **A reading aid.** Nothing new is measured |

Nothing in any phase establishes that a host was compromised. That determination
is the analyst's, and it needs corroboration MemTriage does not have — disk
artifacts, network telemetry, timelines, and knowledge of what the host is
supposed to be doing.

---

## Phase 1 — triage

### What is measured

[VolMemLyzer3](https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool)
runs a fixed plugin set once and produces two things: a flat aggregate feature
row (roughly 520 `plugin.metric` values), and cached raw JSON for the plugins
MemTriage needs per-object detail from — `pslist`, `malfind`, `netscan`, and the
context plugins the rules read. The raw JSON is cached so re-scoring never
re-runs Volatility.

The features are statistical descriptions of the image: counts, ratios,
distributions. They are not judgements.

### How rules work

The scoring engine applies a catalogue of rules to those artifacts. Each rule
that fires contributes a weight, a confidence, an evidence string, and an ATT&CK
technique where one applies. An object's score is the sum of its contributions;
its risk band is that score placed against the current profile's thresholds.
Correlation rules add weight when independent indicators point at the same
object.

**The rules are basic and hand-tuned.** They encode well-known indicators —
unbacked executable memory, unusual parentage, suspicious command lines, listening
sockets on odd ports, hollowing-shaped section mismatches. They were tuned by
hand against reference images. They do not learn, and they carry no notion of
ground truth.

### What this supports, and what it does not

- A score is a **relative ranking aid under the current profile**. Moving the
  sensitivity controls changes every score and band on screen; it changes nothing
  about the image.
- A **high score means "look here first."** It is a claim about how many
  indicators lined up, not about intent or outcome.
- A **low score is not a clean bill of health.** An indicator that did not fire
  is exactly that. Malware that avoids the shapes these rules look for scores
  low, which is why phase 1 is a starting point rather than a filter.
- **ATT&CK alignment is descriptive.** It says an artifact resembles a technique.
  It does not say the technique was executed.
- Every value is **derived from an untrusted image** and can be influenced by
  whatever produced it. All dump-derived text is sanitized before it is stored or
  rendered, and never executed.

The intent of phase 1 is a fast multi-view of the image with the structured
features an analyst needs to decide where to spend manual effort. It is
explicitly not an adjudication, and the disclaimer that says so travels with the
data — into `triage.json`, every `/rescore` response, the consolidated result and
the export.

---

## Phase 2 — the VADViT deep-dive

### The model

[VADViT](https://github.com/YaCnDehfuli/VADViT) renders a process's executable
VAD regions into a grid — one patch per region, with tag/protection, windowed
entropy and a Markov byte-transition table in the three channels — and classifies
the grid with a Vision Transformer.

**The trained weights are not distributed with this application.** By default
MemTriage generates an architecturally identical *untrained* model so the
pipeline runs end to end. When that is what produced a verdict, the family label
is meaningless and is marked as such in three places (`placeholder: true`,
`model_source: "placeholder"`, and an explicit note). See
[MODEL_ACCESS.md](MODEL_ACCESS.md).

### What survives the placeholder

Attention is a property of the architecture and the input, not of training. The
attention map, the ranking of regions it produces, and the whole low-level
analysis built on that ranking describe real memory regardless of which weights
are loaded. Only the class name depends on training.

### The low-level analysis

For the highest-ranked regions, MemTriage recovers:

- an **instruction listing** (recursive descent from entry candidates, then a
  linear sweep over the gaps; architecture detected by scoring both x86 and
  x86-64 on decode density);
- **basic blocks and a control-flow graph**, with typed edges and a computed
  layout;
- a **call graph** — direct call targets, prologue-detected functions, notable
  API names present in the bytes, and a count of indirect calls;
- **byte structure** — windowed entropy, byte histogram, printable ratio, PE
  headers when a PE is mapped, and a hexdump;
- **strings**, bucketed into URLs, addresses, paths, registry keys, commands and
  encoded blobs;
- **catalogued patterns** — PEB walks, GetPC gadgets, ROR-13 API hashing,
  Heaven's Gate, NOP sleds, syscall stubs, decoder loops, stack-built strings,
  and properties of the allocation itself (RWX, executable private memory, high
  entropy).

These are **observations about bytes**, and they are honest about their limits:

- A pattern hit is a shape, not an intent. A GetPC gadget in a JIT region and one
  in an injected buffer are byte-identical; the surrounding region metadata is
  what separates them.
- **No pattern hits is not "clean."** The catalogue covers known shapes only.
- Disassembly of a memory dump has no symbols and no reliable entry point.
  Recovered function boundaries are inferred, and an indirect call's target
  cannot be resolved statically — those are counted and reported rather than
  guessed at.
- Analysis is **budgeted**. A large region is analyzed up to a byte and
  instruction cap, and the result says when it was truncated.

Raw region bytes are never served for download; the hexdump is.

---

## Phase 3 — the assistant

The context pack is a deterministic, structured summary of what phases 1 and 2
already produced. The assistant reasons over that text; it does not read the
memory image and cannot measure anything new. Everything it says inherits the
limits above, plus the limits of the model the analyst chose to send it to.

Sending the pack to a hosted provider transmits memory-derived metadata off the
host. The UI says so before the first request, and the API key is held for the
duration of one request — never persisted, never logged.

---

## Reading a MemTriage report

1. Treat phase 1 as a work queue, not a verdict list.
2. Read the rule evidence, not just the score. Every contribution says which rule
   fired and why.
3. In phase 2, read region metadata alongside pattern hits. RWX private memory
   with a decoder loop and a URL is a different story from the same loop in a
   mapped, file-backed module.
4. Corroborate against artifacts MemTriage never saw before concluding anything.

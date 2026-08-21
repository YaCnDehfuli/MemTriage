# How MemTriage reaches its conclusions — and what it does not conclude

MemTriage runs three phases over one memory image. They differ in what they can
support, and the difference matters more than the output of any one of them.

| Phase | What it does | What its output is |
|---|---|---|
| 1 · Triage | Analyst-scoped VolMemLyzer extraction, then simple tuned rules over the available result | **Leads.** Ranked places to look |
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
runs the plugins selected for this investigation and produces two related forms
of evidence: flat `plugin.metric` features and raw JSON records for the objects
the rules inspect. The selected set is real execution scope: it is passed to
both feature extraction and the scoring-record pass. MemTriage does not run an
unselected full extraction behind a smaller selection.

The Triage workbench offers three ways to choose that scope:

- **Light** is a MemTriage preset with eight quick census and persistence
  plugins: `info`, `pslist`, `pstree`, `cmdline`, `privileges`,
  `scheduled_tasks`, `registry.userassist` and `registry.hivelist`. It excludes
  whole-image scanners and plugins classified as heavy.
- **Deep** is the original curated evidence set plus the inexpensive bearings
  plugin (17 total): `info`, `pslist`, `pstree`,
  `psscan`, `psxview`, `cmdline`, `malfind`, `ldrmodules`, `handles`,
  `privileges`, `threads`, `netscan`, `svcscan`, `scheduled_tasks`,
  `registry.userassist`, `registry.hivelist` and `registry.hivescan`.
- **Custom** is exactly the analyst's checked plugin set. It is useful when a
  question is narrower than either preset, or when a known-expensive scanner is
  not worth the delay on this image.

Concurrency controls how many dependency-ready plugins may overlap and is capped
at eight workers. More workers do not make one scanner intrinsically faster and
can increase disk contention on a large image.

These are application presets, not synonyms for the VolMemLyzer CLI's
`analyze --deep` option. In particular, VolMemLyzer currently uses its own
`--deep` flag to add a process cross-check; MemTriage's Deep preset defines the
complete application-side plugin scope above.

The features are statistical descriptions of the selected views of the image:
counts, ratios and distributions. They are not judgements. The feature explorer
shows the extracted flat names and values directly so an analyst can inspect the
measurements behind the dashboard. The number and kinds of available features
therefore vary with the preset or Custom selection.

### The manual suite is part of triage

The same Triage screen contains a manual Volatility suite for questions that do
not belong in the guided scoring run. The analyst can pick a batch, choose its
concurrency and follow it without treating it as another workflow phase. Manual
output is captured in JSON, rendered as a readable table, and downloadable as
JSON or CSV. The CSV is another representation of the captured JSON, not a
second Volatility execution with potentially different evidence.

The API parses an artifact to build the table preview or convert it to CSV, so
those two server-rendered forms are limited to 16 MiB per plugin artifact. The
original JSON download does not parse the document: it streams the file from
disk and remains available regardless of size. Large outputs should therefore be
downloaded as JSON and inspected with local, streaming-capable tools.

A manual run does not silently change an existing score. Its artifacts share the
same cache, however, so a later guided run that explicitly selects the same
plugin can reuse them, and a manual run can reuse an artifact produced by guided
triage.

### Cache and provenance

Caching is enabled by default because whole-image plugins are expensive. A
completed triage is safe to reuse only when all of the following are true:

- the recorded primary-dump SHA-256 matches;
- the exact selected plugin plan matches;
- the record uses triage schema version 2;
- it still carries the default **Balanced** scoring profile rather than a
  subsequently tuned profile;
- extraction is healthy: every selected plugin was attempted and none failed;
- the artifact manifest covers the complete plan, each target is valid JSON of
  the expected row/record shape, and any accompanying stderr has no recognized
  failure marker.

These checks apply to the current investigation's `triage.json` and to a
completed prior MemTriage investigation found by primary-dump SHA. Mode labels
and worker concurrency do not change the evidence when the resulting plugin plan
is identical; the selected plan is the cache identity that matters.

A tuned, degraded, schema-v1, corrupt or incomplete triage is not returned as the
new result. MemTriage instead rebuilds the default scoring view from any raw
artifacts that pass their own JSON/stderr validation and runs Volatility for
missing or invalid selected outputs. **Force refresh** bypasses completed-triage
reuse and raw plugin-artifact reuse for the requested guided-triage operation.

The ordinary upload workflow does not search the dump's source directory or
blindly accept a sibling `analysis.json`. Captured VolMemLyzer output can be
loaded only through the explicit development/test seeder described in the main
README, run from `backend/`:

```bash
python -m memtriage.pipeline.fixture_seed \
  --dumps-dir ../Dumps \
  --image-name 2580_5.vmem
```

It verifies the named image is present, creates an investigation, symlinks that
image, and copies cache-named `<image>_<plugin>.json`/stderr files into the
investigation layout before optionally running triage. This is controlled fixture
import, not cache discovery by filename.

Cache decisions appear in the same activity stream as executions. This matters
methodologically: “cached” means previously measured evidence was reused, while
“completed” means Volatility ran during this operation.

### Activity and long-running plugins

Each selected plugin has a visible queued, running, cached, completed, timed-out
or failed state, with the underlying VolMemLyzer activity alongside it. Progress
is the fraction of selected plugin work that has reached a terminal state. It is
not an estimate of the internal scan position of the plugin currently running.

Runtime is dominated by image size, symbol availability, storage and the plugin's
algorithm. Whole-image and physical-layer scans such as `psscan`, `psxview` and
`netscan` may take hours; on a very large image or slow host a run can approach a
day. A plugin remaining in `running` for a long time is not, by itself, evidence
of a hang. Completion, timeout and failure are recorded distinctly so a slow run
cannot be mistaken for a clean result. MemTriage defaults to a 24-hour per-plugin
timeout (`MEMTRIAGE_VOL_TIMEOUT_S`). The containing Celery task has no shorter
global deadline. Redis's visibility lease is at least
`MEMTRIAGE_BROKER_VISIBILITY_TIMEOUT_S` (60 days by default) and is raised, if
needed, to the current catalog size multiplied by the per-plugin timeout plus six
hours of headroom. The lease governs broker redelivery after worker loss; it is
not an additional runtime allowance for an individual plugin.

### How rules work

The scoring engine applies a catalogue of rules to the selected artifacts. Each
rule that fires contributes a weight, a confidence, an evidence string, and an
ATT&CK technique where one applies. An object's score is the sum of its
contributions; its risk band is that score placed against the current profile's
thresholds. Correlation rules add weight when independent indicators point at
the same object.

A rule whose source plugin was not selected has no evidence to evaluate and
cannot fire. That is different from the plugin running successfully and finding
nothing, and both are different from a plugin failure. The run configuration,
activity and extraction-health information provide that context. Live sensitivity
tuning only re-scores the cached records that exist; it never launches an omitted
plugin implicitly.

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
  is exactly that; a plugin excluded by Light or Custom scope was not checked at
  all. Malware that avoids the shapes these rules look for scores low, which is
  why phase 1 is a starting point rather than a filter.
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

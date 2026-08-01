# MemTriage

MemTriage is an analyst-centered memory-forensics workspace that turns one raw
memory image, or a short sequence of snapshots from the same host, into a
traceable investigation. It combines broad Volatility-based artifact extraction,
tunable ATT&CK-aligned scoring, process inventory review, and targeted VADViT
process-memory analysis in one exportable workflow.

The project is intended for DFIR research, repeatable security engineering, and
portfolio-grade demonstration of a full-stack forensic pipeline. It is not an
EDR replacement, an AV product, or a live endpoint-monitoring system.

![MemTriage triage overview](docs/assets/memtriage-triage-overview.png)

## What it does

- Ingests a single memory dump or up to five interval snapshots from the same
  host.
- Runs VolMemLyzer-backed extraction to build artifact summaries, IoC evidence,
  ATT&CK alignment, and a process/PID inventory.
- Scores evidence with transparent rules that retain severity, confidence,
  source artifacts, and the reason each rule fired.
- Lets the analyst tune sensitivity and rescore cached evidence without
  re-running Volatility.
- Runs VADViT only for selected processes, preserving analyst control over
  expensive model analysis.
- Renders process VAD regions into the model grid and maps attention back to
  concrete memory regions when a compatible model result is available.
- Produces a consolidated report suitable for review, export, and follow-up.

## Investigation workflow

MemTriage follows a two-phase workflow so automated triage does not bury the
analyst in opaque verdicts.

1. **Ingest:** upload one atomic dump or a small interval sequence. Files stream
   to disk with size, count, extension, and magic-byte checks.
2. **Triage:** run Volatility-backed extraction once, normalize the evidence, and
   score the surfaced objects.
3. **Inventory:** review the ranked process list and select the PID that needs a
   deeper explanation.
4. **Deep-dive:** assemble VAD regions for that process, choose the snapshot with
   the richest region set, render the VADViT grid, classify, and attribute model
   attention back to regions.
5. **Report:** fold every selected process analysis into one investigation
   record.

![Process inventory](docs/assets/memtriage-process-inventory.png)

## Architecture

MemTriage wraps two independently published components rather than forking them:

- [VolMemLyzer3](https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool)
  for Volatility 3-based extraction of memory artifacts and IoCs.
- [VADViT](https://github.com/YaCnDehfuli/VADViT) for explainable Vision
  Transformer analysis of process VAD regions.

The application layer connects those components through a service-oriented local
stack:

```text
frontend/      React + TypeScript analyst workspace
backend/       FastAPI API, SQLAlchemy models, and evidence/scoring services
deploy/        Dockerfiles, nginx config, and docker-compose stack
components/    Wrapped VolMemLyzer3 and VADViT source trees
models/        Optional VADViT checkpoint placement and model notes
```

FastAPI exposes investigation, upload, process, result, scoring, artifact, and
event routes. Celery and Redis coordinate long-running forensic jobs, PostgreSQL
stores investigation state, and the frontend presents the investigation as a
guided workspace rather than a collection of raw plugin outputs.

## Security boundaries

Memory images are treated as untrusted input. Uploads are constrained by file
count, size, extension, and denied executable/container magic bytes. Dump-derived
strings are sanitized before persistence and rendering. The worker container is
designed for isolated parsing work with no internet egress, dropped Linux
capabilities, no privilege escalation, and bounded memory.

Model output is also handled conservatively. If the VADViT checkpoint or runtime
is unavailable, MemTriage returns an explicit unavailable result instead of
fabricating a family label or attention map.

## Screenshots

### Triage Scoring

The triage view surfaces scored objects, risk bands, confidence, and ATT&CK
alignment while keeping the rule evidence expandable and auditable.

![Triage scoring workspace](docs/assets/memtriage-triage-overview.png)

### VADViT Deep-Dive

The deep-dive view shows the selected process grid, attention overlay, model
confidence distribution, and patch-to-region attribution.

![VADViT deep-dive](docs/assets/memtriage-vadvit-deep-dive.png)

## Demo mode

The frontend includes a self-contained demo dataset so the workspace can be
reviewed without a backend, Volatility installation, memory image, or PyTorch
runtime. Demo fixtures live in `frontend/src/demo/` and are isolated from the
production API path.

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. The app starts in demo mode; use the Demo/Live
toggle in the header when testing against the API stack.

## Full stack

Clone with submodules so the wrapped forensic components are present:

```bash
git clone --recurse-submodules https://github.com/YaCnDehfuli/memory_triage_app.git
cd memory_triage_app
```

If the repository was cloned without submodules:

```bash
git submodule update --init --recursive
```

Run the local stack:

```bash
docker compose -f deploy/docker-compose.yml up --build
```

## Quality checks

Backend checks:

```bash
cd backend
python -m pytest
```

Frontend checks:

```bash
cd frontend
npm run typecheck
npm run build
```

## Current status

MemTriage is a work-in-progress security-engineering project. The repository
contains the API, worker workflow, scoring layer, React analyst workspace, demo
mode, Docker stack, and tests. Real VADViT classification requires compatible
weights mounted through the documented model path.

## License

[MIT](LICENSE). Wrapped components retain their own licenses and citations.

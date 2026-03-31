# MemTriage

**Upload a memory image → get one consolidated investigation report.** MemTriage
triages a raw memory capture end-to-end: it inventories the forensic
artifacts/IoCs in the image, flags processes that look malicious, and shows an
analyst *why* — with an explainability heatmap tied back to a named process and
its memory regions.

It does this by combining two independently published components:

- **[VolMemLyzer3](https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool)**
  — Volatility 3-based extraction of 500+ memory artifacts/IoCs.
- **[VADViT](https://github.com/YaCnDehfuli/VADViT)** — an explainable Vision
  Transformer that classifies process memory (VAD) regions as benign or one of
  eight malware families.

Both are vendored as git submodules under [`components/`](components/) and are
**wrapped, not forked** — they remain independently citable.

> **Status:** work in progress. This repository is being built milestone by
> milestone; see the architecture and roadmap in the project plan.

## How it works

MemTriage runs **VolMemLyzer first, then VADViT on demand** — the analyst stays
in the loop:

1. **Ingest** — upload a single atomic memory dump, *or* up to five
   interval-collected snapshots of the same host. Each snapshot streams to disk;
   4GB+ dumps are a first-class case.
2. **Triage (VolMemLyzer)** — extract the IoC/artifact dashboard and build the
   **process/PID inventory**. This runs automatically once and needs no input.
3. **Select** — the analyst picks a process of interest from the inventory.
4. **Deep-dive (VADViT)** — for that PID, MemTriage assembles its VAD regions
   from every snapshot, **consolidates** by choosing the snapshot with the most
   regions (a single dump is trivially chosen), renders the VADViT grid image,
   classifies it, and produces an **attention overlay** mapped back to specific
   VAD regions. The verdict + explanation enrich the VolMemLyzer output.

Steps 3–4 can be repeated for as many processes as the analyst wants; every
result folds into one consolidated, exportable investigation report.

## Non-goals (v1)

MemTriage is a security-engineering demonstration, not a product. It is **not**
an EDR/AV replacement, **not** a live/continuous monitoring tool, and **not** a
general interactive forensics GUI. v1 is a single-shot
*upload-a-memory-image → consolidated-report* tool, and is never benchmarked
against commercial detection products.

## Repository layout

```
backend/       FastAPI API + Celery worker (the MemTriage service)
frontend/      React + TypeScript analyst workspace (Vite + Tailwind)
components/    VolMemLyzer3 and VADViT (git submodules; wrapped, not forked)
deploy/        Dockerfiles + docker-compose stack
```

## Frontend & demo mode

The analyst workspace walks one investigation through **Ingest → Triage overview
→ Process inventory → VADViT deep-dive → Report**. The triage overview drives the
scoring engine live: moving the sensitivity preset (or the advanced controls)
re-scores from cache via `POST /rescore` and highlights what changed.

A built-in **Demo** mode ships realistic canned data, so the whole flow — the
scored IoC table with per-rule evidence, live tuning, the VADViT grid + attention
overlay, and the placeholder verdict — is clickable with no backend, Volatility,
or PyTorch. Toggle **Demo/Live** in the header; demo fixtures are isolated in
`frontend/src/demo/` and removable without touching production code.

```bash
cd frontend && npm install && npm run dev      # http://localhost:5173 (opens in Demo)
# full stack (API + worker + frontend):
docker compose -f deploy/docker-compose.yml up --build
```

## Getting the code

```bash
git clone --recurse-submodules https://github.com/YaCnDehfuli/memory_triage_app.git
# or, after a plain clone:
git submodule update --init --recursive
```

## License

[MIT](LICENSE). The wrapped components retain their own licenses and citations.

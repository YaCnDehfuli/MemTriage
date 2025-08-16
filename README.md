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

## Non-goals (v1)

MemTriage is a security-engineering demonstration, not a product. It is **not**
an EDR/AV replacement, **not** a live/continuous monitoring tool, and **not** a
general interactive forensics GUI. v1 is a single-shot
*upload-a-memory-image → consolidated-report* tool, and is never benchmarked
against commercial detection products.

## Repository layout

```
backend/       FastAPI API + Celery worker (the MemTriage service)
components/    VolMemLyzer3 and VADViT (git submodules; wrapped, not forked)
deploy/        Dockerfiles + docker-compose stack
```

## Getting the code

```bash
git clone --recurse-submodules https://github.com/YaCnDehfuli/memory_triage_app.git
# or, after a plain clone:
git submodule update --init --recursive
```

## License

[MIT](LICENSE). The wrapped components retain their own licenses and citations.

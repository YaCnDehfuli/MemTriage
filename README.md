<div align="center">
# MemTriage

MemTriage is a local workspace for investigating captured Windows memory: a
snapshot of the programs, connections, and data present on a computer at a
particular moment. It turns a large memory image into ranked leads, lets you
inspect the evidence inside a process, and helps you document your assessment
in a report.

Use it to work from “what deserves a closer look?” to specific memory addresses
and an assessment you can check against the evidence.

[![License: MIT](https://img.shields.io/badge/License-MIT-2ea44f.svg)](LICENSE)
[![CI](https://github.com/YaCnDehfuli/MemTriage/actions/workflows/ci.yml/badge.svg)](https://github.com/YaCnDehfuli/MemTriage/actions/workflows/ci.yml)
</div>


## Demos

### Investigate captured memory

A 2-minute walkthrough, from ranked leads to process classification and
inspection of individual memory regions.

https://github.com/user-attachments/assets/eb122be7-c674-4c17-a2e8-ec319ab92d43

[Full-resolution recording](demo.mov)

### Turn evidence into a report

Select findings, annotate evidence, and preview technical or executive reports
for PDF export.

https://github.com/user-attachments/assets/1dc84e09-0c3a-4b10-abdc-d67300101d7e

[Full-resolution recording](report_demo.mp4) · [Project report](https://yacndehfuli.github.io/MemTriage/)
with the worked investigation, current UI, and downloadable report examples.

## Quickstart

Requires Git, [Git LFS](https://git-lfs.com/), and Docker with Compose v2. Start Docker first.

```bash
git lfs install
git clone --recurse-submodules https://github.com/YaCnDehfuli/MemTriage.git
cd MemTriage
./deploy/up.sh
```

The launcher initializes the pinned submodules, checks that the bundled trained
model has been downloaded through Git LFS, and builds and starts the stack.
For an existing checkout, run `git lfs pull` before launching.

Open **[localhost:5173](http://localhost:5173)**, upload a Windows memory image,
and start triage. Choose **Light** for the first pass; **Deep** or **Custom**
expand the checks you run. Leave **Prefer cache** selected to reuse compatible
analysis. Investigation data and cached artifacts persist in Docker volumes.

For deployment settings, see the [Compose configuration](deploy/docker-compose.yml)
and [configuration reference](.env.example).

## From capture to report

1. **Collect and rank.** Upload one image or up to five snapshots of the same
   host. Choose the checks to run, follow their progress, and review scored
   processes, connections, and persistence evidence. Each lead includes the
   rule and evidence behind it; sensitivity changes re-score cached results.
2. **Choose a process.** You decide where to investigate. The trained model
   classifies its memory representation and maps attention back to the regions
   it weighted most.
3. **Inspect the memory.** Follow those addresses into instructions, control
   flow, calls, strings, patterns, byte structure, and hex views. MemTriage's
   backend handles preprocessing and inference; the worker image contains no
   model-training code.
4. **Record your assessment.** Pin evidence, distinguish collection artifacts
   from suspected activity, and add your interpretation and confidence. The
   system structures the report; you select the evidence and own its conclusions.
   Preview technical or executive reports and print to PDF, or export raw
   investigation results as JSON.

Scores are leads, and model probabilities are predictions. Neither establishes
compromise; attention is not a causal explanation. Read them alongside the
capture's quality, extraction coverage, and corroborating evidence.

The forensic worker has **no direct/general internet egress**. Required symbol
retrieval passes through the dedicated, allowlisted `symbolproxy` and uses a
persistent cache; fully offline operation is also supported.

## Go deeper

| Topic | Details |
| --- | --- |
| Scoring | [Rules, weights, thresholds, and validation](https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool/blob/main/docs/ANALYSIS_RULES.md) · [Local catalog measurement](docs/measurements/scoring-catalog.md) |
| Model and memory regions | [Bundled checkpoint, labels, and configuration](docs/MODEL.md) · [VADViT research and implementation](https://github.com/YaCnDehfuli/VADViT) |
| Extraction and caching | [VolMemLyzer evidence-report guide](https://github.com/YaCnDehfuli/VolMemLyzer3-CLI_forensic_tool#evidence-report) · [Interactive analysis reference](https://yacndehfuli.github.io/VolMemLyzer3-CLI_forensic_tool/) |
| Methodology | [Evidence, analysis boundaries, and interpretation](docs/METHODOLOGY.md) |
| Symbols and security | [Proxy, cache, and offline setup](docs/SYMBOLS.md) · [Security scanning](security/SCANNING.md) · [Disclosure](SECURITY.md) |
| Samples and reports | [Sample investigation setup](docs/demo/README.md) · [Report-writing walkthrough](docs/demo/report-writing-demo.md) · [Technical PDF](docs/reports/MemTriage-technical-report.pdf) · [Executive PDF](docs/reports/MemTriage-executive-report.pdf) |

MemTriage is [MIT-licensed](LICENSE). VolMemLyzer retains its GPL-3.0-or-later
license; VADViT retains its MIT license and research citation requirements.
If your work uses the model, cite the
[VADViT paper by Dehfouli and Lashkari (2025)](https://doi.org/10.1016/j.jisa.2025.104200).

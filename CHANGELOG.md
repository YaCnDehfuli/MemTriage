# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-09-10

This release integrates VolMemLyzer's bounded evidence model and makes the
analysis rationale easier to inspect from the MemTriage project page.

### Added

- Full-resolution live MP4 walkthrough with a GitHub-compatible animated GIF
  preview covering ingest, concurrent analysis, surfaced evidence, and the
  PID/VAD deep-dive.
- Direct navigation to VolMemLyzer's interactive rule, cache-validation, and
  520-feature report, with the repository-native rule specification retained
  as the audit source.
- Measured scoring-catalog documentation that distinguishes implementation
  coverage from detection accuracy.

### Changed

- VolMemLyzer is pinned to the 3.1.0 release line with evidence-family
  correlation, a 9-point surfacing threshold, and a hard 30-point score ceiling.
- Cached artifacts are re-scored through the current analysis logic rather than
  reusing stale unbounded triage values.
- README language now consistently presents surfaced objects as analyst review
  leads rather than malware verdicts.
- Default model and security-contact documentation were clarified.

### Fixed

- Fixture seeding and the analyst UI now preserve the bounded score, confidence,
  rule flags, ATT&CK alignment, and cache provenance used by the current
  VolMemLyzer adapter.

## [1.0.0] - 2026-09-05

First public GitHub release of the stable MemTriage workspace.

### Added

- FastAPI investigation API: create, multi-dump upload, triage, process inventory, SSE, export, artifacts, assistant, model-access.
- Celery worker, Redis progress, PostgreSQL investigation state, on-disk artifact layout.
- VolMemLyzer adapter (features, injections, network, inventory) and ATT&CK alignment.
- VAD dump / consolidate / grid render path and attention-ranked region analysis (disasm, CFG, FCG, patterns, strings, structure, hex).
- Deterministic investigation briefing and provider-agnostic assistant (request-scoped keys).
- Docker Compose stack (API, worker without egress, symbol proxy, nginx frontend).
- Security scanning pipeline (Semgrep, Bandit, pip-audit, npm audit, gitleaks, Trivy, CodeQL, ZAP baseline).
- Live cached-investigation GIF and restored region/VADViT stills; research-facility VADViT access wording.
- MIT license.

### Changed

- README product status set to stable tool (not a WIP / demo-mode product).
- Dependabot grouped to monthly updates.
- Backend install no longer reads the repo-root README (setuptools path).
- Prefer-cache / reopen-investigation behaviour for a DONE process analysis.

### Fixed

- Offline Volatility symbols; empty Volatility runs not presented as clean.
- Semgrep DDL suppressions and setuptools / Vite advisory pins so `ci` and `security` on `main` succeed.
- Image paths in the README.

[Unreleased]: https://github.com/YaCnDehfuli/MemTriage/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/YaCnDehfuli/MemTriage/releases/tag/v1.1.0
[1.0.0]: https://github.com/YaCnDehfuli/MemTriage/releases/tag/v1.0.0

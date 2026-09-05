# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/YaCnDehfuli/MemTriage/releases/tag/v1.0.0

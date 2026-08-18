# Security scanning

MemTriage is a security tool, so its own supply chain and code are scanned on
every push and pull request, and weekly on a schedule so a newly disclosed CVE in
a pinned dependency surfaces without anyone touching the repository.

Everything below runs in `.github/workflows/security.yml`. Results that support
SARIF are uploaded to GitHub code scanning under their own category, so findings
are deduplicated across runs and reviewable in one place.

## What runs

| Scanner | Layer | Covers | Fails the build on |
|---|---|---|---|
| **Semgrep** | source | `p/ci`, `p/python`, `p/react`, `p/security-audit` plus `.semgrep.yml` | any ERROR |
| **Bandit** | Python source | common Python security defects | medium severity at medium confidence |
| **pip-audit** | Python deps | known CVEs in `backend/requirements.txt` | any advisory |
| **npm audit** | JS deps | known advisories in `frontend` | high or critical |
| **gitleaks** | git history | committed credentials, across all history | any hit |
| **Trivy (fs)** | tree | dependency CVEs, embedded secrets, IaC misconfiguration | high or critical, fixable |
| **Trivy (image)** | containers | OS and library CVEs in the API and frontend images | high or critical, fixable |
| **CodeQL** | source | dataflow analysis for Python and TypeScript, `security-extended` | any alert |
| **ZAP baseline** | running API | headers, information disclosure, transport issues against a live container | rules not tuned in `.zap/rules.tsv` |
| **Syft** | build | CycloneDX SBOM published as an artifact | — |

## Repo-specific Semgrep rules

The registry packs cover the general cases. `.semgrep.yml` encodes the
invariants this codebase actually depends on:

- **No `shell=True` / `os.system`.** Volatility is invoked with an argument list
  built in code. A shell would put dump-derived text on a command line.
- **No `eval` / `exec` / `pickle.loads` / `yaml.load`.** Everything in the
  pipeline comes from an untrusted memory image and is parsed as data only.
- **No logging or persisting an assistant API key.** Keys are request-scoped;
  a rule catches them reaching a log call or a write.
- **No API key in browser storage.** The key lives in component state for the
  lifetime of the tab.
- **Artifact paths go through `safe_within`.** A `FileResponse` composed directly
  from a request value is flagged.

## Running it locally

Before pushing, the fast checks:

```bash
# Python: lint and tests
cd backend
ruff check .
python -m pytest -q

# Frontend
cd ../frontend
npm run typecheck && npm run build
```

The security scanners, if you have them:

```bash
pip install semgrep bandit pip-audit
semgrep scan --config p/ci --config p/python --config p/react \
             --config p/security-audit --config .semgrep.yml --error
bandit -r backend/memtriage -c backend/pyproject.toml \
       --severity-level medium --confidence-level medium
pip-audit -r backend/requirements.txt --strict
( cd frontend && npm audit --audit-level=high )

# Containers and history
trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL .
gitleaks detect --config .gitleaks.toml --redact
```

The ZAP baseline needs the API running:

```bash
docker build -f deploy/Dockerfile.api -t memtriage-api:local .
docker run --rm -d --name memtriage-api -p 8000:8000 \
  -e MEMTRIAGE_DATABASE_URL=sqlite:////tmp/zap.db \
  -e MEMTRIAGE_DATA_DIR=/tmp/zap-data memtriage-api:local
docker run --rm --network host -v "$PWD/.zap:/zap/wrk:ro" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://127.0.0.1:8000 -r zap.html -c rules.tsv
```

## Triaging a finding

1. **Reproduce it locally** with the command above. A finding that only appears
   in CI is usually a version difference worth pinning rather than ignoring.
2. **Fix it** if it is real. That is almost always cheaper than justifying it.
3. **If it cannot be fixed**, suppress it in the narrowest possible place with a
   written reason:
   - Semgrep: `# nosemgrep: <rule-id>` on the line, with a comment saying why.
   - Bandit: `# nosec B###` on the line, with the same.
   - Trivy: an entry in `.trivyignore`, one CVE per line, and a comment naming
     the reason and when it is revisited.
   - ZAP: a row in `.zap/rules.tsv` with the reason in the description column.
   - gitleaks: an `allowlist` entry in `.gitleaks.toml`, scoped to a path or an
     exact literal — never a broad regex.
4. **Never suppress repo-wide.** A blanket ignore hides the next instance too.

## Deliberate non-findings

Two things get reported regularly and are correct as they stand:

- **No authentication on the API.** MemTriage is a local analyst stack. The
  compose file keeps it on localhost, and `SECURITY.md` states the assumption.
  Exposing it publicly requires putting authentication in front of it.
- **`Content-Security-Policy: default-src 'none'` on API responses.** The API
  serves JSON; the SPA is served separately by nginx with its own headers. A
  scanner reading this as a broken page policy is reading the wrong origin.

## Dependencies

Dependabot opens grouped weekly PRs for pip, npm, Docker base images, and the
actions used by these workflows. Minor and patch updates are grouped; majors come
through individually so they get read.

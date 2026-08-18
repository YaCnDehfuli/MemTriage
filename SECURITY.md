# Security policy

MemTriage parses memory images, which are attacker-influenced input by
definition. Reports about how it handles that input are especially welcome.

## Reporting a vulnerability

Email **yasindeh@yorku.ca** with:

- what the issue is and where in the code it lives,
- how to reproduce it, ideally with a minimal input,
- what an attacker gets from it.

Please do not open a public issue for anything exploitable. Expect an
acknowledgement within a few days.

## Scope

In scope:

- parsing and handling of uploaded images and Volatility output,
- path handling for uploads and derived artifacts,
- the assistant's key handling and egress allowlist,
- container configuration in `deploy/`,
- anything that turns dump-derived content into code execution, a request to
  somewhere it should not go, or a stored payload.

Out of scope:

- findings that require the operator to already have host access,
- missing hardening on a deliberately unauthenticated local demo stack (see
  below), unless it enables something beyond that stack,
- vulnerabilities in Volatility 3, VolMemLyzer or VADViT themselves — report
  those upstream.

## What this project assumes

MemTriage ships as a **local analyst stack**, not an internet-facing service. It
has no authentication, and the compose file binds it to localhost. Exposing it
publicly without putting authentication in front of it is a deployment mistake,
not a finding.

Within that model, the invariants worth breaking:

- The analysis worker has **no outbound network access** (`internal`-only
  network, dropped capabilities, no privilege escalation, bounded memory). Dump
  bytes are read as data and never executed.
- Assistant API keys are **request-scoped**: never persisted, never logged, never
  echoed in a response, and only sent to a base URL on the provider allowlist.
- Every path derived from a request is composed server-side and checked with
  `storage.safe_within`. Raw region bytes are never served for download.
- All dump-derived text is sanitized before it is stored or rendered.

## Scanning

`security/SCANNING.md` documents what runs, what it covers, and how to run it
locally before pushing.

# Volatility symbols

This directory is mounted read-only into the worker at `/symbols`.

Volatility 3 resolves a Windows image's kernel symbols by downloading the
matching PDB from `msdl.microsoft.com` and converting it. The worker container
deliberately has **no outbound network access** — it parses untrusted memory
images — so that download always fails, and without a kernel symbol table *every*
`windows.*` plugin fails. Triage then completes with an empty feature row and an
empty process inventory, which looks identical to a clean image.

Put pre-fetched symbols here. See [docs/SYMBOLS.md](../docs/SYMBOLS.md) for how
to produce them.

Contents are git-ignored; only this file is tracked.

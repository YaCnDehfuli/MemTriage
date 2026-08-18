"""`python -m memtriage.preflight` — report what this environment can actually do.

Exit code is 0 unless a check is in error; missing optional components are
reported as warnings because the pipeline is designed to run without them.
Pass ``--warn-only`` to always exit 0 — useful in CI, where the point is to prove
the report itself works rather than to assert that Redis is running.
"""
from __future__ import annotations

import json
import sys

from .diagnostics import DEGRADED, ERROR, MISSING, OK, run_all

_SYMBOL = {OK: "ok  ", DEGRADED: "warn", MISSING: "warn", ERROR: "FAIL"}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    warn_only = "--warn-only" in argv
    report = run_all()
    failed = 0 if warn_only else int(report["status"] == ERROR)
    if "--json" in argv:
        print(json.dumps(report, indent=2))
        return failed

    print(f"MemTriage preflight — overall: {report['status']}\n")
    for check in report["checks"]:
        print(f"[{_SYMBOL.get(check['status'], '?')}] {check['name']}")
        if check["detail"]:
            print(f"        {check['detail']}")
        if check["status"] != OK and check["remediation"]:
            print(f"        → {check['remediation']}")
    return failed


if __name__ == "__main__":
    raise SystemExit(main())

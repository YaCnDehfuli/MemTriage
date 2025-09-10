"""Per-investigation on-disk layout and path-traversal-safe helpers.

Each investigation gets an isolated tree under
``data_dir/investigations/<investigation_id>/``::

    <id>/
        dumps/               # uploaded snapshots: dump_0, dump_1, ... (never executed)
        volmemlyzer/         # VolMemLyzer triage artifacts (raw plugin JSON, features)
        triage.json          # IoC dashboard + process/PID inventory
        processes/<pid>/     # one per analyzed process
            regions/         # vadinfo --dump region bytes, per snapshot
            grid.png         # rendered VADViT grid image
            attention.png    # attention overlay
            analysis.json    # verdict + attributions
        result.json          # consolidated report (triage + all analyses)
"""
from __future__ import annotations

from pathlib import Path

from .config import get_settings

settings = get_settings()


class InvestigationPaths:
    def __init__(self, investigation_id: str) -> None:
        # investigation_id is a server-generated uuid4, never client-supplied.
        self.root = settings.investigations_dir / investigation_id
        self.dumps = self.root / "dumps"
        self.volmemlyzer = self.root / "volmemlyzer"
        self.processes = self.root / "processes"
        self.triage = self.root / "triage.json"
        self.result = self.root / "result.json"

    def ensure(self) -> "InvestigationPaths":
        for d in (self.root, self.dumps, self.volmemlyzer, self.processes):
            d.mkdir(parents=True, exist_ok=True)
        return self

    def dump_path(self, ordinal: int) -> Path:
        return self.dumps / f"dump_{ordinal}"

    def process_dir(self, pid: int) -> Path:
        return self.processes / str(int(pid))


class ProcessPaths:
    """On-disk artifacts for a single analyzed PID."""

    def __init__(self, investigation_id: str, pid: int) -> None:
        self.root = InvestigationPaths(investigation_id).process_dir(pid)
        self.regions = self.root / "regions"
        self.grid = self.root / "grid.png"
        self.attention = self.root / "attention.png"
        self.result = self.root / "analysis.json"

    def ensure(self) -> "ProcessPaths":
        for d in (self.root, self.regions):
            d.mkdir(parents=True, exist_ok=True)
        return self


def ensure_base_dirs() -> None:
    settings.investigations_dir.mkdir(parents=True, exist_ok=True)


def safe_within(base: Path, candidate: Path) -> bool:
    """True iff ``candidate`` resolves to a location inside ``base``.

    Used to reject path traversal when composing paths from any value that is
    not fully server-controlled.
    """
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False

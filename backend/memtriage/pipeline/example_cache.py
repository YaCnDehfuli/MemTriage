"""Checked-in Volatility artifacts for the public example dump.

The 2580_5.vmem image itself is gitignored (see the repo root ``*.vmem`` rule)
and is not shipped. Captured plugin JSON next to this module's search paths is
small enough to keep in git, and VolMemLyzer will reuse it when the files are
renamed onto MemTriage's on-disk dump name (``dump_<ordinal>_<plugin>.json``).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..storage import InvestigationPaths

EXAMPLE_IMAGE_NAME = "2580_5.vmem"
EXAMPLE_DUMP_SHA256 = "777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4"


def example_outputs_dir() -> Path | None:
    """First directory that holds captured ``2580_5.vmem_<plugin>.json`` files."""
    here = Path(__file__).resolve()
    candidates = (
        Path("/examples/Plugin_Outputs"),
        here.parents[3] / "examples" / "Plugin_Outputs",
        here.parents[2] / "tests" / "fixtures" / "dumps_2580_5",
    )
    prefix = f"{EXAMPLE_IMAGE_NAME}_"
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.glob(f"{prefix}*.json")):
            return candidate
    return None


def list_example_plugins(output_dir: Path | None = None) -> list[str]:
    """Plugin names for which a captured JSON artifact is present and known."""
    directory = output_dir if output_dir is not None else example_outputs_dir()
    if directory is None:
        return []
    from .plugin_runner import plugin_catalog
    known = {row["name"] for row in plugin_catalog()}
    prefix = f"{EXAMPLE_IMAGE_NAME}_"
    names: list[str] = []
    for candidate in directory.glob(f"{prefix}*.json"):
        if not candidate.is_file():
            continue
        plugin = candidate.name[len(prefix) : -5]
        if plugin in known:
            names.append(plugin)
    return sorted(set(names))


def dump_matches_example(*, sha256: str | None, filename: str | None) -> bool:
    """True when this dump is the documented example, by hash or filename."""
    if sha256 and sha256.lower() == EXAMPLE_DUMP_SHA256:
        return True
    return (filename or "") == EXAMPLE_IMAGE_NAME


def seed_example_artifacts(investigation_id: str, dump_ordinal: int = 0) -> list[str]:
    """Copy captured plugin JSON into this investigation's VolMemLyzer cache.

    Returns the plugin names that were copied. Does not run Volatility or triage.
    """
    output_dir = example_outputs_dir()
    if output_dir is None:
        raise FileNotFoundError("Example plugin outputs are not available.")

    plugins = list_example_plugins(output_dir)
    if "pslist" not in plugins:
        raise ValueError("Example plugin outputs are missing pslist.")

    paths = InvestigationPaths(investigation_id).ensure()
    prefix = f"{EXAMPLE_IMAGE_NAME}_"
    copied: list[str] = []
    for plugin in plugins:
        source = output_dir / f"{prefix}{plugin}.json"
        if not source.is_file():
            continue
        shutil.copy2(source, paths.volmemlyzer / f"dump_{dump_ordinal}_{plugin}.json")
        stderr = output_dir / f"{prefix}{plugin}.json.stderr.txt"
        if stderr.is_file():
            shutil.copy2(
                stderr,
                paths.volmemlyzer / f"dump_{dump_ordinal}_{plugin}.json.stderr.txt",
            )
        copied.append(plugin)
    return copied

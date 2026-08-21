"""Seed a real Investigation from pre-captured VolMemLyzer artifacts.

Volatility against a multi-GB image is slow, and this project's worker has no
internet egress by design (see docs/SYMBOLS.md) — reproducing a run from
scratch on a new machine is friction that has nothing to do with proving the
triage pipeline itself works. This module skips that friction using output a
real ``vol``/VolMemLyzer run already produced: point it at a directory holding
the raw image plus VolMemLyzer's own cache-named artifacts
(``<image_name>_<plugin>.<ext>`` [+ ``.stderr.txt``]), and it will:

* create a real ``Investigation`` + ``Dump`` row and on-disk layout
  (:class:`~memtriage.storage.InvestigationPaths`);
* symlink (never copy — the image can be several GB) the raw image into place,
  so ``run_triage``'s real streaming SHA-256 hash step still reads real bytes;
* copy the small cached plugin artifacts into place, **renamed** to match
  VolMemLyzer's cache-hit convention against MemTriage's *on-disk* dump name.
  MemTriage always stores/reads a dump as ``dump_<ordinal>`` (see
  ``InvestigationPaths.dump_path``) — never the originally-uploaded filename —
  and ``Pipeline.check_cache`` keys its lookup off
  ``os.path.basename(image_path)``. So an artifact captured as
  ``2580_5.vmem_pslist.json`` has to land here as ``dump_0_pslist.json``, or
  every plugin silently misses cache and VolMemLyzer re-runs the lot (this bit
  first: the naive same-name copy looked right and produced a working
  triage.json anyway, because offline mode still fails every plugin fast
  without symbols — it just never actually exercised the cache path this
  module exists to prove out);
* run the real ``memtriage.workers.tasks.run_triage`` task body in-process
  (Celery's ``.apply()``, no broker needed) — so the whole
  ``volmemlyzer_adapter.run_triage -> assemble_triage -> scoring engine`` path
  executes for real, against real cached records, with no Volatility
  subprocess spawned for anything that already has a cache hit.

Run as::

    python -m memtriage.pipeline.fixture_seed --dumps-dir ../Dumps
    python -m memtriage.pipeline.fixture_seed --dumps-dir ../Dumps --image-name 2580_5.vmem
"""
from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

from ..db import SessionLocal, init_db
from ..models import Dump, Investigation, InvestigationStatus
from ..storage import InvestigationPaths, ensure_base_dirs


def seed_investigation_from_dumps(
    dumps_dir: str | Path, *, image_name: str = "2580_5.vmem", run: bool = True,
) -> dict:
    """Create (and, by default, triage) a real Investigation from captured artifacts.

    Returns a summary dict: ``investigation_id``, ``artifacts_copied``,
    ``dump_size_bytes``, and (when ``run`` is True) ``task_result``.
    """
    dumps_dir = Path(dumps_dir).expanduser().resolve()
    image_path = dumps_dir / image_name
    if not image_path.is_file():
        raise FileNotFoundError(f"Raw image not found: {image_path}")

    ensure_base_dirs()
    init_db()

    session = SessionLocal()
    try:
        inv = Investigation(
            id=str(uuid.uuid4()),
            status=InvestigationStatus.RECEIVED,
            stage="received",
            message=f"Seeded from captured artifacts in {dumps_dir}",
        )
        session.add(inv)
        session.commit()
        session.refresh(inv)
        investigation_id = inv.id

        paths = InvestigationPaths(investigation_id).ensure()

        dump_target = paths.dump_path(0)
        dump_target.symlink_to(image_path)
        size_bytes = image_path.stat().st_size

        dump = Dump(
            id=str(uuid.uuid4()), investigation_id=investigation_id, ordinal=0,
            original_filename=image_name, size_bytes=size_bytes,
        )
        inv.dump_count = 1
        inv.total_bytes = size_bytes
        session.add_all([dump, inv])
        session.commit()

        # Every file VolMemLyzer would itself have written for this image, but
        # renamed from the "<image_name>_..." prefix it was captured under to
        # the "<dump_target.name>_..." prefix (dump_0) Pipeline.check_cache
        # will actually look for — see the module docstring.
        prefix = f"{image_name}_"
        copied = 0
        for candidate in sorted(dumps_dir.glob(f"{prefix}*")):
            if candidate.is_file():
                renamed = f"{dump_target.name}_{candidate.name[len(prefix):]}"
                shutil.copy2(candidate, paths.volmemlyzer / renamed)
                copied += 1
    finally:
        session.close()

    summary = {
        "investigation_id": investigation_id,
        "artifacts_copied": copied,
        "dump_size_bytes": size_bytes,
    }

    if run:
        # Celery's .apply() runs the task body synchronously, in-process, no
        # broker required — and still honours `bind=True`. The task itself
        # never raises (every branch is try/except'd to a FAILED state), so
        # .get() just returns its "triaged"/"failed"/"missing" string.
        from ..workers.tasks import run_triage

        summary["task_result"] = run_triage.apply(args=[investigation_id]).get()

        paths = InvestigationPaths(investigation_id)
        if paths.triage.exists():
            triage = json.loads(paths.triage.read_text())
            dashboard = triage.get("dashboard", {})
            summary["extraction"] = dashboard.get("extraction", {})
            summary["risk_summary"] = dashboard.get("risk_summary", {})
            summary["suspicious_processes"] = len(dashboard.get("suspicious_processes", []))
            summary["attack_techniques"] = len(dashboard.get("attack_techniques", []))
            summary["persistence"] = len(dashboard.get("persistence", []))
            summary["process_count"] = len(triage.get("processes", []))

    return summary


def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Seed a real Investigation from pre-captured VolMemLyzer artifacts"
    )
    parser.add_argument("--dumps-dir", required=True, help="Directory holding the raw image "
                        "plus its <image>_<plugin>.<ext> cached artifacts")
    parser.add_argument("--image-name", default="2580_5.vmem")
    parser.add_argument("--no-run", action="store_true",
                        help="Only seed the files/DB rows; don't run triage")
    args = parser.parse_args(argv)

    summary = seed_investigation_from_dumps(
        args.dumps_dir, image_name=args.image_name, run=not args.no_run
    )
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())

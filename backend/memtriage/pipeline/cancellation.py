"""Stopping a running Volatility job from outside the worker.

VolMemLyzer launches each plugin as a ``vol`` subprocess of the Celery pool
process, and keeps no handle MemTriage can reach. Neither of the usual tools
stops that cleanly:

* Celery's ``revoke(terminate=True)`` signals the pool process only. The
  ``vol`` processes it spawned survive as orphans, keep scanning, and keep
  writing cache files.
* The API cannot signal anything: it runs in a different container.

So a stop is a request recorded in the database, honoured from inside the task.
:class:`CancelWatch` runs a thread next to the job that polls for that request
and, once it is set, terminates every descendant process of the task — SIGTERM,
then SIGKILL after a grace period — and keeps sweeping until the job returns,
because VolMemLyzer starts the next queued plugin as soon as one dies. Plugins
that finished before the stop keep their cached output.

The same thread records that the worker is alive, which is how the API tells a
job that is still running (and will honour the stop) from one whose worker died
and never will.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

POLL_SECONDS = 1.0
GRACE_SECONDS = 3.0
LIVENESS_SECONDS = 10.0
# The API treats a job whose watcher has been silent this long as having no
# worker behind it. Several liveness intervals, so one slow database write
# cannot make a live job look dead.
STALE_AFTER_SECONDS = 6 * LIVENESS_SECONDS


class JobStopped(Exception):
    """Raised by a task once it has honoured a stop request."""


def _process_table() -> dict[int, int]:
    """``{pid: ppid}`` for every process visible to this one."""
    proc = Path("/proc")
    if proc.is_dir():
        table: dict[int, int] = {}
        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                stat = (entry / "stat").read_text()
            except OSError:
                continue  # exited while we were reading
            # The command name is parenthesised and may contain spaces or ")",
            # so split on the last ")" before reading the fields after it.
            fields = stat.rsplit(")", 1)[-1].split()
            if len(fields) >= 2:
                table[int(entry.name)] = int(fields[1])
        return table
    # No /proc (macOS development): ps is always present there.
    try:
        lister = subprocess.Popen(
            ["ps", "-Ao", "pid=,ppid="],  # noqa: S607
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        out, _ = lister.communicate(timeout=10)
    except (OSError, subprocess.SubprocessError):
        return {}
    table = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            table[int(parts[0])] = int(parts[1])
    # The lister is itself a child of whoever asked; it is not a job process.
    table.pop(lister.pid, None)
    return table


def descendants(root: int) -> list[int]:
    """Every process below ``root``, deepest first."""
    children: dict[int, list[int]] = defaultdict(list)
    for pid, ppid in _process_table().items():
        children[ppid].append(pid)
    ordered: list[int] = []
    frontier = [(root, 0)]
    depth_of: dict[int, int] = {}
    while frontier:
        pid, depth = frontier.pop()
        for child in children.get(pid, ()):
            if child in depth_of or child == root:
                continue
            depth_of[child] = depth + 1
            ordered.append(child)
            frontier.append((child, depth + 1))
    return sorted(ordered, key=lambda p: depth_of[p], reverse=True)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie still answers signal 0; it is not running anything.
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[-1].split()[0]
        return state != "Z"
    except (OSError, IndexError):
        return True


class CancelWatch:
    """Honour a stop request for the job running in this process.

    ``is_cancelled`` is polled from a background thread and must be cheap and
    thread-safe (open its own database session). ``on_alive`` is called every
    :data:`LIVENESS_SECONDS` so the API can see a worker is still behind the job.
    """

    def __init__(
        self,
        is_cancelled: Callable[[], bool],
        *,
        on_alive: Callable[[], None] | None = None,
        root_pid: int | None = None,
        poll_seconds: float = POLL_SECONDS,
        grace_seconds: float = GRACE_SECONDS,
    ) -> None:
        self._is_cancelled = is_cancelled
        self._on_alive = on_alive
        self._root = root_pid if root_pid is not None else os.getpid()
        self._poll = poll_seconds
        self._grace = grace_seconds
        self._stop = threading.Event()
        self._cancelled = threading.Event()
        self._termed: dict[int, float] = {}
        self._thread: threading.Thread | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def raise_if_cancelled(self) -> None:
        """For phase boundaries where there is no subprocess to kill (hashing, copying)."""
        if self.cancelled:
            raise JobStopped()

    def __enter__(self) -> CancelWatch:
        self._thread = threading.Thread(target=self._run, name="job-cancel-watch", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._poll + 1.0)
        if self.cancelled:
            # The job has returned; nothing it started may outlive it.
            self._sweep(final=True)

    def _run(self) -> None:
        last_alive = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            if self._on_alive and now - last_alive >= LIVENESS_SECONDS:
                last_alive = now
                try:
                    self._on_alive()
                except Exception:
                    logger.exception("job liveness update failed")
            if not self.cancelled:
                try:
                    if self._is_cancelled():
                        logger.warning("stop requested; terminating Volatility processes")
                        self._cancelled.set()
                except Exception:
                    logger.exception("stop-request poll failed")
            if self.cancelled:
                self._sweep()
            self._stop.wait(self._poll)

    def _sweep(self, *, final: bool = False) -> None:
        now = time.monotonic()
        for pid in descendants(self._root):
            first = self._termed.get(pid)
            try:
                if first is None:
                    os.kill(pid, signal.SIGTERM)
                    self._termed[pid] = now
                elif final or now - first >= self._grace:
                    if _alive(pid):
                        os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                continue
            except PermissionError:
                logger.warning("not permitted to stop process %s", pid)
        if final:
            deadline = time.monotonic() + self._grace
            while time.monotonic() < deadline:
                remaining = [p for p in descendants(self._root) if _alive(p)]
                if not remaining:
                    return
                time.sleep(0.1)
            for pid in descendants(self._root):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    continue

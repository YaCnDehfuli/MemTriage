"""A stop request must kill the Volatility processes a job spawned — all of them.

Uses real subprocesses (a child that itself spawns a grandchild), because the
failure being guarded against is precisely a process tree that outlives the job.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time

from memtriage.pipeline.cancellation import CancelWatch, JobStopped, descendants

# A stand-in for `vol`: ignores nothing, sleeps long, and starts its own child.
_TREE = (
    "import subprocess, sys, time;"
    "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)']);"
    "time.sleep(300)"
)
# A stand-in for a process that shrugs off SIGTERM, so SIGKILL must follow.
_STUBBORN = (
    "import signal, time;"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
    "time.sleep(300)"
)


def _gone(pid: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                return True
        except ChildProcessError:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return True
        time.sleep(0.05)
    return False


def test_descendants_finds_grandchildren():
    child = subprocess.Popen([sys.executable, "-c", _TREE])
    try:
        deadline = time.monotonic() + 10
        tree: list[int] = []
        while time.monotonic() < deadline:
            tree = descendants(os.getpid())
            if child.pid in tree and len(tree) >= 2:
                break
            time.sleep(0.05)
        assert child.pid in tree
        assert len(tree) >= 2, "the grandchild must be found, not only the direct child"
        assert tree.index(child.pid) > 0, "deepest first: the grandchild precedes its parent"
    finally:
        for pid in descendants(os.getpid()):
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass
        child.wait(timeout=10)


def test_a_stop_request_kills_the_whole_tree_and_is_reported():
    requested = threading.Event()
    child = subprocess.Popen([sys.executable, "-c", _TREE])
    time.sleep(0.5)
    tree = descendants(os.getpid())
    assert len(tree) >= 2

    with CancelWatch(requested.is_set, poll_seconds=0.05, grace_seconds=0.5) as watch:
        assert not watch.cancelled
        requested.set()
        assert _gone(child.pid), "the direct child must die"
        assert watch.cancelled

    for pid in tree:
        assert _gone(pid), f"process {pid} outlived the stop"
    try:
        watch.raise_if_cancelled()
    except JobStopped:
        pass
    else:
        raise AssertionError("a cancelled watch must raise at phase boundaries")


def test_sigterm_is_followed_by_sigkill():
    requested = threading.Event()
    stubborn = subprocess.Popen([sys.executable, "-c", _STUBBORN])
    time.sleep(0.5)
    with CancelWatch(requested.is_set, poll_seconds=0.05, grace_seconds=0.3):
        requested.set()
        assert _gone(stubborn.pid, timeout=10), "a process ignoring SIGTERM must still be killed"


def test_processes_started_after_the_stop_are_swept_too():
    """VolMemLyzer starts the next queued plugin as soon as one dies."""
    requested = threading.Event()
    with CancelWatch(requested.is_set, poll_seconds=0.05, grace_seconds=0.3):
        requested.set()
        time.sleep(0.2)
        late = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        assert _gone(late.pid), "a plugin launched after the stop must not survive"


def test_no_request_means_nothing_is_touched_and_liveness_is_reported():
    beats: list[float] = []
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(3)"])
    try:
        from memtriage.pipeline import cancellation

        original = cancellation.LIVENESS_SECONDS
        cancellation.LIVENESS_SECONDS = 0.1
        try:
            with CancelWatch(lambda: False, on_alive=lambda: beats.append(time.monotonic()),
                             poll_seconds=0.05) as watch:
                time.sleep(0.5)
                assert not watch.cancelled
                assert child.poll() is None, "an unrequested watch must never kill"
        finally:
            cancellation.LIVENESS_SECONDS = original
        assert len(beats) >= 2
    finally:
        child.kill()
        child.wait(timeout=10)


def test_a_failing_poll_does_not_crash_the_job():
    def broken() -> bool:
        raise RuntimeError("database unavailable")

    with CancelWatch(broken, poll_seconds=0.05) as watch:
        time.sleep(0.2)
        assert not watch.cancelled

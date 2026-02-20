"""Test configuration.

Environment is pinned to a throwaway SQLite DB and temp data dir BEFORE any
memtriage module is imported, so the app's cached settings pick these up and the
suite needs no Postgres/Redis to run.
"""
import os
import sys
import tempfile

# The grid-render fidelity test imports VADViT's module from the submodule;
# don't let Python drop a .pyc there and dirty the pinned submodule tree.
sys.dont_write_bytecode = True

_TMP = tempfile.mkdtemp(prefix="memtriage-test-")
os.environ.setdefault("MEMTRIAGE_DATA_DIR", _TMP)
os.environ.setdefault("MEMTRIAGE_DATABASE_URL", f"sqlite:///{_TMP}/test.db")
os.environ.setdefault("MEMTRIAGE_REDIS_URL", "redis://localhost:6379/0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch):
    # Never open a Redis connection in tests: stub the pub/sub publish.
    from memtriage.pipeline import progress

    monkeypatch.setattr(progress, "publish_event", lambda *a, **k: None)


@pytest.fixture()
def client(monkeypatch):
    # Never touch a real broker in tests: stub the enqueue call.
    from memtriage.workers import celery_app as ca

    monkeypatch.setattr(ca.celery_app, "send_task", lambda *a, **k: None)

    from memtriage.main import app

    with TestClient(app) as test_client:
        yield test_client

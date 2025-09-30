"""Celery application.

4GB+ dumps make analysis a long-running, resource-heavy job that must never
block an HTTP request thread. Celery runs it out-of-band on a worker; Redis is
both broker and result backend. Time limits are DoS controls: a malformed or
oversized image cannot pin a worker forever.
"""
from __future__ import annotations

from celery import Celery

from ..config import get_settings

settings = get_settings()

celery_app = Celery(
    "memtriage",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["memtriage.workers.tasks"],
)

celery_app.conf.update(
    task_acks_late=True,               # re-deliver if a worker dies mid-job
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,      # one heavy job at a time per worker slot
    task_track_started=True,
    # Hard/soft ceilings so pathological input cannot run unbounded.
    task_soft_time_limit=60 * 60,      # 60 min soft (raises in-task)
    task_time_limit=75 * 60,           # 75 min hard (kills the worker process)
    result_expires=60 * 60 * 24,
    broker_transport_options={"visibility_timeout": 90 * 60},
)

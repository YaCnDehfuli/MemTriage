"""Celery application.

4GB+ dumps make analysis a long-running, resource-heavy job that must never
block an HTTP request thread. Celery runs it out-of-band on a worker; Redis is
both broker and result backend. Each Volatility subprocess has a finite timeout;
the containing multi-wave batch must not be killed after only one plugin window.
"""
from __future__ import annotations

import logging

from celery import Celery
from celery.signals import worker_process_init

from ..config import get_settings
from ..pipeline.plugin_runner import plugin_catalog

logger = logging.getLogger(__name__)

settings = get_settings()
_MAX_CATALOG_PLUGINS = len(plugin_catalog())
_BATCH_HEADROOM_S = 6 * 60 * 60

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
    result_expires=60 * 60 * 24,
    broker_transport_options={
        "visibility_timeout": max(
            settings.broker_visibility_timeout_s,
            settings.vol_timeout_s * _MAX_CATALOG_PLUGINS + _BATCH_HEADROOM_S,
        ),
    },
)


@worker_process_init.connect
def _prepare_worker(**_kwargs) -> None:
    """The worker may boot before (or without) the API, so it owns its schema too."""
    try:
        from ..db import init_db
        from ..storage import ensure_base_dirs

        ensure_base_dirs()
        init_db()
    except Exception:
        logger.exception("worker startup: could not prepare storage/schema")

"""Database engine and session helpers (synchronous SQLAlchemy 2.0).

The API touches the DB from ``def`` (threadpool) endpoints and the Celery
worker uses its own sessions; a single sync engine keeps both simple. The DB
stores only job/result *metadata* — the dumps and artifacts live on disk.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

logger = logging.getLogger(__name__)

_settings = get_settings()

# SQLite (used for lightweight tests) needs check_same_thread disabled because
# FastAPI's sync endpoints run across a threadpool; Postgres ignores this.
_connect_args: dict = {}
if _settings.database_url.startswith("sqlite"):
    _connect_args = {"check_same_thread": False}

engine = create_engine(
    _settings.database_url,
    pool_pre_ping=True,
    future=True,
    connect_args=_connect_args,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped session."""
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db() -> None:
    """Create tables if they do not yet exist (demo-grade; real deploys migrate)."""
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)
    ensure_schema()


# Columns whose declared type widened after the first release. ``create_all``
# never alters an existing table, so a volume created before the change keeps a
# 32-bit size column and overflows on any dump above 2 GiB.
_WIDENED_TO_BIGINT = (
    ("investigations", "total_bytes"),
    ("dumps", "size_bytes"),
)


def ensure_schema() -> None:
    """Apply the few idempotent widenings ``create_all`` cannot do itself."""
    if engine.dialect.name != "postgresql":
        return
    from sqlalchemy import text

    with engine.begin() as conn:
        for table, column in _WIDENED_TO_BIGINT:
            try:
                conn.execute(text(
                    f"ALTER TABLE {table} ALTER COLUMN {column} TYPE BIGINT"
                ))
            except SQLAlchemyError:
                logger.warning("could not widen %s.%s to BIGINT", table, column)

"""Database engine and session helpers (synchronous SQLAlchemy 2.0).

The API touches the DB from ``def`` (threadpool) endpoints and the Celery
worker uses its own sessions; a single sync engine keeps both simple. The DB
stores only job/result *metadata* — the dumps and artifacts live on disk.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings

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
    finally:
        session.close()


def init_db() -> None:
    """Create tables if they do not yet exist (demo-grade; real deploys migrate)."""
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(bind=engine)

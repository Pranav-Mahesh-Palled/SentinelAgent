"""Database session management and FastAPI dependencies.

Provides session lifecycle management, ensuring connections from the
underlying SQLAlchemy engine pool are cleanly used and returned.
"""

from collections.abc import Generator
import logging
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session, sessionmaker

from app.db.connection import get_engine

logger = logging.getLogger(__name__)

_session_factory: Optional[sessionmaker[Session]] = None


def get_session_factory() -> sessionmaker[Session]:
    """Get or lazily initialize the sessionmaker for the active engine."""
    global _session_factory
    engine = get_engine()
    if engine is None:
        logger.error("Database session requested but engine is uninitialized or unconfigured.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable",
        )

    # Reinitialize factory if engine was reset or disposed
    if _session_factory is None or _session_factory.kw.get("bind") is not engine:
        _session_factory = sessionmaker(
            bind=engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False,
        )

    return _session_factory


def reset_session_factory() -> None:
    """Clear cached session factory, e.g. when engine is disposed."""
    global _session_factory
    _session_factory = None


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency yielding a managed SQLAlchemy Session.

    Reuses SentinelAgent's engine and verified connection pool.
    Guarantees session closure on request completion.
    """
    factory = get_session_factory()
    session = factory()
    try:
        yield session
    finally:
        session.close()


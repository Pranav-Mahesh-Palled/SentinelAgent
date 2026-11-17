"""PostgreSQL database connectivity and engine management.

Uses SQLAlchemy 2.x with the Psycopg 3 driver (postgresql+psycopg://).
Engine is lazily initialized on demand and verifies connections with pool_pre_ping.
Credentials and connection strings are strictly safeguarded against logging.
"""

import logging
from typing import Optional, Tuple
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from app.core.config import get_settings

logger = logging.getLogger(__name__)

_engine: Optional[Engine] = None


def get_engine() -> Optional[Engine]:
    """Get or lazily initialize the SQLAlchemy engine.

    Returns None if DATABASE_URL is not configured.
    Never connects during module import.
    """
    global _engine
    settings = get_settings()

    if not settings.DATABASE_URL:
        return None

    raw_url = settings.DATABASE_URL.get_secret_value().strip()
    if not raw_url:
        return None

    if _engine is None:
        try:
            _engine = create_engine(
                raw_url,
                pool_pre_ping=True,
            )
        except Exception as exc:
            logger.error(
                "Database engine initialization failed: %s",
                type(exc).__name__,
            )
            return None

    return _engine


def dispose_engine() -> None:
    """Safely dispose of the database engine and connection pool."""
    global _engine
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception as exc:
            logger.warning(
                "Database engine disposal encountered an issue: %s",
                type(exc).__name__,
            )
        finally:
            _engine = None
            try:
                from app.db.session import reset_session_factory
                reset_session_factory()
            except ImportError:
                pass


def check_db_connectivity() -> Tuple[bool, str]:
    """Execute 'SELECT 1' to verify database connectivity.

    Returns:
        (True, "connected") on success.
        (False, error_reason) on failure or when unconfigured.

    Strictly avoids exposing connection strings or passwords in logs and responses.
    """
    settings = get_settings()
    if not settings.DATABASE_URL or not settings.DATABASE_URL.get_secret_value().strip():
        logger.warning("Database connectivity check: DATABASE_URL is unconfigured.")
        return False, "Database connection URL is not configured."

    engine = get_engine()
    if engine is None:
        logger.warning("Database connectivity check: Engine could not be created.")
        return False, "Database engine could not be initialized."

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "connected"
    except SQLAlchemyError as err:
        logger.error(
            "Database connectivity check failed (SQLAlchemyError): %s",
            type(err).__name__,
        )
        return False, "Database service is unavailable."
    except Exception as exc:
        logger.error(
            "Database connectivity check encountered unexpected error: %s",
            type(exc).__name__,
        )
        return False, "Database service is unavailable."


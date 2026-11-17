"""Tests for PostgreSQL connection handling and engine management."""

from unittest.mock import MagicMock, patch
import pytest
from pydantic import SecretStr
from sqlalchemy.exc import OperationalError
from app.core.config import Settings
from app.db import connection


@pytest.fixture(autouse=True)
def cleanup_engine():
    """Ensure engine is disposed before and after each test."""
    connection.dispose_engine()
    yield
    connection.dispose_engine()


def test_get_engine_returns_none_when_unconfigured():
    """Engine should be None when DATABASE_URL is not set."""
    mock_settings = Settings(DATABASE_URL=None, _env_file=None)
    with patch("app.db.connection.get_settings", return_value=mock_settings):
        engine = connection.get_engine()
        assert engine is None


def test_get_engine_returns_none_when_empty_string():
    """Engine should be None when DATABASE_URL is empty."""
    mock_settings = Settings(DATABASE_URL=SecretStr("   "), _env_file=None)
    with patch("app.db.connection.get_settings", return_value=mock_settings):
        engine = connection.get_engine()
        assert engine is None


def test_get_engine_initializes_with_pool_pre_ping():
    """Engine initialization must include pool_pre_ping=True."""
    mock_settings = Settings(
        DATABASE_URL=SecretStr("postgresql+psycopg://user:pass@localhost:5432/sentinelagent"),
        _env_file=None,
    )
    with patch("app.db.connection.get_settings", return_value=mock_settings), \
         patch("app.db.connection.create_engine") as mock_create_engine:
        mock_create_engine.return_value = MagicMock()
        engine = connection.get_engine()
        assert engine is not None
        mock_create_engine.assert_called_once_with(
            "postgresql+psycopg://user:pass@localhost:5432/sentinelagent",
            pool_pre_ping=True,
        )


def test_check_db_connectivity_unconfigured():
    """Connectivity check should return (False, reason) when unconfigured."""
    mock_settings = Settings(DATABASE_URL=None, _env_file=None)
    with patch("app.db.connection.get_settings", return_value=mock_settings):
        is_connected, reason = connection.check_db_connectivity()
        assert is_connected is False
        assert "not configured" in reason.lower()


def test_check_db_connectivity_success():
    """Connectivity check executes SELECT 1 and returns (True, 'connected')."""
    mock_settings = Settings(
        DATABASE_URL=SecretStr("postgresql+psycopg://user:pass@localhost:5432/sentinelagent"),
        _env_file=None,
    )
    mock_engine = MagicMock()
    mock_conn = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn

    with patch("app.db.connection.get_settings", return_value=mock_settings), \
         patch("app.db.connection.get_engine", return_value=mock_engine):
        is_connected, reason = connection.check_db_connectivity()
        assert is_connected is True
        assert reason == "connected"
        mock_conn.execute.assert_called_once()
        # Verify SELECT 1 is in the executed statement
        executed_sql = str(mock_conn.execute.call_args[0][0])
        assert "SELECT 1" in executed_sql


def test_check_db_connectivity_operational_error():
    """Connectivity check handles connection failures without leaking details."""
    mock_settings = Settings(
        DATABASE_URL=SecretStr("postgresql+psycopg://user:secret123@localhost:5432/sentinelagent"),
        _env_file=None,
    )
    mock_engine = MagicMock()
    mock_engine.connect.side_effect = OperationalError("connection refused to password secret123", None, None)

    with patch("app.db.connection.get_settings", return_value=mock_settings), \
         patch("app.db.connection.get_engine", return_value=mock_engine):
        is_connected, reason = connection.check_db_connectivity()
        assert is_connected is False
        assert reason == "Database service is unavailable."
        # Ensure credentials are not in reason
        assert "secret123" not in reason


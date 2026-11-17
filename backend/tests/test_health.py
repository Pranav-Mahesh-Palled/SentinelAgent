"""Automated tests for SentinelAgent health and readiness endpoints."""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.exc import OperationalError
from app.core.config import Settings
from app.db import connection
from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Liveness Endpoint Tests (/api/health/live)
# ---------------------------------------------------------------------------

def test_liveness_endpoint_status_code():
    """1. Liveness endpoint returns HTTP 200."""
    response = client.get("/api/health/live")
    assert response.status_code == 200


def test_liveness_endpoint_expected_json():
    """2. Liveness endpoint returns expected JSON payload."""
    response = client.get("/api/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


# ---------------------------------------------------------------------------
# Readiness Endpoint Tests (/api/health/ready)
# ---------------------------------------------------------------------------

def test_readiness_endpoint_success_when_database_connected():
    """3. Readiness endpoint returns HTTP 200 when database connectivity check succeeds."""
    with patch("app.api.health.check_db_connectivity", return_value=(True, "connected")):
        response = client.get("/api/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["mitre_catalogue"] in ("loaded", "unavailable")
        assert data["mitre_required"] is False
        assert data["hindsight"] == "disabled"
        assert data["hindsight_required"] is False


def test_readiness_endpoint_fails_when_configuration_missing():
    """4. Readiness endpoint returns HTTP 503 when database configuration is missing."""
    mock_settings = Settings(DATABASE_URL=None, _env_file=None)
    with patch("app.db.connection.get_settings", return_value=mock_settings):
        # We test the full route through check_db_connectivity
        response = client.get("/api/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unavailable"
        assert data["database"] == "disconnected"
        assert "detail" in data
        assert data["detail"] == "Database service is unavailable"
        assert data["mitre_catalogue"] in ("loaded", "unavailable")
        assert data["mitre_required"] is False
        assert data["hindsight"] == "disabled"
        assert data["hindsight_required"] is False


def test_readiness_endpoint_fails_when_connection_fails():
    """5. Readiness endpoint returns HTTP 503 when PostgreSQL connection fails."""
    with patch("app.api.health.check_db_connectivity", return_value=(False, "Database service is unavailable.")):
        response = client.get("/api/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unavailable"
        assert data["database"] == "disconnected"
        assert data["detail"] == "Database service is unavailable"
        assert data["mitre_catalogue"] in ("loaded", "unavailable")
        assert data["mitre_required"] is False
        assert data["hindsight"] == "disabled"
        assert data["hindsight_required"] is False


def test_readiness_error_response_does_not_expose_credentials():
    """6. Error responses must never expose database credentials or connection strings."""
    sensitive_password = "SuperSecretDbPassword_!987#"
    sensitive_url = f"postgresql+psycopg://admin:{sensitive_password}@prod-db.internal:5432/sentinelagent"

    mock_settings = Settings(DATABASE_URL=SecretStr(sensitive_url), _env_file=None)

    # Simulate an OperationalError that internally holds the connection string
    error_with_creds = OperationalError(
        f"FATAL: password authentication failed for user 'admin' at {sensitive_url}",
        None,
        None,
    )

    with patch("app.db.connection.get_settings", return_value=mock_settings), \
         patch("app.db.connection.get_engine") as mock_get_engine:
        mock_engine = patch("sqlalchemy.Engine").start()
        mock_engine.connect.side_effect = error_with_creds
        mock_get_engine.return_value = mock_engine

        response = client.get("/api/health/ready")

        assert response.status_code == 503
        response_text = response.text
        # Strictly verify sensitive password and credentials are not in response text
        assert sensitive_password not in response_text
        assert "prod-db.internal" not in response_text
        assert "postgresql+psycopg" not in response_text
        data = response.json()
        assert data["status"] == "unavailable"
        assert data["database"] == "disconnected"
        assert data["detail"] == "Database service is unavailable"
        assert data["mitre_catalogue"] in ("loaded", "unavailable")
        assert data["mitre_required"] is False
        assert data["hindsight"] == "disabled"
        assert data["hindsight_required"] is False


def test_real_postgresql_connectivity_if_available():
    """Optional check against real PostgreSQL if valid environment is configured."""
    from app.core.config import get_settings
    settings = get_settings()

    if not settings.DATABASE_URL or not settings.DATABASE_URL.get_secret_value().strip():
        pytest.skip("No real PostgreSQL instance configured in environment; skipping live DB test.")

    # If configured, test actual live connectivity
    is_connected, _ = connection.check_db_connectivity()
    if is_connected:
        response = client.get("/api/health/ready")
        assert response.status_code == 200
        assert response.json()["status"] == "ready"
    else:
        pytest.skip("PostgreSQL configured but currently unreachable; skipping live DB test.")


# ---------------------------------------------------------------------------
# Hindsight Readiness Integration Tests (Task 9B)
# ---------------------------------------------------------------------------

from unittest.mock import AsyncMock
from app.services.hindsight_client import HindsightClientService


def test_readiness_endpoint_hindsight_available_when_enabled():
    """Readiness endpoint returns HTTP 200 and hindsight='available' when client probe succeeds."""
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=False,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key"),
        _env_file=None,
    )
    mock_client_service = AsyncMock(spec=HindsightClientService)
    mock_client_service.check_health.return_value = (True, "available")

    with patch("app.api.health.get_settings", return_value=mock_settings), \
         patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch.object(app.state, "hindsight_client", mock_client_service):

        response = client.get("/api/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["hindsight"] == "available"
        assert data["hindsight_required"] is False


def test_readiness_endpoint_hindsight_unavailable_optional_does_not_fail():
    """When optional (HINDSIGHT_REQUIRED=False), unavailable Hindsight does not fail overall readiness."""
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=False,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key"),
        _env_file=None,
    )
    mock_client_service = AsyncMock(spec=HindsightClientService)
    mock_client_service.check_health.return_value = (False, "unreachable")

    with patch("app.api.health.get_settings", return_value=mock_settings), \
         patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch.object(app.state, "hindsight_client", mock_client_service):

        response = client.get("/api/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert data["hindsight"] == "unavailable"
        assert data["hindsight_required"] is False


def test_readiness_endpoint_hindsight_unavailable_required_returns_503():
    """When required (HINDSIGHT_REQUIRED=True), unavailable Hindsight causes HTTP 503."""
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key"),
        _env_file=None,
    )
    mock_client_service = AsyncMock(spec=HindsightClientService)
    mock_client_service.check_health.return_value = (False, "unreachable")

    with patch("app.api.health.get_settings", return_value=mock_settings), \
         patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch.object(app.state, "hindsight_client", mock_client_service):

        response = client.get("/api/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "unavailable"
        assert data["database"] == "connected"
        assert data["hindsight"] == "unavailable"
        assert data["hindsight_required"] is True
        assert "Required Hindsight service is unavailable" in data["detail"]


def test_readiness_endpoint_hindsight_recovery_restores_readiness():
    """When an unavailable required Hindsight service becomes available, readiness recovers."""
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key"),
        _env_file=None,
    )
    mock_client_service = AsyncMock(spec=HindsightClientService)

    with patch("app.api.health.get_settings", return_value=mock_settings), \
         patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch.object(app.state, "hindsight_client", mock_client_service):

        # First probe: unavailable -> 503
        mock_client_service.check_health.return_value = (False, "unreachable")
        r1 = client.get("/api/health/ready")
        assert r1.status_code == 503

        # Second probe: service recovers -> 200
        mock_client_service.check_health.return_value = (True, "available")
        r2 = client.get("/api/health/ready")
        assert r2.status_code == 200
        assert r2.json()["status"] == "ready"
        assert r2.json()["hindsight"] == "available"


def test_liveness_remains_independent_when_hindsight_required_and_unavailable():
    """Liveness (/live) must return HTTP 200 regardless of Hindsight status."""
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key"),
        _env_file=None,
    )
    mock_client_service = AsyncMock(spec=HindsightClientService)
    mock_client_service.check_health.return_value = (False, "unreachable")

    with patch("app.api.health.get_settings", return_value=mock_settings), \
         patch.object(app.state, "hindsight_client", mock_client_service):

        live_response = client.get("/api/health/live")
        assert live_response.status_code == 200
        assert live_response.json() == {"status": "alive"}



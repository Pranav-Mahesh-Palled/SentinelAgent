"""Automated tests for MITRE ATT&CK application lifecycle, configuration, and readiness.

Verifies Task 8E.2 architecture:
- Application configuration (MITRE_REQUIRED, MITRE_CATALOGUE_PATH).
- FastAPI lifespan initialization and exclusive app.state.mitre_catalogue storage.
- Graceful degradation under optional mode (MITRE_REQUIRED=False).
- Hard failure under mandatory mode (MITRE_REQUIRED=True).
- Partial startup cleanup (Gemini provider and sweeper teardown on startup abort).
- Application instance state isolation.
- Health endpoints (/health/live independent, /health/ready reporting catalogue and DB state).
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.api.health import router as health_router
from app.core.config import Settings
from app.main import lifespan
from app.services.gemini_client import GeminiProvider
from app.services.mitre_catalogue_service import (
    MitreCatalogueChecksumError,
    MitreCatalogueNotFoundError,
    MitreCatalogueService,
    MitreCatalogueValidationError,
)


@pytest.fixture
def mock_catalogue_service():
    """Create a mock MitreCatalogueService instance."""
    mock_service = MagicMock(spec=MitreCatalogueService)
    mock_service.version = "20.1"
    mock_service.domain = "enterprise-attack"
    return mock_service


# =============================================================================
# 1. Configuration Tests
# =============================================================================

def test_mitre_configuration_defaults():
    """Verify default MITRE configuration settings."""
    settings = Settings(_env_file=None)
    assert settings.MITRE_REQUIRED is False
    assert settings.MITRE_CATALOGUE_PATH.name == "mitre_attack_enterprise_v20_1.json"


def test_mitre_configuration_custom_overrides(tmp_path: Path):
    """Verify custom environment overrides for MITRE configuration."""
    custom_path = tmp_path / "custom_cat.json"
    settings = Settings(
        MITRE_REQUIRED=True,
        MITRE_CATALOGUE_PATH=custom_path,
        _env_file=None,
    )
    assert settings.MITRE_REQUIRED is True
    assert settings.MITRE_CATALOGUE_PATH == custom_path


# =============================================================================
# 2. Lifespan Startup & Shutdown (Optional Mode: MITRE_REQUIRED=False)
# =============================================================================

@pytest.mark.asyncio
async def test_lifespan_loads_catalogue_when_available(mock_catalogue_service):
    """Verify catalogue is loaded into app.state.mitre_catalogue during startup."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=False,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", return_value=mock_catalogue_service) as mock_from_file:

        async with lifespan(test_app):
            assert test_app.state.mitre_catalogue is mock_catalogue_service
            mock_from_file.assert_called_once_with(mock_settings.MITRE_CATALOGUE_PATH)

        # After shutdown, state is cleared
        assert test_app.state.mitre_catalogue is None


@pytest.mark.asyncio
async def test_lifespan_optional_missing_catalogue_starts_with_none():
    """Verify optional missing catalogue logs warning and starts with mitre_catalogue = None."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=False,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", side_effect=MitreCatalogueNotFoundError("File missing")):

        async with lifespan(test_app):
            assert test_app.state.mitre_catalogue is None


@pytest.mark.asyncio
async def test_lifespan_optional_corrupted_catalogue_starts_with_none():
    """Verify optional checksum/schema failure logs warning and starts with mitre_catalogue = None."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=False,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", side_effect=MitreCatalogueChecksumError("Mismatch")):

        async with lifespan(test_app):
            assert test_app.state.mitre_catalogue is None


# =============================================================================
# 3. Lifespan Startup (Mandatory Mode: MITRE_REQUIRED=True)
# =============================================================================

@pytest.mark.asyncio
async def test_lifespan_mandatory_missing_catalogue_aborts_startup():
    """Verify mandatory missing catalogue raises MitreCatalogueNotFoundError and aborts."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=True,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", side_effect=MitreCatalogueNotFoundError("File missing")):

        with pytest.raises(MitreCatalogueNotFoundError, match="File missing"):
            async with lifespan(test_app):
                pass


@pytest.mark.asyncio
async def test_lifespan_mandatory_checksum_mismatch_aborts_startup():
    """Verify mandatory checksum mismatch raises MitreCatalogueChecksumError and aborts."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=True,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", side_effect=MitreCatalogueChecksumError("Digest mismatch")):

        with pytest.raises(MitreCatalogueChecksumError, match="Digest mismatch"):
            async with lifespan(test_app):
                pass


@pytest.mark.asyncio
async def test_lifespan_mandatory_validation_failure_aborts_startup():
    """Verify mandatory schema error raises MitreCatalogueValidationError and aborts."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=True,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", side_effect=MitreCatalogueValidationError("Schema error")):

        with pytest.raises(MitreCatalogueValidationError, match="Schema error"):
            async with lifespan(test_app):
                pass


# =============================================================================
# 4. Partial Startup Cleanup
# =============================================================================

@pytest.mark.asyncio
async def test_partial_startup_cleanup_when_mandatory_catalogue_fails():
    """Verify previously initialized GeminiProvider and Sweeper are cleanly stopped on abort."""
    test_app = FastAPI()
    mock_settings = Settings(
        MITRE_REQUIRED=True,
        GEMINI_API_KEY=SecretStr("mock-key-1234"),
        _env_file=None,
    )

    mock_client = MagicMock()
    mock_client.close = MagicMock()
    mock_provider = GeminiProvider(
        client=mock_client,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    )

    mock_sweeper = MagicMock()
    mock_sweeper.start = MagicMock()
    mock_sweeper.stop = AsyncMock()

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.create_gemini_client", return_value=mock_provider), \
         patch("app.main.StaleInvestigationSweeper", return_value=mock_sweeper), \
         patch("app.main.dispose_engine") as mock_dispose, \
         patch.object(MitreCatalogueService, "from_file", side_effect=MitreCatalogueNotFoundError("Catalogue missing")):

        with pytest.raises(MitreCatalogueNotFoundError):
            async with lifespan(test_app):
                pass

        # Sweeper was started, and must have been stopped during partial abort
        mock_sweeper.start.assert_called_once()
        mock_sweeper.stop.assert_awaited_once()

        # Provider was initialized, and must have been closed during partial abort
        assert mock_provider.is_closed is True
        mock_client.close.assert_called_once()

        # Engine disposal was triggered
        mock_dispose.assert_called_once()

        # State attributes are cleanly reset
        assert test_app.state.sweeper is None
        assert test_app.state.gemini_provider is None
        assert test_app.state.mitre_catalogue is None


# =============================================================================
# 5. Application Instance Isolation
# =============================================================================

@pytest.mark.asyncio
async def test_multiple_applications_maintain_independent_mitre_catalogue_state():
    """Verify separate app instances own separate catalogue references without leakage."""
    app1 = FastAPI(lifespan=lifespan)
    app2 = FastAPI(lifespan=lifespan)

    mock_cat1 = MagicMock(spec=MitreCatalogueService)
    mock_cat1.version = "20.1"
    mock_cat1.domain = "enterprise-attack"
    mock_cat2 = MagicMock(spec=MitreCatalogueService)
    mock_cat2.version = "20.1"
    mock_cat2.domain = "enterprise-attack"

    mock_settings = Settings(
        MITRE_REQUIRED=False,
        GEMINI_API_KEY=None,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch.object(MitreCatalogueService, "from_file", side_effect=[mock_cat1, mock_cat2]):

        async with lifespan(app1):
            assert app1.state.mitre_catalogue is mock_cat1

            async with lifespan(app2):
                assert app2.state.mitre_catalogue is mock_cat2
                assert app1.state.mitre_catalogue is not app2.state.mitre_catalogue

            # app2 shut down, its catalogue state cleared
            assert app2.state.mitre_catalogue is None
            # app1 MUST still retain its active catalogue state
            assert app1.state.mitre_catalogue is mock_cat1

        # app1 shut down, its catalogue state cleared
        assert app1.state.mitre_catalogue is None


# =============================================================================
# 6. Health & Readiness Endpoint Tests
# =============================================================================

def test_health_live_unaffected_by_catalogue_or_db():
    """Liveness check returns 200 alive regardless of catalogue or database status."""
    app_instance = FastAPI()
    app_instance.include_router(health_router, prefix="/api")
    test_client = TestClient(app_instance)

    response = test_client.get("/api/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_health_ready_success_with_loaded_catalogue(mock_catalogue_service):
    """Readiness returns 200 ready when DB is connected and catalogue is loaded."""
    app_instance = FastAPI()
    app_instance.state.mitre_catalogue = mock_catalogue_service
    app_instance.include_router(health_router, prefix="/api")
    test_client = TestClient(app_instance)

    with patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch("app.api.health.get_settings", return_value=Settings(MITRE_REQUIRED=False, _env_file=None)):

        response = test_client.get("/api/health/ready")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ready",
            "database": "connected",
            "mitre_catalogue": "loaded",
            "mitre_required": False,
            "hindsight": "disabled",
            "hindsight_required": False,
        }


def test_health_ready_success_with_optional_unavailable_catalogue():
    """Readiness returns 200 ready when DB is connected even if optional catalogue is unavailable."""
    app_instance = FastAPI()
    app_instance.state.mitre_catalogue = None
    app_instance.include_router(health_router, prefix="/api")
    test_client = TestClient(app_instance)

    with patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch("app.api.health.get_settings", return_value=Settings(MITRE_REQUIRED=False, _env_file=None)):

        response = test_client.get("/api/health/ready")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ready",
            "database": "connected",
            "mitre_catalogue": "unavailable",
            "mitre_required": False,
            "hindsight": "disabled",
            "hindsight_required": False,
        }


def test_health_ready_fails_when_database_disconnected(mock_catalogue_service):
    """Readiness returns 503 unavailable when DB is disconnected, retaining MITRE info."""
    app_instance = FastAPI()
    app_instance.state.mitre_catalogue = mock_catalogue_service
    app_instance.include_router(health_router, prefix="/api")
    test_client = TestClient(app_instance)

    with patch("app.api.health.check_db_connectivity", return_value=(False, "Database service is unavailable.")), \
         patch("app.api.health.get_settings", return_value=Settings(MITRE_REQUIRED=False, _env_file=None)):

        response = test_client.get("/api/health/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "unavailable",
            "database": "disconnected",
            "mitre_catalogue": "loaded",
            "mitre_required": False,
            "hindsight": "disabled",
            "hindsight_required": False,
            "detail": "Database service is unavailable",
        }


def test_health_ready_fails_when_mandatory_catalogue_unavailable():
    """Readiness returns 503 unavailable when catalogue is required but unavailable."""
    app_instance = FastAPI()
    app_instance.state.mitre_catalogue = None
    app_instance.include_router(health_router, prefix="/api")
    test_client = TestClient(app_instance)

    with patch("app.api.health.check_db_connectivity", return_value=(True, "connected")), \
         patch("app.api.health.get_settings", return_value=Settings(MITRE_REQUIRED=True, _env_file=None)):

        response = test_client.get("/api/health/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "unavailable",
            "database": "connected",
            "mitre_catalogue": "unavailable",
            "mitre_required": True,
            "hindsight": "disabled",
            "hindsight_required": False,
            "detail": "Required MITRE catalogue is unavailable",
        }

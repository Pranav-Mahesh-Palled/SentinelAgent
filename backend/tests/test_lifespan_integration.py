"""Automated Lifespan and Graceful Shutdown Tests (Task 9C.3.6).

Verifies FastAPI application lifecycle integration for Hindsight incident-memory
outbox worker, ensuring correct dependency initialization, application-scoped
worker ownership, graceful shutdown ordering, and cleanup of partially
initialized resources.
"""

from __future__ import annotations

import asyncio
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, call, patch
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest

from app.core.config import Settings
from app.main import app as main_app, lifespan
from app.services.hindsight_client import (
    HindsightClientService,
    HindsightConfigurationError,
)
from app.services.memory_outbox_claim_service import MemoryOutboxClaimService
from app.services.memory_outbox_processor import HindsightMemoryOutboxProcessor
from app.services.memory_outbox_worker import HindsightMemoryOutboxWorker


# =============================================================================
# Test Helpers & Fixtures
# =============================================================================

def _build_test_settings(
    hindsight_enabled: bool = True,
    hindsight_required: bool = False,
    gemini_key: Optional[str] = None,
    mitre_required: bool = False,
    shutdown_timeout: float = 0.5,
) -> Settings:
    """Construct deterministic Settings instance for lifespan testing."""
    return Settings(
        HINDSIGHT_ENABLED=hindsight_enabled,
        HINDSIGHT_REQUIRED=hindsight_required,
        HINDSIGHT_BASE_URL="http://test-hindsight:8888",
        HINDSIGHT_API_KEY=SecretStr("test-key-12345"),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS=shutdown_timeout,
        GEMINI_API_KEY=SecretStr(gemini_key) if gemini_key else None,
        MITRE_REQUIRED=mitre_required,
        _env_file=None,
    )


def _make_mock_hindsight_service(required: bool = False) -> MagicMock:
    """Construct a mock HindsightClientService."""
    mock = MagicMock(spec=HindsightClientService)
    mock.bank_id = "test-bank"
    mock.base_url = "http://test-hindsight:8888"
    mock.is_required = required
    mock.aclose = AsyncMock()
    mock.check_health = AsyncMock(return_value=(True, "healthy"))
    return mock


def _make_mock_worker() -> MagicMock:
    """Construct a mock HindsightMemoryOutboxWorker."""
    mock = MagicMock(spec=HindsightMemoryOutboxWorker)
    mock.worker_id = f"mock-worker-{uuid.uuid4()}"
    mock.max_concurrency = 5
    mock.batch_size = 10
    mock.is_running = True
    mock.start = MagicMock()
    mock.stop = AsyncMock()
    return mock


# =============================================================================
# 1. Disabled-Mode Tests (Requirements 1-4)
# =============================================================================

@pytest.mark.asyncio
async def test_lifespan_disabled_mode_worker_not_constructed():
    """1. Hindsight disabled: worker is not constructed."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=False)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        async with lifespan(test_app):
            mock_worker_cls.assert_not_called()


@pytest.mark.asyncio
async def test_lifespan_disabled_mode_exposes_none_in_app_state():
    """2. Application state exposes hindsight_memory_outbox_worker=None when disabled."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=False)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        async with lifespan(test_app):
            assert test_app.state.hindsight_memory_outbox_worker is None

        assert test_app.state.hindsight_memory_outbox_worker is None


@pytest.mark.asyncio
async def test_lifespan_disabled_mode_no_worker_task_started():
    """3. No worker background task is started when disabled."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=False)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        async with lifespan(test_app):
            pass

        assert mock_worker_cls.return_value.start.call_count == 0


@pytest.mark.asyncio
async def test_lifespan_disabled_mode_preserves_existing_startup_shutdown():
    """4. Existing application startup and shutdown behavior remains unchanged."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=False)

    mock_sweeper = MagicMock()
    mock_sweeper.stop = AsyncMock()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.StaleInvestigationSweeper", return_value=mock_sweeper), \
         patch("app.main.MitreCatalogueService") as mock_mitre_cls, \
         patch("app.main.dispose_engine") as mock_dispose:

        async with lifespan(test_app):
            mock_sweeper.start.assert_called_once()
            mock_mitre_cls.from_file.assert_called_once()
            assert test_app.state.sweeper is mock_sweeper
            assert test_app.state.hindsight_client is None
            assert test_app.state.hindsight_memory_outbox_worker is None

        mock_sweeper.stop.assert_called_once()
        mock_dispose.assert_called_once()
        assert test_app.state.sweeper is None


# =============================================================================
# 2. Enabled-Mode Tests (Requirements 5-9)
# =============================================================================

@pytest.mark.asyncio
async def test_lifespan_enabled_mode_exactly_one_worker_constructed():
    """5. Hindsight enabled: exactly one worker is constructed."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory") as mock_sf, \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        mock_worker = _make_mock_worker()
        mock_worker_cls.return_value = mock_worker

        async with lifespan(test_app):
            assert mock_worker_cls.call_count == 1


@pytest.mark.asyncio
async def test_lifespan_enabled_mode_worker_receives_application_scoped_dependencies():
    """6. Worker receives the existing application-scoped dependencies."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()
    dummy_sf = MagicMock()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory", return_value=dummy_sf), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.MemoryOutboxClaimService") as mock_claim_cls, \
         patch("app.main.HindsightMemoryOutboxProcessor") as mock_proc_cls, \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        mock_worker = _make_mock_worker()
        mock_worker_cls.return_value = mock_worker

        async with lifespan(test_app):
            # Claim service received session factory and settings
            mock_claim_cls.assert_called_once_with(
                session_factory=dummy_sf,
                settings=settings,
            )
            # Processor received hindsight service and claim service
            mock_proc_cls.assert_called_once()
            _, proc_kwargs = mock_proc_cls.call_args
            assert proc_kwargs["hindsight_service"] is mock_hs
            assert proc_kwargs["claim_service"] is mock_claim_cls.return_value
            assert proc_kwargs["settings"] is settings

            # Worker received claim service, processor, and settings
            mock_worker_cls.assert_called_once()
            _, worker_kwargs = mock_worker_cls.call_args
            assert worker_kwargs["claim_service"] is mock_claim_cls.return_value
            assert worker_kwargs["processor"] is mock_proc_cls.return_value
            assert worker_kwargs["settings"] is settings


@pytest.mark.asyncio
async def test_lifespan_enabled_mode_worker_stored_in_app_state():
    """7. Worker is stored in application state."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        mock_worker = _make_mock_worker()
        mock_worker_cls.return_value = mock_worker

        async with lifespan(test_app):
            assert test_app.state.hindsight_memory_outbox_worker is mock_worker

        assert test_app.state.hindsight_memory_outbox_worker is None


@pytest.mark.asyncio
async def test_lifespan_enabled_mode_worker_starts_exactly_once():
    """8. Worker starts exactly once on application startup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        mock_worker = _make_mock_worker()
        mock_worker_cls.return_value = mock_worker

        async with lifespan(test_app):
            mock_worker.start.assert_called_once()


@pytest.mark.asyncio
async def test_lifespan_startup_order_database_and_hindsight_precede_worker():
    """9. Startup order ensures database and Hindsight initialization precede worker startup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    call_order: list[str] = []

    mock_hs = _make_mock_hindsight_service()

    def record_hs(*args, **kwargs):
        call_order.append("hindsight_init")
        return mock_hs

    def record_sf(*args, **kwargs):
        call_order.append("session_factory")
        return MagicMock()

    mock_worker = _make_mock_worker()

    def record_worker_init(*args, **kwargs):
        call_order.append("worker_init")
        return mock_worker

    def record_worker_start(*args, **kwargs):
        call_order.append("worker_start")

    mock_worker.start.side_effect = record_worker_start

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", side_effect=record_hs), \
         patch("app.main.get_session_factory", side_effect=record_sf), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", side_effect=record_worker_init):

        async with lifespan(test_app):
            pass

    assert call_order == ["hindsight_init", "session_factory", "worker_init", "worker_start"]


# =============================================================================
# 3. Optional & Required Dependency Tests (Requirements 10-13)
# =============================================================================

@pytest.mark.asyncio
async def test_optional_hindsight_outage_does_not_fail_readiness():
    """10. Optional Hindsight outage does not incorrectly fail application readiness."""
    mock_hs = _make_mock_hindsight_service(required=False)
    mock_hs.check_health = AsyncMock(return_value=(False, "Connection refused"))

    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, hindsight_required=False)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        mock_worker_cls.return_value = _make_mock_worker()

        async with lifespan(test_app):
            # Mount health router to verify /ready behavior directly
            from app.api.health import router as health_router
            test_app.include_router(health_router, prefix="/api")

            with patch("app.api.health.check_db_connectivity", return_value=(True, "connected")):
                client = TestClient(test_app)
                res = client.get("/api/health/ready")
                assert res.status_code == 200
                data = res.json()
                assert data["status"] == "ready"
                assert data["hindsight"] == "unavailable"
                assert data["hindsight_required"] is False


@pytest.mark.asyncio
async def test_optional_outage_allows_worker_startup_for_later_retry():
    """11. Optional outage does not silently prevent worker orchestration when client is usable."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, hindsight_required=False)
    mock_hs = _make_mock_hindsight_service(required=False)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        mock_worker = _make_mock_worker()
        mock_worker_cls.return_value = mock_worker

        async with lifespan(test_app):
            # Worker is running to poll and retry records when Hindsight returns
            mock_worker.start.assert_called_once()
            assert test_app.state.hindsight_memory_outbox_worker is mock_worker


@pytest.mark.asyncio
async def test_required_hindsight_initialization_failure_prevents_startup():
    """12. Required Hindsight initialization failure prevents successful application startup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, hindsight_required=True)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", side_effect=HindsightConfigurationError("Invalid key")), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        with pytest.raises(HindsightConfigurationError, match="Invalid key"):
            async with lifespan(test_app):
                pass


@pytest.mark.asyncio
async def test_required_mode_failure_cleans_up_earlier_resources():
    """13. Required-mode failure cleans up resources initialized earlier."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, hindsight_required=True, gemini_key="gem-123")

    mock_gemini = MagicMock()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_gemini_client", return_value=mock_gemini), \
         patch("app.main.create_hindsight_client", side_effect=HindsightConfigurationError("Fatal Hindsight err")), \
         patch("app.main.dispose_engine") as mock_dispose:

        with pytest.raises(HindsightConfigurationError):
            async with lifespan(test_app):
                pass

        mock_gemini.close.assert_called_once()
        mock_dispose.assert_called_once()
        assert test_app.state.gemini_provider is None


# =============================================================================
# 4. Shutdown Tests (Requirements 14-19)
# =============================================================================

@pytest.mark.asyncio
async def test_worker_stop_called_before_hindsight_client_close():
    """14. Worker stop is called before Hindsight client close."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    call_order: list[str] = []

    mock_hs = _make_mock_hindsight_service()
    mock_worker = _make_mock_worker()

    async def record_worker_stop(*args, **kwargs):
        call_order.append("worker_stop")

    async def record_hs_close(*args, **kwargs):
        call_order.append("hindsight_close")

    mock_worker.stop.side_effect = record_worker_stop
    mock_hs.aclose.side_effect = record_hs_close

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker):

        async with lifespan(test_app):
            pass

    assert "worker_stop" in call_order
    assert "hindsight_close" in call_order
    assert call_order.index("worker_stop") < call_order.index("hindsight_close")


@pytest.mark.asyncio
async def test_worker_stop_called_before_database_engine_disposal():
    """15. Worker stop is called before database engine disposal."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    call_order: list[str] = []

    mock_hs = _make_mock_hindsight_service()
    mock_worker = _make_mock_worker()

    async def record_worker_stop(*args, **kwargs):
        call_order.append("worker_stop")

    def record_engine_dispose(*args, **kwargs):
        call_order.append("engine_dispose")

    mock_worker.stop.side_effect = record_worker_stop

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker), \
         patch("app.main.dispose_engine", side_effect=record_engine_dispose):

        async with lifespan(test_app):
            pass

    assert "worker_stop" in call_order
    assert "engine_dispose" in call_order
    assert call_order.index("worker_stop") < call_order.index("engine_dispose")


@pytest.mark.asyncio
async def test_active_processing_receives_configured_shutdown_timeout():
    """16. Active processing receives the configured shutdown timeout."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, shutdown_timeout=3.5)

    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        # Real worker instance to verify shutdown_timeout property propagation
        async with lifespan(test_app):
            worker: HindsightMemoryOutboxWorker = test_app.state.hindsight_memory_outbox_worker
            assert worker.shutdown_timeout == 3.5


@pytest.mark.asyncio
async def test_worker_shutdown_failure_does_not_prevent_hindsight_cleanup():
    """17. Worker shutdown failure does not prevent Hindsight cleanup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)

    mock_hs = _make_mock_hindsight_service()
    mock_worker = _make_mock_worker()
    mock_worker.stop.side_effect = RuntimeError("Worker stop crashed")

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker):

        with pytest.raises(RuntimeError, match="Worker stop crashed"):
            async with lifespan(test_app):
                pass

        # Hindsight client must still have been closed!
        mock_hs.aclose.assert_called_once()
        assert test_app.state.hindsight_client is None
        assert test_app.state.hindsight_memory_outbox_worker is None


@pytest.mark.asyncio
async def test_hindsight_cleanup_failure_does_not_prevent_database_cleanup():
    """18. Hindsight cleanup failure does not prevent database cleanup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)

    mock_hs = _make_mock_hindsight_service()
    mock_hs.aclose.side_effect = RuntimeError("Hindsight aclose failed")
    mock_worker = _make_mock_worker()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker), \
         patch("app.main.dispose_engine") as mock_dispose:

        with pytest.raises(RuntimeError, match="Hindsight aclose failed"):
            async with lifespan(test_app):
                pass

        mock_dispose.assert_called_once()


@pytest.mark.asyncio
async def test_gemini_and_mitre_shutdown_remain_intact():
    """19. Existing Gemini and MITRE shutdown behavior remains intact alongside worker."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, gemini_key="gem-456")

    mock_hs = _make_mock_hindsight_service()
    mock_worker = _make_mock_worker()
    mock_gemini = MagicMock()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_gemini_client", return_value=mock_gemini), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker):

        async with lifespan(test_app):
            assert test_app.state.gemini_provider is mock_gemini

        mock_gemini.close.assert_called_once()
        assert test_app.state.gemini_provider is None
        assert test_app.state.mitre_catalogue is None


# =============================================================================
# 5. Partial-Startup Tests (Requirements 20-24)
# =============================================================================

@pytest.mark.asyncio
async def test_failure_before_worker_construction_leaves_no_worker_task():
    """20. Failure before worker construction leaves no worker task."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, mitre_required=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService.from_file", side_effect=RuntimeError("MITRE missing")), \
         patch("app.main.HindsightMemoryOutboxWorker") as mock_worker_cls:

        with pytest.raises(RuntimeError, match="MITRE missing"):
            async with lifespan(test_app):
                pass

        mock_worker_cls.assert_not_called()
        assert test_app.state.hindsight_memory_outbox_worker is None
        mock_hs.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_failure_during_worker_startup_triggers_cleanup():
    """21. Failure during worker startup triggers cleanup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, hindsight_required=True)
    mock_hs = _make_mock_hindsight_service(required=True)

    mock_worker = _make_mock_worker()
    mock_worker.start.side_effect = RuntimeError("Worker start failed")

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker), \
         patch("app.main.dispose_engine") as mock_dispose:

        with pytest.raises(RuntimeError, match="Worker start failed"):
            async with lifespan(test_app):
                pass

        mock_hs.aclose.assert_called_once()
        mock_dispose.assert_called_once()
        assert test_app.state.hindsight_memory_outbox_worker is None


@pytest.mark.asyncio
async def test_failure_immediately_after_worker_start_does_not_leave_orphaned_task():
    """22. Failure immediately after worker start does not leave an orphaned polling task."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    mock_worker = _make_mock_worker()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.HindsightMemoryOutboxWorker", return_value=mock_worker):

        try:
            async with lifespan(test_app):
                # Simulate application crash or subsequent setup abort inside lifespan
                raise RuntimeError("Post-start failure")
        except RuntimeError:
            pass

        # Worker must have been cleanly stopped during abort
        mock_worker.stop.assert_called_once()
        mock_hs.aclose.assert_called_once()
        assert test_app.state.hindsight_memory_outbox_worker is None


@pytest.mark.asyncio
async def test_partially_initialized_services_cleaned_up_correctly():
    """23. Partially initialized services are cleaned up correctly in reverse order."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, gemini_key="gem-abc")
    cleanup_log: list[str] = []

    mock_gemini = MagicMock()
    mock_gemini.close.side_effect = lambda: cleanup_log.append("gemini_closed")

    mock_hs = _make_mock_hindsight_service()

    async def record_hs_close():
        cleanup_log.append("hs_closed")

    mock_hs.aclose.side_effect = record_hs_close

    mock_sweeper = MagicMock()

    async def record_sweeper_stop():
        cleanup_log.append("sweeper_stopped")

    mock_sweeper.stop.side_effect = record_sweeper_stop

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_gemini_client", return_value=mock_gemini), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.StaleInvestigationSweeper", return_value=mock_sweeper), \
         patch("app.main.MitreCatalogueService.from_file", side_effect=RuntimeError("Catalogue failure")), \
         patch("app.main.dispose_engine", side_effect=lambda: cleanup_log.append("engine_disposed")):

        with pytest.raises(RuntimeError, match="Catalogue failure"):
            # Set MITRE_REQUIRED to True so catalogue failure aborts startup
            settings.MITRE_REQUIRED = True
            async with lifespan(test_app):
                pass

    # Reverse order: sweeper stopped, then hindsight closed, then gemini closed, then engine disposed
    assert cleanup_log == ["sweeper_stopped", "hs_closed", "gemini_closed", "engine_disposed"]


@pytest.mark.asyncio
async def test_original_startup_exception_remains_identifiable():
    """24. The original startup exception remains identifiable after cleanup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True, hindsight_required=True)

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", side_effect=ValueError("Specific root cause error")), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        with pytest.raises(ValueError, match="Specific root cause error"):
            async with lifespan(test_app):
                pass


# =============================================================================
# 6. Lifecycle Robustness (Requirements 25-28)
# =============================================================================

@pytest.mark.asyncio
async def test_repeated_startup_shutdown_cycles_do_not_leak_tasks():
    """25. Repeated startup/shutdown test cycles do not leak workers or tasks."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        for cycle in range(3):
            async with lifespan(test_app):
                worker: HindsightMemoryOutboxWorker = test_app.state.hindsight_memory_outbox_worker
                assert worker is not None
                assert worker.is_running is True

            assert test_app.state.hindsight_memory_outbox_worker is None
            assert worker.is_running is False


@pytest.mark.asyncio
async def test_independent_fastapi_instances_have_independent_workers():
    """26. Independent FastAPI application instances have independent workers."""
    app1 = FastAPI()
    app2 = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        async with lifespan(app1):
            async with lifespan(app2):
                worker1: HindsightMemoryOutboxWorker = app1.state.hindsight_memory_outbox_worker
                worker2: HindsightMemoryOutboxWorker = app2.state.hindsight_memory_outbox_worker

                assert worker1 is not None
                assert worker2 is not None
                assert worker1 is not worker2
                assert worker1.worker_id != worker2.worker_id
                assert worker1.is_running is True
                assert worker2.is_running is True

            assert app2.state.hindsight_memory_outbox_worker is None
            assert worker2.is_running is False
            assert worker1.is_running is True

        assert app1.state.hindsight_memory_outbox_worker is None
        assert worker1.is_running is False


@pytest.mark.asyncio
async def test_no_duplicate_polling_loops_created():
    """27. No duplicate polling loops are created on startup."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        async with lifespan(test_app):
            worker: HindsightMemoryOutboxWorker = test_app.state.hindsight_memory_outbox_worker
            # Calling start again returns the same running task (idempotency)
            second_task = worker.start()
            assert second_task is worker._main_task

            # Attempting run_forever() raises RuntimeError
            with pytest.raises(RuntimeError, match="already running a polling loop"):
                await worker.run_forever()


@pytest.mark.asyncio
async def test_worker_state_cleared_and_stopped_after_shutdown():
    """28. Worker state is cleared and marked stopped appropriately after shutdown."""
    test_app = FastAPI()
    settings = _build_test_settings(hindsight_enabled=True)
    mock_hs = _make_mock_hindsight_service()

    with patch("app.main.get_settings", return_value=settings), \
         patch("app.api.health.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client", return_value=mock_hs), \
         patch("app.main.get_session_factory"), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        async with lifespan(test_app):
            worker: HindsightMemoryOutboxWorker = test_app.state.hindsight_memory_outbox_worker
            assert test_app.state.hindsight_memory_outbox_worker is not None
            assert worker.is_running is True

        assert test_app.state.hindsight_memory_outbox_worker is None
        assert worker.is_running is False
        assert worker.active_task_count == 0


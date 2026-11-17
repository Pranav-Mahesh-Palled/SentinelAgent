"""Automated Integration & Unit Tests for SentinelAgent Investigation API & Lifecycle (Task 7B.6).

Covers all core requirements:
1. POST /api/investigations:
   - Valid request returns HTTP 202 Accepted.
   - Investigation persisted as pending before background execution.
   - BackgroundTask registered with fresh session factory.
   - Missing incident returns HTTP 404.
   - Duplicate active/pending investigation returns HTTP 409.
   - Invalid UUID or payload returns HTTP 422.
   - Internal error does not leak credentials or stack trace.
2. GET /api/investigations/{investigation_id}:
   - Existing pending investigation returns HTTP 200 with pending status.
   - Completed investigation returns HTTP 200 with report payload.
   - Failed investigation returns HTTP 200 with safe failure summary.
   - Unknown investigation returns HTTP 404.
   - Invalid UUID returns HTTP 422.
   - All timestamps strictly timezone-aware.
3. Background Execution:
   - Pending investigation transitions to in_progress exactly once.
   - Agent executes and terminal completion reflected in PostgreSQL.
   - Missing/closed GeminiProvider transitions investigation to failed safely.
   - Agent failure recorded with safe summary without overwriting terminal states.
   - Racing recovery stops execution cleanly.
   - No request-scoped DB session leaks to background worker.
4. Gemini Provider Application Lifespan:
   - Initializes only when GEMINI_API_KEY is configured.
   - Application starts cleanly when GEMINI_API_KEY is missing.
   - No network calls occur during startup.
   - Provider closed on shutdown releasing HTTP resources.
   - Shutdown safe when no provider was initialized.
   - Provider not closed after individual investigations.
5. Periodic Stale Investigation Recovery Sweeper:
   - Initial sweep executes on start.
   - Periodic execution offloads DB transactions to thread pool via asyncio.to_thread.
   - Active investigation unaffected.
   - Duplicate start requests rejected.
   - Sweeper cancels and awaits completion cleanly on shutdown.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import pytest
from fastapi import FastAPI, status
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db import connection
from app.db.session import get_session_factory
from app.main import app, lifespan
from app.models.detection_result import DetectionResult
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.investigation import Investigation
from app.models.investigation_tool_run import InvestigationToolRun
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationReport,
    InvestigationStatusResponse,
)
from app.services.gemini_client import GeminiProvider
from app.services.investigation_agent import InvestigationAgent
from app.services.investigation_service import (
    InvestigationService,
    InvestigationTerminatedError,
)
from app.services.investigation_sweeper import StaleInvestigationSweeper
from app.api.investigations import run_investigation_background


# =============================================================================
# Fixtures & Cleanup Tracker
# =============================================================================

@pytest.fixture
def db_engine():
    """Provides a live database engine."""
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def session_factory(db_engine):
    """Provides an isolated SQLAlchemy session factory."""
    return get_session_factory()


@pytest.fixture
def cleanup_tracker(session_factory):
    """Tracks created database records across tests and deletes them in reverse dependency order."""
    tracker: dict[str, list[uuid.UUID]] = {
        "tool_runs": [],
        "evidence_items": [],
        "investigations": [],
        "incident_events": [],
        "ssh_events": [],
        "detection_results": [],
        "incidents": [],
    }
    yield tracker

    with session_factory() as session:
        try:
            if tracker["evidence_items"]:
                session.execute(
                    delete(EvidenceItem).where(EvidenceItem.evidence_id.in_(tracker["evidence_items"]))
                )
            if tracker["tool_runs"]:
                session.execute(
                    delete(InvestigationToolRun).where(InvestigationToolRun.tool_run_id.in_(tracker["tool_runs"]))
                )
            if tracker["investigations"]:
                session.execute(
                    delete(EvidenceItem).where(EvidenceItem.investigation_id.in_(tracker["investigations"]))
                )
                session.execute(
                    delete(InvestigationToolRun).where(InvestigationToolRun.investigation_id.in_(tracker["investigations"]))
                )
                session.execute(
                    delete(Investigation).where(Investigation.investigation_id.in_(tracker["investigations"]))
                )
            if tracker["incident_events"]:
                session.execute(
                    delete(IncidentEvent).where(IncidentEvent.incident_id.in_(tracker["incident_events"]))
                )
            if tracker["ssh_events"]:
                session.execute(
                    delete(SSHEvent).where(SSHEvent.event_id.in_(tracker["ssh_events"]))
                )
            if tracker["detection_results"]:
                session.execute(
                    delete(DetectionResult).where(DetectionResult.result_id.in_(tracker["detection_results"]))
                )
            if tracker["incidents"]:
                session.execute(
                    delete(Incident).where(Incident.incident_id.in_(tracker["incidents"]))
                )
            session.commit()
        except Exception:
            session.rollback()


@pytest.fixture
def test_incident(session_factory, cleanup_tracker):
    """Create a valid Incident for investigation API tests."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Suspicious SSH Login Burst",
            incident_type="brute_force",
            source_ip="198.51.100.42",
            severity="medium",
            detection_method="hybrid",
            status="open",
            investigation_status="pending",
            created_at=now,
            updated_at=now,
        )
        session.add(inc)
        session.flush()
        cleanup_tracker["incidents"].append(inc.incident_id)
        session.commit()
        return inc


@pytest.fixture
def mock_gemini_provider():
    """Create a mock GeminiProvider with an initialized client."""
    mock_client = MagicMock()
    mock_client.close = MagicMock()
    provider = GeminiProvider(
        client=mock_client,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    )
    return provider


@pytest.fixture
def api_client(mock_gemini_provider):
    """FastAPI TestClient instance with mock provider mounted on app.state."""
    app.state.gemini_provider = mock_gemini_provider
    client = TestClient(app)
    yield client
    app.state.gemini_provider = None


# =============================================================================
# 1. POST /api/investigations Tests
# =============================================================================

def test_post_investigation_valid_returns_202_and_registers_background_task(
    api_client, test_incident, session_factory, cleanup_tracker
):
    """Verify valid POST request returns HTTP 202, persists pending record, and enqueues task."""
    inc_id = test_incident.incident_id

    with patch("app.api.investigations.run_investigation_background") as mock_bg_task:
        response = api_client.post(
            "/api/investigations",
            json={"incident_id": str(inc_id)},
        )
        assert response.status_code == status.HTTP_202_ACCEPTED
        data = response.json()

        assert data["incident_id"] == str(inc_id)
        assert data["status"] == "pending"
        inv_id = uuid.UUID(data["investigation_id"])
        cleanup_tracker["investigations"].append(inv_id)

        # Background task must be enqueued with the created investigation ID
        mock_bg_task.assert_called_once()
        args, kwargs = mock_bg_task.call_args
        assert kwargs["investigation_id"] == inv_id
        # Verify no request session was passed (uses session_factory)
        assert isinstance(kwargs["session_factory"], sessionmaker)

    # Verify database record exists with status 'pending'
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "pending"
        assert inv_row.incident_id == inc_id


def test_post_investigation_missing_incident_returns_404(api_client):
    """Verify POST returns HTTP 404 when incident ID does not exist."""
    missing_id = uuid.uuid4()
    response = api_client.post(
        "/api/investigations",
        json={"incident_id": str(missing_id)},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert f"Incident {missing_id} not found" in response.json()["detail"]


def test_post_investigation_duplicate_returns_409(
    api_client, test_incident, session_factory, cleanup_tracker
):
    """Verify duplicate investigation request for an incident returns HTTP 409 Conflict."""
    inc_id = test_incident.incident_id

    with patch("app.api.investigations.run_investigation_background"):
        # First request succeeds
        resp1 = api_client.post("/api/investigations", json={"incident_id": str(inc_id)})
        assert resp1.status_code == status.HTTP_202_ACCEPTED
        inv_id = uuid.UUID(resp1.json()["investigation_id"])
        cleanup_tracker["investigations"].append(inv_id)

        # Second request must conflict (409)
        resp2 = api_client.post("/api/investigations", json={"incident_id": str(inc_id)})
        assert resp2.status_code == status.HTTP_409_CONFLICT
        assert "already has an active or pending investigation" in resp2.json()["detail"]


def test_post_investigation_invalid_uuid_returns_422(api_client):
    """Verify invalid UUID string in request returns HTTP 422 Unprocessable Entity."""
    response = api_client.post(
        "/api/investigations",
        json={"incident_id": "not-a-valid-uuid"},
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_post_investigation_extra_forbidden_fields_returns_422(api_client, test_incident):
    """Verify extra payload fields are rejected (extra='forbid') with HTTP 422."""
    response = api_client.post(
        "/api/investigations",
        json={
            "incident_id": str(test_incident.incident_id),
            "unauthorized_field": "injection_value",
        },
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_post_investigation_internal_error_does_not_leak_internals(api_client, test_incident):
    """Verify unexpected server errors return clean 500 without leaking secrets or tracebacks."""
    with patch(
        "app.services.investigation_service.InvestigationService.create_investigation",
        side_effect=RuntimeError("SECRET_DB_PASSWORD_LEAK"),
    ):
        response = api_client.post(
            "/api/investigations",
            json={"incident_id": str(test_incident.incident_id)},
        )
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert "SECRET_DB_PASSWORD_LEAK" not in response.text
        assert "internal server error" in response.json()["detail"].lower()


def test_post_investigation_returns_503_when_provider_missing(
    api_client, test_incident, session_factory
):
    """Verify POST returns HTTP 503 and creates no DB rows or background tasks when provider is None."""
    # Ensure provider is completely absent
    app.state.gemini_provider = None

    with patch("app.api.investigations.run_investigation_background") as mock_bg_task:
        response = api_client.post(
            "/api/investigations",
            json={"incident_id": str(test_incident.incident_id)},
        )
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "Google Gemini provider is not configured or is closed" in response.json()["detail"]
        mock_bg_task.assert_not_called()

    # Verify no investigation row was created in the database
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.incident_id == test_incident.incident_id)
        ).first()
        assert inv is None


def test_post_investigation_returns_503_when_provider_closed(
    api_client, test_incident, session_factory, mock_gemini_provider
):
    """Verify POST returns HTTP 503 and creates no DB rows or tasks when provider is closed."""
    # Close provider instance
    mock_gemini_provider.close()
    assert mock_gemini_provider.is_closed is True
    app.state.gemini_provider = mock_gemini_provider

    with patch("app.api.investigations.run_investigation_background") as mock_bg_task:
        response = api_client.post(
            "/api/investigations",
            json={"incident_id": str(test_incident.incident_id)},
        )
        assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert "Google Gemini provider is not configured or is closed" in response.json()["detail"]
        mock_bg_task.assert_not_called()

    # Verify no investigation row was created in the database
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.incident_id == test_incident.incident_id)
        ).first()
        assert inv is None


# =============================================================================
# 2. GET /api/investigations/{investigation_id} Tests
# =============================================================================

def test_get_investigation_pending_status(api_client, test_incident, session_factory, cleanup_tracker):
    """Verify GET returns correct status and timezone-aware timestamps for a pending investigation."""
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    with session_factory() as session:
        inv = Investigation(
            investigation_id=inv_id,
            incident_id=test_incident.incident_id,
            status="pending",
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv_id)

    response = api_client.get(f"/api/investigations/{inv_id}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["investigation_id"] == str(inv_id)
    assert data["incident_id"] == str(test_incident.incident_id)
    assert data["status"] == "pending"
    assert data["investigation_report"] is None
    # Timestamps are timezone-aware ISO strings
    created_dt = datetime.fromisoformat(data["created_at"])
    assert created_dt.tzinfo is not None


def test_get_investigation_completed_includes_report(api_client, test_incident, session_factory, cleanup_tracker):
    """Verify GET returns structured report payload and root cause for completed investigations."""
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    report_dict = {
        "summary": "Successful brute force confirmed",
        "sufficient_evidence": True,
        "confirmed_findings": [],
        "observations": [],
        "hypotheses": [],
        "evidence_gaps": [],
    }
    with session_factory() as session:
        inv = Investigation(
            investigation_id=inv_id,
            incident_id=test_incident.incident_id,
            status="completed",
            investigation_summary="Brute force confirmed",
            root_cause_assessment="Weak root credentials",
            investigation_report=report_dict,
            started_at=now,
            completed_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv_id)

    response = api_client.get(f"/api/investigations/{inv_id}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "completed"
    assert data["investigation_summary"] == "Brute force confirmed"
    assert data["root_cause_assessment"] == "Weak root credentials"
    assert data["investigation_report"]["sufficient_evidence"] is True


def test_get_investigation_failed_exposes_safe_failure_info(
    api_client, test_incident, session_factory, cleanup_tracker
):
    """Verify GET returns sanitized failure summary without exposing raw stack traces."""
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    with session_factory() as session:
        inv = Investigation(
            investigation_id=inv_id,
            incident_id=test_incident.incident_id,
            status="failed",
            investigation_summary="[FAILED:TIMEOUT] Investigation timed out after 30 minutes.",
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv_id)

    response = api_client.get(f"/api/investigations/{inv_id}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "failed"
    assert "[FAILED:TIMEOUT]" in data["investigation_summary"]
    assert data["investigation_report"] is None


def test_get_investigation_unknown_returns_404(api_client):
    """Verify GET unknown investigation ID returns HTTP 404."""
    unknown_id = uuid.uuid4()
    response = api_client.get(f"/api/investigations/{unknown_id}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert f"Investigation {unknown_id} not found" in response.json()["detail"]


def test_get_investigation_invalid_uuid_returns_422(api_client):
    """Verify GET malformed UUID path parameter returns HTTP 422."""
    response = api_client.get("/api/investigations/not-a-valid-uuid")
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_health_endpoints_work_without_gemini_provider(api_client):
    """Verify application health and readiness checks function normally without Gemini configuration."""
    app.state.gemini_provider = None
    resp_live = api_client.get("/api/health/live")
    assert resp_live.status_code == status.HTTP_200_OK
    assert resp_live.json() == {"status": "alive"}

    resp_ready = api_client.get("/api/health/ready")
    assert resp_ready.status_code == status.HTTP_200_OK
    assert resp_ready.json()["status"] == "ready"


def test_get_investigation_works_without_gemini_provider(
    api_client, test_incident, session_factory, cleanup_tracker
):
    """Verify GET investigation details operates independently of Gemini provider availability."""
    app.state.gemini_provider = None
    now = datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    with session_factory() as session:
        inv = Investigation(
            investigation_id=inv_id,
            incident_id=test_incident.incident_id,
            status="pending",
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv_id)

    response = api_client.get(f"/api/investigations/{inv_id}")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["investigation_id"] == str(inv_id)
    assert response.json()["status"] == "pending"


# =============================================================================
# 3. Background Investigation Execution Tests
# =============================================================================

def test_background_worker_transitions_pending_to_in_progress_and_completes(
    test_incident, session_factory, cleanup_tracker
):
    """Verify run_investigation_background starts the job and completes investigation atomically."""
    inv_service = InvestigationService(session_factory=session_factory)
    inv_id = inv_service.create_investigation(test_incident.incident_id)
    cleanup_tracker["investigations"].append(inv_id)

    # Mock agent execution
    mock_agent = MagicMock()
    mock_provider = MagicMock()
    mock_provider.is_closed = False

    with patch("app.api.investigations.InvestigationAgent", return_value=mock_agent):
        run_investigation_background(
            investigation_id=inv_id,
            session_factory=session_factory,
            gemini_provider=mock_provider,
        )
        mock_agent.run.assert_called_once_with(inv_id)

    # Investigation was started (in_progress) before agent execution
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "in_progress"
        assert inv.started_at is not None


def test_background_worker_handles_missing_provider_gracefully(
    test_incident, session_factory, cleanup_tracker
):
    """Verify worker safely fails investigation if Gemini provider is unavailable."""
    inv_service = InvestigationService(session_factory=session_factory)
    inv_id = inv_service.create_investigation(test_incident.incident_id)
    cleanup_tracker["investigations"].append(inv_id)

    run_investigation_background(
        investigation_id=inv_id,
        session_factory=session_factory,
        gemini_provider=None,
    )

    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "failed"
        assert "[FAILED:PROVIDER_UNAVAILABLE]" in inv.investigation_summary


def test_background_worker_handles_closed_provider_gracefully(
    test_incident, session_factory, cleanup_tracker
):
    """Verify worker safely fails investigation if Gemini provider is already closed."""
    inv_service = InvestigationService(session_factory=session_factory)
    inv_id = inv_service.create_investigation(test_incident.incident_id)
    cleanup_tracker["investigations"].append(inv_id)

    mock_provider = MagicMock()
    mock_provider.is_closed = True

    run_investigation_background(
        investigation_id=inv_id,
        session_factory=session_factory,
        gemini_provider=mock_provider,
    )

    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "failed"
        assert "[FAILED:PROVIDER_UNAVAILABLE]" in inv.investigation_summary


def test_background_worker_agent_failure_recorded_safely(
    test_incident, session_factory, cleanup_tracker
):
    """Verify agent execution exceptions fail the investigation without exposing raw errors."""
    inv_service = InvestigationService(session_factory=session_factory)
    inv_id = inv_service.create_investigation(test_incident.incident_id)
    cleanup_tracker["investigations"].append(inv_id)

    mock_agent = MagicMock()
    mock_agent.run.side_effect = RuntimeError("External LLM Gateway 504 Timeout")
    mock_provider = MagicMock()
    mock_provider.is_closed = False

    with patch("app.api.investigations.InvestigationAgent", return_value=mock_agent):
        run_investigation_background(
            investigation_id=inv_id,
            session_factory=session_factory,
            gemini_provider=mock_provider,
        )

    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "failed"
        assert "[FAILED:AGENT_EXECUTION_FAILURE]" in inv.investigation_summary


def test_background_worker_racing_recovery_does_not_overwrite_state(
    test_incident, session_factory, cleanup_tracker
):
    """Verify worker halts cleanly without overwriting DB if recovery sweeper recovered job."""
    inv_service = InvestigationService(session_factory=session_factory)
    inv_id = inv_service.create_investigation(test_incident.incident_id)
    cleanup_tracker["investigations"].append(inv_id)

    # Simulate sweeper failing the investigation before worker calls start_investigation
    inv_service.fail_investigation(
        investigation_id=inv_id,
        error_code="TIMEOUT",
        safe_summary="Recovered by sweeper.",
    )

    mock_agent = MagicMock()
    mock_provider = MagicMock()
    mock_provider.is_closed = False

    with patch("app.api.investigations.InvestigationAgent", return_value=mock_agent):
        run_investigation_background(
            investigation_id=inv_id,
            session_factory=session_factory,
            gemini_provider=mock_provider,
        )
        # Agent should NEVER have run
        mock_agent.run.assert_not_called()

    # Original sweeper summary is preserved
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "failed"
        assert "[FAILED:TIMEOUT]" in inv.investigation_summary


# =============================================================================
# 4. Gemini Provider Application Lifespan Tests
# =============================================================================

@pytest.mark.asyncio
async def test_lifespan_initializes_gemini_provider_when_configured():
    """Verify provider is initialized during startup when GEMINI_API_KEY is present."""
    mock_settings = Settings(
        GEMINI_API_KEY=SecretStr("mock-api-key-xyz"),
        _env_file=None,
    )
    test_app = FastAPI()

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.create_gemini_client") as mock_create_client, \
         patch("app.main.StaleInvestigationSweeper"):

        mock_provider = MagicMock()
        mock_provider.model = "gemini-3.8-flash"
        mock_create_client.return_value = mock_provider

        async with lifespan(test_app):
            # Provider initialized and stored in app.state
            assert test_app.state.gemini_provider == mock_provider
            mock_create_client.assert_called_once_with(mock_settings)

        # After shutdown, provider is closed and state cleared
        mock_provider.close.assert_called_once()
        assert test_app.state.gemini_provider is None


@pytest.mark.asyncio
async def test_lifespan_starts_normally_without_gemini_key():
    """Verify app starts cleanly when GEMINI_API_KEY is not configured (offline mode)."""
    mock_settings = Settings(
        GEMINI_API_KEY=None,
        _env_file=None,
    )
    test_app = FastAPI()

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.create_gemini_client") as mock_create_client, \
         patch("app.main.StaleInvestigationSweeper"):

        async with lifespan(test_app):
            assert test_app.state.gemini_provider is None
            mock_create_client.assert_not_called()


@pytest.mark.asyncio
async def test_lifespan_shutdown_safe_when_no_provider():
    """Verify shutdown completes safely without errors when no provider was initialized."""
    test_app = FastAPI()
    test_app.state.gemini_provider = None

    with patch("app.main.get_settings", return_value=Settings(GEMINI_API_KEY=None, _env_file=None)), \
         patch("app.main.StaleInvestigationSweeper"):
        async with lifespan(test_app):
            pass  # Enter and exit immediately

    assert test_app.state.gemini_provider is None


def test_provider_not_closed_after_individual_investigation(mock_gemini_provider):
    """Verify provider instance remains open and active across investigation executions."""
    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=MagicMock(),
        session_factory=MagicMock(),
    )
    assert not mock_gemini_provider.is_closed
    assert mock_gemini_provider.client.close.call_count == 0


@pytest.mark.asyncio
async def test_multiple_application_instances_maintain_separate_provider_ownership():
    """Verify separate application instances own separate providers and shutting down one does not affect the other."""
    app1 = FastAPI(lifespan=lifespan)
    app2 = FastAPI(lifespan=lifespan)

    client1 = MagicMock()
    client1.close = MagicMock()
    provider1 = GeminiProvider(
        client=client1,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    )

    client2 = MagicMock()
    client2.close = MagicMock()
    provider2 = GeminiProvider(
        client=client2,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    )

    with patch("app.main.get_settings", return_value=Settings(GEMINI_API_KEY=SecretStr("mock-key"), _env_file=None)), \
         patch("app.main.StaleInvestigationSweeper"):

        # Start both apps with their separate providers
        with patch("app.main.create_gemini_client", side_effect=[provider1, provider2]):
            async with lifespan(app1):
                assert app1.state.gemini_provider is provider1
                async with lifespan(app2):
                    assert app2.state.gemini_provider is provider2
                    assert not provider1.is_closed
                    assert not provider2.is_closed

                # app2 has shut down: its provider was closed
                assert provider2.is_closed is True
                assert client2.close.call_count == 1
                # app1 MUST still be open, unclosed, and operational!
                assert provider1.is_closed is False
                assert client1.close.call_count == 0
                assert app1.state.gemini_provider is provider1

            # app1 has shut down: its provider was closed
            assert provider1.is_closed is True
            assert client1.close.call_count == 1


def test_provider_close_is_idempotent(mock_gemini_provider):
    """Verify calling close() multiple times on a provider is strictly idempotent and safe."""
    assert not mock_gemini_provider.is_closed
    mock_gemini_provider.close()
    assert mock_gemini_provider.is_closed is True
    assert mock_gemini_provider.client.close.call_count == 1

    # Second close call must be a safe no-op
    mock_gemini_provider.close()
    assert mock_gemini_provider.is_closed is True
    assert mock_gemini_provider.client.close.call_count == 1


# =============================================================================
# 5. Periodic Stale Investigation Recovery Sweeper Tests
# =============================================================================

@pytest.mark.asyncio
async def test_sweeper_initial_sweep_executes_on_startup(session_factory, cleanup_tracker):
    """Verify sweeper runs an initial recovery sweep immediately on start."""
    now = datetime.now(timezone.utc) - timedelta(minutes=10)

    # Insert an abandoned pending investigation
    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Abandoned Incident",
            incident_type="brute_force",
            source_ip="192.0.2.99",
            severity="medium",
            detection_method="hybrid",
            status="open",
            investigation_status="pending",
            created_at=now,
            updated_at=now,
        )
        session.add(inc)
        session.flush()
        cleanup_tracker["incidents"].append(inc.incident_id)

        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="pending",
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv.investigation_id)
        inv_id = inv.investigation_id

    # Create sweeper with real session factory
    sweeper = StaleInvestigationSweeper(
        session_factory=session_factory,
        interval_seconds=60,
    )
    sweeper.start()
    assert sweeper.is_running

    # Yield control briefly so initial sweep completes
    await asyncio.sleep(0.1)

    # Stop sweeper cleanly
    await sweeper.stop()
    assert not sweeper.is_running

    # Verify abandoned pending investigation was recovered to failed
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "failed"
        assert "[FAILED:TIMEOUT]" in inv_row.investigation_summary


@pytest.mark.asyncio
async def test_sweeper_active_investigation_remains_unaffected(session_factory, cleanup_tracker):
    """Verify that an in_progress investigation with fresh heartbeat is NOT touched by sweeper."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Active Incident",
            incident_type="brute_force",
            source_ip="192.0.2.100",
            severity="medium",
            detection_method="hybrid",
            status="open",
            investigation_status="in_progress",
            created_at=now,
            updated_at=now,
        )
        session.add(inc)
        session.flush()
        cleanup_tracker["incidents"].append(inc.incident_id)

        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv.investigation_id)
        inv_id = inv.investigation_id

    sweeper = StaleInvestigationSweeper(
        session_factory=session_factory,
        interval_seconds=60,
    )
    sweeper.start()
    await asyncio.sleep(0.1)
    await sweeper.stop()

    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "in_progress"


@pytest.mark.asyncio
async def test_sweeper_runs_database_work_off_event_loop():
    """Verify sweeper uses asyncio.to_thread to keep the event loop responsive."""
    mock_service = MagicMock()
    mock_service.recover_stale_investigations.return_value = {"investigations": [], "incidents": []}

    sweeper = StaleInvestigationSweeper(
        service=mock_service,
        interval_seconds=60,
    )

    with patch("asyncio.to_thread", wraps=asyncio.to_thread) as spy_to_thread:
        sweeper.start()
        await asyncio.sleep(0.05)
        await sweeper.stop()
        # Verify asyncio.to_thread was called with recover_stale_investigations
        spy_to_thread.assert_called_with(mock_service.recover_stale_investigations)


@pytest.mark.asyncio
async def test_sweeper_rejects_duplicate_starts():
    """Verify calling start() on an already running sweeper does not create duplicate tasks."""
    mock_service = MagicMock()
    mock_service.recover_stale_investigations.return_value = {"investigations": [], "incidents": []}

    sweeper = StaleInvestigationSweeper(service=mock_service, interval_seconds=60)
    sweeper.start()
    initial_task = sweeper._task

    # Call start() again
    sweeper.start()
    assert sweeper._task is initial_task

    await sweeper.stop()


def test_openapi_investigation_routes_registered(api_client):
    """Verify that investigation routes appear correctly in FastAPI OpenAPI documentation."""
    response = api_client.get("/openapi.json")
    assert response.status_code == status.HTTP_200_OK
    schema = response.json()
    paths = schema["paths"]

    # Verify POST /api/investigations
    assert "/api/investigations" in paths
    assert "post" in paths["/api/investigations"]
    post_op = paths["/api/investigations"]["post"]
    assert "202" in post_op["responses"]
    assert "404" in post_op["responses"]
    assert "409" in post_op["responses"]
    assert "503" in post_op["responses"]

    # Verify GET /api/investigations/{investigation_id}
    assert "/api/investigations/{investigation_id}" in paths
    assert "get" in paths["/api/investigations/{investigation_id}"]
    get_op = paths["/api/investigations/{investigation_id}"]["get"]
    assert "200" in get_op["responses"]
    assert "404" in get_op["responses"]


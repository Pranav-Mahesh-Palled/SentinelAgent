"""SentinelAgent AI Investigation API and Lifecycle Integration (Task 7B.6).

Provides REST API endpoints for:
- Initiating incident investigations (POST /api/investigations)
- Polling investigation status and retrieving epistemic reports (GET /api/investigations/{investigation_id})
- Executing asynchronous investigation workflows in managed background tasks

FastAPI BackgroundTasks Durability Limitations & Mitigation Architecture:
-------------------------------------------------------------------------
1. In-Memory Execution: FastAPI BackgroundTasks execute in the server process memory.
   If the container, process, or worker terminates unexpectedly during execution,
   in-flight tasks are interrupted.
2. No Cross-Restart Queue: Tasks are not backed by an external distributed broker (e.g. Celery/Redis).
3. Stale Recovery Mitigation: SentinelAgent specifically mitigates process crashes and orphaned
   tasks via StaleInvestigationSweeper and InvestigationService.recover_stale_investigations().
   Any investigation left in 'pending' (>5m) or 'in_progress' without heartbeats (>5m)
   is safely recovered to 'failed' with audit records preserved, preventing orphaned locks.
"""

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, status
from sqlalchemy.orm import Session, sessionmaker

from app.db.session import get_session_factory
from app.schemas.investigation import (
    InvestigationCreateRequest,
    InvestigationStatusResponse,
)
from app.services.gemini_client import GeminiProvider
from app.services.incident_memory_recall_service import IncidentMemoryRecallService
from app.services.investigation_agent import (
    InvestigationAgent,
    InvestigationAgentError,
)
from app.services.investigation_service import (
    IncidentNotFoundError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    InvestigationService,
    InvestigationTerminatedError,
)
from app.services.mitre_catalogue_service import MitreCatalogueService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/investigations", tags=["investigations"])


# =============================================================================
# Background Investigation Worker
# =============================================================================

def run_investigation_background(
    investigation_id: uuid.UUID,
    session_factory: Optional[sessionmaker[Session]] = None,
    gemini_provider: Optional[GeminiProvider] = None,
    mitre_catalogue: Optional[MitreCatalogueService] = None,
    recall_service: Optional[IncidentMemoryRecallService] = None,
) -> None:
    """Execute end-to-end incident investigation workflow in a background task.

    Lifecycle:
    1. Obtains short-lived database sessions via session factory (never leaks request-scoped sessions).
    2. Transitions investigation from 'pending' to 'in_progress' via start_investigation().
    3. Obtains configured GeminiProvider from application state.
    4. Initializes InvestigationAgent with injected dependencies.
    5. Executes agent.run(), managing tool execution, heartbeat, and final report synthesis.
    6. Ensures terminal states are never overwritten on failure.
    """
    sf = session_factory or get_session_factory()
    service = InvestigationService(session_factory=sf)

    # 1. Transition pending -> in_progress
    try:
        service.start_investigation(investigation_id)
        logger.info("Investigation %s transitioned to in_progress in background worker.", investigation_id)
    except InvestigationNotFoundError:
        logger.error("Background task aborted: investigation %s not found.", investigation_id)
        return
    except InvestigationConflictError as exc:
        logger.warning(
            "Investigation %s cannot be started (conflict or already running): %s",
            investigation_id,
            exc,
        )
        return
    except InvestigationTerminatedError:
        logger.warning("Investigation %s was terminated before execution could begin.", investigation_id)
        return
    except Exception as exc:
        logger.error("Unexpected error starting investigation %s: %s", investigation_id, exc, exc_info=True)
        try:
            service.fail_investigation(
                investigation_id=investigation_id,
                error_code="STARTUP_FAILURE",
                safe_summary="Failed to start investigation execution.",
            )
        except Exception as fail_err:
            logger.error("Failed to mark investigation %s as failed: %s", investigation_id, fail_err)
        return

    # 2. Resolve GeminiProvider (passed explicitly; no process-global fallback)
    provider = gemini_provider
    if provider is None or provider.is_closed:
        logger.error("Gemini provider is unavailable for investigation %s.", investigation_id)
        try:
            service.fail_investigation(
                investigation_id=investigation_id,
                error_code="PROVIDER_UNAVAILABLE",
                safe_summary="Google Gemini AI provider is unconfigured or closed.",
            )
        except Exception as fail_err:
            logger.error("Failed to mark investigation %s as failed: %s", investigation_id, fail_err)
        return

    # 3. Instantiate Agent and Execute Workflow
    try:
        agent = InvestigationAgent(
            gemini_provider=provider,
            investigation_service=service,
            session_factory=sf,
            mitre_catalogue=mitre_catalogue,
            recall_service=recall_service,
        )
        agent.run(investigation_id)
        logger.info("Investigation %s completed successfully in background worker.", investigation_id)
    except InvestigationTerminatedError:
        # Sweeper or supervisor terminated the run; exit cleanly without database writes
        logger.warning("Investigation %s terminated by recovery sweeper during execution.", investigation_id)
    except Exception as exc:
        logger.error("Investigation %s execution failed: %s", investigation_id, exc, exc_info=True)
        # Note: agent.run() internally transitions to failed on operational errors.
        # Ensure terminal state in case failure occurred before or outside agent.run() error handler:
        try:
            current_inv = service.get_investigation(investigation_id)
            if current_inv.status in ("pending", "in_progress"):
                service.fail_investigation(
                    investigation_id=investigation_id,
                    error_code="AGENT_EXECUTION_FAILURE",
                    safe_summary=f"Investigation execution failed: {type(exc).__name__}",
                )
        except Exception as fail_err:
            logger.error("Failed to record failure status for investigation %s: %s", investigation_id, fail_err)


# =============================================================================
# API Endpoints
# =============================================================================

@router.post(
    "",
    response_model=InvestigationStatusResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate Incident Investigation",
    description=(
        "Validates the specified incident ID, initializes a pending investigation record, "
        "and enqueues the investigation workflow in a background execution task."
    ),
    responses={
        202: {
            "description": "Investigation created and accepted for background execution.",
            "model": InvestigationStatusResponse,
        },
        404: {"description": "Incident not found."},
        409: {"description": "Incident already has an active or pending investigation."},
        422: {"description": "Validation error in request payload."},
        500: {"description": "Internal server error."},
        503: {"description": "AI investigation service is unavailable."},
    },
)
def create_investigation(
    payload: InvestigationCreateRequest,
    background_tasks: BackgroundTasks,
    request: Request,
) -> InvestigationStatusResponse:
    """Create a pending investigation and enqueue background processing."""
    # 1. Reject immediately if GeminiProvider is missing or closed (fail fast before DB write)
    provider: Optional[GeminiProvider] = getattr(request.app.state, "gemini_provider", None)
    if provider is None or provider.is_closed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI investigation service is unavailable: Google Gemini provider is not configured or is closed.",
        )

    # 2. Validate incident ID and persist pending investigation
    service = InvestigationService(session_factory=get_session_factory())

    try:
        inv_id = service.create_investigation(payload.incident_id)
    except IncidentNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {payload.incident_id} not found.",
        )
    except InvestigationConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "Unexpected error creating investigation for incident %s: %s",
            payload.incident_id,
            exc,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal server error occurred while creating the investigation.",
        )

    # 3. Enqueue background execution task with explicitly injected provider, app-scoped catalogue, and recall service
    catalogue: Optional[MitreCatalogueService] = getattr(request.app.state, "mitre_catalogue", None)
    recall_svc: Optional[IncidentMemoryRecallService] = getattr(request.app.state, "incident_memory_recall_service", None)
    background_tasks.add_task(
        run_investigation_background,
        investigation_id=inv_id,
        session_factory=get_session_factory(),
        gemini_provider=provider,
        mitre_catalogue=catalogue,
        recall_service=recall_svc,
    )

    inv_dto = service.get_investigation(inv_id)
    return InvestigationStatusResponse.model_validate(inv_dto)


@router.get(
    "/{investigation_id}",
    response_model=InvestigationStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Investigation Status",
    description="Retrieve the current status, high-level summary, and epistemic investigation report.",
    responses={
        200: {
            "description": "Investigation status details.",
            "model": InvestigationStatusResponse,
        },
        404: {"description": "Investigation not found."},
        422: {"description": "Invalid UUID format."},
    },
)
def get_investigation(
    investigation_id: uuid.UUID,
) -> InvestigationStatusResponse:
    """Retrieve investigation status and report information."""
    service = InvestigationService(session_factory=get_session_factory())

    try:
        dto = service.get_investigation(investigation_id)
    except InvestigationNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation {investigation_id} not found.",
        )

    return InvestigationStatusResponse.model_validate(dto)


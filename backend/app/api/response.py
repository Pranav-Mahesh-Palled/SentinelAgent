"""FastAPI REST API Endpoints for SentinelAgent Response Orchestration (Phase 11.3A).

Provides authenticated, role-authorized REST endpoints for:
1. Proposal Management:
   - POST /api/v1/incidents/{incident_id}/response/proposals
2. Response Action Retrieval:
   - GET /api/v1/incidents/{incident_id}/response/actions
   - GET /api/v1/response/actions/{action_id}
3. Lifecycle Transitions:
   - POST /api/v1/response/actions/{action_id}/approve
   - POST /api/v1/response/actions/{action_id}/reject
   - POST /api/v1/response/actions/{action_id}/cancel
4. Verification and Reconciliation:
   - POST /api/v1/response/actions/{action_id}/re-verify
   - POST /api/v1/response/actions/{action_id}/reconcile-execution
   - POST /api/v1/response/actions/{action_id}/reconcile-verification
"""

from collections.abc import Sequence
import json
import logging
from typing import Any, Optional
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    get_current_principal,
    require_roles,
    validate_proposer_approver_separation,
)
from app.core.auth import OperatorPrincipal, OperatorRole
from app.db.session import get_db_session
import ipaddress

from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.models.response_audit_event import ResponseAuditEvent
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.models.verification_reconciliation_probe import VerificationReconciliationProbe
from app.models.verification_reconciliation_record import VerificationReconciliationRecord
from app.schemas.response import (
    ApprovalRequest,
    CancellationRequest,
    ExecutionReconciliationRequest,
    ExecutionReconciliationResult,
    IncidentListItem,
    InvestigationEvidenceItemResponse,
    ManualReconciliationRequest,
    ManualReconciliationResult,
    OperatorMeResponse,
    ProposalCreateBody,
    ProposalCreateRequest,
    ProposalResponseData,
    RejectionRequest,
    ResponseActionDetailResponse,
    ResponseActionSimulationDetails,
    ResponseActionVerificationDetails,
    ResponseAuditEventResponse,
    TransitionResponseData,
    parse_sac_json_v1,
)
from app.services.investigation_service import IncidentNotFoundError, InvestigationNotFoundError
from app.services.reconciliation_service import ManualReconciliationService
from app.services.response_idempotency_service import (
    ActiveActionConflictError,
    AuthorizationError,
    EvidenceProvenanceError,
    FencingTokenError,
    IdempotencyConflictError,
    InvalidStateTransitionError,
    OptimisticLockError,
    ReconciliationError,
    ResponseServiceError,
)
from app.services.response_proposal_service import ResponseProposalService
from app.services.response_transition_service import ResponseTransitionService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["response-orchestration"])


# =============================================================================
# Helper & Exception Mapping
# =============================================================================

def _map_domain_exception(exc: Exception) -> HTTPException:
    """Map domain exceptions to standard HTTP error responses."""
    if isinstance(exc, (IdempotencyConflictError, ActiveActionConflictError, OptimisticLockError, FencingTokenError)):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))
    if isinstance(exc, AuthorizationError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, (InvalidStateTransitionError, EvidenceProvenanceError, ReconciliationError)):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    if isinstance(exc, (IncidentNotFoundError, InvestigationNotFoundError)):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, ValueError):
        return HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    logger.error("Unhandled error in response API: %s", exc, exc_info=True)
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An internal server error occurred while processing the response action.",
    )


async def _parse_and_validate_sac_json(request: Request, schema_cls: type[BaseModel]) -> BaseModel:
    """Read raw request body, enforce SAC-JSON-v1 invariants, and validate with Pydantic.

    Enforces:
    - Rejection of duplicate raw keys and NFC key collisions before Pydantic receives data.
    - Rejection of floating point values, NaN, and Infinity.
    - Rejection of UTF-8 Byte Order Marks.
    """
    raw_bytes = await request.body()
    if not raw_bytes or not raw_bytes.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request body cannot be empty",
        )

    try:
        parsed_dict = parse_sac_json_v1(raw_bytes)
    except ValueError as val_err:
        logger.warning("SAC-JSON-v1 parse error on request: %s", val_err)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid JSON request: {val_err}",
        ) from val_err

    if not isinstance(parsed_dict, dict):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Request JSON payload must be a dictionary object",
        )

    try:
        return schema_cls.model_validate(parsed_dict)
    except ValidationError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=val_err.errors(),
        ) from val_err


def _extract_idempotency_key(idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key")) -> str:
    """Validate and return mandatory Idempotency-Key header."""
    if not idempotency_key or not idempotency_key.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing mandatory 'Idempotency-Key' header",
        )
    trimmed = idempotency_key.strip()
    if len(trimmed) < 8 or len(trimmed) > 128:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Header 'Idempotency-Key' must be between 8 and 128 characters",
        )
    return trimmed




def _extract_client_ip(request: Request) -> Optional[str]:
    """Safely extract valid client IP, ignoring testclient or non-IP values for PostgreSQL INET."""
    if not request.client or not request.client.host:
        return None
    raw = request.client.host.strip()
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        return None


def _to_detail_response(action: ResponseAction) -> ResponseActionDetailResponse:
    """Convert a ResponseAction SQLAlchemy model to ResponseActionDetailResponse DTO."""
    return ResponseActionDetailResponse(
        response_action_id=action.response_action_id,
        incident_id=action.incident_id,
        investigation_id=action.investigation_id,
        correlation_id=action.correlation_id,
        action_type=action.action_type,
        action_version=action.action_version,
        target_kind=action.target_kind,
        target_value=str(action.target_value),
        payload_json=action.payload_json,
        payload_sha256=action.payload_sha256,
        justification=action.justification,
        proposed_by_operator_id=action.proposed_by_operator_id,
        approval_status=action.approval_status,
        approved_by_operator_id=getattr(action, "approved_by_operator_id", None),
        approved_at=getattr(action, "approved_at", None),
        rejection_reason=getattr(action, "rejection_reason", None),
        rejection_at=getattr(action, "rejection_at", None),
        execution_status=action.execution_status,
        execution_deadline_at=action.execution_deadline_at,
        executed_at=getattr(action, "executed_at", None),
        verification_status=action.verification_status,
        verified_at=getattr(action, "verified_at", None),
        approval_expires_at=action.approval_expires_at,
        version=action.version,
        created_at=action.created_at,
        updated_at=action.updated_at,
    )


# =============================================================================
# A. Proposal Management
# =============================================================================

@router.post(
    "/incidents/{incident_id}/response/proposals",
    response_model=ProposalResponseData,
    summary="Create Response Proposal",
    description="Propose a containment action for an incident with a completed investigation.",
    responses={
        201: {"description": "Proposal created successfully.", "model": ProposalResponseData},
        200: {"description": "Idempotent replay returning existing proposal.", "model": ProposalResponseData},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Insufficient operator permissions."},
        404: {"description": "Incident or investigation not found."},
        409: {"description": "Active action conflict or idempotency conflict."},
        422: {"description": "Validation error or invalid evidence provenance."},
    },
)
async def create_proposal(
    incident_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    principal: OperatorPrincipal = Depends(
        require_roles(OperatorRole.ANALYST, OperatorRole.APPROVER, OperatorRole.ADMIN)
    ),
    session: Session = Depends(get_db_session),
    x_correlation_id: Optional[str] = Header(None, alias="X-Correlation-ID"),
) -> ProposalResponseData:
    """Create a new response proposal or replay previously completed proposal."""
    body_payload: ProposalCreateBody = await _parse_and_validate_sac_json(request, ProposalCreateBody)

    # Ensure path incident_id matches body if supplied
    if body_payload.incident_id is not None and body_payload.incident_id != incident_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Path incident_id ({incident_id}) does not match body incident_id ({body_payload.incident_id})",
        )

    # Reconstruct service request
    service_request = ProposalCreateRequest(
        incident_id=incident_id,
        investigation_id=body_payload.investigation_id,
        justification=body_payload.justification,
        evidence_ids=body_payload.evidence_ids,
        idempotency_key=idempotency_key,
        action_type=body_payload.action_type,
        target_kind=body_payload.target_kind,
        duration_seconds=body_payload.duration_seconds,
    )

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ResponseProposalService.create_proposal(
            session=session,
            request=service_request,
            operator=principal,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


# =============================================================================
# B. Retrieve Response Actions
# =============================================================================

@router.get(
    "/incidents/{incident_id}/response/actions",
    response_model=list[ResponseActionDetailResponse],
    summary="List Response Actions for Incident",
    description="Retrieve all response action proposals and executions associated with an incident.",
    responses={
        200: {"description": "List of response actions.", "model": list[ResponseActionDetailResponse]},
        401: {"description": "Unauthenticated."},
        404: {"description": "Incident not found."},
    },
)
def list_incident_response_actions(
    incident_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> list[ResponseActionDetailResponse]:
    """List response actions for a specific incident."""
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident {incident_id} not found.",
        )

    actions = session.scalars(
        select(ResponseAction)
        .where(ResponseAction.incident_id == incident_id)
        .order_by(ResponseAction.created_at.asc())
    ).all()

    return [_to_detail_response(action) for action in actions]


@router.get(
    "/response/actions",
    response_model=list[ResponseActionDetailResponse],
    summary="List All Response Actions",
    description="Retrieve all response actions across all incidents for the operator dashboard.",
    responses={
        200: {"description": "List of response actions.", "model": list[ResponseActionDetailResponse]},
        401: {"description": "Unauthenticated."},
    },
)
def list_all_response_actions(
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> list[ResponseActionDetailResponse]:
    """Retrieve all response actions ordered by newest first."""
    actions = session.scalars(
        select(ResponseAction).order_by(ResponseAction.created_at.desc())
    ).all()
    return [_to_detail_response(action) for action in actions]


@router.get(
    "/response/actions/{action_id}",
    response_model=ResponseActionDetailResponse,
    summary="Get Response Action Details",
    description="Retrieve detailed metadata and state for a single response action.",
    responses={
        200: {"description": "Response action details.", "model": ResponseActionDetailResponse},
        401: {"description": "Unauthenticated."},
        404: {"description": "Response action not found."},
    },
)
def get_response_action(
    action_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> ResponseActionDetailResponse:
    """Retrieve an individual response action by ID."""
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action {action_id} not found.",
        )
    return _to_detail_response(action)


# =============================================================================
# C. Approval
# =============================================================================

class ApprovalBody(BaseModel):
    """Client request body for approving a response action proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    reason: str = Field(..., min_length=3, max_length=2000, description="Approval justification")
    execution_timeout_seconds: int = Field(
        default=300,
        ge=30,
        le=86400,
        description="Execution deadline window in seconds",
    )


@router.post(
    "/response/actions/{action_id}/approve",
    response_model=TransitionResponseData,
    summary="Approve Response Proposal",
    description="Authorize containment proposal execution. Requires APPROVER role and enforces two-person integrity.",
    responses={
        200: {"description": "Proposal approved or idempotent replay.", "model": TransitionResponseData},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Proposer cannot approve own action or insufficient role."},
        404: {"description": "Response action not found."},
        409: {"description": "Optimistic lock version mismatch or idempotency conflict."},
        422: {"description": "Invalid state transition."},
    },
)
async def approve_response_action(
    action_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    approver: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER)),
    session: Session = Depends(get_db_session),
) -> TransitionResponseData:
    """Approve a pending response proposal and queue simulation execution."""
    body_payload: ApprovalBody = await _parse_and_validate_sac_json(request, ApprovalBody)

    # 1. Look up action to verify proposer/approver separation before transition
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action {action_id} not found.",
        )

    # Enforce separation of duties
    validate_proposer_approver_separation(action.proposed_by_operator_id, approver.operator_id)

    approval_request = ApprovalRequest(
        expected_version=body_payload.expected_version,
        idempotency_key=idempotency_key,
        reason=body_payload.reason,
        execution_timeout_seconds=body_payload.execution_timeout_seconds,
    )

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=action_id,
            request=approval_request,
            operator=approver,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


# =============================================================================
# D. Rejection
# =============================================================================

class RejectionBody(BaseModel):
    """Client request body for rejecting a response action proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    reason: str = Field(..., min_length=3, max_length=2000, description="Rejection reason")


@router.post(
    "/response/actions/{action_id}/reject",
    response_model=TransitionResponseData,
    summary="Reject Response Proposal",
    description="Reject a pending response proposal. Requires APPROVER role.",
    responses={
        200: {"description": "Proposal rejected or idempotent replay.", "model": TransitionResponseData},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Requires APPROVER role."},
        404: {"description": "Response action not found."},
        409: {"description": "Optimistic lock version mismatch or idempotency conflict."},
        422: {"description": "Invalid state transition."},
    },
)
async def reject_response_action(
    action_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    approver: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER)),
    session: Session = Depends(get_db_session),
) -> TransitionResponseData:
    """Reject a pending response proposal."""
    body_payload: RejectionBody = await _parse_and_validate_sac_json(request, RejectionBody)

    rejection_request = RejectionRequest(
        expected_version=body_payload.expected_version,
        idempotency_key=idempotency_key,
        reason=body_payload.reason,
    )

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ResponseTransitionService.reject_proposal(
            session=session,
            response_action_id=action_id,
            request=rejection_request,
            operator=approver,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


# =============================================================================
# E. Cancellation
# =============================================================================

class CancellationBody(BaseModel):
    """Client request body for cancelling a proposal or queued execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    reason: str = Field(..., min_length=3, max_length=2000, description="Cancellation reason")


@router.post(
    "/response/actions/{action_id}/cancel",
    response_model=TransitionResponseData,
    summary="Cancel Response Action",
    description="Cancel a pending proposal or queued execution. Rejects running or indeterminate actions.",
    responses={
        200: {"description": "Action cancelled or idempotent replay.", "model": TransitionResponseData},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Insufficient operator permissions."},
        404: {"description": "Response action not found."},
        409: {"description": "Optimistic lock version mismatch or idempotency conflict."},
        422: {"description": "Invalid state transition (e.g. running or indeterminate action)."},
    },
)
async def cancel_response_action(
    action_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    principal: OperatorPrincipal = Depends(
        require_roles(OperatorRole.ANALYST, OperatorRole.APPROVER, OperatorRole.ADMIN)
    ),
    session: Session = Depends(get_db_session),
) -> TransitionResponseData:
    """Cancel a pending proposal or queued execution."""
    body_payload: CancellationBody = await _parse_and_validate_sac_json(request, CancellationBody)

    cancellation_request = CancellationRequest(
        expected_version=body_payload.expected_version,
        idempotency_key=idempotency_key,
        reason=body_payload.reason,
    )

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ResponseTransitionService.cancel_action(
            session=session,
            response_action_id=action_id,
            request=cancellation_request,
            operator=principal,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


# =============================================================================
# F. Verification Replay
# =============================================================================

class ReVerifyBody(BaseModel):
    """Client request body for enqueuing verification replay."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    reason: str = Field(
        default="Operator requested verification replay",
        min_length=3,
        max_length=2000,
        description="Justification for re-verifying",
    )


@router.post(
    "/response/actions/{action_id}/re-verify",
    response_model=TransitionResponseData,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue Verification Replay",
    description="Enqueue a verification command for an action whose simulation execution succeeded.",
    responses={
        202: {"description": "Verification replay enqueued successfully.", "model": TransitionResponseData},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Requires APPROVER or ADMIN role."},
        404: {"description": "Response action not found."},
        409: {"description": "Optimistic lock version mismatch or idempotency conflict."},
        422: {"description": "Invalid state transition (e.g. execution has not succeeded)."},
    },
)
async def re_verify_response_action(
    action_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    principal: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER, OperatorRole.ADMIN)),
    session: Session = Depends(get_db_session),
) -> TransitionResponseData:
    """Enqueue verification replay for a succeeded simulation execution."""
    body_payload: ReVerifyBody = await _parse_and_validate_sac_json(request, ReVerifyBody)

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ResponseTransitionService.re_verify_action(
            session=session,
            response_action_id=action_id,
            expected_version=body_payload.expected_version,
            idempotency_key=idempotency_key,
            operator=principal,
            reason=body_payload.reason,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


# =============================================================================
# G. Manual Reconciliation
# =============================================================================

@router.post(
    "/response/actions/{action_id}/reconcile-execution",
    response_model=ExecutionReconciliationResult,
    summary="Manually Reconcile Indeterminate Execution",
    description="Manually settle an indeterminate execution outcome based on verified empirical evidence.",
    responses={
        200: {"description": "Execution reconciled successfully.", "model": ExecutionReconciliationResult},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Requires APPROVER or ADMIN role."},
        404: {"description": "Response action not found."},
        409: {"description": "Optimistic lock version mismatch or idempotency conflict."},
        422: {"description": "Invalid state transition or unverified evidence provenance."},
    },
)
async def reconcile_execution_action(
    action_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    principal: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER, OperatorRole.ADMIN)),
    session: Session = Depends(get_db_session),
) -> ExecutionReconciliationResult:
    """Manually reconcile an indeterminate simulation execution."""
    body_payload: ExecutionReconciliationRequest = await _parse_and_validate_sac_json(
        request, ExecutionReconciliationRequest
    )
    if not body_payload.idempotency_key:
        body_payload = body_payload.model_copy(update={"idempotency_key": idempotency_key})

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ManualReconciliationService.reconcile_execution_action(
            session=session,
            response_action_id=action_id,
            request=body_payload,
            operator=principal,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


@router.post(
    "/response/actions/{action_id}/reconcile-verification",
    response_model=ManualReconciliationResult,
    summary="Manually Reconcile Inconclusive Verification",
    description="Manually settle an inconclusive verification outcome based on scenario definition and empirical evidence.",
    responses={
        200: {"description": "Verification reconciled successfully.", "model": ManualReconciliationResult},
        400: {"description": "Missing mandatory headers or malformed payload."},
        403: {"description": "Forbidden: Requires APPROVER or ADMIN role."},
        404: {"description": "Response action not found."},
        409: {"description": "Optimistic lock version mismatch or idempotency conflict."},
        422: {"description": "Invalid state transition, mathematical mismatch, or unverified evidence."},
    },
)
async def reconcile_verification_action(
    action_id: uuid.UUID,
    request: Request,
    response: Response,
    idempotency_key: str = Depends(_extract_idempotency_key),
    principal: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER, OperatorRole.ADMIN)),
    session: Session = Depends(get_db_session),
) -> ManualReconciliationResult:
    """Manually reconcile an inconclusive verification outcome."""
    body_payload: ManualReconciliationRequest = await _parse_and_validate_sac_json(
        request, ManualReconciliationRequest
    )
    if not body_payload.idempotency_key:
        body_payload = body_payload.model_copy(update={"idempotency_key": idempotency_key})

    client_ip = _extract_client_ip(request)

    try:
        status_code, result = ManualReconciliationService.reconcile_inconclusive_action(
            session=session,
            response_action_id=action_id,
            request=body_payload,
            operator=principal,
            client_ip=client_ip,
        )
        response.status_code = status_code
        return result
    except Exception as exc:
        raise _map_domain_exception(exc)


# =============================================================================
# H. Operator Dashboard Identity & Query Endpoints
# =============================================================================

@router.get(
    "/auth/me",
    response_model=OperatorMeResponse,
    summary="Get Current Authenticated Operator Principal",
    tags=["auth"],
)
def get_me(
    principal: OperatorPrincipal = Depends(get_current_principal),
) -> OperatorMeResponse:
    """Return authenticated operator identity and validated server-side role."""
    return OperatorMeResponse(operator_id=principal.operator_id, role=principal.role.value)


@router.get(
    "/incidents",
    response_model=list[IncidentListItem],
    summary="List All Incidents for Operator Dashboard",
)
def list_incidents(
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> list[IncidentListItem]:
    """List all incidents ordered by latest activity."""
    stmt = select(Incident).order_by(Incident.updated_at.desc(), Incident.created_at.desc())
    incidents = session.scalars(stmt).all()

    items: list[IncidentListItem] = []
    for inc in incidents:
        inv_id = session.scalar(
            select(Investigation.investigation_id)
            .where(Investigation.incident_id == inc.incident_id)
            .order_by(Investigation.created_at.desc())
            .limit(1)
        )
        items.append(
            IncidentListItem(
                incident_id=inc.incident_id,
                title=inc.title,
                incident_type=inc.incident_type,
                source_ip=str(inc.source_ip),
                severity=inc.severity,
                detection_method=inc.detection_method,
                status=inc.status,
                investigation_status=inc.investigation_status,
                response_status=inc.response_status,
                verification_status=inc.verification_status,
                created_at=inc.created_at,
                updated_at=inc.updated_at,
                active_investigation_id=inv_id,
            )
        )
    return items


@router.get(
    "/incidents/{incident_id}",
    response_model=IncidentListItem,
    summary="Get Single Incident for Operator Dashboard",
)
def get_incident(
    incident_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> IncidentListItem:
    """Get incident details by ID."""
    inc = session.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_id} not found.")

    inv_id = session.scalar(
        select(Investigation.investigation_id)
        .where(Investigation.incident_id == inc.incident_id)
        .order_by(Investigation.created_at.desc())
        .limit(1)
    )
    return IncidentListItem(
        incident_id=inc.incident_id,
        title=inc.title,
        incident_type=inc.incident_type,
        source_ip=str(inc.source_ip),
        severity=inc.severity,
        detection_method=inc.detection_method,
        status=inc.status,
        investigation_status=inc.investigation_status,
        response_status=inc.response_status,
        verification_status=inc.verification_status,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        active_investigation_id=inv_id,
    )


@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=list[InvestigationEvidenceItemResponse],
    summary="List Investigation Evidence Items",
)
def list_investigation_evidence(
    investigation_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> list[InvestigationEvidenceItemResponse]:
    """Retrieve authoritative evidence items collected during an investigation."""
    inv = session.get(Investigation, investigation_id)
    if inv is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation {investigation_id} not found.")

    evidence_items = session.scalars(
        select(EvidenceItem)
        .where(EvidenceItem.investigation_id == investigation_id)
        .order_by(EvidenceItem.collected_at.asc())
    ).all()

    return [
        InvestigationEvidenceItemResponse(
            evidence_id=e.evidence_id,
            investigation_id=e.investigation_id,
            evidence_type=e.evidence_type,
            title=e.title,
            description=e.description,
            collected_at=e.collected_at,
        )
        for e in evidence_items
    ]


@router.get(
    "/response/actions/{action_id}/simulation",
    response_model=ResponseActionSimulationDetails,
    summary="Get Simulation and Execution Status",
)
def get_action_simulation_details(
    action_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> ResponseActionSimulationDetails:
    """Retrieve execution and simulation details for an action."""
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")

    ledger = session.scalar(
        select(SimulatedBlocklistEntry).where(
            SimulatedBlocklistEntry.response_action_id == action_id
        )
    )
    sim_data = None
    if ledger:
        sim_data = {
            "entry_id": str(ledger.entry_id),
            "target_ip": str(ledger.target_ip),
            "simulated_rule_id": ledger.simulated_rule_id,
            "simulated_at": ledger.simulated_at.isoformat(),
            "payload_sha256": ledger.payload_sha256,
        }

    outbox = session.scalar(
        select(ResponseOutbox).where(
            ResponseOutbox.response_action_id == action_id,
            ResponseOutbox.command_type == "execute_simulation",
        )
    )
    outbox_data = None
    if outbox:
        outbox_data = {
            "outbox_id": str(outbox.outbox_id),
            "status": outbox.status,
            "attempt_count": outbox.attempt_count,
            "max_attempts": outbox.max_attempts,
            "last_error_code": outbox.last_error_code,
            "next_attempt_at": outbox.next_attempt_at.isoformat() if outbox.next_attempt_at else None,
            "completed_at": outbox.completed_at.isoformat() if outbox.completed_at else None,
        }

    return ResponseActionSimulationDetails(
        response_action_id=action.response_action_id,
        execution_status=action.execution_status,
        executed_at=getattr(action, "executed_at", None),
        execution_deadline_at=action.execution_deadline_at,
        simulated_entry=sim_data,
        outbox=outbox_data,
    )


@router.get(
    "/response/actions/{action_id}/verification",
    response_model=ResponseActionVerificationDetails,
    summary="Get Verification and Reconciliation Details",
)
def get_action_verification_details(
    action_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> ResponseActionVerificationDetails:
    """Retrieve verification results, reconciliation records, and synthetic probe evaluations."""
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")

    rec = session.scalar(
        select(VerificationReconciliationRecord)
        .where(VerificationReconciliationRecord.response_action_id == action_id)
        .order_by(VerificationReconciliationRecord.created_at.desc())
        .limit(1)
    )
    rec_data = None
    probes_data = []

    if rec:
        rec_data = {
            "reconciliation_id": str(rec.reconciliation_id),
            "resolution": rec.resolution,
            "synthetic_scenario_id": rec.synthetic_scenario_id,
            "observation_window_start": rec.observation_window_start.isoformat(),
            "observation_window_end": rec.observation_window_end.isoformat(),
            "reconciled_at": rec.created_at.isoformat(),
            "actor_operator_id": rec.actor_operator_id,
        }

        probe_records = session.scalars(
            select(VerificationReconciliationProbe)
            .where(VerificationReconciliationProbe.reconciliation_id == rec.reconciliation_id)
        ).all()
        for p in probe_records:
            probes_data.append({
                "probe_id": p.probe_id,
                "generation_evidence_id": str(p.generation_evidence_id),
                "capture_evidence_id": str(p.capture_evidence_id),
                "interception_evidence_id": str(p.interception_evidence_id) if p.interception_evidence_id else None,
                "intercepted": p.intercepted,
            })

    return ResponseActionVerificationDetails(
        response_action_id=action.response_action_id,
        verification_status=action.verification_status,
        verified_at=getattr(action, "verified_at", None),
        reconciliation_record=rec_data,
        probes=probes_data,
    )


@router.get(
    "/response/actions/{action_id}/audit-events",
    response_model=list[ResponseAuditEventResponse],
    summary="List Audit Trail for Response Action",
)
def list_action_audit_events(
    action_id: uuid.UUID,
    principal: OperatorPrincipal = Depends(get_current_principal),
    session: Session = Depends(get_db_session),
) -> list[ResponseAuditEventResponse]:
    """Retrieve immutable audit trail for a response action."""
    action = session.get(ResponseAction, action_id)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Response action {action_id} not found.")

    events = session.scalars(
        select(ResponseAuditEvent)
        .where(ResponseAuditEvent.response_action_id == action_id)
        .order_by(ResponseAuditEvent.sequence_number.asc())
    ).all()

    return [
        ResponseAuditEventResponse(
            response_audit_event_id=ev.response_audit_event_id,
            response_action_id=ev.response_action_id,
            sequence_number=ev.sequence_number,
            event_type=ev.event_type,
            from_approval_status=ev.from_approval_status,
            to_approval_status=ev.to_approval_status,
            from_execution_status=ev.from_execution_status,
            to_execution_status=ev.to_execution_status,
            from_verification_status=ev.from_verification_status,
            to_verification_status=ev.to_verification_status,
            actor_type=ev.actor_type,
            actor_operator_id=ev.actor_operator_id,
            actor_role_snapshot=ev.actor_role_snapshot,
            reason=ev.reason,
            payload_sha256_snapshot=ev.payload_sha256_snapshot,
            created_at=ev.created_at,
        )
        for ev in events
    ]

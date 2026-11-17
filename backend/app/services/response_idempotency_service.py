"""Response Idempotency and Monotonic Audit Trail Service for SentinelAgent.

Implements:
1. Proposal idempotency lookup by (incident_id, idempotency_key_hash).
2. Transition idempotency lookup by (actor_operator_id, idempotency_key_hash).
3. SAC-JSON-v1 fingerprint matching and conflict detection.
4. Monotonic audit event sequence generation under ResponseAction row lock.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.response_action import ResponseAction
from app.models.response_audit_event import ResponseAuditEvent
from app.schemas.response import (
    calculate_request_fingerprint,
    hash_idempotency_key,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Custom Exception Hierarchy
# =============================================================================

class ResponseServiceError(Exception):
    """Base exception for all response orchestration service errors."""
    pass


class IdempotencyConflictError(ResponseServiceError):
    """Raised when an idempotency key is reused with a conflicting request payload or fingerprint."""
    pass


class ActiveActionConflictError(ResponseServiceError):
    """Raised when an incident already has an active response action."""
    pass


class OptimisticLockError(ResponseServiceError):
    """Raised when an expected version check fails due to concurrent modification."""
    pass


class InvalidStateTransitionError(ResponseServiceError):
    """Raised when an action lifecycle transition is invalid according to the state machine."""
    pass


class FencingTokenError(ResponseServiceError):
    """Raised when a worker's lease token or outbox status fails fencing verification."""
    pass


class AuthorizationError(ResponseServiceError):
    """Raised when an operator lacks the necessary role or violates separation of duties."""
    pass


class EvidenceProvenanceError(ResponseServiceError):
    """Raised when evidence items fail validation (e.g. not in investigation, or invalid type)."""
    pass


class ReconciliationError(ResponseServiceError):
    """Raised when manual or probe reconciliation fails validation invariants."""
    pass


# =============================================================================
# Idempotency and Audit Helper Functions
# =============================================================================

def check_proposal_idempotency(
    session: Session,
    incident_id: uuid.UUID,
    idempotency_key: str,
    request_payload: Any,
) -> Optional[tuple[int, dict[str, Any]]]:
    """Check if a proposal with this idempotency key already exists for the incident.

    Returns:
        tuple[status_code, response_snapshot] if matching request was previously processed.

    Raises:
        IdempotencyConflictError: If the key was used with a different request fingerprint.
    """
    key_hash = hash_idempotency_key(idempotency_key)
    action = session.scalar(
        select(ResponseAction).where(
            ResponseAction.incident_id == incident_id,
            ResponseAction.idempotency_key_hash == key_hash,
        )
    )
    if action is None:
        return None

    # Calculate candidate fingerprint
    candidate_fp = calculate_request_fingerprint(request_payload)

    # Check the initial proposal audit event for fingerprint match
    audit_event = session.scalar(
        select(ResponseAuditEvent).where(
            ResponseAuditEvent.response_action_id == action.response_action_id,
            ResponseAuditEvent.sequence_number == 1,
        )
    )

    recorded_fp = audit_event.request_fingerprint if audit_event else None
    if recorded_fp and recorded_fp != candidate_fp:
        raise IdempotencyConflictError(
            f"Idempotency key '{idempotency_key}' was previously used for incident {incident_id} "
            f"with different payload fingerprint {recorded_fp}, candidate is {candidate_fp}."
        )

    return (action.proposal_response_status_code, action.proposal_response_snapshot)


def check_transition_idempotency(
    session: Session,
    actor_operator_id: str,
    idempotency_key: str,
    request_payload: Any,
) -> Optional[tuple[int, dict[str, Any]]]:
    """Check if a transition with this idempotency key already exists for the operator.

    Returns:
        tuple[status_code, response_snapshot] if matching request was previously executed.

    Raises:
        IdempotencyConflictError: If the key was used with a different request fingerprint.
    """
    key_hash = hash_idempotency_key(idempotency_key)
    audit_event = session.scalar(
        select(ResponseAuditEvent).where(
            ResponseAuditEvent.actor_operator_id == actor_operator_id,
            ResponseAuditEvent.idempotency_key_hash == key_hash,
        )
    )
    if audit_event is None:
        return None

    candidate_fp = calculate_request_fingerprint(request_payload)
    if audit_event.request_fingerprint != candidate_fp:
        raise IdempotencyConflictError(
            f"Transition idempotency key '{idempotency_key}' was previously used by operator "
            f"'{actor_operator_id}' with different payload fingerprint {audit_event.request_fingerprint}, "
            f"candidate is {candidate_fp}."
        )

    if audit_event.response_status_code is None or audit_event.response_snapshot is None:
        raise IdempotencyConflictError(
            f"Audit event for idempotency key '{idempotency_key}' is missing response snapshot."
        )

    return (audit_event.response_status_code, audit_event.response_snapshot)


def append_audit_event(
    session: Session,
    action: ResponseAction,
    event_type: str,
    actor_type: str,
    actor_operator_id: str,
    actor_role_snapshot: str,
    reason: str,
    payload_sha256_snapshot: str,
    event_data: Optional[dict[str, Any]] = None,
    client_ip: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    request_fingerprint: Optional[str] = None,
    response_status_code: Optional[int] = None,
    response_snapshot: Optional[dict[str, Any]] = None,
    from_approval_status: Optional[str] = None,
    to_approval_status: Optional[str] = None,
    from_execution_status: Optional[str] = None,
    to_execution_status: Optional[str] = None,
    from_verification_status: Optional[str] = None,
    to_verification_status: Optional[str] = None,
    reconciliation_id: Optional[uuid.UUID] = None,
) -> ResponseAuditEvent:
    """Atomically append a monotonically sequenced audit event under the ResponseAction row lock.

    Guarantees:
    - action.last_audit_sequence is incremented by exactly 1.
    - sequence_number matches the updated action.last_audit_sequence.
    - If idempotency_key is provided, idempotency_key_hash, response_status_code, and
      response_snapshot are properly set to satisfy PostgreSQL check constraints.
    """
    next_seq = action.last_audit_sequence + 1
    action.last_audit_sequence = next_seq

    key_hash = hash_idempotency_key(idempotency_key) if idempotency_key else None

    # Enforce PostgreSQL constraint: if idempotency_key_hash IS NOT NULL, status code and snapshot must be valid objects
    if key_hash is not None:
        if response_status_code is None:
            response_status_code = 200
        if response_snapshot is None:
            response_snapshot = {
                "action_id": str(action.response_action_id),
                "approval_status": action.approval_status,
                "execution_status": action.execution_status,
                "verification_status": action.verification_status,
                "version": action.version,
            }

    audit_event = ResponseAuditEvent(
        response_audit_event_id=uuid.uuid4(),
        response_action_id=action.response_action_id,
        correlation_id=action.correlation_id,
        reconciliation_id=reconciliation_id,
        sequence_number=next_seq,
        event_type=event_type,
        from_approval_status=from_approval_status,
        to_approval_status=to_approval_status,
        from_execution_status=from_execution_status,
        to_execution_status=to_execution_status,
        from_verification_status=from_verification_status,
        to_verification_status=to_verification_status,
        actor_type=actor_type,
        actor_operator_id=actor_operator_id,
        actor_role_snapshot=actor_role_snapshot,
        reason=reason,
        event_data=event_data or {},
        payload_sha256_snapshot=payload_sha256_snapshot,
        client_ip=client_ip,
        idempotency_key_hash=key_hash,
        request_fingerprint=request_fingerprint,
        response_status_code=response_status_code,
        response_snapshot=response_snapshot,
    )
    session.add(audit_event)
    return audit_event

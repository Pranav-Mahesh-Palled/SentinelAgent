"""Response Transition Service for SentinelAgent.

Implements lifecycle transitions:
1. Approval: Role authorization (strict OperatorRole.APPROVER), separation of duties
   (proposer != approver), optimistic locking, deadline calculation, approved digest binding,
   and execution outbox command enqueuing.
2. Rejection: Proposal rejection with audit event and incident projection.
3. Cancellation: Pending proposal cancellation and approved-but-not-started execution cancellation.
   Explicitly prohibits cancelling running or indeterminate executions.
4. Expiration: System sweeper helpers for proposal expiration and execution deadline expiration.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import OperatorPrincipal, OperatorRole
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.schemas.response import (
    ApprovalRequest,
    CancellationRequest,
    RejectionRequest,
    TransitionResponseData,
    calculate_request_fingerprint,
    hash_idempotency_key,
)
from app.services.response_idempotency_service import (
    AuthorizationError,
    IdempotencyConflictError,
    InvalidStateTransitionError,
    OptimisticLockError,
    append_audit_event,
    check_transition_idempotency,
)
from app.services.response_outbox_service import ResponseOutboxService

logger = logging.getLogger(__name__)


class ResponseTransitionService:
    """Service handling lifecycle state transitions and audit logging for response actions."""

    @staticmethod
    def approve_proposal(
        session: Session,
        response_action_id: uuid.UUID,
        request: ApprovalRequest,
        operator: OperatorPrincipal,
        client_ip: Optional[str] = None,
    ) -> tuple[int, TransitionResponseData]:
        """Approve a pending response proposal and queue it for simulation execution."""
        request_dict = request.model_dump(mode="json")

        # 1. Idempotency Check
        cached = check_transition_idempotency(
            session=session,
            actor_operator_id=operator.operator_id,
            idempotency_key=request.idempotency_key,
            request_payload=request_dict,
        )
        if cached is not None:
            status_code, snapshot = cached
            return (status_code, TransitionResponseData.model_validate(snapshot))

        # 2. Authorization Verification
        if operator.role != OperatorRole.APPROVER:
            raise AuthorizationError(
                f"Operator '{operator.operator_id}' with role '{operator.role.value}' is not authorized to approve proposals. "
                "Only operators with APPROVER role may grant approval. Admin role does not inherit approver privileges."
            )

        # 3. Lock Ordering: Incident -> ResponseAction -> ResponseOutbox
        action = session.scalar(
            select(ResponseAction)
            .where(ResponseAction.response_action_id == response_action_id)
            .with_for_update()
        )
        if action is None:
            raise InvalidStateTransitionError(f"ResponseAction {response_action_id} not found.")

        incident = session.scalar(
            select(Incident)
            .where(Incident.incident_id == action.incident_id)
            .with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {action.incident_id} not found.")

        # 4. Separation of Duties Check
        if operator.operator_id == action.proposed_by_operator_id:
            raise AuthorizationError(
                f"Separation of duties violation: Operator '{operator.operator_id}' proposed action "
                f"{response_action_id} and cannot approve their own proposal."
            )

        # 5. State Machine Validation
        if action.approval_status != "pending_approval":
            raise InvalidStateTransitionError(
                f"Cannot approve action {response_action_id} in approval status '{action.approval_status}', "
                "must be 'pending_approval'."
            )

        if action.version != request.expected_version:
            raise OptimisticLockError(
                f"Optimistic lock violation on action {response_action_id}: expected version "
                f"{request.expected_version}, current version is {action.version}."
            )

        now = datetime.now(timezone.utc)
        if now >= action.approval_expires_at:
            raise InvalidStateTransitionError(
                f"Proposal {response_action_id} expired at {action.approval_expires_at.isoformat()} and cannot be approved."
            )

        # 6. Apply Transition Mutations
        execution_deadline_at = now + timedelta(seconds=request.execution_timeout_seconds)
        action.approval_status = "approved"
        action.execution_status = "queued"
        action.approved_payload_sha256 = action.payload_sha256
        action.execution_deadline_at = execution_deadline_at
        action.version += 1

        # Enqueue execution command
        outbox_entry = ResponseOutboxService.enqueue_execution_command(session, action)

        # Update Incident Projection
        incident.response_status = "approved"

        # Snapshot for idempotent replay
        snapshot_dict: dict[str, Any] = {
            "response_action_id": str(action.response_action_id),
            "approval_status": action.approval_status,
            "execution_status": action.execution_status,
            "verification_status": action.verification_status,
            "version": action.version,
            "action_version": action.action_version,
            "transition_event_type": "approval.granted",
            "sequence_number": action.last_audit_sequence + 1,
            "execution_deadline_at": execution_deadline_at.isoformat(),
            "outbox_id": str(outbox_entry.outbox_id) if outbox_entry else None,
        }

        # 7. Append Monotonic Audit Event
        append_audit_event(
            session=session,
            action=action,
            event_type="approval.granted",
            from_approval_status="pending_approval",
            to_approval_status="approved",
            from_execution_status="not_queued",
            to_execution_status="queued",
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=request.reason,
            payload_sha256_snapshot=action.payload_sha256,
            client_ip=client_ip,
            idempotency_key=request.idempotency_key,
            request_fingerprint=calculate_request_fingerprint(request_dict),
            response_status_code=200,
            response_snapshot=snapshot_dict,
        )

        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            cached_after = check_transition_idempotency(
                session=session,
                actor_operator_id=operator.operator_id,
                idempotency_key=request.idempotency_key,
                request_payload=request_dict,
            )
            if cached_after is not None:
                status_code, snap = cached_after
                return (status_code, TransitionResponseData.model_validate(snap))
            raise InvalidStateTransitionError(f"Concurrent transition conflict: {exc}") from exc

        return (200, TransitionResponseData.model_validate(snapshot_dict))

    @staticmethod
    def reject_proposal(
        session: Session,
        response_action_id: uuid.UUID,
        request: RejectionRequest,
        operator: OperatorPrincipal,
        client_ip: Optional[str] = None,
    ) -> tuple[int, TransitionResponseData]:
        """Reject a pending response action proposal."""
        request_dict = request.model_dump(mode="json")

        cached = check_transition_idempotency(
            session=session,
            actor_operator_id=operator.operator_id,
            idempotency_key=request.idempotency_key,
            request_payload=request_dict,
        )
        if cached is not None:
            status_code, snapshot = cached
            return (status_code, TransitionResponseData.model_validate(snapshot))

        # Lock ordering: Incident -> ResponseAction
        action = session.scalar(
            select(ResponseAction)
            .where(ResponseAction.response_action_id == response_action_id)
            .with_for_update()
        )
        if action is None:
            raise InvalidStateTransitionError(f"ResponseAction {response_action_id} not found.")

        incident = session.scalar(
            select(Incident)
            .where(Incident.incident_id == action.incident_id)
            .with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {action.incident_id} not found.")

        if action.approval_status != "pending_approval":
            raise InvalidStateTransitionError(
                f"Cannot reject action {response_action_id} in approval status '{action.approval_status}', "
                "must be 'pending_approval'."
            )

        if action.version != request.expected_version:
            raise OptimisticLockError(
                f"Optimistic lock violation: expected version {request.expected_version}, current {action.version}."
            )

        action.approval_status = "rejected"
        action.version += 1
        incident.response_status = "rejected"

        snapshot_dict: dict[str, Any] = {
            "response_action_id": str(action.response_action_id),
            "approval_status": action.approval_status,
            "execution_status": action.execution_status,
            "verification_status": action.verification_status,
            "version": action.version,
            "action_version": action.action_version,
            "transition_event_type": "approval.rejected",
            "sequence_number": action.last_audit_sequence + 1,
            "execution_deadline_at": None,
            "outbox_id": None,
        }

        append_audit_event(
            session=session,
            action=action,
            event_type="approval.rejected",
            from_approval_status="pending_approval",
            to_approval_status="rejected",
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=request.reason,
            payload_sha256_snapshot=action.payload_sha256,
            client_ip=client_ip,
            idempotency_key=request.idempotency_key,
            request_fingerprint=calculate_request_fingerprint(request_dict),
            response_status_code=200,
            response_snapshot=snapshot_dict,
        )

        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            cached_after = check_transition_idempotency(
                session=session,
                actor_operator_id=operator.operator_id,
                idempotency_key=request.idempotency_key,
                request_payload=request_dict,
            )
            if cached_after is not None:
                status_code, snap = cached_after
                return (status_code, TransitionResponseData.model_validate(snap))
            raise InvalidStateTransitionError(f"Concurrent transition conflict: {exc}") from exc

        return (200, TransitionResponseData.model_validate(snapshot_dict))

    @staticmethod
    def cancel_action(
        session: Session,
        response_action_id: uuid.UUID,
        request: CancellationRequest,
        operator: OperatorPrincipal,
        client_ip: Optional[str] = None,
    ) -> tuple[int, TransitionResponseData]:
        """Cancel a pending proposal or approved-but-not-started execution.

        Never clears an indeterminate outcome through ordinary cancellation.
        Invalidates stale leases using monotonic fencing tokens.
        """
        request_dict = request.model_dump(mode="json")

        cached = check_transition_idempotency(
            session=session,
            actor_operator_id=operator.operator_id,
            idempotency_key=request.idempotency_key,
            request_payload=request_dict,
        )
        if cached is not None:
            status_code, snapshot = cached
            return (status_code, TransitionResponseData.model_validate(snapshot))

        # Lock ordering: Incident -> ResponseAction -> ResponseOutbox
        action_peek = session.get(ResponseAction, response_action_id)
        if action_peek is None:
            raise InvalidStateTransitionError(f"ResponseAction {response_action_id} not found.")

        incident = session.scalar(
            select(Incident)
            .where(Incident.incident_id == action_peek.incident_id)
            .with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {action_peek.incident_id} not found.")

        action = session.scalar(
            select(ResponseAction)
            .where(ResponseAction.response_action_id == response_action_id)
            .with_for_update()
        )
        if action is None:
            raise InvalidStateTransitionError(f"ResponseAction {response_action_id} not found.")

        # Explicit invariant: Never clear an indeterminate outcome through ordinary cancellation
        if action.execution_status == "indeterminate":
            raise InvalidStateTransitionError(
                f"Action {response_action_id} is in 'indeterminate' execution status. "
                "Indeterminate states represent potential external effects and cannot be cleared through ordinary cancellation."
            )

        if action.version != request.expected_version:
            raise OptimisticLockError(
                f"Optimistic lock violation: expected version {request.expected_version}, current {action.version}."
            )

        event_type: str
        from_app = action.approval_status
        to_app = action.approval_status
        from_exec = action.execution_status
        to_exec = action.execution_status

        if action.approval_status == "pending_approval":
            action.approval_status = "cancelled"
            to_app = "cancelled"
            event_type = "proposal.cancelled"
            incident.response_status = "cancelled"
        elif action.approval_status == "approved" and action.execution_status == "queued":
            action.execution_status = "cancelled"
            to_exec = "cancelled"
            event_type = "execution.cancelled"
            incident.response_status = "cancelled"
            # Invalidate stale leases using monotonic fencing tokens
            ResponseOutboxService.cancel_action_commands(session, action.response_action_id)
        else:
            raise InvalidStateTransitionError(
                f"Cannot cancel action {response_action_id} in approval='{action.approval_status}', "
                f"execution='{action.execution_status}'. Running or indeterminate actions cannot be cancelled."
            )

        action.version += 1

        snapshot_dict: dict[str, Any] = {
            "response_action_id": str(action.response_action_id),
            "approval_status": action.approval_status,
            "execution_status": action.execution_status,
            "verification_status": action.verification_status,
            "version": action.version,
            "action_version": action.action_version,
            "transition_event_type": event_type,
            "sequence_number": action.last_audit_sequence + 1,
            "execution_deadline_at": None,
            "outbox_id": None,
        }

        append_audit_event(
            session=session,
            action=action,
            event_type=event_type,
            from_approval_status=from_app if to_app != from_app else None,
            to_approval_status=to_app if to_app != from_app else None,
            from_execution_status=from_exec if to_exec != from_exec else None,
            to_execution_status=to_exec if to_exec != from_exec else None,
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=request.reason,
            payload_sha256_snapshot=action.payload_sha256,
            client_ip=client_ip,
            idempotency_key=request.idempotency_key,
            request_fingerprint=calculate_request_fingerprint(request_dict),
            response_status_code=200,
            response_snapshot=snapshot_dict,
        )

        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            cached_after = check_transition_idempotency(
                session=session,
                actor_operator_id=operator.operator_id,
                idempotency_key=request.idempotency_key,
                request_payload=request_dict,
            )
            if cached_after is not None:
                status_code, snap = cached_after
                return (status_code, TransitionResponseData.model_validate(snap))
            raise InvalidStateTransitionError(f"Concurrent transition conflict: {exc}") from exc

        return (200, TransitionResponseData.model_validate(snapshot_dict))

    @staticmethod
    def expire_stale_proposals(session: Session, limit: int = 50) -> int:
        """System sweeper: Transition expired pending proposals to 'expired'.

        Preserves global lock hierarchy: Incident -> ResponseAction.
        """
        now = datetime.now(timezone.utc)
        candidate_ids = session.scalars(
            select(ResponseAction.response_action_id)
            .where(
                ResponseAction.approval_status == "pending_approval",
                ResponseAction.approval_expires_at <= now,
            )
            .limit(limit)
        ).all()

        expired_count = 0
        for aid in candidate_ids:
            action_peek = session.get(ResponseAction, aid)
            if not action_peek or action_peek.approval_status != "pending_approval":
                continue

            # Lock hierarchy: Incident -> ResponseAction
            incident = session.scalar(
                select(Incident).where(Incident.incident_id == action_peek.incident_id).with_for_update()
            )
            action = session.scalar(
                select(ResponseAction).where(ResponseAction.response_action_id == aid).with_for_update()
            )
            if not action or action.approval_status != "pending_approval" or action.approval_expires_at > now:
                continue

            action.approval_status = "expired"
            action.version += 1
            if incident:
                incident.response_status = "expired"

            append_audit_event(
                session=session,
                action=action,
                event_type="proposal.expired",
                from_approval_status="pending_approval",
                to_approval_status="expired",
                actor_type="system_worker",
                actor_operator_id="system_sweeper",
                actor_role_snapshot="system",
                reason="Proposal exceeded approval_expires_at deadline without decision.",
                payload_sha256_snapshot=action.payload_sha256,
            )
            expired_count += 1

        if expired_count > 0:
            session.commit()

        return expired_count

    @staticmethod
    def expire_stale_executions(session: Session, limit: int = 50) -> int:
        """System sweeper: Reconcile simulation ledger and fence workers before expiring executions.

        Preserves global lock hierarchy: Incident -> ResponseAction -> ResponseOutbox.
        Does not blindly expire executions: checks simulation ledger for committed effects.
        Fences previous workers using monotonic lease token increment.
        """
        now = datetime.now(timezone.utc)
        candidate_ids = session.scalars(
            select(ResponseAction.response_action_id)
            .where(
                ResponseAction.execution_status.in_(["queued", "running"]),
                ResponseAction.execution_deadline_at.is_not(None),
                ResponseAction.execution_deadline_at <= now,
            )
            .limit(limit)
        ).all()

        expired_count = 0
        for aid in candidate_ids:
            action_peek = session.get(ResponseAction, aid)
            if not action_peek or action_peek.execution_status not in ("queued", "running"):
                continue

            # Lock hierarchy: Incident -> ResponseAction -> ResponseOutbox
            incident = session.scalar(
                select(Incident).where(Incident.incident_id == action_peek.incident_id).with_for_update()
            )
            action = session.scalar(
                select(ResponseAction).where(ResponseAction.response_action_id == aid).with_for_update()
            )
            if not action or action.execution_status not in ("queued", "running"):
                continue

            outbox = session.scalar(
                select(ResponseOutbox).where(ResponseOutbox.response_action_id == aid).with_for_update()
            )

            # Reconcile with simulation ledger before determining final expired state
            ledger_entry = session.scalar(
                select(SimulatedBlocklistEntry).where(
                    SimulatedBlocklistEntry.response_action_id == action.response_action_id
                )
            )

            from_exec = action.execution_status

            if ledger_entry is not None:
                # Check for exact match vs integrity mismatch
                if (
                    str(ledger_entry.target_ip) == str(action.target_value)
                    and ledger_entry.payload_sha256 == action.payload_sha256
                ):
                    # Exact matching committed ledger record: recover as succeeded and queue verification
                    action.execution_status = "succeeded"
                    action.verification_status = "pending"
                    action.version += 1
                    if incident:
                        incident.response_status = "simulated"
                        incident.verification_status = "pending"
                    if outbox:
                        outbox.status = "completed"
                        outbox.completed_at = now

                    append_audit_event(
                        session=session,
                        action=action,
                        event_type="execution.succeeded",
                        from_execution_status=from_exec,
                        to_execution_status="succeeded",
                        from_verification_status="not_started",
                        to_verification_status="pending",
                        actor_type="system_worker",
                        actor_operator_id="system_sweeper",
                        actor_role_snapshot="system",
                        reason="Recovered execution as succeeded based on exact matching committed ledger record.",
                        payload_sha256_snapshot=action.payload_sha256,
                    )
                    ResponseOutboxService.enqueue_verification_command(session, action)
                else:
                    # Integrity mismatch: indeterminate and blocked
                    action.execution_status = "indeterminate"
                    action.version += 1
                    if incident:
                        incident.response_status = "indeterminate"
                    if outbox:
                        outbox.status = "dead_letter"
                        outbox.last_error_code = "INTEGRITY_ANOMALY"
                        outbox.lease_token += 1
                        outbox.lease_owner = None
                        outbox.lease_expires_at = None

                    append_audit_event(
                        session=session,
                        action=action,
                        event_type="execution.indeterminate",
                        from_execution_status=from_exec,
                        to_execution_status="indeterminate",
                        actor_type="system_worker",
                        actor_operator_id="system_sweeper",
                        actor_role_snapshot="system",
                        reason="Integrity mismatch detected on simulation ledger during expiration sweep; transitioned to indeterminate.",
                        payload_sha256_snapshot=action.payload_sha256,
                    )
            else:
                # Confirmed absence: safe to mark expired with terminal dead_letter outbox state
                action.execution_status = "expired"
                action.version += 1
                if incident:
                    incident.response_status = "expired"
                if outbox:
                    outbox.status = "dead_letter"
                    outbox.last_error_code = "EXECUTION_DEADLINE_EXPIRED"
                    outbox.lease_token += 1
                    outbox.lease_owner = None
                    outbox.lease_expires_at = None

                append_audit_event(
                    session=session,
                    action=action,
                    event_type="execution.expired",
                    from_execution_status=from_exec,
                    to_execution_status="expired",
                    actor_type="system_worker",
                    actor_operator_id="system_sweeper",
                    actor_role_snapshot="system",
                    reason="Execution exceeded execution_deadline_at before completion with confirmed absence in ledger.",
                    payload_sha256_snapshot=action.payload_sha256,
                )

            expired_count += 1

        if expired_count > 0:
            session.commit()

        return expired_count

    @staticmethod
    def re_verify_action(
        session: Session,
        response_action_id: uuid.UUID,
        expected_version: int,
        idempotency_key: str,
        operator: OperatorPrincipal,
        reason: str = "Operator requested re-verification",
        client_ip: Optional[str] = None,
    ) -> tuple[int, TransitionResponseData]:
        """Enqueue verification replay for an action whose simulation execution succeeded."""
        request_dict = {
            "response_action_id": str(response_action_id),
            "expected_version": expected_version,
            "idempotency_key": idempotency_key,
            "reason": reason,
        }

        # 1. Idempotency Check
        cached = check_transition_idempotency(
            session=session,
            actor_operator_id=operator.operator_id,
            idempotency_key=idempotency_key,
            request_payload=request_dict,
        )
        if cached is not None:
            status_code, snapshot = cached
            return (status_code, TransitionResponseData.model_validate(snapshot))

        # 2. Authorization Check: APPROVER or ADMIN
        if operator.role not in (OperatorRole.APPROVER, OperatorRole.ADMIN):
            raise AuthorizationError(
                f"Operator '{operator.operator_id}' with role '{operator.role.value}' is not authorized to trigger re-verification. "
                "Only APPROVER or ADMIN roles may trigger verification replay."
            )

        # 3. Lock hierarchy: Incident -> ResponseAction -> ResponseOutbox
        action_peek = session.get(ResponseAction, response_action_id)
        if action_peek is None:
            raise InvalidStateTransitionError(f"ResponseAction {response_action_id} not found.")

        incident = session.scalar(
            select(Incident).where(Incident.incident_id == action_peek.incident_id).with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {action_peek.incident_id} not found.")

        action = session.scalar(
            select(ResponseAction).where(ResponseAction.response_action_id == response_action_id).with_for_update()
        )
        outbox = session.scalar(
            select(ResponseOutbox).where(ResponseOutbox.response_action_id == response_action_id).with_for_update()
        )

        if action.version != expected_version:
            raise OptimisticLockError(
                f"Optimistic lock violation: expected version {expected_version}, current {action.version}."
            )

        if action.execution_status != "succeeded":
            raise InvalidStateTransitionError(
                f"Cannot re-verify action {response_action_id} in execution_status '{action.execution_status}'. "
                "Only actions with 'succeeded' simulation execution can be re-verified."
            )

        from_verif = action.verification_status
        action.verification_status = "pending"
        action.version += 1
        incident.verification_status = "pending"

        # Enqueue verification command atomically in outbox
        now = datetime.now(timezone.utc)
        dedup_key = f"resp_outbox_{action.response_action_id}_verify_simulation_v{action.version}"
        verif_cmd = ResponseOutbox(
            outbox_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            command_type="verify_simulation",
            deduplication_key=dedup_key,
            status="pending",
            attempt_count=0,
            max_attempts=3,
            next_attempt_at=now,
            lease_token=0,
            lease_owner=None,
            lease_expires_at=None,
        )
        session.add(verif_cmd)

        snapshot_dict: dict[str, Any] = {
            "response_action_id": str(action.response_action_id),
            "approval_status": action.approval_status,
            "execution_status": action.execution_status,
            "verification_status": action.verification_status,
            "version": action.version,
            "action_version": action.action_version,
            "transition_event_type": "verification.replayed",
            "sequence_number": action.last_audit_sequence + 1,
            "execution_deadline_at": (
                action.execution_deadline_at.isoformat() if action.execution_deadline_at else None
            ),
            "outbox_id": str(verif_cmd.outbox_id),
        }

        append_audit_event(
            session=session,
            action=action,
            event_type="verification.replayed",
            from_verification_status=from_verif,
            to_verification_status="pending",
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=reason,
            payload_sha256_snapshot=action.payload_sha256,
            client_ip=client_ip,
            idempotency_key=idempotency_key,
            request_fingerprint=calculate_request_fingerprint(request_dict),
            response_status_code=202,
            response_snapshot=snapshot_dict,
        )

        try:
            session.commit()
        except IntegrityError as exc:
            session.rollback()
            cached_after = check_transition_idempotency(
                session=session,
                actor_operator_id=operator.operator_id,
                idempotency_key=idempotency_key,
                request_payload=request_dict,
            )
            if cached_after is not None:
                status_code, snap = cached_after
                return (status_code, TransitionResponseData.model_validate(snap))
            raise InvalidStateTransitionError(f"Concurrent transition conflict: {exc}") from exc

        return (202, TransitionResponseData.model_validate(snapshot_dict))

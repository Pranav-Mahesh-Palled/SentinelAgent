"""Simulation Execution Service for SentinelAgent.

Orchestrates the four-stage lifecycle for simulation execution:
- Stage 1: Queue claim (ResponseOutboxService.claim_next_command)
- Stage 2: Execution Gate (Incident -> ResponseAction -> ResponseOutbox lock, validate approval/lease,
  increment attempt_count exactly once, transition queued -> running, commit).
- Transaction A: Independently validate fencing, validate deadline, insert/reconcile simulation ledger record,
  commit without combining execution-state transition.
- Transaction B: Independently validate fencing, verify committed simulation record, mark execution succeeded,
  update incident projection ('simulated', 'pending'), complete execution outbox, enqueue verification,
  append audit event, commit.
- Recovery: Distinguish matching ledger evidence, confirmed absence, and integrity anomalies.
  Fences stale workers using monotonic tokens and does not automatically requeue indeterminate actions.
"""

from datetime import datetime, timezone
import logging
from typing import Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.schemas.response import OutboxClaim, SimulationExecutionResult
from app.services.response_idempotency_service import FencingTokenError, append_audit_event
from app.services.response_outbox_service import ResponseOutboxService
from app.services.simulation_adapter import SimulationAdapter

logger = logging.getLogger(__name__)


class SimulationExecutionService:
    """Service managing the four-stage simulation execution lifecycle and recovery."""

    @staticmethod
    def execute_simulation_claim(
        session_factory: sessionmaker[Session],
        claim: OutboxClaim,
    ) -> SimulationExecutionResult:
        """Execute a claimed 'execute_simulation' outbox command using the four-stage lifecycle.

        Args:
            session_factory: SQLAlchemy sessionmaker.
            claim: Claimed outbox task representation (from Stage 1).

        Returns:
            SimulationExecutionResult indicating outcome and created IDs.
        """
        if claim is None:
            raise ValueError("Cannot execute simulation with None claim")

        sim_entry_id: Optional[uuid.UUID] = None

        # ---------------------------------------------------------------------
        # STAGE 2: Execution Gate
        # ---------------------------------------------------------------------
        try:
            with session_factory() as session_gate:
                # 1. Lookup incident_id first without lock to enforce strict lock order
                action_meta = session_gate.execute(
                    select(ResponseAction.incident_id).where(
                        ResponseAction.response_action_id == claim.response_action_id
                    )
                ).first()
                if action_meta is None:
                    raise FencingTokenError(f"ResponseAction {claim.response_action_id} not found.")
                inc_id = action_meta[0]

                # 2. Lock hierarchy strictly: Incident -> ResponseAction -> ResponseOutbox
                incident = session_gate.scalar(
                    select(Incident).where(Incident.incident_id == inc_id).with_for_update()
                )
                if incident is None:
                    raise FencingTokenError(f"Incident {inc_id} not found.")

                action = session_gate.scalar(
                    select(ResponseAction)
                    .where(ResponseAction.response_action_id == claim.response_action_id)
                    .with_for_update()
                )
                if action is None:
                    raise FencingTokenError(f"ResponseAction {claim.response_action_id} not found.")

                outbox = session_gate.scalar(
                    select(ResponseOutbox)
                    .where(ResponseOutbox.outbox_id == claim.outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    raise FencingTokenError(f"Outbox entry {claim.outbox_id} not found.")

                if action.approval_status != "approved":
                    raise FencingTokenError(
                        f"Action {action.response_action_id} not approved: '{action.approval_status}'"
                    )

                if outbox.status != "claimed" or outbox.lease_token != claim.lease_token:
                    raise FencingTokenError(
                        f"Fencing violation on outbox {outbox.outbox_id}: status={outbox.status}, "
                        f"token={outbox.lease_token}, expected={claim.lease_token}"
                    )

                # Validate retry budget BEFORE accepting and incrementing:
                if outbox.attempt_count >= outbox.max_attempts:
                    outbox.status = "dead_letter"
                    outbox.last_error_code = "MAX_ATTEMPTS_EXCEEDED"
                    session_gate.commit()
                    raise FencingTokenError("Max attempts exceeded at execution gate.")

                # Increment attempt_count exactly once at Execution Gate
                outbox.attempt_count += 1

                # Transition queued -> running if not already running
                if action.execution_status == "queued":
                    action.execution_status = "running"
                    action.version += 1
                    append_audit_event(
                        session=session_gate,
                        action=action,
                        event_type="execution.claimed",
                        from_execution_status="queued",
                        to_execution_status="running",
                        actor_type="system_worker",
                        actor_operator_id=claim.lease_owner,
                        actor_role_snapshot="system",
                        reason=f"Worker '{claim.lease_owner}' entered execution gate with lease token {claim.lease_token}.",
                        payload_sha256_snapshot=action.payload_sha256,
                    )

                session_gate.commit()
        except Exception as exc:
            logger.error(f"Stage 2 (Execution Gate) failed for action {claim.response_action_id}: {exc}", exc_info=True)
            with session_factory() as fail_session:
                ResponseOutboxService.fail_command(
                    session=fail_session,
                    outbox_id=claim.outbox_id,
                    claimed_lease_token=claim.lease_token,
                    error_code="STAGE_2_GATE_FAILURE",
                )
                fail_session.commit()
            return SimulationExecutionResult(
                success=False,
                response_action_id=claim.response_action_id,
                outbox_id=claim.outbox_id,
                error_code="STAGE_2_GATE_FAILURE",
                error_message=str(exc),
            )

        # ---------------------------------------------------------------------
        # TRANSACTION A: Simulation Ledger Effect
        # ---------------------------------------------------------------------
        try:
            with session_factory() as session_a:
                action = session_a.scalar(
                    select(ResponseAction)
                    .where(ResponseAction.response_action_id == claim.response_action_id)
                    .with_for_update()
                )
                incident = session_a.scalar(
                    select(Incident)
                    .where(Incident.incident_id == action.incident_id)
                    .with_for_update()
                )
                outbox = session_a.scalar(
                    select(ResponseOutbox)
                    .where(ResponseOutbox.outbox_id == claim.outbox_id)
                    .with_for_update()
                )

                # Execute adapter logic (strictly inserts or reconciles ledger record; does not touch action state)
                simulated_entry = SimulationAdapter.execute_simulation_effect(
                    session=session_a,
                    action=action,
                    outbox=outbox,
                    worker_id=claim.lease_owner,
                    claimed_lease_token=claim.lease_token,
                )
                sim_entry_id = simulated_entry.entry_id

                session_a.commit()
        except Exception as exc:
            logger.error(f"Transaction A failed for action {claim.response_action_id}: {exc}", exc_info=True)
            with session_factory() as fail_session:
                ResponseOutboxService.fail_command(
                    session=fail_session,
                    outbox_id=claim.outbox_id,
                    claimed_lease_token=claim.lease_token,
                    error_code="TRANSACTION_A_FAILURE",
                )
                fail_session.commit()
            return SimulationExecutionResult(
                success=False,
                response_action_id=claim.response_action_id,
                outbox_id=claim.outbox_id,
                error_code="TRANSACTION_A_FAILURE",
                error_message=str(exc),
            )

        # ---------------------------------------------------------------------
        # TRANSACTION B: State Settlement and Verification Enqueue
        # ---------------------------------------------------------------------
        try:
            with session_factory() as session_b:
                action = session_b.scalar(
                    select(ResponseAction)
                    .where(ResponseAction.response_action_id == claim.response_action_id)
                    .with_for_update()
                )
                if action is None:
                    raise FencingTokenError(f"ResponseAction {claim.response_action_id} not found in Tx B.")

                incident = session_b.scalar(
                    select(Incident)
                    .where(Incident.incident_id == action.incident_id)
                    .with_for_update()
                )
                if incident is None:
                    raise FencingTokenError(f"Incident {action.incident_id} not found in Tx B.")

                outbox = session_b.scalar(
                    select(ResponseOutbox)
                    .where(ResponseOutbox.outbox_id == claim.outbox_id)
                    .with_for_update()
                )
                if outbox is None:
                    raise FencingTokenError(f"Outbox {claim.outbox_id} not found in Tx B.")

                # Re-verify fencing invariants in Transaction B
                if action.approval_status != "approved":
                    raise FencingTokenError(f"Action approval status changed to {action.approval_status}")
                if action.execution_status != "running":
                    raise FencingTokenError(f"Action execution status is {action.execution_status}, expected running")
                if outbox.lease_token != claim.lease_token or outbox.status != "claimed":
                    raise FencingTokenError("Outbox lease token changed or unleased between Tx A and Tx B")

                # Verify committed simulation record exists
                effect = session_b.scalar(
                    select(SimulatedBlocklistEntry).where(
                        SimulatedBlocklistEntry.response_action_id == action.response_action_id
                    )
                )
                if effect is None:
                    raise FencingTokenError("Confirmed absence: simulation effect not committed in ledger")

                # Settle action state to succeeded and verification to pending
                action.execution_status = "succeeded"
                action.verification_status = "pending"
                action.version += 1

                # Update incident projections
                incident.response_status = "simulated"
                incident.verification_status = "pending"

                # Mark outbox completed
                outbox.status = "completed"
                outbox.completed_at = datetime.now(timezone.utc)

                # Monotonic audit event
                append_audit_event(
                    session=session_b,
                    action=action,
                    event_type="execution.succeeded",
                    from_execution_status="running",
                    to_execution_status="succeeded",
                    from_verification_status="not_started",
                    to_verification_status="pending",
                    actor_type="system_worker",
                    actor_operator_id=claim.lease_owner,
                    actor_role_snapshot="system",
                    reason="Simulated blocklist entry confirmed and persisted.",
                    payload_sha256_snapshot=action.payload_sha256,
                    event_data={
                        "simulated_entry_id": str(effect.entry_id),
                        "idempotency_key": effect.idempotency_key,
                    },
                )

                # Enqueue verification command
                ResponseOutboxService.enqueue_verification_command(session_b, action)

                session_b.commit()
        except Exception as exc:
            logger.error(f"Transaction B failed for action {claim.response_action_id}: {exc}", exc_info=True)
            with session_factory() as fail_session:
                ResponseOutboxService.fail_command(
                    session=fail_session,
                    outbox_id=claim.outbox_id,
                    claimed_lease_token=claim.lease_token,
                    error_code="TRANSACTION_B_FAILURE",
                )
                fail_session.commit()
            return SimulationExecutionResult(
                success=False,
                response_action_id=claim.response_action_id,
                simulated_entry_id=sim_entry_id,
                outbox_id=claim.outbox_id,
                error_code="TRANSACTION_B_FAILURE",
                error_message=str(exc),
            )

        return SimulationExecutionResult(
            success=True,
            response_action_id=claim.response_action_id,
            simulated_entry_id=sim_entry_id,
            outbox_id=claim.outbox_id,
        )

    @staticmethod
    def recover_simulation_execution(
        session_factory: sessionmaker[Session],
        response_action_id: uuid.UUID,
    ) -> str:
        """Reconciliation and recovery for stalled, crashed, or interrupted executions.

        Enforces four distinct outcomes:
        - Exact matching committed ledger record: recover as succeeded and queue verification.
        - Confirmed ledger absence with expired deadline: expire.
        - Confirmed absence with retry budget remaining: safely requeue (attempt_count untouched).
        - Integrity mismatch: indeterminate and blocked.
        """
        with session_factory() as session:
            # 1. Lookup incident_id first without lock to enforce strict lock order
            action_meta = session.execute(
                select(ResponseAction.incident_id).where(
                    ResponseAction.response_action_id == response_action_id
                )
            ).first()
            if action_meta is None:
                return "action_not_found"
            inc_id = action_meta[0]

            # 2. Lock hierarchy strictly: Incident -> ResponseAction -> ResponseOutbox
            incident = session.scalar(
                select(Incident).where(Incident.incident_id == inc_id).with_for_update()
            )
            action = session.scalar(
                select(ResponseAction)
                .where(ResponseAction.response_action_id == response_action_id)
                .with_for_update()
            )
            outbox = session.scalar(
                select(ResponseOutbox)
                .where(ResponseOutbox.response_action_id == response_action_id)
                .with_for_update()
            )

            # Check simulation ledger
            ledger_entry = session.scalar(
                select(SimulatedBlocklistEntry).where(
                    SimulatedBlocklistEntry.response_action_id == response_action_id
                )
            )

            now = datetime.now(timezone.utc)

            # Case 1: Integrity Anomaly / Mismatch
            if ledger_entry is not None:
                if (
                    str(ledger_entry.target_ip) != str(action.target_value)
                    or ledger_entry.payload_sha256 != action.payload_sha256
                ):
                    action.execution_status = "indeterminate"
                    action.version += 1
                    if incident:
                        incident.response_status = "indeterminate"
                    if outbox:
                        outbox.status = "dead_letter"
                        outbox.last_error_code = "INTEGRITY_ANOMALY"
                        outbox.lease_token += 1

                    append_audit_event(
                        session=session,
                        action=action,
                        event_type="execution.indeterminate",
                        from_execution_status="running",
                        to_execution_status="indeterminate",
                        actor_type="recovery_sweeper",
                        actor_operator_id="recovery_worker",
                        actor_role_snapshot="system",
                        reason="Integrity anomaly detected: ledger entry fields conflict with action specification.",
                        payload_sha256_snapshot=action.payload_sha256,
                    )
                    session.commit()
                    return "integrity_anomaly"

                # Case 2: Matching Committed Ledger Evidence
                if action.execution_status != "succeeded":
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
                        from_execution_status="running",
                        to_execution_status="succeeded",
                        from_verification_status="not_started",
                        to_verification_status="pending",
                        actor_type="recovery_sweeper",
                        actor_operator_id="recovery_worker",
                        actor_role_snapshot="system",
                        reason="Reconciliation: settled execution based on durable matching simulation ledger evidence.",
                        payload_sha256_snapshot=action.payload_sha256,
                    )
                    ResponseOutboxService.enqueue_verification_command(session, action)
                    session.commit()
                    return "reconciled_success"

            # Case 3: Confirmed Absence
            if ledger_entry is None:
                if outbox and outbox.status in ("claimed", "pending"):
                    # Invalidate stale worker lease with monotonic fencing token
                    outbox.lease_token += 1
                    outbox.lease_owner = None
                    outbox.lease_expires_at = None

                    # If deadline passed, expire; otherwise reset to pending if attempts remain
                    if action.execution_deadline_at is not None and now >= action.execution_deadline_at:
                        action.execution_status = "expired"
                        action.version += 1
                        if incident:
                            incident.response_status = "expired"
                        outbox.status = "dead_letter"
                        outbox.last_error_code = "EXECUTION_DEADLINE_EXPIRED"
                        append_audit_event(
                            session=session,
                            action=action,
                            event_type="execution.expired",
                            from_execution_status=action.execution_status,
                            to_execution_status="expired",
                            actor_type="recovery_sweeper",
                            actor_operator_id="recovery_worker",
                            actor_role_snapshot="system",
                            reason="Execution expired with confirmed absence of simulation effect in ledger.",
                            payload_sha256_snapshot=action.payload_sha256,
                        )
                        session.commit()
                        return "expired"
                    elif outbox.attempt_count < outbox.max_attempts:
                        action.execution_status = "queued"
                        action.version += 1
                        outbox.status = "pending"
                        outbox.next_attempt_at = now
                        append_audit_event(
                            session=session,
                            action=action,
                            event_type="execution.requeued",
                            from_execution_status="running",
                            to_execution_status="queued",
                            actor_type="recovery_sweeper",
                            actor_operator_id="recovery_worker",
                            actor_role_snapshot="system",
                            reason="Requeued after worker failure with confirmed absence in ledger.",
                            payload_sha256_snapshot=action.payload_sha256,
                        )
                        session.commit()
                        return "requeued"
                    else:
                        outbox.status = "dead_letter"
                        outbox.last_error_code = "MAX_ATTEMPTS_EXCEEDED"
                        action.execution_status = "failed"
                        action.version += 1
                        if incident:
                            incident.response_status = "failed"
                        append_audit_event(
                            session=session,
                            action=action,
                            event_type="execution.failed",
                            from_execution_status="running",
                            to_execution_status="failed",
                            actor_type="recovery_sweeper",
                            actor_operator_id="recovery_worker",
                            actor_role_snapshot="system",
                            reason="Execution failed: retry budget exhausted with confirmed absence in ledger.",
                            payload_sha256_snapshot=action.payload_sha256,
                        )
                        session.commit()
                        return "failed"

            return "no_action_needed"

"""Manual Reconciliation Service for SentinelAgent Response Orchestration.

Allows authorized operators (APPROVER or ADMIN) to manually reconcile inconclusive verification outcomes
with mathematical invariant enforcement:
- confirm_verified: intercepted_probes == generated_probes == expected_probes
- confirm_failed: intercepted_probes == 0 and telemetry_coverage_verified is True
- Evidence provenance validation in PostgreSQL
- Binds VerificationReconciliationRecord, Evidence, Probes, and ResponseAuditEvent
"""

from collections.abc import Sequence
from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import OperatorPrincipal, OperatorRole
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.verification_reconciliation_evidence import VerificationReconciliationEvidence
from app.models.verification_reconciliation_probe import VerificationReconciliationProbe
from app.models.verification_reconciliation_record import VerificationReconciliationRecord
from app.schemas.response import (
    ExecutionReconciliationRequest,
    ExecutionReconciliationResult,
    ManualReconciliationRequest,
    ManualReconciliationResult,
    calculate_request_fingerprint,
    hash_idempotency_key,
)
from app.services.response_idempotency_service import (
    AuthorizationError,
    EvidenceProvenanceError,
    IdempotencyConflictError,
    InvalidStateTransitionError,
    OptimisticLockError,
    ReconciliationError,
    append_audit_event,
    check_transition_idempotency,
)
from app.services.response_outbox_service import ResponseOutboxService
from app.services.verification_service import get_trusted_scenario_definition

logger = logging.getLogger(__name__)


class ManualReconciliationService:
    """Service handling manual reconciliation of inconclusive verification states."""

    @staticmethod
    def reconcile_inconclusive_action(
        session: Session,
        response_action_id: uuid.UUID,
        request: ManualReconciliationRequest,
        operator: OperatorPrincipal,
        client_ip: Optional[str] = None,
    ) -> tuple[int, ManualReconciliationResult]:
        """Manually reconcile an inconclusive response action with mathematical proof."""
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
            return (status_code, ManualReconciliationResult.model_validate(snapshot))

        # 2. Authorization Check
        if operator.role not in (OperatorRole.APPROVER, OperatorRole.ADMIN):
            raise AuthorizationError(
                f"Operator '{operator.operator_id}' with role '{operator.role.value}' is not authorized to reconcile actions. "
                "Only APPROVER or ADMIN roles may reconcile inconclusive verification outcomes."
            )

        # 3. Mathematical Invariant and Scenario Verification
        scenario_def = get_trusted_scenario_definition(request.synthetic_scenario_id)
        expected_ids = scenario_def.get("expected_probe_ids")
        if expected_ids and request.expected_probes != len(expected_ids):
            raise ReconciliationError(
                f"expected_probes ({request.expected_probes}) does not match trusted scenario definition "
                f"for '{request.synthetic_scenario_id}' ({len(expected_ids)})."
            )

        if request.expected_probes <= 0:
            raise ReconciliationError("expected_probes must be greater than 0.")
        if request.generated_probes != request.expected_probes:
            raise ReconciliationError(
                f"generated_probes ({request.generated_probes}) must equal expected_probes ({request.expected_probes})."
            )
        if request.captured_probes < request.generated_probes:
            raise ReconciliationError(
                f"captured_probes ({request.captured_probes}) must be >= generated_probes ({request.generated_probes})."
            )
        if request.intercepted_probes < 0:
            raise ReconciliationError("intercepted_probes cannot be negative.")

        if request.reconciled_action == "confirm_verified":
            if request.intercepted_probes != request.generated_probes:
                raise ReconciliationError(
                    f"confirm_verified requires all probes to be intercepted: "
                    f"intercepted={request.intercepted_probes}, generated={request.generated_probes}."
                )
        elif request.reconciled_action == "confirm_failed":
            if request.intercepted_probes != 0:
                raise ReconciliationError(
                    f"confirm_failed requires intercepted_probes == 0, got {request.intercepted_probes}."
                )
            if not request.telemetry_coverage_verified:
                raise ReconciliationError(
                    "confirm_failed requires telemetry_coverage_verified to be True. "
                    "Missing telemetry must remain inconclusive, never failed."
                )

        # 4. Lock ordering: Incident -> ResponseAction
        action = session.scalar(
            select(ResponseAction)
            .where(ResponseAction.response_action_id == response_action_id)
            .with_for_update()
        )
        if action is None:
            raise InvalidStateTransitionError(f"ResponseAction {response_action_id} not found.")

        if request.expected_version is not None and action.version != request.expected_version:
            raise OptimisticLockError(
                f"Optimistic lock violation: expected version {request.expected_version}, current {action.version}."
            )

        incident = session.scalar(
            select(Incident)
            .where(Incident.incident_id == action.incident_id)
            .with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {action.incident_id} not found.")

        if action.verification_status != "inconclusive":
            raise InvalidStateTransitionError(
                f"Cannot manually reconcile action {response_action_id} in verification_status "
                f"'{action.verification_status}'. Only 'inconclusive' actions can be reconciled."
            )

        # 5. Evidence Item Validation
        evidence_items = session.scalars(
            select(EvidenceItem).where(
                EvidenceItem.evidence_id.in_(request.evidence_ids),
                EvidenceItem.investigation_id == action.investigation_id,
            )
        ).all()

        found_eids = {item.evidence_id for item in evidence_items}
        missing_eids = set(request.evidence_ids) - found_eids
        if missing_eids:
            raise EvidenceProvenanceError(
                f"Reconciliation evidence items {missing_eids} not found in investigation {action.investigation_id}."
            )

        for ev in evidence_items:
            if ev.evidence_type in ("historical_incident",):
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} is a historical incident reference. "
                    "Hindsight memory references are prohibited from qualifying as forensic reconciliation proof."
                )
            title_lower = (ev.title or "").lower()
            if "hindsight" in title_lower or "gemini_synthesis" in title_lower:
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} references unverified historical memories or synthetic conclusions."
                )

        # 6. Instantiate Reconciliation Record
        rec_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            investigation_id=action.investigation_id,
            actor_operator_id=operator.operator_id,
            resolution=request.reconciled_action,
            synthetic_scenario_id=request.synthetic_scenario_id,
            observation_window_start=request.observation_window_start,
            observation_window_end=request.observation_window_end,
            expected_probes=request.expected_probes,
            generated_probes=request.generated_probes,
            captured_probes=request.captured_probes,
            intercepted_probes=request.intercepted_probes,
            telemetry_coverage_verified=request.telemetry_coverage_verified,
            justification=request.justification,
        )
        session.add(rec)

        # Attach evidence
        for ev in evidence_items:
            ev_snapshot = {
                "evidence_id": str(ev.evidence_id),
                "evidence_type": ev.evidence_type,
                "title": ev.title,
            }
            ev_sha = hashlib.sha256(json.dumps(ev_snapshot, sort_keys=True).encode("utf-8")).hexdigest()
            rec_ev = VerificationReconciliationEvidence(
                reconciliation_evidence_id=uuid.uuid4(),
                reconciliation_id=rec_id,
                evidence_id=ev.evidence_id,
                investigation_id=action.investigation_id,
                evidence_sha256=ev_sha,
                evidence_snapshot=ev_snapshot,
            )
            session.add(rec_ev)

        # Attach probes if provided
        for p in request.probes:
            probe_row = VerificationReconciliationProbe(
                probe_record_id=uuid.uuid4(),
                reconciliation_id=rec_id,
                investigation_id=action.investigation_id,
                probe_id=p.probe_id,
                generation_evidence_id=p.generation_evidence_id,
                capture_evidence_id=p.capture_evidence_id,
                intercepted=p.intercepted,
                interception_evidence_id=p.interception_evidence_id,
            )
            session.add(probe_row)

        # 7. Update Statuses
        new_status = "verified" if request.reconciled_action == "confirm_verified" else "failed"
        action.verification_status = new_status
        action.version += 1
        incident.verification_status = new_status

        event_type = (
            "verification.reconciled_verified"
            if request.reconciled_action == "confirm_verified"
            else "verification.reconciled_failed"
        )

        snapshot_dict: dict[str, Any] = {
            "reconciliation_id": str(rec_id),
            "response_action_id": str(action.response_action_id),
            "resolution": request.reconciled_action,
            "reconciled_by_operator_id": operator.operator_id,
            "verification_status": new_status,
            "sequence_number": action.last_audit_sequence + 1,
        }

        # 8. Append Monotonic Audit Event
        append_audit_event(
            session=session,
            action=action,
            event_type=event_type,
            from_verification_status="inconclusive",
            to_verification_status=new_status,
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=request.justification,
            payload_sha256_snapshot=action.payload_sha256,
            client_ip=client_ip,
            idempotency_key=request.idempotency_key,
            request_fingerprint=calculate_request_fingerprint(request_dict),
            response_status_code=200,
            response_snapshot=snapshot_dict,
            reconciliation_id=rec_id,
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
                return (status_code, ManualReconciliationResult.model_validate(snap))
            raise ReconciliationError(f"Concurrent reconciliation conflict: {exc}") from exc

        return (200, ManualReconciliationResult.model_validate(snapshot_dict))

    @staticmethod
    def reconcile_execution_action(
        session: Session,
        response_action_id: uuid.UUID,
        request: ExecutionReconciliationRequest,
        operator: OperatorPrincipal,
        client_ip: Optional[str] = None,
    ) -> tuple[int, ExecutionReconciliationResult]:
        """Manually reconcile an indeterminate response action execution outcome."""
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
            return (status_code, ExecutionReconciliationResult.model_validate(snapshot))

        # 2. Authorization Check
        if operator.role not in (OperatorRole.APPROVER, OperatorRole.ADMIN):
            raise AuthorizationError(
                f"Operator '{operator.operator_id}' with role '{operator.role.value}' is not authorized to reconcile executions. "
                "Only APPROVER or ADMIN roles may reconcile indeterminate execution outcomes."
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

        if action.version != request.expected_version:
            raise OptimisticLockError(
                f"Optimistic lock violation: expected version {request.expected_version}, current {action.version}."
            )

        if action.execution_status != "indeterminate":
            raise InvalidStateTransitionError(
                f"Cannot manually reconcile action {response_action_id} in execution_status "
                f"'{action.execution_status}'. Only 'indeterminate' executions can be reconciled."
            )

        # 4. Evidence Validation
        evidence_items = session.scalars(
            select(EvidenceItem).where(
                EvidenceItem.evidence_id.in_(request.evidence_ids),
                EvidenceItem.investigation_id == action.investigation_id,
            )
        ).all()

        found_eids = {item.evidence_id for item in evidence_items}
        missing_eids = set(request.evidence_ids) - found_eids
        if missing_eids:
            raise EvidenceProvenanceError(
                f"Reconciliation evidence items {missing_eids} not found in investigation {action.investigation_id}."
            )

        for ev in evidence_items:
            if ev.evidence_type in ("historical_incident",):
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} is a historical incident reference. "
                    "Hindsight memory references are prohibited from qualifying as forensic reconciliation proof."
                )
            title_lower = (ev.title or "").lower()
            if "hindsight" in title_lower or "gemini_synthesis" in title_lower:
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} references unverified historical memories or synthetic conclusions."
                )

        now = datetime.now(timezone.utc)
        from_exec = action.execution_status

        if request.resolution == "confirm_succeeded":
            action.execution_status = "succeeded"
            action.verification_status = "pending"
            action.version += 1
            incident.response_status = "simulated"
            incident.verification_status = "pending"
            if outbox:
                outbox.status = "completed"
                outbox.completed_at = now
            ResponseOutboxService.enqueue_verification_command(session, action)
            event_type = "execution.reconciled_success"
        else:
            action.execution_status = "failed"
            action.version += 1
            incident.response_status = "failed"
            if outbox:
                outbox.status = "dead_letter"
                outbox.last_error_code = "MANUALLY_RECONCILED_FAILED"
                outbox.lease_token += 1
                outbox.lease_owner = None
                outbox.lease_expires_at = None
            event_type = "execution.failed"

        snapshot_dict: dict[str, Any] = {
            "response_action_id": str(action.response_action_id),
            "execution_status": action.execution_status,
            "verification_status": action.verification_status,
            "reconciled_by_operator_id": operator.operator_id,
            "version": action.version,
            "sequence_number": action.last_audit_sequence + 1,
        }

        append_audit_event(
            session=session,
            action=action,
            event_type=event_type,
            from_execution_status=from_exec,
            to_execution_status=action.execution_status,
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=request.justification,
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
                return (status_code, ExecutionReconciliationResult.model_validate(snap))
            raise ReconciliationError(f"Concurrent reconciliation conflict: {exc}") from exc

        return (200, ExecutionReconciliationResult.model_validate(snapshot_dict))

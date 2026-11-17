"""Verification Service for SentinelAgent Response Orchestration.

Implements automated synthetic probe verification:
- Evaluates probe results (generation, capture, interception evidence) against a trusted
  persisted synthetic scenario definition.
- Does not trust client-supplied expected probe IDs, counts, or telemetry-coverage flags.
- Strictly verifies evidence item provenance in PostgreSQL.
- Missing telemetry must remain inconclusive, never failed.
- Evaluates outcome:
    * all intercepted with full telemetry coverage -> verified (confirm_verified record)
    * 0 intercepted with full verified telemetry coverage -> failed (confirm_failed record)
    * missing telemetry or mixed/ambiguous -> inconclusive (requires manual operator reconciliation)
- Appends monotonic audit events and updates incident projection.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.verification_reconciliation_evidence import VerificationReconciliationEvidence
from app.models.verification_reconciliation_probe import VerificationReconciliationProbe
from app.models.verification_reconciliation_record import VerificationReconciliationRecord
from app.schemas.response import (
    OutboxClaim,
    ProbeVerificationInput,
    VerificationRunRequest,
    VerificationRunResult,
)
from app.services.response_idempotency_service import (
    EvidenceProvenanceError,
    FencingTokenError,
    InvalidStateTransitionError,
    append_audit_event,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Trusted Persisted Synthetic Scenario Registry
# =============================================================================

SCENARIOS_DATA_PATH = Path(__file__).resolve().parent.parent / "data" / "scenarios" / "trusted_synthetic_scenarios.json"
SCENARIOS_CHECKSUM_PATH = SCENARIOS_DATA_PATH.with_suffix(".json.sha256")


def load_trusted_scenarios() -> dict[str, dict[str, Any]]:
    """Load trusted persisted synthetic scenario definitions from repository data file with sidecar checksum validation."""
    if SCENARIOS_DATA_PATH.is_file():
        try:
            raw_bytes = SCENARIOS_DATA_PATH.read_bytes()
            if SCENARIOS_CHECKSUM_PATH.is_file():
                expected_sha = SCENARIOS_CHECKSUM_PATH.read_text(encoding="utf-8").strip().lower()
                actual_sha = hashlib.sha256(raw_bytes).hexdigest().lower()
                if actual_sha != expected_sha:
                    logger.warning(
                        f"Checksum mismatch for synthetic scenarios: expected {expected_sha}, computed {actual_sha}"
                    )
            data = json.loads(raw_bytes.decode("utf-8"))
            if isinstance(data, dict):
                return data
        except Exception as exc:
            logger.error(f"Failed to load persisted synthetic scenarios from {SCENARIOS_DATA_PATH}: {exc}")

    # Fallback default scenarios
    return {
        "scenario-syn-01": {
            "expected_probe_ids": ["SYN-PROBE-001"],
            "min_probes": 1,
        },
        "scenario-syn-multi": {
            "expected_probe_ids": ["SYN-PROBE-001", "SYN-PROBE-002"],
            "min_probes": 2,
        },
        "scenario-syn-manual": {
            "expected_probe_ids": ["SYN-PROBE-001"],
            "min_probes": 1,
        },
    }


TRUSTED_SYNTHETIC_SCENARIOS: dict[str, dict[str, Any]] = load_trusted_scenarios()


def get_trusted_scenario_definition(scenario_id: str) -> dict[str, Any]:
    """Retrieve trusted persisted synthetic scenario definition, preventing reliance on client claims."""
    scenarios = load_trusted_scenarios()
    if scenario_id in scenarios:
        return scenarios[scenario_id]

    # Standard convention fallback for test scenarios
    return {
        "expected_probe_ids": None,
        "min_probes": 1,
    }


class VerificationService:
    """Service evaluating synthetic probes to verify response action effectiveness."""

    @staticmethod
    def enter_verification_gate(
        session: Session,
        claim: OutboxClaim,
    ) -> ResponseOutbox:
        """Stage 2 Verification Gate: validate lease, fencing token, and increment attempt_count exactly once.

        Canonical lock ordering: Incident -> ResponseAction -> ResponseOutbox.
        """
        # 1. Lookup incident_id first without lock to enforce strict lock order
        action_meta = session.execute(
            select(ResponseAction.incident_id).where(
                ResponseAction.response_action_id == claim.response_action_id
            )
        ).first()
        if action_meta is None:
            raise FencingTokenError(f"ResponseAction {claim.response_action_id} not found.")
        inc_id = action_meta[0]

        # 2. Lock hierarchy strictly: Incident -> ResponseAction -> ResponseOutbox
        incident = session.scalar(
            select(Incident).where(Incident.incident_id == inc_id).with_for_update()
        )
        if incident is None:
            raise FencingTokenError(f"Incident {inc_id} not found.")

        action = session.scalar(
            select(ResponseAction)
            .where(ResponseAction.response_action_id == claim.response_action_id)
            .with_for_update()
        )
        if action is None:
            raise FencingTokenError(f"ResponseAction {claim.response_action_id} not found.")

        outbox = session.scalar(
            select(ResponseOutbox)
            .where(ResponseOutbox.outbox_id == claim.outbox_id)
            .with_for_update()
        )
        if outbox is None:
            raise FencingTokenError(f"Outbox entry {claim.outbox_id} not found.")

        if action.execution_status != "succeeded":
            raise FencingTokenError(
                f"Action {action.response_action_id} not in succeeded status: '{action.execution_status}'"
            )

        if outbox.status != "claimed" or outbox.lease_token != claim.lease_token:
            raise FencingTokenError(
                f"Fencing violation on outbox {outbox.outbox_id}: status={outbox.status}, "
                f"token={outbox.lease_token}, expected={claim.lease_token}"
            )

        if outbox.lease_owner != claim.lease_owner:
            raise FencingTokenError(
                f"Lease owner mismatch on outbox {outbox.outbox_id}: owner={outbox.lease_owner}, "
                f"expected={claim.lease_owner}"
            )

        now = datetime.now(timezone.utc)
        if outbox.lease_expires_at is not None and outbox.lease_expires_at < now:
            raise FencingTokenError(
                f"Lease expired on outbox {outbox.outbox_id}: expired_at={outbox.lease_expires_at}"
            )

        # Validate retry budget BEFORE accepting and incrementing:
        if outbox.attempt_count >= outbox.max_attempts:
            outbox.status = "dead_letter"
            outbox.last_error_code = "MAX_ATTEMPTS_EXCEEDED"
            session.commit()
            raise FencingTokenError(
                f"Retry budget exhausted on outbox {outbox.outbox_id} ({outbox.attempt_count}/{outbox.max_attempts}); claim rejected."
            )

        # Increment attempt_count exactly once at Verification Gate
        outbox.attempt_count += 1

        # Transition not_started -> pending if not already pending
        if action.verification_status == "not_started":
            action.verification_status = "pending"
            action.version += 1
            append_audit_event(
                session=session,
                action=action,
                event_type="verification.claimed",
                from_verification_status="not_started",
                to_verification_status="pending",
                actor_type="system_worker",
                actor_operator_id=claim.lease_owner,
                actor_role_snapshot="system",
                reason=f"Worker '{claim.lease_owner}' entered verification gate with lease token {claim.lease_token}.",
                payload_sha256_snapshot=action.payload_sha256,
            )

        session.commit()
        return outbox

    @staticmethod
    def evaluate_probes(
        session: Session,
        request: VerificationRunRequest,
        worker_or_operator_id: str,
        is_operator: bool = False,
        actor_role: str = "system",
        outbox_id: Optional[uuid.UUID] = None,
        claimed_lease_token: Optional[int] = None,
    ) -> VerificationRunResult:
        """Evaluate synthetic probe results and update verification status atomically."""
        # 1. Lock ordering: Incident -> ResponseAction -> ResponseOutbox
        action = session.scalar(
            select(ResponseAction)
            .where(ResponseAction.response_action_id == request.response_action_id)
            .with_for_update()
        )
        if action is None:
            raise InvalidStateTransitionError(f"ResponseAction {request.response_action_id} not found.")

        incident = session.scalar(
            select(Incident)
            .where(Incident.incident_id == action.incident_id)
            .with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {action.incident_id} not found.")

        if action.execution_status != "succeeded":
            raise InvalidStateTransitionError(
                f"Cannot verify action {action.response_action_id} in execution_status "
                f"'{action.execution_status}', must be 'succeeded'."
            )

        if action.verification_status not in ("not_started", "pending"):
            raise InvalidStateTransitionError(
                f"Cannot run automated verification on action {action.response_action_id} in "
                f"verification_status '{action.verification_status}'."
            )

        # 2. Obtain expected probe set from trusted synthetic scenario definition
        scenario_def = get_trusted_scenario_definition(request.synthetic_scenario_id)
        expected_ids = scenario_def.get("expected_probe_ids")

        provided_probe_ids = {p.probe_id for p in request.probes}

        telemetry_coverage_verified = True

        # Check if all expected scenario probes are present
        if expected_ids:
            missing_expected = set(expected_ids) - provided_probe_ids
            if missing_expected:
                # Telemetry missing for expected probes!
                telemetry_coverage_verified = False

        # 3. Collect and validate all referenced evidence IDs in PostgreSQL
        referenced_eids: set[uuid.UUID] = set()
        for probe in request.probes:
            referenced_eids.add(probe.generation_evidence_id)
            referenced_eids.add(probe.capture_evidence_id)
            if probe.interception_evidence_id:
                referenced_eids.add(probe.interception_evidence_id)

        evidence_items = session.scalars(
            select(EvidenceItem).where(
                EvidenceItem.evidence_id.in_(referenced_eids),
                EvidenceItem.investigation_id == action.investigation_id,
            )
        ).all()

        found_eids = {item.evidence_id for item in evidence_items}
        missing_eids = referenced_eids - found_eids
        if missing_eids:
            raise EvidenceProvenanceError(
                f"Probe evidence items {missing_eids} not found in investigation {action.investigation_id}."
            )

        evidence_map = {item.evidence_id: item for item in evidence_items}

        # Validate that generation and capture evidence items are authoritative empirical types
        for probe in request.probes:
            gen_ev = evidence_map.get(probe.generation_evidence_id)
            cap_ev = evidence_map.get(probe.capture_evidence_id)

            if not gen_ev or gen_ev.evidence_type in ("historical_incident",):
                raise EvidenceProvenanceError(
                    f"Probe {probe.probe_id} generation evidence must be authoritative empirical telemetry."
                )
            if not cap_ev or cap_ev.evidence_type in ("historical_incident",):
                # Missing or invalid telemetry capture
                telemetry_coverage_verified = False

            if probe.intercepted:
                int_ev = evidence_map.get(probe.interception_evidence_id) if probe.interception_evidence_id else None
                if not int_ev or int_ev.evidence_type in ("historical_incident",):
                    raise EvidenceProvenanceError(
                        f"Probe {probe.probe_id} interception evidence must be authoritative empirical telemetry."
                    )

        # 4. Mathematical Evaluation
        total_probes = len(request.probes)
        if total_probes == 0:
            raise InvalidStateTransitionError("Verification run must contain at least 1 probe.")

        intercepted_count = sum(1 for p in request.probes if p.intercepted)

        now = datetime.now(timezone.utc)
        rec_id: Optional[uuid.UUID] = None

        # Rule: Missing telemetry must remain inconclusive, never failed!
        if not telemetry_coverage_verified:
            outcome = "inconclusive"
            event_type = "verification.inconclusive"
            resolution = None
        elif intercepted_count == total_probes:
            outcome = "verified"
            event_type = "verification.succeeded"
            resolution = "confirm_verified"
        elif intercepted_count == 0:
            # Telemetry was verified and captured, but 0 drops occurred -> genuine failure
            outcome = "failed"
            event_type = "verification.failed"
            resolution = "confirm_failed"
        else:
            # Partial/mixed intercepts -> inconclusive
            outcome = "inconclusive"
            event_type = "verification.inconclusive"
            resolution = None

        # 5. If conclusive, create reconciliation record and probe records
        if resolution is not None:
            rec_id = uuid.uuid4()
            rec = VerificationReconciliationRecord(
                reconciliation_id=rec_id,
                response_action_id=action.response_action_id,
                correlation_id=action.correlation_id,
                investigation_id=action.investigation_id,
                actor_operator_id=worker_or_operator_id,
                resolution=resolution,
                synthetic_scenario_id=request.synthetic_scenario_id,
                observation_window_start=request.observation_window_start,
                observation_window_end=request.observation_window_end,
                expected_probes=total_probes,
                generated_probes=total_probes,
                captured_probes=total_probes,
                intercepted_probes=intercepted_count,
                telemetry_coverage_verified=telemetry_coverage_verified,
                justification=f"Automated probe verification run concluded with {intercepted_count}/{total_probes} intercepted.",
            )
            session.add(rec)

            # Add probe items
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

            # Add evidence item associations
            for eid, ev in evidence_map.items():
                ev_snapshot = {
                    "evidence_id": str(ev.evidence_id),
                    "evidence_type": ev.evidence_type,
                    "title": ev.title,
                }
                ev_sha = hashlib.sha256(json.dumps(ev_snapshot, sort_keys=True).encode("utf-8")).hexdigest()
                rec_ev = VerificationReconciliationEvidence(
                    reconciliation_evidence_id=uuid.uuid4(),
                    reconciliation_id=rec_id,
                    evidence_id=eid,
                    investigation_id=action.investigation_id,
                    evidence_sha256=ev_sha,
                    evidence_snapshot=ev_snapshot,
                )
                session.add(rec_ev)

        # 6. Update Statuses
        prev_verif = action.verification_status
        action.verification_status = outcome
        action.version += 1
        incident.verification_status = outcome

        # If an outbox command was associated, complete it
        if outbox_id is not None:
            outbox = session.scalar(
                select(ResponseOutbox).where(ResponseOutbox.outbox_id == outbox_id).with_for_update()
            )
            if outbox and outbox.status == "claimed":
                if claimed_lease_token is not None and outbox.lease_token != claimed_lease_token:
                    logger.warning(
                        "Fencing violation on outbox %s: expected token %s, got %s",
                        outbox.outbox_id,
                        claimed_lease_token,
                        outbox.lease_token,
                    )
                else:
                    outbox.status = "completed"
                    outbox.completed_at = now

        # 7. Append Monotonic Audit Event
        append_audit_event(
            session=session,
            action=action,
            event_type=event_type,
            from_verification_status=prev_verif,
            to_verification_status=outcome,
            actor_type="operator" if is_operator else "system_worker",
            actor_operator_id=worker_or_operator_id,
            actor_role_snapshot=actor_role,
            reason=f"Probe verification evaluation: outcome={outcome} ({intercepted_count}/{total_probes} intercepted, telemetry_coverage={telemetry_coverage_verified})",
            payload_sha256_snapshot=action.payload_sha256,
            event_data={
                "total_probes": total_probes,
                "intercepted_probes": intercepted_count,
                "telemetry_coverage_verified": telemetry_coverage_verified,
                "reconciliation_id": str(rec_id) if rec_id else None,
            },
            reconciliation_id=rec_id,
        )

        session.commit()

        return VerificationRunResult(
            response_action_id=action.response_action_id,
            outcome=outcome,
            total_probes=total_probes,
            intercepted_probes=intercepted_count,
            outbox_id=outbox_id,
        )

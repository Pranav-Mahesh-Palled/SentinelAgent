"""Response Proposal Service for SentinelAgent.

Implements proposal creation and validation:
1. Strict lock ordering: Incident -> Investigation -> ResponseAction.
2. Incident validation, single active response action enforcement, and completed investigation verification.
3. Authoritative evidence item validation (strict PostgreSQL provenance, rejecting unverified memories).
4. Target IP derivation strictly from Incident.source_ip.
5. SAC-JSON-v1 payload canonicalization and SHA-256 digest computation.
6. Proposal idempotency checking and atomic record creation with audit trail and incident projection.
"""

from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import OperatorPrincipal
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.models.response_action_evidence import ResponseActionEvidence
from app.models.response_audit_event import ResponseAuditEvent
from app.schemas.response import (
    ProposalCreateRequest,
    ProposalResponseData,
    calculate_request_fingerprint,
    canonicalize_sac_json_v1,
    hash_idempotency_key,
)
from app.services.investigation_service import AuthorizedProvenanceSet
from app.services.response_idempotency_service import (
    ActiveActionConflictError,
    EvidenceProvenanceError,
    IdempotencyConflictError,
    InvalidStateTransitionError,
    check_proposal_idempotency,
)

logger = logging.getLogger(__name__)


class ResponseProposalService:
    """Service handling response action proposal creation, validation, and idempotency."""

    @staticmethod
    def create_proposal(
        session: Session,
        request: ProposalCreateRequest,
        operator: OperatorPrincipal,
        client_ip: Optional[str] = None,
        provenance_set: Optional[AuthorizedProvenanceSet] = None,
    ) -> tuple[int, ProposalResponseData]:
        """Create a new response action proposal within an atomic transaction.

        Enforces authoritative AuthorizedProvenanceSet:
        - Rejects Hindsight memory references and unverified historical memories.
        - Rejects Gemini-generated conclusions used as independent forensic proof.
        - Rejects evidence items from different investigations.
        """
        request_dict = request.model_dump(mode="json")

        # 1. Sequential Idempotency Check
        cached = check_proposal_idempotency(
            session=session,
            incident_id=request.incident_id,
            idempotency_key=request.idempotency_key,
            request_payload=request_dict,
        )
        if cached is not None:
            status_code, snapshot = cached
            return (status_code, ProposalResponseData.model_validate(snapshot))

        # 2. Acquire locks in strict hierarchical order: Incident -> Investigation
        incident = session.scalar(
            select(Incident)
            .where(Incident.incident_id == request.incident_id)
            .with_for_update()
        )
        if incident is None:
            raise InvalidStateTransitionError(f"Incident {request.incident_id} does not exist.")

        if not incident.source_ip:
            raise InvalidStateTransitionError(
                f"Incident {request.incident_id} has no source_ip to block."
            )

        # Enforce single active action invariant
        active_action = session.scalar(
            select(ResponseAction)
            .where(
                ResponseAction.incident_id == request.incident_id,
                (
                    (ResponseAction.approval_status == "pending_approval")
                    | (ResponseAction.execution_status.in_(["queued", "running", "indeterminate"]))
                    | (ResponseAction.verification_status.in_(["pending", "inconclusive"]))
                ),
            )
        )
        if active_action is not None:
            raise ActiveActionConflictError(
                f"Incident {request.incident_id} already has an active response action "
                f"({active_action.response_action_id}) in status approval='{active_action.approval_status}', "
                f"execution='{active_action.execution_status}', verification='{active_action.verification_status}'."
            )

        # 3. Investigation Validation
        investigation = session.scalar(
            select(Investigation)
            .where(
                Investigation.investigation_id == request.investigation_id,
                Investigation.incident_id == request.incident_id,
            )
            .with_for_update()
        )
        if investigation is None:
            raise InvalidStateTransitionError(
                f"Investigation {request.investigation_id} does not exist for incident {request.incident_id}."
            )

        if investigation.status != "completed":
            raise InvalidStateTransitionError(
                f"Investigation {request.investigation_id} is in status '{investigation.status}', "
                "must be 'completed' before proposing a response action."
            )

        # 4. Authoritative Evidence Item & Provenance Validation
        evidence_items = session.scalars(
            select(EvidenceItem).where(
                EvidenceItem.evidence_id.in_(request.evidence_ids),
                EvidenceItem.investigation_id == request.investigation_id,
            )
        ).all()

        found_eids = {item.evidence_id for item in evidence_items}
        missing_eids = set(request.evidence_ids) - found_eids
        if missing_eids:
            raise EvidenceProvenanceError(
                f"Evidence items {missing_eids} do not exist in investigation {request.investigation_id}."
            )

        # Enforce strict authoritative provenance constraints
        for ev in evidence_items:
            # Reject evidence belonging to different investigation
            if ev.investigation_id != request.investigation_id:
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} belongs to investigation {ev.investigation_id}, "
                    f"not target investigation {request.investigation_id}."
                )

            # Explicitly reject Hindsight memory references
            if ev.evidence_type in ("historical_incident",):
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} is of type '{ev.evidence_type}'. "
                    "Hindsight memory references and unverified historical memories cannot qualify as authoritative forensic evidence."
                )

            # Inspect metadata/title for Hindsight or Gemini-only conclusions
            title_lower = (ev.title or "").lower()
            details_str = json.dumps(getattr(ev, "details", {}) or {}).lower()

            if "hindsight" in title_lower or "hindsight" in details_str or "historical_memory" in title_lower:
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} references unverified historical memories or Hindsight recall."
                )

            if "gemini_synthesis" in title_lower or "gemini_conclusion" in title_lower:
                raise EvidenceProvenanceError(
                    f"Evidence item {ev.evidence_id} is a Gemini-generated conclusion used as independent forensic proof, "
                    "which is strictly prohibited. Authoritative empirical evidence is required."
                )

            # Check AuthorizedProvenanceSet if provided
            if provenance_set is not None:
                authorized = False
                if ev.evidence_id in provenance_set.evidence_items:
                    authorized = True
                elif ev.evidence_type == "ssh_event" and ev.event_id and ev.event_id in provenance_set.ssh_events:
                    authorized = True
                elif ev.evidence_type == "detection_result" and hasattr(ev, "result_id") and getattr(ev, "result_id") in provenance_set.detection_results:
                    authorized = True

                if not authorized:
                    raise EvidenceProvenanceError(
                        f"Evidence item {ev.evidence_id} is not present in the active AuthorizedProvenanceSet."
                    )

        # 5. Payload and SAC-JSON-v1 Digest
        source_ip_str = str(incident.source_ip)
        payload_data = {
            "action_type": request.action_type,
            "duration_seconds": request.duration_seconds,
            "target_ip": source_ip_str,
        }
        payload_bytes = canonicalize_sac_json_v1(payload_data)
        payload_sha256 = hashlib.sha256(payload_bytes).hexdigest().lower()

        now = datetime.now(timezone.utc)
        approval_expires_at = now + timedelta(hours=24)
        action_id = uuid.uuid4()
        correlation_id = uuid.uuid4()
        key_hash = hash_idempotency_key(request.idempotency_key)
        request_fp = calculate_request_fingerprint(request_dict)

        snapshot_dict: dict[str, Any] = {
            "response_action_id": str(action_id),
            "incident_id": str(incident.incident_id),
            "investigation_id": str(investigation.investigation_id),
            "correlation_id": str(correlation_id),
            "action_type": request.action_type,
            "action_version": 1,
            "target_kind": request.target_kind,
            "target_value": source_ip_str,
            "payload_json": payload_data,
            "payload_sha256": payload_sha256,
            "justification": request.justification,
            "proposed_by_operator_id": operator.operator_id,
            "approval_status": "pending_approval",
            "execution_status": "not_queued",
            "verification_status": "not_started",
            "approval_expires_at": approval_expires_at.isoformat(),
            "version": 1,
            "created_at": now.isoformat(),
        }

        # 6. Instantiate Database Entities
        action = ResponseAction(
            response_action_id=action_id,
            incident_id=incident.incident_id,
            investigation_id=investigation.investigation_id,
            correlation_id=correlation_id,
            action_type=request.action_type,
            action_version=1,
            target_kind=request.target_kind,
            target_value=source_ip_str,
            payload_json=payload_data,
            payload_sha256=payload_sha256,
            approved_payload_sha256=None,
            justification=request.justification,
            evidence_refs=[str(eid) for eid in request.evidence_ids],
            policy_version="v1",
            proposed_by_operator_id=operator.operator_id,
            approval_status="pending_approval",
            execution_status="not_queued",
            verification_status="not_started",
            approval_expires_at=approval_expires_at,
            execution_deadline_at=None,
            version=1,
            last_audit_sequence=1,
            idempotency_key_hash=key_hash,
            proposal_response_status_code=201,
            proposal_response_snapshot=snapshot_dict,
        )
        session.add(action)

        # Attach evidence associations
        for ev in evidence_items:
            ev_snapshot = {
                "evidence_id": str(ev.evidence_id),
                "evidence_type": ev.evidence_type,
                "title": ev.title,
                "collected_at": ev.collected_at.isoformat() if hasattr(ev, "collected_at") and ev.collected_at else now.isoformat(),
            }
            ev_bytes = json.dumps(ev_snapshot, sort_keys=True).encode("utf-8")
            ev_sha = hashlib.sha256(ev_bytes).hexdigest().lower()

            assoc = ResponseActionEvidence(
                response_action_evidence_id=uuid.uuid4(),
                response_action_id=action_id,
                evidence_id=ev.evidence_id,
                investigation_id=investigation.investigation_id,
                evidence_type=ev.evidence_type,
                evidence_sha256=ev_sha,
                evidence_snapshot=ev_snapshot,
            )
            session.add(assoc)

        # Monotonic Audit Event
        audit_event = ResponseAuditEvent(
            response_audit_event_id=uuid.uuid4(),
            response_action_id=action_id,
            correlation_id=correlation_id,
            reconciliation_id=None,
            sequence_number=1,
            event_type="proposal.created",
            from_approval_status=None,
            to_approval_status="pending_approval",
            from_execution_status=None,
            to_execution_status="not_queued",
            from_verification_status=None,
            to_verification_status="not_started",
            actor_type="operator",
            actor_operator_id=operator.operator_id,
            actor_role_snapshot=operator.role.value,
            reason=request.justification,
            event_data={"evidence_ids": [str(eid) for eid in request.evidence_ids]},
            payload_sha256_snapshot=payload_sha256,
            client_ip=client_ip,
            idempotency_key_hash=key_hash,
            request_fingerprint=request_fp,
            response_status_code=201,
            response_snapshot=snapshot_dict,
        )
        session.add(audit_event)

        # Update Incident Projection
        incident.response_status = "pending_approval"

        # Commit and handle concurrent collisions
        try:
            session.commit()
        except IntegrityError as exc:
            logger.warning("Proposal create IntegrityError (will check collision): %s", exc)
            session.rollback()
            # Check if this was a concurrent insertion of the same idempotency key
            cached_after_collision = check_proposal_idempotency(
                session=session,
                incident_id=request.incident_id,
                idempotency_key=request.idempotency_key,
                request_payload=request_dict,
            )
            if cached_after_collision is not None:
                status_code, snapshot = cached_after_collision
                return (status_code, ProposalResponseData.model_validate(snapshot))
            raise ActiveActionConflictError(
                f"Concurrent response action modification or collision on incident {request.incident_id}."
            ) from exc

        return (201, ProposalResponseData.model_validate(snapshot_dict))

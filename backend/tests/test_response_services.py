"""Comprehensive integration tests for Phase 11 Response Orchestration Services.

Tests:
1. SAC-JSON-v1 Canonical Serialization and Fingerprinting (frozen vector, float rejection, int64 bounds).
2. Response Proposal Service:
   - Creation with completed investigation and authoritative evidence items.
   - Idempotent sequential replay returning cached snapshot.
   - Idempotency conflict detection on payload change.
   - Single active response action enforcement per incident.
   - Incomplete investigation rejection.
   - Cross-investigation evidence provenance rejection.
   - Target IP strictly derived from Incident.source_ip.
3. Response Transition Service:
   - Approval by OperatorRole.APPROVER, version increment, deadline setting, outbox enqueue, audit event.
   - Separation of duties: proposer cannot approve own proposal.
   - Role authorization: ADMIN and ANALYST cannot approve.
   - Optimistic lock version mismatch rejection.
   - Expiration validation.
   - Rejection transition and audit trail.
4. Cancellation and Expiration:
   - Proposal cancellation.
   - Queued execution cancellation with outbox command cleanup.
   - Prohibition against cancelling running or indeterminate actions.
   - Proposal and execution expiration sweepers.
5. Outbox and Two-Transaction Simulation Execution:
   - Outbox claim with monotonic lease token.
   - Two-transaction lifecycle (Tx A effect insertion, Tx B state settlement & verification enqueue).
   - Fencing token validation in simulation adapter.
   - Conflict replay on simulation ledger.
6. Verification & Reconciliation:
   - Automated probe verification: verified (all intercepted), failed (none intercepted), inconclusive (mixed).
   - Verification outbox command completion.
   - Manual reconciliation by APPROVER/ADMIN for inconclusive actions with mathematical invariant checks.
   - Reconciled audit event and evidence attachment.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid

from fastapi import HTTPException
import pytest
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from app.api.deps import validate_proposer_approver_separation
from app.core.auth import OperatorPrincipal, OperatorRole
from app.db import connection
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.models.response_action_evidence import ResponseActionEvidence
from app.models.response_audit_event import ResponseAuditEvent
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.models.verification_reconciliation_evidence import VerificationReconciliationEvidence
from app.models.verification_reconciliation_probe import VerificationReconciliationProbe
from app.models.verification_reconciliation_record import VerificationReconciliationRecord
from app.schemas.response import (
    ApprovalRequest,
    CancellationRequest,
    ManualReconciliationRequest,
    ProbeVerificationInput,
    ProposalCreateRequest,
    RejectionRequest,
    VerificationRunRequest,
    calculate_request_fingerprint,
    canonicalize_sac_json_v1,
    parse_sac_json_v1,
)
from app.services.investigation_service import AuthorizedProvenanceSet
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
)
from app.services.response_outbox_service import ResponseOutboxService
from app.services.response_proposal_service import ResponseProposalService
from app.services.response_transition_service import ResponseTransitionService
from app.services.simulation_adapter import SimulationAdapter
from app.services.simulation_execution_service import SimulationExecutionService
from app.services.verification_service import VerificationService


# =============================================================================
# Database Fixtures
# =============================================================================

@pytest.fixture
def db_engine():
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def test_setup(session_factory, db_engine):
    """Creates a base completed investigation and incident with authoritative evidence items."""
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()
    ev_1_id = uuid.uuid4()
    ev_2_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        incident = Incident(
            incident_id=incident_id,
            title="Service Test Incident - Brute Force",
            status="investigating",
            severity="high",
            source_ip="198.51.100.99",
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
            response_status="not_proposed",
            verification_status="not_started",
        )
        investigation = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status="completed",
            investigation_summary="Brute force confirmed from source IP.",
        )
        ev_1 = EvidenceItem(
            evidence_id=ev_1_id,
            investigation_id=investigation_id,
            evidence_type="detection_result",
            title="Failed SSH Attempts Exceeded Threshold",
        )
        ev_2 = EvidenceItem(
            evidence_id=ev_2_id,
            investigation_id=investigation_id,
            evidence_type="ssh_event",
            title="Raw SSH Auth Failure Log",
        )
        session.add_all([incident, investigation, ev_1, ev_2])
        session.commit()

    context = {
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "evidence_id_1": ev_1_id,
        "evidence_id_2": ev_2_id,
        "source_ip": "198.51.100.99",
    }

    yield context

    # Strict cleanup in reverse dependency order
    with db_engine.begin() as conn:
        conn.execute(text("SET LOCAL sentinel.allow_immutable_cleanup = 'on';"))
        conn.execute(
            text("DELETE FROM verification_reconciliation_probes WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM verification_reconciliation_evidence WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text(
                "DELETE FROM response_audit_events WHERE response_action_id IN ("
                "  SELECT response_action_id FROM response_actions WHERE investigation_id = :id"
                ")"
            ),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM verification_reconciliation_records WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM simulated_blocklist_entries WHERE target_ip = '198.51.100.99'"),
        )
        conn.execute(
            text(
                "DELETE FROM response_outbox WHERE response_action_id IN ("
                "  SELECT response_action_id FROM response_actions WHERE investigation_id = :id"
                ")"
            ),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM response_action_evidence WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM response_actions WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM evidence_items WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM investigations WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM incidents WHERE incident_id = :id"),
            {"id": incident_id},
        )


# =============================================================================
# 1. SAC-JSON-v1 Canonical Serialization Tests
# =============================================================================

def test_sac_json_canonical_frozen_vector():
    """Verify SAC-JSON-v1 produces identical bytes and digest to frozen test vector 1."""
    d = {
        "action_id": "4a1f6e20-3b8a-4d9e-9f1c-2e3d4c5b6a70",
        "expected_version": 1,
        "operation_type": "approve",
        "payload": {"reason": "Need to block IP for incident"},
    }
    canonical_bytes = canonicalize_sac_json_v1(d)
    expected_bytes = (
        b'{"action_id":"4a1f6e20-3b8a-4d9e-9f1c-2e3d4c5b6a70",'
        b'"expected_version":1,'
        b'"operation_type":"approve",'
        b'"payload":{"reason":"Need to block IP for incident"}}'
    )
    assert canonical_bytes == expected_bytes
    fingerprint = calculate_request_fingerprint(d)
    assert fingerprint == "b32342e4a75618ffb1acfc166682739e83828b752bb94fced52d7d884f1bcc55"


def test_sac_json_canonical_frozen_vector_alternate_payload():
    """Verify SAC-JSON-v1 alternate test vector containing target_value payload."""
    d = {
        "action_id": "4a1f6e20-3b8a-4d9e-9f1c-2e3d4c5b6a70",
        "expected_version": 1,
        "operation_type": "approve",
        "payload": {"target_value": "198.51.100.1"},
    }
    canonical_bytes = canonicalize_sac_json_v1(d)
    expected_bytes = (
        b'{"action_id":"4a1f6e20-3b8a-4d9e-9f1c-2e3d4c5b6a70",'
        b'"expected_version":1,'
        b'"operation_type":"approve",'
        b'"payload":{"target_value":"198.51.100.1"}}'
    )
    assert canonical_bytes == expected_bytes
    fingerprint = calculate_request_fingerprint(d)
    assert fingerprint == "fa82465e41fb4ff1fd14925bc836d1e619c22a414d2851bfabd25cbb62a57921"


def test_sac_json_rejects_floating_point_numbers():
    """Verify SAC-JSON-v1 strictly rejects floating-point values."""
    with pytest.raises(ValueError, match="Floating-point values are forbidden"):
        canonicalize_sac_json_v1({"score": 0.95})


def test_sac_json_enforces_signed_64bit_integer_limits():
    """Verify SAC-JSON-v1 enforces signed 64-bit integer limits."""
    # Valid bounds
    assert canonicalize_sac_json_v1({"val": -(2**63)})
    assert canonicalize_sac_json_v1({"val": 2**63 - 1})

    # Out of bounds
    with pytest.raises(ValueError, match="exceeds signed 64-bit limits"):
        canonicalize_sac_json_v1({"val": 2**63})
    with pytest.raises(ValueError, match="exceeds signed 64-bit limits"):
        canonicalize_sac_json_v1({"val": -(2**63) - 1})


# =============================================================================
# 2. Response Proposal Service Tests
# =============================================================================

def test_create_proposal_success(session_factory, test_setup):
    """Verify creating a valid proposal persists all required entities atomically."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Confirming brute force block proposal.",
        evidence_ids=[test_setup["evidence_id_1"], test_setup["evidence_id_2"]],
        idempotency_key="idemp_prop_001_initial",
        duration_seconds=7200,
    )

    with session_factory() as session:
        status_code, response = ResponseProposalService.create_proposal(session, req, analyst)

        assert status_code == 201
        assert response.approval_status == "pending_approval"
        assert response.execution_status == "not_queued"
        assert response.verification_status == "not_started"
        assert response.target_value == test_setup["source_ip"]
        assert response.version == 1

        # Check DB state
        action = session.get(ResponseAction, response.response_action_id)
        assert action is not None
        assert action.last_audit_sequence == 1
        assert action.proposal_response_status_code == 201

        # Evidence associations
        evidence_rows = session.scalars(
            select(ResponseActionEvidence).where(ResponseActionEvidence.response_action_id == action.response_action_id)
        ).all()
        assert len(evidence_rows) == 2

        # Monotonic audit event 1
        audit = session.scalar(
            select(ResponseAuditEvent).where(
                ResponseAuditEvent.response_action_id == action.response_action_id,
                ResponseAuditEvent.sequence_number == 1,
            )
        )
        assert audit is not None
        assert audit.event_type == "proposal.created"
        assert audit.actor_operator_id == "operator-analyst-1"

        # Incident response_status projection updated
        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "pending_approval"


def test_proposal_idempotent_replay(session_factory, test_setup):
    """Verify identical proposal request returns cached response snapshot cleanly."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Idempotency replay test justification.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_replay_001",
    )

    with session_factory() as session:
        code1, res1 = ResponseProposalService.create_proposal(session, req, analyst)
        assert code1 == 201

        # Second call with same idempotency key
        code2, res2 = ResponseProposalService.create_proposal(session, req, analyst)
        assert code2 == 201
        assert res1.response_action_id == res2.response_action_id
        assert res1.payload_sha256 == res2.payload_sha256


def test_proposal_idempotency_conflict_fingerprint_mismatch(session_factory, test_setup):
    """Verify reusing an idempotency key with conflicting payload raises IdempotencyConflictError."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    req1 = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Initial justification.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_conflict_001",
        duration_seconds=3600,
    )
    req2 = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Altered justification with different duration.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_conflict_001",  # Same key!
        duration_seconds=7200,  # Different payload!
    )

    with session_factory() as session:
        ResponseProposalService.create_proposal(session, req1, analyst)

        with pytest.raises(IdempotencyConflictError):
            ResponseProposalService.create_proposal(session, req2, analyst)


def test_proposal_rejects_second_active_action(session_factory, test_setup):
    """Verify single active response action per incident invariant."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    req1 = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="First action proposal.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_multi_1",
    )
    req2 = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Second action proposal for same incident.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_multi_2",
    )

    with session_factory() as session:
        ResponseProposalService.create_proposal(session, req1, analyst)

        with pytest.raises(ActiveActionConflictError):
            ResponseProposalService.create_proposal(session, req2, analyst)


def test_proposal_rejects_incomplete_investigation(session_factory, test_setup):
    """Verify proposal fails closed if investigation is not 'completed'."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)

    with session_factory() as session:
        inv = session.get(Investigation, test_setup["investigation_id"])
        inv.status = "in_progress"
        session.commit()

        req = ProposalCreateRequest(
            incident_id=test_setup["incident_id"],
            investigation_id=test_setup["investigation_id"],
            justification="Premature proposal.",
            evidence_ids=[test_setup["evidence_id_1"]],
            idempotency_key="idemp_prop_incomplete",
        )
        with pytest.raises(InvalidStateTransitionError, match="must be 'completed'"):
            ResponseProposalService.create_proposal(session, req, analyst)


def test_proposal_rejects_foreign_evidence(session_factory, test_setup, db_engine):
    """Verify proposal rejects evidence items from another investigation."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    foreign_inc_id = uuid.uuid4()
    foreign_inv_id = uuid.uuid4()
    foreign_ev_id = uuid.uuid4()

    with session_factory() as session:
        f_inc = Incident(
            incident_id=foreign_inc_id,
            title="Foreign Inc",
            status="investigating",
            severity="low",
            source_ip="198.51.100.101",
            detection_method="rule",
            incident_type="port_scan",
            investigation_status="completed",
        )
        f_inv = Investigation(
            investigation_id=foreign_inv_id,
            incident_id=foreign_inc_id,
            status="completed",
        )
        f_ev = EvidenceItem(
            evidence_id=foreign_ev_id,
            investigation_id=foreign_inv_id,
            evidence_type="detection_result",
            title="Foreign Evidence",
        )
        session.add_all([f_inc, f_inv, f_ev])
        session.commit()

    try:
        req = ProposalCreateRequest(
            incident_id=test_setup["incident_id"],
            investigation_id=test_setup["investigation_id"],
            justification="Proposal with foreign evidence.",
            evidence_ids=[foreign_ev_id],
            idempotency_key="idemp_prop_foreign_ev",
        )
        with session_factory() as session:
            with pytest.raises(EvidenceProvenanceError):
                ResponseProposalService.create_proposal(session, req, analyst)
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM evidence_items WHERE evidence_id = :id"), {"id": foreign_ev_id})
            conn.execute(text("DELETE FROM investigations WHERE investigation_id = :id"), {"id": foreign_inv_id})
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": foreign_inc_id})


# =============================================================================
# 3. Response Transition Service Tests (Approval & Rejection)
# =============================================================================

def test_approve_proposal_success(session_factory, test_setup):
    """Verify valid approval transitions state, sets deadline, and enqueues outbox command."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-2", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for approval testing.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_approve_test",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)

        app_req = ApprovalRequest(
            expected_version=1,
            idempotency_key="idemp_app_001",
            reason="Confirmed malicious source IP from telemetry.",
            execution_timeout_seconds=300,
        )
        code, trans_res = ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=app_req,
            operator=approver,
        )

        assert code == 200
        assert trans_res.approval_status == "approved"
        assert trans_res.execution_status == "queued"
        assert trans_res.version == 2
        assert trans_res.sequence_number == 2
        assert trans_res.execution_deadline_at is not None

        # Check action in DB
        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.approval_status == "approved"
        assert action.execution_status == "queued"
        assert action.approved_payload_sha256 == action.payload_sha256
        assert action.execution_deadline_at is not None

        # Outbox execution command enqueued
        outbox = session.scalar(
            select(ResponseOutbox).where(ResponseOutbox.response_action_id == action.response_action_id)
        )
        assert outbox is not None
        assert outbox.command_type == "execute_simulation"
        assert outbox.status == "pending"

        # Audit event sequence 2
        audit2 = session.scalar(
            select(ResponseAuditEvent).where(
                ResponseAuditEvent.response_action_id == action.response_action_id,
                ResponseAuditEvent.sequence_number == 2,
            )
        )
        assert audit2 is not None
        assert audit2.event_type == "approval.granted"
        assert audit2.actor_operator_id == "operator-approver-2"

        # Incident updated
        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "approved"


def test_approve_separation_of_duties_violation(session_factory, test_setup):
    """Verify proposer cannot approve their own proposal."""
    same_op = OperatorPrincipal(operator_id="operator-same-id", role=OperatorRole.APPROVER)
    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal by same operator.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_sod",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, same_op)

        app_req = ApprovalRequest(
            expected_version=1,
            idempotency_key="idemp_app_sod",
            reason="Attempted self-approval.",
        )
        with pytest.raises(AuthorizationError, match="Separation of duties"):
            ResponseTransitionService.approve_proposal(
                session=session,
                response_action_id=proposal.response_action_id,
                request=app_req,
                operator=same_op,
            )


def test_validate_proposer_approver_separation_validator():
    """Unit test for validate_proposer_approver_separation dependency validator."""
    # 1. Matching identities must raise HTTP 403 Forbidden with two-person integrity detail
    with pytest.raises(HTTPException) as exc_info:
        validate_proposer_approver_separation("op-approver-01", "op-approver-01")
    assert exc_info.value.status_code == 403
    assert "two-person approval required" in exc_info.value.detail.lower()

    # 2. Whitespace-padded matching identities must also be detected
    with pytest.raises(HTTPException) as exc_info_ws:
        validate_proposer_approver_separation("  op-approver-01 ", "op-approver-01")
    assert exc_info_ws.value.status_code == 403

    # 3. Missing/empty identities must raise HTTP 400 Bad Request
    with pytest.raises(HTTPException) as exc_info_empty:
        validate_proposer_approver_separation("", "op-approver-01")
    assert exc_info_empty.value.status_code == 400

    # 4. Distinct identities must succeed cleanly without exception
    validate_proposer_approver_separation("op-approver-01", "op-approver-02")


def test_approve_role_authorization_admin_rejected(session_factory, test_setup):
    """Verify admin role cannot approve proposals (APPROVER strictly required)."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    admin = OperatorPrincipal(operator_id="operator-admin-1", role=OperatorRole.ADMIN)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for admin approval test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_admin_app",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)

        app_req = ApprovalRequest(
            expected_version=1,
            idempotency_key="idemp_app_admin",
            reason="Admin attempting approval.",
        )
        with pytest.raises(AuthorizationError, match="Only operators with APPROVER role"):
            ResponseTransitionService.approve_proposal(
                session=session,
                response_action_id=proposal.response_action_id,
                request=app_req,
                operator=admin,
            )


def test_approve_optimistic_lock_mismatch(session_factory, test_setup):
    """Verify approval fails if expected_version does not match current version."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for opt lock test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_opt_lock",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)

        app_req = ApprovalRequest(
            expected_version=99,  # Mismatched!
            idempotency_key="idemp_app_opt_fail",
            reason="Approval with outdated version.",
        )
        with pytest.raises(OptimisticLockError):
            ResponseTransitionService.approve_proposal(
                session=session,
                response_action_id=proposal.response_action_id,
                request=app_req,
                operator=approver,
            )


def test_reject_proposal_success(session_factory, test_setup):
    """Verify rejecting a proposal updates status and audit log cleanly."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for rejection test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_reject",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)

        rej_req = RejectionRequest(
            expected_version=1,
            idempotency_key="idemp_rej_001",
            reason="False positive or internal IP address.",
        )
        code, trans_res = ResponseTransitionService.reject_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=rej_req,
            operator=approver,
        )

        assert code == 200
        assert trans_res.approval_status == "rejected"
        assert trans_res.execution_status == "not_queued"

        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.approval_status == "rejected"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "rejected"


# =============================================================================
# 4. Cancellation & Expiration Tests
# =============================================================================

def test_cancel_pending_proposal(session_factory, test_setup):
    """Verify cancelling a pending proposal."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for cancel test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_cancel_pending",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)

        canc_req = CancellationRequest(
            expected_version=1,
            idempotency_key="idemp_canc_001",
            reason="Threat resolved by other means.",
        )
        code, res = ResponseTransitionService.cancel_action(
            session=session,
            response_action_id=proposal.response_action_id,
            request=canc_req,
            operator=analyst,
        )

        assert code == 200
        assert res.approval_status == "cancelled"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "cancelled"


def test_cancel_queued_execution_cancels_outbox(session_factory, test_setup):
    """Verify cancelling an approved-but-queued execution cancels its outbox entries."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for queued cancel test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_cancel_queued",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_cq", reason="Approved"),
            operator=approver,
        )

        # Cancel queued execution
        canc_req = CancellationRequest(
            expected_version=2,
            idempotency_key="idemp_canc_queued",
            reason="Cancelled before worker picked it up.",
        )
        code, res = ResponseTransitionService.cancel_action(
            session=session,
            response_action_id=proposal.response_action_id,
            request=canc_req,
            operator=approver,
        )

        assert code == 200
        assert res.execution_status == "cancelled"

        # Outbox should be marked cancelled
        outbox = session.scalar(
            select(ResponseOutbox).where(ResponseOutbox.response_action_id == proposal.response_action_id)
        )
        assert outbox.status == "cancelled"


def test_cancel_prohibits_running_execution(session_factory, test_setup):
    """Verify cancellation fails closed if execution is running."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for running cancel test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_cancel_running",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_cr", reason="Approved"),
            operator=approver,
        )

        # Manually advance to running
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        session.commit()

        canc_req = CancellationRequest(
            expected_version=2,
            idempotency_key="idemp_canc_fail_running",
            reason="Attempt to cancel running.",
        )
        with pytest.raises(InvalidStateTransitionError, match="Running or indeterminate actions cannot be cancelled"):
            ResponseTransitionService.cancel_action(
                session=session,
                response_action_id=proposal.response_action_id,
                request=canc_req,
                operator=approver,
            )


def test_expire_stale_proposals_sweeper(session_factory, test_setup):
    """Verify proposal expiration sweeper flags timed out proposals."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for expiration sweeper test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_sweep_exp",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)

        # Set approval_expires_at in the past
        action = session.get(ResponseAction, proposal.response_action_id)
        action.approval_expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        session.commit()

        expired_count = ResponseTransitionService.expire_stale_proposals(session)
        assert expired_count >= 1

        action_after = session.get(ResponseAction, proposal.response_action_id)
        assert action_after.approval_status == "expired"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "expired"


# =============================================================================
# 5. Outbox & Two-Transaction Simulation Execution Tests
# =============================================================================

def test_simulation_execution_two_transaction_lifecycle(session_factory, test_setup):
    """Verify full two-transaction simulation execution lifecycle."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for full 2-tx simulation lifecycle.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_sim_lifecycle",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_sim", reason="Approved"),
            operator=approver,
        )

    # 1. Claim Outbox Command
    with session_factory() as session:
        claim = ResponseOutboxService.claim_next_command(
            session=session,
            worker_id="worker-sim-node-01",
            lease_duration_seconds=60,
            command_type="execute_simulation",
        )
        assert claim is not None
        assert claim.response_action_id == proposal.response_action_id
        assert claim.lease_token == 1
        assert claim.lease_owner == "worker-sim-node-01"
        session.commit()

    # 2. Execute Two-Transaction Lifecycle
    exec_result = SimulationExecutionService.execute_simulation_claim(session_factory, claim)
    assert exec_result.success is True
    assert exec_result.simulated_entry_id is not None

    # 3. Verify Database Settlement
    with session_factory() as session:
        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.execution_status == "succeeded"
        assert action.approval_status == "approved"
        assert action.verification_status == "pending"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "simulated"

        # Simulated blocklist entry exists and is durable
        sim_entry = session.scalar(
            select(SimulatedBlocklistEntry).where(
                SimulatedBlocklistEntry.response_action_id == action.response_action_id
            )
        )
        assert sim_entry is not None
        assert str(sim_entry.target_ip) == test_setup["source_ip"]
        assert sim_entry.idempotency_key == f"resp_sim_{action.response_action_id}"

        # Original execute_simulation outbox completed
        orig_outbox = session.get(ResponseOutbox, claim.outbox_id)
        assert orig_outbox.status == "completed"

        # Verification command enqueued
        verif_outbox = session.scalar(
            select(ResponseOutbox).where(
                ResponseOutbox.response_action_id == action.response_action_id,
                ResponseOutbox.command_type == "verify_simulation",
            )
        )
        assert verif_outbox is not None
        assert verif_outbox.status == "pending"


def test_simulation_adapter_fencing_token_superseded(session_factory, test_setup):
    """Verify simulation adapter rejects worker with outdated lease token."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for fencing token test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_fencing",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_fen", reason="Approved"),
            operator=approver,
        )

        claim = ResponseOutboxService.claim_next_command(
            session=session,
            worker_id="worker-01",
            command_type="execute_simulation",
        )
        session.commit()

        # Advance to running as required by Stage 2
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        session.commit()

        # Try to execute with outdated token
        action = session.get(ResponseAction, proposal.response_action_id)
        outbox = session.get(ResponseOutbox, claim.outbox_id)

        with pytest.raises(FencingTokenError, match="superseded"):
            SimulationAdapter.execute_simulation_effect(
                session=session,
                action=action,
                outbox=outbox,
                worker_id="worker-01",
                claimed_lease_token=claim.lease_token - 1,  # Outdated token!
            )


# =============================================================================
# 6. Verification & Reconciliation Service Tests
# =============================================================================

def test_automated_verification_all_intercepted_succeeds(session_factory, test_setup):
    """Verify automated verification with 100% intercepted probes transitions to 'verified'."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for verification success test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_verif_succ",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_vs", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

    SimulationExecutionService.execute_simulation_claim(session_factory, claim)

    now = datetime.now(timezone.utc)
    probe_input = ProbeVerificationInput(
        probe_id="SYN-PROBE-001",
        generation_evidence_id=test_setup["evidence_id_1"],
        capture_evidence_id=test_setup["evidence_id_2"],
        interception_evidence_id=test_setup["evidence_id_1"],
        intercepted=True,
    )
    run_req = VerificationRunRequest(
        response_action_id=proposal.response_action_id,
        synthetic_scenario_id="scenario-syn-01",
        observation_window_start=now - timedelta(minutes=5),
        observation_window_end=now,
        probes=[probe_input],
    )

    with session_factory() as session:
        res = VerificationService.evaluate_probes(session, run_req, "worker-verif-01")
        assert res.outcome == "verified"
        assert res.intercepted_probes == 1

        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.verification_status == "verified"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.verification_status == "verified"

        # Reconciliation record persisted
        rec = session.scalar(
            select(VerificationReconciliationRecord).where(
                VerificationReconciliationRecord.response_action_id == action.response_action_id
            )
        )
        assert rec is not None
        assert rec.resolution == "confirm_verified"


def test_automated_verification_inconclusive_outcome(session_factory, test_setup):
    """Verify mixed probe results result in 'inconclusive' status without reconciliation record."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for inconclusive test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_inconcl",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_incon", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

    SimulationExecutionService.execute_simulation_claim(session_factory, claim)

    now = datetime.now(timezone.utc)
    # 2 probes: 1 intercepted, 1 dropped (mixed)
    p1 = ProbeVerificationInput(
        probe_id="SYN-PROBE-001",
        generation_evidence_id=test_setup["evidence_id_1"],
        capture_evidence_id=test_setup["evidence_id_2"],
        interception_evidence_id=test_setup["evidence_id_1"],
        intercepted=True,
    )
    p2 = ProbeVerificationInput(
        probe_id="SYN-PROBE-002",
        generation_evidence_id=test_setup["evidence_id_1"],
        capture_evidence_id=test_setup["evidence_id_2"],
        interception_evidence_id=None,
        intercepted=False,
    )
    run_req = VerificationRunRequest(
        response_action_id=proposal.response_action_id,
        synthetic_scenario_id="scenario-syn-01",
        observation_window_start=now - timedelta(minutes=5),
        observation_window_end=now,
        probes=[p1, p2],
    )

    with session_factory() as session:
        res = VerificationService.evaluate_probes(session, run_req, "worker-verif-01")
        assert res.outcome == "inconclusive"
        assert res.total_probes == 2
        assert res.intercepted_probes == 1

        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.verification_status == "inconclusive"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.verification_status == "inconclusive"

        # No reconciliation record created yet for inconclusive outcome
        rec = session.scalar(
            select(VerificationReconciliationRecord).where(
                VerificationReconciliationRecord.response_action_id == action.response_action_id
            )
        )
        assert rec is None


def test_manual_reconciliation_inconclusive_action_success(session_factory, test_setup):
    """Verify authorized operator manually reconciles an inconclusive action with mathematical proof."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for manual reconciliation test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_man_rec",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_mr", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

    SimulationExecutionService.execute_simulation_claim(session_factory, claim)

    # Set to inconclusive via mixed probe verification
    now = datetime.now(timezone.utc)
    p1 = ProbeVerificationInput(
        probe_id="SYN-PROBE-001",
        generation_evidence_id=test_setup["evidence_id_1"],
        capture_evidence_id=test_setup["evidence_id_2"],
        interception_evidence_id=test_setup["evidence_id_1"],
        intercepted=True,
    )
    p2 = ProbeVerificationInput(
        probe_id="SYN-PROBE-002",
        generation_evidence_id=test_setup["evidence_id_1"],
        capture_evidence_id=test_setup["evidence_id_2"],
        interception_evidence_id=None,
        intercepted=False,
    )
    with session_factory() as session:
        VerificationService.evaluate_probes(
            session,
            VerificationRunRequest(
                response_action_id=proposal.response_action_id,
                synthetic_scenario_id="syn-scen",
                observation_window_start=now - timedelta(minutes=5),
                observation_window_end=now,
                probes=[p1, p2],
            ),
            "worker-1",
        )

    # Now manually reconcile confirming failed with mathematical validity
    with session_factory() as session:
        rec_req = ManualReconciliationRequest(
            reconciled_action="confirm_failed",
            justification="Manual audit confirms probe 2 leaked through due to firewall rule delay.",
            idempotency_key="idemp_man_rec_001",
            synthetic_scenario_id="scenario-syn-manual",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=0,
            telemetry_coverage_verified=True,
            evidence_ids=[test_setup["evidence_id_1"]],
        )

        code, rec_res = ManualReconciliationService.reconcile_inconclusive_action(
            session=session,
            response_action_id=proposal.response_action_id,
            request=rec_req,
            operator=approver,
        )

        assert code == 200
        assert rec_res.resolution == "confirm_failed"
        assert rec_res.verification_status == "failed"

        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.verification_status == "failed"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.verification_status == "failed"


def test_manual_reconciliation_rejects_mathematical_mismatch(session_factory, test_setup):
    """Verify manual reconciliation rejects invalid math (e.g. confirm_verified with missing intercept)."""
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)
    now = datetime.now(timezone.utc)

    # Invalid math: confirm_verified but intercepted_probes != generated_probes
    rec_req = ManualReconciliationRequest(
        reconciled_action="confirm_verified",
        justification="Invalid math request.",
        idempotency_key="idemp_man_rec_bad_math",
        synthetic_scenario_id="scenario-bad-math",
        observation_window_start=now - timedelta(minutes=10),
        observation_window_end=now,
        expected_probes=2,
        generated_probes=2,
        captured_probes=2,
        intercepted_probes=1,  # Mismatch with generated_probes=2!
        telemetry_coverage_verified=True,
        evidence_ids=[test_setup["evidence_id_1"]],
    )

    with session_factory() as session:
        with pytest.raises(ReconciliationError, match="confirm_verified requires all probes to be intercepted"):
            ManualReconciliationService.reconcile_inconclusive_action(
                session=session,
                response_action_id=uuid.uuid4(),
                request=rec_req,
                operator=approver,
            )


# =============================================================================
# 7. Focused Regression Tests for Task 11.2C.1 Correctness Invariants
# =============================================================================

def test_sac_json_utf8_byte_sorting_non_ascii_and_nfc():
    """Verify dictionary keys are sorted strictly by UTF-8 byte values with NFC normalization."""
    # In UTF-8:
    # 'a' -> 0x61
    # '\u00e9' -> 0xc3 0xa9 (NFC é)
    # '\u0100' -> 0xc4 0x80 (Ā)
    # 'z' -> 0x7a
    # UTF-8 byte order: 'a' (0x61) < 'z' (0x7a) < '\u00e9' (0xc3) < '\u0100' (0xc4)
    # Note: In UTF-16, '\u00e9' (0x00e9) < '\u0100' (0x0100) < 'z' (0x007a is before \u00e9)
    d = {
        "\u0100": 1,
        "z": 2,
        "\u00e9": 3,
        "a": 4,
    }
    canonical = canonicalize_sac_json_v1(d)
    expected = b'{"a":4,"z":2,"\xc3\xa9":3,"\xc4\x80":1}'
    assert canonical == expected


def test_sac_json_nested_dictionaries():
    """Verify nested dictionary keys are recursively normalized and sorted by UTF-8 bytes."""
    nested = {
        "outer_b": {"inner_z": 1, "inner_a": 2},
        "outer_a": {"key": 3},
    }
    canonical = canonicalize_sac_json_v1(nested)
    assert canonical == b'{"outer_a":{"key":3},"outer_b":{"inner_a":2,"inner_z":1}}'


def test_sac_json_duplicate_raw_keys_rejected():
    """Verify raw JSON with duplicate keys is rejected before Pydantic receives it."""
    raw_json = b'{"key": 1, "key": 2}'
    with pytest.raises(ValueError, match="Duplicate raw JSON property detected"):
        parse_sac_json_v1(raw_json)


def test_sac_json_nfc_key_collision_rejected():
    """Verify keys that normalize to the same NFC form are detected as collisions and rejected."""
    # 'e\u0301' (decomposed) vs '\u00e9' (composed NFC)
    raw_json = '{"e\u0301": 1, "\u00e9": 2}'
    with pytest.raises(ValueError, match="NFC key collision detected"):
        parse_sac_json_v1(raw_json)


def test_sac_json_bom_rejected():
    """Verify UTF-8 Byte Order Mark (BOM) is strictly rejected."""
    raw_bytes = b"\xef\xbb\xbf" + b'{"action": "test"}'
    with pytest.raises(ValueError, match="Byte Order Mark .* strictly forbidden"):
        parse_sac_json_v1(raw_bytes)


def test_sac_json_nan_infinity_rejected():
    """Verify NaN, Infinity, and -Infinity are strictly rejected."""
    with pytest.raises(ValueError, match="forbidden"):
        parse_sac_json_v1('{"value": NaN}')
    with pytest.raises(ValueError, match="forbidden"):
        parse_sac_json_v1('{"value": Infinity}')
    with pytest.raises(ValueError, match="forbidden"):
        parse_sac_json_v1('{"value": -Infinity}')


def test_proposal_rejects_hindsight_historical_memory():
    """Verify proposals strictly reject Hindsight memory references."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    incident_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    ev_hindsight_id = uuid.uuid4()

    engine = connection.get_engine()
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    with factory() as session:
        inc = Incident(
            incident_id=incident_id,
            title="Hindsight Rejection Test Incident",
            status="investigating",
            severity="high",
            source_ip="198.51.100.123",
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
        )
        inv = Investigation(
            investigation_id=inv_id,
            incident_id=incident_id,
            status="completed",
        )
        # Evidence item of forbidden type 'historical_incident'
        ev_hindsight = EvidenceItem(
            evidence_id=ev_hindsight_id,
            investigation_id=inv_id,
            evidence_type="historical_incident",
            title="Hindsight Memory Recall for Prior Incident",
        )
        session.add_all([inc, inv, ev_hindsight])
        session.commit()

    try:
        with factory() as session:
            req = ProposalCreateRequest(
                incident_id=incident_id,
                investigation_id=inv_id,
                justification="Testing hindsight rejection.",
                evidence_ids=[ev_hindsight_id],
                idempotency_key="idemp_prop_hindsight_test",
            )
            with pytest.raises(EvidenceProvenanceError, match="Hindsight memory references"):
                ResponseProposalService.create_proposal(session, req, analyst)
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM evidence_items WHERE evidence_id = :id"), {"id": ev_hindsight_id})
            conn.execute(text("DELETE FROM investigations WHERE investigation_id = :id"), {"id": inv_id})
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": incident_id})


def test_proposal_rejects_gemini_synthesis_as_independent_proof():
    """Verify proposals reject Gemini-generated conclusions used as independent forensic proof."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    incident_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    ev_gemini_id = uuid.uuid4()

    engine = connection.get_engine()
    factory = sessionmaker(bind=engine, expire_on_commit=False)

    with factory() as session:
        inc = Incident(
            incident_id=incident_id,
            title="Gemini Rejection Test Incident",
            status="investigating",
            severity="high",
            source_ip="198.51.100.124",
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
        )
        inv = Investigation(
            investigation_id=inv_id,
            incident_id=incident_id,
            status="completed",
        )
        ev_gemini = EvidenceItem(
            evidence_id=ev_gemini_id,
            investigation_id=inv_id,
            evidence_type="detection_result",
            title="Gemini_Synthesis Unverified Conclusion",
        )
        session.add_all([inc, inv, ev_gemini])
        session.commit()

    try:
        with factory() as session:
            req = ProposalCreateRequest(
                incident_id=incident_id,
                investigation_id=inv_id,
                justification="Testing Gemini conclusion rejection.",
                evidence_ids=[ev_gemini_id],
                idempotency_key="idemp_prop_gemini_test",
            )
            with pytest.raises(EvidenceProvenanceError, match="Gemini-generated conclusion"):
                ResponseProposalService.create_proposal(session, req, analyst)
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM evidence_items WHERE evidence_id = :id"), {"id": ev_gemini_id})
            conn.execute(text("DELETE FROM investigations WHERE investigation_id = :id"), {"id": inv_id})
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": incident_id})


def test_proposal_with_authorized_provenance_set(session_factory, test_setup):
    """Verify proposals validate correctly when an AuthorizedProvenanceSet is supplied."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    provenance_set = AuthorizedProvenanceSet()
    provenance_set.add_evidence_item(test_setup["evidence_id_1"])

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal with AuthorizedProvenanceSet.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_prov_set",
    )

    with session_factory() as session:
        status_code, res = ResponseProposalService.create_proposal(
            session=session,
            request=req,
            operator=analyst,
            provenance_set=provenance_set,
        )
        assert status_code == 201
        assert res.approval_status == "pending_approval"


def test_simulation_recovery_matching_evidence(session_factory, test_setup):
    """Verify recovery when matching simulation ledger evidence exists advances to succeeded."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for recovery matching test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_rec_match",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_rm", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

        # Simulate: Worker completed Stage 2 and Tx A, but crashed before Tx B!
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        sim_entry = SimulatedBlocklistEntry(
            entry_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            idempotency_key=f"resp_sim_{action.response_action_id}",
            payload_sha256=action.payload_sha256,
            target_ip=str(action.target_value),
            simulated_rule_id="rule_sim_rec",
            metadata_json={"target_ip": str(action.target_value)},
        )
        session.add(sim_entry)
        session.commit()

    # Recovery sweeper runs
    recovery_result = SimulationExecutionService.recover_simulation_execution(
        session_factory,
        proposal.response_action_id,
    )
    assert recovery_result == "reconciled_success"

    with session_factory() as session:
        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.execution_status == "succeeded"
        assert action.verification_status == "pending"


def test_simulation_recovery_integrity_anomaly_sets_indeterminate(session_factory, test_setup):
    """Verify recovery detects integrity anomaly (conflicting IP/digest) and sets indeterminate without requeuing."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for recovery anomaly test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_rec_anomaly",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_ra", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

        # Simulate: Conflicting ledger entry inserted with mismatched IP!
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        sim_entry = SimulatedBlocklistEntry(
            entry_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            idempotency_key=f"resp_sim_{action.response_action_id}",
            payload_sha256="0" * 64,  # Conflicting SHA!
            target_ip=str(action.target_value),
            simulated_rule_id="rule_sim_anomaly",
            metadata_json={"target_ip": str(action.target_value)},
        )
        session.add(sim_entry)
        session.commit()

    recovery_result = SimulationExecutionService.recover_simulation_execution(
        session_factory,
        proposal.response_action_id,
    )
    assert recovery_result == "integrity_anomaly"

    with session_factory() as session:
        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.execution_status == "indeterminate"

        incident = session.get(Incident, test_setup["incident_id"])
        assert incident.response_status == "indeterminate"


def test_expire_stale_executions_with_ledger_effect_sets_indeterminate(session_factory, test_setup):
    """Verify expiration sweeper detects integrity mismatch on simulation ledger and sets indeterminate."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for expiration ledger effect test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_exp_effect",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_ee", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

        # Simulate: Conflicting ledger record inserted with mismatched SHA!
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        action.execution_deadline_at = datetime.now(timezone.utc) - timedelta(seconds=10)

        sim_entry = SimulatedBlocklistEntry(
            entry_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            idempotency_key=f"resp_sim_{action.response_action_id}",
            payload_sha256="0" * 64,  # Mismatched SHA causing integrity mismatch!
            target_ip=str(action.target_value),
            simulated_rule_id="rule_sim_ee",
            metadata_json={"target_ip": str(action.target_value)},
        )
        session.add(sim_entry)
        session.commit()

        # Expiration sweeper runs
        expired_count = ResponseTransitionService.expire_stale_executions(session)
        assert expired_count >= 1

        action_after = session.get(ResponseAction, proposal.response_action_id)
        # Must be indeterminate due to integrity mismatch!
        assert action_after.execution_status == "indeterminate"


def test_expire_stale_executions_with_matching_ledger_recovers_succeeded(session_factory, test_setup):
    """Verify expiration sweeper recovers exact matching ledger record as succeeded and queues verification."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for expiration exact match test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_exp_match",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_em", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

        # Simulate: Worker committed valid matching Tx A effect, then crashed/timed out
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        action.execution_deadline_at = datetime.now(timezone.utc) - timedelta(seconds=10)

        sim_entry = SimulatedBlocklistEntry(
            entry_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            idempotency_key=f"resp_sim_{action.response_action_id}",
            payload_sha256=action.payload_sha256,
            target_ip=str(action.target_value),
            simulated_rule_id="rule_sim_match",
            metadata_json={"target_ip": str(action.target_value)},
        )
        session.add(sim_entry)
        session.commit()

        # Expiration sweeper runs
        expired_count = ResponseTransitionService.expire_stale_executions(session)
        assert expired_count >= 1

        action_after = session.get(ResponseAction, proposal.response_action_id)
        assert action_after.execution_status == "succeeded"
        assert action_after.verification_status == "pending"

        # Verification command must be queued in outbox
        verif_cmd = session.scalar(
            select(ResponseOutbox).where(
                ResponseOutbox.response_action_id == proposal.response_action_id,
                ResponseOutbox.command_type == "verify_simulation",
            )
        )
        assert verif_cmd is not None
        assert verif_cmd.status == "pending"


def test_expire_stale_executions_confirmed_absence_expires(session_factory, test_setup):
    """Verify expiration sweeper transitions to expired on confirmed absence in simulation ledger."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for expiration absence test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_exp_abs",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_ea", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

        # Set deadline in the past with no ledger entry
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        action.execution_deadline_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        session.commit()

        expired_count = ResponseTransitionService.expire_stale_executions(session)
        assert expired_count >= 1

        action_after = session.get(ResponseAction, proposal.response_action_id)
        assert action_after.execution_status == "expired"
        outbox_after = session.get(ResponseOutbox, claim.outbox_id)
        assert outbox_after.status == "dead_letter"
        assert outbox_after.last_error_code == "EXECUTION_DEADLINE_EXPIRED"


def test_simulation_recovery_confirmed_absence_expired_deadline(session_factory, test_setup):
    """Verify recovery marks execution expired when deadline passed and no effect exists in ledger."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for recovery deadline expiration test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_rec_exp",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_re", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        action.execution_deadline_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        session.commit()

    outcome = SimulationExecutionService.recover_simulation_execution(session_factory, proposal.response_action_id)
    assert outcome == "expired"

    with session_factory() as session:
        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.execution_status == "expired"
        outbox = session.get(ResponseOutbox, claim.outbox_id)
        assert outbox.status == "dead_letter"
        assert outbox.last_error_code == "EXECUTION_DEADLINE_EXPIRED"


def test_simulation_recovery_confirmed_absence_requeues(session_factory, test_setup):
    """Verify recovery safely requeues execution without incrementing attempt count when attempts remain."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for recovery requeue test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_rec_req",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_rr", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "running"
        action.execution_deadline_at = datetime.now(timezone.utc) + timedelta(minutes=10)
        outbox = session.get(ResponseOutbox, claim.outbox_id)
        initial_attempts = outbox.attempt_count
        session.commit()

    outcome = SimulationExecutionService.recover_simulation_execution(session_factory, proposal.response_action_id)
    assert outcome == "requeued"

    with session_factory() as session:
        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.execution_status == "queued"
        outbox = session.get(ResponseOutbox, claim.outbox_id)
        assert outbox.status == "pending"
        # Requeue must NOT increment attempt count!
        assert outbox.attempt_count == initial_attempts


def test_outbox_attempt_count_lifecycle(session_factory, test_setup):
    """Verify ResponseOutbox.attempt_count lifecycle:
    - Stage 1 claim does NOT increment it.
    - Stage 2 increments it exactly once.
    - Failed/rejected execution gate does NOT consume an attempt.
    - Recovery requeue does NOT increment it.
    """
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for attempt count lifecycle test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_attempt_lc",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_alc", reason="Approved"),
            operator=approver,
        )
        # 1. Stage 1: Queue claim
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

        # Check: Stage 1 must NOT increment attempt_count
        outbox = session.get(ResponseOutbox, claim.outbox_id)
        assert outbox.attempt_count == 0

    # 2. Stage 2: Failed Execution Gate (simulate invalid lease token)
    invalid_claim = claim.model_copy(update={"lease_token": claim.lease_token + 99})
    gate_res = SimulationExecutionService.execute_simulation_claim(session_factory, invalid_claim)
    assert not gate_res.success
    assert gate_res.error_code == "STAGE_2_GATE_FAILURE"

    with session_factory() as session:
        outbox = session.get(ResponseOutbox, claim.outbox_id)
        # Check: Failed execution gate must NOT consume an attempt
        assert outbox.attempt_count == 0

        # Reset lease for worker-2 claim
        outbox.status = "pending"
        outbox.lease_owner = None
        outbox.lease_expires_at = None
        outbox.next_attempt_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()

        # Re-claim command for successful execution gate
        new_claim = ResponseOutboxService.claim_next_command(session, "worker-2", command_type="execute_simulation")
        assert new_claim is not None
        session.commit()

    # 3. Stage 2: Successful Execution Gate through full execution
    exec_res = SimulationExecutionService.execute_simulation_claim(session_factory, new_claim)
    assert exec_res.success

    with session_factory() as session:
        outbox = session.get(ResponseOutbox, new_claim.outbox_id)
        # Check: Stage 2 incremented attempt_count exactly once
        assert outbox.attempt_count == 1
        assert outbox.status == "completed"


def test_trusted_scenario_registry_persisted_and_tamper_proof():
    """Verify trusted scenarios load from repository data file and cannot be tampered with."""
    from app.services.verification_service import get_trusted_scenario_definition, SCENARIOS_DATA_PATH

    assert SCENARIOS_DATA_PATH.is_file(), f"Expected persisted scenario file at {SCENARIOS_DATA_PATH}"

    def_01 = get_trusted_scenario_definition("scenario-syn-01")
    assert def_01["expected_probe_ids"] == ["SYN-PROBE-001"]
    assert def_01["min_probes"] == 1

    def_multi = get_trusted_scenario_definition("scenario-syn-multi")
    assert def_multi["expected_probe_ids"] == ["SYN-PROBE-001", "SYN-PROBE-002"]
    assert def_multi["min_probes"] == 2


def test_cancel_action_rejects_indeterminate(session_factory, test_setup):
    """Verify ordinary cancellation strictly rejects indeterminate actions."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for indeterminate cancellation test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key=f"idemp_prop_indet_cancel_{uuid.uuid4().hex[:8]}",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key=f"idemp_app_ic_{uuid.uuid4().hex[:8]}", reason="Approved"),
            operator=approver,
        )

        action = session.get(ResponseAction, proposal.response_action_id)
        action.execution_status = "indeterminate"
        session.commit()

        canc_req = CancellationRequest(
            expected_version=2,
            idempotency_key="idemp_canc_indet_reject",
            reason="Attempting to cancel indeterminate action.",
        )
        with pytest.raises(InvalidStateTransitionError, match="Indeterminate states represent potential external effects"):
            ResponseTransitionService.cancel_action(
                session=session,
                response_action_id=proposal.response_action_id,
                request=canc_req,
                operator=approver,
            )


def test_automated_verification_missing_telemetry_remains_inconclusive(session_factory, test_setup):
    """Verify missing telemetry remains inconclusive, never failed."""
    analyst = OperatorPrincipal(operator_id="operator-analyst-1", role=OperatorRole.ANALYST)
    approver = OperatorPrincipal(operator_id="operator-approver-1", role=OperatorRole.APPROVER)

    req = ProposalCreateRequest(
        incident_id=test_setup["incident_id"],
        investigation_id=test_setup["investigation_id"],
        justification="Proposal for missing telemetry test.",
        evidence_ids=[test_setup["evidence_id_1"]],
        idempotency_key="idemp_prop_missing_telem",
    )

    with session_factory() as session:
        _, proposal = ResponseProposalService.create_proposal(session, req, analyst)
        ResponseTransitionService.approve_proposal(
            session=session,
            response_action_id=proposal.response_action_id,
            request=ApprovalRequest(expected_version=1, idempotency_key="idemp_app_mt", reason="Approved"),
            operator=approver,
        )
        claim = ResponseOutboxService.claim_next_command(session, "worker-1", command_type="execute_simulation")
        session.commit()

    SimulationExecutionService.execute_simulation_claim(session_factory, claim)

    now = datetime.now(timezone.utc)
    # Scenario requires SYN-PROBE-001 and SYN-PROBE-002 (scenario-syn-multi), but caller only supplies SYN-PROBE-001
    p1 = ProbeVerificationInput(
        probe_id="SYN-PROBE-001",
        generation_evidence_id=test_setup["evidence_id_1"],
        capture_evidence_id=test_setup["evidence_id_2"],
        interception_evidence_id=None,
        intercepted=False,  # 0 intercepted, BUT probe 2 is missing!
    )
    run_req = VerificationRunRequest(
        response_action_id=proposal.response_action_id,
        synthetic_scenario_id="scenario-syn-multi",  # Requires 2 probes!
        observation_window_start=now - timedelta(minutes=5),
        observation_window_end=now,
        probes=[p1],
    )

    with session_factory() as session:
        res = VerificationService.evaluate_probes(session, run_req, "worker-verif-01")
        # Missing telemetry MUST remain inconclusive, NEVER failed!
        assert res.outcome == "inconclusive"

        action = session.get(ResponseAction, proposal.response_action_id)
        assert action.verification_status == "inconclusive"


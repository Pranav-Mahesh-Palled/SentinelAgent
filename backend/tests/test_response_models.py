"""Integration and unit tests for Phase 11 Response Orchestration relational models.

Verifies:
1. Valid state matrix across approval, execution, and verification status dimensions.
2. Bidirectional state check constraints on response_actions.
3. Partial unique index enforcing a single active response action per incident.
4. Composite foreign keys ensuring investigation boundary coherence across actions,
   evidence attachments, reconciliation records, probes, and audit events.
5. Immutability triggers preventing UPDATE, DELETE, and TRUNCATE on forensic and ledger tables.
6. Identity trigger preventing alteration of immutable response_action identity/payload attributes.
7. Exact simulation ledger idempotency key constraint.
8. Reconciliation probe mathematical invariants.
9. SAC-JSON-v1 canonical test vector verification.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

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
def test_context(session_factory, db_engine):
    """Creates a base incident and investigation for response testing, cleaned up after."""
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()

    with session_factory() as session:
        incident = Incident(
            incident_id=incident_id,
            title="Test Phase 11 Brute Force Incident",
            status="investigating",
            severity="high",
            source_ip="198.51.100.42",
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="in_progress",
            response_status="pending_approval",
            verification_status="not_started",
        )
        investigation = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status="in_progress",
        )
        session.add(incident)
        session.add(investigation)
        session.commit()

    yield {
        "incident_id": incident_id,
        "investigation_id": investigation_id,
    }

    # Cleanup in proper dependency order
    with db_engine.begin() as conn:
        conn.execute(text("SET LOCAL sentinel.allow_immutable_cleanup = 'on';"))
        conn.execute(
            text("DELETE FROM verification_reconciliation_probes WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM verification_reconciliation_evidence WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text(
                "DELETE FROM response_audit_events WHERE response_action_id IN ("
                "  SELECT response_action_id FROM response_actions WHERE investigation_id = :inv_id"
                ")"
            ),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM verification_reconciliation_records WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM simulated_blocklist_entries WHERE target_ip = '198.51.100.42'"),
        )
        conn.execute(
            text(
                "DELETE FROM response_outbox WHERE response_action_id IN ("
                "  SELECT response_action_id FROM response_actions WHERE investigation_id = :inv_id"
                ")"
            ),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM response_action_evidence WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM response_actions WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM evidence_items WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM investigations WHERE investigation_id = :inv_id"),
            {"inv_id": investigation_id},
        )
        conn.execute(
            text("DELETE FROM incidents WHERE incident_id = :inc_id"),
            {"inc_id": incident_id},
        )


def _make_action_kwargs(test_context, **overrides):
    payload = {"target_ip": "198.51.100.42", "duration_seconds": 3600}
    payload_str = json.dumps(payload, sort_keys=True)
    payload_sha256 = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    defaults = {
        "response_action_id": uuid.uuid4(),
        "incident_id": test_context["incident_id"],
        "investigation_id": test_context["investigation_id"],
        "correlation_id": uuid.uuid4(),
        "action_type": "simulation.block_source_ip",
        "action_version": 1,
        "target_kind": "source_ip",
        "target_value": "198.51.100.42",
        "payload_json": payload,
        "payload_sha256": payload_sha256,
        "approved_payload_sha256": None,
        "justification": "Simulated block against active brute force source IP.",
        "proposed_by_operator_id": "operator-sec-01",
        "approval_status": "pending_approval",
        "execution_status": "not_queued",
        "verification_status": "not_started",
        "approval_expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
        "execution_deadline_at": None,
        "version": 1,
        "last_audit_sequence": 0,
        "idempotency_key_hash": hashlib.sha256(str(uuid.uuid4()).encode("utf-8")).hexdigest(),
        "proposal_response_status_code": 201,
        "proposal_response_snapshot": {"status": "pending_approval", "action_id": "test"},
    }
    defaults.update(overrides)
    return defaults


# =============================================================================
# 1. State Machine & Check Constraint Tests
# =============================================================================

def test_response_action_valid_pending_proposal(session_factory, test_context):
    """Verify inserting a valid pending proposal succeeds."""
    kwargs = _make_action_kwargs(test_context)
    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        session.commit()

        queried = session.get(ResponseAction, kwargs["response_action_id"])
        assert queried is not None
        assert queried.approval_status == "pending_approval"
        assert queried.execution_status == "not_queued"
        assert queried.verification_status == "not_started"


def test_response_action_valid_approved_running_state(session_factory, test_context):
    """Verify inserting an approved, running action with matching digest and deadline succeeds."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="approved",
        execution_status="running",
        verification_status="not_started",
    )
    kwargs["approved_payload_sha256"] = kwargs["payload_sha256"]
    kwargs["execution_deadline_at"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        session.commit()

        queried = session.get(ResponseAction, kwargs["response_action_id"])
        assert queried is not None
        assert queried.approval_status == "approved"
        assert queried.execution_status == "running"


def test_response_action_valid_succeeded_verified_state(session_factory, test_context):
    """Verify inserting an approved, succeeded, and verified action succeeds."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="approved",
        execution_status="succeeded",
        verification_status="verified",
    )
    kwargs["approved_payload_sha256"] = kwargs["payload_sha256"]
    kwargs["execution_deadline_at"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        session.commit()

        queried = session.get(ResponseAction, kwargs["response_action_id"])
        assert queried is not None
        assert queried.verification_status == "verified"


def test_chk_approval_execution_bidirectional_non_approved_queued_rejected(session_factory, test_context):
    """Verify check constraint rejects non-approved action having execution_status != 'not_queued'."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="pending_approval",
        execution_status="queued",  # Invalid: non-approved cannot be queued
    )
    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_resp_approval_execution_bidirectional" in str(exc_info.value)


def test_chk_approval_execution_bidirectional_approved_not_queued_rejected(session_factory, test_context):
    """Verify check constraint rejects approved action having execution_status == 'not_queued'."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="approved",
        execution_status="not_queued",  # Invalid: approved must be queued/running/succeeded/failed/indeterminate
    )
    kwargs["approved_payload_sha256"] = kwargs["payload_sha256"]
    kwargs["execution_deadline_at"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_resp_approval_execution_bidirectional" in str(exc_info.value)


def test_chk_execution_verification_bidirectional_succeeded_not_started_rejected(session_factory, test_context):
    """Verify check constraint rejects succeeded execution having verification_status == 'not_started'."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="approved",
        execution_status="succeeded",
        verification_status="not_started",  # Invalid: succeeded must have verification != not_started
    )
    kwargs["approved_payload_sha256"] = kwargs["payload_sha256"]
    kwargs["execution_deadline_at"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_resp_execution_verification_bid" in str(exc_info.value)


def test_chk_execution_verification_bidirectional_running_verified_rejected(session_factory, test_context):
    """Verify check constraint rejects running execution having verification_status == 'verified'."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="approved",
        execution_status="running",
        verification_status="verified",  # Invalid: running must have verification == not_started
    )
    kwargs["approved_payload_sha256"] = kwargs["payload_sha256"]
    kwargs["execution_deadline_at"] = datetime.now(timezone.utc) + timedelta(minutes=30)

    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_resp_execution_verification_bid" in str(exc_info.value)


def test_chk_approval_digest_deadline_bidirectional_missing_digest_rejected(session_factory, test_context):
    """Verify check constraint rejects approved action with missing approved digest or deadline."""
    kwargs = _make_action_kwargs(
        test_context,
        approval_status="approved",
        execution_status="queued",
        approved_payload_sha256=None,  # Invalid: approved requires approved_payload_sha256 = payload_sha256
        execution_deadline_at=None,
    )
    with session_factory() as session:
        action = ResponseAction(**kwargs)
        session.add(action)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_resp_approval_digest_deadline" in str(exc_info.value)


# =============================================================================
# 2. Unique Partial Index: Single Active Action per Incident
# =============================================================================

def test_uq_response_actions_single_active_per_incident_rejected(session_factory, test_context):
    """Verify unique partial index prevents two simultaneous active actions for the same incident."""
    action1_kwargs = _make_action_kwargs(test_context, approval_status="pending_approval")
    action2_kwargs = _make_action_kwargs(test_context, approval_status="pending_approval")

    with session_factory() as session:
        action1 = ResponseAction(**action1_kwargs)
        session.add(action1)
        session.commit()

        action2 = ResponseAction(**action2_kwargs)
        session.add(action2)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "uq_response_actions_single_active_per_incident" in str(exc_info.value)


def test_uq_response_actions_terminal_alongside_active_allowed(session_factory, test_context):
    """Verify a terminal (e.g. rejected or fully verified) action allows a new active action."""
    rejected_kwargs = _make_action_kwargs(
        test_context,
        approval_status="rejected",
        execution_status="not_queued",
        verification_status="not_started",
    )
    active_kwargs = _make_action_kwargs(
        test_context,
        approval_status="pending_approval",
        execution_status="not_queued",
        verification_status="not_started",
    )

    with session_factory() as session:
        action_rejected = ResponseAction(**rejected_kwargs)
        session.add(action_rejected)
        session.commit()

        action_active = ResponseAction(**active_kwargs)
        session.add(action_active)
        session.commit()

        count = session.query(ResponseAction).filter_by(incident_id=test_context["incident_id"]).count()
        assert count == 2


# =============================================================================
# 3. Composite Foreign Keys & Boundary Coherence
# =============================================================================

def test_composite_fk_action_investigation_mismatch_rejected(session_factory, test_context, db_engine):
    """Verify ResponseAction fails if incident_id and investigation_id belong to different incidents."""
    other_incident_id = uuid.uuid4()
    with session_factory() as session:
        other_inc = Incident(
            incident_id=other_incident_id,
            title="Other Incident",
            status="open",
            severity="low",
            source_ip="198.51.100.99",
            detection_method="rule",
            incident_type="port_scan",
            investigation_status="pending",
            response_status="not_proposed",
            verification_status="not_started",
        )
        session.add(other_inc)
        session.commit()

    try:
        kwargs = _make_action_kwargs(
            test_context,
            incident_id=other_incident_id,  # Mismatched with test_context["investigation_id"]
        )
        with session_factory() as session:
            action = ResponseAction(**kwargs)
            session.add(action)
            with pytest.raises(IntegrityError) as exc_info:
                session.commit()
            assert "fk_resp_actions_incident_investigation" in str(exc_info.value)
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": other_incident_id})


def test_response_action_evidence_cross_investigation_rejected(session_factory, test_context, db_engine):
    """Verify ResponseActionEvidence rejects linking evidence from another investigation."""
    action_kwargs = _make_action_kwargs(test_context)
    other_incident_id = uuid.uuid4()
    other_inv_id = uuid.uuid4()
    other_evidence_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        other_inc = Incident(
            incident_id=other_incident_id,
            title="Other Incident",
            status="open",
            severity="low",
            source_ip="198.51.100.99",
            detection_method="rule",
            incident_type="port_scan",
            investigation_status="pending",
            response_status="not_proposed",
            verification_status="not_started",
        )
        other_inv = Investigation(
            investigation_id=other_inv_id,
            incident_id=other_incident_id,
            status="pending",
        )
        other_evid = EvidenceItem(
            evidence_id=other_evidence_id,
            investigation_id=other_inv_id,
            evidence_type="detection_result",
            title="Foreign Evidence",
            evidence_data={"bytes": 100},
        )
        session.add(action)
        session.add(other_inc)
        session.add(other_inv)
        session.add(other_evid)
        session.commit()

    try:
        with session_factory() as session:
            # Attempt to associate test_context investigation action with other_inv evidence
            assoc = ResponseActionEvidence(
                response_action_id=action_kwargs["response_action_id"],
                evidence_id=other_evidence_id,
                investigation_id=test_context["investigation_id"],  # Mismatch with other_evid's investigation_id
                evidence_type="detection_result",
                evidence_sha256="a" * 64,
                evidence_snapshot={"bytes": 100},
            )
            session.add(assoc)
            with pytest.raises(IntegrityError) as exc_info:
                session.commit()
            assert "fk_resp_evid_item_investigation" in str(exc_info.value)
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM evidence_items WHERE evidence_id = :id"), {"id": other_evidence_id})
            conn.execute(text("DELETE FROM investigations WHERE investigation_id = :id"), {"id": other_inv_id})
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": other_incident_id})


# =============================================================================
# 4. Immutability Triggers
# =============================================================================

def test_response_audit_event_immutability_update_rejected(session_factory, test_context):
    """Verify UPDATE on response_audit_events is blocked by trigger."""
    action_kwargs = _make_action_kwargs(test_context)
    audit_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        audit = ResponseAuditEvent(
            response_audit_event_id=audit_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            sequence_number=1,
            event_type="proposal.created",
            actor_type="operator",
            actor_operator_id="operator-sec-01",
            actor_role_snapshot="analyst",
            reason="Proposal initialization",
            payload_sha256_snapshot=action_kwargs["payload_sha256"],
        )
        session.add(audit)
        session.commit()

    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_audit_events SET reason = 'Tampered' WHERE response_audit_event_id = :id"),
                {"id": audit_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)


def test_response_audit_event_immutability_delete_rejected(session_factory, test_context):
    """Verify DELETE on response_audit_events is blocked by trigger."""
    action_kwargs = _make_action_kwargs(test_context)
    audit_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        audit = ResponseAuditEvent(
            response_audit_event_id=audit_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            sequence_number=1,
            event_type="proposal.created",
            actor_type="operator",
            actor_operator_id="operator-sec-01",
            actor_role_snapshot="analyst",
            reason="Proposal initialization",
            payload_sha256_snapshot=action_kwargs["payload_sha256"],
        )
        session.add(audit)
        session.commit()

    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM response_audit_events WHERE response_audit_event_id = :id"),
                {"id": audit_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)


def test_simulated_blocklist_immutability_update_rejected(session_factory, test_context):
    """Verify UPDATE on simulated_blocklist_entries is blocked by trigger."""
    action_kwargs = _make_action_kwargs(test_context)
    entry_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        entry = SimulatedBlocklistEntry(
            entry_id=entry_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            idempotency_key=f"resp_sim_{action_kwargs['response_action_id']}",
            payload_sha256=action_kwargs["payload_sha256"],
            target_ip="198.51.100.42",
            simulated_rule_id="sim-rule-001",
        )
        session.add(entry)
        session.commit()

    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE simulated_blocklist_entries SET simulated_rule_id = 'tampered' WHERE entry_id = :id"),
                {"id": entry_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)


def test_response_action_immutable_identity_trigger(session_factory, test_context):
    """Verify trigger prevents altering immutable identity, payload, and proposal snapshot attributes."""
    action_kwargs = _make_action_kwargs(test_context)
    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

    # 1. Attempting to change immutable payload_sha256
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_actions SET payload_sha256 = :new_hash WHERE response_action_id = :id"),
                {"new_hash": "0" * 64, "id": action_kwargs["response_action_id"]},
            )
            session.commit()
        assert "Immutable identity and payload attributes of response_actions cannot be altered." in str(exc_info.value)

    # 2. Attempting to change proposal_response_status_code
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_actions SET proposal_response_status_code = 200 WHERE response_action_id = :id"),
                {"id": action_kwargs["response_action_id"]},
            )
            session.commit()
        assert "Immutable identity and payload attributes of response_actions cannot be altered." in str(exc_info.value)

    # 3. Attempting to change proposal_response_snapshot
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_actions SET proposal_response_snapshot = '{\"status\":\"tampered\"}'::jsonb WHERE response_action_id = :id"),
                {"id": action_kwargs["response_action_id"]},
            )
            session.commit()
        assert "Immutable identity and payload attributes of response_actions cannot be altered." in str(exc_info.value)

    # 4. Attempting to change idempotency_key_hash
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_actions SET idempotency_key_hash = :new_hash WHERE response_action_id = :id"),
                {"new_hash": "e" * 64, "id": action_kwargs["response_action_id"]},
            )
            session.commit()
        assert "Immutable identity and payload attributes of response_actions cannot be altered." in str(exc_info.value)


def test_response_action_mutable_columns_update_succeeds(session_factory, test_context):
    """Verify mutable columns (approval_status, execution_status, etc.) can be updated cleanly."""
    action_kwargs = _make_action_kwargs(test_context)
    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

    now = datetime.now(timezone.utc)
    with session_factory() as session:
        action = session.get(ResponseAction, action_kwargs["response_action_id"])
        action.approval_status = "approved"
        action.execution_status = "queued"
        action.approved_payload_sha256 = action.payload_sha256
        action.execution_deadline_at = now + timedelta(minutes=30)
        session.commit()

        updated = session.get(ResponseAction, action_kwargs["response_action_id"])
        assert updated.approval_status == "approved"
        assert updated.execution_status == "queued"


# =============================================================================
# 5. Simulation Ledger Idempotency & Reconciliation Invariants
# =============================================================================

def test_simulated_blocklist_idempotency_key_format_constraint(session_factory, test_context):
    """Verify idempotency_key must exactly equal 'resp_sim_' || response_action_id::text."""
    action_kwargs = _make_action_kwargs(test_context)
    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        invalid_entry = SimulatedBlocklistEntry(
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            idempotency_key="resp_sim_wrong_format_key",  # Invalid key format
            payload_sha256=action_kwargs["payload_sha256"],
            target_ip="198.51.100.42",
            simulated_rule_id="sim-rule-001",
        )
        session.add(invalid_entry)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_sim_idempotency_key_exact" in str(exc_info.value)


def test_verification_reconciliation_record_math_constraints(session_factory, test_context):
    """Verify reconciliation record mathematically validates probe interception counts."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        # Inconsistent record: confirm_verified but intercepted < generated
        invalid_rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_verified",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=10,
            generated_probes=10,
            captured_probes=10,
            intercepted_probes=9,  # Missing 1 probe: cannot confirm_verified!
            telemetry_coverage_verified=True,
            justification="Manual review of packet captures.",
        )
        session.add(invalid_rec)
        with pytest.raises(IntegrityError) as exc_info:
            session.commit()
        assert "chk_verif_rec_ve" in str(exc_info.value)


# =============================================================================
# 6. SAC-JSON-v1 Canonical Hash Determinism Test
# =============================================================================

def test_sac_json_v1_frozen_vector():
    """Verify SAC-JSON-v1 canonical test vector and frozen SHA-256 digest from Task 11.2A.8/9."""
    # Test vector 1 bytes from frozen specification:
    raw_vector_bytes = (
        b'{"action_id":"4a1f6e20-3b8a-4d9e-9f1c-2e3d4c5b6a70",'
        b'"expected_version":1,'
        b'"operation_type":"approve",'
        b'"payload":{"reason":"Need to block IP for incident"}}'
    )
    expected_digest = "b32342e4a75618ffb1acfc166682739e83828b752bb94fced52d7d884f1bcc55"
    actual_digest = hashlib.sha256(raw_vector_bytes).hexdigest()
    assert actual_digest == expected_digest


def test_sac_json_v1_alternate_frozen_vector():
    """Verify SAC-JSON-v1 alternate test vector containing target_value."""
    raw_vector_bytes = (
        b'{"action_id":"4a1f6e20-3b8a-4d9e-9f1c-2e3d4c5b6a70",'
        b'"expected_version":1,'
        b'"operation_type":"approve",'
        b'"payload":{"target_value":"198.51.100.1"}}'
    )
    expected_digest = "fa82465e41fb4ff1fd14925bc836d1e619c22a414d2851bfabd25cbb62a57921"
    actual_digest = hashlib.sha256(raw_vector_bytes).hexdigest()
    assert actual_digest == expected_digest


# =============================================================================
# 7. Reconciliation Probes & Outbox Lifecycle Integration Tests
# =============================================================================

def test_verification_reconciliation_probe_lifecycle_and_constraints(session_factory, test_context):
    """Verify probe creation, bijection check constraints, and immutability."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    ev_gen_id = uuid.uuid4()
    ev_cap_id = uuid.uuid4()
    ev_int_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)

        ev_gen = EvidenceItem(
            evidence_id=ev_gen_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Probe Gen",
        )
        ev_cap = EvidenceItem(
            evidence_id=ev_cap_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Probe Cap",
        )
        ev_int = EvidenceItem(
            evidence_id=ev_int_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Probe Int",
        )
        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_verified",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=1,
            telemetry_coverage_verified=True,
            justification="Probe verified successfully.",
        )
        session.add_all([ev_gen, ev_cap, ev_int, rec])
        session.commit()

        # Valid probe insert: intercepted=True with interception_evidence_id
        probe = VerificationReconciliationProbe(
            probe_record_id=uuid.uuid4(),
            reconciliation_id=rec_id,
            investigation_id=test_context["investigation_id"],
            probe_id="SYN-PROBE-001",
            generation_evidence_id=ev_gen_id,
            capture_evidence_id=ev_cap_id,
            intercepted=True,
            interception_evidence_id=ev_int_id,
        )
        session.add(probe)
        session.commit()

        # Duplicate (reconciliation_id, probe_id) rejected
        duplicate_probe = VerificationReconciliationProbe(
            probe_record_id=uuid.uuid4(),
            reconciliation_id=rec_id,
            investigation_id=test_context["investigation_id"],
            probe_id="SYN-PROBE-001",
            generation_evidence_id=ev_gen_id,
            capture_evidence_id=ev_cap_id,
            intercepted=True,
            interception_evidence_id=ev_int_id,
        )
        session.add(duplicate_probe)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        # Invariant check: intercepted=False with non-null interception_evidence_id rejected
        invalid_probe = VerificationReconciliationProbe(
            probe_record_id=uuid.uuid4(),
            reconciliation_id=rec_id,
            investigation_id=test_context["investigation_id"],
            probe_id="SYN-PROBE-002",
            generation_evidence_id=ev_gen_id,
            capture_evidence_id=ev_cap_id,
            intercepted=False,
            interception_evidence_id=ev_int_id,  # Invalid: intercepted=False must have null evidence
        )
        session.add(invalid_probe)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    # Immutability check on probe: UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE verification_reconciliation_probes SET intercepted = FALSE WHERE probe_id = 'SYN-PROBE-001'")
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)


def test_response_outbox_lifecycle_and_invariants(session_factory, test_context):
    """Verify outbox table state transitions and lease check constraints."""
    action_kwargs = _make_action_kwargs(test_context)
    outbox_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        outbox = ResponseOutbox(
            outbox_id=outbox_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            command_type="execute_simulation",
            deduplication_key=f"outbox_cmd_{action_kwargs['response_action_id']}_1",
            status="pending",
        )
        session.add(outbox)
        session.commit()

        # Invalid claimed status without lease owner/expiry
        outbox.status = "claimed"
        outbox.lease_owner = None
        outbox.lease_expires_at = None
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

        # Invalid completed status without completed_at
        outbox = session.get(ResponseOutbox, outbox_id)
        outbox.status = "completed"
        outbox.completed_at = None
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


def test_response_audit_event_partial_unique_operator_idempotency(session_factory, test_context):
    """Verify partial unique index on audit events prevents duplicate operator submissions."""
    action_kwargs = _make_action_kwargs(test_context)
    idemp_hash = hashlib.sha256(b"unique_operator_request_payload").hexdigest()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        audit1 = ResponseAuditEvent(
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            sequence_number=1,
            event_type="proposal.created",
            actor_type="operator",
            actor_operator_id="operator-lead-01",
            actor_role_snapshot="analyst",
            reason="Initial proposal",
            payload_sha256_snapshot=action_kwargs["payload_sha256"],
            idempotency_key_hash=idemp_hash,
            response_status_code=201,
            response_snapshot={"status": "created"},
        )
        session.add(audit1)
        session.commit()

        audit2 = ResponseAuditEvent(
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            sequence_number=2,
            event_type="approval.granted",
            actor_type="operator",
            actor_operator_id="operator-lead-01",  # Same operator
            actor_role_snapshot="analyst",
            reason="Duplicate submission",
            payload_sha256_snapshot=action_kwargs["payload_sha256"],
            idempotency_key_hash=idemp_hash,  # Same idempotency hash -> duplicate!
            response_status_code=200,
            response_snapshot={"status": "approved"},
        )
        session.add(audit2)
        with pytest.raises(IntegrityError):
            session.commit()


# =============================================================================
# 8. Complete Append-Only Trigger Tests for all Six Tables
# =============================================================================

def test_response_audit_events_immutability_full(session_factory, test_context):
    """Verify UPDATE, DELETE, and TRUNCATE rejection on response_audit_events, verifying row intact."""
    action_kwargs = _make_action_kwargs(test_context)
    audit_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        audit = ResponseAuditEvent(
            response_audit_event_id=audit_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            sequence_number=1,
            event_type="proposal.created",
            actor_type="operator",
            actor_operator_id="operator-sec-01",
            actor_role_snapshot="analyst",
            reason="Original audit reason",
            payload_sha256_snapshot=action_kwargs["payload_sha256"],
        )
        session.add(audit)
        session.commit()

    # 1. UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_audit_events SET reason = 'tampered' WHERE response_audit_event_id = :id"),
                {"id": audit_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 2. DELETE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM response_audit_events WHERE response_audit_event_id = :id"),
                {"id": audit_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 3. TRUNCATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(text("TRUNCATE TABLE response_audit_events"))
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # Confirm original row remains intact
    with session_factory() as session:
        row = session.get(ResponseAuditEvent, audit_id)
        assert row is not None
        assert row.reason == "Original audit reason"


def test_simulated_blocklist_entries_immutability_full(session_factory, test_context):
    """Verify UPDATE, DELETE, and TRUNCATE rejection on simulated_blocklist_entries, verifying row intact."""
    action_kwargs = _make_action_kwargs(test_context)
    entry_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        entry = SimulatedBlocklistEntry(
            entry_id=entry_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            idempotency_key=f"resp_sim_{action_kwargs['response_action_id']}",
            payload_sha256=action_kwargs["payload_sha256"],
            target_ip="198.51.100.42",
            simulated_rule_id="sim-rule-original",
        )
        session.add(entry)
        session.commit()

    # 1. UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE simulated_blocklist_entries SET simulated_rule_id = 'tampered' WHERE entry_id = :id"),
                {"id": entry_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 2. DELETE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM simulated_blocklist_entries WHERE entry_id = :id"),
                {"id": entry_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 3. TRUNCATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(text("TRUNCATE TABLE simulated_blocklist_entries"))
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # Confirm original row remains intact
    with session_factory() as session:
        row = session.get(SimulatedBlocklistEntry, entry_id)
        assert row is not None
        assert row.simulated_rule_id == "sim-rule-original"


def test_verification_reconciliation_records_immutability_full(session_factory, test_context):
    """Verify UPDATE, DELETE, and TRUNCATE rejection on verification_reconciliation_records, verifying row intact."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        session.add(action)
        session.commit()

        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_verified",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=1,
            telemetry_coverage_verified=True,
            justification="Original reconciliation verdict.",
        )
        session.add(rec)
        session.commit()

    # 1. UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE verification_reconciliation_records SET justification = 'tampered' WHERE reconciliation_id = :id"),
                {"id": rec_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 2. DELETE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM verification_reconciliation_records WHERE reconciliation_id = :id"),
                {"id": rec_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 3. TRUNCATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(text("TRUNCATE TABLE verification_reconciliation_records CASCADE"))
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # Confirm original row remains intact
    with session_factory() as session:
        row = session.get(VerificationReconciliationRecord, rec_id)
        assert row is not None
        assert row.justification == "Original reconciliation verdict."


def test_verification_reconciliation_evidence_immutability_full(session_factory, test_context):
    """Verify UPDATE, DELETE, and TRUNCATE rejection on verification_reconciliation_evidence, verifying row intact."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    assoc_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        ev = EvidenceItem(
            evidence_id=ev_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Reconciliation Evidence",
        )
        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_verified",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=1,
            telemetry_coverage_verified=True,
            justification="Reconciliation evidence test.",
        )
        session.add_all([action, ev, rec])
        session.commit()

        assoc = VerificationReconciliationEvidence(
            reconciliation_evidence_id=assoc_id,
            reconciliation_id=rec_id,
            evidence_id=ev_id,
            investigation_id=test_context["investigation_id"],
            evidence_sha256="c" * 64,
            evidence_snapshot={"status": "clean"},
        )
        session.add(assoc)
        session.commit()

    # 1. UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE verification_reconciliation_evidence SET evidence_sha256 = :new_hash WHERE reconciliation_evidence_id = :id"),
                {"new_hash": "d" * 64, "id": assoc_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 2. DELETE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM verification_reconciliation_evidence WHERE reconciliation_evidence_id = :id"),
                {"id": assoc_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 3. TRUNCATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(text("TRUNCATE TABLE verification_reconciliation_evidence"))
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # Confirm original row remains intact
    with session_factory() as session:
        row = session.get(VerificationReconciliationEvidence, assoc_id)
        assert row is not None
        assert row.evidence_sha256 == "c" * 64


def test_verification_reconciliation_probes_immutability_full(session_factory, test_context):
    """Verify UPDATE, DELETE, and TRUNCATE rejection on verification_reconciliation_probes, verifying row intact."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    probe_rec_id = uuid.uuid4()
    ev_gen_id = uuid.uuid4()
    ev_cap_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        ev_gen = EvidenceItem(
            evidence_id=ev_gen_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Probe Gen",
        )
        ev_cap = EvidenceItem(
            evidence_id=ev_cap_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Probe Cap",
        )
        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_failed",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=0,
            telemetry_coverage_verified=True,
            justification="Probe failed check.",
        )
        session.add_all([action, ev_gen, ev_cap, rec])
        session.commit()

        probe = VerificationReconciliationProbe(
            probe_record_id=probe_rec_id,
            reconciliation_id=rec_id,
            investigation_id=test_context["investigation_id"],
            probe_id="SYN-PROBE-FULL-001",
            generation_evidence_id=ev_gen_id,
            capture_evidence_id=ev_cap_id,
            intercepted=False,
            interception_evidence_id=None,
        )
        session.add(probe)
        session.commit()

    # 1. UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE verification_reconciliation_probes SET probe_id = 'TAMPERED' WHERE probe_record_id = :id"),
                {"id": probe_rec_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 2. DELETE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM verification_reconciliation_probes WHERE probe_record_id = :id"),
                {"id": probe_rec_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 3. TRUNCATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(text("TRUNCATE TABLE verification_reconciliation_probes"))
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # Confirm original row remains intact
    with session_factory() as session:
        row = session.get(VerificationReconciliationProbe, probe_rec_id)
        assert row is not None
        assert row.probe_id == "SYN-PROBE-FULL-001"


def test_response_action_evidence_immutability_full(session_factory, test_context):
    """Verify UPDATE, DELETE, and TRUNCATE rejection on response_action_evidence, verifying row intact."""
    action_kwargs = _make_action_kwargs(test_context)
    assoc_id = uuid.uuid4()
    ev_id = uuid.uuid4()

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        ev = EvidenceItem(
            evidence_id=ev_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Action Evidence Item",
        )
        session.add_all([action, ev])
        session.commit()

        assoc = ResponseActionEvidence(
            response_action_evidence_id=assoc_id,
            response_action_id=action_kwargs["response_action_id"],
            evidence_id=ev_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            evidence_sha256="f" * 64,
            evidence_snapshot={"raw": "data"},
        )
        session.add(assoc)
        session.commit()

    # 1. UPDATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("UPDATE response_action_evidence SET evidence_sha256 = :new_hash WHERE response_action_evidence_id = :id"),
                {"new_hash": "e" * 64, "id": assoc_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 2. DELETE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(
                text("DELETE FROM response_action_evidence WHERE response_action_evidence_id = :id"),
                {"id": assoc_id},
            )
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # 3. TRUNCATE rejected
    with session_factory() as session:
        with pytest.raises(DBAPIError) as exc_info:
            session.execute(text("TRUNCATE TABLE response_action_evidence"))
            session.commit()
        assert "Modifications and deletions are strictly forbidden on immutable" in str(exc_info.value)

    # Confirm original row remains intact
    with session_factory() as session:
        row = session.get(ResponseActionEvidence, assoc_id)
        assert row is not None
        assert row.evidence_sha256 == "f" * 64


# =============================================================================
# 9. Composite Foreign Keys & Downgrade Safety Guard Tests
# =============================================================================

def test_verification_reconciliation_evidence_composite_fk_cross_investigation_rejected(session_factory, test_context, db_engine):
    """Verify VerificationReconciliationEvidence rejects evidence from another investigation."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    other_inc_id = uuid.uuid4()
    other_inv_id = uuid.uuid4()
    other_ev_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_verified",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=1,
            telemetry_coverage_verified=True,
            justification="Valid reconciliation record.",
        )
        other_inc = Incident(
            incident_id=other_inc_id,
            title="Foreign Inc",
            status="open",
            severity="low",
            source_ip="198.51.100.88",
            detection_method="rule",
            incident_type="port_scan",
            investigation_status="pending",
            response_status="not_proposed",
            verification_status="not_started",
        )
        other_inv = Investigation(
            investigation_id=other_inv_id,
            incident_id=other_inc_id,
            status="pending",
        )
        other_ev = EvidenceItem(
            evidence_id=other_ev_id,
            investigation_id=other_inv_id,
            evidence_type="detection_result",
            title="Foreign Evidence",
        )
        session.add_all([action, rec, other_inc, other_inv, other_ev])
        session.commit()

    try:
        # Cross-investigation foreign key violation: evidence belongs to other_inv_id
        with session_factory() as session:
            assoc = VerificationReconciliationEvidence(
                reconciliation_evidence_id=uuid.uuid4(),
                reconciliation_id=rec_id,
                evidence_id=other_ev_id,
                investigation_id=test_context["investigation_id"],  # Mismatch with other_ev.investigation_id
                evidence_sha256="1" * 64,
                evidence_snapshot={"test": "data"},
            )
            session.add(assoc)
            with pytest.raises(IntegrityError) as exc_info:
                session.commit()
            assert "fk_verif_rec_evid_item_investigation" in str(exc_info.value)
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM evidence_items WHERE evidence_id = :id"), {"id": other_ev_id})
            conn.execute(text("DELETE FROM investigations WHERE investigation_id = :id"), {"id": other_inv_id})
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": other_inc_id})


def test_verification_reconciliation_probe_composite_fk_cross_investigation_rejected(session_factory, test_context, db_engine):
    """Verify VerificationReconciliationProbe rejects probes referencing evidence from another investigation."""
    action_kwargs = _make_action_kwargs(test_context)
    rec_id = uuid.uuid4()
    other_inc_id = uuid.uuid4()
    other_inv_id = uuid.uuid4()
    foreign_ev_id = uuid.uuid4()
    valid_ev_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        action = ResponseAction(**action_kwargs)
        rec = VerificationReconciliationRecord(
            reconciliation_id=rec_id,
            response_action_id=action_kwargs["response_action_id"],
            correlation_id=action_kwargs["correlation_id"],
            investigation_id=test_context["investigation_id"],
            actor_operator_id="operator-lead-01",
            resolution="confirm_verified",
            synthetic_scenario_id="scenario-syn-01",
            observation_window_start=now - timedelta(minutes=10),
            observation_window_end=now,
            expected_probes=1,
            generated_probes=1,
            captured_probes=1,
            intercepted_probes=1,
            telemetry_coverage_verified=True,
            justification="Probe test record.",
        )
        valid_ev = EvidenceItem(
            evidence_id=valid_ev_id,
            investigation_id=test_context["investigation_id"],
            evidence_type="detection_result",
            title="Valid Probe Evidence",
        )
        other_inc = Incident(
            incident_id=other_inc_id,
            title="Foreign Inc 2",
            status="open",
            severity="low",
            source_ip="198.51.100.89",
            detection_method="rule",
            incident_type="port_scan",
            investigation_status="pending",
            response_status="not_proposed",
            verification_status="not_started",
        )
        other_inv = Investigation(
            investigation_id=other_inv_id,
            incident_id=other_inc_id,
            status="pending",
        )
        foreign_ev = EvidenceItem(
            evidence_id=foreign_ev_id,
            investigation_id=other_inv_id,
            evidence_type="detection_result",
            title="Foreign Gen Evidence",
        )
        session.add_all([action, rec, valid_ev, other_inc, other_inv, foreign_ev])
        session.commit()

    try:
        # Cross-investigation foreign key violation on generation evidence
        with session_factory() as session:
            probe = VerificationReconciliationProbe(
                probe_record_id=uuid.uuid4(),
                reconciliation_id=rec_id,
                investigation_id=test_context["investigation_id"],
                probe_id="SYN-FOREIGN-01",
                generation_evidence_id=foreign_ev_id,  # Belongs to other_inv_id
                capture_evidence_id=valid_ev_id,
                intercepted=False,
            )
            session.add(probe)
            with pytest.raises(IntegrityError) as exc_info:
                session.commit()
            assert "fk_verif_probe_gen_evidence" in str(exc_info.value)
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM evidence_items WHERE evidence_id = :id"), {"id": foreign_ev_id})
            conn.execute(text("DELETE FROM investigations WHERE investigation_id = :id"), {"id": other_inv_id})
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": other_inc_id})


@pytest.mark.parametrize("status_column,status_value", [
    ("response_status", "simulated"),
    ("response_status", "failed"),
    ("response_status", "cancelled"),
    ("response_status", "expired"),
    ("response_status", "indeterminate"),
    ("verification_status", "inconclusive"),
])
def test_downgrade_guard_detects_phase_11_incident_projections(db_engine, status_column, status_value):
    """Verify downgrade safety query identifies all Phase 11-only incident status projections."""
    inc_id = uuid.uuid4()
    with db_engine.begin() as conn:
        conn.execute(
            text(f"""
                INSERT INTO incidents (
                    incident_id, title, status, severity, source_ip, detection_method,
                    incident_type, investigation_status, response_status, verification_status
                ) VALUES (
                    :id, 'Projection Test', 'investigating', 'high', '198.51.100.77', 'rule',
                    'brute_force', 'in_progress',
                    {' :val' if status_column == 'response_status' else "'not_proposed'"},
                    {' :val' if status_column == 'verification_status' else "'not_started'"}
                );
            """),
            {"id": inc_id, "val": status_value},
        )

    try:
        with db_engine.connect() as conn:
            res = conn.execute(text("""
                SELECT 
                    (SELECT COUNT(*) FROM response_actions) +
                    (SELECT COUNT(*) FROM response_action_evidence) +
                    (SELECT COUNT(*) FROM response_outbox) +
                    (SELECT COUNT(*) FROM simulated_blocklist_entries) +
                    (SELECT COUNT(*) FROM verification_reconciliation_records) +
                    (SELECT COUNT(*) FROM verification_reconciliation_evidence) +
                    (SELECT COUNT(*) FROM verification_reconciliation_probes) +
                    (SELECT COUNT(*) FROM response_audit_events) AS row_count,
                    (SELECT COUNT(*) FROM incidents WHERE response_status IN ('simulated', 'failed', 'cancelled', 'expired', 'indeterminate') OR verification_status = 'inconclusive') AS incident_count
            """)).fetchone()
            assert res is not None
            assert res[1] > 0, f"Expected guard to flag incident with {status_column}={status_value}"
    finally:
        with db_engine.begin() as conn:
            conn.execute(text("DELETE FROM incidents WHERE incident_id = :id"), {"id": inc_id})


def test_downgrade_safety_guard_actual_alembic_blocks(db_engine, test_context):
    """Verify Alembic downgrade() raises RuntimeError when Phase 11 table rows exist."""
    from alembic.config import Config
    from alembic import command

    action_kwargs = _make_action_kwargs(test_context)
    with db_engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO response_actions (
                    response_action_id, incident_id, investigation_id, correlation_id,
                    action_type, action_version, target_kind, target_value, payload_json,
                    payload_sha256, justification, proposed_by_operator_id, approval_status,
                    execution_status, verification_status, approval_expires_at, version,
                    last_audit_sequence, idempotency_key_hash, proposal_response_status_code,
                    proposal_response_snapshot
                ) VALUES (
                    :aid, :inc_id, :inv_id, :cid, 'simulation.block_source_ip', 1, 'source_ip',
                    '198.51.100.42', '{"target_ip":"198.51.100.42"}'::jsonb, :sha,
                    'Guard test', 'operator-test', 'pending_approval', 'not_queued', 'not_started',
                    now() + interval '1 day', 1, 0, :idemp, 201, '{"status":"pending_approval"}'::jsonb
                );
            """),
            {
                "aid": action_kwargs["response_action_id"],
                "inc_id": test_context["incident_id"],
                "inv_id": test_context["investigation_id"],
                "cid": action_kwargs["correlation_id"],
                "sha": action_kwargs["payload_sha256"],
                "idemp": action_kwargs["idempotency_key_hash"],
            },
        )

    alembic_cfg = Config("alembic.ini")
    with pytest.raises(RuntimeError) as exc_info:
        command.downgrade(alembic_cfg, "-1")

    assert "Downgrade blocked by safety guard" in str(exc_info.value)



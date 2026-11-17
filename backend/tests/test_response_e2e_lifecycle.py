"""End-to-End Integration Lifecycle Test for Phase 11 Response Orchestration and Verification.

Executes the complete 12-stage operational lifecycle:
1. Synthetic Incident Ingestion & Authoritative Evidence Storage
2. Operator Identity Verification & Role Scoping
3. Containment Action Proposal by Analyst with SAC-JSON-v1 Enforcements
4. Two-Person Separation Verification (Self-approval rejected, Admin approval rejected)
5. Containment Action Approval by Dedicated Approver
6. Background Worker Dispatch: Simulation Execution & Ledger Ingestion
7. Background Worker Dispatch: Synthetic Scenario Verification & Probing
8. Verification Replay Enqueueing and Succeeded Processing
9. Inconclusive Verification Handling and Manual Operator Reconciliation
10. Immutable Audit Trail Review with Monotonic Sequence Guarantees
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid

import pytest
from sqlalchemy import select
from starlette import status

from app.core.auth import OperatorPrincipal, OperatorRole, hash_api_key
from app.core.config import Settings
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.models.response_audit_event import ResponseAuditEvent
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.models.verification_reconciliation_record import VerificationReconciliationRecord
from app.services.response_worker_runtime import ResponseWorkerRuntime

# Import fixtures directly from test_response_api
from backend.tests.test_response_api import (
    api_client,
    auth_headers_analyst,
    auth_headers_approver_1,
    auth_headers_approver_2,
    auth_headers_admin,
    session_factory,
    db_engine,
)


def test_complete_phase11_e2e_workflow(
    api_client,
    auth_headers_analyst,
    auth_headers_approver_1,
    auth_headers_approver_2,
    auth_headers_admin,
    session_factory,
):
    """Demonstrate the complete, production-grade 12-stage operational lifecycle."""
    inc_id = uuid.uuid4()
    inv_id = uuid.uuid4()
    ev_1_id = uuid.uuid4()
    ev_2_id = uuid.uuid4()
    attacker_ip = "198.51.100.99"
    run_id = uuid.uuid4().hex[:8]

    # =========================================================================
    # Step 1: Synthetic SSH Activity & Incident Ingestion
    # =========================================================================
    with session_factory() as session:
        incident = Incident(
            incident_id=inc_id,
            title="High-Frequency SSH Brute-Force from Suspicious Range",
            status="investigating",
            severity="critical",
            source_ip=attacker_ip,
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
            response_status="not_proposed",
            verification_status="not_started",
        )
        investigation = Investigation(
            investigation_id=inv_id,
            incident_id=inc_id,
            status="completed",
            investigation_summary="Multi-threaded password spraying targeting root account verified.",
        )
        evidence_1 = EvidenceItem(
            evidence_id=ev_1_id,
            investigation_id=inv_id,
            evidence_type="detection_result",
            title="Failed SSH Attempts Exceeded 50/minute",
            description="Multi-threaded password spraying targeting root account verified.",
            source_reference="/var/log/auth.log",
        )
        evidence_2 = EvidenceItem(
            evidence_id=ev_2_id,
            investigation_id=inv_id,
            evidence_type="ssh_event",
            title="Encrypted Traffic Capture Sample",
            description="Captured 45 failed handshake attempts.",
            source_reference="/var/log/suricata/eve.json",
        )
        session.add_all([incident, investigation, evidence_1, evidence_2])
        session.commit()

    # =========================================================================
    # Step 2: Operator Identity Verification & Role Discovery
    # =========================================================================
    me_analyst = api_client.get("/api/v1/auth/me", headers=auth_headers_analyst).json()
    assert me_analyst["operator_id"] == "op-analyst-01"
    assert me_analyst["role"] == "analyst"

    me_approver = api_client.get("/api/v1/auth/me", headers=auth_headers_approver_1).json()
    assert me_approver["operator_id"] == "op-approver-01"
    assert me_approver["role"] == "approver"

    # =========================================================================
    # Step 3: Containment Action Proposal by Analyst
    # =========================================================================
    prop_payload = {
        "investigation_id": str(inv_id),
        "justification": "Credential stuffing attacks confirmed from attacker IP 198.51.100.99. Containment required.",
        "evidence_ids": [str(ev_1_id), str(ev_2_id)],
    }
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": f"e2e_idemp_prop_{run_id}"},
        json=prop_payload,
    )
    assert prop_res.status_code == status.HTTP_201_CREATED
    prop_data = prop_res.json()
    action_id = uuid.UUID(prop_data["response_action_id"])
    assert prop_data["approval_status"] == "pending_approval"
    assert prop_data["execution_status"] == "not_queued"
    assert prop_data["proposed_by_operator_id"] == "op-analyst-01"

    # Verify target IP derived authoritatively
    action_detail = api_client.get(f"/api/v1/response/actions/{action_id}", headers=auth_headers_analyst).json()
    assert action_detail["target_value"] == attacker_ip

    # =========================================================================
    # Step 4: Two-Person Separation Verification
    # =========================================================================
    # 4a. Proposer attempts self-approval
    self_appr = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_analyst, "Idempotency-Key": f"e2e_self_appr_{run_id}"},
        json={"expected_version": 1, "reason": "Self-authorizing"},
    )
    assert self_appr.status_code == status.HTTP_403_FORBIDDEN

    # 4b. Admin attempts approval (role restriction)
    admin_appr = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_admin, "Idempotency-Key": f"e2e_admin_appr_{run_id}"},
        json={"expected_version": 1, "reason": "Admin overriding"},
    )
    assert admin_appr.status_code == status.HTTP_403_FORBIDDEN

    # =========================================================================
    # Step 5: Containment Action Authorization by Dedicated Approver
    # =========================================================================
    appr_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_1, "Idempotency-Key": f"e2e_valid_appr_{run_id}"},
        json={
            "expected_version": 1,
            "reason": "Approved containment action after reviewing evidence item hashes.",
            "execution_timeout_seconds": 300,
        },
    )
    assert appr_res.status_code == status.HTTP_200_OK
    appr_data = appr_res.json()
    assert appr_data["approval_status"] == "approved"
    assert appr_data["execution_status"] == "queued"
    assert appr_data["version"] == 2

    # =========================================================================
    # Step 6: Background Worker Execution Dispatch
    # =========================================================================
    worker_runtime = ResponseWorkerRuntime(
        session_factory=session_factory,
        worker_id="e2e-test-worker-01",
    )

    # Run one batch cycle to execute simulation
    stats1 = worker_runtime.run_once()
    assert stats1["claims_processed"] >= 1
    assert stats1["results"][0]["success"] is True

    # Verify simulation ledger entry and state
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        assert action.execution_status == "succeeded"
        assert action.verification_status == "pending"

        ledger = session.scalar(
            select(SimulatedBlocklistEntry).where(SimulatedBlocklistEntry.response_action_id == action_id)
        )
        assert ledger is not None
        assert str(ledger.target_ip) == attacker_ip
        assert ledger.simulated_rule_id.startswith("rule_sim_")

    # =========================================================================
    # Step 7: Background Worker Verification Dispatch
    # =========================================================================
    # Run second batch cycle to execute verification
    stats2 = worker_runtime.run_once()
    assert stats2["claims_processed"] >= 1
    assert stats2["results"][0]["success"] is True

    # Verify containment verification state
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        assert action.verification_status == "verified"

    verif_detail = api_client.get(
        f"/api/v1/response/actions/{action_id}/verification",
        headers=auth_headers_analyst,
    ).json()
    assert verif_detail["verification_status"] == "verified"

    # =========================================================================
    # Step 8: Verification Replay Enqueueing and Succeeded Processing
    # =========================================================================
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        v_replay = action.version

    re_verif_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/re-verify",
        headers={**auth_headers_approver_1, "Idempotency-Key": f"e2e_reverif_{run_id}"},
        json={"expected_version": v_replay, "reason": "Operator requested verification replay"},
    )
    assert re_verif_res.status_code == status.HTTP_202_ACCEPTED
    assert re_verif_res.json()["verification_status"] == "pending"

    # Worker executes replay
    stats3 = worker_runtime.run_once()
    assert stats3["claims_processed"] >= 1
    assert stats3["results"][0]["success"] is True

    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        assert action.verification_status == "verified"

    # =========================================================================
    # Step 9: Inconclusive Verification & Manual Operator Reconciliation
    # =========================================================================
    # Set action verification status to inconclusive for reconciliation demonstration
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        action.verification_status = "inconclusive"
        action.version += 1
        current_version = action.version
        session.commit()

    now = datetime.now(timezone.utc)
    rec_payload = {
        "reconciled_action": "confirm_verified",
        "justification": "Manual pcap packet capture review confirms all synthetic probes were dropped.",
        "expected_version": current_version,
        "synthetic_scenario_id": "scenario-syn-manual",
        "observation_window_start": (now - timedelta(minutes=5)).isoformat(),
        "observation_window_end": now.isoformat(),
        "expected_probes": 1,
        "generated_probes": 1,
        "captured_probes": 1,
        "intercepted_probes": 1,
        "telemetry_coverage_verified": True,
        "evidence_ids": [str(ev_1_id)],
    }

    rec_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/reconcile-verification",
        headers={**auth_headers_approver_2, "Idempotency-Key": f"e2e_rec_success_{run_id}"},
        json=rec_payload,
    )
    assert rec_res.status_code == status.HTTP_200_OK
    assert rec_res.json()["verification_status"] == "verified"

    # Verify reconciliation record in PostgreSQL
    with session_factory() as session:
        rec_record = session.scalar(
            select(VerificationReconciliationRecord)
            .where(VerificationReconciliationRecord.response_action_id == action_id)
            .order_by(VerificationReconciliationRecord.created_at.desc())
        )
        assert rec_record is not None
        assert rec_record.resolution == "confirm_verified"
        assert rec_record.actor_operator_id == "op-approver-02"

    # =========================================================================
    # Step 10: Immutable Audit Trail Review
    # =========================================================================
    audit_res = api_client.get(
        f"/api/v1/response/actions/{action_id}/audit-events",
        headers=auth_headers_analyst,
    )
    assert audit_res.status_code == status.HTTP_200_OK
    events = audit_res.json()
    assert len(events) >= 5

    # Verify strictly monotonic sequence numbering
    seqs = [e["sequence_number"] for e in events]
    assert seqs == sorted(seqs)
    assert seqs[0] == 1
    for i in range(len(seqs) - 1):
        assert seqs[i + 1] == seqs[i] + 1

    event_types = [e["event_type"] for e in events]
    assert "proposal.created" in event_types
    assert "approval.granted" in event_types
    assert "execution.succeeded" in event_types
    assert "verification.succeeded" in event_types
    assert "verification.reconciled_verified" in event_types

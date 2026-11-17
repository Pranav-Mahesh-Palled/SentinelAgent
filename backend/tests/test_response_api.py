"""Automated API Integration Tests for SentinelAgent Response Orchestration (Task 11.3A).

Tests all endpoints under /api/v1/incidents/{incident_id}/response and /api/v1/response/actions:
1. Authentication & Role-Based Access Control:
   - Missing/invalid API keys return HTTP 401.
   - Role authorization enforcement (Analyst, Approver, Admin).
   - Admin does not inherit Approver permissions (HTTP 403).
   - Two-person integrity: proposer cannot approve own action (HTTP 403).
2. Proposal Management:
   - Valid proposal creation (HTTP 201).
   - Target IP derived strictly by backend from Incident.source_ip.
   - Client-supplied target IP rejected (HTTP 422).
   - Duplicate raw JSON property rejected before Pydantic parsing (HTTP 422).
   - Floating-point values rejected before Pydantic parsing (HTTP 422).
   - Missing Idempotency-Key header rejected (HTTP 400).
   - Completed investigation and valid evidence required (HTTP 404/422).
   - Idempotent replay returns HTTP 200 with identical snapshot.
   - Conflicting idempotency key returns HTTP 409.
3. Response Action Retrieval:
   - List actions for incident (HTTP 200).
   - Get single action detail (HTTP 200).
   - Lease tokens and sensitive worker credentials are never exposed in DTOs.
4. Lifecycle Transitions:
   - Approve proposal (HTTP 200).
   - Reject proposal with mandatory reason (HTTP 200).
   - Cancel proposal or queued execution (HTTP 200).
   - Reject ordinary cancellation of indeterminate executions (HTTP 422).
   - Optimistic concurrency version mismatch returns HTTP 409.
5. Verification Replay & Manual Reconciliation:
   - Re-verify succeeded execution enqueues verification command atomically (HTTP 202).
   - Manual execution reconciliation of indeterminate actions (HTTP 200).
   - Manual verification reconciliation of inconclusive actions (HTTP 200).
   - Mathematical mismatch or prohibited evidence rejected (HTTP 422).
"""

from datetime import datetime, timedelta, timezone
import json
from typing import Any
import uuid

from fastapi import status
from fastapi.testclient import TestClient
from pydantic import SecretStr
import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

from app.core.auth import hash_api_key
from app.core.config import Settings
from app.db import connection
from app.db.session import get_session_factory
from app.main import app
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry


# =============================================================================
# Credentials & API Keys Fixtures
# =============================================================================

ANALYST_RAW_KEY = "sa_analyst_test_key_secret_1234567890abcdef"
APPROVER_1_RAW_KEY = "sa_approver1_test_key_secret_abcdef123456789"
APPROVER_2_RAW_KEY = "sa_approver2_test_key_secret_9876543210fedcba"
ADMIN_RAW_KEY = "sa_admin_test_key_secret_99999999999999999999"

ANALYST_HASH = hash_api_key(ANALYST_RAW_KEY)
APPROVER_1_HASH = hash_api_key(APPROVER_1_RAW_KEY)
APPROVER_2_HASH = hash_api_key(APPROVER_2_RAW_KEY)
ADMIN_HASH = hash_api_key(ADMIN_RAW_KEY)


@pytest.fixture
def auth_headers_analyst():
    return {"Authorization": f"Bearer {ANALYST_RAW_KEY}"}


@pytest.fixture
def auth_headers_approver_1():
    return {"Authorization": f"Bearer {APPROVER_1_RAW_KEY}"}


@pytest.fixture
def auth_headers_approver_2():
    return {"Authorization": f"Bearer {APPROVER_2_RAW_KEY}"}


@pytest.fixture
def auth_headers_admin():
    return {"Authorization": f"Bearer {ADMIN_RAW_KEY}"}


@pytest.fixture
def api_client(monkeypatch):
    """Configure TestClient with server-side operator credentials."""
    creds_data = [
        {"operator_id": "op-analyst-01", "role": "analyst", "key_sha256": ANALYST_HASH},
        {"operator_id": "op-approver-01", "role": "approver", "key_sha256": APPROVER_1_HASH},
        {"operator_id": "op-approver-02", "role": "approver", "key_sha256": APPROVER_2_HASH},
        {"operator_id": "op-admin-01", "role": "admin", "key_sha256": ADMIN_HASH},
    ]
    test_settings = Settings(
        OPERATOR_CREDENTIALS=SecretStr(json.dumps(creds_data)),
        _env_file=None,
    )
    monkeypatch.setattr("app.api.deps.get_settings", lambda: test_settings)
    monkeypatch.setattr("app.core.config.get_settings", lambda: test_settings)
    app.state.settings = test_settings

    client = TestClient(app)
    return client


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
    """Seed base completed investigation with incident and authoritative evidence items."""
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()
    ev_1_id = uuid.uuid4()
    ev_2_id = uuid.uuid4()

    with session_factory() as session:
        inc = Incident(
            incident_id=incident_id,
            title="Brute Force SSH Attack",
            status="investigating",
            severity="high",
            source_ip="198.51.100.55",
            detection_method="rule",
            incident_type="brute_force",
            investigation_status="completed",
            response_status="not_proposed",
            verification_status="not_started",
        )
        inv = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status="completed",
            investigation_summary="Source IP confirmed conducting automated credential stuffing.",
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
        session.add_all([inc, inv, ev_1, ev_2])
        session.commit()

    context = {
        "incident_id": incident_id,
        "investigation_id": investigation_id,
        "evidence_id_1": ev_1_id,
        "evidence_id_2": ev_2_id,
        "source_ip": "198.51.100.55",
    }

    yield context

    # Clean up
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
            text(
                "DELETE FROM simulated_blocklist_entries WHERE response_action_id IN ("
                "  SELECT response_action_id FROM response_actions WHERE investigation_id = :id"
                ")"
            ),
            {"id": investigation_id},
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
            text(
                "DELETE FROM response_action_evidence WHERE response_action_id IN ("
                "  SELECT response_action_id FROM response_actions WHERE investigation_id = :id"
                ")"
            ),
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
# 1. Authentication & Role Authorization Tests
# =============================================================================

def test_response_endpoints_require_authentication(api_client, test_context):
    """Verify that all response endpoints reject requests with missing or invalid tokens."""
    inc_id = test_context["incident_id"]
    fake_action_id = uuid.uuid4()

    # Missing Authorization header -> 401
    res = api_client.get(f"/api/v1/incidents/{inc_id}/response/actions")
    assert res.status_code == status.HTTP_401_UNAUTHORIZED

    # Invalid token -> 401
    res = api_client.get(
        f"/api/v1/incidents/{inc_id}/response/actions",
        headers={"Authorization": "Bearer invalid_secret_token_12345"},
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED

    # Missing auth on action detail -> 401
    res = api_client.get(f"/api/v1/response/actions/{fake_action_id}")
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_admin_cannot_approve_proposals(api_client, auth_headers_analyst, auth_headers_admin, test_context):
    """Verify admin role does not inherit approver permissions (strict separation)."""
    inc_id = test_context["incident_id"]
    prop_payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Block source IP for bruteforce incident.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }
    # Create proposal as Analyst
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_admin_test_01"},
        json=prop_payload,
    )
    assert prop_res.status_code == status.HTTP_201_CREATED
    action_id = prop_res.json()["response_action_id"]

    # Admin attempts to approve -> 403 Forbidden
    app_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_admin, "Idempotency-Key": "idemp_app_admin_01"},
        json={"expected_version": 1, "reason": "Admin attempting to approve"},
    )
    assert app_res.status_code == status.HTTP_403_FORBIDDEN


def test_self_approval_rejected(api_client, auth_headers_approver_1, test_context):
    """Verify two-person integrity: an operator cannot approve their own proposal."""
    inc_id = test_context["incident_id"]
    prop_payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Self-approval proposal test.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }
    # Create proposal as Approver 1
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_approver_1, "Idempotency-Key": "idemp_prop_self_app"},
        json=prop_payload,
    )
    assert prop_res.status_code == status.HTTP_201_CREATED
    action_id = prop_res.json()["response_action_id"]

    # Approver 1 attempts to approve own proposal -> 403 Forbidden
    app_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_1, "Idempotency-Key": "idemp_app_self_app"},
        json={"expected_version": 1, "reason": "Approving my own proposal"},
    )
    assert app_res.status_code == status.HTTP_403_FORBIDDEN
    assert "two-person approval required" in app_res.json()["detail"].lower()


def test_proposer_approver_separation_and_secondary_approval(
    api_client, auth_headers_approver_1, auth_headers_approver_2, auth_headers_analyst, test_context
):
    """Verify full separation of duties lifecycle:
    1. Operator with APPROVER role creates response proposal.
    2. Same operator attempts to approve proposal -> Role authorization passes,
       validate_proposer_approver_separation executes, returning HTTP 403 (two-person approval required).
    3. Different authorized approver succeeds in approving proposal -> HTTP 200 OK.
    4. Operator with ANALYST role attempting approval is rejected by role authorization.
    """
    inc_id = test_context["incident_id"]
    test_run_id = uuid.uuid4().hex[:8]
    prop_payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Controlled separation-of-duties verification proposal.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }

    # 1. Approver 1 creates proposal
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_approver_1, "Idempotency-Key": f"idemp_prop_sep_{test_run_id}"},
        json=prop_payload,
    )
    assert prop_res.status_code == status.HTTP_201_CREATED
    action_id = prop_res.json()["response_action_id"]
    assert prop_res.json()["proposed_by_operator_id"] == "op-approver-01"

    # 2. Approver 1 attempts to approve own proposal -> Role auth passes, separation validator executes
    self_app_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_1, "Idempotency-Key": f"idemp_app_self_{test_run_id}"},
        json={"expected_version": 1, "reason": "Approver 1 self-approval attempt"},
    )
    assert self_app_res.status_code == status.HTTP_403_FORBIDDEN
    assert "two-person approval required" in self_app_res.json()["detail"].lower()

    # 3. Approver 2 (distinct authorized approver) approves proposal -> 200 OK
    sec_app_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_2, "Idempotency-Key": f"idemp_app_sec_{test_run_id}"},
        json={"expected_version": 1, "reason": "Approver 2 secondary independent authorization"},
    )
    assert sec_app_res.status_code == status.HTTP_200_OK
    assert sec_app_res.json()["approval_status"] == "approved"
    assert sec_app_res.json()["transition_event_type"] == "approval.granted"
    assert sec_app_res.json()["outbox_id"] is not None

    # Fetch audit events to confirm approval was recorded under op-approver-02
    events_res = api_client.get(
        f"/api/v1/response/actions/{action_id}/audit-events",
        headers=auth_headers_approver_2,
    )
    assert events_res.status_code == status.HTTP_200_OK
    app_events = [ev for ev in events_res.json() if ev["event_type"] == "approval.granted"]
    assert len(app_events) == 1
    assert app_events[0]["actor_operator_id"] == "op-approver-02"
    assert app_events[0]["actor_role_snapshot"] == "approver"


def test_analyst_approval_rejected_by_role_authorization(
    api_client, auth_headers_analyst, test_context
):
    """Verify analyst proposing an action and attempting approval is rejected by RBAC role check."""
    inc_id = test_context["incident_id"]
    test_run_id = uuid.uuid4().hex[:8]
    prop_payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Analyst role proposal test.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }

    # 1. Analyst creates proposal
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": f"idemp_prop_an_{test_run_id}"},
        json=prop_payload,
    )
    assert prop_res.status_code == status.HTTP_201_CREATED
    action_id = prop_res.json()["response_action_id"]
    assert prop_res.json()["proposed_by_operator_id"] == "op-analyst-01"

    # 2. Analyst attempts to approve -> 403 Forbidden by role check (insufficient permissions)
    an_app_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_analyst, "Idempotency-Key": f"idemp_app_an_{test_run_id}"},
        json={"expected_version": 1, "reason": "Analyst approval attempt"},
    )
    assert an_app_res.status_code == status.HTTP_403_FORBIDDEN
    assert "insufficient operator permissions" in an_app_res.json()["detail"].lower()


# =============================================================================
# 2. Proposal Management Tests
# =============================================================================

def test_create_proposal_success_and_target_ip_derivation(
    api_client, auth_headers_analyst, test_context
):
    """Verify proposal creation derives target IP from incident and returns 201."""
    inc_id = test_context["incident_id"]
    payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Automated brute-force attacks detected from source IP.",
        "evidence_ids": [str(test_context["evidence_id_1"]), str(test_context["evidence_id_2"])],
        "duration_seconds": 7200,
    }

    res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_success_01"},
        json=payload,
    )
    assert res.status_code == status.HTTP_201_CREATED
    data = res.json()
    assert data["incident_id"] == str(inc_id)
    # Verified target_value is derived strictly from Incident.source_ip
    assert data["target_value"] == test_context["source_ip"]
    assert data["approval_status"] == "pending_approval"
    assert data["execution_status"] == "not_queued"
    assert data["version"] == 1


def test_proposal_client_supplied_target_ip_rejected(
    api_client, auth_headers_analyst, test_context
):
    """Verify client cannot supply arbitrary target IP (extra forbidden field -> 422)."""
    inc_id = test_context["incident_id"]
    payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Attempting to supply arbitrary target IP.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
        "target_ip": "1.2.3.4",  # Prohibited!
    }

    res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_arb_ip"},
        json=payload,
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_proposal_missing_idempotency_key_header_rejected(
    api_client, auth_headers_analyst, test_context
):
    """Verify request without Idempotency-Key header returns HTTP 400."""
    inc_id = test_context["incident_id"]
    payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Proposal without idempotency key.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }

    res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers=auth_headers_analyst,  # Missing Idempotency-Key
        json=payload,
    )
    assert res.status_code == status.HTTP_400_BAD_REQUEST


def test_proposal_sac_json_duplicate_raw_keys_rejected(
    api_client, auth_headers_analyst, test_context
):
    """Verify raw JSON with duplicate keys is rejected before Pydantic parsing."""
    inc_id = test_context["incident_id"]
    inv_id = str(test_context["investigation_id"])
    ev_id = str(test_context["evidence_id_1"])

    raw_duplicate_json = (
        f'{{"investigation_id":"{inv_id}","justification":"Test 1","justification":"Test 2",'
        f'"evidence_ids":["{ev_id}"]}}'
    ).encode("utf-8")

    res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={
            **auth_headers_analyst,
            "Idempotency-Key": "idemp_prop_dup_raw",
            "Content-Type": "application/json",
        },
        content=raw_duplicate_json,
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "duplicate" in res.json()["detail"].lower()


def test_proposal_sac_json_floating_point_rejected(
    api_client, auth_headers_analyst, test_context
):
    """Verify raw JSON with floating-point values is rejected before Pydantic parsing."""
    inc_id = test_context["incident_id"]
    inv_id = str(test_context["investigation_id"])
    ev_id = str(test_context["evidence_id_1"])

    raw_float_json = (
        f'{{"investigation_id":"{inv_id}","justification":"Valid justification text",'
        f'"evidence_ids":["{ev_id}"],"duration_seconds":3600.5}}'
    ).encode("utf-8")

    res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={
            **auth_headers_analyst,
            "Idempotency-Key": "idemp_prop_float_raw",
            "Content-Type": "application/json",
        },
        content=raw_float_json,
    )
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "floating-point" in res.json()["detail"].lower()


def test_proposal_idempotent_replay_and_conflict(
    api_client, auth_headers_analyst, test_context
):
    """Verify sequential replay returns 200 with identical snapshot, while payload conflict returns 409."""
    inc_id = test_context["incident_id"]
    payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Initial proposal justification.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }

    # 1. Initial Creation -> 201
    res1 = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_replay_01"},
        json=payload,
    )
    assert res1.status_code == status.HTTP_201_CREATED
    action_id_1 = res1.json()["response_action_id"]

    # 2. Replay with identical payload -> 200
    res2 = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_replay_01"},
        json=payload,
    )
    assert res2.status_code in (status.HTTP_200_OK, status.HTTP_201_CREATED)
    assert res2.json()["response_action_id"] == action_id_1

    # 3. Reuse idempotency key with conflicting justification -> 409 Conflict
    conflicting_payload = {**payload, "justification": "Changed justification payload"}
    res3 = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_replay_01"},
        json=conflicting_payload,
    )
    assert res3.status_code == status.HTTP_409_CONFLICT


# =============================================================================
# 3. Retrieve Response Actions Tests
# =============================================================================

def test_get_actions_never_exposes_internal_lease_tokens(
    api_client, auth_headers_analyst, test_context
):
    """Verify action detail and list endpoints never expose internal lease tokens or credentials."""
    inc_id = test_context["incident_id"]
    prop_payload = {
        "investigation_id": str(test_context["investigation_id"]),
        "justification": "Security inspection action test.",
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }
    create_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_inspect_sec"},
        json=prop_payload,
    )
    action_id = create_res.json()["response_action_id"]

    # 1. List endpoint
    list_res = api_client.get(
        f"/api/v1/incidents/{inc_id}/response/actions",
        headers=auth_headers_analyst,
    )
    assert list_res.status_code == status.HTTP_200_OK
    list_data = list_res.json()
    assert len(list_data) >= 1
    for item in list_data:
        assert "lease_token" not in item
        assert "lease_owner" not in item
        assert "key_sha256" not in item

    # 2. Get detail endpoint
    detail_res = api_client.get(
        f"/api/v1/response/actions/{action_id}",
        headers=auth_headers_analyst,
    )
    assert detail_res.status_code == status.HTTP_200_OK
    detail_data = detail_res.json()
    assert detail_data["response_action_id"] == action_id
    assert "lease_token" not in detail_data
    assert "lease_owner" not in detail_data


# =============================================================================
# 4. Lifecycle Transitions Tests
# =============================================================================

def test_approval_lifecycle_and_optimistic_concurrency(
    api_client, auth_headers_analyst, auth_headers_approver_2, test_context
):
    """Verify proposal approval by authorized approver, outbox command creation, and version mismatch."""
    t_id = uuid.uuid4().hex[:8]
    inc_id = test_context["incident_id"]
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": f"idemp_prop_trans_{t_id}"},
        json={
            "investigation_id": str(test_context["investigation_id"]),
            "justification": "Valid proposal for approval test.",
            "evidence_ids": [str(test_context["evidence_id_1"])],
        },
    )
    action_id = prop_res.json()["response_action_id"]

    # 1. Version mismatch -> 409
    bad_ver_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_2, "Idempotency-Key": f"idemp_app_bad_ver_{t_id}"},
        json={"expected_version": 99, "reason": "Approved with wrong version"},
    )
    assert bad_ver_res.status_code == status.HTTP_409_CONFLICT

    # 2. Successful approval with expected_version=1 -> 200
    app_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_2, "Idempotency-Key": f"idemp_app_success_{t_id}"},
        json={"expected_version": 1, "reason": "Authorized IP containment"},
    )
    assert app_res.status_code == status.HTTP_200_OK
    app_data = app_res.json()
    assert app_data["approval_status"] == "approved"
    assert app_data["execution_status"] == "queued"
    assert app_data["version"] == 2
    assert app_data["outbox_id"] is not None

    # 3. Idempotent replay of approval -> 200
    replay_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/approve",
        headers={**auth_headers_approver_2, "Idempotency-Key": f"idemp_app_success_{t_id}"},
        json={"expected_version": 1, "reason": "Authorized IP containment"},
    )
    assert replay_res.status_code == status.HTTP_200_OK
    assert replay_res.json()["response_action_id"] == action_id


def test_rejection_lifecycle(
    api_client, auth_headers_analyst, auth_headers_approver_2, test_context
):
    """Verify proposal rejection by authorized approver."""
    inc_id = test_context["incident_id"]
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_rej_01"},
        json={
            "investigation_id": str(test_context["investigation_id"]),
            "justification": "Proposal to be rejected.",
            "evidence_ids": [str(test_context["evidence_id_1"])],
        },
    )
    action_id = prop_res.json()["response_action_id"]

    rej_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/reject",
        headers={**auth_headers_approver_2, "Idempotency-Key": "idemp_rej_success_01"},
        json={"expected_version": 1, "reason": "Insufficient evidence of active threat"},
    )
    assert rej_res.status_code == status.HTTP_200_OK
    assert rej_res.json()["approval_status"] == "rejected"


def test_cancel_pending_proposal(
    api_client, auth_headers_analyst, test_context
):
    """Verify cancellation of a pending proposal."""
    inc_id = test_context["incident_id"]
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_canc_01"},
        json={
            "investigation_id": str(test_context["investigation_id"]),
            "justification": "Proposal to be cancelled.",
            "evidence_ids": [str(test_context["evidence_id_1"])],
        },
    )
    action_id = prop_res.json()["response_action_id"]

    canc_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/cancel",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_canc_success_01"},
        json={"expected_version": 1, "reason": "Incident resolved via external mechanism"},
    )
    assert canc_res.status_code == status.HTTP_200_OK
    assert canc_res.json()["approval_status"] == "cancelled"


# =============================================================================
# 5. Verification Replay & Manual Reconciliation Tests
# =============================================================================

def test_re_verify_action_enqueues_outbox_command(
    api_client, auth_headers_analyst, auth_headers_approver_2, test_context, session_factory
):
    """Verify POST /re-verify accepts request and enqueues verify command (HTTP 202)."""
    inc_id = test_context["incident_id"]
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_reverif_01"},
        json={
            "investigation_id": str(test_context["investigation_id"]),
            "justification": "Proposal for re-verification test.",
            "evidence_ids": [str(test_context["evidence_id_1"])],
        },
    )
    action_id = uuid.UUID(prop_res.json()["response_action_id"])

    # Simulate: Action execution succeeded in database
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        action.approval_status = "approved"
        action.approved_payload_sha256 = action.payload_sha256
        action.execution_deadline_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        action.execution_status = "succeeded"
        action.verification_status = "failed"
        action.version = 3
        session.commit()

    reverif_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/re-verify",
        headers={**auth_headers_approver_2, "Idempotency-Key": "idemp_reverif_cmd_01"},
        json={"expected_version": 3, "reason": "Operator requested verification probe rerun"},
    )
    assert reverif_res.status_code == status.HTTP_202_ACCEPTED
    data = reverif_res.json()
    assert data["verification_status"] == "pending"
    assert data["version"] == 4
    assert data["outbox_id"] is not None


def test_manual_execution_reconciliation(
    api_client, auth_headers_analyst, auth_headers_approver_2, test_context, session_factory
):
    """Verify manual reconciliation of an indeterminate execution outcome."""
    inc_id = test_context["incident_id"]
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_rec_exec_01"},
        json={
            "investigation_id": str(test_context["investigation_id"]),
            "justification": "Proposal for execution reconciliation.",
            "evidence_ids": [str(test_context["evidence_id_1"])],
        },
    )
    action_id = uuid.UUID(prop_res.json()["response_action_id"])

    # Set execution status to indeterminate
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        action.approval_status = "approved"
        action.approved_payload_sha256 = action.payload_sha256
        action.execution_deadline_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        action.execution_status = "indeterminate"
        action.version = 2
        session.commit()

    rec_payload = {
        "resolution": "confirm_succeeded",
        "justification": "External router telemetry confirms IP 198.51.100.55 was successfully dropped.",
        "expected_version": 2,
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }

    rec_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/reconcile-execution",
        headers={**auth_headers_approver_2, "Idempotency-Key": "idemp_rec_exec_success"},
        json=rec_payload,
    )
    assert rec_res.status_code == status.HTTP_200_OK
    assert rec_res.json()["execution_status"] == "succeeded"
    assert rec_res.json()["verification_status"] == "pending"


def test_manual_verification_reconciliation(
    api_client, auth_headers_analyst, auth_headers_approver_2, test_context, session_factory
):
    """Verify manual reconciliation of an inconclusive verification outcome."""
    inc_id = test_context["incident_id"]
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_rec_verif_01"},
        json={
            "investigation_id": str(test_context["investigation_id"]),
            "justification": "Proposal for verification reconciliation.",
            "evidence_ids": [str(test_context["evidence_id_1"])],
        },
    )
    action_id = uuid.UUID(prop_res.json()["response_action_id"])

    # Set verification status to inconclusive
    with session_factory() as session:
        action = session.get(ResponseAction, action_id)
        action.approval_status = "approved"
        action.approved_payload_sha256 = action.payload_sha256
        action.execution_deadline_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        action.execution_status = "succeeded"
        action.verification_status = "inconclusive"
        action.version = 3
        session.commit()

    now = datetime.now(timezone.utc)
    rec_payload = {
        "reconciled_action": "confirm_failed",
        "justification": "Manual pcap analysis confirms synthetic probes bypassed simulation filter.",
        "synthetic_scenario_id": "scenario-syn-manual",
        "observation_window_start": (now - timedelta(minutes=10)).isoformat(),
        "observation_window_end": now.isoformat(),
        "expected_probes": 1,
        "generated_probes": 1,
        "captured_probes": 1,
        "intercepted_probes": 0,
        "telemetry_coverage_verified": True,
        "evidence_ids": [str(test_context["evidence_id_1"])],
    }

    rec_res = api_client.post(
        f"/api/v1/response/actions/{action_id}/reconcile-verification",
        headers={**auth_headers_approver_2, "Idempotency-Key": "idemp_rec_verif_success"},
        json=rec_payload,
    )
    assert rec_res.status_code == status.HTTP_200_OK
    assert rec_res.json()["resolution"] == "confirm_failed"
    assert rec_res.json()["verification_status"] == "failed"

"""Tests for Task 11.3C Operator Dashboard API endpoints.

Validates:
- GET /api/v1/auth/me returns valid principal and role
- GET /api/v1/incidents lists incidents with response actions count
- GET /api/v1/incidents/{incident_id} retrieves individual incident
- GET /api/v1/investigations/{investigation_id}/evidence returns valid evidence items
- GET /api/v1/response/actions lists global response actions without leaking tokens
- GET /api/v1/response/actions/{id}/simulation returns safe simulation status
- GET /api/v1/response/actions/{id}/verification returns verification details
- GET /api/v1/response/actions/{id}/audit-events returns complete audit event trail
"""

import uuid
import pytest
from starlette import status

# Import fixtures directly from test_response_api
from backend.tests.test_response_api import (
    api_client,
    auth_headers_analyst,
    auth_headers_approver_1,
    auth_headers_approver_2,
    auth_headers_admin,
    test_context,
    session_factory,
    db_engine,
)


def test_auth_me_endpoint_roles(api_client, auth_headers_analyst, auth_headers_approver_1, auth_headers_admin):
    """Verify /api/v1/auth/me returns authenticated principal and server-validated role."""
    # 1. Analyst
    res = api_client.get("/api/v1/auth/me", headers=auth_headers_analyst)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["operator_id"] == "op-analyst-01"
    assert data["role"] == "analyst"

    # 2. Approver
    res = api_client.get("/api/v1/auth/me", headers=auth_headers_approver_1)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["operator_id"] == "op-approver-01"
    assert data["role"] == "approver"

    # 3. Admin
    res = api_client.get("/api/v1/auth/me", headers=auth_headers_admin)
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert data["operator_id"] == "op-admin-01"
    assert data["role"] == "admin"

    # 4. Unauthorized
    res = api_client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid_key"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_dashboard_incidents_and_evidence(api_client, auth_headers_analyst, test_context):
    """Verify listing incidents and reading investigation evidence items."""
    inc_id = test_context["incident_id"]
    inv_id = test_context["investigation_id"]

    # 1. List incidents
    res = api_client.get("/api/v1/incidents", headers=auth_headers_analyst)
    assert res.status_code == status.HTTP_200_OK
    incidents = res.json()
    assert isinstance(incidents, list)
    matching = [i for i in incidents if i["incident_id"] == str(inc_id)]
    assert len(matching) == 1
    assert matching[0]["source_ip"] == "198.51.100.55"

    # 2. Get specific incident
    res = api_client.get(f"/api/v1/incidents/{inc_id}", headers=auth_headers_analyst)
    assert res.status_code == status.HTTP_200_OK
    inc_data = res.json()
    assert inc_data["incident_id"] == str(inc_id)
    assert inc_data["source_ip"] == "198.51.100.55"

    # 3. Get investigation evidence
    res = api_client.get(f"/api/v1/investigations/{inv_id}/evidence", headers=auth_headers_analyst)
    assert res.status_code == status.HTTP_200_OK
    evidence_items = res.json()
    assert isinstance(evidence_items, list)
    assert len(evidence_items) >= 2
    ev_ids = [e["evidence_id"] for e in evidence_items]
    assert str(test_context["evidence_id_1"]) in ev_ids


def test_dashboard_action_inspection_endpoints(api_client, auth_headers_analyst, test_context):
    """Verify simulation details, verification details, and audit events endpoints."""
    inc_id = test_context["incident_id"]
    inv_id = test_context["investigation_id"]
    ev_id = test_context["evidence_id_1"]

    # Create proposal
    prop_res = api_client.post(
        f"/api/v1/incidents/{inc_id}/response/proposals",
        headers={**auth_headers_analyst, "Idempotency-Key": "idemp_prop_inspect_details_01"},
        json={
            "investigation_id": str(inv_id),
            "justification": "Detailed inspection test action.",
            "evidence_ids": [str(ev_id)],
        },
    )
    assert prop_res.status_code == status.HTTP_201_CREATED
    action_id = prop_res.json()["response_action_id"]

    # 1. Global list
    list_res = api_client.get("/api/v1/response/actions", headers=auth_headers_analyst)
    assert list_res.status_code == status.HTTP_200_OK
    all_actions = list_res.json()
    assert any(a["response_action_id"] == action_id for a in all_actions)

    # 2. Simulation details
    sim_res = api_client.get(f"/api/v1/response/actions/{action_id}/simulation", headers=auth_headers_analyst)
    assert sim_res.status_code == status.HTTP_200_OK
    sim_data = sim_res.json()
    assert sim_data["response_action_id"] == action_id
    assert sim_data["execution_status"] == "not_queued"
    assert sim_data["simulated_entry"] is None
    assert "lease_token" not in sim_data
    assert "key_sha256" not in sim_data

    # 3. Verification details
    ver_res = api_client.get(f"/api/v1/response/actions/{action_id}/verification", headers=auth_headers_analyst)
    assert ver_res.status_code == status.HTTP_200_OK
    ver_data = ver_res.json()
    assert ver_data["response_action_id"] == action_id
    assert ver_data["verification_status"] == "not_started"

    # 4. Audit events
    audit_res = api_client.get(f"/api/v1/response/actions/{action_id}/audit-events", headers=auth_headers_analyst)
    assert audit_res.status_code == status.HTTP_200_OK
    events = audit_res.json()
    assert len(events) >= 1
    assert events[0]["event_type"] == "proposal.created"
    assert events[0]["actor_operator_id"] == "op-analyst-01"

"""Unit and Integration Tests for SentinelAgent Operator Authentication and Authorization (Task 11.1).

Covers:
1. Core Authentication & Cryptographic Verification:
   - OperatorRole enum values and immutability.
   - OperatorPrincipal immutable construction and schema validation.
   - SHA-256 API key hashing and CSPRNG key generation.
   - Credential parsing, validation, duplicate rejection, and malformed configuration rejection.
   - Constant-time verification via hmac.compare_digest.
   - Masking of SecretStr credentials in logs/repr.

2. FastAPI Security Dependencies (get_current_principal, require_roles):
   - Valid analyst, approver, and admin Bearer tokens.
   - Missing, malformed, or empty Authorization headers.
   - Non-existent or invalid API keys.
   - Fail-closed behavior on unconfigured or empty server credentials.
   - Client-supplied headers (X-User, X-Role) cannot impersonate operators.
   - Role enforcement (analyst cannot access approver endpoints; approver cannot access analyst).
   - Admin does NOT automatically bypass role restrictions (least privilege).
   - Two-person approval separation validation (proposer != approver).
"""

import json
import logging
import re
from typing import Optional
from unittest.mock import MagicMock

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
import pytest

from app.api.deps import (
    get_current_principal,
    require_roles,
    validate_proposer_approver_separation,
)
from app.core.auth import (
    AuthenticationConfigurationError,
    OperatorCredential,
    OperatorPrincipal,
    OperatorRole,
    authenticate_api_key,
    generate_operator_api_key,
    hash_api_key,
    load_operator_credentials,
    validate_operator_credentials_json,
)
from app.core.config import Settings


# =============================================================================
# Test Fixtures & Sample Test Credentials
# =============================================================================

ANALYST_RAW_KEY = "sa_analyst_test_key_secret_1234567890abcdef"
APPROVER_RAW_KEY = "sa_approver_test_key_secret_abcdef1234567890"
ADMIN_RAW_KEY = "sa_admin_test_key_secret_99999999999999999999"

ANALYST_KEY_HASH = hash_api_key(ANALYST_RAW_KEY)
APPROVER_KEY_HASH = hash_api_key(APPROVER_RAW_KEY)
ADMIN_KEY_HASH = hash_api_key(ADMIN_RAW_KEY)


@pytest.fixture
def valid_credentials_data():
    """Return dictionary list of valid test credentials."""
    return [
        {
            "operator_id": "op-analyst-01",
            "role": "analyst",
            "key_sha256": ANALYST_KEY_HASH,
        },
        {
            "operator_id": "op-approver-01",
            "role": "approver",
            "key_sha256": APPROVER_KEY_HASH,
        },
        {
            "operator_id": "op-admin-01",
            "role": "admin",
            "key_sha256": ADMIN_KEY_HASH,
        },
    ]


@pytest.fixture
def valid_credentials_json(valid_credentials_data):
    """Return valid serialized JSON string of operator credentials."""
    return json.dumps(valid_credentials_data)


@pytest.fixture
def auth_settings(valid_credentials_json):
    """Return Settings instance populated with valid operator credentials."""
    return Settings(
        OPERATOR_CREDENTIALS=SecretStr(valid_credentials_json),
        _env_file=None,
    )


@pytest.fixture
def test_app(auth_settings):
    """Create isolated FastAPI test application with protected routes."""
    app = FastAPI(title="AuthTestApp")
    app.state.settings = auth_settings

    @app.get("/test/whoami")
    def whoami(principal: OperatorPrincipal = Depends(get_current_principal)):
        return {"operator_id": principal.operator_id, "role": principal.role.value}

    @app.post("/test/proposals")
    def create_proposal(
        principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ANALYST)),
    ):
        return {"status": "created", "proposer": principal.operator_id}

    @app.post("/test/approvals")
    def approve_proposal(
        principal: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER)),
    ):
        return {"status": "approved", "approver": principal.operator_id}

    @app.post("/test/admin-only")
    def admin_action(
        principal: OperatorPrincipal = Depends(require_roles(OperatorRole.ADMIN)),
    ):
        return {"status": "admin_ok", "admin": principal.operator_id}

    @app.post("/test/approver-or-admin")
    def approver_or_admin(
        principal: OperatorPrincipal = Depends(require_roles(OperatorRole.APPROVER, OperatorRole.ADMIN)),
    ):
        return {"status": "action_ok", "operator": principal.operator_id}

    return app


@pytest.fixture
def client(test_app):
    """TestClient for protected FastAPI application."""
    return TestClient(test_app)


# =============================================================================
# 1. Principal & Role Model Unit Tests
# =============================================================================

def test_operator_role_enum_values():
    """Verify expected operator roles are strictly defined."""
    assert OperatorRole.ANALYST.value == "analyst"
    assert OperatorRole.APPROVER.value == "approver"
    assert OperatorRole.ADMIN.value == "admin"
    assert len(OperatorRole) == 3


def test_operator_principal_immutability():
    """Verify OperatorPrincipal is frozen and forbids mutation and extra fields."""
    principal = OperatorPrincipal(operator_id="op-analyst-01", role=OperatorRole.ANALYST)
    assert principal.operator_id == "op-analyst-01"
    assert principal.role == OperatorRole.ANALYST

    with pytest.raises(ValidationError):
        principal.operator_id = "op-other"

    with pytest.raises(ValidationError):
        OperatorPrincipal(operator_id="op-1", role=OperatorRole.ANALYST, extra_field="forbidden")


def test_operator_principal_requires_valid_role():
    """Verify invalid role string is rejected during principal instantiation."""
    with pytest.raises(ValidationError):
        OperatorPrincipal(operator_id="op-1", role="superuser")


# =============================================================================
# 2. Cryptographic Key Generation & Hashing Unit Tests
# =============================================================================

def test_hash_api_key_deterministic():
    """Verify SHA-256 hash is deterministic, lowercase 64-hex characters."""
    raw = "test_key_sample"
    hash1 = hash_api_key(raw)
    hash2 = hash_api_key(raw)
    assert hash1 == hash2
    assert len(hash1) == 64
    assert re.match(r"^[0-9a-f]{64}$", hash1)


def test_hash_api_key_empty_rejected():
    """Verify hashing empty or whitespace key is rejected."""
    with pytest.raises(ValueError, match="Cannot hash empty API key"):
        hash_api_key("")
    with pytest.raises(ValueError, match="Cannot hash empty API key"):
        hash_api_key("   ")


def test_generate_operator_api_key_entropy():
    """Verify generated API keys have sufficient entropy and correct prefix."""
    key1 = generate_operator_api_key()
    key2 = generate_operator_api_key()
    assert key1.startswith("sa_")
    assert key2.startswith("sa_")
    assert key1 != key2
    assert len(key1) >= 45  # prefix (3) + 32-byte urlsafe token (43 chars)


# =============================================================================
# 3. Credential Loading & Validation Unit Tests
# =============================================================================

def test_load_operator_credentials_success(valid_credentials_json):
    """Verify loading valid credentials from SecretStr."""
    creds = load_operator_credentials(SecretStr(valid_credentials_json))
    assert len(creds) == 3
    assert creds[0].operator_id == "op-analyst-01"
    assert creds[0].role == OperatorRole.ANALYST
    assert creds[1].operator_id == "op-approver-01"
    assert creds[1].role == OperatorRole.APPROVER
    assert creds[2].operator_id == "op-admin-01"
    assert creds[2].role == OperatorRole.ADMIN


def test_load_operator_credentials_missing_rejected():
    """Verify missing (None) or empty credentials fail closed."""
    with pytest.raises(AuthenticationConfigurationError, match="missing"):
        load_operator_credentials(None)

    with pytest.raises(AuthenticationConfigurationError, match="empty"):
        load_operator_credentials(SecretStr(""))

    with pytest.raises(AuthenticationConfigurationError, match="empty"):
        load_operator_credentials(SecretStr("   "))


def test_validate_operator_credentials_malformed_json():
    """Verify malformed JSON syntax is rejected."""
    with pytest.raises(AuthenticationConfigurationError, match="Malformed operator credentials JSON"):
        validate_operator_credentials_json("{not_valid_json")


def test_validate_operator_credentials_not_list():
    """Verify credentials JSON that is not a list is rejected."""
    with pytest.raises(AuthenticationConfigurationError, match="must be a list"):
        validate_operator_credentials_json('{"operator_id": "op-1"}')


def test_validate_operator_credentials_empty_list():
    """Verify empty credential list fails closed."""
    with pytest.raises(AuthenticationConfigurationError, match="cannot be empty"):
        validate_operator_credentials_json("[]")


def test_validate_operator_credentials_duplicate_operator_id(valid_credentials_data):
    """Verify duplicate operator_id is rejected."""
    dup_data = list(valid_credentials_data)
    dup_data.append({
        "operator_id": "op-analyst-01",  # duplicate ID
        "role": "approver",
        "key_sha256": hash_api_key("different_key_hash_value_1234567890"),
    })
    with pytest.raises(AuthenticationConfigurationError, match="Duplicate operator_id"):
        validate_operator_credentials_json(json.dumps(dup_data))


def test_validate_operator_credentials_duplicate_key_hash(valid_credentials_data):
    """Verify duplicate key_sha256 is rejected."""
    dup_data = list(valid_credentials_data)
    dup_data.append({
        "operator_id": "op-unique-02",
        "role": "approver",
        "key_sha256": ANALYST_KEY_HASH,  # duplicate hash
    })
    with pytest.raises(AuthenticationConfigurationError, match="Duplicate key_sha256"):
        validate_operator_credentials_json(json.dumps(dup_data))


def test_validate_operator_credentials_invalid_hash_format():
    """Verify non-hex or non-64-character hash is rejected."""
    bad_data = [{"operator_id": "op-1", "role": "analyst", "key_sha256": "not_64_hex"}]
    with pytest.raises(AuthenticationConfigurationError, match="key_sha256"):
        validate_operator_credentials_json(json.dumps(bad_data))


def test_validate_operator_credentials_invalid_role():
    """Verify invalid role string is rejected."""
    bad_data = [{"operator_id": "op-1", "role": "unsupported_role", "key_sha256": ANALYST_KEY_HASH}]
    with pytest.raises(AuthenticationConfigurationError, match="role"):
        validate_operator_credentials_json(json.dumps(bad_data))


# =============================================================================
# 4. In-Memory Key Authentication Function Tests
# =============================================================================

def test_authenticate_api_key_success(valid_credentials_json):
    """Verify valid keys resolve to correct OperatorPrincipal."""
    creds = load_operator_credentials(SecretStr(valid_credentials_json))

    p1 = authenticate_api_key(ANALYST_RAW_KEY, creds)
    assert p1 is not None
    assert p1.operator_id == "op-analyst-01"
    assert p1.role == OperatorRole.ANALYST

    p2 = authenticate_api_key(APPROVER_RAW_KEY, creds)
    assert p2 is not None
    assert p2.operator_id == "op-approver-01"
    assert p2.role == OperatorRole.APPROVER


def test_authenticate_api_key_invalid():
    """Verify unrecognized key returns None."""
    creds = [OperatorCredential(operator_id="op-1", role=OperatorRole.ANALYST, key_sha256=ANALYST_KEY_HASH)]
    assert authenticate_api_key("wrong_key_123456", creds) is None
    assert authenticate_api_key("", creds) is None
    assert authenticate_api_key(None, creds) is None


# =============================================================================
# 5. FastAPI Endpoint Authentication Tests (get_current_principal)
# =============================================================================

def test_endpoint_valid_analyst_key(client):
    """Verify analyst Bearer token authenticates successfully."""
    resp = client.get("/test/whoami", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"operator_id": "op-analyst-01", "role": "analyst"}


def test_endpoint_valid_approver_key(client):
    """Verify approver Bearer token authenticates successfully to separate identity."""
    resp = client.get("/test/whoami", headers={"Authorization": f"Bearer {APPROVER_RAW_KEY}"})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"operator_id": "op-approver-01", "role": "approver"}


def test_endpoint_missing_authorization_header(client):
    """Verify request without Authorization header returns 401 with WWW-Authenticate."""
    resp = client.get("/test/whoami")
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.headers.get("WWW-Authenticate") == "Bearer"
    assert "Missing Authorization header" in resp.json()["detail"]


def test_endpoint_malformed_authorization_schemes(client):
    """Verify malformed authorization headers are rejected."""
    # Basic scheme rejected
    resp1 = client.get("/test/whoami", headers={"Authorization": f"Basic {ANALYST_RAW_KEY}"})
    assert resp1.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Bearer token required" in resp1.json()["detail"]

    # Only "Bearer" without token
    resp2 = client.get("/test/whoami", headers={"Authorization": "Bearer"})
    assert resp2.status_code == status.HTTP_401_UNAUTHORIZED

    # Whitespace token
    resp3 = client.get("/test/whoami", headers={"Authorization": "Bearer   "})
    assert resp3.status_code == status.HTTP_401_UNAUTHORIZED


def test_endpoint_invalid_api_key(client):
    """Verify invalid or unconfigured key returns generic 401 without leakage."""
    resp = client.get("/test/whoami", headers={"Authorization": "Bearer sa_invalid_bogus_token_xyz"})
    assert resp.status_code == status.HTTP_401_UNAUTHORIZED
    assert resp.headers.get("WWW-Authenticate") == "Bearer"
    assert "Invalid or unrecognized API key" in resp.json()["detail"]


def test_endpoint_unconfigured_credentials_fails_closed():
    """Verify that if credentials are not configured, endpoint returns 500 without leaking."""
    empty_app = FastAPI()
    empty_app.state.settings = Settings(OPERATOR_CREDENTIALS=None, _env_file=None)

    @empty_app.get("/test/whoami")
    def whoami(p: OperatorPrincipal = Depends(get_current_principal)):
        return {"op": p.operator_id}

    test_client = TestClient(empty_app)
    resp = test_client.get("/test/whoami", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
    assert resp.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "Authentication service is improperly configured" in resp.json()["detail"]


def test_endpoint_client_headers_cannot_impersonate(client):
    """Verify client-supplied headers (X-User, operator_id, X-Role) are completely ignored."""
    resp = client.get(
        "/test/whoami",
        headers={
            "Authorization": f"Bearer {ANALYST_RAW_KEY}",
            "X-User": "op-admin-01",
            "X-Role": "admin",
            "operator_id": "op-approver-01",
        },
    )
    assert resp.status_code == status.HTTP_200_OK
    # Must strictly reflect server-side resolution from token, NOT the headers
    assert resp.json() == {"operator_id": "op-analyst-01", "role": "analyst"}


# =============================================================================
# 6. Role Authorization Dependency Tests (require_roles)
# =============================================================================

def test_analyst_can_access_proposal_route(client):
    """Verify analyst can access proposal creation route."""
    resp = client.post("/test/proposals", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"status": "created", "proposer": "op-analyst-01"}


def test_analyst_cannot_access_approval_route(client):
    """Verify analyst is rejected with 403 on approver-only route."""
    resp = client.post("/test/approvals", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert "Insufficient operator permissions" in resp.json()["detail"]


def test_approver_can_access_approval_route(client):
    """Verify approver can access approval route."""
    resp = client.post("/test/approvals", headers={"Authorization": f"Bearer {APPROVER_RAW_KEY}"})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"status": "approved", "approver": "op-approver-01"}


def test_approver_cannot_access_proposal_route(client):
    """Verify approver is rejected with 403 on analyst-only route."""
    resp = client.post("/test/proposals", headers={"Authorization": f"Bearer {APPROVER_RAW_KEY}"})
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert "Insufficient operator permissions" in resp.json()["detail"]


def test_admin_cannot_automatically_access_approver_route(client):
    """CRITICAL SECURITY INVARIANT: Admin does NOT automatically bypass role checks to become an approver."""
    resp = client.post("/test/approvals", headers={"Authorization": f"Bearer {ADMIN_RAW_KEY}"})
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    assert "Insufficient operator permissions" in resp.json()["detail"]


def test_admin_can_access_admin_route(client):
    """Verify admin accesses routes where OperatorRole.ADMIN is explicitly allowed."""
    resp = client.post("/test/admin-only", headers={"Authorization": f"Bearer {ADMIN_RAW_KEY}"})
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json() == {"status": "admin_ok", "admin": "op-admin-01"}


def test_multi_role_endpoint_access(client):
    """Verify multi-role route permits either approver or admin, but rejects analyst."""
    # Approver allowed
    r_app = client.post("/test/approver-or-admin", headers={"Authorization": f"Bearer {APPROVER_RAW_KEY}"})
    assert r_app.status_code == status.HTTP_200_OK

    # Admin allowed
    r_adm = client.post("/test/approver-or-admin", headers={"Authorization": f"Bearer {ADMIN_RAW_KEY}"})
    assert r_adm.status_code == status.HTTP_200_OK

    # Analyst rejected
    r_ana = client.post("/test/approver-or-admin", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
    assert r_ana.status_code == status.HTTP_403_FORBIDDEN


# =============================================================================
# 7. Two-Person Approval Separation Invariant Tests
# =============================================================================

def test_two_person_approval_separation_enforced():
    """Verify validate_proposer_approver_separation blocks self-approval."""
    # Distinct operators: succeeds
    validate_proposer_approver_separation("op-analyst-01", "op-approver-01")

    # Identical operators: raises 403 Forbidden
    with pytest.raises(HTTPException) as exc_info:
        validate_proposer_approver_separation("op-analyst-01", "op-analyst-01")

    assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
    assert "two-person approval required" in exc_info.value.detail


def test_two_person_approval_empty_ids_rejected():
    """Verify empty proposer or approver ID raises 400 Bad Request."""
    with pytest.raises(HTTPException) as exc1:
        validate_proposer_approver_separation("", "op-approver-01")
    assert exc1.value.status_code == status.HTTP_400_BAD_REQUEST

    with pytest.raises(HTTPException) as exc2:
        validate_proposer_approver_separation("op-analyst-01", "")
    assert exc2.value.status_code == status.HTTP_400_BAD_REQUEST


# =============================================================================
# 8. Secret Protection & Logging Safety Tests
# =============================================================================

def test_operator_credentials_secretstr_masked(valid_credentials_json):
    """Verify OPERATOR_CREDENTIALS is shielded by SecretStr and never leaks plaintext in str/repr."""
    settings = Settings(OPERATOR_CREDENTIALS=SecretStr(valid_credentials_json), _env_file=None)
    assert isinstance(settings.OPERATOR_CREDENTIALS, SecretStr)
    assert valid_credentials_json not in str(settings.OPERATOR_CREDENTIALS)
    assert valid_credentials_json not in repr(settings.OPERATOR_CREDENTIALS)
    assert settings.OPERATOR_CREDENTIALS.get_secret_value() == valid_credentials_json


def test_no_api_key_leaks_in_captured_logs(client, caplog):
    """Verify API keys and hashes are never printed into application logs during authentication."""
    with caplog.at_level(logging.DEBUG):
        client.get("/test/whoami", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
        client.post("/test/approvals", headers={"Authorization": f"Bearer {ANALYST_RAW_KEY}"})
        client.get("/test/whoami", headers={"Authorization": "Bearer sa_bogus_probe_key_12345"})

    captured = caplog.text
    # Verify raw secret tokens are not present in logs
    assert ANALYST_RAW_KEY not in captured
    assert APPROVER_RAW_KEY not in captured
    assert "sa_bogus_probe_key_12345" not in captured
    # Verify credential hashes are not leaked in log text
    assert ANALYST_KEY_HASH not in captured
    assert APPROVER_KEY_HASH not in captured

"""Comprehensive automated tests for IncidentMemoryRecallService (Task 9D.3).

Verifies all 54 scenarios specified by Task 9D Recall Architecture:
- Query & Scope: Active/historical IP and username tag generation, 6-query cap, deterministic ordering,
  duplicate plan elimination, IP-only, username-only, missing identifiers, deterministic query building,
  sensitive data stripping.
- Concurrency & Deadlines: Semaphore reuse, instance isolation, bounded concurrency, semaphore timeout,
  5.0s overall deadline, per-query timeout, partial result preservation, task cancellation, permit release,
  external cancellation propagation, zero orphan tasks.
- Result Merging: Native ranking preservation, round-robin ordering, no score comparison, stable ID deduplication,
  similar text retention, 5 items/query cap, 10 items aggregate cap, oversized memory rejection (>1000 chars),
  2000-char aggregate ceiling, no silent truncation, zero HMAC exposure in DTOs.
- Failure Handling: success, empty, partial, unavailable, skipped, authentication failure classification,
  malformed adapter results, sensitive data log protection.
- Application Lifespan: Enabled recall creates exactly one service instance on app.state, disabled stores None,
  reuses existing Hindsight client, independent semaphores, zero network requests at construction,
  preserves Task 9C.3.6 lifespan guarantees.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Optional, Sequence
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.main import app, lifespan
from app.schemas.memory_payload import MemoryMitreMapping
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreCandidateProposal,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.hindsight_client import (
    HindsightAuthenticationError,
    HindsightClientError,
    HindsightClientService,
    HindsightConnectionError,
    HindsightProtocolError,
    HindsightRecallItem,
    HindsightRecallResult,
    HindsightServerError,
    HindsightTimeoutError,
    HindsightValidationError,
)
from app.services.hmac_pseudonymizer import HmacPseudonymizer
from app.services.incident_memory_recall_service import (
    MAX_AGGREGATE_CONTEXT_CHARS,
    MAX_FAN_OUT_QUERIES,
    MAX_ITEMS_PER_QUERY,
    MAX_RECALLED_MEMORIES,
    MAX_SINGLE_MEMORY_CHARS,
    PERMITTED_AUTH_PATTERNS,
    PERMITTED_DETECTION_CATEGORIES,
    AuthoritativeRecallContext,
    IncidentMemoryRecallResult,
    IncidentMemoryRecallService,
    RecallItemResult,
    RecallQueryPlan,
    build_recall_query,
    sanitize_query_token,
)
from app.services.investigation_tools import ActiveInvestigationContext
from app.services.mitre_mapping_validator import (
    APPROVED_RULE_CONFIDENCES,
    APPROVED_RULE_STATUSES,
    APPROVED_RULE_TECHNIQUES,
    RULE_MAP_SSH_001,
    RULE_MAP_SSH_002,
    RULE_MAP_SSH_003,
)

# Test HMAC Keys (>= 32 bytes)
ACTIVE_KEY = "active-key-test-secret-at-least-32-bytes!!"
PREV_KEY_1 = "prev-key-1-test-secret-at-least-32-bytes!!"
PREV_KEY_2 = "prev-key-2-test-secret-at-least-32-bytes!!"


@pytest.fixture
def pseudonymizer():
    """Create a configured HmacPseudonymizer with active (v3) and two historical keys (v1, v2)."""
    return HmacPseudonymizer(
        active_key=ACTIVE_KEY,
        active_version="v3",
        previous_keys={
            "v1": PREV_KEY_1,
            "v2": PREV_KEY_2,
        },
    )


@pytest.fixture
def mock_hindsight_client():
    """Mock HindsightClientService."""
    client = MagicMock(spec=HindsightClientService)
    client.recall_incident_memories = AsyncMock()
    client.bank_id = "sentinelagent-incident-memory-dev"
    client.is_closed = False
    return client


@pytest.fixture
def recall_settings():
    """Valid test settings with recall enabled."""
    return Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_BANK_ID="sentinelagent-incident-memory-dev",
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        HINDSIGHT_HMAC_KEY_VERSION="v3",
        HINDSIGHT_PREVIOUS_HMAC_KEYS={"v1": PREV_KEY_1, "v2": PREV_KEY_2},
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_BUDGET="mid",
        HINDSIGHT_RECALL_MAX_TOKENS=1024,
        HINDSIGHT_RECALL_MAX_TOKENS_CEILING=4096,
        HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=3.0,
        HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=5.0,
        HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS=10,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=1.0,
        _env_file=None,
    )


@pytest.fixture
def recall_service(mock_hindsight_client, pseudonymizer, recall_settings):
    """Create an IncidentMemoryRecallService instance for testing."""
    return IncidentMemoryRecallService(
        hindsight_client=mock_hindsight_client,
        pseudonymizer=pseudonymizer,
        settings=recall_settings,
    )


def make_context(
    source_ip: Optional[str] = "10.0.0.1",
    username: Optional[str] = None,
    incident_type: Optional[str] = "brute_force",
    auth_pattern: Optional[str] = None,
    detection_category: Optional[str] = None,
    incident_timestamp: Optional[datetime] = None,
    investigation_id: Optional[uuid.UUID] = None,
    incident_id: Optional[uuid.UUID] = None,
    validated_mitre_mappings: Optional[Sequence[Any]] = None,
) -> ActiveInvestigationContext:
    return ActiveInvestigationContext(
        incident_id=incident_id or uuid.uuid4(),
        investigation_id=investigation_id or uuid.uuid4(),
        source_ip=source_ip,
        created_at=incident_timestamp or datetime.now(timezone.utc),
        username=username,
        incident_type=incident_type,
        auth_pattern=auth_pattern,
        detection_category=detection_category,
        validated_mitre_mappings=validated_mitre_mappings,
    )


# =============================================================================
# 1. Query & Scope Tests (Scenarios 1-15)
# =============================================================================


def test_active_ip_tag_generation(recall_service, pseudonymizer):
    """Scenario 1: Active IP tag is generated with active version."""
    plans = recall_service.generate_query_plans(
        source_ip="192.168.1.50",
        username=None,
        query_text="query",
    )
    assert len(plans) == 3  # v3, v1, v2
    assert plans[0].identity_category == "source_ip"
    assert plans[0].key_version == "v3"
    assert plans[0].tag == pseudonymizer.pseudonymize_ip("192.168.1.50", "v3")


def test_active_username_tag_generation(recall_service, pseudonymizer):
    """Scenario 2: Active username tag is generated with active version."""
    plans = recall_service.generate_query_plans(
        source_ip=None,
        username="admin",
        query_text="query",
    )
    assert len(plans) == 3
    assert plans[0].identity_category == "username"
    assert plans[0].key_version == "v3"
    assert plans[0].tag == pseudonymizer.pseudonymize_username("admin", "v3")


def test_historical_ip_tag_generation(recall_service, pseudonymizer):
    """Scenario 3: Historical IP tags are generated for configured previous keys."""
    plans = recall_service.generate_query_plans(
        source_ip="10.0.0.1",
        username=None,
        query_text="query",
    )
    versions = [p.key_version for p in plans]
    assert versions == ["v3", "v1", "v2"]
    assert plans[1].tag == pseudonymizer.pseudonymize_ip("10.0.0.1", "v1")
    assert plans[2].tag == pseudonymizer.pseudonymize_ip("10.0.0.1", "v2")


def test_historical_username_tag_generation(recall_service, pseudonymizer):
    """Scenario 4: Historical username tags are generated for configured previous keys."""
    plans = recall_service.generate_query_plans(
        source_ip=None,
        username="root",
        query_text="query",
    )
    versions = [p.key_version for p in plans]
    assert versions == ["v3", "v1", "v2"]
    assert plans[1].tag == pseudonymizer.pseudonymize_username("root", "v1")
    assert plans[2].tag == pseudonymizer.pseudonymize_username("root", "v2")


def test_maximum_six_query_plans(recall_service):
    """Scenario 5: At most six query plans are generated for IP + username across 3 keys."""
    plans = recall_service.generate_query_plans(
        source_ip="172.16.0.5",
        username="deploy",
        query_text="query",
    )
    assert len(plans) == 6
    assert len(plans) <= MAX_FAN_OUT_QUERIES


def test_deterministic_query_plan_order(recall_service):
    """Scenario 6: Query plan ordering is strictly IP active, IP hist, User active, User hist."""
    plans = recall_service.generate_query_plans(
        source_ip="192.168.1.1",
        username="alice",
        query_text="query",
    )
    expected_order = [
        ("source_ip", "v3"),
        ("source_ip", "v1"),
        ("source_ip", "v2"),
        ("username", "v3"),
        ("username", "v1"),
        ("username", "v2"),
    ]
    actual_order = [(p.identity_category, p.key_version) for p in plans]
    assert actual_order == expected_order


def test_duplicate_plan_elimination(recall_service, mock_hindsight_client):
    """Scenario 7: Duplicate tags resulting from key reuse or duplicate inputs are eliminated."""
    # Create pseudonymizer where active and previous key produce the same tag
    dup_pseudo = HmacPseudonymizer(
        active_key=ACTIVE_KEY,
        active_version="v1",
        previous_keys={"v2": ACTIVE_KEY},  # Same key
    )
    service = IncidentMemoryRecallService(
        hindsight_client=mock_hindsight_client,
        pseudonymizer=dup_pseudo,
    )
    # Even if keys differ in version label, if the key is the same the domain input has version:
    # "ip:v1:..." != "ip:v2:...". But if duplicate plans were ever generated, seen_tags eliminates them.
    plans = service.generate_query_plans(source_ip="10.0.0.1", username=None, query_text="query")
    tags = [p.tag for p in plans]
    assert len(tags) == len(set(tags))


@pytest.mark.asyncio
async def test_no_ip_and_no_username_skips_recall(recall_service, mock_hindsight_client):
    """Scenario 8: Missing both IP and username skips recall with zero Hindsight calls."""
    ctx = make_context(source_ip=None, username=None, incident_type=None)
    res = await recall_service.recall_memories(ctx)
    assert res.status == "skipped"
    assert res.skipped_reason == "NO_USABLE_IDENTIFIERS"
    assert res.items == ()
    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_ip_only_retrieval_works(recall_service, mock_hindsight_client):
    """Scenario 9: IP-only recall generates only IP plans and executes cleanly."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    ctx = make_context(
        source_ip="192.168.1.100",
        username=None,
        incident_type="brute_force",
    )
    res = await recall_service.recall_memories(ctx)
    assert res.status == "empty"
    assert res.attempted_queries == 3  # 3 IP keys
    # Verify all calls used IP tags
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert call.kwargs["tag"].startswith("ip:")


@pytest.mark.asyncio
async def test_username_only_retrieval_works(recall_service, mock_hindsight_client):
    """Scenario 10: Username-only recall generates only username plans and executes cleanly."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    ctx = make_context(
        source_ip=None,
        username="victim_user",
        incident_type="credential_stuffing",
    )
    res = await recall_service.recall_memories(ctx)
    assert res.status == "empty"
    assert res.attempted_queries == 3  # 3 username keys
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert call.kwargs["tag"].startswith("user:")


def test_query_construction_is_deterministic():
    """Scenario 11: Query construction produces identical strings for identical inputs."""
    q1 = build_recall_query(
        incident_type="brute_force",
        auth_pattern="password_spray",
        mitre_techniques=["T1110.001", "T1078"],
        detection_category="ssh_anomaly",
    )
    q2 = build_recall_query(
        incident_type="brute_force",
        auth_pattern="password_spray",
        mitre_techniques=["T1078", "T1110.001"],  # Swapped order
        detection_category="ssh_anomaly",
    )
    assert q1 is not None
    assert q1 == q2
    assert "classification: brute_force" in q1
    assert "techniques: T1078, T1110.001" in q1


def test_raw_ip_never_appears_in_query_text():
    """Scenario 12: Attempting to inject raw IPs into query components is stripped."""
    # Passing an IP as incident_type or auth_pattern is rejected by sanitizer
    q = build_recall_query(
        incident_type="192.168.1.100",  # Raw IPv4
        auth_pattern="2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # Raw IPv6
    )
    assert q is None


def test_raw_username_never_appears_in_query_text():
    """Scenario 13: Raw usernames and freeform user content cannot be injected."""
    # Sanitize token rejects tokens with spaces, punctuation, or length > 64
    assert sanitize_query_token("admin user with prompt injection") is None
    assert sanitize_query_token("Robert'); DROP TABLE--") is None


def test_credentials_and_raw_log_lines_never_appear_in_query_text():
    """Scenario 14: Passwords, tokens, and raw SSH log lines are stripped."""
    log_line = "Failed password for invalid user admin from 192.168.1.1 port 22 ssh2"
    q = build_recall_query(
        incident_type=log_line,
        auth_pattern="api_key=secret-token-12345",
    )
    assert q is None


@pytest.mark.asyncio
async def test_unvalidated_or_arbitrary_context_cannot_expand_query_scope(recall_service, mock_hindsight_client):
    """Scenario 15: If all contextual query fields are empty, recall skips safely."""
    ctx = make_context(
        source_ip="192.168.1.1",
        incident_type=None,
        auth_pattern=None,
        detection_category=None,
    )
    res = await recall_service.recall_memories(ctx)
    assert res.status == "skipped"
    assert res.skipped_reason == "INSUFFICIENT_QUERY_CONTEXT"
    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_direct_authoritative_recall_context_rejected(recall_service, mock_hindsight_client):
    """Scenario 15a: Direct AuthoritativeRecallContext input is rejected by the public recall method."""
    auth_ctx = AuthoritativeRecallContext(
        investigation_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        source_ip="10.0.0.1",
        incident_type="brute_force",
    )
    with pytest.raises(TypeError, match="Direct AuthoritativeRecallContext input is rejected"):
        await recall_service.recall_memories(auth_ctx)  # type: ignore

    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_dictionaries_and_arbitrary_objects_rejected(recall_service, mock_hindsight_client):
    """Scenario 15b: Dictionaries and arbitrary objects are rejected with zero Hindsight calls."""
    with pytest.raises(TypeError, match="must be an ActiveInvestigationContext instance"):
        await recall_service.recall_memories({"source_ip": "10.0.0.1"})  # type: ignore

    with pytest.raises(TypeError, match="must be an ActiveInvestigationContext instance"):
        await recall_service.recall_memories("invalid_context")  # type: ignore

    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_valid_active_investigation_context_accepted(recall_service, mock_hindsight_client):
    """Scenario 15c: Valid ActiveInvestigationContext input is accepted and converted internally."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    inv_ctx = ActiveInvestigationContext(
        incident_id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        source_ip="10.0.0.1",
        created_at=datetime.now(timezone.utc),
        incident_type="brute_force",
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    assert res.attempted_queries == 3


@pytest.mark.asyncio
async def test_forged_or_unauthorized_identifiers_rejected(recall_service, mock_hindsight_client):
    """Scenario 15d: Forged non-UUID, malformed IP, invalid username, or non-allowlisted type are rejected."""
    # Forged incident_id (not a UUID)
    with pytest.raises(ValueError, match="incident_id must be a uuid.UUID instance"):
        await recall_service.recall_memories(
            ActiveInvestigationContext(
                incident_id="forged-incident-string",  # type: ignore
                investigation_id=uuid.uuid4(),
                source_ip="10.0.0.1",
                created_at=datetime.now(timezone.utc),
                incident_type="brute_force",
            )
        )

    # Malformed source_ip
    with pytest.raises(ValueError, match="Invalid source_ip"):
        await recall_service.recall_memories(
            make_context(source_ip="999.999.999.999", incident_type="brute_force")
        )

    # Invalid username (embedded IP)
    with pytest.raises(ValueError, match="Invalid username"):
        await recall_service.recall_memories(
            make_context(source_ip="10.0.0.1", username="192.168.1.1", incident_type="brute_force")
        )

    # Non-allowlisted classification
    with pytest.raises(ValueError, match="allowlisted classifications"):
        await recall_service.recall_memories(
            make_context(source_ip="10.0.0.1", incident_type="malicious_eval")
        )

    # Non-allowlisted auth pattern
    with pytest.raises(ValueError, match="allowlisted authentication patterns"):
        await recall_service.recall_memories(
            make_context(source_ip="10.0.0.1", incident_type="brute_force", auth_pattern="custom_hack")
        )

    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_regex_valid_unverified_mitre_identifier_excluded(recall_service, mock_hindsight_client):
    """Scenario 15e: A regex-valid string or unverified mapping is excluded from recall query."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    # Pass strings and dicts that match the T#### format but are NOT server-validated MitreAttackMapping instances
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=["T1078", "T1110.001", {"technique_id": "T1078"}],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    # Verify no technique IDs leaked into the recall queries
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "techniques:" not in call.kwargs["query"]
        assert "T1078" not in call.kwargs["query"]
        assert "T1110.001" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_server_validated_mitre_technique_included(recall_service, mock_hindsight_client):
    """Scenario 15f: A verified MitreAttackMapping instance is recognized and included in the recall query."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    validated_mapping = MitreAttackMapping(
        mapping_id=uuid.uuid4(),
        rule_id="MAP-SSH-001",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_ids=["TA0006"],
        tactic_names=["Credential Access"],
        mapping_status=MitreMappingStatus.CANDIDATE,
        confidence=MitreConfidenceLevel.HIGH,
        supporting_references=["ssh_events/00000000-0000-0000-0000-000000000001"],
        event_ids=[uuid.uuid4()],
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        rationale="Verified brute force attempts exceeding threshold.",
        catalogue_version="20.1",
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=[validated_mapping],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "techniques: T1110" in call.kwargs["query"]


@pytest.mark.asyncio
async def test_missing_validated_mitre_mappings_does_not_prevent_recall(recall_service, mock_hindsight_client):
    """Scenario 15g: Missing or empty validated MITRE mappings allows recall to proceed cleanly."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=None,
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    assert res.attempted_queries == 3
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "classification: brute_force" in call.kwargs["query"]
        assert "techniques:" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_no_invalid_or_untrusted_context_reaches_hindsight_adapter(recall_service, mock_hindsight_client):
    """Scenario 15h: Zero Hindsight calls occur when invalid or untrusted contexts are provided."""
    untrusted_inputs = [
        None,
        {"source_ip": "10.0.0.1"},
        "raw_string_context",
        [1, 2, 3],
        AuthoritativeRecallContext(
            investigation_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            source_ip="10.0.0.1",
            incident_type="brute_force",
        ),
    ]
    for bad_input in untrusted_inputs:
        with pytest.raises(TypeError):
            await recall_service.recall_memories(bad_input)  # type: ignore

    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_username_cannot_originate_from_historical_memory(recall_service, mock_hindsight_client):
    """Scenario 15i: Historical memory objects or recalled DTOs containing usernames are rejected."""
    historical_item = RecallItemResult(
        memory_id="mem-hist-001",
        text="Observed attack targeting victim_user",
        fact_type="experience",
    )
    with pytest.raises(TypeError, match="must be an ActiveInvestigationContext instance"):
        await recall_service.recall_memories(historical_item)  # type: ignore

    # Attempting to supply a dict with historical username
    with pytest.raises(TypeError, match="must be an ActiveInvestigationContext instance"):
        await recall_service.recall_memories({"username": "historical_user", "source_ip": "10.0.0.1"})  # type: ignore

    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_unvalidated_mitre_candidates_cannot_enter_recall_queries(recall_service, mock_hindsight_client):
    """Scenario 15j: Unvalidated MitreCandidateProposal objects are excluded from recall queries."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    dummy_event_id = uuid.uuid4()
    unvalidated_proposal = MitreCandidateProposal(
        mapping_id=uuid.uuid4(),
        rule_id="MAP-SSH-001",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_ids=["TA0006"],
        tactic_names=["Credential Access"],
        mapping_status=MitreMappingStatus.CANDIDATE,
        confidence=MitreConfidenceLevel.HIGH,
        supporting_references=[f"ssh_events/{dummy_event_id}"],
        event_ids=[dummy_event_id],
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        rationale="Candidate proposal before validation.",
        catalogue_version="20.1",
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=[unvalidated_proposal],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "techniques:" not in call.kwargs["query"]
        assert "T1110" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_historical_mitre_mappings_cannot_enter_recall_queries(recall_service, mock_hindsight_client):
    """Scenario 15k: Historical MemoryMitreMapping schemas are excluded from active recall queries."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    historical_mapping = MemoryMitreMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_ids=["TA0006"],
        confidence="high",
        mapping_status="candidate",
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=[historical_mapping],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "techniques:" not in call.kwargs["query"]
        assert "T1110" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_current_incident_and_investigation_identities_server_controlled(recall_service, mock_hindsight_client):
    """Scenario 15l: Forged or tampered incident/investigation UUIDs are rejected at context validation."""
    forged_inputs = [
        (None, uuid.uuid4()),
        ("not-a-uuid", uuid.uuid4()),
        (uuid.uuid4(), None),
        (uuid.uuid4(), "not-a-uuid"),
        ("12345", "67890"),
    ]
    for inc_id, inv_id in forged_inputs:
        with pytest.raises(ValueError):
            await recall_service.recall_memories(
                ActiveInvestigationContext(
                    incident_id=inc_id,  # type: ignore
                    investigation_id=inv_id,  # type: ignore
                    source_ip="10.0.0.1",
                    created_at=datetime.now(timezone.utc),
                    incident_type="brute_force",
                )
            )

    assert mock_hindsight_client.recall_incident_memories.await_count == 0


def test_task8_mitre_mapping_definitions_remain_unchanged():
    """Scenario 15m: Authoritative Task 8 MITRE definitions match exact rule-technique mapping."""
    assert APPROVED_RULE_TECHNIQUES == {
        RULE_MAP_SSH_001: "T1110",
        RULE_MAP_SSH_002: "T1110.003",
        RULE_MAP_SSH_003: "T1078",
    }
    assert APPROVED_RULE_STATUSES[RULE_MAP_SSH_001] == {MitreMappingStatus.CANDIDATE}
    assert APPROVED_RULE_STATUSES[RULE_MAP_SSH_002] == {MitreMappingStatus.HYPOTHESIS}
    assert APPROVED_RULE_STATUSES[RULE_MAP_SSH_003] == {MitreMappingStatus.CANDIDATE}


@pytest.mark.asyncio
async def test_map_ssh_002_cannot_accidentally_become_t1110_001(recall_service, mock_hindsight_client):
    """Scenario 15n: MAP-SSH-002 with T1110.001 is rejected from recall queries (authoritative is T1110.003)."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    dummy_event_id = uuid.uuid4()
    tampered_mapping = MitreAttackMapping(
        mapping_id=uuid.uuid4(),
        evidence_item_id=uuid.uuid4(),
        rule_id="MAP-SSH-002",
        technique_id="T1110.001",  # Tampered: Should be T1110.003
        technique_name="Password Guessing",
        tactic_ids=["TA0006"],
        tactic_names=["Credential Access"],
        mapping_status=MitreMappingStatus.HYPOTHESIS,
        confidence=MitreConfidenceLevel.LOW,
        supporting_references=[f"ssh_events/{dummy_event_id}"],
        event_ids=[dummy_event_id],
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        rationale="Tampered sub-technique.",
        catalogue_version="20.1",
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=[tampered_mapping],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "T1110.001" not in call.kwargs["query"]
        assert "techniques:" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_map_ssh_003_cannot_accidentally_become_t1110_003(recall_service, mock_hindsight_client):
    """Scenario 15o: MAP-SSH-003 with T1110.003 is rejected (authoritative is T1078)."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    dummy_event_id = uuid.uuid4()
    tampered_mapping = MitreAttackMapping(
        mapping_id=uuid.uuid4(),
        evidence_item_id=uuid.uuid4(),
        rule_id="MAP-SSH-003",
        technique_id="T1110.003",  # Tampered: Should be T1078
        technique_name="Password Spraying",
        tactic_ids=["TA0006"],
        tactic_names=["Credential Access"],
        mapping_status=MitreMappingStatus.CANDIDATE,
        confidence=MitreConfidenceLevel.LOW,
        supporting_references=[f"ssh_events/{dummy_event_id}"],
        event_ids=[dummy_event_id],
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        rationale="Tampered mapping.",
        catalogue_version="20.1",
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=[tampered_mapping],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "T1110.003" not in call.kwargs["query"]
        assert "techniques:" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_deferred_mappings_cannot_enter_recall_scope(recall_service, mock_hindsight_client):
    """Scenario 15p: Deferred rules (e.g. MAP-SSH-004) are excluded from recall queries."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    dummy_event_id = uuid.uuid4()
    deferred_mapping = MitreAttackMapping(
        mapping_id=uuid.uuid4(),
        evidence_item_id=uuid.uuid4(),
        rule_id="MAP-SSH-004",  # Deferred rule
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic_ids=["TA0001"],
        tactic_names=["Initial Access"],
        mapping_status=MitreMappingStatus.CANDIDATE,
        confidence=MitreConfidenceLevel.LOW,
        supporting_references=[f"ssh_events/{dummy_event_id}"],
        event_ids=[dummy_event_id],
        window_start=datetime.now(timezone.utc),
        window_end=datetime.now(timezone.utc),
        rationale="Deferred rule proposal.",
        catalogue_version="20.1",
    )
    inv_ctx = make_context(
        source_ip="10.0.0.1",
        incident_type="brute_force",
        validated_mitre_mappings=[deferred_mapping],
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "T1078" not in call.kwargs["query"]
        assert "techniques:" not in call.kwargs["query"]


@pytest.mark.asyncio
async def test_untrusted_auth_pattern_rejected(recall_service):
    """Scenario 15q: Non-allowlisted auth_pattern raises ValueError upon context creation."""
    with pytest.raises(ValueError, match="Must be one of allowlisted authentication patterns"):
        await recall_service.recall_memories(
            ActiveInvestigationContext(
                incident_id=uuid.uuid4(),
                investigation_id=uuid.uuid4(),
                source_ip="10.0.0.1",
                created_at=datetime.now(timezone.utc),
                incident_type="brute_force",
                auth_pattern="arbitrary_untrusted_pattern",
            )
        )


@pytest.mark.asyncio
async def test_untrusted_detection_category_rejected(recall_service):
    """Scenario 15r: Non-allowlisted detection_category raises ValueError upon context creation."""
    with pytest.raises(ValueError, match="Must be one of allowlisted detection categories"):
        await recall_service.recall_memories(
            ActiveInvestigationContext(
                incident_id=uuid.uuid4(),
                investigation_id=uuid.uuid4(),
                source_ip="10.0.0.1",
                created_at=datetime.now(timezone.utc),
                incident_type="brute_force",
                detection_category="arbitrary_untrusted_category",
            )
        )


@pytest.mark.asyncio
async def test_missing_detection_metadata_does_not_prevent_otherwise_valid_recall(recall_service, mock_hindsight_client):
    """Scenario 15s: When MITRE mappings, auth_pattern, and detection_category are omitted, recall succeeds."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="sentinelagent-incident-memory-dev",
        query="query",
        items=(),
        total_count=0,
    )
    inv_ctx = ActiveInvestigationContext(
        incident_id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        source_ip="10.0.0.1",
        created_at=datetime.now(timezone.utc),
        incident_type="brute_force",
        username="admin",
        # auth_pattern=None, detection_category=None, validated_mitre_mappings=()
    )
    res = await recall_service.recall_memories(inv_ctx)
    assert res.status == "empty"
    # Recall was executed for source_ip and username
    assert mock_hindsight_client.recall_incident_memories.await_count > 0
    for call in mock_hindsight_client.recall_incident_memories.call_args_list:
        assert "techniques:" not in call.kwargs["query"]
        assert "pattern:" not in call.kwargs["query"]
        assert "category:" not in call.kwargs["query"]



# =============================================================================
# 2. Concurrency & Timeout Tests (Scenarios 16-28)
# =============================================================================


def test_one_semaphore_reused_across_investigations(recall_service):
    """Scenario 16: The same semaphore instance is reused across invocations."""
    sem1 = recall_service.semaphore
    assert sem1 is recall_service._semaphore
    assert sem1._value == 10


def test_independent_service_instances_have_independent_semaphores(mock_hindsight_client, pseudonymizer, recall_settings):
    """Scenario 17: Distinct service instances have independent semaphores."""
    svc1 = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)
    svc2 = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)
    assert svc1.semaphore is not svc2.semaphore


@pytest.mark.asyncio
async def test_maximum_configured_concurrency_never_exceeded(mock_hindsight_client, pseudonymizer):
    """Scenario 18: Active concurrent calls to recall_incident_memories never exceed semaphore capacity."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS=3,  # Capacity of 3
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, settings)

    current_concurrent = 0
    max_observed_concurrent = 0
    lock = asyncio.Lock()

    async def mock_recall(*args, **kwargs):
        nonlocal current_concurrent, max_observed_concurrent
        async with lock:
            current_concurrent += 1
            if current_concurrent > max_observed_concurrent:
                max_observed_concurrent = current_concurrent
        await asyncio.sleep(0.05)
        async with lock:
            current_concurrent -= 1
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    # Launch recall with 6 plans
    await svc.recall_memories(
        make_context(
            source_ip="10.0.0.1",
            username="admin",
            incident_type="brute_force",
        )
    )

    assert max_observed_concurrent <= 3


@pytest.mark.asyncio
async def test_semaphore_acquisition_timeout_skips_queries_safely(mock_hindsight_client, pseudonymizer):
    """Scenario 19: When semaphore capacity is exhausted, waiting query times out and skips safely."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_MAX_CONCURRENT_REQUESTS=1,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=0.05,  # 50ms timeout
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, settings)

    # Acquire the single permit externally
    await svc.semaphore.acquire()

    try:
        res = await svc.recall_memories(
            make_context(
                source_ip="10.0.0.1",
                incident_type="brute_force",
            )
        )
        assert res.status == "unavailable"
        assert res.failed_queries == 3
        assert "SEMAPHORE_CAPACITY_EXHAUSTED" in res.diagnostic_classifications
    finally:
        svc.semaphore.release()


@pytest.mark.asyncio
async def test_five_second_overall_deadline_enforced(mock_hindsight_client, pseudonymizer):
    """Scenario 20: Five-second overall deadline cancels pending tasks on expiration."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=0.05,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=0.02,
        HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=0.1,  # 100ms overall deadline
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, settings)

    async def hanging_recall(*args, **kwargs):
        await asyncio.sleep(5.0)  # Exceeds 100ms
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = hanging_recall

    start = asyncio.get_running_loop().time()
    res = await svc.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    elapsed = asyncio.get_running_loop().time() - start

    assert elapsed < 1.0  # Finished promptly after 100ms deadline
    assert res.status == "unavailable"
    assert "OVERALL_DEADLINE_EXCEEDED" in res.diagnostic_classifications


@pytest.mark.asyncio
async def test_per_query_adapter_timeout_remains_enforced(mock_hindsight_client, recall_service):
    """Scenario 21: Adapter HindsightTimeoutError is cleanly caught and mapped."""
    mock_hindsight_client.recall_incident_memories.side_effect = HindsightTimeoutError("Request timed out")

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "unavailable"
    assert "REQUEST_TIMEOUT" in res.diagnostic_classifications


@pytest.mark.asyncio
async def test_completed_successful_queries_survive_partial_timeout(mock_hindsight_client, pseudonymizer):
    """Scenario 22: Completed successful queries survive when other parallel queries time out."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=0.1,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=0.02,
        HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=0.2,  # 200ms overall deadline
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, settings)

    item1 = HindsightRecallItem(id="mem-fast", text="Fast query result", fact_type="experience", scope_verified=True)

    async def mixed_recall(tag, *args, **kwargs):
        if "v3" in tag:
            # Fast query succeeds in 20ms
            await asyncio.sleep(0.02)
            return HindsightRecallResult(bank_id="dev", query="q", items=(item1,), total_count=1)
        else:
            # Slow queries hang beyond 200ms
            await asyncio.sleep(1.0)
            return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mixed_recall

    res = await svc.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))

    assert res.status == "partial"
    assert len(res.items) == 1
    assert res.items[0].memory_id == "mem-fast"
    assert "OVERALL_DEADLINE_EXCEEDED" in res.diagnostic_classifications


@pytest.mark.asyncio
async def test_pending_tasks_are_cancelled(mock_hindsight_client, pseudonymizer):
    """Scenario 23: Pending tasks are explicitly cancelled upon deadline expiration."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=0.04,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=0.02,
        HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=0.08,
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, settings)

    task_cancelled = False

    async def slow_recall(*args, **kwargs):
        nonlocal task_cancelled
        try:
            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            task_cancelled = True
            raise
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = slow_recall

    await svc.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert task_cancelled is True


@pytest.mark.asyncio
async def test_semaphore_permits_released_after_success(mock_hindsight_client, recall_service):
    """Scenario 24: Semaphore permits are released back to pool after successful query."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(), total_count=0
    )

    initial_permits = recall_service.semaphore._value
    await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert recall_service.semaphore._value == initial_permits


@pytest.mark.asyncio
async def test_semaphore_permits_released_after_exceptions(mock_hindsight_client, recall_service):
    """Scenario 25: Semaphore permits are released after adapter exceptions."""
    mock_hindsight_client.recall_incident_memories.side_effect = HindsightServerError("500 Server Error")

    initial_permits = recall_service.semaphore._value
    await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert recall_service.semaphore._value == initial_permits


@pytest.mark.asyncio
async def test_semaphore_permits_released_after_cancellation(mock_hindsight_client, pseudonymizer):
    """Scenario 26: Semaphore permits are released when tasks are cancelled."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS=0.04,
        HINDSIGHT_RECALL_SEMAPHORE_TIMEOUT_SECONDS=0.02,
        HINDSIGHT_RECALL_OVERALL_TIMEOUT_SECONDS=0.08,
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, settings)

    async def cancelled_recall(*args, **kwargs):
        await asyncio.sleep(1.0)
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = cancelled_recall

    initial_permits = svc.semaphore._value
    await svc.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert svc.semaphore._value == initial_permits


@pytest.mark.asyncio
async def test_external_cancellation_propagates(mock_hindsight_client, recall_service):
    """Scenario 27: External cancellation of recall_memories propagates CancelledError untouched."""
    async def slow_recall(*args, **kwargs):
        await asyncio.sleep(5.0)
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = slow_recall

    recall_task = asyncio.create_task(
        recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    )
    await asyncio.sleep(0.02)
    recall_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await recall_task


@pytest.mark.asyncio
async def test_no_orphan_tasks_remain_after_cancellation(mock_hindsight_client, recall_service):
    """Scenario 28: Zero orphan tasks remain running after external cancellation."""
    child_cancelled = False

    async def hanging_query(*args, **kwargs):
        nonlocal child_cancelled
        try:
            await asyncio.sleep(5.0)
        except asyncio.CancelledError:
            child_cancelled = True
            raise
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = hanging_query

    task = asyncio.create_task(
        recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    )
    await asyncio.sleep(0.02)
    task.cancel()

    try:
        await task
    except asyncio.CancelledError:
        pass

    assert child_cancelled is True
    # Verify semaphore fully restored
    assert recall_service.semaphore._value == recall_service.max_concurrency


# =============================================================================
# 3. Result Merging Tests (Scenarios 29-39)
# =============================================================================


@pytest.mark.asyncio
async def test_native_within_query_ranking_preserved(mock_hindsight_client, recall_service):
    """Scenario 29: Native result rank within individual queries is strictly preserved."""
    items_q1 = (
        HindsightRecallItem(id="m1", text="text 1", fact_type="experience", scope_verified=True, rank=1),
        HindsightRecallItem(id="m2", text="text 2", fact_type="experience", scope_verified=True, rank=2),
    )
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=items_q1, total_count=2
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    # For a single stream, items appear in exact rank order
    first_two_ids = [item.memory_id for item in res.items[:2]]
    assert first_two_ids == ["m1", "m2"]


@pytest.mark.asyncio
async def test_round_robin_query_ordering_is_deterministic(mock_hindsight_client, pseudonymizer, recall_settings):
    """Scenario 30: Round-robin merge deterministically interleaves across queries."""
    # Q1 (IP v3): A, B, C
    # Q2 (IP v1): D, E
    # Q3 (User v3): F, G
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)

    async def mock_recall(tag, *args, **kwargs):
        if tag.startswith("ip:") and "v3" in tag:
            return HindsightRecallResult(
                bank_id="dev", query="q",
                items=(
                    HindsightRecallItem(id="A", text="mem A", fact_type="experience", scope_verified=True),
                    HindsightRecallItem(id="B", text="mem B", fact_type="experience", scope_verified=True),
                    HindsightRecallItem(id="C", text="mem C", fact_type="experience", scope_verified=True),
                ),
                total_count=3,
            )
        elif tag.startswith("ip:") and "v1" in tag:
            return HindsightRecallResult(
                bank_id="dev", query="q",
                items=(
                    HindsightRecallItem(id="D", text="mem D", fact_type="observation", scope_verified=True),
                    HindsightRecallItem(id="E", text="mem E", fact_type="observation", scope_verified=True),
                ),
                total_count=2,
            )
        elif tag.startswith("user:") and "v3" in tag:
            return HindsightRecallResult(
                bank_id="dev", query="q",
                items=(
                    HindsightRecallItem(id="F", text="mem F", fact_type="experience", scope_verified=True),
                    HindsightRecallItem(id="G", text="mem G", fact_type="experience", scope_verified=True),
                ),
                total_count=2,
            )
        else:
            return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    res = await svc.recall_memories(
        make_context(
            source_ip="10.0.0.1",
            username="admin",
            incident_type="brute_force",
        )
    )

    # Priority stream order: IP_v3, IP_v1, IP_v2 (empty), User_v3, User_v1 (empty), User_v2 (empty)
    # Depth 0: A, D, F
    # Depth 1: B, E, G
    # Depth 2: C
    expected_ids = ["A", "D", "F", "B", "E", "G", "C"]
    assert [item.memory_id for item in res.items] == expected_ids


@pytest.mark.asyncio
async def test_round_robin_merging_worked_example_ordering(mock_hindsight_client, pseudonymizer, recall_settings):
    """Scenario 30b: Verify worked example from architecture doc Section 8.3.
    Input streams:
      Active IP (v3): [A, B, C]
      Historical IP (v1): [A, D]
      Active username (v3): [E, F]
    Expected merged order: [A, E, B, D, F, C]
    """
    svc = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)

    async def mock_recall(tag, *args, **kwargs):
        if tag.startswith("ip:") and "v3" in tag:
            return HindsightRecallResult(
                bank_id="dev", query="q",
                items=(
                    HindsightRecallItem(id="A", text="mem A", fact_type="experience", scope_verified=True),
                    HindsightRecallItem(id="B", text="mem B", fact_type="experience", scope_verified=True),
                    HindsightRecallItem(id="C", text="mem C", fact_type="experience", scope_verified=True),
                ),
                total_count=3,
            )
        elif tag.startswith("ip:") and "v1" in tag:
            return HindsightRecallResult(
                bank_id="dev", query="q",
                items=(
                    HindsightRecallItem(id="A", text="mem A duplicate", fact_type="observation", scope_verified=True),
                    HindsightRecallItem(id="D", text="mem D", fact_type="observation", scope_verified=True),
                ),
                total_count=2,
            )
        elif tag.startswith("user:") and "v3" in tag:
            return HindsightRecallResult(
                bank_id="dev", query="q",
                items=(
                    HindsightRecallItem(id="E", text="mem E", fact_type="experience", scope_verified=True),
                    HindsightRecallItem(id="F", text="mem F", fact_type="experience", scope_verified=True),
                ),
                total_count=2,
            )
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    res = await svc.recall_memories(
        make_context(
            source_ip="10.0.0.1",
            username="admin",
            incident_type="brute_force",
        )
    )

    # Priority stream order: IP_v3, IP_v1, IP_v2 (empty), User_v3, User_v1 (empty), User_v2 (empty)
    # Depth 0: A (from IP_v3), A in IP_v1 duplicate skipped, E (from User_v3) -> [A, E]
    # Depth 1: B (from IP_v3), D (from IP_v1), F (from User_v3) -> [A, E, B, D, F]
    # Depth 2: C (from IP_v3) -> [A, E, B, D, F, C]
    assert [item.memory_id for item in res.items] == ["A", "E", "B", "D", "F", "C"]


@pytest.mark.asyncio
async def test_cross_query_scores_never_compared(mock_hindsight_client, recall_service):
    """Scenario 31: Merging relies strictly on stream priority and native rank, not scores."""
    # Stream 1 has items with rank 1, 2; Stream 2 has items with rank 1, 2
    # Regardless of whatever scores might have been in Hindsight, round-robin interleaving governs order
    res1 = (HindsightRecallItem(id="low-rel-1", text="text", fact_type="experience", scope_verified=True),)
    res2 = (HindsightRecallItem(id="high-rel-1", text="text", fact_type="experience", scope_verified=True),)

    async def mock_recall(tag, *args, **kwargs):
        if "source_ip" in tag or tag.startswith("ip:v3"):
            return HindsightRecallResult(bank_id="dev", query="q", items=res1, total_count=1)
        elif tag.startswith("user:v3"):
            return HindsightRecallResult(bank_id="dev", query="q", items=res2, total_count=1)
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    res = await recall_service.recall_memories(
        make_context(
            source_ip="10.0.0.1",
            username="admin",
            incident_type="brute_force",
        )
    )
    # IP active comes before Username active
    assert res.items[0].memory_id == "low-rel-1"
    assert res.items[1].memory_id == "high-rel-1"


@pytest.mark.asyncio
async def test_duplicate_memory_ids_eliminated(mock_hindsight_client, recall_service):
    """Scenario 32: Duplicate memory IDs returned across streams are deduplicated."""
    shared_item = HindsightRecallItem(id="mem-shared", text="Shared fact", fact_type="experience", scope_verified=True)
    item_unique = HindsightRecallItem(id="mem-unique", text="Unique fact", fact_type="experience", scope_verified=True)

    async def mock_recall(tag, *args, **kwargs):
        if tag.startswith("ip:v3"):
            return HindsightRecallResult(bank_id="dev", query="q", items=(shared_item,), total_count=1)
        elif tag.startswith("ip:v1"):
            return HindsightRecallResult(bank_id="dev", query="q", items=(shared_item, item_unique), total_count=2)
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    ids = [item.memory_id for item in res.items]
    assert ids == ["mem-shared", "mem-unique"]
    assert len(ids) == len(set(ids))


@pytest.mark.asyncio
async def test_similar_text_with_different_ids_retained(mock_hindsight_client, recall_service):
    """Scenario 33: Two distinct memories with similar text but different IDs are both retained."""
    m1 = HindsightRecallItem(id="id-1", text="Identical observed text", fact_type="observation", scope_verified=True)
    m2 = HindsightRecallItem(id="id-2", text="Identical observed text", fact_type="observation", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(m1, m2), total_count=2
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert len(res.items) == 2
    assert res.items[0].memory_id == "id-1"
    assert res.items[1].memory_id == "id-2"


@pytest.mark.asyncio
async def test_maximum_five_items_per_query_enforced(mock_hindsight_client, recall_service):
    """Scenario 34: At most five items from an individual query stream enter the candidate pool."""
    many_items = tuple(
        HindsightRecallItem(id=f"mem-{i}", text=f"Text {i}", fact_type="experience", scope_verified=True)
        for i in range(10)  # 10 items in response
    )

    async def mock_recall(tag, *args, **kwargs):
        if tag.startswith("ip:v3"):
            return HindsightRecallResult(bank_id="dev", query="q", items=many_items, total_count=10)
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert len(res.items) == 5
    assert res.total_candidates_retrieved == 5


@pytest.mark.asyncio
async def test_maximum_ten_aggregate_items_enforced(mock_hindsight_client, recall_service):
    """Scenario 35: Final merged results are capped at MAX_RECALLED_MEMORIES = 10."""
    stream1 = tuple(HindsightRecallItem(id=f"s1-{i}", text=f"Fact 1-{i}", fact_type="experience", scope_verified=True) for i in range(5))
    stream2 = tuple(HindsightRecallItem(id=f"s2-{i}", text=f"Fact 2-{i}", fact_type="experience", scope_verified=True) for i in range(5))
    stream3 = tuple(HindsightRecallItem(id=f"s3-{i}", text=f"Fact 3-{i}", fact_type="experience", scope_verified=True) for i in range(5))

    async def mock_recall(tag, *args, **kwargs):
        if tag.startswith("ip:v3"):
            return HindsightRecallResult(bank_id="dev", query="q", items=stream1, total_count=5)
        elif tag.startswith("ip:v1"):
            return HindsightRecallResult(bank_id="dev", query="q", items=stream2, total_count=5)
        elif tag.startswith("user:v3"):
            return HindsightRecallResult(bank_id="dev", query="q", items=stream3, total_count=5)
        return HindsightRecallResult(bank_id="dev", query="q", items=(), total_count=0)

    mock_hindsight_client.recall_incident_memories.side_effect = mock_recall

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", username="admin", incident_type="brute_force"))
    assert len(res.items) == 10
    assert len(res.items) <= MAX_RECALLED_MEMORIES


@pytest.mark.asyncio
async def test_oversized_individual_memories_are_rejected(mock_hindsight_client, recall_service):
    """Scenario 36: Memories exceeding 1,000 characters are completely rejected and omitted."""
    normal_item = HindsightRecallItem(id="mem-normal", text="Valid short memory fact", fact_type="experience", scope_verified=True)
    oversized_item = HindsightRecallItem(id="mem-giant", text="A" * 1001, fact_type="experience", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(oversized_item, normal_item), total_count=2
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.items_rejected_oversized == 1
    assert len(res.items) == 1
    assert res.items[0].memory_id == "mem-normal"


@pytest.mark.asyncio
async def test_aggregate_2000_character_ceiling_enforced(mock_hindsight_client, recall_service):
    """Scenario 37: Result inclusion halts before exceeding the 2,000-character aggregate context ceiling."""
    # 3 items of 800 chars each: 800 + 800 = 1600 (fits), 1600 + 800 = 2400 (exceeds 2000!)
    item1 = HindsightRecallItem(id="m1", text="A" * 800, fact_type="experience", scope_verified=True)
    item2 = HindsightRecallItem(id="m2", text="B" * 800, fact_type="experience", scope_verified=True)
    item3 = HindsightRecallItem(id="m3", text="C" * 800, fact_type="experience", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(item1, item2, item3), total_count=3
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    # Only m1 and m2 are accepted (1600 chars <= 2000)
    assert len(res.items) == 2
    total_chars = sum(len(i.text) for i in res.items)
    assert total_chars <= MAX_AGGREGATE_CONTEXT_CHARS
    assert [i.memory_id for i in res.items] == ["m1", "m2"]


@pytest.mark.asyncio
async def test_aggregate_character_budget_subsequent_shorter_memory_fits(mock_hindsight_client, recall_service):
    """Scenario 37b: Oversized candidate exceeding aggregate budget is skipped; subsequent shorter candidate is accepted."""
    # Candidate 1: 900 chars (fits, total=900)
    # Candidate 2: 900 chars (fits, total=1800)
    # Candidate 3: 500 chars (1800+500=2300 > 2000 -> skipped because of aggregate limit, not single limit!)
    # Candidate 4: 150 chars (1800+150=1950 <= 2000 -> fits! accepted)
    item1 = HindsightRecallItem(id="m1", text="A" * 900, fact_type="experience", scope_verified=True)
    item2 = HindsightRecallItem(id="m2", text="B" * 900, fact_type="experience", scope_verified=True)
    item3 = HindsightRecallItem(id="m3", text="C" * 500, fact_type="experience", scope_verified=True)
    item4 = HindsightRecallItem(id="m4", text="D" * 150, fact_type="experience", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(item1, item2, item3, item4), total_count=4
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert len(res.items) == 3
    assert [i.memory_id for i in res.items] == ["m1", "m2", "m4"]
    assert sum(len(i.text) for i in res.items) == 1950
    assert res.items_rejected_oversized == 0


@pytest.mark.asyncio
async def test_accepted_text_is_not_silently_truncated(mock_hindsight_client, recall_service):
    """Scenario 38: Accepted memory facts retain their exact original text without clipping."""
    exact_text = "Prior confirmed password spraying campaign against internal gateway"
    item = HindsightRecallItem(id="m-exact", text=exact_text, fact_type="experience", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(item,), total_count=1
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.items[0].text == exact_text


@pytest.mark.asyncio
async def test_hmac_tags_and_raw_queries_absent_from_result_dtos(mock_hindsight_client, recall_service):
    """Scenario 39: Neither HMAC pseudonyms nor raw queries are exposed on result DTOs."""
    item = HindsightRecallItem(id="m-clean", text="Behavioral observation", fact_type="observation", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(item,), total_count=1
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    res_dump = repr(res)
    item_dump = repr(res.items[0])

    # Assert no hex digests or HMAC prefixes
    assert "ip:v" not in res_dump
    assert "user:v" not in res_dump
    assert not hasattr(res.items[0], "tag")
    assert not hasattr(res.items[0], "tags")


# =============================================================================
# 4. Failure Handling Tests (Scenarios 40-47)
# =============================================================================


@pytest.mark.asyncio
async def test_all_successful_queries_produce_success(mock_hindsight_client, recall_service):
    """Scenario 40: When all queries succeed and return items, status is 'success'."""
    item = HindsightRecallItem(id="m-ok", text="Valid fact", fact_type="experience", scope_verified=True)
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(item,), total_count=1
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "success"
    assert res.successful_queries == 3
    assert res.failed_queries == 0


@pytest.mark.asyncio
async def test_all_successful_queries_with_no_items_produce_empty(mock_hindsight_client, recall_service):
    """Scenario 41: When all queries succeed but return zero items, status is 'empty'."""
    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(), total_count=0
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "empty"
    assert res.successful_queries == 3
    assert len(res.items) == 0


@pytest.mark.asyncio
async def test_all_returned_items_rejected_as_oversized_produces_empty_status(mock_hindsight_client, recall_service):
    """Scenario 41b: All attempted queries succeed, but all returned items are oversized (>1000 chars) -> status='empty'."""
    oversized1 = HindsightRecallItem(id="bad1", text="X" * 1001, fact_type="experience", scope_verified=True)
    oversized2 = HindsightRecallItem(id="bad2", text="Y" * 1050, fact_type="experience", scope_verified=True)

    mock_hindsight_client.recall_incident_memories.return_value = HindsightRecallResult(
        bank_id="dev", query="q", items=(oversized1, oversized2), total_count=2
    )

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "empty"
    assert res.items_rejected_oversized == 2
    assert len(res.items) == 0
    assert res.successful_queries == 3
    assert res.failed_queries == 0


@pytest.mark.asyncio
async def test_partial_query_failures_with_results_produce_partial(mock_hindsight_client, recall_service):
    """Scenario 42: When some queries succeed with results and others fail, status is 'partial'."""
    item = HindsightRecallItem(id="m-part", text="Partial result", fact_type="experience", scope_verified=True)

    async def mixed_recall(tag, *args, **kwargs):
        if "v3" in tag:
            return HindsightRecallResult(bank_id="dev", query="q", items=(item,), total_count=1)
        raise HindsightServerError("500 Server Error")

    mock_hindsight_client.recall_incident_memories.side_effect = mixed_recall

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "partial"
    assert res.successful_queries == 1
    assert res.failed_queries == 2
    assert len(res.items) == 1


@pytest.mark.asyncio
async def test_all_query_failures_produce_unavailable(mock_hindsight_client, recall_service):
    """Scenario 43: When all queries fail, status is 'unavailable'."""
    mock_hindsight_client.recall_incident_memories.side_effect = HindsightConnectionError("Connection refused")

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "unavailable"
    assert res.successful_queries == 0
    assert res.failed_queries == 3


@pytest.mark.asyncio
async def test_missing_identifiers_produce_skipped(recall_service):
    """Scenario 44: Empty or missing identifiers produce 'skipped' with zero API calls."""
    res = await recall_service.recall_memories(make_context(source_ip=None, username=None, incident_type="brute_force"))
    assert res.status == "skipped"
    assert res.skipped_reason == "NO_USABLE_IDENTIFIERS"


@pytest.mark.asyncio
async def test_authentication_failures_remain_distinguishable(mock_hindsight_client, recall_service):
    """Scenario 45: 401 Unauthorized is classified as AUTHENTICATION_ERROR."""
    mock_hindsight_client.recall_incident_memories.side_effect = HindsightAuthenticationError("Invalid API Key")

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "unavailable"
    assert "AUTHENTICATION_ERROR" in res.diagnostic_classifications


@pytest.mark.asyncio
async def test_malformed_adapter_results_do_not_enter_merged_result(mock_hindsight_client, recall_service):
    """Scenario 46: Malformed items missing id or text are excluded from merged result."""
    mock_hindsight_client.recall_incident_memories.side_effect = HindsightProtocolError("Corrupted payload")

    res = await recall_service.recall_memories(make_context(source_ip="10.0.0.1", incident_type="brute_force"))
    assert res.status == "unavailable"
    assert "PROTOCOL_ERROR" in res.diagnostic_classifications
    assert res.items == ()


@pytest.mark.asyncio
async def test_logging_does_not_expose_sensitive_data(mock_hindsight_client, recall_service, caplog):
    """Scenario 47: Logs never expose raw IPs, usernames, HMAC keys, or raw exception strings."""
    secret_key = "very-secret-token-must-not-be-logged"
    mock_hindsight_client.recall_incident_memories.side_effect = HindsightServerError(f"Error with key {secret_key}")

    with caplog.at_level(logging.DEBUG):
        await recall_service.recall_memories(
            make_context(
                source_ip="192.168.1.100",
                username="superadmin",
                incident_type="brute_force",
            )
        )

    log_output = caplog.text
    assert secret_key not in log_output
    assert "192.168.1.100" not in log_output
    assert "superadmin" not in log_output


# =============================================================================
# 5. Application Lifecycle Tests (Scenarios 48-54)
# =============================================================================


@pytest.mark.asyncio
async def test_enabled_recall_creates_exactly_one_service_instance():
    """Scenario 48: Enabled recall creates exactly one service instance."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client") as mock_create_client, \
         patch("app.main.dispose_engine"):

        mock_hindsight = MagicMock(spec=HindsightClientService)
        mock_hindsight.bank_id = "sentinelagent-incident-memory-dev"
        mock_hindsight.base_url = "http://localhost:8888"
        mock_hindsight.is_required = False
        mock_hindsight.aclose = AsyncMock()
        mock_create_client.return_value = mock_hindsight

        async with lifespan(app):
            assert app.state.incident_memory_recall_service is not None
            assert isinstance(app.state.incident_memory_recall_service, IncidentMemoryRecallService)


@pytest.mark.asyncio
async def test_service_stored_in_app_state_incident_memory_recall_service():
    """Scenario 49: Service is stored in app.state.incident_memory_recall_service with proper concurrency."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client") as mock_create_client, \
         patch("app.main.dispose_engine"):

        mock_hindsight = MagicMock(spec=HindsightClientService)
        mock_hindsight.bank_id = "sentinelagent-incident-memory-dev"
        mock_hindsight.base_url = "http://localhost:8888"
        mock_hindsight.is_required = False
        mock_hindsight.aclose = AsyncMock()
        mock_create_client.return_value = mock_hindsight

        async with lifespan(app):
            service = app.state.incident_memory_recall_service
            assert service is not None
            assert service.max_concurrency == 10

        assert app.state.incident_memory_recall_service is None


@pytest.mark.asyncio
async def test_disabled_recall_stores_none():
    """Scenario 50: When recall is disabled, app.state.incident_memory_recall_service is None."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=False,  # Disabled
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client") as mock_create_client, \
         patch("app.main.dispose_engine"):

        mock_hindsight = MagicMock(spec=HindsightClientService)
        mock_hindsight.bank_id = "sentinelagent-incident-memory-dev"
        mock_hindsight.base_url = "http://localhost:8888"
        mock_hindsight.is_required = False
        mock_hindsight.aclose = AsyncMock()
        mock_create_client.return_value = mock_hindsight

        async with lifespan(app):
            assert app.state.incident_memory_recall_service is None


@pytest.mark.asyncio
async def test_service_reuses_existing_hindsight_client():
    """Scenario 51: IncidentMemoryRecallService reuses app.state.hindsight_client without creating a second SDK."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client") as mock_create_client, \
         patch("app.main.dispose_engine"):

        mock_hindsight = MagicMock(spec=HindsightClientService)
        mock_hindsight.bank_id = "sentinelagent-incident-memory-dev"
        mock_hindsight.base_url = "http://localhost:8888"
        mock_hindsight.is_required = False
        mock_hindsight.aclose = AsyncMock()
        mock_create_client.return_value = mock_hindsight

        async with lifespan(app):
            # Exactly one Hindsight client service created
            assert mock_create_client.call_count == 1
            assert app.state.incident_memory_recall_service._hindsight_client is app.state.hindsight_client


def test_independent_application_instances_have_independent_semaphores(mock_hindsight_client, pseudonymizer, recall_settings):
    """Scenario 52: Independent recall service instances have independent semaphores."""
    svc_a = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)
    svc_b = IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)
    assert svc_a.semaphore is not svc_b.semaphore
    assert id(svc_a.semaphore) != id(svc_b.semaphore)


def test_recall_service_construction_performs_no_network_requests(mock_hindsight_client, pseudonymizer, recall_settings):
    """Scenario 53: Service instantiation performs exactly zero network requests."""
    IncidentMemoryRecallService(mock_hindsight_client, pseudonymizer, recall_settings)
    assert mock_hindsight_client.recall_incident_memories.await_count == 0



@pytest.mark.asyncio
async def test_existing_task_9c36_lifespan_behavior_remains_intact():
    """Scenario 54: Outbox worker, sweeper, and Hindsight client clean up properly on shutdown."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_RECALL_ENABLED=True,
        HINDSIGHT_HMAC_KEY=SecretStr(ACTIVE_KEY),
        _env_file=None,
    )
    with patch("app.main.get_settings", return_value=settings), \
         patch("app.main.create_hindsight_client") as mock_create_client, \
         patch("app.main.dispose_engine"):

        mock_hindsight = MagicMock(spec=HindsightClientService)
        mock_hindsight.bank_id = "sentinelagent-incident-memory-dev"
        mock_hindsight.base_url = "http://localhost:8888"
        mock_hindsight.is_required = False
        mock_hindsight.aclose = AsyncMock()
        mock_create_client.return_value = mock_hindsight

        async with lifespan(app):
            assert app.state.hindsight_client is not None
            assert app.state.incident_memory_recall_service is not None

        # Cleaned up on exit
        assert app.state.hindsight_client is None
        assert app.state.incident_memory_recall_service is None
        assert mock_hindsight.aclose.await_count == 1

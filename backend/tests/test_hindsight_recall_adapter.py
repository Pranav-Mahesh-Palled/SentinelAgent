"""Unit tests for the Hindsight recall client adapter and configuration hardening (Task 9D.2.1).

Verifies:
- Authenticated async recall uses existing HindsightClientService.
- Calls native SDK `arecall()`, not synchronous `recall()`.
- Exact request parameters passed to SDK.
- Correct memory types (['experience', 'observation']).
- tags_match='all_strict' enforced.
- Single valid IP / Username HMAC tag accepted.
- Missing, multiple, raw, and malformed tags rejected.
- Response converted to immutable HindsightRecallItem and HindsightRecallResult DTOs.
- Native Hindsight result ordering preserved.
- Unsupported fact types and out-of-scope memories rejected.
- Malformed response structure and malformed items handled safely.
- Empty successful results distinguishable from errors.
- Entities, chunks, source facts, and traces disabled.
- rerank and min_scores set to None.
- Logical timeout mapped to HindsightTimeoutError.
- External asyncio.CancelledError propagated unchanged.
- Existing exception mappings (401, connection, etc.) intact.
- Zero raw memory text or secrets in log outputs.
- Environment bank isolation enforced (mismatches rejected before network call).
- Feature flag HINDSIGHT_RECALL_ENABLED strictly respected (fails locally when disabled).
- Caller-supplied limits (max_tokens ceiling, request_timeout bound, booleans rejected).
- Returned HMAC metadata strictly minimized (only verified requested tag retained).
- Text treated as untrusted historical memory, preserving exact original content.
"""

import asyncio
from datetime import datetime, timezone
import logging
import math
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from pydantic import SecretStr

from hindsight_client import Hindsight
import hindsight_client_api.exceptions as hindsight_exceptions
from hindsight_client_api.models.recall_result import RecallResult
from hindsight_client_api.models.recall_response import RecallResponse

from app.core.config import Settings
from app.services.hindsight_client import (
    HindsightAuthenticationError,
    HindsightClientError,
    HindsightClientService,
    HindsightConfigurationError,
    HindsightConnectionError,
    HindsightProtocolError,
    HindsightRecallItem,
    HindsightRecallResult,
    HindsightServerError,
    HindsightTimeoutError,
    HindsightValidationError,
    validate_recall_tag,
)

VALID_IP_TAG = "ip:v1:0123456789abcdef0123456789abcdef"
VALID_USER_TAG = "user:v1:fedcba9876543210fedcba9876543210"
VALID_V2_TAG = "ip:v2:abcdef0123456789abcdef0123456789"


@pytest.fixture
def mock_hindsight_sdk():
    """Create a mock official Hindsight SDK instance."""
    mock_sdk = MagicMock(spec=Hindsight)
    mock_sdk.arecall = AsyncMock()
    mock_sdk.recall = MagicMock()
    mock_sdk.aclose = AsyncMock()
    return mock_sdk


@pytest.fixture
def enabled_recall_settings():
    """Create a valid Settings instance with recall enabled."""
    return Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("valid-key-secret-token-1234567890"),
        HINDSIGHT_BANK_ID="sentinelagent-incident-memory-dev",
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


@pytest.fixture(autouse=True)
def patch_recall_settings(enabled_recall_settings):
    """Patch get_settings across all tests to default to enabled recall."""
    with patch("app.services.hindsight_client.get_settings", return_value=enabled_recall_settings):
        yield enabled_recall_settings


@pytest.fixture
def client_service(mock_hindsight_sdk):
    """Create a test HindsightClientService instance."""
    return HindsightClientService(
        client=mock_hindsight_sdk,
        bank_id="sentinelagent-incident-memory-dev",
        base_url="http://localhost:8888",
    )


# =============================================================================
# Tag Validation Tests (Section 2.1)
# =============================================================================

def test_validate_recall_tag_valid_ip():
    """Valid IP HMAC tags are accepted and preserved."""
    assert validate_recall_tag(VALID_IP_TAG) == VALID_IP_TAG
    assert validate_recall_tag(VALID_V2_TAG) == VALID_V2_TAG


def test_validate_recall_tag_valid_username():
    """Valid Username HMAC tags are accepted and preserved."""
    assert validate_recall_tag(VALID_USER_TAG) == VALID_USER_TAG


@pytest.mark.parametrize("empty_tag", ["", "   ", None])
def test_validate_recall_tag_empty_rejected(empty_tag):
    """Empty or None tags are rejected."""
    with pytest.raises(HindsightValidationError, match="cannot be empty"):
        validate_recall_tag(empty_tag)


@pytest.mark.parametrize(
    "raw_val",
    [
        "192.168.1.100",
        "10.0.0.1",
        "::1",
        "2001:db8::1",
        "admin",
        "root",
        "service_account",
    ],
)
def test_validate_recall_tag_raw_identifiers_rejected(raw_val):
    """Raw IP addresses and usernames must be strictly rejected without echoing."""
    with pytest.raises(HindsightValidationError) as exc_info:
        validate_recall_tag(raw_val)
    # Ensure raw identifier is never leaked into exception message
    assert raw_val not in str(exc_info.value)
    assert "Invalid identity tag for recall" in str(exc_info.value)


@pytest.mark.parametrize(
    "malformed_tag",
    [
        "ip:v1:0123456789ABCDEF0123456789ABCDEF",  # uppercase hex
        "ip:v1:012345",  # truncated hex
        "ip:v1:0123456789abcdef0123456789abcdef0",  # 33-char hex
        "ip:v1:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",  # non-hex
        "host:v1:0123456789abcdef0123456789abcdef",  # unsupported family
        "domain:v1:0123456789abcdef0123456789abcdef",  # unsupported family
        "ip::0123456789abcdef0123456789abcdef",  # missing version
        f"{VALID_IP_TAG},{VALID_USER_TAG}",  # multiple tags
    ],
)
def test_validate_recall_tag_malformed_rejected(malformed_tag):
    """Malformed or unsupported identity tags must be rejected."""
    with pytest.raises(HindsightValidationError, match="Invalid identity tag for recall"):
        validate_recall_tag(malformed_tag)


# =============================================================================
# Feature Flag Tests (Task 9D.2.1 Item 3)
# =============================================================================

@pytest.mark.asyncio
async def test_recall_disabled_by_default_raises(client_service, mock_hindsight_sdk):
    """When HINDSIGHT_RECALL_ENABLED is False, recall_incident_memories fails locally."""
    disabled_settings = Settings(_env_file=None)
    assert disabled_settings.HINDSIGHT_RECALL_ENABLED is False

    with patch("app.services.hindsight_client.get_settings", return_value=disabled_settings):
        with pytest.raises(
            HindsightConfigurationError,
            match="Hindsight incident-memory recall is disabled",
        ):
            await client_service.recall_incident_memories(
                tag=VALID_IP_TAG,
                query="test query",
            )
    assert mock_hindsight_sdk.arecall.await_count == 0


# =============================================================================
# Environment Bank Isolation Tests (Task 9D.2.1 Item 1)
# =============================================================================

@pytest.mark.asyncio
async def test_bank_isolation_correct_configured_bank_accepted(client_service, mock_hindsight_sdk):
    """Explicitly supplying the authoritative bank ID is accepted."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(results=[])

    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="test query",
        bank_id="sentinelagent-incident-memory-dev",
    )
    assert res.bank_id == "sentinelagent-incident-memory-dev"
    assert mock_hindsight_sdk.arecall.await_count == 1
    assert mock_hindsight_sdk.arecall.call_args.kwargs["bank_id"] == "sentinelagent-incident-memory-dev"


@pytest.mark.asyncio
async def test_bank_isolation_omitted_bank_uses_authoritative(client_service, mock_hindsight_sdk):
    """Omitted or None bank_id uses the authoritative configured bank."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(results=[])

    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="test query",
        bank_id=None,
    )
    assert res.bank_id == "sentinelagent-incident-memory-dev"
    assert mock_hindsight_sdk.arecall.await_count == 1
    assert mock_hindsight_sdk.arecall.call_args.kwargs["bank_id"] == "sentinelagent-incident-memory-dev"


@pytest.mark.asyncio
async def test_bank_isolation_dev_substituted_for_prod_rejected(mock_hindsight_sdk):
    """In a production environment, substituting development bank is rejected."""
    prod_service = HindsightClientService(
        client=mock_hindsight_sdk,
        bank_id="sentinelagent-incident-memory-prod",
        base_url="http://localhost:8888",
    )

    with pytest.raises(
        HindsightValidationError,
        match="does not match authoritative environment bank 'sentinelagent-incident-memory-prod'",
    ):
        await prod_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            bank_id="sentinelagent-incident-memory-dev",
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
async def test_bank_isolation_prod_substituted_for_dev_rejected(client_service, mock_hindsight_sdk):
    """In a development environment, substituting production bank is rejected."""
    with pytest.raises(
        HindsightValidationError,
        match="does not match authoritative environment bank 'sentinelagent-incident-memory-dev'",
    ):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            bank_id="sentinelagent-incident-memory-prod",
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("empty_bank", ["", "   ", "\t", "\n"])
async def test_bank_isolation_explicit_empty_bank_rejected(client_service, mock_hindsight_sdk, empty_bank):
    """Explicitly supplying an empty or whitespace-only bank ID is rejected locally with zero SDK calls."""
    with pytest.raises(HindsightValidationError, match="Explicit bank_id cannot be empty or whitespace-only"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            bank_id=empty_bank,
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_bank_type", [123, True, False, [], {}])
async def test_bank_isolation_non_string_bank_rejected(client_service, mock_hindsight_sdk, invalid_bank_type):
    """Supplying a non-string bank ID is rejected locally with zero SDK calls."""
    with pytest.raises(HindsightValidationError, match="bank_id must be a string or None"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            bank_id=invalid_bank_type,
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


# =============================================================================
# Caller-Supplied Limits (Task 9D.2.1 Item 2)
# =============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("bad_tokens", [True, False, 0, -1, -500])
async def test_caller_max_tokens_non_positive_or_boolean_rejected(client_service, mock_hindsight_sdk, bad_tokens):
    """max_tokens must reject booleans and non-positive integers."""
    with pytest.raises(HindsightValidationError, match="max_tokens must be a positive integer"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            max_tokens=bad_tokens,
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
async def test_caller_max_tokens_exceeding_ceiling_rejected(client_service, mock_hindsight_sdk):
    """max_tokens cannot exceed configured ceiling (4096)."""
    with pytest.raises(HindsightValidationError, match="exceeds maximum configured ceiling of 4096"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            max_tokens=4097,
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
async def test_adapter_enforces_absolute_4096_ceiling_even_if_settings_higher(client_service, mock_hindsight_sdk):
    """The adapter enforces the absolute 4096 token ceiling even if settings configure a higher value."""
    with patch("app.services.hindsight_client.get_settings") as mock_get_settings:
        mock_settings = MagicMock()
        mock_settings.HINDSIGHT_RECALL_ENABLED = True
        mock_settings.HINDSIGHT_RECALL_MAX_TOKENS = 1024
        mock_settings.HINDSIGHT_RECALL_MAX_TOKENS_CEILING = 8192  # Attempted ceiling inflation
        mock_settings.HINDSIGHT_RECALL_BUDGET = "mid"
        mock_settings.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS = 3.0
        mock_get_settings.return_value = mock_settings

        with pytest.raises(HindsightValidationError, match="exceeds maximum configured ceiling of 4096"):
            await client_service.recall_incident_memories(
                tag=VALID_IP_TAG,
                query="test query",
                max_tokens=4097,
            )
        assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
async def test_caller_max_tokens_valid_override_accepted(client_service, mock_hindsight_sdk):
    """Valid max_tokens override within ceiling is passed to arecall."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(results=[])

    await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="test query",
        max_tokens=2048,
    )
    assert mock_hindsight_sdk.arecall.call_args.kwargs["max_tokens"] == 2048


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_timeout", [True, False, 0.0, -1.0, float("nan"), float("inf"), float("-inf")])
async def test_caller_request_timeout_invalid_or_boolean_rejected(client_service, mock_hindsight_sdk, bad_timeout):
    """request_timeout must reject booleans, zero, negative, and non-finite floats."""
    with pytest.raises(HindsightValidationError, match="request_timeout must be a positive finite number"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            request_timeout=bad_timeout,
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
async def test_caller_request_timeout_exceeding_limit_rejected(client_service, mock_hindsight_sdk):
    """request_timeout cannot exceed configured 3.0s limit."""
    with pytest.raises(HindsightValidationError, match=r"request_timeout \(3\.5s\) cannot exceed configured limit of 3\.0s"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="test query",
            request_timeout=3.5,
        )
    assert mock_hindsight_sdk.arecall.await_count == 0


@pytest.mark.asyncio
async def test_caller_request_timeout_valid_override_accepted(client_service, mock_hindsight_sdk):
    """Valid request_timeout override within 3.0s is accepted."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(results=[])

    await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="test query",
        request_timeout=1.5,
    )
    assert mock_hindsight_sdk.arecall.await_count == 1


# =============================================================================
# Returned Metadata Minimization (Task 9D.2.1 Item 4)
# =============================================================================

@pytest.mark.asyncio
async def test_metadata_minimization_unrelated_tags_stripped(client_service, mock_hindsight_sdk):
    """Remote memory with unrelated IP and username tags has all foreign tags stripped."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-multitag",
                text="Structurally validated observation memory",
                type="observation",
                tags=[
                    VALID_IP_TAG,  # Queried tag
                    "user:v1:otheruser987654321012345678",  # Unrelated username tag
                    "ip:v1:otherip1234567890123456789012",  # Unrelated IP tag
                    "mitre:T1110",  # Remote category tag
                ],
            )
        ]
    )

    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="query",
    )

    assert res.total_count == 1
    item = res.items[0]
    assert item.id == "mem-multitag"
    assert item.scope_verified is True
    # DTOs must not contain tags or verified_tag attributes
    assert not hasattr(item, "tags")
    assert not hasattr(item, "verified_tag")
    assert not hasattr(res, "tag")
    # Assert neither requested HMAC tag nor foreign pseudonyms are exposed anywhere in item attributes
    item_attrs_str = " ".join(str(getattr(item, f.name)) for f in item.__dataclass_fields__.values())
    assert VALID_IP_TAG not in item_attrs_str
    assert "user:v1:otheruser987654321012345678" not in item_attrs_str
    assert "ip:v1:otherip1234567890123456789012" not in item_attrs_str
    assert "mitre:T1110" not in item_attrs_str


@pytest.mark.asyncio
async def test_hmac_tags_never_exposed_in_returned_dtos(client_service, mock_hindsight_sdk):
    """Returned DTOs must never expose the requested HMAC tag or any other HMAC tag."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-privacy",
                text="Historical behavioral event without leaking HMAC metadata",
                type="experience",
                tags=[VALID_USER_TAG, "mitre:T1078"],
            )
        ]
    )

    res = await client_service.recall_incident_memories(
        tag=VALID_USER_TAG,
        query="privacy check query",
    )

    assert res.total_count == 1
    item = res.items[0]
    assert item.scope_verified is True
    assert not hasattr(item, "tags")
    assert not hasattr(item, "verified_tag")
    assert not hasattr(res, "tag")

    # Serialize or inspect all field values of result and item
    result_dump = repr(res)
    assert VALID_USER_TAG not in result_dump
    assert "mitre:T1078" not in result_dump


def test_hindsight_recall_item_construction_without_scope_verified_rejected():
    """HindsightRecallItem cannot be constructed without explicit scope_verified field."""
    with pytest.raises(TypeError, match="missing .* 'scope_verified'"):
        HindsightRecallItem(  # type: ignore[call-arg]
            id="mem-no-scope",
            text="Memory text",
            fact_type="observation",
        )


def test_hindsight_recall_item_construction_with_false_scope_verified_rejected():
    """HindsightRecallItem rejects construction if scope_verified is False or not True."""
    with pytest.raises(ValueError, match="HindsightRecallItem must have scope_verified=True"):
        HindsightRecallItem(
            id="mem-false-scope",
            text="Memory text",
            fact_type="observation",
            scope_verified=False,
        )


def test_hindsight_recall_item_construction_with_explicit_scope_verified_true_succeeds():
    """HindsightRecallItem succeeds when explicit scope_verified=True is provided."""
    item = HindsightRecallItem(
        id="mem-verified",
        text="Memory text",
        fact_type="observation",
        scope_verified=True,
    )
    assert item.id == "mem-verified"
    assert item.scope_verified is True


@pytest.mark.asyncio
async def test_metadata_minimization_missing_requested_tag_rejected(client_service, mock_hindsight_sdk):
    """Remote memory lacking the requested tag is rejected as out-of-scope."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-foreign",
                text="Foreign memory",
                type="observation",
                tags=["ip:v1:otherip1234567890123456789012"],
            )
        ]
    )

    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="query",
    )
    assert res.total_count == 0
    assert res.items == ()


# =============================================================================
# Memory Text Trust Classification (Task 9D.2.1 Item 5)
# =============================================================================

@pytest.mark.asyncio
async def test_memory_text_unaltered_and_untrusted(client_service, mock_hindsight_sdk):
    """Returned text preserves exact raw Hindsight content without rewriting or claiming sanitization."""
    raw_content = "Adversary attempted SSH login with password 'P@ssword123!' from 192.168.1.1"
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-raw",
                text=raw_content,
                type="experience",
                tags=[VALID_IP_TAG],
            )
        ]
    )

    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="query",
    )
    # The text is preserved verbatim as untrusted historical memory
    assert res.items[0].text == raw_content


# =============================================================================
# Request Parameters and SDK Invocation (Section 2.2)
# =============================================================================

@pytest.mark.asyncio
async def test_recall_uses_arecall_with_exact_parameters(client_service, mock_hindsight_sdk):
    """Verify that recall_incident_memories invokes arecall with exact approved parameters."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-001",
                text="Historical adversary brute force observation",
                type="observation",
                tags=[VALID_IP_TAG, "mitre:T1110"],
            )
        ]
    )

    query_time = datetime(2026, 11, 10, 8, 30, 0, tzinfo=timezone.utc)
    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="brute force activity targeting SSH",
        bank_id="sentinelagent-incident-memory-dev",
        query_timestamp=query_time,
        max_tokens=1024,
        budget="mid",
    )

    # Assert arecall was called, and synchronous recall was NEVER called
    assert mock_hindsight_sdk.arecall.await_count == 1
    assert mock_hindsight_sdk.recall.call_count == 0

    call_kwargs = mock_hindsight_sdk.arecall.call_args.kwargs
    assert call_kwargs["bank_id"] == "sentinelagent-incident-memory-dev"
    assert call_kwargs["query"] == "brute force activity targeting SSH"
    assert call_kwargs["types"] == ["experience", "observation"]
    assert call_kwargs["max_tokens"] == 1024
    assert call_kwargs["budget"] == "mid"
    assert call_kwargs["trace"] is False
    assert call_kwargs["query_timestamp"] == query_time.isoformat()
    assert call_kwargs["include_entities"] is False
    assert call_kwargs["include_chunks"] is False
    assert call_kwargs["include_source_facts"] is False
    assert call_kwargs["tags"] == [VALID_IP_TAG]
    assert call_kwargs["tags_match"] == "all_strict"
    assert call_kwargs["tag_groups"] is None
    assert call_kwargs["prefer_observations"] is True
    assert call_kwargs["rerank"] is None
    assert call_kwargs["min_scores"] is None
    assert call_kwargs["temporal_window"] is None
    assert "timeout" not in call_kwargs

    assert isinstance(res, HindsightRecallResult)
    assert res.total_count == 1
    assert res.items[0].id == "mem-001"
    assert res.items[0].fact_type == "observation"
    assert res.items[0].rank == 1


@pytest.mark.asyncio
async def test_recall_accepts_username_tag(client_service, mock_hindsight_sdk):
    """Username HMAC tag is accepted and passed cleanly."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-user-1",
                text="Prior targeted password spraying against user account",
                type="experience",
                tags=[VALID_USER_TAG],
            )
        ]
    )

    res = await client_service.recall_incident_memories(
        tag=VALID_USER_TAG,
        query="investigation query",
    )

    assert mock_hindsight_sdk.arecall.await_count == 1
    assert mock_hindsight_sdk.arecall.call_args.kwargs["tags"] == [VALID_USER_TAG]
    assert res.total_count == 1
    assert res.items[0].id == "mem-user-1"


@pytest.mark.asyncio
async def test_recall_closed_client_raises(client_service):
    """Invoking recall on a closed client raises HindsightClientError."""
    await client_service.aclose()
    with pytest.raises(HindsightClientError, match="Cannot call recall_incident_memories on closed"):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="test")


@pytest.mark.asyncio
@pytest.mark.parametrize("empty_query", ["", "   "])
async def test_recall_empty_query_rejected(client_service, empty_query):
    """Empty query string must be rejected before network call."""
    with pytest.raises(HindsightValidationError, match="Recall query string cannot be empty"):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query=empty_query)


# =============================================================================
# Response DTO Conversion & Filtering (Section 2.3)
# =============================================================================

@pytest.mark.asyncio
async def test_recall_result_immutability_and_types(client_service, mock_hindsight_sdk):
    """Verify DTO immutability and accurate field assignment."""
    dt_start = "2026-11-01T12:00:00Z"
    dt_end = "2026-11-01T13:00:00Z"
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-100",
                text="Detailed observation fact",
                type="observation",
                context="Context notes",
                document_id="doc-xyz",
                tags=[VALID_IP_TAG, "category:recon"],
                occurred_start=dt_start,
                occurred_end=dt_end,
                mentioned_at=None,
            )
        ]
    )

    res = await client_service.recall_incident_memories(
        tag=VALID_IP_TAG,
        query="recon search",
    )

    item = res.items[0]
    assert item.id == "mem-100"
    assert item.text == "Detailed observation fact"
    assert item.fact_type == "observation"
    assert item.context == "Context notes"
    assert item.document_id == "doc-xyz"
    assert item.scope_verified is True
    assert not hasattr(item, "tags")
    assert not hasattr(item, "verified_tag")
    assert not hasattr(res, "tag")
    assert item.occurred_start == datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    assert item.occurred_end == datetime(2026, 11, 1, 13, 0, tzinfo=timezone.utc)
    assert item.mentioned_at is None
    assert item.rank == 1

    # Verify DTO immutability
    with pytest.raises(Exception):
        item.text = "modified text"
    with pytest.raises(Exception):
        res.items = ()


@pytest.mark.asyncio
async def test_recall_preserves_native_ranking_order(client_service, mock_hindsight_sdk):
    """Native result ordering from Hindsight is preserved with 1-based ranks."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(id="m1", text="First fact", type="experience", tags=[VALID_IP_TAG]),
            RecallResult(id="m2", text="Second fact", type="observation", tags=[VALID_IP_TAG]),
            RecallResult(id="m3", text="Third fact", type="world", tags=[VALID_IP_TAG]),
        ]
    )

    res = await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")
    assert [item.id for item in res.items] == ["m1", "m2", "m3"]
    assert [item.rank for item in res.items] == [1, 2, 3]


@pytest.mark.asyncio
async def test_recall_rejects_out_of_scope_tag_memories(client_service, mock_hindsight_sdk, caplog):
    """Memories not containing the exact requested tag are rejected as out-of-scope."""
    other_tag = "ip:v1:99999999999999999999999999999999"
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(id="m1", text="Valid memory", type="experience", tags=[VALID_IP_TAG]),
            RecallResult(id="m2", text="Leaked foreign memory", type="experience", tags=[other_tag]),
            RecallResult(id="m3", text="Untagged memory", type="experience", tags=[]),
        ]
    )

    with caplog.at_level(logging.WARNING):
        res = await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")

    # Only m1 carries the requested tag
    assert [item.id for item in res.items] == ["m1"]
    assert res.total_count == 1
    assert "missing requested identity tag" in caplog.text


@pytest.mark.asyncio
async def test_recall_rejects_unsupported_fact_types(client_service, mock_hindsight_sdk, caplog):
    """Facts with unsupported/generic types ('fact', 'event') are rejected."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(id="m1", text="Valid observation", type="observation", tags=[VALID_IP_TAG]),
            RecallResult(id="m2", text="Generic fact", type="fact", tags=[VALID_IP_TAG]),
            RecallResult(id="m3", text="Generic event", type="event", tags=[VALID_IP_TAG]),
            RecallResult(id="m4", text="Valid experience", type="experience", tags=[VALID_IP_TAG]),
        ]
    )

    with caplog.at_level(logging.WARNING):
        res = await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")

    assert [item.id for item in res.items] == ["m1", "m4"]
    assert res.total_count == 2
    assert "invalid fact type" in caplog.text


@pytest.mark.asyncio
async def test_recall_rejects_malformed_individual_records(client_service, mock_hindsight_sdk, caplog):
    """Individual records with missing IDs, missing text, or non-list tags are skipped."""
    mock_hindsight_sdk.arecall.return_value = {
        "results": [
            {"id": "", "text": "Empty id", "type": "experience", "tags": [VALID_IP_TAG]},
            {"id": "m2", "text": "", "type": "experience", "tags": [VALID_IP_TAG]},
            {"id": "m3", "text": "Valid item", "type": "experience", "tags": [VALID_IP_TAG]},
            {"id": "m4", "text": "Malformed tags", "type": "experience", "tags": "not-a-list"},
        ]
    }

    with caplog.at_level(logging.WARNING):
        res = await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")

    assert [item.id for item in res.items] == ["m3"]
    assert res.total_count == 1


@pytest.mark.asyncio
async def test_recall_empty_results_distinguishable_from_error(client_service, mock_hindsight_sdk):
    """Empty results collection returns a clean 0-item result, not an exception."""
    mock_hindsight_sdk.arecall.return_value = RecallResponse(results=[])

    res = await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="clean query")
    assert isinstance(res, HindsightRecallResult)
    assert res.total_count == 0
    assert res.items == ()


@pytest.mark.asyncio
async def test_recall_malformed_response_structure_raises_protocol_error(client_service, mock_hindsight_sdk):
    """Structurally corrupted responses raise HindsightProtocolError."""
    # Case 1: None response
    mock_hindsight_sdk.arecall.return_value = None
    with pytest.raises(HindsightProtocolError, match="returned None response"):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")

    # Case 2: Missing results attribute
    mock_hindsight_sdk.arecall.return_value = {"not_results": 123}
    with pytest.raises(HindsightProtocolError, match="missing valid 'results' collection"):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")

    # Case 3: Results is not an iterable collection
    mock_hindsight_sdk.arecall.return_value = {"results": "invalid_string"}
    with pytest.raises(HindsightProtocolError, match="missing valid 'results' collection"):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")


# =============================================================================
# Timeout and Cancellation Semantics (Section 3)
# =============================================================================

@pytest.mark.asyncio
async def test_recall_operation_timeout_mapped_to_hindsight_timeout_error(client_service, mock_hindsight_sdk):
    """Per-operation timeout wraps arecall and maps to HindsightTimeoutError."""
    async def slow_call(*args, **kwargs):
        await asyncio.sleep(0.5)
        return RecallResponse(results=[])

    mock_hindsight_sdk.arecall.side_effect = slow_call

    with pytest.raises(HindsightTimeoutError, match="Hindsight recall operation timed out"):
        await client_service.recall_incident_memories(
            tag=VALID_IP_TAG,
            query="query",
            request_timeout=0.05,
        )


@pytest.mark.asyncio
async def test_recall_external_cancellation_propagates(client_service, mock_hindsight_sdk):
    """Externally supplied asyncio.CancelledError must propagate untouched."""
    async def cancelled_call(*args, **kwargs):
        raise asyncio.CancelledError()

    mock_hindsight_sdk.arecall.side_effect = cancelled_call

    with pytest.raises(asyncio.CancelledError):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")


# =============================================================================
# Upstream Exception Mappings & Privacy (Section 4)
# =============================================================================

@pytest.mark.asyncio
async def test_recall_unauthorized_maps_to_authentication_error(client_service, mock_hindsight_sdk):
    """401 Unauthorized is mapped to HindsightAuthenticationError."""
    mock_hindsight_sdk.arecall.side_effect = hindsight_exceptions.UnauthorizedException(status=401)
    with pytest.raises(HindsightAuthenticationError) as exc_info:
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_recall_connection_error_maps_to_connection_error(client_service, mock_hindsight_sdk):
    """Connection failure maps to HindsightConnectionError."""
    mock_hindsight_sdk.arecall.side_effect = ConnectionRefusedError("Connection refused")
    with pytest.raises(HindsightConnectionError):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")


@pytest.mark.asyncio
async def test_recall_server_error_maps_to_server_error(client_service, mock_hindsight_sdk):
    """5xx response maps to HindsightServerError."""
    mock_hindsight_sdk.arecall.side_effect = hindsight_exceptions.ApiException(status=500)
    with pytest.raises(HindsightServerError) as exc_info:
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="query")
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_recall_zero_secrets_or_raw_data_in_logs(client_service, mock_hindsight_sdk, caplog):
    """Verify that sensitive inputs and raw memory text never leak into log records."""
    secret_text = "CONFIDENTIAL_PAYLOAD_DATA_987654"
    mock_hindsight_sdk.arecall.return_value = RecallResponse(
        results=[
            RecallResult(
                id="mem-secret",
                text=secret_text,
                type="invalid_type_to_trigger_log",
                tags=[VALID_IP_TAG],
            )
        ]
    )

    with caplog.at_level(logging.DEBUG):
        await client_service.recall_incident_memories(tag=VALID_IP_TAG, query="search query")

    log_output = caplog.text
    assert secret_text not in log_output
    assert VALID_IP_TAG not in log_output

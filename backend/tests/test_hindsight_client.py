"""Unit and lifecycle tests for Hindsight client foundation and FastAPI integration.

Verifies Task 9B architecture:
- Pydantic configuration and validation.
- HindsightClientService application-scoped wrapper and official SDK usage.
- Native async SDK operations (aretain, arecall, aclose).
- Harmless, authenticated read-only readiness probe via list_banks(limit=1).
- FastAPI lifespan integration (disabled, optional, required, and partial-startup safety).
- Client closed exactly once without resource leaks.
- Zero credential exposure in logs, errors, or strings.
"""

import asyncio
from datetime import datetime, timezone
import logging
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from fastapi import FastAPI
from pydantic import SecretStr

from hindsight_client import Hindsight
import hindsight_client_api.exceptions as hindsight_exceptions
import hindsight_client_api.models as hindsight_models

from app.core.config import Settings
from app.main import lifespan
from app.services.hindsight_client import (
    ALLOWED_ERROR_CLASSIFICATIONS,
    HindsightAuthenticationError,
    HindsightClientError,
    HindsightClientService,
    HindsightConfigurationError,
    HindsightConflictError,
    HindsightConnectionError,
    HindsightNotFoundError,
    HindsightProtocolError,
    HindsightRateLimitError,
    HindsightServerError,
    HindsightTimeoutError,
    HindsightValidationError,
    OperationRetryResult,
    OperationStatusResult,
    RetainSubmissionResult,
    create_hindsight_client,
)


class FakeBanksApi:
    """Mock BanksApi providing controlled list_banks responses."""

    def __init__(self, outcome: str = "success"):
        self.outcome = outcome
        self.call_count = 0

    async def list_banks(self, limit: int = 1):
        self.call_count += 1
        if self.outcome == "unauthorized":
            raise hindsight_exceptions.UnauthorizedException(status=401, reason="Unauthorized")
        elif self.outcome == "api_error":
            raise hindsight_exceptions.ApiException(status=500, reason="Internal Server Error")
        elif self.outcome == "connection_error":
            raise ConnectionRefusedError("Connection refused to Hindsight port")
        return []


class FakeOperationsApi:
    """Mock OperationsApi providing controlled get_operation_status and retry_operation responses."""

    def __init__(self):
        self.status_calls = []
        self.retry_calls = []
        self.status_response = None
        self.status_side_effect = None
        self.retry_response = None
        self.retry_side_effect = None

    async def get_operation_status(self, bank_id: str, operation_id: str, **kwargs):
        self.status_calls.append({"bank_id": bank_id, "operation_id": operation_id, "kwargs": kwargs})
        if self.status_side_effect:
            raise self.status_side_effect
        if self.status_response is not None:
            return self.status_response
        return {
            "operation_id": operation_id,
            "status": "completed",
            "operation_type": "retain",
            "created_at": "2026-11-09T18:00:00Z",
            "completed_at": "2026-11-09T18:00:05Z",
            "retry_count": 0,
        }

    async def retry_operation(self, bank_id: str, operation_id: str, **kwargs):
        self.retry_calls.append({"bank_id": bank_id, "operation_id": operation_id, "kwargs": kwargs})
        if self.retry_side_effect:
            raise self.retry_side_effect
        if self.retry_response is not None:
            return self.retry_response
        return {
            "success": True,
            "operation_id": operation_id,
            "message": "Operation retry scheduled",
        }


class FakeHindsightClient:
    """Typed test double simulating official Hindsight client without network calls."""

    def __init__(self, outcome: str = "success"):
        self.banks = FakeBanksApi(outcome=outcome)
        self.operations = FakeOperationsApi()
        self.closed = False
        self.close_count = 0
        self.recalled_queries = []
        self.retained_payloads = []
        self.retain_side_effect = None
        self.retain_response = None

    async def aclose(self):
        self.closed = True
        self.close_count += 1

    async def arecall(self, *args, **kwargs):
        self.recalled_queries.append((args, kwargs))
        return ["memory_unit_1", "memory_unit_2"]

    async def aretain(self, *args, **kwargs):
        self.retained_payloads.append((args, kwargs))
        if self.retain_side_effect:
            raise self.retain_side_effect
        if self.retain_response is not None:
            return self.retain_response
        if "operation_id" in kwargs:
            return {
                "success": True,
                "bank_id": kwargs.get("bank_id", "test-bank"),
                "operation_id": kwargs["operation_id"],
                "items_count": 1,
                "var_async": True,
            }
        return {"operation_id": "op-test-123"}


# =============================================================================
# 1. Hindsight Configuration Tests
# =============================================================================

def test_hindsight_disabled_by_default():
    """Hindsight memory integration is disabled by default."""
    settings = Settings(_env_file=None)
    assert settings.HINDSIGHT_ENABLED is False
    assert settings.HINDSIGHT_REQUIRED is False
    assert settings.HINDSIGHT_BASE_URL is None
    assert settings.HINDSIGHT_API_KEY is None


def test_hindsight_enabled_requires_url():
    """HINDSIGHT_ENABLED=True requires HINDSIGHT_BASE_URL."""
    with pytest.raises(ValueError, match="HINDSIGHT_BASE_URL must be explicitly configured"):
        Settings(
            HINDSIGHT_ENABLED=True,
            HINDSIGHT_BASE_URL="",
            HINDSIGHT_API_KEY=SecretStr("valid-key"),
            _env_file=None,
        )


def test_hindsight_enabled_requires_api_key():
    """HINDSIGHT_ENABLED=True requires HINDSIGHT_API_KEY."""
    with pytest.raises(ValueError, match="HINDSIGHT_API_KEY must be explicitly configured"):
        Settings(
            HINDSIGHT_ENABLED=True,
            HINDSIGHT_BASE_URL="http://localhost:8888",
            HINDSIGHT_API_KEY=None,
            _env_file=None,
        )


def test_hindsight_required_cannot_be_true_when_disabled():
    """HINDSIGHT_REQUIRED cannot be True when HINDSIGHT_ENABLED is False."""
    with pytest.raises(ValueError, match="HINDSIGHT_REQUIRED cannot be True when HINDSIGHT_ENABLED is False"):
        Settings(
            HINDSIGHT_ENABLED=False,
            HINDSIGHT_REQUIRED=True,
            _env_file=None,
        )


def test_hindsight_api_key_secret_str_masking():
    """Hindsight API key must be a SecretStr and never print plain value."""
    secret = "my-super-secret-key-xyz"
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr(secret),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        _env_file=None,
    )
    assert isinstance(settings.HINDSIGHT_API_KEY, SecretStr)
    assert secret not in str(settings.HINDSIGHT_API_KEY)
    assert secret not in repr(settings.HINDSIGHT_API_KEY)
    assert settings.HINDSIGHT_API_KEY.get_secret_value() == secret


def test_hindsight_bank_id_dev_prod_isolation():
    """Non-production environments must not configure production banks."""
    with pytest.raises(ValueError, match="cannot use production memory bank"):
        Settings(
            ENVIRONMENT="development",
            HINDSIGHT_BANK_ID="sentinelagent-incident-memory-prod",
            _env_file=None,
        )

    # Allowed in production environment
    prod_settings = Settings(
        ENVIRONMENT="production",
        HINDSIGHT_BANK_ID="sentinelagent-incident-memory-prod",
        _env_file=None,
    )
    assert prod_settings.HINDSIGHT_BANK_ID == "sentinelagent-incident-memory-prod"


# =============================================================================
# 2. HindsightClientService & Factory Tests
# =============================================================================

def test_create_hindsight_client_raises_when_disabled():
    """create_hindsight_client raises HindsightConfigurationError if disabled."""
    settings = Settings(HINDSIGHT_ENABLED=False, _env_file=None)
    with pytest.raises(HindsightConfigurationError, match="Cannot create Hindsight client when HINDSIGHT_ENABLED is False"):
        create_hindsight_client(settings)


def test_create_hindsight_client_constructs_real_sdk():
    """create_hindsight_client passes base_url and api_key to official Hindsight SDK."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://hindsight-server:8888",
        HINDSIGHT_API_KEY=SecretStr("token-12345"),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        _env_file=None,
    )
    with patch("app.services.hindsight_client.Hindsight") as mock_sdk_cls:
        mock_instance = MagicMock(spec=Hindsight)
        mock_sdk_cls.return_value = mock_instance

        service = create_hindsight_client(settings)

        mock_sdk_cls.assert_called_once_with(
            base_url="http://hindsight-server:8888",
            api_key="token-12345",
            timeout=30.0,
            user_agent="SentinelAgent/1.0",
        )
        assert service.client is mock_instance
        assert service.bank_id == "sentinelagent-incident-memory-dev"
        assert service.base_url == "http://hindsight-server:8888"
        assert service.is_required is False
        assert service.is_closed is False


def test_create_hindsight_client_with_override():
    """create_hindsight_client supports injecting a test double."""
    settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("token"),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        _env_file=None,
    )
    fake_client = FakeHindsightClient()
    service = create_hindsight_client(settings, client_override=fake_client)

    assert service.client is fake_client
    assert service.bank_id == "sentinelagent-incident-memory-dev"


@pytest.mark.asyncio
async def test_client_service_async_delegation():
    """HindsightClientService delegates aretain and arecall to underlying client."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    recalled = await service.arecall(bank_id="test-bank", query="brute force")
    assert recalled == ["memory_unit_1", "memory_unit_2"]
    assert len(fake_client.recalled_queries) == 1

    retained = await service.aretain(bank_id="test-bank", document="payload")
    assert retained == {"operation_id": "op-test-123"}
    assert len(fake_client.retained_payloads) == 1


@pytest.mark.asyncio
async def test_client_service_aclose_idempotent():
    """aclose() closes the client and is safe to call multiple times."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    assert service.is_closed is False
    await service.aclose()
    assert service.is_closed is True
    assert fake_client.close_count == 1

    # Second invocation is a no-op
    await service.aclose()
    assert fake_client.close_count == 1

    # Invocations after close raise error
    with pytest.raises(HindsightClientError, match="Cannot call arecall on closed"):
        await service.arecall(bank_id="test-bank", query="test")


@pytest.mark.asyncio
async def test_check_health_probes_list_banks_harmlessly():
    """check_health() executes list_banks(limit=1) read-only probe."""
    fake_client = FakeHindsightClient(outcome="success")
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    healthy, msg = await service.check_health()
    assert healthy is True
    assert msg == "available"
    assert fake_client.banks.call_count == 1


@pytest.mark.asyncio
async def test_check_health_unauthorized_mapping():
    """HTTP 401 Unauthorized maps to (False, 'unauthorized') without logging secrets."""
    fake_client = FakeHindsightClient(outcome="unauthorized")
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    healthy, msg = await service.check_health()
    assert healthy is False
    assert msg == "unauthorized"


@pytest.mark.asyncio
async def test_check_health_api_error_mapping():
    """API 500 error maps to (False, 'error_http_500')."""
    fake_client = FakeHindsightClient(outcome="api_error")
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    healthy, msg = await service.check_health()
    assert healthy is False
    assert "error_http_500" in msg


@pytest.mark.asyncio
async def test_check_health_connection_error_mapping():
    """Connection failure maps to (False, 'unreachable')."""
    fake_client = FakeHindsightClient(outcome="connection_error")
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    healthy, msg = await service.check_health()
    assert healthy is False
    assert msg == "unreachable"


# =============================================================================
# 3. FastAPI Lifespan Integration Tests
# =============================================================================

@pytest.mark.asyncio
async def test_lifespan_disabled_mode():
    """When Hindsight is disabled, client is not constructed and state is None."""
    test_app = FastAPI()
    mock_settings = Settings(
        HINDSIGHT_ENABLED=False,
        GEMINI_API_KEY=None,
        MITRE_REQUIRED=False,
        _env_file=None,
    )

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"):

        async with lifespan(test_app):
            assert test_app.state.hindsight_client is None

        assert test_app.state.hindsight_client is None


@pytest.mark.asyncio
async def test_lifespan_enabled_optional_mode():
    """When Hindsight is enabled and optional, service is constructed and closed on shutdown."""
    test_app = FastAPI()
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=False,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("token-xyz"),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        GEMINI_API_KEY=None,
        MITRE_REQUIRED=False,
        _env_file=None,
    )
    fake_client = FakeHindsightClient(outcome="success")

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.create_hindsight_client") as mock_factory:

        service_instance = HindsightClientService(
            client=fake_client,
            bank_id="sentinelagent-incident-memory-dev",
            base_url="http://localhost:8888",
            is_required=False,
        )
        mock_factory.return_value = service_instance

        async with lifespan(test_app):
            assert test_app.state.hindsight_client is service_instance
            assert test_app.state.hindsight_client.is_closed is False

        assert test_app.state.hindsight_client is None
        assert fake_client.closed is True
        assert fake_client.close_count == 1


@pytest.mark.asyncio
async def test_lifespan_partial_startup_failure_cleans_up_hindsight():
    """If startup fails after Hindsight client creation, client is closed during abort."""
    test_app = FastAPI()
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=False,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("token-xyz"),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        GEMINI_API_KEY=None,
        MITRE_REQUIRED=True,  # Will cause failure when catalogue fails
        _env_file=None,
    )
    fake_client = FakeHindsightClient(outcome="success")
    service_instance = HindsightClientService(
        client=fake_client,
        bank_id="sentinelagent-incident-memory-dev",
        base_url="http://localhost:8888",
    )
    mock_sweeper = MagicMock()
    mock_sweeper.stop = AsyncMock()

    # Simulate MITRE catalogue failure causing startup abort (step 4 aborts after step 2 created Hindsight)
    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper", return_value=mock_sweeper), \
         patch("app.main.create_hindsight_client", return_value=service_instance), \
         patch("app.main.MitreCatalogueService.from_file", side_effect=RuntimeError("Catalogue missing")):

        with pytest.raises(RuntimeError, match="Catalogue missing"):
            async with lifespan(test_app):
                pass

        # Hindsight client should have been closed in except BaseException:
        assert test_app.state.hindsight_client is None
        assert fake_client.closed is True
        assert fake_client.close_count == 1


@pytest.mark.asyncio
async def test_lifespan_gemini_lifecycle_coexists_with_hindsight():
    """Gemini provider and Hindsight client both initialize and close cleanly."""
    test_app = FastAPI()
    mock_settings = Settings(
        HINDSIGHT_ENABLED=True,
        HINDSIGHT_REQUIRED=False,
        HINDSIGHT_BASE_URL="http://localhost:8888",
        HINDSIGHT_API_KEY=SecretStr("token-xyz"),
        HINDSIGHT_HMAC_KEY=SecretStr("0123456789abcdef0123456789abcdef"),
        GEMINI_API_KEY=SecretStr("gemini-test-key"),
        MITRE_REQUIRED=False,
        _env_file=None,
    )
    fake_hindsight = FakeHindsightClient(outcome="success")
    mock_gemini_provider = MagicMock()

    with patch("app.main.get_settings", return_value=mock_settings), \
         patch("app.main.StaleInvestigationSweeper"), \
         patch("app.main.MitreCatalogueService"), \
         patch("app.main.create_gemini_client", return_value=mock_gemini_provider), \
         patch("app.main.create_hindsight_client") as mock_hindsight_factory:

        service_instance = HindsightClientService(
            client=fake_hindsight,
            bank_id="sentinelagent-incident-memory-dev",
            base_url="http://localhost:8888",
        )
        mock_hindsight_factory.return_value = service_instance

        async with lifespan(test_app):
            assert test_app.state.gemini_provider is mock_gemini_provider
            assert test_app.state.hindsight_client is service_instance

        # On shutdown, both are closed
        assert test_app.state.gemini_provider is None
        assert test_app.state.hindsight_client is None
        mock_gemini_provider.close.assert_called_once()
        assert fake_hindsight.closed is True
        assert fake_hindsight.close_count == 1


# =============================================================================
# 4. Outbox Async Retain Operation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_retain_investigation_memory_success():
    """retain_investigation_memory submits payload and preserves caller operation_id."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.retain_investigation_memory(
        bank_id="test-bank",
        document_id="doc-inc-12345",
        content='{"incident_id": "12345", "summary": "Brute force attack"}',
        operation_id="11111111-2222-3333-4444-555555555555",
        tags=["incident", "brute_force", "t1110"],
        update_mode="replace",
        retain_async=True,
    )

    assert isinstance(result, RetainSubmissionResult)
    assert result.success is True
    assert result.bank_id == "test-bank"
    assert result.operation_id == "11111111-2222-3333-4444-555555555555"
    assert result.items_count == 1
    assert result.is_async is True

    # Verify underlying aretain call parameters
    assert len(fake_client.retained_payloads) == 1
    _, kwargs = fake_client.retained_payloads[0]
    assert kwargs["bank_id"] == "test-bank"
    assert kwargs["document_id"] == "doc-inc-12345"
    assert kwargs["content"] == '{"incident_id": "12345", "summary": "Brute force attack"}'
    assert kwargs["operation_id"] == "11111111-2222-3333-4444-555555555555"
    assert kwargs["tags"] == ["incident", "brute_force", "t1110"]
    assert kwargs["update_mode"] == "replace"
    assert kwargs["retain_async"] is True


@pytest.mark.asyncio
async def test_retain_investigation_memory_with_sdk_model_response():
    """retain_investigation_memory properly parses RetainResponse SDK model."""
    fake_client = FakeHindsightClient()
    fake_client.retain_response = hindsight_models.RetainResponse(
        success=True,
        bank_id="test-bank",
        items_count=3,
        var_async=True,
        operation_id="matching-op-uuid",
    )
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.retain_investigation_memory(
        bank_id="test-bank",
        document_id="doc-1",
        content="serialized-memory-content",
        operation_id="matching-op-uuid",
    )

    assert result.success is True
    assert result.bank_id == "test-bank"
    assert result.operation_id == "matching-op-uuid"
    assert result.items_count == 3
    assert result.is_async is True


@pytest.mark.asyncio
async def test_retain_investigation_memory_input_validation():
    """retain_investigation_memory enforces strict argument types and values."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    valid_args = {
        "bank_id": "test-bank",
        "document_id": "doc-1",
        "content": '{"test": true}',
        "operation_id": "op-uuid-1",
    }

    # Empty or whitespace bank_id
    with pytest.raises(ValueError, match="bank_id must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "bank_id": ""})
    with pytest.raises(ValueError, match="bank_id must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "bank_id": "   "})

    # Empty or whitespace document_id
    with pytest.raises(ValueError, match="document_id must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "document_id": ""})
    with pytest.raises(ValueError, match="document_id must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "document_id": "   "})

    # Empty or whitespace operation_id
    with pytest.raises(ValueError, match="operation_id must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "operation_id": ""})
    with pytest.raises(ValueError, match="operation_id must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "operation_id": "   "})
    with pytest.raises(ValueError, match="leading or trailing whitespace"):
        await service.retain_investigation_memory(**{**valid_args, "operation_id": " op-uuid-1"})
    with pytest.raises(ValueError, match="leading or trailing whitespace"):
        await service.retain_investigation_memory(**{**valid_args, "operation_id": "op-uuid-1 "})

    # Content must be string, not dictionary or int
    with pytest.raises(TypeError, match="content must be a string, received dict"):
        await service.retain_investigation_memory(**{**valid_args, "content": {"key": "val"}})
    with pytest.raises(TypeError, match="content must be a string, received int"):
        await service.retain_investigation_memory(**{**valid_args, "content": 12345})

    # Content cannot be empty or whitespace
    with pytest.raises(ValueError, match="content must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "content": ""})
    with pytest.raises(ValueError, match="content must be a non-empty string"):
        await service.retain_investigation_memory(**{**valid_args, "content": "   "})

    # update_mode must be 'replace'
    with pytest.raises(ValueError, match="update_mode must be 'replace'"):
        await service.retain_investigation_memory(**{**valid_args, "update_mode": "append"})
    with pytest.raises(ValueError, match="update_mode must be 'replace'"):
        await service.retain_investigation_memory(**{**valid_args, "update_mode": "merge"})

    # retain_async must be True
    with pytest.raises(ValueError, match="retain_async must be True"):
        await service.retain_investigation_memory(**{**valid_args, "retain_async": False})


@pytest.mark.asyncio
async def test_retain_investigation_memory_closed_client_raises():
    """Calling retain_investigation_memory on closed service raises HindsightClientError."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )
    await service.aclose()

    with pytest.raises(HindsightClientError, match="Cannot perform operation on closed"):
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id="op-1",
        )


# =============================================================================
# 5. Operation Status Query Tests
# =============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("status_val", ["pending", "processing", "completed", "failed", "cancelled"])
async def test_get_operation_status_standard_statuses(status_val):
    """get_operation_status correctly captures standard Hindsight status values."""
    fake_client = FakeHindsightClient()
    fake_client.operations.status_response = {
        "operation_id": "op-status-123",
        "status": status_val,
        "operation_type": "retain",
        "created_at": "2026-11-09T17:00:00Z",
        "updated_at": "2026-11-09T17:01:00Z",
        "completed_at": "2026-11-09T17:02:00Z" if status_val in ("completed", "failed", "cancelled") else None,
        "retry_count": 1,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.get_operation_status(bank_id="test-bank", operation_id="op-status-123")

    assert isinstance(result, OperationStatusResult)
    assert result.operation_id == "op-status-123"
    assert result.status == status_val
    assert result.operation_type == "retain"
    assert result.retry_count == 1
    assert result.created_at == datetime(2026, 11, 9, 17, 0, 0, tzinfo=timezone.utc)
    assert result.updated_at == datetime(2026, 11, 9, 17, 1, 0, tzinfo=timezone.utc)
    if status_val in ("completed", "failed", "cancelled"):
        assert result.completed_at == datetime(2026, 11, 9, 17, 2, 0, tzinfo=timezone.utc)
    else:
        assert result.completed_at is None

    if status_val == "failed":
        assert result.has_error is True
        assert result.error_classification == "remote_failure"
    else:
        assert result.has_error is False
        assert result.error_classification is None


@pytest.mark.asyncio
async def test_get_operation_status_preserves_unknown_status():
    """get_operation_status preserves unknown status strings without misclassifying as completed."""
    fake_client = FakeHindsightClient()
    fake_client.operations.status_response = {
        "operation_id": "op-custom-999",
        "status": "evaluating_observation_scope",
        "operation_type": "retain",
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.get_operation_status(bank_id="test-bank", operation_id="op-custom-999")

    assert result.status == "evaluating_observation_scope"
    assert result.status != "completed"
    assert result.has_error is False
    assert result.error_classification is None


@pytest.mark.asyncio
async def test_get_operation_status_with_sdk_model_response():
    """get_operation_status correctly handles official OperationStatusResponse SDK model."""
    fake_client = FakeHindsightClient()
    fake_client.operations.status_response = hindsight_models.OperationStatusResponse(
        operation_id="op-sdk-model",
        status="processing",
        operation_type="retain",
        created_at="2026-11-09T18:30:00+00:00",
        error_message=None,
        retry_count=2,
    )
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.get_operation_status(bank_id="test-bank", operation_id="op-sdk-model")

    assert result.operation_id == "op-sdk-model"
    assert result.status == "processing"
    assert result.operation_type == "retain"
    assert result.created_at == datetime(2026, 11, 9, 18, 30, 0, tzinfo=timezone.utc)
    assert result.retry_count == 2
    assert result.has_error is False
    assert result.error_classification is None


@pytest.mark.asyncio
async def test_get_operation_status_validation_and_closed_checks():
    """get_operation_status validates arguments and checks closed state."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(ValueError, match="bank_id must be a non-empty string"):
        await service.get_operation_status(bank_id="", operation_id="op-1")
    with pytest.raises(ValueError, match="bank_id must be a non-empty string"):
        await service.get_operation_status(bank_id="   ", operation_id="op-1")
    with pytest.raises(ValueError, match="operation_id must be a non-empty string"):
        await service.get_operation_status(bank_id="test-bank", operation_id="")
    with pytest.raises(ValueError, match="operation_id must be a non-empty string"):
        await service.get_operation_status(bank_id="test-bank", operation_id="   ")

    await service.aclose()
    with pytest.raises(HindsightClientError, match="Cannot perform operation on closed"):
        await service.get_operation_status(bank_id="test-bank", operation_id="op-1")


# =============================================================================
# 6. Retry Operation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_retry_operation_success_preserves_id():
    """retry_operation preserves original caller operation_id without generating new UUID."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    original_op_id = "op-uuid-retry-target"
    result = await service.retry_operation(bank_id="test-bank", operation_id=original_op_id)

    assert isinstance(result, OperationRetryResult)
    assert result.success is True
    assert result.operation_id == original_op_id
    assert result.message == "Operation retry scheduled"

    assert len(fake_client.operations.retry_calls) == 1
    call = fake_client.operations.retry_calls[0]
    assert call["bank_id"] == "test-bank"
    assert call["operation_id"] == original_op_id


@pytest.mark.asyncio
async def test_retry_operation_with_sdk_model_response():
    """retry_operation handles official RetryOperationResponse SDK model."""
    fake_client = FakeHindsightClient()
    fake_client.operations.retry_response = hindsight_models.RetryOperationResponse(
        success=True,
        operation_id="op-model-retry",
        message="Retry dispatched successfully",
    )
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.retry_operation(bank_id="test-bank", operation_id="op-model-retry")

    assert result.success is True
    assert result.operation_id == "op-model-retry"
    assert result.message == "Retry dispatched successfully"


@pytest.mark.asyncio
async def test_retry_operation_validation_and_closed_checks():
    """retry_operation validates arguments and checks closed state."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(ValueError, match="bank_id must be a non-empty string"):
        await service.retry_operation(bank_id="", operation_id="op-1")
    with pytest.raises(ValueError, match="bank_id must be a non-empty string"):
        await service.retry_operation(bank_id="   ", operation_id="op-1")
    with pytest.raises(ValueError, match="operation_id must be a non-empty string"):
        await service.retry_operation(bank_id="test-bank", operation_id="")
    with pytest.raises(ValueError, match="operation_id must be a non-empty string"):
        await service.retry_operation(bank_id="test-bank", operation_id="   ")

    await service.aclose()
    with pytest.raises(HindsightClientError, match="Cannot perform operation on closed"):
        await service.retry_operation(bank_id="test-bank", operation_id="op-1")


# =============================================================================
# 7. Exception Mapping and Privacy / Sanitization Tests
# =============================================================================

@pytest.mark.asyncio
async def test_exception_mapping_hierarchy():
    """SDK exceptions map into specific typed HindsightClientError subclasses."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    # 401 Unauthorized
    fake_client.retain_side_effect = hindsight_exceptions.UnauthorizedException(status=401, reason="Unauthorized")
    with pytest.raises(HindsightAuthenticationError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.status_code == 401
    assert exc_info.value.error_code == "AUTHENTICATION_FAILED"

    # 403 Forbidden
    fake_client.retain_side_effect = hindsight_exceptions.ForbiddenException(status=403, reason="Forbidden")
    with pytest.raises(HindsightAuthenticationError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.status_code == 403

    # 409 Conflict
    fake_client.retain_side_effect = hindsight_exceptions.ApiException(status=409, reason="Conflict")
    with pytest.raises(HindsightConflictError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.status_code == 409
    assert exc_info.value.error_code == "CONFLICT"

    # 400 BadRequest
    fake_client.retain_side_effect = hindsight_exceptions.BadRequestException(status=400, reason="Bad Request")
    with pytest.raises(HindsightValidationError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.status_code == 400
    assert exc_info.value.error_code == "VALIDATION_ERROR"

    # 422 Unprocessable Entity
    fake_client.retain_side_effect = hindsight_exceptions.ApiException(status=422, reason="Unprocessable Entity")
    with pytest.raises(HindsightValidationError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.status_code == 422

    # 404 NotFound
    fake_client.operations.status_side_effect = hindsight_exceptions.NotFoundException(status=404, reason="Not Found")
    with pytest.raises(HindsightNotFoundError) as exc_info:
        await service.get_operation_status(bank_id="test-bank", operation_id="op-missing")
    assert exc_info.value.status_code == 404
    assert exc_info.value.error_code == "NOT_FOUND"

    # 429 RateLimit with Retry-After header
    class RateLimitApiException(hindsight_exceptions.ApiException):
        def __init__(self):
            super().__init__(status=429, reason="Too Many Requests")
            self.headers = {"Retry-After": "45.5"}

    fake_client.retain_side_effect = RateLimitApiException()
    with pytest.raises(HindsightRateLimitError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.status_code == 429
    assert exc_info.value.error_code == "RATE_LIMITED"
    assert exc_info.value.retry_after == 45.5

    # 500 ServiceException
    fake_client.operations.retry_side_effect = hindsight_exceptions.ServiceException(status=503, reason="Service Unavailable")
    with pytest.raises(HindsightServerError) as exc_info:
        await service.retry_operation(bank_id="test-bank", operation_id="op-1")
    assert exc_info.value.status_code == 503
    assert exc_info.value.error_code == "SERVER_ERROR"

    # Timeout
    fake_client.retain_side_effect = asyncio.TimeoutError("Client timeout")
    with pytest.raises(HindsightTimeoutError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.error_code == "TIMEOUT"

    # Connection Error
    fake_client.retain_side_effect = ConnectionResetError("Connection reset by peer")
    with pytest.raises(HindsightConnectionError) as exc_info:
        await service.retain_investigation_memory(bank_id="test-bank", document_id="d1", content="{}", operation_id="op-1")
    assert exc_info.value.error_code == "CONNECTION_ERROR"


@pytest.mark.asyncio
async def test_privacy_sanitization_does_not_leak_payload_or_credentials(caplog):
    """Exception messages and logs must never leak sensitive bodies, headers, or memory content."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    sensitive_token = "Bearer secret-top-secret-token-12345"
    sensitive_memory_payload = '{"incident_id": "123", "confidential_finding": "Zero-day exploited"}'

    # Simulate an OpenAPI exception whose raw attributes contain sensitive tokens and bodies
    class LeakyApiException(hindsight_exceptions.ApiException):
        def __init__(self):
            super().__init__(status=500, reason="Internal Server Error")
            self.body = f"Server crashed while processing {sensitive_memory_payload}"
            self.headers = {"Authorization": sensitive_token}

    fake_client.retain_side_effect = LeakyApiException()

    with caplog.at_level(logging.WARNING):
        with pytest.raises(HindsightServerError) as exc_info:
            await service.retain_investigation_memory(
                bank_id="test-bank",
                document_id="doc-inc-1",
                content=sensitive_memory_payload,
                operation_id="op-sanitize-1",
            )

    # 1. Verify raised exception message contains NO leaked secrets or payload
    raised_message = str(exc_info.value)
    assert sensitive_token not in raised_message
    assert sensitive_memory_payload not in raised_message
    assert "Zero-day exploited" not in raised_message

    # 2. Verify logged records contain NO leaked secrets or payload
    for record in caplog.records:
        assert sensitive_token not in record.message
        assert sensitive_memory_payload not in record.message
        assert "Zero-day exploited" not in record.message


# =============================================================================
# 8. Retain Submission Identity & Protocol Error Tests
# =============================================================================

@pytest.mark.asyncio
async def test_retain_submission_matching_id_succeeds():
    """Matching returned operation ID succeeds and returns RetainSubmissionResult."""
    fake_client = FakeHindsightClient()
    caller_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    fake_client.retain_response = {
        "success": True,
        "bank_id": "test-bank",
        "operation_id": caller_uuid,
        "items_count": 1,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.retain_investigation_memory(
        bank_id="test-bank",
        document_id="doc-1",
        content='{"test": 1}',
        operation_id=caller_uuid,
    )

    assert result.success is True
    assert result.operation_id == caller_uuid
    assert result.is_async is True


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_id", [None, "", "   "])
async def test_retain_submission_missing_id_fails(missing_id):
    """Missing or empty returned operation ID raises HindsightProtocolError."""
    fake_client = FakeHindsightClient()
    fake_client.retain_response = {
        "success": True,
        "bank_id": "test-bank",
        "operation_id": missing_id,
        "items_count": 1,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id="expected-caller-uuid",
        )

    assert "missing or empty operation ID" in str(exc_info.value)
    assert exc_info.value.error_code == "PROTOCOL_ERROR"


@pytest.mark.asyncio
async def test_retain_submission_mismatched_id_fails():
    """Mismatched returned operation ID raises HindsightProtocolError."""
    fake_client = FakeHindsightClient()
    fake_client.retain_response = {
        "success": True,
        "bank_id": "test-bank",
        "operation_id": "unexpected-different-uuid-9999",
        "items_count": 1,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id="expected-caller-uuid",
        )

    assert "mismatched operation ID" in str(exc_info.value)
    assert exc_info.value.error_code == "PROTOCOL_ERROR"


@pytest.mark.asyncio
async def test_retain_submission_returned_id_leading_whitespace_fails():
    """Returned operation ID with leading whitespace fails without calling .strip()."""
    fake_client = FakeHindsightClient()
    caller_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    fake_client.retain_response = {
        "success": True,
        "bank_id": "test-bank",
        "operation_id": f" {caller_uuid}",
        "items_count": 1,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id=caller_uuid,
        )

    assert "mismatched operation ID" in str(exc_info.value)
    assert exc_info.value.error_code == "PROTOCOL_ERROR"


@pytest.mark.asyncio
async def test_retain_submission_returned_id_trailing_whitespace_fails():
    """Returned operation ID with trailing whitespace fails without calling .strip()."""
    fake_client = FakeHindsightClient()
    caller_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    fake_client.retain_response = {
        "success": True,
        "bank_id": "test-bank",
        "operation_id": f"{caller_uuid} ",
        "items_count": 1,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id=caller_uuid,
        )

    assert "mismatched operation ID" in str(exc_info.value)
    assert exc_info.value.error_code == "PROTOCOL_ERROR"


@pytest.mark.asyncio
async def test_retain_submission_success_false_fails():
    """Retain response with success=False raises HindsightProtocolError."""
    fake_client = FakeHindsightClient()
    fake_client.retain_response = {
        "success": False,
        "bank_id": "test-bank",
        "operation_id": "caller-uuid-1",
        "items_count": 0,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id="caller-uuid-1",
        )

    assert "success=False" in str(exc_info.value)
    assert exc_info.value.error_code == "PROTOCOL_ERROR"


@pytest.mark.asyncio
async def test_retain_submission_var_async_false_fails():
    """Retain response with var_async=False raises HindsightProtocolError."""
    fake_client = FakeHindsightClient()
    fake_client.retain_response = {
        "success": True,
        "bank_id": "test-bank",
        "operation_id": "caller-uuid-1",
        "items_count": 1,
        "var_async": False,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content='{"test": 1}',
            operation_id="caller-uuid-1",
        )

    assert "did not confirm asynchronous execution" in str(exc_info.value)
    assert exc_info.value.error_code == "PROTOCOL_ERROR"


@pytest.mark.asyncio
async def test_retain_submission_protocol_error_sanitization():
    """Protocol error messages must not leak memory payload or sensitive content."""
    fake_client = FakeHindsightClient()
    sensitive_payload = '{"secret_token": "super-confidential-credential-12345"}'
    fake_client.retain_response = {
        "success": False,
        "bank_id": "test-bank",
        "operation_id": "caller-uuid-1",
        "items_count": 0,
        "var_async": True,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with pytest.raises(HindsightProtocolError) as exc_info:
        await service.retain_investigation_memory(
            bank_id="test-bank",
            document_id="doc-1",
            content=sensitive_payload,
            operation_id="caller-uuid-1",
        )

    msg = str(exc_info.value)
    assert sensitive_payload not in msg
    assert "super-confidential-credential" not in msg


# =============================================================================
# 9. Operation Status Privacy & Error Classification Tests
# =============================================================================

@pytest.mark.asyncio
async def test_operation_status_privacy_raw_error_message_never_exposed():
    """Raw upstream error_message is never exposed on OperationStatusResult."""
    fake_client = FakeHindsightClient()
    sensitive_upstream_error = "DB_EXCEPTION: Table leak password=dbpass123 at host internal.db:5432"
    fake_client.operations.status_response = {
        "operation_id": "op-err-priv-1",
        "status": "failed",
        "operation_type": "retain",
        "error_message": sensitive_upstream_error,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.get_operation_status(bank_id="test-bank", operation_id="op-err-priv-1")

    # 1. error_message attribute must NOT exist on result DTO
    assert not hasattr(result, "error_message")

    # 2. has_error and classification are safe
    assert result.has_error is True
    assert result.error_classification == "remote_failure"
    assert result.error_classification in ALLOWED_ERROR_CLASSIFICATIONS

    # 3. Sensitive text is not in DTO string representation
    assert sensitive_upstream_error not in repr(result)
    assert "dbpass123" not in repr(result)
    assert "internal.db" not in repr(result)


@pytest.mark.asyncio
async def test_operation_status_unknown_status_with_error():
    """Unknown remote status with an error reports unknown_remote_failure while preserving status."""
    fake_client = FakeHindsightClient()
    fake_client.operations.status_response = {
        "operation_id": "op-custom-err-1",
        "status": "circuit_breaker_interrupted",
        "operation_type": "retain",
        "error_message": "Some internal server diagnostic",
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    result = await service.get_operation_status(bank_id="test-bank", operation_id="op-custom-err-1")

    assert result.status == "circuit_breaker_interrupted"
    assert result.has_error is True
    assert result.error_classification == "unknown_remote_failure"
    assert result.error_classification in ALLOWED_ERROR_CLASSIFICATIONS
    assert not hasattr(result, "error_message")


@pytest.mark.asyncio
async def test_operation_status_classification_allowlist():
    """All error classifications must come strictly from ALLOWED_ERROR_CLASSIFICATIONS."""
    fake_client = FakeHindsightClient()
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    test_cases = [
        ({"status": "completed", "error_message": None}, False, None),
        ({"status": "pending", "error_message": None}, False, None),
        ({"status": "processing", "error_message": None}, False, None),
        ({"status": "failed", "error_message": "failed detail"}, True, "remote_failure"),
        ({"status": "failed", "error_message": None}, True, "remote_failure"),
        ({"status": "unrecognized_state", "error_message": "err"}, True, "unknown_remote_failure"),
        ({"status": "unrecognized_state", "error_message": None}, False, None),
    ]

    for resp_data, expected_has_error, expected_classification in test_cases:
        fake_client.operations.status_response = {
            "operation_id": "op-allowlist-check",
            "operation_type": "retain",
            **resp_data,
        }
        result = await service.get_operation_status(bank_id="test-bank", operation_id="op-allowlist-check")

        assert result.has_error is expected_has_error
        assert result.error_classification == expected_classification
        if result.error_classification is not None:
            assert result.error_classification in ALLOWED_ERROR_CLASSIFICATIONS


@pytest.mark.asyncio
async def test_operation_status_logs_never_contain_raw_error_message(caplog):
    """Logs during get_operation_status must never contain raw upstream error message."""
    fake_client = FakeHindsightClient()
    secret_db_string = "SECRET_SQL_INJECTION_DETAIL_xyz999"
    fake_client.operations.status_response = {
        "operation_id": "op-log-privacy",
        "status": "failed",
        "operation_type": "retain",
        "error_message": secret_db_string,
    }
    service = HindsightClientService(
        client=fake_client,
        bank_id="test-bank",
        base_url="http://localhost:8888",
    )

    with caplog.at_level(logging.DEBUG):
        result = await service.get_operation_status(bank_id="test-bank", operation_id="op-log-privacy")

    assert result.has_error is True
    for record in caplog.records:
        assert secret_db_string not in record.message



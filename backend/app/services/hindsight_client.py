"""Hindsight Client Foundation and Service Integration for SentinelAgent.

Provides an application-scoped asynchronous client wrapper around the official
hindsight-client SDK, supporting Bearer authentication, connection pooling,
graceful cleanup, harmless read-only health probing, and durable asynchronous
outbox retention operations with privacy-sanitized error handling.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import logging
import math
import re
from typing import Any, Optional, Sequence, Tuple, Union

import aiohttp
from hindsight_client import Hindsight
import hindsight_client_api.exceptions as hindsight_exceptions

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


# =============================================================================
# Exception Hierarchy
# =============================================================================

class HindsightConfigurationError(Exception):
    """Raised when Hindsight configuration is missing or invalid."""
    pass


class HindsightClientError(Exception):
    """Base exception for Hindsight client operation failures."""

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        error_code: str = "CLIENT_ERROR",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code


class HindsightAuthenticationError(HindsightClientError):
    """Raised when authentication against Hindsight fails (HTTP 401 or 403)."""

    def __init__(
        self,
        message: str = "Hindsight authentication failed",
        status_code: int = 401,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="AUTHENTICATION_FAILED",
        )


class HindsightConflictError(HindsightClientError):
    """Raised when an operation conflicts with an existing operation or lock in Hindsight (HTTP 409)."""

    def __init__(
        self,
        message: str = "Hindsight operation conflict",
        status_code: int = 409,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="CONFLICT",
        )


class HindsightValidationError(HindsightClientError):
    """Raised when request validation fails on client or server side (HTTP 400 or 422)."""

    def __init__(
        self,
        message: str = "Hindsight validation failed",
        status_code: int = 400,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="VALIDATION_ERROR",
        )


class HindsightRateLimitError(HindsightClientError):
    """Raised when Hindsight rate limits requests (HTTP 429)."""

    def __init__(
        self,
        message: str = "Hindsight rate limit exceeded",
        status_code: int = 429,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="RATE_LIMITED",
        )
        self.retry_after = retry_after


class HindsightNotFoundError(HindsightClientError):
    """Raised when a requested resource or operation is not found in Hindsight (HTTP 404)."""

    def __init__(
        self,
        message: str = "Hindsight resource not found",
        status_code: int = 404,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="NOT_FOUND",
        )


class HindsightServerError(HindsightClientError):
    """Raised when Hindsight returns 5xx server error."""

    def __init__(
        self,
        message: str = "Hindsight internal server error",
        status_code: int = 500,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="SERVER_ERROR",
        )


class HindsightTimeoutError(HindsightClientError):
    """Raised when a request to Hindsight times out."""

    def __init__(
        self,
        message: str = "Hindsight request timed out",
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="TIMEOUT",
        )


class HindsightConnectionError(HindsightClientError):
    """Raised when connection to Hindsight daemon fails."""

    def __init__(
        self,
        message: str = "Hindsight service unreachable",
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="CONNECTION_ERROR",
        )


class HindsightProtocolError(HindsightClientError):
    """Raised when Hindsight returns a response violating protocol contracts."""

    def __init__(
        self,
        message: str = "Hindsight response violated protocol expectations",
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="PROTOCOL_ERROR",
        )


# =============================================================================
# Typed Response DTOs
# =============================================================================

ALLOWED_ERROR_CLASSIFICATIONS = frozenset({
    "remote_failure",
    "remote_failure_retryable",
    "remote_failure_permanent",
    "unknown_remote_failure",
})


@dataclass(frozen=True)
class RetainSubmissionResult:
    """Typed result of asynchronous retain submission to Hindsight."""

    success: bool
    bank_id: str
    operation_id: str
    items_count: int
    is_async: bool


@dataclass(frozen=True)
class OperationStatusResult:
    """Typed status of an asynchronous Hindsight operation."""

    operation_id: str
    status: str
    operation_type: Optional[str] = None
    has_error: bool = False
    error_classification: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retry_count: Optional[int] = None


@dataclass(frozen=True)
class OperationRetryResult:
    """Typed result of retrying an asynchronous operation."""

    success: bool
    operation_id: str
    message: Optional[str] = None


PERMITTED_HINDSIGHT_FACT_TYPES = frozenset({"world", "experience", "observation"})
RECALL_IDENTITY_TAG_PATTERN = re.compile(r"^(ip|user):([a-zA-Z0-9_-]{1,16}):([0-9a-f]{32})$")


@dataclass(frozen=True)
class HindsightRecallItem:
    """Immutable representation of a validated historical memory item retrieved from Hindsight.

    Forensic & Epistemic Boundaries:
    - Text represents structurally validated Hindsight content, treated strictly as
      untrusted historical context. It is NOT guaranteed to be fully sanitized; prompt
      safety filtering and quotation boundaries are enforced downstream in Task 9D.4.
    - Recalled memories are strictly unverified historical intelligence. They do not
      carry authoritative evidence classifications and cannot enter AuthorizedProvenanceSet.
    - HMAC metadata is minimized to protect privacy: neither the requested tag nor
      unrelated remote tags are exposed in the DTO. The scope_verified flag certifies
      that the item was cryptographically matched to the requested scope by the adapter.
    """

    id: str
    text: str
    fact_type: Optional[str]
    scope_verified: bool
    context: Optional[str] = None
    document_id: Optional[str] = None
    occurred_start: Optional[datetime] = None
    occurred_end: Optional[datetime] = None
    mentioned_at: Optional[datetime] = None
    rank: int = 1

    def __post_init__(self) -> None:
        if self.scope_verified is not True:
            raise ValueError("HindsightRecallItem must have scope_verified=True.")


@dataclass(frozen=True)
class HindsightRecallResult:
    """Immutable typed result of a single scoped asynchronous recall operation against Hindsight."""

    bank_id: str
    query: str
    items: tuple[HindsightRecallItem, ...]
    total_count: int


def validate_recall_tag(tag: Any) -> str:
    """Validate that tag is a single canonical pseudonymous identity tag.

    Permitted families:
    - ip:<version>:<32 lowercase hex characters>
    - user:<version>:<32 lowercase hex characters>

    Rejects empty, missing, multiple, raw IP, raw username, and malformed tags
    without leaking sensitive raw identifiers in error messages.
    """
    if not isinstance(tag, str) or not tag.strip():
        raise HindsightValidationError("Identity tag for recall cannot be empty.")
    clean_tag = tag.strip()
    if not RECALL_IDENTITY_TAG_PATTERN.match(clean_tag):
        raise HindsightValidationError(
            "Invalid identity tag for recall: must match canonical 'ip:<version>:<32hex>' "
            "or 'user:<version>:<32hex>' format."
        )
    return clean_tag


def _parse_datetime(val: Any) -> Optional[datetime]:
    """Safely parse datetime from ISO string or existing datetime object."""
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str) and val.strip():
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    return None


# =============================================================================
# Service Implementation
# =============================================================================

class HindsightClientService:
    """Application-scoped async wrapper for official Hindsight SDK."""

    def __init__(
        self,
        client: Hindsight,
        bank_id: str,
        base_url: str,
        is_required: bool = False,
    ) -> None:
        self._client = client
        self._bank_id = bank_id
        self._base_url = base_url.rstrip("/")
        self._is_required = is_required
        self._closed = False

    @property
    def client(self) -> Hindsight:
        """Underlying official Hindsight client instance."""
        return self._client

    @property
    def bank_id(self) -> str:
        """Resolved memory bank identifier."""
        return self._bank_id

    @property
    def base_url(self) -> str:
        """Hindsight server base URL."""
        return self._base_url

    @property
    def is_required(self) -> bool:
        """Whether Hindsight memory is mandatory for application operation."""
        return self._is_required

    @property
    def is_closed(self) -> bool:
        """True if the underlying client has been asynchronously closed."""
        return self._closed

    @staticmethod
    def _map_exception(exc: Exception, operation_context: str) -> HindsightClientError:
        """Map SDK/aiohttp/network exceptions into typed HindsightClientError subclasses.

        Sanitizes error messages to prevent leakage of HTTP request/response
        bodies, authorization headers, or sensitive payload data.
        """
        if isinstance(exc, HindsightClientError):
            return exc

        # Handle Timeout errors
        if isinstance(exc, (asyncio.TimeoutError, TimeoutError, aiohttp.ServerTimeoutError)):
            logger.warning(
                "Hindsight timeout during %s: type=%s",
                operation_context,
                type(exc).__name__,
            )
            return HindsightTimeoutError(
                f"Hindsight request timed out during {operation_context}"
            )

        # Handle Connection errors
        if isinstance(exc, (ConnectionError, aiohttp.ClientConnectionError, aiohttp.ClientError)):
            logger.warning(
                "Hindsight connection error during %s: type=%s",
                operation_context,
                type(exc).__name__,
            )
            return HindsightConnectionError(
                f"Hindsight service unreachable during {operation_context}"
            )

        # Handle SDK UnauthorizedException (HTTP 401)
        if isinstance(exc, hindsight_exceptions.UnauthorizedException):
            logger.warning(
                "Hindsight authentication failure during %s: status=401",
                operation_context,
            )
            return HindsightAuthenticationError(
                f"Hindsight authentication failed (HTTP 401) during {operation_context}",
                status_code=401,
            )

        # Handle SDK ForbiddenException (HTTP 403)
        if isinstance(exc, hindsight_exceptions.ForbiddenException):
            logger.warning(
                "Hindsight access forbidden during %s: status=403",
                operation_context,
            )
            return HindsightAuthenticationError(
                f"Hindsight access forbidden (HTTP 403) during {operation_context}",
                status_code=403,
            )

        # Handle SDK NotFoundException (HTTP 404)
        if isinstance(exc, hindsight_exceptions.NotFoundException):
            logger.warning(
                "Hindsight resource not found during %s: status=404",
                operation_context,
            )
            return HindsightNotFoundError(
                f"Hindsight resource not found (HTTP 404) during {operation_context}",
                status_code=404,
            )

        # Handle SDK BadRequestException (HTTP 400)
        if isinstance(exc, hindsight_exceptions.BadRequestException):
            logger.warning(
                "Hindsight validation error during %s: status=400",
                operation_context,
            )
            return HindsightValidationError(
                f"Hindsight validation error (HTTP 400) during {operation_context}",
                status_code=400,
            )

        # Handle SDK ServiceException (HTTP 5xx)
        if isinstance(exc, hindsight_exceptions.ServiceException):
            status = getattr(exc, "status", 500)
            logger.warning(
                "Hindsight server error during %s: status=%s",
                operation_context,
                status,
            )
            return HindsightServerError(
                f"Hindsight server error (HTTP {status}) during {operation_context}",
                status_code=status,
            )

        # Handle generic ApiException from OpenAPI generator
        if isinstance(exc, hindsight_exceptions.ApiException):
            status = getattr(exc, "status", None)
            logger.warning(
                "Hindsight API exception during %s: status=%s",
                operation_context,
                status,
            )

            if status in (401, 403):
                return HindsightAuthenticationError(
                    f"Hindsight authentication failed (HTTP {status}) during {operation_context}",
                    status_code=status,
                )
            elif status == 409:
                return HindsightConflictError(
                    f"Hindsight operation conflict (HTTP 409) during {operation_context}",
                    status_code=409,
                )
            elif status in (400, 422):
                return HindsightValidationError(
                    f"Hindsight validation error (HTTP {status}) during {operation_context}",
                    status_code=status,
                )
            elif status == 404:
                return HindsightNotFoundError(
                    f"Hindsight resource not found (HTTP 404) during {operation_context}",
                    status_code=404,
                )
            elif status == 429:
                retry_after: Optional[float] = None
                headers = getattr(exc, "headers", None)
                if headers and hasattr(headers, "get"):
                    raw_ra = headers.get("Retry-After") or headers.get("retry-after")
                    if raw_ra is not None:
                        try:
                            retry_after = float(raw_ra)
                        except (ValueError, TypeError):
                            pass
                return HindsightRateLimitError(
                    f"Hindsight rate limit exceeded (HTTP 429) during {operation_context}",
                    status_code=429,
                    retry_after=retry_after,
                )
            elif status is not None and 500 <= status < 600:
                return HindsightServerError(
                    f"Hindsight server error (HTTP {status}) during {operation_context}",
                    status_code=status,
                )
            else:
                return HindsightClientError(
                    f"Hindsight API error (HTTP {status or 'unknown'}) during {operation_context}",
                    status_code=status,
                )

        # General unmapped error fallback
        logger.warning(
            "Unexpected Hindsight error during %s: type=%s",
            operation_context,
            type(exc).__name__,
        )
        return HindsightClientError(
            f"Unexpected Hindsight error ({type(exc).__name__}) during {operation_context}"
        )

    async def check_health(self) -> Tuple[bool, str]:
        """Perform a harmless, authenticated read-only readiness check.

        Queries the bank list API endpoint with limit=1 to verify both
        network reachability and Bearer token authentication without mutating
        or creating any memory banks.

        Returns:
            Tuple of (is_healthy, detail_message).
        """
        if self._closed:
            return False, "Hindsight client is closed"

        try:
            # Query banks with limit=1: harmless, authenticated read-only probe
            await self._client.banks.list_banks(limit=1)
            return True, "available"
        except (hindsight_exceptions.UnauthorizedException, hindsight_exceptions.ForbiddenException) as exc:
            logger.warning(
                "Hindsight authentication failed (HTTP %s): invalid or missing API key",
                getattr(exc, "status", 401),
            )
            return False, "unauthorized"
        except hindsight_exceptions.ApiException as exc:
            logger.warning(
                "Hindsight API returned error during readiness probe (HTTP %s)",
                getattr(exc, "status", "unknown"),
            )
            return False, f"error_http_{getattr(exc, 'status', 'unknown')}"
        except Exception as exc:
            logger.warning(
                "Hindsight service unreachable during readiness probe: %s",
                type(exc).__name__,
            )
            return False, "unreachable"

    async def arecall(self, *args: Any, **kwargs: Any) -> Any:
        """Delegate asynchronous recall call to the official SDK."""
        if self._closed:
            raise HindsightClientError("Cannot call arecall on closed Hindsight client")
        return await self._client.arecall(*args, **kwargs)

    async def aretain(self, *args: Any, **kwargs: Any) -> Any:
        """Delegate asynchronous retain call to the official SDK."""
        if self._closed:
            raise HindsightClientError("Cannot call aretain on closed Hindsight client")
        return await self._client.aretain(*args, **kwargs)

    async def retain_investigation_memory(
        self,
        bank_id: str,
        document_id: str,
        content: str,
        operation_id: str,
        tags: Optional[Sequence[str]] = None,
        update_mode: str = "replace",
        retain_async: bool = True,
    ) -> RetainSubmissionResult:
        """Submit an outbox record's serialized payload to Hindsight asynchronously.

        Args:
            bank_id: Non-empty target bank identifier.
            document_id: Non-empty document identifier.
            content: Non-empty serialized JSON memory payload string.
            operation_id: Caller-supplied idempotency key (outbox row UUID).
            tags: Optional sequence of string tags.
            update_mode: Must be "replace".
            retain_async: Must be True.

        Returns:
            RetainSubmissionResult capturing submission status and operation ID.

        Raises:
            HindsightClientError: If client is closed or Hindsight returns an error.
            ValueError: If string arguments are empty or update_mode/retain_async invalid.
            TypeError: If content is not a string.
        """
        if self._closed:
            raise HindsightClientError("Cannot perform operation on closed Hindsight client")

        if not isinstance(bank_id, str) or not bank_id.strip():
            raise ValueError("bank_id must be a non-empty string")
        if not isinstance(document_id, str) or not document_id.strip():
            raise ValueError("document_id must be a non-empty string")
        if not isinstance(content, str):
            raise TypeError(f"content must be a string, received {type(content).__name__}")
        if not content.strip():
            raise ValueError("content must be a non-empty string")
        if not isinstance(operation_id, str) or not operation_id.strip() or operation_id != operation_id.strip():
            raise ValueError("operation_id must be a non-empty string without leading or trailing whitespace")
        if update_mode != "replace":
            raise ValueError(f"update_mode must be 'replace', received {update_mode!r}")
        if retain_async is not True:
            raise ValueError(f"retain_async must be True, received {retain_async!r}")

        clean_bank_id = bank_id.strip()
        clean_doc_id = document_id.strip()
        clean_tags = [str(t) for t in tags] if tags is not None else None

        try:
            response = await self._client.aretain(
                bank_id=clean_bank_id,
                content=content,
                document_id=clean_doc_id,
                tags=clean_tags,
                update_mode=update_mode,
                retain_async=True,
                operation_id=operation_id,
            )
        except Exception as exc:
            raise self._map_exception(exc, "retain_investigation_memory") from None

        if isinstance(response, dict):
            success = bool(response.get("success", False))
            resp_bank_id = str(response.get("bank_id") or clean_bank_id)
            resp_op_id = response.get("operation_id")
            items_count = int(response.get("items_count", 0) or 0)
            is_async = bool(response.get("var_async", response.get("is_async", False)))
        else:
            success = bool(getattr(response, "success", False))
            resp_bank_id = str(getattr(response, "bank_id", None) or clean_bank_id)
            resp_op_id = getattr(response, "operation_id", None)
            items_count = int(getattr(response, "items_count", 0) or 0)
            is_async = bool(getattr(response, "var_async", getattr(response, "is_async", False)))

        # Enforce returned operation identity and protocol contracts
        if not success:
            raise HindsightProtocolError(
                "Hindsight retain submission returned success=False"
            )

        if not is_async:
            raise HindsightProtocolError(
                "Hindsight retain submission did not confirm asynchronous execution"
            )

        if not resp_op_id or not isinstance(resp_op_id, str) or not resp_op_id.strip():
            raise HindsightProtocolError(
                "Hindsight retain submission returned missing or empty operation ID"
            )

        if resp_op_id != operation_id:
            raise HindsightProtocolError(
                "Hindsight retain submission returned mismatched operation ID"
            )

        return RetainSubmissionResult(
            success=True,
            bank_id=resp_bank_id,
            operation_id=operation_id,
            items_count=items_count,
            is_async=True,
        )

    async def get_operation_status(
        self,
        bank_id: str,
        operation_id: str,
    ) -> OperationStatusResult:
        """Query the current execution status of an asynchronous Hindsight operation.

        Args:
            bank_id: Non-empty target bank identifier.
            operation_id: Non-empty operation UUID string.

        Returns:
            OperationStatusResult with normalized status and timestamps.

        Raises:
            HindsightClientError: If client is closed or Hindsight returns an error.
            ValueError: If bank_id or operation_id are empty or not strings.
        """
        if self._closed:
            raise HindsightClientError("Cannot perform operation on closed Hindsight client")

        if not isinstance(bank_id, str) or not bank_id.strip():
            raise ValueError("bank_id must be a non-empty string")
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise ValueError("operation_id must be a non-empty string")

        clean_bank_id = bank_id.strip()
        clean_op_id = operation_id.strip()

        try:
            raw = await self._client.operations.get_operation_status(
                bank_id=clean_bank_id,
                operation_id=clean_op_id,
            )
        except Exception as exc:
            raise self._map_exception(exc, "get_operation_status") from None

        if isinstance(raw, dict):
            op_id = str(raw.get("operation_id") or clean_op_id)
            status = str(raw.get("status", "unknown"))
            op_type = raw.get("operation_type")
            raw_has_error = bool(raw.get("error_message"))
            created_at = _parse_datetime(raw.get("created_at"))
            updated_at = _parse_datetime(raw.get("updated_at"))
            completed_at = _parse_datetime(raw.get("completed_at"))
            retry_count = raw.get("retry_count")
        else:
            op_id = str(getattr(raw, "operation_id", None) or clean_op_id)
            status = str(getattr(raw, "status", "unknown"))
            op_type = getattr(raw, "operation_type", None)
            raw_has_error = bool(getattr(raw, "error_message", None))
            created_at = _parse_datetime(getattr(raw, "created_at", None))
            updated_at = _parse_datetime(getattr(raw, "updated_at", None))
            completed_at = _parse_datetime(getattr(raw, "completed_at", None))
            retry_count = getattr(raw, "retry_count", None)

        # Derive sanitized error classification without exposing raw upstream error strings
        has_error = (status == "failed") or raw_has_error
        error_classification: Optional[str] = None
        if has_error:
            if status == "failed":
                error_classification = "remote_failure"
            elif status in ("pending", "processing", "completed"):
                error_classification = "remote_failure"
            else:
                error_classification = "unknown_remote_failure"

        return OperationStatusResult(
            operation_id=op_id,
            status=status,
            operation_type=str(op_type) if op_type is not None else None,
            has_error=has_error,
            error_classification=error_classification,
            created_at=created_at,
            updated_at=updated_at,
            completed_at=completed_at,
            retry_count=int(retry_count) if retry_count is not None else None,
        )

    async def retry_operation(
        self,
        bank_id: str,
        operation_id: str,
    ) -> OperationRetryResult:
        """Instruct Hindsight to retry an asynchronous operation.

        Preserves original operation_id without generating a new UUID.

        Args:
            bank_id: Non-empty target bank identifier.
            operation_id: Non-empty operation UUID string.

        Returns:
            OperationRetryResult with retry status and message.

        Raises:
            HindsightClientError: If client is closed or Hindsight returns an error.
            ValueError: If bank_id or operation_id are empty or not strings.
        """
        if self._closed:
            raise HindsightClientError("Cannot perform operation on closed Hindsight client")

        if not isinstance(bank_id, str) or not bank_id.strip():
            raise ValueError("bank_id must be a non-empty string")
        if not isinstance(operation_id, str) or not operation_id.strip():
            raise ValueError("operation_id must be a non-empty string")

        clean_bank_id = bank_id.strip()
        clean_op_id = operation_id.strip()

        try:
            raw = await self._client.operations.retry_operation(
                bank_id=clean_bank_id,
                operation_id=clean_op_id,
            )
        except Exception as exc:
            raise self._map_exception(exc, "retry_operation") from None

        if isinstance(raw, dict):
            success = bool(raw.get("success", True))
            op_id = str(raw.get("operation_id") or clean_op_id)
            message = raw.get("message")
        else:
            success = bool(getattr(raw, "success", True))
            op_id = str(getattr(raw, "operation_id", None) or clean_op_id)
            message = getattr(raw, "message", None)

        return OperationRetryResult(
            success=success,
            operation_id=op_id,
            message=str(message) if message is not None else None,
        )

    async def recall_incident_memories(
        self,
        tag: str,
        query: str,
        bank_id: Optional[str] = None,
        query_timestamp: Optional[Union[str, datetime]] = None,
        max_tokens: Optional[int] = None,
        budget: Optional[str] = None,
        request_timeout: Optional[float] = None,
    ) -> HindsightRecallResult:
        """Execute a single authenticated, scoped asynchronous recall query against Hindsight.

        Adheres strictly to Task 9D.1.3 architecture:
        - Uses native async arecall() from pinned hindsight-client == 1.2.0.
        - Enforces exactly one validated pseudonymous HMAC identity tag.
        - Uses tags_match='all_strict' to exclude untagged/unrelated records.
        - Limits fact types to ['experience', 'observation'].
        - Bounds operation with an asynchronous timeout wrapper (default 3.0s).
        - Sanitizes and validates returned items, rejecting malformed or out-of-scope records.
        - Preserves native per-query ranking in immutable HindsightRecallItem DTOs.
        - Allows external asyncio.CancelledError to propagate untouched.

        Args:
            tag: Server-generated pseudonymous HMAC tag ('ip:vX:...' or 'user:vX:...').
            query: Sanitized server-generated behavioral search query.
            bank_id: Optional target memory bank; defaults to self._bank_id.
            query_timestamp: Optional authoritative incident timestamp.
            max_tokens: Optional token ceiling; defaults to HINDSIGHT_RECALL_MAX_TOKENS (1024).
            budget: Optional budget ('low', 'mid', 'high'); defaults to HINDSIGHT_RECALL_BUDGET ('mid').
            request_timeout: Optional per-operation timeout; defaults to 3.0s.

        Returns:
            Immutable HindsightRecallResult containing validated HindsightRecallItem records.

        Raises:
            HindsightClientError: If client is closed or recall operation fails.
            HindsightValidationError: If inputs (tag, query, etc.) violate constraints.
            HindsightTimeoutError: If the logical operation exceeds the per-operation deadline.
            HindsightProtocolError: If Hindsight returns a structurally corrupted response.
            asyncio.CancelledError: Propagated directly if cancelled externally.
        """
        if self._closed:
            raise HindsightClientError("Cannot call recall_incident_memories on closed Hindsight client")

        app_settings = get_settings()

        # 1. Feature Flag: Enforce that Hindsight incident-memory recall is enabled
        if not app_settings.HINDSIGHT_RECALL_ENABLED:
            raise HindsightConfigurationError(
                "Hindsight incident-memory recall is disabled (HINDSIGHT_RECALL_ENABLED is False)."
            )

        # 2. Validate inputs
        clean_tag = validate_recall_tag(tag)

        if not isinstance(query, str) or not query.strip():
            raise HindsightValidationError("Recall query string cannot be empty.")
        clean_query = query.strip()

        # Enforce authoritative environment bank isolation
        authoritative_bank_id = self._bank_id
        if bank_id is None:
            clean_bank_id = authoritative_bank_id
        elif isinstance(bank_id, str):
            clean_bank_id = bank_id.strip()
            if not clean_bank_id:
                raise HindsightValidationError("Explicit bank_id cannot be empty or whitespace-only.")
            if clean_bank_id != authoritative_bank_id:
                raise HindsightValidationError(
                    f"Supplied bank_id '{clean_bank_id}' does not match authoritative environment bank '{authoritative_bank_id}'."
                )
        else:
            raise HindsightValidationError("bank_id must be a string or None.")

        clean_timestamp: Optional[str] = None
        if query_timestamp is not None:
            if isinstance(query_timestamp, datetime):
                clean_timestamp = query_timestamp.isoformat()
            elif isinstance(query_timestamp, str) and query_timestamp.strip():
                clean_timestamp = query_timestamp.strip()

        # Enforce strict caller-supplied limits: max_tokens (bounded by hard non-overridable ceiling)
        ceiling_max_tokens = min(app_settings.HINDSIGHT_RECALL_MAX_TOKENS_CEILING, 4096)
        if max_tokens is not None:
            if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens <= 0:
                raise HindsightValidationError("max_tokens must be a positive integer.")
            if max_tokens > ceiling_max_tokens:
                raise HindsightValidationError(
                    f"max_tokens ({max_tokens}) exceeds maximum configured ceiling of {ceiling_max_tokens}."
                )
            eff_max_tokens = max_tokens
        else:
            eff_max_tokens = min(app_settings.HINDSIGHT_RECALL_MAX_TOKENS, ceiling_max_tokens)

        eff_budget = budget if budget is not None else app_settings.HINDSIGHT_RECALL_BUDGET
        if eff_budget not in ("low", "mid", "high"):
            raise HindsightValidationError(f"budget must be one of 'low', 'mid', 'high', got '{eff_budget}'")

        # Enforce strict caller-supplied limits: request_timeout
        configured_max_timeout = app_settings.HINDSIGHT_RECALL_REQUEST_TIMEOUT_SECONDS
        if request_timeout is not None:
            if (
                isinstance(request_timeout, bool)
                or not isinstance(request_timeout, (int, float))
                or not math.isfinite(request_timeout)
                or request_timeout <= 0
            ):
                raise HindsightValidationError("request_timeout must be a positive finite number.")
            if request_timeout > configured_max_timeout:
                raise HindsightValidationError(
                    f"request_timeout ({request_timeout}s) cannot exceed configured limit of {configured_max_timeout}s."
                )
            eff_timeout = float(request_timeout)
        else:
            eff_timeout = configured_max_timeout

        # 2. Execute bounded asynchronous recall via SDK
        try:
            async with asyncio.timeout(eff_timeout):
                raw_response = await self._client.arecall(
                    bank_id=clean_bank_id,
                    query=clean_query,
                    types=["experience", "observation"],
                    max_tokens=eff_max_tokens,
                    budget=eff_budget,
                    trace=False,
                    query_timestamp=clean_timestamp,
                    include_entities=False,
                    include_chunks=False,
                    include_source_facts=False,
                    tags=[clean_tag],
                    tags_match="all_strict",
                    tag_groups=None,
                    prefer_observations=True,
                    rerank=None,
                    min_scores=None,
                    temporal_window=None,
                )
        except asyncio.CancelledError:
            # External cancellation must propagate untouched
            raise
        except (asyncio.TimeoutError, TimeoutError):
            logger.warning("Hindsight recall operation timed out after %s seconds", eff_timeout)
            raise HindsightTimeoutError(
                f"Hindsight recall operation timed out after {eff_timeout}s"
            ) from None
        except Exception as exc:
            raise self._map_exception(exc, "recall_incident_memories") from None

        # 3. Validate response structure
        if raw_response is None:
            raise HindsightProtocolError("Hindsight recall returned None response")

        if isinstance(raw_response, dict):
            raw_results = raw_response.get("results")
        else:
            raw_results = getattr(raw_response, "results", None)

        if raw_results is None or not isinstance(raw_results, (list, tuple)):
            raise HindsightProtocolError(
                "Hindsight recall response missing valid 'results' collection"
            )

        # 4. Parse and validate individual items
        valid_items: list[HindsightRecallItem] = []
        for idx, raw_item in enumerate(raw_results):
            if isinstance(raw_item, dict):
                item_id = raw_item.get("id")
                item_text = raw_item.get("text")
                item_type = raw_item.get("type")
                item_context = raw_item.get("context")
                item_doc_id = raw_item.get("document_id")
                item_tags = raw_item.get("tags")
                raw_start = raw_item.get("occurred_start")
                raw_end = raw_item.get("occurred_end")
                raw_mentioned = raw_item.get("mentioned_at")
            else:
                item_id = getattr(raw_item, "id", None)
                item_text = getattr(raw_item, "text", None)
                item_type = getattr(raw_item, "type", None)
                item_context = getattr(raw_item, "context", None)
                item_doc_id = getattr(raw_item, "document_id", None)
                item_tags = getattr(raw_item, "tags", None)
                raw_start = getattr(raw_item, "occurred_start", None)
                raw_end = getattr(raw_item, "occurred_end", None)
                raw_mentioned = getattr(raw_item, "mentioned_at", None)

            # Validate memory ID and text
            if not item_id or not isinstance(item_id, str) or not item_id.strip():
                logger.warning("Rejected recall memory item at index %d: missing or empty id", idx)
                continue
            if not item_text or not isinstance(item_text, str) or not item_text.strip():
                logger.warning("Rejected recall memory item at index %d: missing or empty text", idx)
                continue

            # Validate native fact type
            clean_type: Optional[str] = None
            if item_type is not None:
                if not isinstance(item_type, str) or item_type not in PERMITTED_HINDSIGHT_FACT_TYPES:
                    logger.warning(
                        "Rejected recall memory item at index %d: invalid fact type '%s'",
                        idx,
                        item_type,
                    )
                    continue
                clean_type = item_type

            # Parse tags and enforce identity scope
            parsed_tags: tuple[str, ...] = ()
            if item_tags is not None:
                if isinstance(item_tags, (list, tuple)):
                    parsed_tags = tuple(str(t).strip() for t in item_tags if t and isinstance(t, str))
                else:
                    logger.warning("Rejected recall memory item at index %d: malformed tags field", idx)
                    continue

            # Scope verification: item must carry the requested identity tag
            if clean_tag not in parsed_tags:
                logger.warning(
                    "Rejected recall memory item at index %d: missing requested identity tag",
                    idx,
                )
                continue

            # Safe context and doc_id parsing
            clean_context = str(item_context) if item_context is not None and isinstance(item_context, str) else None
            clean_doc_id = str(item_doc_id) if item_doc_id is not None and isinstance(item_doc_id, str) else None

            # Scope verification passed: item carries the requested identity tag.
            # To protect privacy, neither requested nor remote HMAC pseudonyms are exposed in DTO.
            valid_items.append(
                HindsightRecallItem(
                    id=item_id.strip(),
                    text=item_text.strip(),
                    fact_type=clean_type,
                    context=clean_context,
                    document_id=clean_doc_id,
                    scope_verified=True,
                    occurred_start=_parse_datetime(raw_start),
                    occurred_end=_parse_datetime(raw_end),
                    mentioned_at=_parse_datetime(raw_mentioned),
                    rank=idx + 1,  # 1-based native ranking from Hindsight
                )
            )

        return HindsightRecallResult(
            bank_id=clean_bank_id,
            query=clean_query,
            items=tuple(valid_items),
            total_count=len(valid_items),
        )

    async def aclose(self) -> None:
        """Explicitly close the client and release underlying aiohttp resources.

        Safe to invoke multiple times.
        """
        if not self._closed:
            try:
                await self._client.aclose()
            except Exception as exc:
                logger.error("Error closing Hindsight client session: %s", exc)
            finally:
                self._closed = True

    async def __aenter__(self) -> "HindsightClientService":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()


def create_hindsight_client(
    settings: Optional[Settings] = None,
    client_override: Optional[Any] = None,
) -> HindsightClientService:
    """Factory function to instantiate application-scoped HindsightClientService.

    Args:
        settings: Optional Settings instance; uses cached settings if omitted.
        client_override: Optional pre-configured or mock Hindsight client for testing.

    Returns:
        HindsightClientService wrapping the Hindsight client.

    Raises:
        HindsightConfigurationError: If Hindsight is disabled or improperly configured.
    """
    app_settings = settings or get_settings()

    if not app_settings.HINDSIGHT_ENABLED:
        raise HindsightConfigurationError(
            "Cannot create Hindsight client when HINDSIGHT_ENABLED is False."
        )

    if not app_settings.HINDSIGHT_BASE_URL:
        raise HindsightConfigurationError(
            "HINDSIGHT_BASE_URL is required when HINDSIGHT_ENABLED is True."
        )

    if not app_settings.HINDSIGHT_API_KEY:
        raise HindsightConfigurationError(
            "HINDSIGHT_API_KEY is required when HINDSIGHT_ENABLED is True."
        )

    base_url = app_settings.HINDSIGHT_BASE_URL.strip()
    api_key = app_settings.HINDSIGHT_API_KEY.get_secret_value().strip()
    bank_id = app_settings.HINDSIGHT_BANK_ID or "sentinelagent-incident-memory-dev"

    if client_override is not None:
        client = client_override
    else:
        client = Hindsight(
            base_url=base_url,
            api_key=api_key,
            timeout=app_settings.HINDSIGHT_TIMEOUT_SECONDS,
            user_agent="SentinelAgent/1.0",
        )

    return HindsightClientService(
        client=client,
        bank_id=bank_id,
        base_url=base_url,
        is_required=app_settings.HINDSIGHT_REQUIRED,
    )

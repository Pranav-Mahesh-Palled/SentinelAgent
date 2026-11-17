"""Response Orchestration Pydantic Schemas and SAC-JSON-v1 Canonical Serialization.

Implements:
1. SAC-JSON-v1 deterministic canonical JSON serialization and SHA-256 fingerprinting.
2. Response Proposal, Approval, Rejection, and Cancellation request and response schemas.
3. Outbox command, execution, verification, and manual reconciliation schemas.
"""

from collections.abc import Mapping, Sequence
from datetime import datetime
import hashlib
import ipaddress
import json
import math
from typing import Any, Literal, Optional
import unicodedata
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator


# =============================================================================
# SAC-JSON-v1 Canonical Serialization, Parsing and Fingerprinting
# =============================================================================

INT64_MIN = -(2**63)
INT64_MAX = 2**63 - 1
UTF8_BOM = b"\xef\xbb\xbf"


def _sac_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Parse JSON object pairs enforcing no raw duplicate keys and no NFC collisions."""
    result: dict[str, Any] = {}
    seen_raw_keys: set[str] = set()
    seen_nfc_keys: set[str] = set()

    for raw_k, v in pairs:
        if not isinstance(raw_k, str):
            raise ValueError(f"SAC-JSON-v1 object keys must be strings, got {type(raw_k).__name__}")
        if raw_k in seen_raw_keys:
            raise ValueError(f"Duplicate raw JSON property detected: '{raw_k}'")
        seen_raw_keys.add(raw_k)

        nfc_k = unicodedata.normalize("NFC", raw_k)
        if nfc_k in seen_nfc_keys:
            raise ValueError(f"NFC key collision detected: '{raw_k}' normalizes to existing key '{nfc_k}'")
        seen_nfc_keys.add(nfc_k)

        result[nfc_k] = v

    return result


def parse_sac_json_v1(raw: bytes | str) -> Any:
    """Parse raw JSON text or bytes under strict SAC-JSON-v1 invariants.

    Enforces:
    - Rejection of UTF-8 Byte Order Mark (BOM).
    - Detection of duplicate raw keys and NFC key collisions before Pydantic parsing.
    - Rejection of floating-point numbers.
    - Rejection of JSON constants (NaN, Infinity, -Infinity).
    - Validation of signed 64-bit integer limits.
    """
    if isinstance(raw, bytes):
        if raw.startswith(UTF8_BOM):
            raise ValueError("UTF-8 Byte Order Mark (BOM) is strictly forbidden in SAC-JSON-v1")
        text_str = raw.decode("utf-8")
    elif isinstance(raw, str):
        if raw.startswith("\ufeff"):
            raise ValueError("Unicode Byte Order Mark (BOM) is strictly forbidden in SAC-JSON-v1")
        text_str = raw
    else:
        raise ValueError(f"Expected bytes or str for SAC-JSON-v1 parsing, got {type(raw).__name__}")

    def _reject_float(val_str: str) -> None:
        raise ValueError(f"Floating-point values are forbidden in SAC-JSON-v1: {val_str}")

    def _reject_constant(const_str: str) -> None:
        raise ValueError(f"JSON constants such as '{const_str}' are forbidden in SAC-JSON-v1")

    parsed = json.loads(
        text_str,
        object_pairs_hook=_sac_object_pairs_hook,
        parse_float=_reject_float,
        parse_constant=_reject_constant,
    )
    _validate_sac_node(parsed)
    return parsed


def _validate_sac_node(val: Any) -> None:
    """Recursively validate that node contains only allowed SAC-JSON-v1 types and ranges."""
    if isinstance(val, bool):
        # Must check bool before int because bool subclasses int in Python
        return
    if isinstance(val, int):
        if not (INT64_MIN <= val <= INT64_MAX):
            raise ValueError(f"Integer {val} exceeds signed 64-bit limits [{INT64_MIN}, {INT64_MAX}]")
        return
    if isinstance(val, float):
        raise ValueError(f"Floating-point values are forbidden in SAC-JSON-v1: {val}")
    if isinstance(val, str):
        return
    if val is None:
        return
    if isinstance(val, (list, tuple)):
        for item in val:
            _validate_sac_node(item)
        return
    if isinstance(val, (dict, Mapping)):
        seen_nfc_keys: set[str] = set()
        for k, v in val.items():
            if not isinstance(k, str):
                raise ValueError(f"SAC-JSON-v1 dictionary keys must be strings, got {type(k).__name__}")
            nfc_k = unicodedata.normalize("NFC", k)
            if nfc_k in seen_nfc_keys:
                raise ValueError(f"NFC key collision detected: '{k}' normalizes to existing key '{nfc_k}'")
            seen_nfc_keys.add(nfc_k)
            _validate_sac_node(v)
        return
    if isinstance(val, (uuid.UUID, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return
    raise ValueError(f"Unsupported data type for SAC-JSON-v1 serialization: {type(val).__name__}")


def _normalize_sac_value(val: Any) -> Any:
    """Normalize values (NFC Unicode, UUID, IP to str) and sort dict keys by UTF-8 byte values."""
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        return unicodedata.normalize("NFC", val)
    if val is None:
        return None
    if isinstance(val, (uuid.UUID, ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return str(val)
    if isinstance(val, (list, tuple)):
        return [_normalize_sac_value(item) for item in val]
    if isinstance(val, (dict, Mapping)):
        # Normalize and sort keys lexicographically by UTF-8 byte values
        normalized_items: list[tuple[str, bytes, Any]] = []
        seen_nfc_keys: set[str] = set()
        for k, v in val.items():
            if not isinstance(k, str):
                raise ValueError(f"SAC-JSON-v1 dictionary keys must be strings, got {type(k).__name__}")
            nfc_k = unicodedata.normalize("NFC", k)
            if nfc_k in seen_nfc_keys:
                raise ValueError(f"NFC key collision detected: '{k}' normalizes to existing key '{nfc_k}'")
            seen_nfc_keys.add(nfc_k)
            k_bytes = nfc_k.encode("utf-8")
            normalized_items.append((nfc_k, k_bytes, _normalize_sac_value(v)))

        # Sort strictly by UTF-8 byte values
        normalized_items.sort(key=lambda item: item[1])
        return {item[0]: item[2] for item in normalized_items}

    raise ValueError(f"Unsupported data type for SAC-JSON-v1: {type(val).__name__}")


def canonicalize_sac_json_v1(data: Any) -> bytes:
    """Serialize a Python data structure into deterministic SAC-JSON-v1 UTF-8 bytes.

    Specification:
    - Recursively rejects floats, NaN, Infinity, and out-of-range 64-bit signed integers.
    - Dict keys must be strings and are normalized to NFC.
    - Dict keys are sorted strictly by UTF-8 byte values.
    - No whitespace between tokens: separators=(',', ':').
    - Output is encoded strictly as UTF-8.
    """
    _validate_sac_node(data)
    normalized = _normalize_sac_value(data)
    json_str = json.dumps(
        normalized,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=False,  # Already sorted by UTF-8 bytes in _normalize_sac_value
    )
    return json_str.encode("utf-8")



def calculate_request_fingerprint(data: Any) -> str:
    """Calculate the 64-character lowercase hexadecimal SHA-256 digest of SAC-JSON-v1 bytes."""
    serialized = canonicalize_sac_json_v1(data)
    return hashlib.sha256(serialized).hexdigest().lower()


def hash_idempotency_key(idempotency_key: str) -> str:
    """Compute the 64-character lowercase SHA-256 hash of an idempotency key string."""
    if not idempotency_key or not idempotency_key.strip():
        raise ValueError("idempotency_key cannot be empty or whitespace")
    return hashlib.sha256(idempotency_key.strip().encode("utf-8")).hexdigest().lower()


# =============================================================================
# Proposal Schemas
# =============================================================================

class ProposalCreateRequest(BaseModel):
    """Client request schema for creating a response action proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    incident_id: uuid.UUID = Field(..., description="Target incident ID")
    investigation_id: uuid.UUID = Field(..., description="Completed investigation ID")
    justification: str = Field(..., min_length=5, max_length=4000, description="Security rationale for the proposal")
    evidence_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=50, description="Authoritative evidence item IDs")
    idempotency_key: str = Field(..., min_length=8, max_length=128, description="Client idempotency key")
    action_type: Literal["simulation.block_source_ip"] = Field(
        default="simulation.block_source_ip",
        description="Type of response action",
    )
    target_kind: Literal["source_ip"] = Field(
        default="source_ip",
        description="Target attribute kind",
    )
    duration_seconds: int = Field(
        default=3600,
        ge=60,
        le=604800,
        description="Block duration in seconds (1 min to 7 days)",
    )


class ProposalCreateBody(BaseModel):
    """Client-facing request body schema for POST /api/v1/incidents/{incident_id}/response/proposals."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: uuid.UUID = Field(..., description="Completed investigation ID")
    justification: str = Field(..., min_length=5, max_length=4000, description="Security rationale for the proposal")
    evidence_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=50, description="Authoritative evidence item IDs")
    action_type: Literal["simulation.block_source_ip"] = Field(
        default="simulation.block_source_ip",
        description="Type of response action",
    )
    target_kind: Literal["source_ip"] = Field(
        default="source_ip",
        description="Target attribute kind",
    )
    duration_seconds: int = Field(
        default=3600,
        ge=60,
        le=604800,
        description="Block duration in seconds (1 min to 7 days)",
    )
    incident_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Optional incident ID; if provided, must match path parameter",
    )
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Optional idempotency key in body; must match Idempotency-Key header if provided",
    )


class ProposalResponseData(BaseModel):
    """Immutable response payload returned when a proposal is created or replayed."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    incident_id: uuid.UUID
    investigation_id: uuid.UUID
    correlation_id: uuid.UUID
    action_type: str
    action_version: int
    target_kind: str
    target_value: str
    payload_json: dict[str, Any]
    payload_sha256: str
    justification: str
    proposed_by_operator_id: str
    approval_status: str
    execution_status: str
    verification_status: str
    approval_expires_at: datetime
    version: int
    created_at: datetime


class ResponseActionDetailResponse(BaseModel):
    """Detailed DTO for an individual response action safe for API exposure."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    incident_id: uuid.UUID
    investigation_id: uuid.UUID
    correlation_id: uuid.UUID
    action_type: str
    action_version: int
    target_kind: str
    target_value: str
    payload_json: dict[str, Any]
    payload_sha256: str
    justification: str
    proposed_by_operator_id: str
    approval_status: str
    approved_by_operator_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    rejection_at: Optional[datetime] = None
    execution_status: str
    execution_deadline_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None
    verification_status: str
    verified_at: Optional[datetime] = None
    approval_expires_at: Optional[datetime] = None
    version: int
    created_at: datetime
    updated_at: datetime


# =============================================================================
# Transition (Approval, Rejection, Cancellation) Schemas
# =============================================================================

class ApprovalRequest(BaseModel):
    """Request payload for approving a response action proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version for optimistic concurrency")
    idempotency_key: str = Field(..., min_length=8, max_length=128, description="Operator idempotency key")
    reason: str = Field(..., min_length=3, max_length=2000, description="Approval justification")
    execution_timeout_seconds: int = Field(
        default=300,
        ge=30,
        le=86400,
        description="Execution deadline window from approval timestamp in seconds",
    )


class RejectionRequest(BaseModel):
    """Request payload for rejecting a response action proposal."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    idempotency_key: str = Field(..., min_length=8, max_length=128, description="Operator idempotency key")
    reason: str = Field(..., min_length=3, max_length=2000, description="Rejection reason")


class CancellationRequest(BaseModel):
    """Request payload for cancelling an action (proposal or queued execution)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    idempotency_key: str = Field(..., min_length=8, max_length=128, description="Operator idempotency key")
    reason: str = Field(..., min_length=3, max_length=2000, description="Cancellation reason")


class TransitionResponseData(BaseModel):
    """Response payload returned when a lifecycle transition succeeds or is replayed."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    approval_status: str
    execution_status: str
    verification_status: str
    version: int
    action_version: int
    transition_event_type: str
    sequence_number: int
    execution_deadline_at: Optional[datetime] = None
    outbox_id: Optional[uuid.UUID] = None


# =============================================================================
# Outbox and Simulation Execution Schemas
# =============================================================================

class OutboxClaim(BaseModel):
    """Representation of a claimed outbox task lease."""

    model_config = ConfigDict(frozen=True)

    outbox_id: uuid.UUID
    response_action_id: uuid.UUID
    correlation_id: uuid.UUID
    command_type: str
    deduplication_key: str
    lease_token: int
    lease_owner: str
    lease_expires_at: datetime
    attempt_count: int


class SimulationExecutionResult(BaseModel):
    """Outcome of a simulation execution cycle."""

    model_config = ConfigDict(frozen=True)

    success: bool
    response_action_id: uuid.UUID
    simulated_entry_id: Optional[uuid.UUID] = None
    outbox_id: Optional[uuid.UUID] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None


# =============================================================================
# Verification and Reconciliation Schemas
# =============================================================================

class ProbeVerificationInput(BaseModel):
    """Input specification for an individual synthetic verification probe."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str = Field(..., min_length=1, max_length=64, description="Probe unique identifier within run")
    generation_evidence_id: uuid.UUID = Field(..., description="Evidence confirming probe transmission")
    capture_evidence_id: uuid.UUID = Field(..., description="Evidence confirming telemetry capture coverage")
    interception_evidence_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Evidence confirming interception/drop (required if intercepted=True, forbidden if False)",
    )
    intercepted: bool = Field(..., description="Whether the synthetic probe was intercepted")

    @field_validator("interception_evidence_id")
    @classmethod
    def validate_interception_bijection(cls, v: Optional[uuid.UUID], info: Any) -> Optional[uuid.UUID]:
        data = info.data
        intercepted = data.get("intercepted")
        if intercepted is True and v is None:
            raise ValueError("interception_evidence_id is required when intercepted is True")
        if intercepted is False and v is not None:
            raise ValueError("interception_evidence_id must be None when intercepted is False")
        return v


class VerificationRunRequest(BaseModel):
    """Command payload for evaluating verification probes against a response action."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    response_action_id: uuid.UUID
    synthetic_scenario_id: str = Field(..., min_length=1, max_length=128)
    observation_window_start: datetime
    observation_window_end: datetime
    probes: list[ProbeVerificationInput] = Field(..., min_length=1, max_length=100)

    @field_validator("observation_window_end")
    @classmethod
    def validate_observation_window(cls, v: datetime, info: Any) -> datetime:
        start = info.data.get("observation_window_start")
        if start and v <= start:
            raise ValueError("observation_window_end must be strictly greater than observation_window_start")
        return v


class VerificationRunResult(BaseModel):
    """Result of automated probe verification evaluation."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    outcome: Literal["verified", "failed", "inconclusive"]
    total_probes: int
    intercepted_probes: int
    outbox_id: Optional[uuid.UUID] = None


class ManualReconciliationRequest(BaseModel):
    """Operator request to reconcile an inconclusive verification outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    reconciled_action: Literal["confirm_verified", "confirm_failed"]
    justification: str = Field(..., min_length=10, max_length=4000)
    idempotency_key: Optional[str] = Field(default=None, min_length=8, max_length=128)
    expected_version: Optional[int] = Field(default=None, ge=1, description="Expected response_action.version")
    synthetic_scenario_id: str = Field(..., min_length=1, max_length=128)
    observation_window_start: datetime
    observation_window_end: datetime
    expected_probes: int = Field(..., gt=0)
    generated_probes: int = Field(..., gt=0)
    captured_probes: int = Field(..., gt=0)
    intercepted_probes: int = Field(..., ge=0)
    telemetry_coverage_verified: bool
    evidence_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=50)
    probes: list[ProbeVerificationInput] = Field(default_factory=list)

    @field_validator("observation_window_end")
    @classmethod
    def validate_observation_window(cls, v: datetime, info: Any) -> datetime:
        start = info.data.get("observation_window_start")
        if start and v <= start:
            raise ValueError("observation_window_end must be strictly greater than observation_window_start")
        return v


class ManualReconciliationResult(BaseModel):
    """Response returned upon successful manual verification reconciliation."""

    model_config = ConfigDict(frozen=True)

    reconciliation_id: uuid.UUID
    response_action_id: uuid.UUID
    resolution: str
    reconciled_by_operator_id: str
    verification_status: str
    sequence_number: int


class ExecutionReconciliationRequest(BaseModel):
    """Operator request to reconcile an indeterminate execution outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    resolution: Literal["confirm_succeeded", "confirm_failed"]
    justification: str = Field(..., min_length=10, max_length=4000)
    idempotency_key: Optional[str] = Field(default=None, min_length=8, max_length=128)
    expected_version: int = Field(..., ge=1, description="Expected response_action.version")
    evidence_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=50)


class ExecutionReconciliationResult(BaseModel):
    """Response returned upon successful manual execution reconciliation."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    execution_status: str
    verification_status: str
    reconciled_by_operator_id: str
    version: int
    sequence_number: int


# =============================================================================
# Dashboard Inspection Schemas
# =============================================================================

class OperatorMeResponse(BaseModel):
    """Operator principal representation for frontend identity synchronization."""

    model_config = ConfigDict(frozen=True)

    operator_id: str
    role: str


class IncidentListItem(BaseModel):
    """Incident summary DTO for Operator Dashboard Incident Overview."""

    model_config = ConfigDict(frozen=True)

    incident_id: uuid.UUID
    title: str
    incident_type: str
    source_ip: str
    severity: Optional[str] = None
    detection_method: str
    status: str
    investigation_status: str
    response_status: str
    verification_status: str
    created_at: datetime
    updated_at: datetime
    active_investigation_id: Optional[uuid.UUID] = None


class InvestigationEvidenceItemResponse(BaseModel):
    """Authoritative forensic evidence item for an investigation."""

    model_config = ConfigDict(frozen=True)

    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    evidence_type: str
    title: str
    description: Optional[str] = None
    collected_at: datetime


class ResponseActionSimulationDetails(BaseModel):
    """Execution and simulation inspection payload."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    execution_status: str
    executed_at: Optional[datetime] = None
    execution_deadline_at: Optional[datetime] = None
    simulated_entry: Optional[dict[str, Any]] = None
    outbox: Optional[dict[str, Any]] = None


class ResponseActionVerificationDetails(BaseModel):
    """Verification inspection payload."""

    model_config = ConfigDict(frozen=True)

    response_action_id: uuid.UUID
    verification_status: str
    verified_at: Optional[datetime] = None
    reconciliation_record: Optional[dict[str, Any]] = None
    probes: list[dict[str, Any]] = Field(default_factory=list)


class ResponseAuditEventResponse(BaseModel):
    """Response audit event record for timeline and audit history."""

    model_config = ConfigDict(frozen=True)

    response_audit_event_id: uuid.UUID
    response_action_id: uuid.UUID
    sequence_number: int
    event_type: str
    from_approval_status: Optional[str] = None
    to_approval_status: Optional[str] = None
    from_execution_status: Optional[str] = None
    to_execution_status: Optional[str] = None
    from_verification_status: Optional[str] = None
    to_verification_status: Optional[str] = None
    actor_type: str
    actor_operator_id: Optional[str] = None
    actor_role_snapshot: Optional[str] = None
    reason: str
    payload_sha256_snapshot: str
    created_at: datetime

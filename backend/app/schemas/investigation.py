"""Pydantic schemas and immutable DTOs for SentinelAgent investigations.

Adheres strictly to Task 7B Architecture Revision 5:
- Exact tool names:
    * get_incident_context
    * get_ssh_events
    * get_detection_results
    * get_prior_evidence
    * search_ssh_events_by_username
    * get_related_incidents_for_ip
- Standard canonical source references:
    * ssh_events/<uuid>
    * detection_results/<uuid>
    * incidents/<uuid>
    * evidence_items/<uuid>
    * mitre/<technique_id>
    * playbooks/<playbook_id>
- Deep immutability for DTOs via MappingProxyType and nested tuple freezing.
- Strict timezone-aware datetimes across all API and DTO timestamp fields.
- Exact tool limits:
    * get_ssh_events: default 100, bounds 1-500
    * search_ssh_events_by_username: default 50, bounds 1-200
    * get_related_incidents_for_ip: default 10, bounds 1-50
- Server-scoped tool arguments (extra='forbid', no arbitrary incident_id/source_ip).
- Explicit, bounded tool output schemas with truncated metadata.
"""

from datetime import datetime
import re
from types import MappingProxyType
from typing import Any, Mapping, Optional, Union
import uuid

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    field_validator,
)
from typing_extensions import Annotated

from app.schemas.mitre import MitreAttackMapping


# =============================================================================
# Helper: Deep Immutability & Serialization for DTO JSON/Nested Fields
# =============================================================================

def _freeze_nested(val: Any) -> Any:
    """Recursively freeze nested dictionaries to MappingProxyType and lists to tuples."""
    if isinstance(val, dict):
        return MappingProxyType({k: _freeze_nested(v) for k, v in val.items()})
    elif isinstance(val, (list, tuple)):
        return tuple(_freeze_nested(x) for x in val)
    return val


def _unfreeze_nested(val: Any) -> Any:
    """Recursively unpack MappingProxyType and tuples back to regular dicts and lists."""
    if isinstance(val, (MappingProxyType, dict, Mapping)):
        return {k: _unfreeze_nested(v) for k, v in val.items()}
    elif isinstance(val, (tuple, list)):
        return [_unfreeze_nested(x) for x in val]
    return val


# Type alias for deeply immutable JSON-like mappings that serialize back to standard dicts
FrozenJSONMapping = Annotated[
    Any,
    PlainSerializer(_unfreeze_nested, return_type=dict[str, Any], when_used="always"),
]


# =============================================================================
# Helper: Canonical Source Reference Validation
# =============================================================================

CANONICAL_PREFIXES = {
    "ssh_events",
    "detection_results",
    "incidents",
    "evidence_items",
    "mitre",
    "playbooks",
}

UUID_PREFIXES = {
    "ssh_events",
    "detection_results",
    "incidents",
    "evidence_items",
}

IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def validate_canonical_source_reference(ref: str) -> str:
    """Validate canonical source reference format per Task 7B Revision 5.

    Formats:
    - ssh_events/<uuid>
    - detection_results/<uuid>
    - incidents/<uuid>
    - evidence_items/<uuid>
    - mitre/<technique_id>
    - playbooks/<playbook_id>

    Strictly parses UUIDs to reject malformed or non-canonical identifiers.
    """
    trimmed = ref.strip()
    if "/" not in trimmed:
        raise ValueError(
            f"Invalid source reference format: '{ref}'. Expected format '<prefix>/<identifier>' "
            f"using one of: {sorted(CANONICAL_PREFIXES)}"
        )

    prefix, identifier = trimmed.split("/", 1)
    if prefix not in CANONICAL_PREFIXES:
        raise ValueError(
            f"Invalid source reference prefix: '{prefix}'. Permitted prefixes: {sorted(CANONICAL_PREFIXES)}"
        )

    if prefix in UUID_PREFIXES:
        try:
            parsed = uuid.UUID(identifier)
            if str(parsed) != identifier:
                raise ValueError(
                    f"UUID in source reference '{ref}' must be canonical lowercase."
                )
        except Exception as err:
            raise ValueError(
                f"Malformed UUID in source reference '{ref}': {err}"
            ) from err
    else:
        # mitre, playbooks
        if not identifier or not IDENTIFIER_REGEX.match(identifier):
            raise ValueError(
                f"Invalid identifier in reference '{ref}'. Must be non-empty alphanumeric, hyphens, periods, or underscores."
            )

    return trimmed


# =============================================================================
# Helper: Timezone Awareness Validator
# =============================================================================

def validate_timezone_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Validate that datetime instances are strictly timezone-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("Datetime must be timezone-aware (tzinfo cannot be None).")
    return dt


# =============================================================================
# A. API Request and Response Schemas
# =============================================================================

class InvestigationCreateRequest(BaseModel):
    """API request payload to initiate an incident investigation."""

    incident_id: uuid.UUID = Field(
        ...,
        description="UUID of the existing incident to investigate.",
    )

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "example": {
                "incident_id": "1a3d1fa7-bc89-40a9-a3b8-c1e9392456de"
            }
        },
    )


class InvestigationStatusResponse(BaseModel):
    """API response payload returning investigation state and progress."""

    investigation_id: uuid.UUID = Field(
        ...,
        description="Unique identifier of the investigation.",
    )
    incident_id: uuid.UUID = Field(
        ...,
        description="Associated incident identifier.",
    )
    status: str = Field(
        ...,
        description="Current lifecycle status of the investigation.",
    )
    investigation_summary: Optional[str] = Field(
        None,
        description="High-level narrative summary of findings.",
    )
    root_cause_assessment: Optional[str] = Field(
        None,
        description="Assessment of initial attack vector or root cause.",
    )
    investigation_report: Optional[dict[str, Any]] = Field(
        None,
        description="Structured investigation report if completed.",
    )
    started_at: Optional[datetime] = Field(
        None,
        description="Timestamp when investigation execution began.",
    )
    completed_at: Optional[datetime] = Field(
        None,
        description="Timestamp when investigation execution completed.",
    )
    created_at: datetime = Field(
        ...,
        description="Timestamp when the investigation record was created.",
    )
    updated_at: datetime = Field(
        ...,
        description="Timestamp when the investigation was last modified.",
    )

    model_config = ConfigDict(
        from_attributes=True,
        extra="ignore",
    )

    @field_validator("started_at", "completed_at", "created_at", "updated_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# =============================================================================
# B. Immutable DTOs (Deeply Frozen for Cross-Session Safety)
# =============================================================================

class InvestigationDTO(BaseModel):
    """Immutable data transfer object representing an Investigation record.

    Deeply freezes nested investigation_report dicts into MappingProxyType/tuples
    to prevent accidental modification across service layers or after database sessions close.
    """

    investigation_id: uuid.UUID
    incident_id: uuid.UUID
    status: str
    investigation_summary: Optional[str] = None
    investigation_report: Optional[FrozenJSONMapping] = None
    root_cause_assessment: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        frozen=True,
        from_attributes=True,
        arbitrary_types_allowed=True,
    )

    @field_validator("investigation_report", mode="after")
    @classmethod
    def freeze_report(cls, v: Any) -> Any:
        return _freeze_nested(v) if v is not None else None

    @field_validator("started_at", "completed_at", "created_at", "updated_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


class ToolRunDTO(BaseModel):
    """Immutable data transfer object representing an InvestigationToolRun record.

    Deeply freezes input_summary and output_summary to prevent accidental modification.
    """

    tool_run_id: uuid.UUID
    investigation_id: uuid.UUID
    tool_name: str
    execution_status: str
    input_summary: Optional[FrozenJSONMapping] = None
    output_summary: Optional[FrozenJSONMapping] = None
    error_code: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    created_at: datetime

    model_config = ConfigDict(
        frozen=True,
        from_attributes=True,
        arbitrary_types_allowed=True,
    )

    @field_validator("input_summary", "output_summary", mode="after")
    @classmethod
    def freeze_summaries(cls, v: Any) -> Any:
        return _freeze_nested(v) if v is not None else None

    @field_validator("started_at", "completed_at", "created_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


class EvidenceItemDTO(BaseModel):
    """Immutable data transfer object representing an EvidenceItem record.

    Deeply freezes evidence_data and validates source_reference format if present.
    """

    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    event_id: Optional[uuid.UUID] = None
    evidence_type: str
    title: str
    description: Optional[str] = None
    evidence_data: Optional[FrozenJSONMapping] = None
    source_reference: Optional[str] = None
    collected_at: datetime

    model_config = ConfigDict(
        frozen=True,
        from_attributes=True,
        arbitrary_types_allowed=True,
    )

    @field_validator("evidence_data", mode="after")
    @classmethod
    def freeze_evidence_data(cls, v: Any) -> Any:
        return _freeze_nested(v) if v is not None else None

    @field_validator("source_reference")
    @classmethod
    def validate_source_ref(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return validate_canonical_source_reference(v)
        return None

    @field_validator("collected_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# =============================================================================
# C. Structured Investigation Report
# =============================================================================

class ConfirmedFinding(BaseModel):
    """A factual conclusion directly corroborated by retrieved evidence.

    Must reference at least one valid canonical source reference.
    """

    finding_id: str = Field(
        ...,
        description="Identifier for this finding (e.g. 'FIND-001').",
    )
    title: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Concise description of the confirmed finding.",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Detailed factual description based solely on retrieved evidence.",
    )
    evidence_references: list[str] = Field(
        ...,
        min_length=1,
        description="Exact canonical references to evidence items supporting this finding.",
    )
    confidence: str = Field(
        default="high",
        description="Confidence level in this finding based on corroborating data.",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("evidence_references")
    @classmethod
    def validate_references(cls, refs: list[str]) -> list[str]:
        if not refs:
            raise ValueError("ConfirmedFinding must contain at least one evidence reference.")
        return [validate_canonical_source_reference(r) for r in refs]

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: str) -> str:
        v_lower = v.strip().lower()
        if v_lower not in {"low", "medium", "high"}:
            raise ValueError(f"Invalid confidence: '{v}'. Permitted: 'low', 'medium', 'high'.")
        return v_lower


class Observation(BaseModel):
    """An observable telemetry pattern visible in data without definitive attribution."""

    observation_id: str = Field(
        ...,
        description="Identifier for this observation (e.g. 'OBS-001').",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Observable telemetry pattern directly visible in retrieved data.",
    )
    evidence_references: list[str] = Field(
        default_factory=list,
        description="Optional canonical references to raw telemetry items demonstrating this pattern.",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("evidence_references")
    @classmethod
    def validate_references(cls, refs: list[str]) -> list[str]:
        return [validate_canonical_source_reference(r) for r in refs]


class Hypothesis(BaseModel):
    """A plausible explanation or attack vector that still requires verification."""

    hypothesis_id: str = Field(
        ...,
        description="Identifier for this hypothesis (e.g. 'HYP-001').",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Plausible explanation requiring further verification.",
    )
    likelihood: str = Field(
        default="medium",
        description="Estimated likelihood of this hypothesis ('low', 'medium', 'high').",
    )
    required_verification: str = Field(
        ...,
        min_length=1,
        description="Evidence or telemetry needed to verify or dispel this hypothesis.",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("likelihood")
    @classmethod
    def validate_likelihood(cls, v: str) -> str:
        v_lower = v.strip().lower()
        if v_lower not in {"low", "medium", "high"}:
            raise ValueError(f"Invalid likelihood: '{v}'. Permitted: 'low', 'medium', 'high'.")
        return v_lower


class EvidenceGap(BaseModel):
    """Forensic information needed to complete the investigation but currently unavailable."""

    gap_id: str = Field(
        ...,
        description="Identifier for this evidence gap (e.g. 'GAP-001').",
    )
    description: str = Field(
        ...,
        min_length=1,
        description="Description of missing or unavailable telemetry.",
    )
    potential_sources: list[str] = Field(
        default_factory=list,
        description="Potential logs or systems that could fill this gap.",
    )

    model_config = ConfigDict(extra="forbid")


class InvestigationSynthesisReport(BaseModel):
    """LLM-facing synthesis report generated by Gemini during Phase B.

    Excludes authoritative server-owned fields like mitre_attack_mappings,
    preventing the LLM from fabricating or hallucinating MITRE mappings.
    """

    summary: str = Field(
        ...,
        min_length=1,
        description="Executive summary of the investigation results.",
    )
    sufficient_evidence: bool = Field(
        ...,
        description="Whether sufficient evidence was gathered to reach a sound conclusion.",
    )
    confirmed_findings: list[ConfirmedFinding] = Field(
        default_factory=list,
        description="Findings backed by evidence. Empty if evidence is insufficient.",
    )
    observations: list[Observation] = Field(
        default_factory=list,
        description="Patterns observed in retrieved telemetry.",
    )
    hypotheses: list[Hypothesis] = Field(
        default_factory=list,
        description="Unverified theories or possible attack vectors.",
    )
    evidence_gaps: list[EvidenceGap] = Field(
        default_factory=list,
        description="Missing data needed to confirm or dispel hypotheses.",
    )
    root_cause_assessment: Optional[str] = Field(
        None,
        description="Assessed initial attack vector if sufficient evidence exists.",
    )

    model_config = ConfigDict(extra="forbid")


class InvestigationReport(InvestigationSynthesisReport):
    """Complete structured forensic investigation report stored in PostgreSQL.

    Inherits all core epistemic fields from InvestigationSynthesisReport,
    and extends it with authoritative server-validated mitre_attack_mappings.
    Maintains 100% backward compatibility with historical reports.
    """

    mitre_attack_mappings: list[MitreAttackMapping] = Field(
        default_factory=list,
        description="Authoritative, server-validated MITRE ATT&CK behavioral mappings.",
    )

    model_config = ConfigDict(extra="forbid")


# =============================================================================
# D. Tool Argument Schemas (Server-Scoped Context)
# =============================================================================
# Model-controlled arguments are strictly bounded. Context parameters
# (incident_id, investigation_id, source_ip) CANNOT be supplied by the model.

class EmptyArgs(BaseModel):
    """Empty argument schema for parameterless tools:
    - get_incident_context
    - get_detection_results
    - get_prior_evidence
    """

    model_config = ConfigDict(extra="forbid")


class GetSSHEventsArgs(BaseModel):
    """Model arguments for get_ssh_events (retrieves events linked to the incident).

    Approved bounds:
    - Default limit: 100
    - Minimum limit: 1
    - Maximum limit: 500
    """

    limit: int = Field(
        default=100,
        ge=1,
        le=500,
        description="Maximum number of SSH events to retrieve (1-500).",
    )

    model_config = ConfigDict(extra="forbid")


class SearchSSHEventsByUsernameArgs(BaseModel):
    """Model arguments for search_ssh_events_by_username.

    Approved bounds:
    - Default limit: 50
    - Minimum limit: 1
    - Maximum limit: 200
    """

    username: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Target username to filter events by.",
    )
    limit: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Maximum number of SSH events to retrieve (1-200).",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("username")
    @classmethod
    def validate_username_non_empty(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("username cannot be empty or whitespace.")
        return trimmed


class GetRelatedIncidentsForIPArgs(BaseModel):
    """Model arguments for get_related_incidents_for_ip.

    Approved bounds:
    - Default limit: 10
    - Minimum limit: 1
    - Maximum limit: 50
    """

    limit: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum number of related incidents to retrieve (1-50).",
    )

    model_config = ConfigDict(extra="forbid")


# =============================================================================
# E. Tool Output Schemas (Explicitly Defined for all 6 Tools)
# =============================================================================

# 1. Output for get_incident_context
class IncidentContextOutput(BaseModel):
    """Tool output schema for get_incident_context."""

    incident_id: uuid.UUID
    title: str
    incident_type: str
    source_ip: str
    severity: Optional[str] = None
    detection_method: str
    status: str
    investigation_status: str
    created_at: datetime
    updated_at: datetime
    associated_event_count: int
    associated_detection_count: int

    model_config = ConfigDict(extra="ignore")

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# Record for SSH events
class SSHEventRecord(BaseModel):
    """Individual SSH event record in tool outputs."""

    event_id: uuid.UUID
    event_timestamp: datetime
    source_ip: str
    username: str
    authentication_result: str
    event_type: str
    ingested_at: datetime

    model_config = ConfigDict(extra="ignore")

    @field_validator("event_timestamp", "ingested_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# 2. Output for get_ssh_events (max 500)
class SSHEventsOutput(BaseModel):
    """Tool output schema for get_ssh_events."""

    events: list[SSHEventRecord] = Field(
        ...,
        max_length=500,
        description="List of returned SSH event records (up to 500).",
    )
    count: int = Field(
        ...,
        description="Number of records returned in this response.",
    )
    truncated: bool = Field(
        ...,
        description="True if additional records existed beyond the requested limit.",
    )

    model_config = ConfigDict(extra="ignore")

    @field_validator("count")
    @classmethod
    def validate_count_matches(cls, v: int, info: Any) -> int:
        events = info.data.get("events")
        if events is not None and v != len(events):
            raise ValueError(f"count ({v}) must match length of returned events ({len(events)}).")
        return v


# 3. Output for search_ssh_events_by_username (max 200)
class UsernameSSHEventsOutput(BaseModel):
    """Tool output schema for search_ssh_events_by_username."""

    events: list[SSHEventRecord] = Field(
        ...,
        max_length=200,
        description="List of returned SSH event records matching username (up to 200).",
    )
    count: int = Field(
        ...,
        description="Number of records returned in this response.",
    )
    truncated: bool = Field(
        ...,
        description="True if additional matching records existed beyond the limit.",
    )

    model_config = ConfigDict(extra="ignore")

    @field_validator("count")
    @classmethod
    def validate_count_matches(cls, v: int, info: Any) -> int:
        events = info.data.get("events")
        if events is not None and v != len(events):
            raise ValueError(f"count ({v}) must match length of returned events ({len(events)}).")
        return v


# Record for Detection Results
class DetectionResultRecord(BaseModel):
    """Individual detection result record within tool outputs."""

    result_id: uuid.UUID
    incident_id: Optional[uuid.UUID] = None
    source_ip: str
    window_start: datetime
    window_end: datetime
    detector_type: str
    is_suspicious: bool
    triggered_rules: list[Any] = Field(default_factory=list)
    feature_snapshot: dict[str, Any] = Field(default_factory=dict)
    normality_score: Optional[float] = None
    calibrated_threshold: Optional[float] = None
    model_version: Optional[str] = None
    evaluated_at: datetime

    model_config = ConfigDict(extra="ignore")

    @field_validator("window_start", "window_end", "evaluated_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# 4. Output for get_detection_results (max 100)
class DetectionResultsOutput(BaseModel):
    """Tool output schema for get_detection_results."""

    results: list[DetectionResultRecord] = Field(
        ...,
        max_length=100,
        description="List of returned detection results (up to 100).",
    )
    count: int = Field(
        ...,
        description="Number of records returned in this response.",
    )
    truncated: bool = Field(
        ...,
        description="True if additional detection results existed beyond the limit.",
    )

    model_config = ConfigDict(extra="ignore")

    @field_validator("count")
    @classmethod
    def validate_count_matches(cls, v: int, info: Any) -> int:
        results = info.data.get("results")
        if results is not None and v != len(results):
            raise ValueError(f"count ({v}) must match length of returned results ({len(results)}).")
        return v


# Record for Evidence Items
class EvidenceItemRecord(BaseModel):
    """Individual evidence item record within tool outputs."""

    evidence_id: uuid.UUID
    investigation_id: uuid.UUID
    event_id: Optional[uuid.UUID] = None
    evidence_type: str
    title: str
    description: Optional[str] = None
    evidence_data: Optional[dict[str, Any]] = None
    source_reference: Optional[str] = None
    collected_at: datetime

    model_config = ConfigDict(extra="ignore")

    @field_validator("collected_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# 5. Output for get_prior_evidence (max 100)
class PriorEvidenceOutput(BaseModel):
    """Tool output schema for get_prior_evidence."""

    evidence_items: list[EvidenceItemRecord] = Field(
        ...,
        max_length=100,
        description="List of returned previously recorded evidence items (up to 100).",
    )
    count: int = Field(
        ...,
        description="Number of records returned in this response.",
    )
    truncated: bool = Field(
        ...,
        description="True if additional evidence items existed beyond the limit.",
    )

    model_config = ConfigDict(extra="ignore")

    @field_validator("count")
    @classmethod
    def validate_count_matches(cls, v: int, info: Any) -> int:
        items = info.data.get("evidence_items")
        if items is not None and v != len(items):
            raise ValueError(f"count ({v}) must match length of returned evidence_items ({len(items)}).")
        return v


# Record for Related Incidents
class RelatedIncidentRecord(BaseModel):
    """Related incident record within tool outputs."""

    incident_id: uuid.UUID
    title: str
    incident_type: str
    status: str
    investigation_status: str
    created_at: datetime

    model_config = ConfigDict(extra="ignore")

    @field_validator("created_at")
    @classmethod
    def validate_dt_tz(cls, v: Optional[datetime]) -> Optional[datetime]:
        return validate_timezone_aware(v)


# 6. Output for get_related_incidents_for_ip (max 50)
class RelatedIncidentsOutput(BaseModel):
    """Tool output schema for get_related_incidents_for_ip."""

    incidents: list[RelatedIncidentRecord] = Field(
        ...,
        max_length=50,
        description="List of returned related incidents from the same IP (up to 50).",
    )
    count: int = Field(
        ...,
        description="Number of records returned in this response.",
    )
    truncated: bool = Field(
        ...,
        description="True if additional related incidents existed beyond the limit.",
    )

    model_config = ConfigDict(extra="ignore")

    @field_validator("count")
    @classmethod
    def validate_count_matches(cls, v: int, info: Any) -> int:
        incidents = info.data.get("incidents")
        if incidents is not None and v != len(incidents):
            raise ValueError(f"count ({v}) must match length of returned incidents ({len(incidents)}).")
        return v

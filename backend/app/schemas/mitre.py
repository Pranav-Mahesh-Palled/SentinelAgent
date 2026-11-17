"""Pydantic v2 schemas for the normalized MITRE ATT&CK Enterprise catalogue and behavioral mapping.

Adheres strictly to Task 8B, Task 8C, and Task 8D Architecture:
- Immutable records using frozen=True, extra="forbid".
- Pydantic v2 validation and pattern enforcement for canonical identifiers.
- Official MITRE ATT&CK Enterprise v20.1 domain metadata.
- Authoritative tactic and technique representations.
- Dedicated candidate proposal representation for deterministic behavioral mapping engine (Task 8C).
- Authoritative final MitreAttackMapping representation linked to persisted EvidenceItems (Task 8D).
- Timezone-aware UTC datetime fields for observation windows.
"""

from datetime import datetime
from enum import Enum
from typing import Mapping, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


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
# A. Enumerations for Behavioral Mapping (Task 8C / 8D)
# =============================================================================

class MitreMappingStatus(str, Enum):
    """Forensic status of a candidate behavioral mapping."""

    CANDIDATE = "candidate"      # Telemetry matches deterministic rule criteria
    SUPPORTED = "supported"      # Fully corroborated by independent multi-source telemetry
    HYPOTHESIS = "hypothesis"    # Plausible interpretation with incomplete/unobservable telemetry
    REJECTED = "rejected"        # Ruled out by contradictory evidence or threshold failure


class MitreConfidenceLevel(str, Enum):
    """Qualitative confidence describing the degree of fit to an ATT&CK technique."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# =============================================================================
# B. Catalogue Metadata and Taxonomy Schemas (Task 8B)
# =============================================================================

class MitreCatalogueMetadata(BaseModel):
    """Metadata describing the compiled MITRE ATT&CK catalogue artifact."""

    domain: str = Field(
        ...,
        description="MITRE ATT&CK domain, e.g. 'enterprise-attack'.",
    )
    version: str = Field(
        ...,
        description="Version of the MITRE ATT&CK release, e.g. '20.1'.",
    )
    release_date: str = Field(
        ...,
        description="Official upstream release or modification date (ISO 8601 string).",
    )
    upstream_repository: str = Field(
        ...,
        description="Upstream source repository URL.",
    )
    upstream_commit: str = Field(
        ...,
        description="Immutable git commit SHA of the upstream source dataset.",
    )
    upstream_file: str = Field(
        ...,
        description="Original upstream filename.",
    )
    upstream_sha256: str = Field(
        ...,
        description="Hex-encoded SHA-256 digest of the raw upstream STIX 2.1 source bundle.",
    )
    technique_count: int = Field(
        ...,
        ge=0,
        description="Total number of techniques and sub-techniques in the catalogue.",
    )
    active_technique_count: int = Field(
        ...,
        ge=0,
        description="Number of non-deprecated, non-revoked active techniques.",
    )
    revoked_technique_count: int = Field(
        ...,
        ge=0,
        description="Number of revoked techniques in the catalogue.",
    )
    deprecated_technique_count: int = Field(
        ...,
        ge=0,
        description="Number of deprecated techniques in the catalogue.",
    )
    tactic_count: int = Field(
        ...,
        ge=0,
        description="Total number of enterprise tactics in the catalogue.",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


class MitreTacticRecord(BaseModel):
    """Authoritative metadata for a single MITRE ATT&CK enterprise tactic."""

    id: str = Field(
        ...,
        pattern=r"^TA\d{4}$",
        description="Canonical ATT&CK Tactic identifier, e.g. 'TA0006'.",
    )
    stix_id: str = Field(
        ...,
        description="Original STIX 2.1 object identifier, e.g. 'x-mitre-tactic--...'.",
    )
    name: str = Field(
        ...,
        min_length=1,
        description="Official tactic display name, e.g. 'Credential Access'.",
    )
    short_name: str = Field(
        ...,
        min_length=1,
        description="Machine-readable short name, e.g. 'credential-access'.",
    )
    description: str = Field(
        ...,
        description="Official tactic description.",
    )
    url: Optional[str] = Field(
        None,
        description="Official ATT&CK website reference URL.",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


class MitreTechniqueRecord(BaseModel):
    """Authoritative metadata for a single MITRE ATT&CK technique or sub-technique."""

    id: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Canonical ATT&CK Technique or Sub-technique identifier, e.g. 'T1110' or 'T1110.001'.",
    )
    stix_id: str = Field(
        ...,
        description="Original STIX 2.1 object identifier, e.g. 'attack-pattern--...'.",
    )
    name: str = Field(
        ...,
        min_length=1,
        description="Official technique name, e.g. 'Brute Force'.",
    )
    description: str = Field(
        ...,
        description="Official technique forensic description.",
    )
    tactics: list[str] = Field(
        default_factory=list,
        description="Associated canonical tactic IDs (e.g. ['TA0006']). Sorted alphabetically.",
    )
    platforms: list[str] = Field(
        default_factory=list,
        description="Applicable operating systems / platforms (e.g. ['Linux', 'Windows']). Sorted.",
    )
    is_subtechnique: bool = Field(
        ...,
        description="Whether this object is an ATT&CK sub-technique.",
    )
    subtechnique_of: Optional[str] = Field(
        None,
        pattern=r"^T\d{4}$",
        description="Parent technique ID if this is a sub-technique, else None.",
    )
    subtechniques: list[str] = Field(
        default_factory=list,
        description="List of child sub-technique IDs. Sorted alphabetically.",
    )
    revoked: bool = Field(
        default=False,
        description="Whether this technique has been revoked by MITRE.",
    )
    deprecated: bool = Field(
        default=False,
        description="Whether this technique has been deprecated by MITRE.",
    )
    replaced_by: Optional[str] = Field(
        None,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Canonical ID of the replacement technique if revoked, else None.",
    )
    url: Optional[str] = Field(
        None,
        description="Official ATT&CK website reference URL.",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


class MitreCatalogueDocument(BaseModel):
    """Root container model representing the entire compiled MITRE ATT&CK catalogue."""

    metadata: MitreCatalogueMetadata = Field(
        ...,
        description="Catalogue provenance and version metadata.",
    )
    tactics: dict[str, MitreTacticRecord] = Field(
        ...,
        description="Mapping from canonical tactic ID (TAxxxx) to tactic record.",
    )
    techniques: dict[str, MitreTechniqueRecord] = Field(
        ...,
        description="Mapping from canonical technique ID (Txxxx or Txxxx.yyy) to technique record.",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)


# =============================================================================
# C. Dedicated Candidate Proposal Schema (Task 8C)
# =============================================================================

class MitreCandidateProposal(BaseModel):
    """Candidate behavioral proposal emitted deterministically by MitreMappingEngine.

    Separate from the final authoritative MitreAttackMapping persisted in Task 8D.
    Uses immutable frozen configuration and strict validation.
    """

    mapping_id: uuid.UUID = Field(
        ...,
        description="Deterministic RFC 4122 UUID5 fingerprint computed from investigation and evidence context.",
    )
    rule_id: str = Field(
        ...,
        pattern=r"^MAP-SSH-\d{3}$",
        description="Behavioral mapping rule identifier, e.g. 'MAP-SSH-001'.",
    )
    technique_id: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Canonical ATT&CK Technique or Sub-technique identifier, e.g. 'T1110'.",
    )
    technique_name: str = Field(
        ...,
        min_length=1,
        description="Authoritative technique name looked up from MitreCatalogueService.",
    )
    tactic_ids: list[str] = Field(
        default_factory=list,
        description="Authoritative tactic identifiers looked up from MitreCatalogueService (sorted).",
    )
    tactic_names: list[str] = Field(
        default_factory=list,
        description="Authoritative tactic names looked up from MitreCatalogueService (sorted).",
    )
    mapping_status: MitreMappingStatus = Field(
        ...,
        description="Mapping status (candidate, hypothesis, supported, rejected).",
    )
    confidence: MitreConfidenceLevel = Field(
        ...,
        description="Qualitative confidence rating (low, medium, high).",
    )
    supporting_references: list[str] = Field(
        ...,
        min_length=1,
        description="Canonical source references (e.g. 'ssh_events/<uuid>') demonstrating the behavior (sorted).",
    )
    event_ids: list[uuid.UUID] = Field(
        ...,
        min_length=1,
        description="Underlying SSH event UUIDs demonstrating the pattern (sorted).",
    )
    window_start: datetime = Field(
        ...,
        description="Timezone-aware UTC timestamp of the earliest contributing event in the pattern.",
    )
    window_end: datetime = Field(
        ...,
        description="Timezone-aware UTC timestamp of the latest contributing event in the pattern.",
    )
    rationale: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Behavioral justification grounded strictly in observed telemetry.",
    )
    catalogue_version: str = Field(
        ...,
        description="Pinned version of the MITRE ATT&CK catalogue used for evaluation.",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("window_start", "window_end")
    @classmethod
    def validate_dt_tz(cls, v: datetime) -> datetime:
        return validate_timezone_aware(v)


# =============================================================================
# D. Authoritative Persisted Mapping Schema (Task 8D)
# =============================================================================

class MitreAttackMapping(BaseModel):
    """Authoritative MITRE ATT&CK mapping validated and persisted in SentinelAgent.

    Represents a verified, server-persisted behavioral mapping assessment linked
    to an actual EvidenceItem record and embedded into the final InvestigationReport.
    Immutable, strictly typed, and completely overwritten from authoritative catalogue metadata.
    """

    mapping_id: uuid.UUID = Field(
        ...,
        description="Deterministic RFC 4122 UUID5 fingerprint identical to the candidate proposal.",
    )
    evidence_item_id: Optional[uuid.UUID] = Field(
        None,
        description="UUID of the persisted EvidenceItem record representing this mapping assessment.",
    )
    rule_id: str = Field(
        ...,
        pattern=r"^MAP-SSH-\d{3}$",
        description="Behavioral mapping rule identifier, e.g. 'MAP-SSH-001'.",
    )
    technique_id: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Canonical ATT&CK Technique or Sub-technique identifier, e.g. 'T1110'.",
    )
    technique_name: str = Field(
        ...,
        min_length=1,
        description="Authoritative technique name looked up from MitreCatalogueService.",
    )
    tactic_ids: list[str] = Field(
        default_factory=list,
        description="Authoritative tactic identifiers looked up from MitreCatalogueService (sorted).",
    )
    tactic_names: list[str] = Field(
        default_factory=list,
        description="Authoritative tactic names looked up from MitreCatalogueService (sorted).",
    )
    mapping_status: MitreMappingStatus = Field(
        ...,
        description="Validated forensic mapping status (candidate, hypothesis).",
    )
    confidence: MitreConfidenceLevel = Field(
        ...,
        description="Validated qualitative confidence rating.",
    )
    supporting_references: list[str] = Field(
        ...,
        min_length=1,
        description="Canonical source references (e.g. 'ssh_events/<uuid>') demonstrating the behavior (sorted).",
    )
    event_ids: list[uuid.UUID] = Field(
        ...,
        min_length=1,
        description="Underlying SSH event UUIDs demonstrating the pattern (sorted).",
    )
    window_start: datetime = Field(
        ...,
        description="Timezone-aware UTC timestamp of the earliest contributing event in the pattern.",
    )
    window_end: datetime = Field(
        ...,
        description="Timezone-aware UTC timestamp of the latest contributing event in the pattern.",
    )
    rationale: str = Field(
        ...,
        min_length=10,
        max_length=2000,
        description="Behavioral justification grounded strictly in observed telemetry.",
    )
    catalogue_version: str = Field(
        ...,
        description="Pinned version of the MITRE ATT&CK catalogue used for evaluation.",
    )

    model_config = ConfigDict(extra="forbid", frozen=True)

    @field_validator("window_start", "window_end")
    @classmethod
    def validate_dt_tz(cls, v: datetime) -> datetime:
        return validate_timezone_aware(v)

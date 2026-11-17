"""Typed Memory Context Schemas for Historical Incident Recall (Task 9D.4).

Defines bounded, immutable, strictly typed Pydantic v2 data models for historical
incident intelligence retrieved from Hindsight.

Forensic & Epistemic Invariants:
1. Context Is Not Evidence:
   - All recalled memory items and context containers carry the mandatory classification
     trust_classification='HISTORICAL_CONTEXT_ONLY'.
   - Recalled items cannot enter AuthorizedProvenanceSet, cannot satisfy MitreMappingValidator,
     cannot be converted implicitly into EvidenceItem, and cannot establish attribution.
2. Cryptographic Tag Verification:
   - scope_verified is a mandatory boolean field that MUST be strictly True. Items failing
     cryptographic scope verification cannot be instantiated in this schema.
3. Strict Size Bounds:
   - Individual memory facts: <= 1,000 characters.
   - Aggregate memory text across items: <= 2,000 characters.
   - Item count: <= 10 items.
4. Schema Isolation:
   - extra='forbid' prevents unauthorized fields (such as raw HMAC pseudonyms, credentials,
     or arbitrary prompts) from entering the memory context.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


MAX_ITEMS_PER_CONTEXT: int = 10
MAX_SINGLE_MEMORY_TEXT_CHARS: int = 1000
MAX_AGGREGATE_MEMORY_TEXT_CHARS: int = 2000

FactType = Literal["world", "experience", "observation"]
RecallStatus = Literal["success", "empty", "partial", "skipped", "unavailable"]
TrustClassification = Literal["HISTORICAL_CONTEXT_ONLY"]


class RecalledMemoryItem(BaseModel):
    """Immutable representation of a single recalled historical memory unit.

    Adheres strictly to Hindsight 1.2.0 fact typing while enforcing application-level
    length safety, cryptographic scope verification, and forensic containment.
    """

    memory_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Validated Hindsight memory identifier.",
    )
    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_SINGLE_MEMORY_TEXT_CHARS,
        description="Structurally validated historical memory text (<= 1,000 chars).",
    )
    fact_type: Optional[FactType] = Field(
        default=None,
        description="Native Hindsight fact category: 'world', 'experience', or 'observation'.",
    )
    context: Optional[str] = Field(
        default=None,
        max_length=1000,
        description="Optional validated context metadata.",
    )
    document_id: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Optional source document citation.",
    )
    identity_category: Optional[Literal["source_ip", "username"]] = Field(
        default=None,
        description="Category of the identity tag used for recall.",
    )
    key_version: Optional[str] = Field(
        default=None,
        max_length=32,
        description="HMAC key version used for tag match.",
    )
    within_query_rank: int = Field(
        default=1,
        ge=1,
        le=10,
        description="Positive 1-based original within-query ranking.",
    )
    occurred_start: Optional[datetime] = Field(
        default=None,
        description="Optional timestamp marking the beginning of the described event.",
    )
    occurred_end: Optional[datetime] = Field(
        default=None,
        description="Optional timestamp marking the conclusion of the described event.",
    )
    mentioned_at: Optional[datetime] = Field(
        default=None,
        description="Optional timestamp when the memory was recorded or mentioned.",
    )
    retrieved_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when the memory was recalled from Hindsight.",
    )
    scope_verified: Literal[True] = Field(
        ...,
        description="Mandatory certification that item was cryptographically verified against requested scope.",
    )
    trust_classification: TrustClassification = Field(
        default="HISTORICAL_CONTEXT_ONLY",
        description="Mandatory forensic trust classification. Strictly HISTORICAL_CONTEXT_ONLY.",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("memory_id must not be empty or whitespace-only.")
        return clean

    @field_validator("text")
    @classmethod
    def validate_text(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("text must not be empty or whitespace-only.")
        if len(clean) > MAX_SINGLE_MEMORY_TEXT_CHARS:
            raise ValueError(
                f"Memory text exceeds maximum permitted length of {MAX_SINGLE_MEMORY_TEXT_CHARS} characters "
                f"(actual: {len(clean)})."
            )
        return clean

    @field_validator("scope_verified")
    @classmethod
    def validate_scope_verified(cls, v: bool) -> bool:
        if v is not True:
            raise ValueError("scope_verified must be strictly True. Unverified items are rejected.")
        return True

    @field_validator("trust_classification")
    @classmethod
    def validate_trust_classification(cls, v: str) -> str:
        if v != "HISTORICAL_CONTEXT_ONLY":
            raise ValueError("trust_classification must be strictly 'HISTORICAL_CONTEXT_ONLY'.")
        return v


class IncidentMemoryContext(BaseModel):
    """Structured container for recalled incident memories presented to the investigation agent."""

    status: RecallStatus = Field(
        ...,
        description="Outcome of the recall operation (matches IncidentMemoryRecallResult.status).",
    )
    items: tuple[RecalledMemoryItem, ...] = Field(
        default=(),
        description="Ranked, deduplicated, verified historical memories (maximum 10).",
    )
    total_items: int = Field(
        default=0,
        ge=0,
        description="Count of accepted memory items.",
    )
    items_rejected_oversized: int = Field(
        default=0,
        ge=0,
        description="Count of candidate items rejected for exceeding MAX_SINGLE_MEMORY_CHARS.",
    )
    attempted_queries: int = Field(
        default=0,
        ge=0,
        description="Count of queries dispatched to Hindsight.",
    )
    successful_queries: int = Field(
        default=0,
        ge=0,
        description="Count of queries that returned successful recall responses.",
    )
    failed_queries: int = Field(
        default=0,
        ge=0,
        description="Count of queries that failed or timed out.",
    )
    diagnostic_classifications: tuple[str, ...] = Field(
        default=(),
        description="Sanitized diagnostic classifications or error codes.",
    )
    skipped_reason: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Sanitized reason if recall operation was skipped.",
    )
    retrieved_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp when recall was executed.",
    )
    trust_classification: TrustClassification = Field(
        default="HISTORICAL_CONTEXT_ONLY",
        description="Mandatory forensic classification for the entire context container.",
    )

    model_config = ConfigDict(frozen=True, extra="forbid")

    @model_validator(mode="after")
    def validate_bounds_and_invariants(self) -> "IncidentMemoryContext":
        if len(self.items) > MAX_ITEMS_PER_CONTEXT:
            raise ValueError(
                f"IncidentMemoryContext cannot contain more than {MAX_ITEMS_PER_CONTEXT} items "
                f"(actual: {len(self.items)})."
            )

        aggregate_text_len = sum(len(item.text) for item in self.items)
        if aggregate_text_len > MAX_AGGREGATE_MEMORY_TEXT_CHARS:
            raise ValueError(
                f"Aggregate memory text length ({aggregate_text_len}) exceeds maximum ceiling of "
                f"{MAX_AGGREGATE_MEMORY_TEXT_CHARS} characters."
            )

        return self


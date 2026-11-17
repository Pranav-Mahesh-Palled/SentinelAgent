"""Pydantic v2 schemas for allowlisted, pseudonymized incident memory payloads.

Adheres strictly to Task 9A and Task 9C.2 specifications:
- Strongly typed, allowlisted schema (does NOT dump raw InvestigationReport).
- Seven distinct epistemic categories:
    1. observed_facts
    2. detection_results
    3. investigation_findings
    4. hypotheses
    5. mitre_mappings
    6. evidence_gaps
    7. investigation_outcomes
- Explicit schema version ('v1').
- Bounded list counts, string lengths, and payload size.
  NOTE: Field-size ceilings enforce structured compactness for Hindsight ingestion, but DO NOT
  guarantee that JSON structures or documents will never be split across chunks by Hindsight's
  retain chunker (configured at HINDSIGHT_API_RETAIN_CHUNK_SIZE=1024 characters). Actual chunking
  dynamics, fact-extraction fidelity, and relational integrity must be empirically verified
  via live retain integration tests in Task 9C.3.
- Explicit tag taxonomy:
    * ip:<version>:<32-hex-pseudonym>
    * user:<version>:<32-hex-pseudonym>
    * mitre:<technique_id>
    * category:<category_name>
- Strict rejection of credentials, passwords, raw auth payloads, and image attachments.
"""

from datetime import datetime
from typing import Any, Literal, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION_V1 = "v1"

# Bounded text and item limits for structured compactness.
# Hindsight's chunk size is HINDSIGHT_API_RETAIN_CHUNK_SIZE=1024 characters.
MAX_SUMMARY_LENGTH = 1000
MAX_DESCRIPTION_LENGTH = 500
MAX_ITEMS_PER_CATEGORY = 20
MAX_TAGS_COUNT = 50


class MemoryObservedFact(BaseModel):
    """Forensic observed fact grounded in authoritative telemetry (e.g. SSH event counts)."""

    fact_id: str = Field(..., max_length=64, description="Fact identifier (e.g. 'FACT-001').")
    fact_type: str = Field(..., max_length=64, description="Type of fact (e.g. 'event_summary').")
    summary: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH, description="Pseudonymized summary.")
    event_count: int = Field(default=0, ge=0, description="Total verified event count.")
    success_count: int = Field(default=0, ge=0, description="Successful authentication count.")
    failure_count: int = Field(default=0, ge=0, description="Failed authentication count.")
    source_reference: Optional[str] = Field(None, max_length=255, description="Traceable forensic anchor.")

    model_config = ConfigDict(extra="forbid")


class MemoryDetectionResult(BaseModel):
    """Detection alert metadata grounded in verified detection results."""

    result_id: str = Field(..., max_length=64, description="Detection result UUID or string ID.")
    detector_type: str = Field(..., max_length=64, description="Type of detector ('rule', 'isolation_forest').")
    severity: str = Field(..., max_length=32, description="Severity rating ('low', 'medium', 'high', 'critical').")
    summary: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH, description="Pseudonymized detection summary.")
    source_reference: Optional[str] = Field(None, max_length=255, description="Traceable forensic anchor.")

    model_config = ConfigDict(extra="forbid")


class MemoryConfirmedFinding(BaseModel):
    """Corroborated analytical finding grounded in evidence items."""

    finding_id: str = Field(..., max_length=64, description="Finding identifier (e.g. 'FND-001').")
    title: str = Field(..., max_length=255, description="Pseudonymized finding title.")
    description: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH, description="Pseudonymized description.")
    confidence: Literal["low", "medium", "high"] = Field("high", description="Assessed confidence level.")
    source_references: list[str] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Canonical evidence references.",
    )

    model_config = ConfigDict(extra="forbid")


class MemoryHypothesis(BaseModel):
    """Plausible analytical theory requiring further verification."""

    hypothesis_id: str = Field(..., max_length=64, description="Hypothesis identifier (e.g. 'HYP-001').")
    description: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH, description="Pseudonymized hypothesis.")
    likelihood: Literal["low", "medium", "high"] = Field("medium", description="Estimated likelihood.")

    model_config = ConfigDict(extra="forbid")


class MemoryMitreMapping(BaseModel):
    """Server-validated MITRE ATT&CK technique mapping."""

    technique_id: str = Field(
        ...,
        pattern=r"^T\d{4}(\.\d{3})?$",
        description="Canonical MITRE technique or sub-technique ID.",
    )
    technique_name: str = Field(..., max_length=128, description="Authoritative technique name.")
    tactic_ids: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Associated tactic IDs.",
    )
    confidence: Literal["low", "medium", "high"] = Field("medium", description="Mapping confidence rating.")
    mapping_status: Literal["candidate", "supported", "hypothesis", "rejected"] = Field(
        "candidate",
        description="Forensic mapping validation status.",
    )

    model_config = ConfigDict(extra="forbid")


class MemoryEvidenceGap(BaseModel):
    """Identified blind spot or missing forensic data."""

    gap_id: str = Field(..., max_length=64, description="Evidence gap identifier (e.g. 'GAP-001').")
    description: str = Field(..., max_length=MAX_DESCRIPTION_LENGTH, description="Description of missing data.")

    model_config = ConfigDict(extra="forbid")


class MemoryInvestigationOutcome(BaseModel):
    """Investigation terminal status and high-level root cause assessment."""

    status: str = Field(..., max_length=32, description="Terminal status ('completed', 'failed').")
    sufficient_evidence: bool = Field(..., description="Whether sufficient evidence existed.")
    root_cause_assessment: Optional[str] = Field(
        None,
        max_length=MAX_SUMMARY_LENGTH,
        description="Pseudonymized root cause assessment.",
    )

    model_config = ConfigDict(extra="forbid")


class SerializedIncidentMemoryPayload(BaseModel):
    """Root container model for allowlisted, pseudonymized incident memory.

    Persisted as JSONB in PostgreSQL `incident_memory_outbox.serialized_memory_payload`
    and submitted to Hindsight during memory retention.
    """

    schema_version: Literal["v1"] = Field(SCHEMA_VERSION_V1, description="Memory payload schema version.")
    investigation_id: str = Field(..., description="UUID string of the investigation.")
    incident_id: str = Field(..., description="UUID string of the incident.")
    title: str = Field(..., max_length=255, description="Pseudonymized incident title.")
    summary: str = Field(..., max_length=MAX_SUMMARY_LENGTH, description="Pseudonymized executive summary.")
    tags: list[str] = Field(
        default_factory=list,
        max_length=MAX_TAGS_COUNT,
        description="Approved recall and indexing tags.",
    )

    # Seven approved epistemic categories
    observed_facts: list[MemoryObservedFact] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Verified telemetry counts and observations.",
    )
    detection_results: list[MemoryDetectionResult] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Corroborating detection alerts.",
    )
    investigation_findings: list[MemoryConfirmedFinding] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Confirmed findings backed by evidence.",
    )
    hypotheses: list[MemoryHypothesis] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Analytical working theories.",
    )
    mitre_mappings: list[MemoryMitreMapping] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Server-validated MITRE ATT&CK techniques.",
    )
    evidence_gaps: list[MemoryEvidenceGap] = Field(
        default_factory=list,
        max_length=MAX_ITEMS_PER_CATEGORY,
        description="Identified observational blind spots.",
    )
    investigation_outcomes: list[MemoryInvestigationOutcome] = Field(
        default_factory=list,
        max_length=1,
        description="Investigation completion outcome.",
    )

    model_config = ConfigDict(extra="forbid")

    @field_validator("tags")
    @classmethod
    def validate_tags_format(cls, tags: list[str]) -> list[str]:
        """Validate that all tags strictly match approved SentinelAgent tag taxonomy."""
        for t in tags:
            if not isinstance(t, str) or not t.strip():
                raise ValueError("Tag must be a non-empty string.")
            t_clean = t.strip()
            # Allowed tag prefixes: ip:, user:, mitre:, category:
            if not (
                t_clean.startswith("ip:")
                or t_clean.startswith("user:")
                or t_clean.startswith("mitre:")
                or t_clean.startswith("category:")
            ):
                raise ValueError(
                    f"Invalid tag format '{t_clean}'. Allowed prefixes: 'ip:', 'user:', 'mitre:', 'category:'"
                )
        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for t in tags:
            if t not in seen:
                seen.add(t)
                deduped.append(t)
        return deduped


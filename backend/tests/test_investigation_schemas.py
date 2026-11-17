"""Comprehensive unit tests for Investigation Schemas and DTOs (Task 7B.2 Refined).

Verifies:
- Exact approved tool names:
    * get_incident_context
    * get_ssh_events
    * get_detection_results
    * get_prior_evidence
    * search_ssh_events_by_username
    * get_related_incidents_for_ip
- Standard canonical source reference formats:
    * ssh_events/<uuid>
    * detection_results/<uuid>
    * incidents/<uuid>
    * evidence_items/<uuid>
    * mitre/<technique_id>
    * playbooks/<playbook_id>
    * Strict rejection of non-canonical/malformed UUIDs and old colon format.
- Deep DTO immutability via MappingProxyType and nested tuple freezing.
- Strict timezone-aware datetimes across API and DTO timestamp fields (rejection of naive datetimes).
- Tool argument bounds:
    * get_ssh_events: default 100, bounds 1-500.
    * search_ssh_events_by_username: default 50, bounds 1-200.
    * get_related_incidents_for_ip: default 10, bounds 1-50.
    * Rejection of arbitrary incident_id/source_ip from model arguments.
- Tool output contracts:
    * All 6 tools have explicit output models.
    * search_ssh_events_by_username has explicit UsernameSSHEventsOutput.
    * Bounded collection maximum lengths.
    * count matches returned records.
- Structured InvestigationReport rules:
    * ConfirmedFinding requires at least 1 canonical evidence reference.
    * Insufficient evidence report without hallucinations.
- google-genai 3.0.0 SDK compatibility:
    * Offline transformation of InvestigationReport to Schema.
    * GenerateContentConfig response_schema integration.
"""

from datetime import datetime, timedelta, timezone
from types import MappingProxyType
import uuid
import pytest
from pydantic import ValidationError

from google.genai import _transformers, types

from app.schemas.mitre import (
    MitreAttackMapping,
    MitreConfidenceLevel,
    MitreMappingStatus,
)

from app.schemas.investigation import (
    ConfirmedFinding,
    DetectionResultRecord,
    DetectionResultsOutput,
    EmptyArgs,
    EvidenceGap,
    EvidenceItemDTO,
    EvidenceItemRecord,
    GetRelatedIncidentsForIPArgs,
    GetSSHEventsArgs,
    Hypothesis,
    IncidentContextOutput,
    InvestigationCreateRequest,
    InvestigationDTO,
    InvestigationReport,
    InvestigationStatusResponse,
    InvestigationSynthesisReport,
    Observation,
    PriorEvidenceOutput,
    RelatedIncidentRecord,
    RelatedIncidentsOutput,
    SSHEventRecord,
    SSHEventsOutput,
    SearchSSHEventsByUsernameArgs,
    ToolRunDTO,
    UsernameSSHEventsOutput,
    validate_canonical_source_reference,
)


# =============================================================================
# 1. API Request and Response Schemas
# =============================================================================

def test_investigation_create_request_valid():
    """Verify InvestigationCreateRequest accepts valid UUID."""
    inc_id = uuid.uuid4()
    req = InvestigationCreateRequest(incident_id=inc_id)
    assert req.incident_id == inc_id


def test_investigation_create_request_invalid_uuid():
    """Verify InvestigationCreateRequest rejects malformed UUID."""
    with pytest.raises(ValidationError):
        InvestigationCreateRequest(incident_id="not-a-valid-uuid")


def test_investigation_create_request_rejects_unknown_fields():
    """Verify InvestigationCreateRequest rejects extra fields (extra='forbid')."""
    with pytest.raises(ValidationError):
        InvestigationCreateRequest(
            incident_id=uuid.uuid4(),
            extra_field="malicious_payload",
        )


def test_investigation_status_response_valid_tz():
    """Verify InvestigationStatusResponse accepts timezone-aware timestamps."""
    inv_id = uuid.uuid4()
    inc_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    resp = InvestigationStatusResponse(
        investigation_id=inv_id,
        incident_id=inc_id,
        status="pending",
        investigation_summary=None,
        root_cause_assessment=None,
        investigation_report=None,
        started_at=None,
        completed_at=None,
        created_at=now_utc,
        updated_at=now_utc,
    )
    assert resp.investigation_id == inv_id
    assert resp.status == "pending"
    assert resp.created_at == now_utc


def test_investigation_status_response_rejects_naive_datetime():
    """Verify InvestigationStatusResponse rejects naive datetime."""
    naive_now = datetime.now()
    with pytest.raises(ValidationError, match="timezone-aware"):
        InvestigationStatusResponse(
            investigation_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            status="pending",
            created_at=naive_now,
            updated_at=naive_now,
        )


# =============================================================================
# 2. Immutable DTOs (Deep Immutability & Timezone Awareness)
# =============================================================================

def test_investigation_dto_deep_immutability():
    """Verify InvestigationDTO is frozen and deeply freezes nested report data."""
    inv_id = uuid.uuid4()
    inc_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    nested_report = {
        "summary": "Suspicious login burst",
        "findings": [{"id": "F1", "targets": ["admin", "root"]}],
        "metadata": {"source": "detector"},
    }

    dto = InvestigationDTO(
        investigation_id=inv_id,
        incident_id=inc_id,
        status="in_progress",
        investigation_summary="Summary",
        investigation_report=nested_report,
        created_at=now_utc,
        updated_at=now_utc,
    )

    # 1. Top-level attribute assignment blocked
    with pytest.raises(ValidationError):
        dto.status = "completed"

    # 2. Nested dictionary modification blocked (MappingProxyType)
    assert isinstance(dto.investigation_report, (MappingProxyType, dict))
    with pytest.raises(TypeError):
        dto.investigation_report["summary"] = "Mutated summary"

    # 3. Deeply nested sub-dictionary modification blocked
    with pytest.raises(TypeError):
        dto.investigation_report["metadata"]["source"] = "attacker"

    # 4. Deeply nested list modification blocked (converted to tuple)
    findings_list = dto.investigation_report["findings"]
    assert isinstance(findings_list, tuple)
    with pytest.raises(AttributeError):
        findings_list.append({"id": "F2"})

    # 5. Serialization back to JSON dict preserves standard types
    dumped = dto.model_dump()
    assert dumped["investigation_report"]["summary"] == "Suspicious login burst"
    assert isinstance(dumped["investigation_report"], dict)
    assert isinstance(dumped["investigation_report"]["findings"], list)


def test_tool_run_dto_deep_immutability():
    """Verify ToolRunDTO deeply freezes input_summary and output_summary."""
    now_utc = datetime.now(timezone.utc)
    dto = ToolRunDTO(
        tool_run_id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        tool_name="get_incident_context",
        execution_status="succeeded",
        input_summary={"limit": 100, "tags": ["auth", "burst"]},
        output_summary={"count": 50, "truncated": False},
        created_at=now_utc,
    )

    # Frozen model prevents attribute mutation
    with pytest.raises(ValidationError):
        dto.execution_status = "failed"

    # Input summary is frozen MappingProxyType
    with pytest.raises(TypeError):
        dto.input_summary["limit"] = 200

    # Nested tags tuple cannot be mutated
    with pytest.raises(AttributeError):
        dto.input_summary["tags"].append("extra")


def test_evidence_item_dto_deep_immutability_and_source_ref():
    """Verify EvidenceItemDTO deeply freezes evidence_data and validates source_reference."""
    ev_uuid = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    dto = EvidenceItemDTO(
        evidence_id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        evidence_type="ssh_event",
        title="Brute Force Event",
        evidence_data={"raw_payload": {"user": "admin"}},
        source_reference=f"ssh_events/{ev_uuid}",
        collected_at=now_utc,
    )

    with pytest.raises(TypeError):
        dto.evidence_data["raw_payload"]["user"] = "hacker"

    assert dto.source_reference == f"ssh_events/{ev_uuid}"


def test_dto_rejects_naive_datetime():
    """Verify DTOs reject naive datetimes across all timestamp fields."""
    naive_dt = datetime.now()
    with pytest.raises(ValidationError, match="timezone-aware"):
        InvestigationDTO(
            investigation_id=uuid.uuid4(),
            incident_id=uuid.uuid4(),
            status="pending",
            created_at=naive_dt,
            updated_at=datetime.now(timezone.utc),
        )


def test_dto_accepts_non_utc_offset_datetime():
    """Verify DTOs accept valid non-UTC timezone offsets (e.g. UTC+5:30)."""
    offset_dt = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    dto = InvestigationDTO(
        investigation_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        status="pending",
        created_at=offset_dt,
        updated_at=offset_dt,
    )
    assert dto.created_at == offset_dt


# =============================================================================
# 3. Canonical Evidence Reference Formatting Tests
# =============================================================================

@pytest.mark.parametrize(
    "prefix,ident",
    [
        ("ssh_events", str(uuid.uuid4())),
        ("detection_results", str(uuid.uuid4())),
        ("incidents", str(uuid.uuid4())),
        ("evidence_items", str(uuid.uuid4())),
        ("mitre", "T1110.001"),
        ("playbooks", "PB-SSH-BRUTEFORCE-01"),
    ],
)
def test_valid_canonical_source_references(prefix: str, ident: str):
    """Verify canonical source reference validation for all permitted prefixes."""
    ref = f"{prefix}/{ident}"
    assert validate_canonical_source_reference(ref) == ref


def test_source_reference_rejects_old_colon_format():
    """Verify old colon format is rejected per Task 7B Revision 5."""
    with pytest.raises(ValueError, match="Expected format '<prefix>/<identifier>'"):
        validate_canonical_source_reference(f"ssh_events:{uuid.uuid4()}")


def test_source_reference_rejects_malformed_uuid():
    """Verify malformed or invalid UUIDs are strictly rejected."""
    with pytest.raises(ValueError, match="Malformed UUID"):
        validate_canonical_source_reference("ssh_events/not-a-valid-uuid")


def test_source_reference_rejects_uppercase_uuid():
    """Verify non-canonical uppercase UUID is rejected."""
    upper_uuid = str(uuid.uuid4()).upper()
    with pytest.raises(ValueError, match="must be canonical lowercase"):
        validate_canonical_source_reference(f"ssh_events/{upper_uuid}")


def test_source_reference_rejects_unknown_prefix():
    """Verify unrecognized prefixes are rejected."""
    with pytest.raises(ValueError, match="Invalid source reference prefix"):
        validate_canonical_source_reference(f"unknown_source/{uuid.uuid4()}")


# =============================================================================
# 4. Structured Investigation Report Tests
# =============================================================================

def test_confirmed_finding_with_valid_canonical_reference():
    """Verify ConfirmedFinding accepts canonical slash reference format."""
    ev_id = uuid.uuid4()
    finding = ConfirmedFinding(
        finding_id="FIND-001",
        title="Multiple Failed SSH Logins",
        description="Observed 25 consecutive failed logins from single IP.",
        evidence_references=[f"ssh_events/{ev_id}"],
        confidence="high",
    )
    assert len(finding.evidence_references) == 1
    assert finding.evidence_references[0] == f"ssh_events/{ev_id}"


def test_confirmed_finding_rejects_empty_evidence_references():
    """Verify ConfirmedFinding requires at least one evidence reference."""
    with pytest.raises(ValidationError):
        ConfirmedFinding(
            finding_id="FIND-001",
            title="Finding Without Proof",
            description="Speculative claim.",
            evidence_references=[],
        )


def test_confirmed_finding_rejects_malformed_reference():
    """Verify ConfirmedFinding rejects invalid reference strings."""
    with pytest.raises(ValidationError):
        ConfirmedFinding(
            finding_id="FIND-001",
            title="Invalid Ref",
            description="Invalid ref.",
            evidence_references=["random_string_not_matching_pattern"],
        )


def test_observation_valid():
    """Verify Observation accepts pattern description and optional canonical references."""
    obs = Observation(
        observation_id="OBS-001",
        description="High volume of authentication attempts across multiple usernames.",
    )
    assert obs.observation_id == "OBS-001"
    assert obs.evidence_references == []


def test_hypothesis_valid():
    """Verify Hypothesis requires description, likelihood, and required verification."""
    hyp = Hypothesis(
        hypothesis_id="HYP-001",
        description="External actor attempting credential spraying against admin accounts.",
        likelihood="medium",
        required_verification="Check auth logs from preceding 24 hours.",
    )
    assert hyp.likelihood == "medium"


def test_evidence_gap_valid():
    """Verify EvidenceGap accepts missing telemetry description."""
    gap = EvidenceGap(
        gap_id="GAP-001",
        description="Firewall flow logs for the correlation window are unavailable.",
        potential_sources=["Network flow logs", "Edge router logs"],
    )
    assert len(gap.potential_sources) == 2


def test_investigation_report_insufficient_evidence():
    """Verify report cleanly expresses insufficient evidence without hallucinations."""
    report = InvestigationReport(
        summary="Unable to reach conclusive attribution due to missing firewall and host logs.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[
            Observation(
                observation_id="OBS-001",
                description="Isolated anomalous spike detected by Isolation Forest.",
            )
        ],
        hypotheses=[
            Hypothesis(
                hypothesis_id="HYP-001",
                description="Possible port scan or automated scanner.",
                likelihood="low",
                required_verification="Network boundary telemetry.",
            )
        ],
        evidence_gaps=[
            EvidenceGap(
                gap_id="GAP-001",
                description="Host process logs not available for target server.",
            )
        ],
        root_cause_assessment=None,
    )
    assert report.sufficient_evidence is False
    assert len(report.confirmed_findings) == 0
    assert report.root_cause_assessment is None


def test_investigation_report_rejects_extra_fields():
    """Verify InvestigationReport rejects unknown/arbitrary fields."""
    with pytest.raises(ValidationError):
        InvestigationReport(
            summary="Report",
            sufficient_evidence=True,
            mitigation_action="block_ip",  # Not allowed in investigation report
        )


# =============================================================================
# 5. Tool Argument Schemas (Approved Limits & Context Scoping)
# =============================================================================

def test_empty_args():
    """Verify EmptyArgs forbids any parameters."""
    args = EmptyArgs()
    assert args.model_dump() == {}

    with pytest.raises(ValidationError):
        EmptyArgs(incident_id=uuid.uuid4())


def test_get_ssh_events_args_approved_bounds():
    """Verify GetSSHEventsArgs default is 100 and bounds are 1-500."""
    default_args = GetSSHEventsArgs()
    assert default_args.limit == 100

    custom = GetSSHEventsArgs(limit=500)
    assert custom.limit == 500

    # Bounds: < 1 or > 500 must fail
    with pytest.raises(ValidationError):
        GetSSHEventsArgs(limit=0)
    with pytest.raises(ValidationError):
        GetSSHEventsArgs(limit=501)

    # Rejects model-supplied incident_id or source_ip
    with pytest.raises(ValidationError):
        GetSSHEventsArgs(incident_id=uuid.uuid4())
    with pytest.raises(ValidationError):
        GetSSHEventsArgs(source_ip="192.0.2.1")


def test_search_ssh_events_by_username_args():
    """Verify SearchSSHEventsByUsernameArgs: default 50, bounds 1-200, non-empty username."""
    default_args = SearchSSHEventsByUsernameArgs(username="secops_admin")
    assert default_args.limit == 50
    assert default_args.username == "secops_admin"

    custom = SearchSSHEventsByUsernameArgs(username="root", limit=200)
    assert custom.limit == 200

    # Bounds: > 200 must fail
    with pytest.raises(ValidationError):
        SearchSSHEventsByUsernameArgs(username="root", limit=201)

    with pytest.raises(ValidationError):
        SearchSSHEventsByUsernameArgs(username="   ")

    # Rejects model-supplied context IDs
    with pytest.raises(ValidationError):
        SearchSSHEventsByUsernameArgs(username="admin", incident_id=uuid.uuid4())


def test_get_related_incidents_for_ip_args():
    """Verify GetRelatedIncidentsForIPArgs: default 10, bounds 1-50."""
    default_args = GetRelatedIncidentsForIPArgs()
    assert default_args.limit == 10

    custom = GetRelatedIncidentsForIPArgs(limit=50)
    assert custom.limit == 50

    with pytest.raises(ValidationError):
        GetRelatedIncidentsForIPArgs(limit=0)
    with pytest.raises(ValidationError):
        GetRelatedIncidentsForIPArgs(limit=51)

    # Rejects model-supplied source_ip
    with pytest.raises(ValidationError):
        GetRelatedIncidentsForIPArgs(source_ip="192.0.2.100")


# =============================================================================
# 6. Tool Output Schemas (Explicitly Defined for all 6 Tools)
# =============================================================================

def test_incident_context_output():
    """Verify IncidentContextOutput output schema for get_incident_context."""
    now = datetime.now(timezone.utc)
    out = IncidentContextOutput(
        incident_id=uuid.uuid4(),
        title="Brute Force Attack on SSH",
        incident_type="brute_force",
        source_ip="192.0.2.10",
        severity="high",
        detection_method="hybrid",
        status="open",
        investigation_status="in_progress",
        created_at=now,
        updated_at=now,
        associated_event_count=15,
        associated_detection_count=2,
    )
    dumped = out.model_dump()
    assert dumped["title"] == "Brute Force Attack on SSH"
    assert dumped["associated_event_count"] == 15
    assert dumped["associated_detection_count"] == 2
    assert dumped["severity"] == "high"


def test_ssh_events_output_bounds_and_count_matching():
    """Verify SSHEventsOutput preserves truncated flag and enforces count match."""
    now = datetime.now(timezone.utc)
    ev = SSHEventRecord(
        event_id=uuid.uuid4(),
        event_timestamp=now,
        source_ip="192.0.2.10",
        username="root",
        authentication_result="failure",
        event_type="password",
        ingested_at=now,
    )
    # Valid output: count matches len(events)
    out = SSHEventsOutput(events=[ev], count=1, truncated=True)
    assert out.truncated is True
    assert out.count == 1

    # Invalid output: count doesn't match len(events)
    with pytest.raises(ValidationError, match="count .* must match"):
        SSHEventsOutput(events=[ev], count=99, truncated=True)


def test_username_ssh_events_output():
    """Verify UsernameSSHEventsOutput for search_ssh_events_by_username."""
    now = datetime.now(timezone.utc)
    ev = SSHEventRecord(
        event_id=uuid.uuid4(),
        event_timestamp=now,
        source_ip="192.0.2.10",
        username="admin",
        authentication_result="success",
        event_type="password",
        ingested_at=now,
    )
    out = UsernameSSHEventsOutput(events=[ev], count=1, truncated=False)
    assert out.count == 1
    assert out.truncated is False


def test_detection_results_output_serialization():
    """Verify DetectionResultsOutput output schema for get_detection_results."""
    now = datetime.now(timezone.utc)
    rec = DetectionResultRecord(
        result_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        source_ip="192.0.2.10",
        window_start=now,
        window_end=now,
        detector_type="isolation_forest",
        is_suspicious=True,
        triggered_rules=[],
        feature_snapshot={"failed_logins": 25},
        normality_score=-0.15,
        calibrated_threshold=0.035,
        model_version="1.0.0",
        evaluated_at=now,
    )
    out = DetectionResultsOutput(results=[rec], count=1, truncated=False)
    assert out.truncated is False
    assert out.results[0].normality_score == -0.15


def test_prior_evidence_output():
    """Verify PriorEvidenceOutput schema for get_prior_evidence."""
    now = datetime.now(timezone.utc)
    item = EvidenceItemRecord(
        evidence_id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        evidence_type="ssh_event",
        title="Prior Evidence",
        source_reference=f"ssh_events/{uuid.uuid4()}",
        collected_at=now,
    )
    out = PriorEvidenceOutput(evidence_items=[item], count=1, truncated=False)
    assert out.count == 1
    assert out.evidence_items[0].title == "Prior Evidence"


def test_related_incidents_output():
    """Verify RelatedIncidentsOutput schema for get_related_incidents_for_ip."""
    now = datetime.now(timezone.utc)
    inc = RelatedIncidentRecord(
        incident_id=uuid.uuid4(),
        title="Earlier Attack",
        incident_type="brute_force",
        status="closed",
        investigation_status="completed",
        created_at=now,
    )
    out = RelatedIncidentsOutput(incidents=[inc], count=1, truncated=False)
    assert out.count == 1
    assert out.incidents[0].status == "closed"


# =============================================================================
# 7. Gemini Structured Output Compatibility
# =============================================================================

def test_gemini_schema_transformation_compatibility():
    """Verify google-genai SDK transforms InvestigationReport into types.Schema without error."""
    schema = _transformers.t_schema(None, InvestigationReport)
    assert isinstance(schema, types.Schema)
    assert schema.type == types.Type.OBJECT
    assert "summary" in schema.properties
    assert "sufficient_evidence" in schema.properties
    assert "confirmed_findings" in schema.properties
    assert "observations" in schema.properties
    assert "hypotheses" in schema.properties
    assert "evidence_gaps" in schema.properties
    assert "root_cause_assessment" in schema.properties


def test_gemini_generate_content_config_with_investigation_report():
    """Verify types.GenerateContentConfig accepts InvestigationReport as response_schema."""
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=InvestigationReport,
        max_output_tokens=8192,
        thinking_config=types.ThinkingConfig(thinking_level="medium"),
    )
    assert config.response_schema == InvestigationReport
    assert config.response_mime_type == "application/json"
    assert config.max_output_tokens == 8192


def test_gemini_phase_b_synthesis_report_schema_isolation():
    """Verify InvestigationSynthesisReport isolates Gemini Phase B from authoring MITRE mappings."""
    # 1. Properties check
    assert "mitre_attack_mappings" not in InvestigationSynthesisReport.model_fields
    assert "mitre_attack_mappings" in InvestigationReport.model_fields

    # 2. SDK Schema transformation check
    schema = _transformers.t_schema(None, InvestigationSynthesisReport)
    assert isinstance(schema, types.Schema)
    assert schema.type == types.Type.OBJECT
    assert "summary" in schema.properties
    assert "sufficient_evidence" in schema.properties
    assert "mitre_attack_mappings" not in schema.properties

    # 3. Model validation check: attempting to pass mitre_attack_mappings to synthesis report fails closed
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        InvestigationSynthesisReport(
            summary="Synthesis report",
            sufficient_evidence=True,
            mitre_attack_mappings=[{"mapping_id": str(uuid.uuid4())}],  # Extra forbidden field
        )


def test_investigation_report_backward_compatibility_and_mitre_extension():
    """Verify historical reports deserialize seamlessly and MITRE mappings serialize properly."""
    # 1. Historical report JSON (without mitre_attack_mappings property)
    historical_json = """{
        "summary": "Historical investigation without MITRE mappings",
        "sufficient_evidence": true,
        "confirmed_findings": [
            {
                "finding_id": "FIND-01",
                "title": "Historical finding",
                "description": "Historical desc",
                "evidence_references": ["ssh_events/11111111-1111-1111-1111-111111111111"],
                "confidence": "high"
            }
        ],
        "observations": [],
        "hypotheses": [],
        "evidence_gaps": []
    }"""
    rep = InvestigationReport.model_validate_json(historical_json)
    assert rep.summary == "Historical investigation without MITRE mappings"
    assert rep.sufficient_evidence is True
    assert len(rep.confirmed_findings) == 1
    assert rep.mitre_attack_mappings == []

    # 2. Modern report populated with server-persisted MitreAttackMapping
    now = datetime.now(timezone.utc)
    ev_id = uuid.uuid4()
    mapping = MitreAttackMapping(
        mapping_id=uuid.uuid4(),
        evidence_item_id=uuid.uuid4(),
        rule_id="MAP-SSH-001",
        technique_id="T1110",
        technique_name="Brute Force",
        tactic_ids=["TA0006"],
        tactic_names=["Credential Access"],
        mapping_status=MitreMappingStatus.CANDIDATE,
        confidence=MitreConfidenceLevel.HIGH,
        supporting_references=[f"ssh_events/{ev_id}"],
        event_ids=[ev_id],
        window_start=now - timedelta(minutes=5),
        window_end=now,
        rationale="Behavioral rationale text for valid mapping.",
        catalogue_version="20.1",
    )

    extended_rep = InvestigationReport(
        summary="Modern report with server mappings",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[],
        mitre_attack_mappings=[mapping],
    )
    dumped = extended_rep.model_dump(mode="json")
    assert "mitre_attack_mappings" in dumped
    assert len(dumped["mitre_attack_mappings"]) == 1
    assert dumped["mitre_attack_mappings"][0]["technique_id"] == "T1110"

    # Re-deserialize to verify round-trip integrity
    round_trip = InvestigationReport.model_validate(dumped)
    assert len(round_trip.mitre_attack_mappings) == 1
    assert round_trip.mitre_attack_mappings[0].technique_id == "T1110"

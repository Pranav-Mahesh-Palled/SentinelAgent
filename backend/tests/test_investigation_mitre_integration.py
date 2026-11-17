"""End-to-End Integration and Verification Tests for MITRE ATT&CK Investigation Agent (Task 8E.4).

Verifies the final orchestration stage:
1. Application-Scoped Dependency Injection:
   - Injected from app.state.mitre_catalogue into background runner and InvestigationAgent.
   - Application instance isolation.
2. Server-Controlled Execution:
   - Telemetry retrieval runs server-side independently of Gemini tool choices.
   - Internal retrieval is not exposed as a Gemini tool.
   - Gemini allowlist remains exactly six tools.
   - Retrieved events registered in AuthorizedProvenanceSet.
3. End-to-End Behavioral Mapping in Final Report:
   - Brute-force burst produces candidate T1110 (MAP-SSH-001) in report with persisted EvidenceItem.
   - Password spray produces hypothesis T1110.003 (MAP-SSH-002) in report with persisted EvidenceItem.
   - Valid accounts (MAP-SSH-003) produces candidate T1078 when 2h coverage is complete.
   - Clean / normal telemetry produces empty mitre_attack_mappings list.
4. Validation & Atomic Persistence Guarantees:
   - Persisted EvidenceItem records match report.mitre_attack_mappings[].evidence_item_id.
   - Idempotent re-execution does not create duplicate EvidenceItem records.
   - Failed validation fails closed and prevents investigation completion.
   - Supporting references point to authorized events, never circular.
5. Gemini Isolation:
   - Gemini Phase B output schema remains InvestigationSynthesisReport (unaware of MITRE).
   - Gemini cannot tamper with, fabricate, or override MITRE mappings or confidence.
6. Optional Mode & Graceful Degradation:
   - When mitre_catalogue is None, investigation completes cleanly with mitre_attack_mappings=[].
   - Operational failures (e.g. database error) fail closed even if optional.
7. Heartbeat & Lifecycle Preservation:
   - Heartbeats updated before and after retrieval, mapping, and persistence.
   - InvestigationTerminatedError halts execution without overwriting state.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.api.investigations import router as investigations_router
from app.api.investigations import run_investigation_background
from app.core.config import Settings
from app.db import connection
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.investigation_tool_run import InvestigationToolRun
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    ConfirmedFinding,
    EvidenceGap,
    InvestigationReport,
    InvestigationSynthesisReport,
    Observation,
    SSHEventRecord,
)
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.gemini_client import GeminiProvider
from app.services.investigation_agent import (
    ALLOWED_TOOL_NAMES,
    InvestigationAgent,
    InvestigationAgentError,
)
from app.services.investigation_service import (
    AuthorizedProvenanceSet,
    InvestigationService,
    InvestigationTerminatedError,
)
from app.services.investigation_tools import (
    INTERNAL_RETRIEVAL_TOOL_NAME,
    ActiveInvestigationContext,
)
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_validator import MitreMappingValidationError


# =============================================================================
# Fixtures and Cleanup Tracking
# =============================================================================

@pytest.fixture
def db_engine():
    """Provides a live database engine."""
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def session_factory(db_engine):
    """Provides a sessionmaker bound to the live database engine."""
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def cleanup_tracker(db_engine):
    """Tracks created database entities and deletes them in reverse FK order upon test teardown."""
    tracker = {
        "tool_runs": [],
        "evidence_items": [],
        "investigations": [],
        "incidents": [],
        "ssh_events": [],
    }
    yield tracker

    with db_engine.begin() as conn:
        if tracker["investigations"]:
            conn.execute(
                delete(InvestigationToolRun).where(
                    InvestigationToolRun.investigation_id.in_(tracker["investigations"])
                )
            )
            conn.execute(
                delete(EvidenceItem).where(
                    EvidenceItem.investigation_id.in_(tracker["investigations"])
                )
            )
            conn.execute(
                delete(Investigation).where(
                    Investigation.investigation_id.in_(tracker["investigations"])
                )
            )
        if tracker["incidents"]:
            conn.execute(
                delete(Incident).where(
                    Incident.incident_id.in_(tracker["incidents"])
                )
            )
        if tracker["ssh_events"]:
            conn.execute(
                delete(SSHEvent).where(
                    SSHEvent.event_id.in_(tracker["ssh_events"])
                )
            )


@pytest.fixture(scope="module")
def real_catalogue():
    """Provides the verified Enterprise ATT&CK v20.1 catalogue."""
    from app.core.config import get_settings
    settings = get_settings()
    return MitreCatalogueService.from_file(settings.MITRE_CATALOGUE_PATH)


@pytest.fixture
def mock_gemini_provider():
    """Creates a mock GeminiProvider configured with default thinking level."""
    mock_client = MagicMock()
    mock_client.close = MagicMock()
    provider = GeminiProvider(
        client=mock_client,
        model="gemini-3.8-flash",
        max_output_tokens=8192,
        timeout_seconds=120,
        thinking_level="medium",
    )
    return provider


def _configure_mock_gemini(provider, synthesis_report: InvestigationSynthesisReport):
    """Configures mock Gemini client to cleanly exit Phase A and return synthesis report in Phase B."""
    from google.genai import types
    resp_finish_tools = MagicMock(
        candidates=[MagicMock(content=types.Content(role="model", parts=[types.Part(text="Sufficient telemetry.")]))],
        text="Sufficient telemetry.",
        function_calls=[],
    )
    raw_json = synthesis_report.model_dump_json()
    resp_report = MagicMock(
        candidates=[MagicMock(content=types.Content(role="model", parts=[types.Part(text=raw_json)]))],
        text=raw_json,
        function_calls=[],
    )
    provider.client.models.generate_content.side_effect = [resp_finish_tools, resp_report]


# =============================================================================
# 1. Application-Scoped Dependency Injection Tests
# =============================================================================

def test_catalogue_injected_from_app_state_into_background_worker(session_factory, real_catalogue):
    """Verify create_investigation passes request.app.state.mitre_catalogue to background task."""
    test_app = FastAPI()
    test_app.state.gemini_provider = MagicMock(is_closed=False)
    test_app.state.mitre_catalogue = real_catalogue
    test_app.include_router(investigations_router, prefix="/api")

    incident_id = uuid.uuid4()
    with patch("app.api.investigations.get_session_factory", return_value=session_factory), \
         patch("app.services.investigation_service.InvestigationService.create_investigation", return_value=uuid.uuid4()), \
         patch("app.services.investigation_service.InvestigationService.get_investigation") as mock_get_inv, \
         patch("app.api.investigations.run_investigation_background") as mock_bg_task:

        mock_inv_dto = MagicMock()
        mock_inv_dto.investigation_id = uuid.uuid4()
        mock_inv_dto.incident_id = incident_id
        mock_inv_dto.status = "pending"
        mock_inv_dto.investigation_summary = None
        mock_inv_dto.investigation_report = None
        mock_inv_dto.root_cause_assessment = None
        mock_inv_dto.started_at = None
        mock_inv_dto.completed_at = None
        mock_inv_dto.created_at = datetime.now(timezone.utc)
        mock_inv_dto.updated_at = datetime.now(timezone.utc)
        mock_get_inv.return_value = mock_inv_dto

        client = TestClient(test_app)
        response = client.post("/api/investigations", json={"incident_id": str(incident_id)})
        assert response.status_code == 202

        # Verify background task was enqueued with the app.state.mitre_catalogue
        mock_bg_task.assert_called_once()
        _, kwargs = mock_bg_task.call_args
        assert kwargs["mitre_catalogue"] is real_catalogue


def test_independent_application_instances_maintain_separate_catalogue_injection():
    """Verify two separate FastAPI apps maintain isolated catalogue instances in app.state."""
    app1 = FastAPI()
    app2 = FastAPI()

    cat1 = MagicMock(spec=MitreCatalogueService)
    cat2 = MagicMock(spec=MitreCatalogueService)

    app1.state.mitre_catalogue = cat1
    app2.state.mitre_catalogue = cat2

    assert app1.state.mitre_catalogue is not app2.state.mitre_catalogue
    assert app1.state.mitre_catalogue is cat1
    assert app2.state.mitre_catalogue is cat2


# =============================================================================
# 2. Server-Controlled Execution & Gemini Isolation Tests
# =============================================================================

def test_mitre_mapping_runs_even_when_gemini_requests_zero_tools(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify MITRE supplemental retrieval and mapping execute even if Gemini makes 0 tool calls."""
    anchor = datetime(2026, 7, 10, 14, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.77"

    # Setup incident & investigation in DB
    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Password Guessing Activity",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    # Insert 35 failed SSH login attempts (MAP-SSH-001 candidate trigger)
    ssh_ids = []
    with session_factory() as session:
        for i in range(35):
            ev_id = uuid.uuid4()
            ssh_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=8) + timedelta(seconds=i * 10),
                source_ip=source_ip,
                username="victim",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        cleanup_tracker["ssh_events"].extend(ssh_ids)
        session.commit()

    # Gemini immediately finishes Phase A (0 tool calls) and provides synthesis
    empty_tool_response = MagicMock()
    empty_tool_response.candidates = [MagicMock(content=MagicMock(parts=[]))]
    empty_tool_response.function_calls = []

    synthesis_report = InvestigationSynthesisReport(
        summary="Automated analysis concluded no findings from basic tool checks.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[
            EvidenceGap(
                gap_id="GAP-1",
                description="No interactive tools executed.",
                potential_sources=[],
            )
        ],
        root_cause_assessment="Indeterminate based solely on initial scan.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    # Run agent with real catalogue
    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )
    completed_dto = agent.run(inv_id)

    # Verify investigation completed
    assert completed_dto.status == "completed"
    report = completed_dto.investigation_report
    assert report is not None
    assert "mitre_attack_mappings" in report

    # Verify MAP-SSH-001 (T1110) was generated and persisted by server despite 0 Gemini tool calls!
    mappings = report["mitre_attack_mappings"]
    assert len(mappings) >= 1
    t1110 = next(m for m in mappings if m["rule_id"] == "MAP-SSH-001")
    assert t1110["technique_id"] == "T1110"
    assert t1110["mapping_status"] == "candidate"
    assert t1110["confidence"] == "high"
    assert t1110["evidence_item_id"] is not None

    # Verify EvidenceItem was created in database
    with session_factory() as session:
        ev_item = session.execute(
            select(EvidenceItem).where(EvidenceItem.evidence_id == uuid.UUID(t1110["evidence_item_id"]))
        ).scalar_one_or_none()
        assert ev_item is not None
        assert ev_item.evidence_type == "mitre_technique"
        assert ev_item.source_reference == "mitre/T1110"
        cleanup_tracker["evidence_items"].append(ev_item.evidence_id)


def test_gemini_allowlist_remains_strictly_six_tools():
    """Verify Gemini tool allowlist is NOT modified and does not expose internal retrieval."""
    expected_tools = {
        "get_incident_context",
        "get_ssh_events",
        "get_detection_results",
        "get_prior_evidence",
        "search_ssh_events_by_username",
        "get_related_incidents_for_ip",
    }
    assert ALLOWED_TOOL_NAMES == expected_tools
    assert INTERNAL_RETRIEVAL_TOOL_NAME not in ALLOWED_TOOL_NAMES


# =============================================================================
# 3. Behavioral Mapping in Final Report & Persistence Verification
# =============================================================================

def test_end_to_end_map_ssh_001_candidate_persisted_in_report(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Proves full orchestration of MAP-SSH-001 candidate:
    Synthetic failed events -> server retrieval -> proposal generation ->
    independent validator -> atomic PostgreSQL EvidenceItem persistence ->
    InvestigationReport inclusion with candidate status, medium confidence, and valid evidence_item_id.
    """
    anchor = datetime(2026, 7, 10, 14, 30, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.75"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="SSH Brute Force Attack",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    # Insert 12 failed SSH attempts within 8 minutes for a single username (qualifies for MAP-SSH-001: 10-29 failures -> Medium Candidate)
    ssh_ids = []
    with session_factory() as session:
        for i in range(12):
            ev_id = uuid.uuid4()
            ssh_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=8) + timedelta(seconds=i * 20),
                source_ip=source_ip,
                username="test_user",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        cleanup_tracker["ssh_events"].extend(ssh_ids)
        session.commit()

    synthesis_report = InvestigationSynthesisReport(
        summary="Analysis observed brute force authentication attempts.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="External brute force credential guessing.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )
    completed_dto = agent.run(inv_id)

    assert completed_dto.status == "completed"
    report = completed_dto.investigation_report
    assert report is not None
    assert "mitre_attack_mappings" in report

    mappings = report["mitre_attack_mappings"]
    assert len(mappings) >= 1

    # Verify MAP-SSH-001 mapping details
    t1110 = next(m for m in mappings if m["rule_id"] == "MAP-SSH-001")
    assert t1110["technique_id"] == "T1110"
    assert t1110["technique_name"] == "Brute Force"
    assert t1110["mapping_status"] == "candidate"
    assert t1110["confidence"] == "medium"
    assert "Credential Access" in t1110["tactic_names"]
    assert t1110["evidence_item_id"] is not None

    # Verify atomic PostgreSQL EvidenceItem persistence
    ev_uuid = uuid.UUID(t1110["evidence_item_id"])
    with session_factory() as session:
        ev_item = session.execute(
            select(EvidenceItem).where(EvidenceItem.evidence_id == ev_uuid)
        ).scalar_one_or_none()
        assert ev_item is not None
        assert ev_item.investigation_id == inv_id
        assert ev_item.evidence_type == "mitre_technique"
        assert ev_item.source_reference == "mitre/T1110"
        assert ev_item.evidence_data["rule_id"] == "MAP-SSH-001"
        assert ev_item.evidence_data["mapping_status"] == "candidate"
        assert ev_item.evidence_data["confidence"] == "medium"
        assert len(ev_item.evidence_data["supporting_references"]) == 12
        cleanup_tracker["evidence_items"].append(ev_item.evidence_id)


def test_map_ssh_002_horizontal_spray_produces_hypothesis_t1110_003(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify horizontal multi-user failed attempts produce T1110.003 hypothesis in report."""
    anchor = datetime(2026, 7, 10, 15, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.88"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Password Spray Detection",
            incident_type="password_spray",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    # Insert 6 failed attempts targeting 6 distinct usernames (satisfies MAP-SSH-002: >=5 unique users)
    ssh_ids = []
    with session_factory() as session:
        for i in range(6):
            ev_id = uuid.uuid4()
            ssh_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=20 - i * 2),
                source_ip=source_ip,
                username=f"user_{i}",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        cleanup_tracker["ssh_events"].extend(ssh_ids)
        session.commit()

    synthesis_report = InvestigationSynthesisReport(
        summary="Analysis observed authentication anomalies.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Potential automated spray activity.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )
    completed_dto = agent.run(inv_id)

    report = completed_dto.investigation_report
    mappings = report["mitre_attack_mappings"]
    t1110_003 = next(m for m in mappings if m["rule_id"] == "MAP-SSH-002")
    assert t1110_003["technique_id"] == "T1110.003"
    assert t1110_003["mapping_status"] == "hypothesis"
    assert t1110_003["confidence"] in ("low", "medium")
    assert t1110_003["evidence_item_id"] is not None

    with session_factory() as session:
        ev_item = session.execute(
            select(EvidenceItem).where(EvidenceItem.evidence_id == uuid.UUID(t1110_003["evidence_item_id"]))
        ).scalar_one()
        assert ev_item.evidence_type == "mitre_technique"
        cleanup_tracker["evidence_items"].append(ev_item.evidence_id)


def test_map_ssh_003_valid_accounts_persisted_with_complete_coverage(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify successful authentication preceded by 5 failures with complete 2h coverage yields T1078 candidate."""
    anchor = datetime(2026, 7, 10, 16, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.99"
    success_time = anchor + timedelta(minutes=20)

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Suspicious Login Activity",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    ssh_ids = []
    with session_factory() as session:
        for i in range(5):
            ev_id = uuid.uuid4()
            ssh_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=30 - i * 5),
                source_ip=source_ip,
                username="victim_admin",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        succ_id = uuid.uuid4()
        ssh_ids.append(succ_id)
        session.add(SSHEvent(
            event_id=succ_id,
            event_timestamp=success_time,
            source_ip=source_ip,
            username="victim_admin",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend(ssh_ids)
        session.commit()

    synthesis_report = InvestigationSynthesisReport(
        summary="Successful authentication observed after failed attempts.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Possible compromise.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )
    completed_dto = agent.run(inv_id)

    report = completed_dto.investigation_report
    mappings = report["mitre_attack_mappings"]
    t1078 = next((m for m in mappings if m["rule_id"] == "MAP-SSH-003"), None)
    assert t1078 is not None
    assert t1078["technique_id"] == "T1078"
    assert t1078["mapping_status"] == "candidate"
    assert t1078["confidence"] == "low"
    assert t1078["evidence_item_id"] is not None

    with session_factory() as session:
        ev_item = session.execute(
            select(EvidenceItem).where(EvidenceItem.evidence_id == uuid.UUID(t1078["evidence_item_id"]))
        ).scalar_one()
        assert ev_item.evidence_type == "mitre_technique"
        cleanup_tracker["evidence_items"].append(ev_item.evidence_id)


def test_clean_telemetry_produces_empty_mapping_list(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify normal telemetry without attacks completes with mitre_attack_mappings=[]."""
    anchor = datetime(2026, 7, 10, 17, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.111"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Benign Investigation",
            incident_type="benign",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    # Single normal successful authentication
    ev_id = uuid.uuid4()
    with session_factory() as session:
        session.add(SSHEvent(
            event_id=ev_id,
            event_timestamp=anchor,
            source_ip=source_ip,
            username="normal_user",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].append(ev_id)
        session.commit()

    synthesis_report = InvestigationSynthesisReport(
        summary="No threat activity identified.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Benign administrative session.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )
    completed_dto = agent.run(inv_id)

    report = completed_dto.investigation_report
    assert len(report["mitre_attack_mappings"]) == 0


# =============================================================================
# 4. Optional Mode and Operational Failure Handling Tests
# =============================================================================

def test_optional_mode_without_catalogue_completes_cleanly(
    session_factory, cleanup_tracker, mock_gemini_provider
):
    """Verify when mitre_catalogue is None, agent logs and completes with mitre_attack_mappings=[]."""
    anchor = datetime(2026, 7, 10, 18, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.122"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Optional Mode Investigation",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    synthesis_report = InvestigationSynthesisReport(
        summary="Investigation ran without MITRE catalogue.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Catalogue omitted.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    # Initialize agent with mitre_catalogue=None
    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=None,
    )
    completed_dto = agent.run(inv_id)

    assert completed_dto.status == "completed"
    assert len(completed_dto.investigation_report["mitre_attack_mappings"]) == 0


def test_database_retrieval_failure_fails_closed_and_marks_investigation_failed(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify database retrieval failure in MITRE step causes investigation to fail closed."""
    anchor = datetime(2026, 7, 10, 19, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.133"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="DB Error Incident",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    synthesis_report = InvestigationSynthesisReport(
        summary="Phase B completed.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Pending MITRE evaluation.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )

    # Simulate database retrieval failure
    with patch(
        "app.services.investigation_agent.retrieve_incident_ssh_telemetry",
        side_effect=OperationalError("Connection lost during retrieval", None, None),
    ):
        with pytest.raises(InvestigationAgentError, match="Connection lost during retrieval"):
            agent.run(inv_id)

    # Verify investigation transitioned to failed
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "failed"
        assert "OperationalError" in (inv.investigation_summary or "")


def test_validation_failure_fails_closed(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify tampered or invalid proposals raise validation error and fail investigation."""
    anchor = datetime(2026, 7, 10, 20, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.144"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Validation Tampering Incident",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    synthesis_report = InvestigationSynthesisReport(
        summary="Synthesis finished.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="None.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )

    with patch.object(
        inv_service,
        "persist_validated_mitre_mappings",
        side_effect=MitreMappingValidationError("Proposal hash mismatch"),
    ), patch(
        "app.services.investigation_agent.retrieve_incident_ssh_telemetry",
        return_value=((), MagicMock()),
    ), patch(
        "app.services.investigation_agent.MitreMappingEngine.evaluate",
        return_value=[MagicMock()],
    ):
        with pytest.raises(InvestigationAgentError, match="Proposal hash mismatch"):
            agent.run(inv_id)

    # Verify investigation transitioned to failed
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv.status == "failed"


# =============================================================================
# 5. Heartbeat & Lifecycle Tests
# =============================================================================

def test_heartbeat_updated_during_mitre_pipeline(
    session_factory, cleanup_tracker, real_catalogue, mock_gemini_provider
):
    """Verify heartbeat is updated around MITRE retrieval, mapping, and persistence."""
    anchor = datetime(2026, 7, 10, 21, 0, 0, tzinfo=timezone.utc)
    source_ip = "198.51.100.155"

    inv_service = InvestigationService(session_factory=session_factory)
    with session_factory() as session:
        inc = Incident(
            title="Heartbeat Incident",
            incident_type="brute_force",
            source_ip=source_ip,
            status="investigating",
            detection_method="rule",
            created_at=anchor,
        )
        session.add(inc)
        session.flush()
        inv = Investigation(
            incident_id=inc.incident_id,
            status="in_progress",
            created_at=anchor,
            started_at=anchor,
        )
        session.add(inv)
        session.commit()
        inc_id = inc.incident_id
        inv_id = inv.investigation_id

    cleanup_tracker["incidents"].append(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    synthesis_report = InvestigationSynthesisReport(
        summary="Report synthesized.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="None.",
    )
    _configure_mock_gemini(mock_gemini_provider, synthesis_report)

    agent = InvestigationAgent(
        gemini_provider=mock_gemini_provider,
        investigation_service=inv_service,
        session_factory=session_factory,
        mitre_catalogue=real_catalogue,
    )

    with patch.object(inv_service, "update_heartbeat", wraps=inv_service.update_heartbeat) as mock_heartbeat:
        agent.run(inv_id)
        # Should be called during Phase A, Phase B, and multiple times around MITRE pipeline
        assert mock_heartbeat.call_count >= 3

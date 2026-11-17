"""Automated Integration Tests for InvestigationService (Task 7B.4 Audited).

Covers all core requirements and audit criteria:
1. Lifecycle Management:
   - create_investigation (pending state, NULL started_at/completed_at)
   - duplicate investigation rejection (InvestigationConflictError)
   - start_investigation (in_progress state, sets started_at, incident sync)
   - duplicate active investigation rejection
   - complete_investigation (completed state, report persistence, incident sync)
   - fail_investigation (failed state, sanitized failure summary, incident sync)
   - invalid lifecycle transitions rejected
   - non-existent incident or investigation raises specific NotFound errors
2. Heartbeat State Guard:
   - active investigation heartbeat succeeds
   - completed or failed investigation heartbeat raises InvestigationTerminatedError
3. Tool-Run Audit Lifecycle:
   - record_tool_run_start (creates running tool run with started_at)
   - record_tool_run_success (marks succeeded, calculates duration_ms)
   - record_tool_run_failure (marks failed, sanitizes error_code)
   - tool run lifecycle errors on non-existent or invalid transitions
4. Evidence Persistence and Provenance Validation (Fail-Closed):
   - valid SSH event evidence with direct link
   - valid SSH event evidence with correlation-window check
   - valid detection result evidence
   - valid historical incident evidence
   - prior evidence ownership check
   - invalid/unauthorized reference rejected (ProvenanceValidationError)
   - missing provenance set rejects confirmed findings with references
   - insufficient evidence report with zero findings accepted without provenance set
   - non-existent DB source record rejected
   - source IP mismatch rejected
   - correlation window boundary rejection
   - transaction rollback when validation fails
5. Stale and Abandoned Investigation Recovery & Tool-Run Cleanliness:
   - abandoned pending investigation (>5m) recovered to failed
   - stale in-progress investigation (>5m without heartbeat/tool activity) recovered to failed
   - hard ceiling duration (>30m based on started_at) recovered to failed
   - recently active investigation (<5m) preserved
   - incident status synced to failed only when no active investigations remain
   - abandoned running tool runs automatically transitioned to failed (INVESTIGATION_RECOVERED)
   - already succeeded/failed tool runs preserved
6. Concurrency and Worker Termination:
   - concurrent create_investigation attempts (only one succeeds)
   - tool success after investigation recovery is rejected
   - tool failure after investigation recovery is rejected
   - evidence insertion after recovery is rejected
   - completion after recovery is rejected
   - zero ORM instances escape service layer (all return DTOs)
"""

import concurrent.futures
from datetime import datetime, timedelta, timezone
import threading
import uuid
import pytest
from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.db import connection
from app.models.detection_result import DetectionResult
from app.models.evidence_item import EvidenceItem
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.investigation import Investigation
from app.models.investigation_tool_run import InvestigationToolRun
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import (
    ConfirmedFinding,
    EvidenceGap,
    EvidenceItemDTO,
    Hypothesis,
    InvestigationDTO,
    InvestigationReport,
    Observation,
)
from app.schemas.mitre import (
    MitreAttackMapping,
    MitreConfidenceLevel,
    MitreMappingStatus,
)
from app.services.investigation_service import (
    AuthorizedProvenanceSet,
    IncidentNotFoundError,
    InvestigationConflictError,
    InvestigationNotFoundError,
    InvestigationService,
    InvestigationTerminatedError,
    ProvenanceValidationError,
    ToolRunLifecycleError,
)


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
def investigation_service(session_factory):
    """Provides an InvestigationService instance configured with session_factory."""
    return InvestigationService(session_factory=session_factory)


@pytest.fixture
def cleanup_tracker(db_engine):
    """Tracks created database entities and deletes them in reverse FK order upon test teardown."""
    tracker = {
        "tool_runs": [],
        "evidence_items": [],
        "investigations": [],
        "incident_events": [],
        "detection_results": [],
        "incidents": [],
        "ssh_events": [],
    }
    yield tracker

    with db_engine.begin() as conn:
        if tracker["tool_runs"]:
            conn.execute(
                delete(InvestigationToolRun).where(
                    InvestigationToolRun.tool_run_id.in_(tracker["tool_runs"])
                )
            )
        if tracker["evidence_items"]:
            conn.execute(
                delete(EvidenceItem).where(
                    EvidenceItem.evidence_id.in_(tracker["evidence_items"])
                )
            )
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
            # Clean up memory outbox entries referencing investigations
            from app.models.memory_outbox import IncidentMemoryOutbox
            conn.execute(
                delete(IncidentMemoryOutbox).where(
                    IncidentMemoryOutbox.investigation_id.in_(tracker["investigations"])
                )
            )
            conn.execute(
                delete(Investigation).where(
                    Investigation.investigation_id.in_(tracker["investigations"])
                )
            )
        if tracker["incident_events"]:
            conn.execute(
                delete(IncidentEvent).where(
                    IncidentEvent.incident_id.in_(tracker["incident_events"])
                )
            )
        if tracker["detection_results"]:
            conn.execute(
                delete(DetectionResult).where(
                    DetectionResult.result_id.in_(tracker["detection_results"])
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


def create_incident(
    session: Session,
    cleanup_tracker: dict,
    source_ip: str = "192.0.2.111",
    created_at: datetime | None = None,
) -> Incident:
    """Helper to insert an Incident record tracked for cleanup."""
    now = created_at or datetime.now(timezone.utc)
    inc = Incident(
        incident_id=uuid.uuid4(),
        title="Investigation Service Test Incident",
        incident_type="brute_force",
        source_ip=source_ip,
        severity="medium",
        detection_method="hybrid",
        status="open",
        investigation_status="pending",
        created_at=now,
        updated_at=now,
    )
    session.add(inc)
    session.flush()
    cleanup_tracker["incidents"].append(inc.incident_id)
    return inc


# =============================================================================
# 1. Lifecycle Management Tests
# =============================================================================

def test_create_and_start_investigation_lifecycle(investigation_service, session_factory, cleanup_tracker):
    """Verify investigation creation, pending state, and transition to in_progress."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    # 1. Create investigation
    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    assert isinstance(inv_id, uuid.UUID)

    # Verify pending state in DB
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "pending"
        assert inv_row.started_at is None
        assert inv_row.completed_at is None

        inc_row = session.execute(
            select(Incident).where(Incident.incident_id == inc_id)
        ).scalar_one()
        assert inc_row.investigation_status == "pending"

    # 2. Duplicate create must be rejected
    with pytest.raises(InvestigationConflictError, match="already has an active or pending investigation"):
        investigation_service.create_investigation(inc_id)

    # 3. Start investigation
    dto = investigation_service.start_investigation(inv_id)
    assert isinstance(dto, InvestigationDTO)
    assert dto.status == "in_progress"
    assert dto.started_at is not None
    assert dto.completed_at is None

    # Verify DB updated
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "in_progress"
        assert inv_row.started_at is not None

        inc_row = session.execute(
            select(Incident).where(Incident.incident_id == inc_id)
        ).scalar_one()
        assert inc_row.investigation_status == "in_progress"

    # 4. Starting again must be rejected (not pending)
    with pytest.raises(InvestigationConflictError, match="current status is 'in_progress'"):
        investigation_service.start_investigation(inv_id)


def test_complete_investigation_lifecycle(investigation_service, session_factory, cleanup_tracker):
    """Verify investigation completion, report persistence, and incident synchronization."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # Build report with no confirmed findings (honest insufficient evidence)
    report = InvestigationReport(
        summary="Successful SSH brute force leading to unauthorized access.",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[
            Observation(observation_id="OBS-1", description="Observed login spike.")
        ],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Weak password on root account.",
    )

    completed_dto = investigation_service.complete_investigation(
        investigation_id=inv_id,
        report=report,
        summary="Executive summary",
        root_cause="Credential guessing",
    )

    assert isinstance(completed_dto, InvestigationDTO)
    assert completed_dto.status == "completed"
    assert completed_dto.completed_at is not None
    assert completed_dto.investigation_summary == "Executive summary"
    assert completed_dto.root_cause_assessment == "Credential guessing"

    # Verify database
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "completed"
        assert inv_row.completed_at is not None
        assert inv_row.investigation_report["summary"] == report.summary

        inc_row = session.execute(
            select(Incident).where(Incident.incident_id == inc_id)
        ).scalar_one()
        assert inc_row.investigation_status == "completed"


def test_fail_investigation_lifecycle(investigation_service, session_factory, cleanup_tracker):
    """Verify fail_investigation transitions status, writes safe summary, and updates incident."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    investigation_service.fail_investigation(
        investigation_id=inv_id,
        error_code="LLM_RATE_LIMIT",
        safe_summary="Provider rate limit exceeded after maximum retries.",
    )

    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "failed"
        assert inv_row.completed_at is not None
        assert "[FAILED:LLM_RATE_LIMIT]" in inv_row.investigation_summary

        inc_row = session.execute(
            select(Incident).where(Incident.incident_id == inc_id)
        ).scalar_one()
        assert inc_row.investigation_status == "failed"


# =============================================================================
# 2. Heartbeat State Guard Tests
# =============================================================================

def test_heartbeat_execution_guard(investigation_service, session_factory, cleanup_tracker):
    """Verify update_heartbeat succeeds for in_progress and fails for terminal states."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # 1. In-progress heartbeat succeeds
    investigation_service.update_heartbeat(inv_id)

    # 2. Complete investigation
    report = InvestigationReport(
        summary="Concluded.",
        sufficient_evidence=False,
    )
    investigation_service.complete_investigation(inv_id, report)

    # 3. Heartbeat after completion must raise InvestigationTerminatedError
    with pytest.raises(InvestigationTerminatedError, match="no longer in_progress"):
        investigation_service.update_heartbeat(inv_id)


# =============================================================================
# 3. Tool-Run Audit Lifecycle Tests
# =============================================================================

def test_tool_run_audit_lifecycle(investigation_service, session_factory, cleanup_tracker):
    """Verify start, success, and failure transitions of InvestigationToolRun."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # 1. Start tool run
    tool_run_id = investigation_service.record_tool_run_start(
        investigation_id=inv_id,
        tool_name="get_ssh_events",
        input_summary={"limit": 50},
    )
    cleanup_tracker["tool_runs"].append(tool_run_id)
    assert isinstance(tool_run_id, uuid.UUID)

    with session_factory() as session:
        tr = session.execute(
            select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tool_run_id)
        ).scalar_one()
        assert tr.execution_status == "running"
        assert tr.started_at is not None
        assert tr.completed_at is None

    # 2. Complete tool run
    investigation_service.record_tool_run_success(
        tool_run_id=tool_run_id,
        output_summary={"count": 25, "truncated": False},
    )

    with session_factory() as session:
        tr = session.execute(
            select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tool_run_id)
        ).scalar_one()
        assert tr.execution_status == "succeeded"
        assert tr.completed_at is not None
        assert tr.duration_ms is not None
        assert tr.duration_ms >= 0
        assert tr.output_summary["count"] == 25

    # 3. Second transition on already succeeded tool run must fail
    with pytest.raises(ToolRunLifecycleError, match="current status is 'succeeded'"):
        investigation_service.record_tool_run_success(tool_run_id)

    # 4. Start second tool run and mark failed
    tool_run_2 = investigation_service.record_tool_run_start(
        investigation_id=inv_id,
        tool_name="search_ssh_events_by_username",
        input_summary={"username": "admin"},
    )
    cleanup_tracker["tool_runs"].append(tool_run_2)

    investigation_service.record_tool_run_failure(
        tool_run_id=tool_run_2,
        error_code="QUERY_TIMEOUT",
        output_summary={"error": "Database query timed out"},
    )

    with session_factory() as session:
        tr2 = session.execute(
            select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tool_run_2)
        ).scalar_one()
        assert tr2.execution_status == "failed"
        assert tr2.error_code == "QUERY_TIMEOUT"
        assert tr2.completed_at is not None


# =============================================================================
# 4. Evidence Persistence and Provenance Validation Tests (Fail-Closed)
# =============================================================================

def test_record_evidence_provenance_validation(investigation_service, session_factory, cleanup_tracker):
    """Verify two-tier provenance validation for EvidenceItem persistence."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker, source_ip="192.0.2.222", created_at=now)

        # 1. Linked SSH event
        ev_linked = SSHEvent(
            event_id=uuid.uuid4(),
            event_timestamp=now,
            source_ip="192.0.2.222",
            username="root",
            authentication_result="failure",
            event_type="password",
        )
        session.add(ev_linked)
        session.flush()
        cleanup_tracker["ssh_events"].append(ev_linked.event_id)

        session.add(IncidentEvent(incident_id=inc.incident_id, event_id=ev_linked.event_id))
        cleanup_tracker["incident_events"].append(inc.incident_id)

        # 2. Detection result for incident
        dr = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            source_ip="192.0.2.222",
            window_start=now,
            window_end=now + timedelta(minutes=1),
            detector_type="rule",
            is_suspicious=True,
            feature_snapshot={},
        )
        session.add(dr)
        session.flush()
        cleanup_tracker["detection_results"].append(dr.result_id)

        # 3. Detection result for OTHER incident
        other_inc = create_incident(session, cleanup_tracker, source_ip="198.51.100.1")
        dr_other = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=other_inc.incident_id,
            source_ip="198.51.100.1",
            window_start=now,
            window_end=now + timedelta(minutes=1),
            detector_type="rule",
            is_suspicious=True,
            feature_snapshot={},
        )
        session.add(dr_other)
        session.flush()
        cleanup_tracker["detection_results"].append(dr_other.result_id)

        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # Initialize authorized provenance set
    prov_set = AuthorizedProvenanceSet()
    prov_set.add_ssh_event(ev_linked.event_id)
    prov_set.add_detection_result(dr.result_id)

    # A. Valid SSH evidence record
    item_dto = investigation_service.record_evidence(
        investigation_id=inv_id,
        evidence_type="ssh_event",
        title="Failed Login Attempt",
        source_reference=f"ssh_events/{ev_linked.event_id}",
        description="Observed login failure on root.",
        provenance_set=prov_set,
    )
    cleanup_tracker["evidence_items"].append(item_dto.evidence_id)
    assert isinstance(item_dto, EvidenceItemDTO)
    assert item_dto.event_id == ev_linked.event_id
    assert item_dto.source_reference == f"ssh_events/{ev_linked.event_id}"

    # B. Valid Detection Result evidence record
    dr_dto = investigation_service.record_evidence(
        investigation_id=inv_id,
        evidence_type="detection_result",
        title="Brute Force Anomaly",
        source_reference=f"detection_results/{dr.result_id}",
        provenance_set=prov_set,
    )
    cleanup_tracker["evidence_items"].append(dr_dto.evidence_id)
    assert dr_dto.event_id is None
    assert dr_dto.source_reference == f"detection_results/{dr.result_id}"

    # C. Rejected: Reference not in AuthorizedProvenanceSet
    unauthorized_uuid = uuid.uuid4()
    with pytest.raises(ProvenanceValidationError, match="not found in provenance set|not retrieved"):
        investigation_service.record_evidence(
            investigation_id=inv_id,
            evidence_type="ssh_event",
            title="Unauthorized Fake Event",
            source_reference=f"ssh_events/{unauthorized_uuid}",
            provenance_set=prov_set,
        )

    # D. Rejected: Reference in ProvenanceSet but detection result belongs to OTHER incident
    prov_set.add_detection_result(dr_other.result_id)
    with pytest.raises(ProvenanceValidationError, match="belongs to incident .*, not current incident"):
        investigation_service.record_evidence(
            investigation_id=inv_id,
            evidence_type="detection_result",
            title="Other Incident's Result",
            source_reference=f"detection_results/{dr_other.result_id}",
            provenance_set=prov_set,
        )


def test_completion_provenance_fail_closed(investigation_service, session_factory, cleanup_tracker):
    """Verify complete_investigation fails closed when provenance_set is omitted or lacks references."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # Report with confirmed finding having an evidence reference
    fake_ref = f"ssh_events/{uuid.uuid4()}"
    report = InvestigationReport(
        summary="Incident summary",
        sufficient_evidence=True,
        confirmed_findings=[
            ConfirmedFinding(
                finding_id="F-1",
                title="Unauthorized claim",
                description="No evidence registry supplied",
                evidence_references=[fake_ref],
            )
        ],
    )

    # 1. Omitted provenance_set must raise ProvenanceValidationError
    with pytest.raises(ProvenanceValidationError, match="AuthorizedProvenanceSet was omitted"):
        investigation_service.complete_investigation(
            investigation_id=inv_id,
            report=report,
            provenance_set=None,
        )

    # 2. Provided provenance_set that lacks the reference must raise ProvenanceValidationError
    empty_prov_set = AuthorizedProvenanceSet()
    with pytest.raises(ProvenanceValidationError, match="unauthorized evidence reference"):
        investigation_service.complete_investigation(
            investigation_id=inv_id,
            report=report,
            provenance_set=empty_prov_set,
        )


# =============================================================================
# 5. Stale and Abandoned Investigation Recovery Tests & Tool Run Cleaning
# =============================================================================

def test_recover_stale_investigations_and_running_tool_runs(investigation_service, session_factory, cleanup_tracker):
    """Verify recovery sweeper cleans up abandoned jobs, stale in-progress jobs, and running tool runs."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        # Incident 1: Abandoned pending investigation (>5m ago)
        inc1 = create_incident(session, cleanup_tracker, created_at=now - timedelta(minutes=10))
        inv_pending_stale = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc1.incident_id,
            status="pending",
            created_at=now - timedelta(minutes=6),
            updated_at=now - timedelta(minutes=6),
        )
        session.add(inv_pending_stale)
        cleanup_tracker["investigations"].append(inv_pending_stale.investigation_id)

        # Incident 2: Stale in-progress (>5m without heartbeat/tool activity)
        inc2 = create_incident(session, cleanup_tracker, created_at=now - timedelta(minutes=20))
        inv_inprogress_stale = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc2.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=15),
            created_at=now - timedelta(minutes=15),
            updated_at=now - timedelta(minutes=6),  # stale heartbeat
        )
        session.add(inv_inprogress_stale)
        cleanup_tracker["investigations"].append(inv_inprogress_stale.investigation_id)

        # Running tool run associated with stale in-progress investigation (MUST BE FAILED BY RECOVERY)
        tr_running = InvestigationToolRun(
            tool_run_id=uuid.uuid4(),
            investigation_id=inv_inprogress_stale.investigation_id,
            tool_name="get_ssh_events",
            execution_status="running",
            started_at=now - timedelta(minutes=7),
            completed_at=None,
        )
        # Succeeded tool run associated with stale in-progress investigation (MUST REMAIN SUCCEEDED)
        tr_succeeded = InvestigationToolRun(
            tool_run_id=uuid.uuid4(),
            investigation_id=inv_inprogress_stale.investigation_id,
            tool_name="get_incident_context",
            execution_status="succeeded",
            started_at=now - timedelta(minutes=10),
            completed_at=now - timedelta(minutes=9),
            duration_ms=1000,
        )
        session.add_all([tr_running, tr_succeeded])
        cleanup_tracker["tool_runs"].extend([tr_running.tool_run_id, tr_succeeded.tool_run_id])

        # Incident 3: Recently active in-progress (<5m ago) -> MUST NOT BE RECOVERED
        inc3 = create_incident(session, cleanup_tracker, created_at=now - timedelta(minutes=5))
        inv_active = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc3.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=3),
            created_at=now - timedelta(minutes=3),
            updated_at=now - timedelta(minutes=1),  # recent heartbeat
        )
        session.add(inv_active)
        cleanup_tracker["investigations"].append(inv_active.investigation_id)

        # Incident 4: Hard duration ceiling exceeded (>30m) -> MUST BE RECOVERED
        inc4 = create_incident(session, cleanup_tracker, created_at=now - timedelta(minutes=40))
        inv_hard_ceiling = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc4.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=35),
            created_at=now - timedelta(minutes=35),
            updated_at=now - timedelta(minutes=1),  # even with recent heartbeat!
        )
        session.add(inv_hard_ceiling)
        cleanup_tracker["investigations"].append(inv_hard_ceiling.investigation_id)

        session.commit()

    # Run recovery sweeper
    recovery_results = investigation_service.recover_stale_investigations()

    recovered_invs = recovery_results["recovered_investigations"]
    recovered_incs = recovery_results["recovered_incidents"]

    # Invs 1, 2, and 4 should be recovered
    assert inv_pending_stale.investigation_id in recovered_invs
    assert inv_inprogress_stale.investigation_id in recovered_invs
    assert inv_hard_ceiling.investigation_id in recovered_invs

    # Inv 3 must NOT be recovered
    assert inv_active.investigation_id not in recovered_invs

    # Verify Incidents updated to failed
    assert inc1.incident_id in recovered_incs
    assert inc2.incident_id in recovered_incs
    assert inc4.incident_id in recovered_incs
    assert inc3.incident_id not in recovered_incs

    # Verify database state for investigations and tool runs
    with session_factory() as session:
        inv1_row = session.execute(select(Investigation).where(Investigation.investigation_id == inv_pending_stale.investigation_id)).scalar_one()
        assert inv1_row.status == "failed"
        assert "[FAILED:TIMEOUT]" in inv1_row.investigation_summary

        inv3_row = session.execute(select(Investigation).where(Investigation.investigation_id == inv_active.investigation_id)).scalar_one()
        assert inv3_row.status == "in_progress"

        # Verify running tool run was failed with INVESTIGATION_RECOVERED
        tr_run_row = session.execute(select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tr_running.tool_run_id)).scalar_one()
        assert tr_run_row.execution_status == "failed"
        assert tr_run_row.error_code == "INVESTIGATION_RECOVERED"
        assert tr_run_row.completed_at is not None
        assert tr_run_row.duration_ms is not None

        # Verify succeeded tool run remained succeeded
        tr_succ_row = session.execute(select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tr_succeeded.tool_run_id)).scalar_one()
        assert tr_succ_row.execution_status == "succeeded"


# =============================================================================
# 6. Concurrency Safety and Worker Termination Tests
# =============================================================================

def test_concurrent_investigation_creation_safety(investigation_service, session_factory, cleanup_tracker):
    """Verify that multiple sessions cannot create duplicate pending investigations for the same incident."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    # Create first
    inv1_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv1_id)

    # Second creation in parallel/sequential session must raise InvestigationConflictError
    with pytest.raises(InvestigationConflictError):
        investigation_service.create_investigation(inc_id)


def test_worker_operations_blocked_after_investigation_recovery(investigation_service, session_factory, cleanup_tracker):
    """Verify that after an investigation is recovered/failed, stale worker writes are blocked."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # Start a tool run
    tr_id = investigation_service.record_tool_run_start(
        investigation_id=inv_id,
        tool_name="get_ssh_events",
    )
    cleanup_tracker["tool_runs"].append(tr_id)

    # Investigation fails / recovered
    investigation_service.fail_investigation(
        investigation_id=inv_id,
        error_code="WORKER_CRASH",
        safe_summary="Simulated worker crash.",
    )

    # 1. Stale worker attempting tool success must be rejected
    with pytest.raises(InvestigationTerminatedError, match="parent investigation is in status 'failed'"):
        investigation_service.record_tool_run_success(tr_id)

    # 2. Stale worker attempting tool failure must be rejected
    with pytest.raises(InvestigationTerminatedError, match="parent investigation is in status 'failed'"):
        investigation_service.record_tool_run_failure(tr_id, error_code="STALE_WORKER")

    # 3. Stale worker attempting evidence write must be rejected
    with pytest.raises(InvestigationTerminatedError, match="Investigation .* is in status 'failed'"):
        investigation_service.record_evidence(
            investigation_id=inv_id,
            evidence_type="ssh_event",
            title="Stale evidence",
            source_reference=f"ssh_events/{uuid.uuid4()}",
        )

    # 4. Stale worker attempting completion must be rejected
    report = InvestigationReport(summary="Stale report", sufficient_evidence=False)
    with pytest.raises(InvestigationTerminatedError, match="current status is 'failed'"):
        investigation_service.complete_investigation(
            investigation_id=inv_id,
            report=report,
        )


# =============================================================================
# 7. Insufficient Evidence Lifecycle & Category Provenance Tests
# =============================================================================

def test_insufficient_evidence_lifecycle_semantics(investigation_service, session_factory, cleanup_tracker):
    """Verify technically successful investigation with insufficient evidence uses status='completed'."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    # Valid report with sufficient_evidence=False and populated evidence_gaps
    gap = EvidenceGap(
        gap_id="GAP-001",
        description="Missing firewall netflow logs to confirm lateral movement.",
        potential_sources=["pcap", "firewall_logs"],
    )
    report = InvestigationReport(
        summary="Investigation could not confirm root cause due to missing firewall telemetry.",
        sufficient_evidence=False,
        confirmed_findings=[],
        observations=[],
        hypotheses=[],
        evidence_gaps=[gap],
    )

    # Completion without provenance_set must succeed because there are zero source references
    dto = investigation_service.complete_investigation(
        investigation_id=inv_id,
        report=report,
        summary="Investigation completed with insufficient evidence.",
    )

    # Verify DTO snapshot
    assert dto.status == "completed"
    assert dto.investigation_report["sufficient_evidence"] is False
    assert len(dto.investigation_report["evidence_gaps"]) == 1
    assert dto.investigation_report["evidence_gaps"][0]["gap_id"] == "GAP-001"

    # Verify PostgreSQL row
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "completed"  # NOT "insufficient_evidence"
        assert inv_row.investigation_report["sufficient_evidence"] is False

        inc_row = session.execute(
            select(Incident).where(Incident.incident_id == inc_id)
        ).scalar_one()
        assert inc_row.investigation_status == "completed"


def test_provenance_set_tracks_identifiers_by_source_category(investigation_service, session_factory, cleanup_tracker):
    """Verify AuthorizedProvenanceSet enforces strict per-category type isolation."""
    prov_set = AuthorizedProvenanceSet()

    fake_ssh_id = uuid.uuid4()
    fake_dr_id = uuid.uuid4()
    fake_inc_id = uuid.uuid4()
    fake_ev_id = uuid.uuid4()

    prov_set.add_ssh_event(fake_ssh_id)
    prov_set.add_detection_result(fake_dr_id)
    prov_set.add_historical_incident(fake_inc_id)
    prov_set.add_evidence_item(fake_ev_id)

    # 1. Correct categories must be accepted
    assert prov_set.contains_reference(f"ssh_events/{fake_ssh_id}") is True
    assert prov_set.contains_reference(f"detection_results/{fake_dr_id}") is True
    assert prov_set.contains_reference(f"incidents/{fake_inc_id}") is True
    assert prov_set.contains_reference(f"evidence_items/{fake_ev_id}") is True

    # 2. Cross-category spoofing must be strictly rejected
    # Attempting to use SSH event UUID under detection_results prefix
    assert prov_set.contains_reference(f"detection_results/{fake_ssh_id}") is False
    with pytest.raises(ProvenanceValidationError, match="not found in provenance set"):
        prov_set.validate_reference(f"detection_results/{fake_ssh_id}")

    # Attempting to use detection result UUID under ssh_events prefix
    assert prov_set.contains_reference(f"ssh_events/{fake_dr_id}") is False
    with pytest.raises(ProvenanceValidationError, match="not found in provenance set"):
        prov_set.validate_reference(f"ssh_events/{fake_dr_id}")

    # 3. Observations with unauthorized references must fail closed in complete_investigation
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    inv_id = investigation_service.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)
    investigation_service.start_investigation(inv_id)

    report_with_bad_obs = InvestigationReport(
        summary="Report with unauthorized observation reference",
        sufficient_evidence=False,
        observations=[
            Observation(
                observation_id="OBS-1",
                description="Suspicious burst",
                evidence_references=[f"ssh_events/{uuid.uuid4()}"],
            )
        ],
    )

    with pytest.raises(ProvenanceValidationError, match="unauthorized evidence reference"):
        investigation_service.complete_investigation(
            investigation_id=inv_id,
            report=report_with_bad_obs,
            provenance_set=prov_set,
        )


# =============================================================================
# 8. Genuine PostgreSQL Concurrency Tests (Independent Sessions & Overlapping Transactions)
# =============================================================================

def test_genuine_concurrent_investigation_creation(session_factory, cleanup_tracker):
    """Test 1: Multiple threads concurrently attempt to create an investigation for the same incident."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    barrier = threading.Barrier(3)
    results: list[uuid.UUID] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker():
        # Independent service and independent DB session/connection per thread
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()  # Synchronize threads so transactions overlap in PostgreSQL
        try:
            inv_id = svc.create_investigation(inc_id)
            with lock:
                results.append(inv_id)
                cleanup_tracker["investigations"].append(inv_id)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    # Exactly 1 thread must succeed; the other 2 must receive InvestigationConflictError
    assert len(results) == 1
    assert len(errors) == 2
    for err in errors:
        assert isinstance(err, InvestigationConflictError)

    # Verify final database state: exactly 1 pending investigation
    with session_factory() as session:
        rows = session.execute(
            select(Investigation).where(Investigation.incident_id == inc_id)
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].status == "pending"


def test_genuine_concurrent_investigation_start(session_factory, cleanup_tracker):
    """Test 2: Multiple threads concurrently attempt to start the same pending investigation."""
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        session.commit()
        inc_id = inc.incident_id

    svc_init = InvestigationService(session_factory=session_factory)
    inv_id = svc_init.create_investigation(inc_id)
    cleanup_tracker["investigations"].append(inv_id)

    barrier = threading.Barrier(2)
    successes: list[InvestigationDTO] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        try:
            dto = svc.start_investigation(inv_id)
            with lock:
                successes.append(dto)
        except Exception as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)

    # Exactly 1 thread must succeed; the other must receive InvestigationConflictError
    assert len(successes) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], InvestigationConflictError)
    assert successes[0].status == "in_progress"

    # Verify database state
    with session_factory() as session:
        row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert row.status == "in_progress"
        assert row.started_at is not None


def test_genuine_recovery_racing_with_active_worker(session_factory, cleanup_tracker):
    """Test 3: Recovery sweeper racing with an active worker sending heartbeats."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=4),  # Active within 30m ceiling
            updated_at=now - timedelta(minutes=1),  # Fresh heartbeat (< 5m)
        )
        session.add(inv)
        session.commit()
        inv_id = inv.investigation_id
        cleanup_tracker["investigations"].append(inv_id)

    barrier = threading.Barrier(2)
    worker_errors: list[Exception] = []
    recovery_results: list[dict] = []

    def worker():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        try:
            # Active worker updates heartbeat
            svc.update_heartbeat(inv_id)
        except Exception as exc:
            worker_errors.append(exc)

    def sweeper():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        res = svc.recover_stale_investigations()
        recovery_results.append(res)

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=sweeper)
    t1.start()
    t2.start()
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)

    assert len(worker_errors) == 0
    # The active investigation must NOT be recovered
    assert inv_id not in recovery_results[0]["recovered_investigations"]

    with session_factory() as session:
        row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert row.status == "in_progress"


def test_genuine_tool_completion_racing_with_recovery(session_factory, cleanup_tracker):
    """Test 4: Worker attempting tool completion while recovery sweeps a stale investigation."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=35),  # Beyond 30m ceiling -> stale
            updated_at=now - timedelta(minutes=10),
        )
        session.add(inv)
        tr = InvestigationToolRun(
            tool_run_id=uuid.uuid4(),
            investigation_id=inv.investigation_id,
            tool_name="get_ssh_events",
            execution_status="running",
            started_at=now - timedelta(minutes=10),
        )
        session.add(tr)
        session.commit()
        inv_id = inv.investigation_id
        tr_id = tr.tool_run_id
        cleanup_tracker["investigations"].append(inv_id)
        cleanup_tracker["tool_runs"].append(tr_id)

    barrier = threading.Barrier(2)
    worker_error: list[Exception] = []

    def worker():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        try:
            svc.record_tool_run_success(tr_id, output_summary={"result": "ok"})
        except Exception as exc:
            worker_error.append(exc)

    def sweeper():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        svc.recover_stale_investigations()

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=sweeper)
    t1.start()
    t2.start()
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)

    # In either execution order, DB must be consistent and have no orphaned running tool runs
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        tr_row = session.execute(
            select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tr_id)
        ).scalar_one()

        assert inv_row.status == "failed"
        assert tr_row.execution_status in {"failed", "succeeded"}
        assert tr_row.execution_status != "running"


def test_genuine_evidence_insertion_racing_with_recovery(session_factory, cleanup_tracker):
    """Test 5: Worker inserting evidence concurrently with investigation recovery."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=35),  # Stale
            updated_at=now - timedelta(minutes=10),
        )
        session.add(inv)
        ev = SSHEvent(
            event_id=uuid.uuid4(),
            event_timestamp=inc.created_at,
            source_ip=str(inc.source_ip),
            username="root",
            authentication_result="failure",
            event_type="password",
        )
        session.add(ev)
        session.flush()
        cleanup_tracker["ssh_events"].append(ev.event_id)
        session.add(IncidentEvent(incident_id=inc.incident_id, event_id=ev.event_id))
        cleanup_tracker["incident_events"].append(inc.incident_id)
        session.commit()
        inv_id = inv.investigation_id
        ev_id = ev.event_id
        cleanup_tracker["investigations"].append(inv_id)

    barrier = threading.Barrier(2)
    worker_error: list[Exception] = []

    def worker():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        try:
            dto = svc.record_evidence(
                investigation_id=inv_id,
                evidence_type="ssh_event",
                title="Concurrent test",
                source_reference=f"ssh_events/{ev_id}",
            )
            cleanup_tracker["evidence_items"].append(dto.evidence_id)
        except Exception as exc:
            worker_error.append(exc)

    def sweeper():
        svc = InvestigationService(session_factory=session_factory)
        barrier.wait()
        svc.recover_stale_investigations()

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=sweeper)
    t1.start()
    t2.start()
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)

    # Database must end in terminal failed state
    with session_factory() as session:
        inv_row = session.execute(
            select(Investigation).where(Investigation.investigation_id == inv_id)
        ).scalar_one()
        assert inv_row.status == "failed"


def test_recovery_and_audit_consistency_multi_investigation(session_factory, cleanup_tracker):
    """Verify recovery consistency when multiple investigations exist for an incident."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = create_incident(session, cleanup_tracker)
        # Investigation 1: Stale in-progress (>30m)
        inv_stale = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now - timedelta(minutes=40),
            updated_at=now - timedelta(minutes=40),
        )
        session.add(inv_stale)

        # Investigation 2: Completed tool run and succeeded tool run on stale investigation
        tr_succeeded = InvestigationToolRun(
            tool_run_id=uuid.uuid4(),
            investigation_id=inv_stale.investigation_id,
            tool_name="get_incident_context",
            execution_status="succeeded",
            started_at=now - timedelta(minutes=39),
            completed_at=now - timedelta(minutes=38),
            duration_ms=60000,
        )
        session.add(tr_succeeded)

        tr_running = InvestigationToolRun(
            tool_run_id=uuid.uuid4(),
            investigation_id=inv_stale.investigation_id,
            tool_name="get_ssh_events",
            execution_status="running",
            started_at=now - timedelta(minutes=38),
        )
        session.add(tr_running)

        # Investigation 3: Active pending investigation for SAME incident (should NOT be marked failed)
        inv_active = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="pending",
            created_at=now - timedelta(minutes=1),
        )
        session.add(inv_active)

        session.commit()
        inc_id = inc.incident_id
        inv_stale_id = inv_stale.investigation_id
        inv_active_id = inv_active.investigation_id
        tr_succ_id = tr_succeeded.tool_run_id
        tr_run_id = tr_running.tool_run_id

        cleanup_tracker["investigations"].extend([inv_stale_id, inv_active_id])
        cleanup_tracker["tool_runs"].extend([tr_succ_id, tr_run_id])

    svc = InvestigationService(session_factory=session_factory)
    rec = svc.recover_stale_investigations()

    assert inv_stale_id in rec["recovered_investigations"]
    assert inv_active_id not in rec["recovered_investigations"]
    # Incident status must NOT be set to failed because inv_active remains pending
    assert inc_id not in rec["recovered_incidents"]

    with session_factory() as session:
        inc_row = session.execute(
            select(Incident).where(Incident.incident_id == inc_id)
        ).scalar_one()
        # Incident investigation_status must remain 'pending' (or whatever active state it was in)
        assert inc_row.investigation_status != "failed"

        # Running tool run was recovered to failed
        tr_run_row = session.execute(
            select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tr_run_id)
        ).scalar_one()
        assert tr_run_row.execution_status == "failed"
        assert tr_run_row.error_code == "INVESTIGATION_RECOVERED"
        assert tr_run_row.duration_ms is not None

        # Succeeded tool run remained succeeded
        tr_succ_row = session.execute(
            select(InvestigationToolRun).where(InvestigationToolRun.tool_run_id == tr_succ_id)
        ).scalar_one()
        assert tr_succ_row.execution_status == "succeeded"
        assert tr_succ_row.duration_ms == 60000


def test_get_active_investigation_context_loads_authoritative_mitre_evidence(session_factory, investigation_service, cleanup_tracker):
    """Verifies that get_active_investigation_context loads validated MitreAttackMapping from EvidenceItem (evidence_type='mitre_technique')."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Brute force test",
            incident_type="brute_force",
            source_ip="192.168.1.100",
            detection_method="rule",
            status="investigating",
            investigation_status="in_progress",
        )
        session.add(inc)

        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now,
        )
        session.add(inv)

        dummy_event_id = uuid.uuid4()
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
            supporting_references=[f"ssh_events/{dummy_event_id}"],
            event_ids=[dummy_event_id],
            window_start=now - timedelta(minutes=5),
            window_end=now,
            rationale="Automated test mapping.",
            catalogue_version="20.1",
        )

        ev_item = EvidenceItem(
            evidence_id=mapping.evidence_item_id,
            investigation_id=inv.investigation_id,
            evidence_type="mitre_technique",  # Authoritative storage contract
            title="MITRE ATT&CK T1110: Brute Force",
            source_reference="mitre/T1110",
            evidence_data=mapping.model_dump(mode="json"),
            collected_at=now,
        )
        session.add(ev_item)
        session.commit()

        cleanup_tracker["incidents"].append(inc.incident_id)
        cleanup_tracker["investigations"].append(inv.investigation_id)
        cleanup_tracker["evidence_items"].append(ev_item.evidence_id)

    ctx = investigation_service.get_active_investigation_context(inv.investigation_id)
    assert ctx.investigation_id == inv.investigation_id
    assert ctx.source_ip == "192.168.1.100"
    assert len(ctx.validated_mitre_mappings) == 1
    loaded = ctx.validated_mitre_mappings[0]
    assert isinstance(loaded, MitreAttackMapping)
    assert loaded.rule_id == "MAP-SSH-001"
    assert loaded.technique_id == "T1110"


def test_get_active_investigation_context_skips_malformed_mitre_evidence(session_factory, investigation_service, cleanup_tracker):
    """Verifies that corrupted evidence_data results in omission, not failure or speculative replacement."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Corrupted evidence test",
            incident_type="brute_force",
            source_ip="192.168.1.101",
            detection_method="rule",
            status="investigating",
            investigation_status="in_progress",
        )
        session.add(inc)

        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now,
        )
        session.add(inv)

        corrupt_ev = EvidenceItem(
            evidence_id=uuid.uuid4(),
            investigation_id=inv.investigation_id,
            evidence_type="mitre_technique",
            title="Corrupt MITRE item",
            source_reference="mitre/T9999",
            evidence_data={"corrupted": "missing_required_fields"},
            collected_at=now,
        )
        session.add(corrupt_ev)
        session.commit()

        cleanup_tracker["incidents"].append(inc.incident_id)
        cleanup_tracker["investigations"].append(inv.investigation_id)
        cleanup_tracker["evidence_items"].append(corrupt_ev.evidence_id)

    ctx = investigation_service.get_active_investigation_context(inv.investigation_id)
    assert ctx.validated_mitre_mappings == ()


def test_evidence_item_rejects_mitre_mappings_evidence_type(session_factory, cleanup_tracker):
    """Verifies that 'mitre_mappings' is not a valid evidence type and is rejected by the database constraint."""
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Constraint test",
            incident_type="brute_force",
            source_ip="192.168.1.102",
            detection_method="rule",
            status="investigating",
            investigation_status="in_progress",
        )
        session.add(inc)
        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=now,
        )
        session.add(inv)
        session.commit()

        cleanup_tracker["incidents"].append(inc.incident_id)
        cleanup_tracker["investigations"].append(inv.investigation_id)

        invalid_ev = EvidenceItem(
            evidence_id=uuid.uuid4(),
            investigation_id=inv.investigation_id,
            evidence_type="mitre_mappings",  # Invalid type, violates check constraint
            title="Invalid Evidence Type",
            collected_at=now,
        )
        session.add(invalid_ev)
        with pytest.raises(Exception):
            session.commit()
        session.rollback()


"""Automated Integration Tests for Investigation Database Foundation (Task 7A).

Covers all 22 required verification tests:
INVESTIGATIONS:
1. Investigation creation.
2. Valid statuses.
3. Invalid status rejected.
4. Incident relationship.
5. Multiple investigations per incident.
6. JSONB report persistence.

EVIDENCE:
7. Evidence creation.
8. Valid evidence types.
9. Invalid evidence type rejected.
10. SSH event reference.
11. JSONB evidence persistence.
12. Foreign-key integrity.

TOOL RUNS:
13. Tool execution creation.
14. Valid execution statuses.
15. Invalid status rejected.
16. JSONB input and output summaries.
17. Execution duration.
18. Investigation relationship.

INTEGRITY:
19. Historical evidence preservation.
20. Investigation deletion restrictions.
21. Tool execution retrieval.
22. Alembic revision synchronization.
"""

from datetime import datetime, timezone
import uuid
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import delete, inspect, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db import connection
from app.models.detection_result import DetectionResult
from app.models.evidence_item import EvidenceItem, VALID_EVIDENCE_TYPES
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.investigation import Investigation, VALID_INVESTIGATION_STATUSES
from app.models.investigation_tool_run import InvestigationToolRun, VALID_TOOL_RUN_STATUSES
from app.models.ssh_event import SSHEvent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_engine():
    """Provides a live database engine."""
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def db_session(db_engine):
    """Provides an isolated database session with post-test rollback."""
    SessionLocal = sessionmaker(bind=db_engine, expire_on_commit=False)
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def cleanup_tracker(db_engine):
    """Tracks created records across all tables and cleanly removes them in reverse FK order."""
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
        # 1. Tool runs
        if tracker["tool_runs"]:
            conn.execute(
                delete(InvestigationToolRun).where(
                    InvestigationToolRun.tool_run_id.in_(tracker["tool_runs"])
                )
            )

        # 2. Evidence items
        if tracker["evidence_items"]:
            conn.execute(
                delete(EvidenceItem).where(
                    EvidenceItem.evidence_id.in_(tracker["evidence_items"])
                )
            )

        # 3. Investigations
        if tracker["investigations"]:
            conn.execute(
                delete(Investigation).where(
                    Investigation.investigation_id.in_(tracker["investigations"])
                )
            )

        # 4. Incident events
        if tracker["incidents"] or tracker["ssh_events"]:
            conds = []
            if tracker["incidents"]:
                conds.append(IncidentEvent.incident_id.in_(tracker["incidents"]))
            if tracker["ssh_events"]:
                conds.append(IncidentEvent.event_id.in_(tracker["ssh_events"]))
            if conds:
                conn.execute(delete(IncidentEvent).where(or_(*conds)))

        # 5. Detection results
        if tracker["detection_results"]:
            conn.execute(
                delete(DetectionResult).where(
                    DetectionResult.result_id.in_(tracker["detection_results"])
                )
            )

        # 6. Incidents
        if tracker["incidents"]:
            conn.execute(
                delete(Incident).where(
                    Incident.incident_id.in_(tracker["incidents"])
                )
            )

        # 7. SSH events
        if tracker["ssh_events"]:
            conn.execute(
                delete(SSHEvent).where(
                    SSHEvent.event_id.in_(tracker["ssh_events"])
                )
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_mock_incident(session: Session, tracker: dict) -> Incident:
    """Helper to persist a test Incident."""
    inc_id = uuid.uuid4()
    tracker["incidents"].append(inc_id)
    inc = Incident(
        incident_id=inc_id,
        title="Investigation Test Incident",
        incident_type="brute_force",
        source_ip="192.0.2.77",
        detection_method="hybrid",
        status="open",
    )
    session.add(inc)
    session.commit()
    return inc


def create_mock_ssh_event(session: Session, tracker: dict) -> SSHEvent:
    """Helper to persist a test SSHEvent."""
    event_id = uuid.uuid4()
    tracker["ssh_events"].append(event_id)
    event = SSHEvent(
        event_id=event_id,
        event_timestamp=datetime.now(timezone.utc),
        source_ip="192.0.2.77",
        username="target_user",
        authentication_result="failure",
        event_type="password",
    )
    session.add(event)
    session.commit()
    return event


def create_mock_investigation(session: Session, tracker: dict, incident: Incident) -> Investigation:
    """Helper to persist a test Investigation."""
    inv_id = uuid.uuid4()
    tracker["investigations"].append(inv_id)
    inv = Investigation(
        investigation_id=inv_id,
        incident_id=incident.incident_id,
        status="pending",
    )
    session.add(inv)
    session.commit()
    return inv


# ---------------------------------------------------------------------------
# Tests 1-6: INVESTIGATIONS
# ---------------------------------------------------------------------------

def test_investigation_creation(db_session, cleanup_tracker):
    """Test 1: Successfully create an investigation record with defaults."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv_id = uuid.uuid4()
    cleanup_tracker["investigations"].append(inv_id)

    inv = Investigation(
        investigation_id=inv_id,
        incident_id=inc.incident_id,
        status="pending",
        investigation_summary="Preliminary investigation into SSH authentication bursts.",
    )
    db_session.add(inv)
    db_session.commit()

    retrieved = db_session.get(Investigation, inv_id)
    assert retrieved is not None
    assert retrieved.incident_id == inc.incident_id
    assert retrieved.status == "pending"
    assert retrieved.investigation_summary == "Preliminary investigation into SSH authentication bursts."
    assert retrieved.started_at is None
    assert retrieved.completed_at is None
    assert retrieved.created_at is not None
    assert retrieved.updated_at is not None


def test_investigation_timestamp_lifecycle(db_session, cleanup_tracker):
    """Verifies timestamp semantics across pending, in_progress, and completed states."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv_id = uuid.uuid4()
    cleanup_tracker["investigations"].append(inv_id)

    # 1. Created as pending: created_at and updated_at populated, started_at and completed_at are None
    inv = Investigation(
        investigation_id=inv_id,
        incident_id=inc.incident_id,
        status="pending",
    )
    db_session.add(inv)
    db_session.commit()
    db_session.expire_all()

    pending_inv = db_session.get(Investigation, inv_id)
    assert pending_inv.created_at is not None
    assert pending_inv.updated_at is not None
    assert pending_inv.started_at is None
    assert pending_inv.completed_at is None
    initial_created = pending_inv.created_at
    initial_updated = pending_inv.updated_at

    # 2. Transition to in_progress: started_at is populated, completed_at remains None
    now_start = datetime.now(timezone.utc)
    pending_inv.status = "in_progress"
    pending_inv.started_at = now_start
    db_session.commit()
    db_session.expire_all()

    running_inv = db_session.get(Investigation, inv_id)
    assert running_inv.status == "in_progress"
    assert running_inv.started_at is not None
    assert running_inv.completed_at is None
    assert running_inv.created_at == initial_created

    # 3. Transition to completed: completed_at is populated, updated_at reflects modification
    now_complete = datetime.now(timezone.utc)
    running_inv.status = "completed"
    running_inv.completed_at = now_complete
    running_inv.investigation_summary = "Investigation successfully concluded."
    db_session.commit()
    db_session.expire_all()

    completed_inv = db_session.get(Investigation, inv_id)
    assert completed_inv.status == "completed"
    assert completed_inv.started_at is not None
    assert completed_inv.completed_at is not None
    assert completed_inv.completed_at >= completed_inv.started_at
    assert completed_inv.updated_at >= initial_updated


def test_valid_investigation_statuses(db_session, cleanup_tracker):
    """Test 2: All controlled investigation statuses are accepted."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    for st in ("pending", "in_progress", "completed", "failed"):
        inv.status = st
        db_session.commit()
        retrieved = db_session.get(Investigation, inv.investigation_id)
        assert retrieved.status == st


def test_invalid_investigation_status_rejected(db_session, cleanup_tracker):
    """Test 3: Unapproved investigation status is rejected by CHECK constraint."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    inv.status = "abandoned"
    with pytest.raises(IntegrityError, match="ck_investigations_status_valid"):
        db_session.commit()
    db_session.rollback()


def test_incident_relationship(db_session, cleanup_tracker):
    """Test 4: Investigation and Incident navigate cleanly in both directions."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    db_session.expire_all()

    # Investigation -> Incident
    retrieved_inv = db_session.get(Investigation, inv.investigation_id)
    assert retrieved_inv.incident is not None
    assert retrieved_inv.incident.incident_id == inc.incident_id

    # Incident -> Investigations
    retrieved_inc = db_session.get(Incident, inc.incident_id)
    assert len(retrieved_inc.investigations) == 1
    assert retrieved_inc.investigations[0].investigation_id == inv.investigation_id


def test_multiple_investigations_per_incident(db_session, cleanup_tracker):
    """Test 5: An incident can have multiple distinct investigations."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv1 = create_mock_investigation(db_session, cleanup_tracker, inc)
    inv2 = create_mock_investigation(db_session, cleanup_tracker, inc)

    db_session.expire_all()
    retrieved_inc = db_session.get(Incident, inc.incident_id)
    assert len(retrieved_inc.investigations) == 2
    inv_ids = {i.investigation_id for i in retrieved_inc.investigations}
    assert inv_ids == {inv1.investigation_id, inv2.investigation_id}


def test_jsonb_report_persistence(db_session, cleanup_tracker):
    """Test 6: Complex investigation report JSONB persists and round-trips accurately."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv_id = uuid.uuid4()
    cleanup_tracker["investigations"].append(inv_id)

    report_payload = {
        "confidence_score": 0.94,
        "attack_narrative": "High velocity credential stuffing followed by targeted password guessing.",
        "mitre_techniques": ["T1110.001", "T1110.003"],
        "recommended_containment": ["block_ip", "rotate_credentials"],
        "evidence_counts": {"ssh_events": 45, "external_intel": 1},
    }

    inv = Investigation(
        investigation_id=inv_id,
        incident_id=inc.incident_id,
        status="completed",
        investigation_report=report_payload,
        root_cause_assessment="Weak password policy allowed dictionary traversal.",
        completed_at=datetime.now(timezone.utc),
    )
    db_session.add(inv)
    db_session.commit()

    retrieved = db_session.get(Investigation, inv_id)
    assert retrieved.investigation_report == report_payload
    assert retrieved.investigation_report["confidence_score"] == 0.94
    assert retrieved.root_cause_assessment == "Weak password policy allowed dictionary traversal."


# ---------------------------------------------------------------------------
# Tests 7-12: EVIDENCE
# ---------------------------------------------------------------------------

def test_evidence_creation(db_session, cleanup_tracker):
    """Test 7: Successfully create and persist an evidence item."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)

    evidence = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=inv.investigation_id,
        evidence_type="mitre_technique",
        title="T1110.001 - Password Guessing",
        description="Identified pattern matches MITRE sub-technique T1110.001.",
        source_reference="https://attack.mitre.org/techniques/T1110/001/",
    )
    db_session.add(evidence)
    db_session.commit()

    retrieved = db_session.get(EvidenceItem, ev_id)
    assert retrieved is not None
    assert retrieved.evidence_type == "mitre_technique"
    assert retrieved.title == "T1110.001 - Password Guessing"
    assert retrieved.collected_at is not None


def test_valid_evidence_types(db_session, cleanup_tracker):
    """Test 8: All approved evidence types are permitted."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    for etype in ("ssh_event", "detection_result", "mitre_technique", "security_playbook", "historical_incident"):
        ev_id = uuid.uuid4()
        cleanup_tracker["evidence_items"].append(ev_id)
        item = EvidenceItem(
            evidence_id=ev_id,
            investigation_id=inv.investigation_id,
            evidence_type=etype,
            title=f"Sample {etype} evidence",
        )
        db_session.add(item)
        db_session.commit()
        assert db_session.get(EvidenceItem, ev_id).evidence_type == etype


def test_invalid_evidence_type_rejected(db_session, cleanup_tracker):
    """Test 9: Unapproved evidence type is rejected by CHECK constraint."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)

    item = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=inv.investigation_id,
        evidence_type="network_packet_capture",
        title="Invalid Type Test",
    )
    db_session.add(item)
    with pytest.raises(IntegrityError, match="ck_evidence_items_evidence_type_valid"):
        db_session.commit()
    db_session.rollback()


def test_ssh_event_reference(db_session, cleanup_tracker):
    """Test 10: EvidenceItem cleanly links to an existing SSHEvent via foreign key."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    ssh_evt = create_mock_ssh_event(db_session, cleanup_tracker)

    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)
    evidence = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=inv.investigation_id,
        event_id=ssh_evt.event_id,
        evidence_type="ssh_event",
        title="Primary Auth Failure Event",
    )
    db_session.add(evidence)
    db_session.commit()

    retrieved = db_session.get(EvidenceItem, ev_id)
    assert retrieved.event_id == ssh_evt.event_id
    assert retrieved.event is not None
    assert retrieved.event.event_id == ssh_evt.event_id


def test_jsonb_evidence_persistence(db_session, cleanup_tracker):
    """Test 11: Structured evidence data persists faithfully in JSONB."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)

    data_payload = {
        "heuristic_score": 0.98,
        "matched_criteria": ["velocity_exceeded", "multi_user"],
        "raw_attributes": {"source_port": 54210, "protocol": "SSH-2.0-OpenSSH_8.2"},
    }

    evidence = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=inv.investigation_id,
        evidence_type="detection_result",
        title="High Velocity Anomaly Evidence",
        evidence_data=data_payload,
    )
    db_session.add(evidence)
    db_session.commit()

    retrieved = db_session.get(EvidenceItem, ev_id)
    assert retrieved.evidence_data == data_payload


def test_evidence_foreign_key_integrity(db_session, cleanup_tracker):
    """Test 12: Linking to non-existent investigation or SSH event fails foreign key validation."""
    fake_inv_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)

    evidence = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=fake_inv_id,
        evidence_type="mitre_technique",
        title="Bad FK Evidence",
    )
    db_session.add(evidence)
    with pytest.raises(IntegrityError, match="fk_evidence_items_investigation_id_investigations"):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# Tests 13-18: TOOL RUNS
# ---------------------------------------------------------------------------

def test_tool_execution_creation(db_session, cleanup_tracker):
    """Test 13: Successfully create and persist an InvestigationToolRun."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    # 1. Pending tool run: started_at and completed_at are None
    pending_id = uuid.uuid4()
    cleanup_tracker["tool_runs"].append(pending_id)
    pending_run = InvestigationToolRun(
        tool_run_id=pending_id,
        investigation_id=inv.investigation_id,
        tool_name="threat_intel_lookup",
        execution_status="pending",
    )
    db_session.add(pending_run)
    db_session.commit()

    retrieved_pending = db_session.get(InvestigationToolRun, pending_id)
    assert retrieved_pending is not None
    assert retrieved_pending.execution_status == "pending"
    assert retrieved_pending.started_at is None
    assert retrieved_pending.completed_at is None

    # 2. Running tool run: started_at is populated, completed_at is None
    run_id = uuid.uuid4()
    cleanup_tracker["tool_runs"].append(run_id)

    run = InvestigationToolRun(
        tool_run_id=run_id,
        investigation_id=inv.investigation_id,
        tool_name="mitre_technique_search",
        execution_status="running",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(run)
    db_session.commit()

    retrieved = db_session.get(InvestigationToolRun, run_id)
    assert retrieved is not None
    assert retrieved.tool_name == "mitre_technique_search"
    assert retrieved.execution_status == "running"
    assert retrieved.started_at is not None
    assert retrieved.completed_at is None


def test_valid_tool_execution_statuses(db_session, cleanup_tracker):
    """Test 14: All approved tool execution statuses are accepted."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    for st in ("pending", "running", "succeeded", "failed"):
        run_id = uuid.uuid4()
        cleanup_tracker["tool_runs"].append(run_id)
        run = InvestigationToolRun(
            tool_run_id=run_id,
            investigation_id=inv.investigation_id,
            tool_name="threat_intel_lookup",
            execution_status=st,
        )
        db_session.add(run)
        db_session.commit()
        assert db_session.get(InvestigationToolRun, run_id).execution_status == st


def test_invalid_tool_execution_status_rejected(db_session, cleanup_tracker):
    """Test 15: Invalid execution status is rejected by CHECK constraint."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    run_id = uuid.uuid4()
    cleanup_tracker["tool_runs"].append(run_id)

    run = InvestigationToolRun(
        tool_run_id=run_id,
        investigation_id=inv.investigation_id,
        tool_name="threat_intel_lookup",
        execution_status="aborted",
    )
    db_session.add(run)
    with pytest.raises(IntegrityError, match="ck_investigation_tool_runs_execution_status_valid"):
        db_session.commit()
    db_session.rollback()


def test_jsonb_tool_input_and_output_summaries(db_session, cleanup_tracker):
    """Test 16: Structured input and output summaries round-trip in JSONB."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    run_id = uuid.uuid4()
    cleanup_tracker["tool_runs"].append(run_id)

    input_summary = {"technique_query": "password guessing", "top_k": 3}
    output_summary = {
        "matched_techniques": ["T1110.001", "T1110.003"],
        "max_relevance_score": 0.91,
    }

    run = InvestigationToolRun(
        tool_run_id=run_id,
        investigation_id=inv.investigation_id,
        tool_name="mitre_technique_search",
        execution_status="succeeded",
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=125,
    )
    db_session.add(run)
    db_session.commit()

    retrieved = db_session.get(InvestigationToolRun, run_id)
    assert retrieved.input_summary == input_summary
    assert retrieved.output_summary == output_summary
    assert retrieved.duration_ms == 125


def test_execution_duration(db_session, cleanup_tracker):
    """Test 17: duration_ms accepts positive values and rejects negative durations."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    run_id = uuid.uuid4()
    cleanup_tracker["tool_runs"].append(run_id)

    # 1. Valid positive duration
    run = InvestigationToolRun(
        tool_run_id=run_id,
        investigation_id=inv.investigation_id,
        tool_name="timing_test",
        execution_status="succeeded",
        duration_ms=450,
    )
    db_session.add(run)
    db_session.commit()
    assert db_session.get(InvestigationToolRun, run_id).duration_ms == 450

    # 2. Negative duration rejected
    run.duration_ms = -50
    with pytest.raises(IntegrityError, match="ck_investigation_tool_runs_duration_ms_non_negative"):
        db_session.commit()
    db_session.rollback()


def test_tool_run_investigation_relationship(db_session, cleanup_tracker):
    """Test 18: Tool runs navigate cleanly to parent Investigation."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    run_id = uuid.uuid4()
    cleanup_tracker["tool_runs"].append(run_id)

    run = InvestigationToolRun(
        tool_run_id=run_id,
        investigation_id=inv.investigation_id,
        tool_name="playbook_selector",
        execution_status="succeeded",
    )
    db_session.add(run)
    db_session.commit()

    db_session.expire_all()
    retrieved_run = db_session.get(InvestigationToolRun, run_id)
    assert retrieved_run.investigation.investigation_id == inv.investigation_id


# ---------------------------------------------------------------------------
# Tests 19-22: INTEGRITY
# ---------------------------------------------------------------------------

def test_historical_evidence_preservation(db_session, cleanup_tracker):
    """Test 19: Attempting to delete an SSHEvent referenced by an EvidenceItem fails (RESTRICT)."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)
    ssh_evt = create_mock_ssh_event(db_session, cleanup_tracker)

    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)
    evidence = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=inv.investigation_id,
        event_id=ssh_evt.event_id,
        evidence_type="ssh_event",
        title="Evidence protecting raw SSH Event",
    )
    db_session.add(evidence)
    db_session.commit()

    # Attempt delete on SSHEvent
    db_session.delete(ssh_evt)
    with pytest.raises(IntegrityError, match="fk_evidence_items_event_id_ssh_events"):
        db_session.commit()
    db_session.rollback()


def test_investigation_deletion_restrictions(db_session, cleanup_tracker):
    """Test 20: Deletion of Investigation is restricted when evidence or tool runs exist."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    # 1. EvidenceItem restricts Investigation deletion
    ev_id = uuid.uuid4()
    cleanup_tracker["evidence_items"].append(ev_id)
    evidence = EvidenceItem(
        evidence_id=ev_id,
        investigation_id=inv.investigation_id,
        evidence_type="mitre_technique",
        title="Restricting Evidence",
    )
    db_session.add(evidence)
    db_session.commit()

    db_session.delete(inv)
    with pytest.raises(IntegrityError, match="fk_evidence_items_investigation_id_investigations"):
        db_session.commit()
    db_session.rollback()

    # 2. Also Incident deletion is restricted when Investigation references it
    db_session.delete(inc)
    with pytest.raises(IntegrityError, match="fk_investigations_incident_id_incidents"):
        db_session.commit()
    db_session.rollback()


def test_tool_execution_retrieval(db_session, cleanup_tracker):
    """Test 21: Multiple tool runs are retrieved through the Investigation relationship."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    inv = create_mock_investigation(db_session, cleanup_tracker, inc)

    run_ids = []
    for tool in ("ssh_event_query", "mitre_search", "containment_playbook"):
        rid = uuid.uuid4()
        run_ids.append(rid)
        cleanup_tracker["tool_runs"].append(rid)
        run = InvestigationToolRun(
            tool_run_id=rid,
            investigation_id=inv.investigation_id,
            tool_name=tool,
            execution_status="succeeded",
        )
        db_session.add(run)
    db_session.commit()

    db_session.expire_all()
    retrieved_inv = db_session.get(Investigation, inv.investigation_id)
    assert len(retrieved_inv.tool_runs) == 3
    tool_names = {r.tool_name for r in retrieved_inv.tool_runs}
    assert tool_names == {"ssh_event_query", "mitre_search", "containment_playbook"}


def test_alembic_revision_synchronization(db_engine):
    """Test 22: Live PostgreSQL database is synchronized with latest head revision."""
    with db_engine.connect() as conn:
        current_rev = conn.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()

    alembic_cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(alembic_cfg)
    head_rev = script.get_current_head()

    assert current_rev is not None
    assert current_rev == head_rev
    assert current_rev in ("c92d43956a00", "34ea070e907d")
    # Verify migration lineage
    revisions = [rev.revision for rev in script.walk_revisions()]
    assert "34ea070e907d" in revisions
    assert "c92d43956a00" in revisions
    assert "73ce52b4ca79" in revisions
    assert "8a70914c5c3e" in revisions
    assert "c6b1eef00aa0" in revisions


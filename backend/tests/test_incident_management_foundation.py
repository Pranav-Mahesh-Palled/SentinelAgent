"""Tests for Incident Management database models, migrations, constraints, and relationships (Task 6A).

Covers:
DETECTION RESULTS:
1. Valid rule detection record.
2. Valid ML detection record.
3. Rule record without an ML score.
4. ML record with a valid normality score.
5. Invalid detector type.
6. Invalid time window.
7. JSONB feature snapshot persistence.

INCIDENTS:
8. Incident creation.
9. Valid incident states.
10. Invalid lifecycle state rejected.
11. Nullable severity.
12. Valid detection method.
13. Invalid detection method.
14. Timestamp defaults.

INCIDENT EVENTS:
15. Valid SSH event association.
16. Duplicate association rejection.
17. Foreign-key integrity.
18. Referential integrity after attempted deletion.

DATABASE INTEGRATION:
19. Incident retrieval with associated SSH events.
20. Incident retrieval with associated detection results.
21. Database migration revision verification.
22. Existing SSH event table remains unchanged.
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import delete, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.db import connection
from app.models.detection_result import DetectionResult
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.ssh_event import SSHEvent


# ---------------------------------------------------------------------------
# Database Fixtures
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
        "incident_events": [],  # list of (incident_id, event_id)
        "detection_results": [],  # list of result_id
        "incidents": [],  # list of incident_id
        "ssh_events": [],  # list of event_id
    }
    yield tracker

    with db_engine.begin() as conn:
        # 1. Clean incident_events
        if tracker["incident_events"]:
            for inc_id, evt_id in tracker["incident_events"]:
                conn.execute(
                    delete(IncidentEvent).where(
                        IncidentEvent.incident_id == inc_id,
                        IncidentEvent.event_id == evt_id,
                    )
                )

        # 2. Clean detection_results
        if tracker["detection_results"]:
            conn.execute(
                delete(DetectionResult).where(
                    DetectionResult.result_id.in_(tracker["detection_results"])
                )
            )

        # 3. Clean incidents
        if tracker["incidents"]:
            conn.execute(
                delete(Incident).where(
                    Incident.incident_id.in_(tracker["incidents"])
                )
            )

        # 4. Clean ssh_events
        if tracker["ssh_events"]:
            conn.execute(
                delete(SSHEvent).where(
                    SSHEvent.event_id.in_(tracker["ssh_events"])
                )
            )


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def create_mock_ssh_event(
    session: Session,
    tracker: dict,
    *,
    source_ip: str = "192.0.2.10",
    username: str = "investigator",
    auth_result: str = "failure",
) -> SSHEvent:
    """Helper to persist a test SSHEvent."""
    event_id = uuid.uuid4()
    tracker["ssh_events"].append(event_id)
    event = SSHEvent(
        event_id=event_id,
        event_timestamp=datetime.now(timezone.utc),
        source_ip=source_ip,
        username=username,
        authentication_result=auth_result,
        event_type="password",
    )
    session.add(event)
    session.commit()
    return event


def create_mock_incident(
    session: Session,
    tracker: dict,
    *,
    title: str = "Test Incident",
    incident_type: str = "brute_force",
    source_ip: str = "192.0.2.10",
    detection_method: str = "rule",
    severity: str | None = None,
    status: str = "open",
) -> Incident:
    """Helper to persist a test Incident."""
    incident_id = uuid.uuid4()
    tracker["incidents"].append(incident_id)
    inc = Incident(
        incident_id=incident_id,
        title=title,
        incident_type=incident_type,
        source_ip=source_ip,
        detection_method=detection_method,
        severity=severity,
        status=status,
    )
    session.add(inc)
    session.commit()
    return inc


# ---------------------------------------------------------------------------
# 1-7: DETECTION RESULTS TESTS
# ---------------------------------------------------------------------------

def test_valid_rule_detection_record(db_session, cleanup_tracker):
    """Test 1: Successfully store and retrieve a valid rule-based detection result."""
    t0 = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.1",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="rule",
        is_suspicious=True,
        triggered_rules=["R001"],
        feature_snapshot={"failed_logins": 15, "total_attempts": 15},
        normality_score=None,
        calibrated_threshold=None,
        model_version=None,
    )
    db_session.add(record)
    db_session.commit()

    retrieved = db_session.get(DetectionResult, res_id)
    assert retrieved is not None
    assert retrieved.detector_type == "rule"
    assert retrieved.is_suspicious is True
    assert retrieved.triggered_rules == ["R001"]
    assert retrieved.feature_snapshot["failed_logins"] == 15
    assert retrieved.normality_score is None
    assert retrieved.evaluated_at is not None


def test_valid_ml_detection_record(db_session, cleanup_tracker):
    """Test 2: Successfully store and retrieve a valid ML detection result."""
    t0 = datetime(2026, 11, 8, 12, 5, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.2",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="isolation_forest",
        is_suspicious=True,
        triggered_rules=[],
        feature_snapshot={"total_attempts": 20, "failure_ratio": 0.95},
        normality_score=-0.285431,
        calibrated_threshold=0.035673,
        model_version="isolation_forest_v1",
    )
    db_session.add(record)
    db_session.commit()

    retrieved = db_session.get(DetectionResult, res_id)
    assert retrieved is not None
    assert retrieved.detector_type == "isolation_forest"
    assert retrieved.is_suspicious is True
    assert retrieved.triggered_rules == []
    assert retrieved.normality_score == pytest.approx(-0.285431, abs=1e-5)
    assert retrieved.calibrated_threshold == pytest.approx(0.035673, abs=1e-5)
    assert retrieved.model_version == "isolation_forest_v1"


def test_rule_record_without_ml_score(db_session, cleanup_tracker):
    """Test 3: Rule detection results cleanly support NULL ML normality scores and thresholds."""
    t0 = datetime(2026, 11, 8, 12, 10, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.3",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="rule",
        is_suspicious=False,
        triggered_rules=[],
        feature_snapshot={"failed_logins": 1},
        normality_score=None,
        calibrated_threshold=None,
    )
    db_session.add(record)
    db_session.commit()

    retrieved = db_session.get(DetectionResult, res_id)
    assert retrieved.normality_score is None
    assert retrieved.calibrated_threshold is None


def test_ml_record_with_valid_normality_score(db_session, cleanup_tracker):
    """Test 4: ML detection result accurately persists continuous decision_function score."""
    t0 = datetime(2026, 11, 8, 12, 15, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.4",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="isolation_forest",
        is_suspicious=False,
        triggered_rules=[],
        feature_snapshot={"failed_logins": 0},
        normality_score=0.089124,
        calibrated_threshold=0.035673,
    )
    db_session.add(record)
    db_session.commit()

    retrieved = db_session.get(DetectionResult, res_id)
    assert retrieved.normality_score == pytest.approx(0.089124, abs=1e-5)


def test_invalid_detector_type(db_session, cleanup_tracker):
    """Test 5: Rejects detector_type not in ('rule', 'isolation_forest')."""
    t0 = datetime(2026, 11, 8, 12, 20, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.5",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="deep_learning",
        is_suspicious=True,
    )
    db_session.add(record)
    with pytest.raises(IntegrityError, match="ck_detection_results_detector_type_valid"):
        db_session.commit()
    db_session.rollback()


def test_invalid_time_window(db_session, cleanup_tracker):
    """Test 6: Rejects detection result where window_end <= window_start."""
    t0 = datetime(2026, 11, 8, 12, 25, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.6",
        window_start=t0,
        window_end=t0 - timedelta(minutes=1),  # Invalid backwards window
        detector_type="rule",
        is_suspicious=False,
    )
    db_session.add(record)
    with pytest.raises(IntegrityError, match="ck_detection_results_window_order"):
        db_session.commit()
    db_session.rollback()


def test_jsonb_feature_snapshot_persistence(db_session, cleanup_tracker):
    """Test 7: Complex JSONB data structures round-trip faithfully."""
    t0 = datetime(2026, 11, 8, 12, 30, 0, tzinfo=timezone.utc)
    res_id = uuid.uuid4()
    cleanup_tracker["detection_results"].append(res_id)

    complex_snapshot = {
        "counts": {"failed": 12, "success": 1},
        "ratios": {"failure_rate": 0.923},
        "flags": [True, False, True],
        "nested": {"deep": {"value": 42}},
    }
    rules = ["R001", "R002"]

    record = DetectionResult(
        result_id=res_id,
        source_ip="198.51.100.7",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="rule",
        is_suspicious=True,
        triggered_rules=rules,
        feature_snapshot=complex_snapshot,
    )
    db_session.add(record)
    db_session.commit()

    retrieved = db_session.get(DetectionResult, res_id)
    assert retrieved.feature_snapshot == complex_snapshot
    assert retrieved.triggered_rules == rules


# ---------------------------------------------------------------------------
# 8-14: INCIDENTS TESTS
# ---------------------------------------------------------------------------

def test_incident_creation(db_session, cleanup_tracker):
    """Test 8: Successfully create an incident with required fields and defaults."""
    inc_id = uuid.uuid4()
    cleanup_tracker["incidents"].append(inc_id)

    incident = Incident(
        incident_id=inc_id,
        title="SSH Brute Force Attack",
        incident_type="brute_force",
        source_ip="203.0.113.10",
        detection_method="rule",
        severity=None,
    )
    db_session.add(incident)
    db_session.commit()

    retrieved = db_session.get(Incident, inc_id)
    assert retrieved is not None
    assert retrieved.title == "SSH Brute Force Attack"
    assert retrieved.status == "open"
    assert retrieved.investigation_status == "pending"
    assert retrieved.response_status == "not_proposed"
    assert retrieved.verification_status == "not_started"
    assert retrieved.severity is None
    assert retrieved.created_at is not None
    assert retrieved.updated_at is not None
    assert retrieved.closed_at is None


def test_valid_incident_states(db_session, cleanup_tracker):
    """Test 9: Successfully transition through valid lifecycle states."""
    inc = create_mock_incident(db_session, cleanup_tracker, status="open")
    assert inc.status == "open"

    for st in ("investigating", "resolved", "closed"):
        inc.status = st
        db_session.commit()
        retrieved = db_session.get(Incident, inc.incident_id)
        assert retrieved.status == st


def test_invalid_lifecycle_state_rejected(db_session, cleanup_tracker):
    """Test 10: Rejects invalid lifecycle status values via CHECK constraint."""
    inc_id = uuid.uuid4()
    cleanup_tracker["incidents"].append(inc_id)

    incident = Incident(
        incident_id=inc_id,
        title="Invalid Status Test",
        incident_type="brute_force",
        source_ip="203.0.113.11",
        detection_method="rule",
        status="invalid_status",
    )
    db_session.add(incident)
    with pytest.raises(IntegrityError, match="ck_incidents_status_valid"):
        db_session.commit()
    db_session.rollback()


def test_nullable_severity(db_session, cleanup_tracker):
    """Test 11: Severity is nullable initially, accepts approved levels, and rejects arbitrary strings."""
    # 1. Null severity is permitted
    inc1 = create_mock_incident(db_session, cleanup_tracker, severity=None)
    assert inc1.severity is None

    # 2. Approved severity levels are permitted
    for sev in ("low", "medium", "high", "critical"):
        inc1.severity = sev
        db_session.commit()
        assert db_session.get(Incident, inc1.incident_id).severity == sev

    # 3. Invalid severity string is rejected
    inc1.severity = "ultra_severe"
    with pytest.raises(IntegrityError, match="ck_incidents_severity_valid"):
        db_session.commit()
    db_session.rollback()


def test_valid_detection_method(db_session, cleanup_tracker):
    """Test 12: Accepts detection methods 'rule', 'ml', and 'hybrid'."""
    for method in ("rule", "ml", "hybrid"):
        inc = create_mock_incident(db_session, cleanup_tracker, detection_method=method)
        assert inc.detection_method == method


def test_invalid_detection_method(db_session, cleanup_tracker):
    """Test 13: Rejects unknown detection method strings."""
    inc_id = uuid.uuid4()
    cleanup_tracker["incidents"].append(inc_id)

    incident = Incident(
        incident_id=inc_id,
        title="Invalid Method Test",
        incident_type="brute_force",
        source_ip="203.0.113.12",
        detection_method="deep_learning",
    )
    db_session.add(incident)
    with pytest.raises(IntegrityError, match="ck_incidents_detection_method_valid"):
        db_session.commit()
    db_session.rollback()


def test_timestamp_defaults(db_session, cleanup_tracker):
    """Test 14: Server automatically sets created_at and updated_at timestamps."""
    inc_id = uuid.uuid4()
    cleanup_tracker["incidents"].append(inc_id)

    incident = Incident(
        incident_id=inc_id,
        title="Timestamp Defaults Test",
        incident_type="brute_force",
        source_ip="203.0.113.13",
        detection_method="rule",
    )
    db_session.add(incident)
    db_session.commit()

    retrieved = db_session.get(Incident, inc_id)
    assert retrieved.created_at is not None
    assert retrieved.updated_at is not None
    assert retrieved.closed_at is None


# ---------------------------------------------------------------------------
# 15-18: INCIDENT EVENTS TESTS
# ---------------------------------------------------------------------------

def test_valid_ssh_event_association(db_session, cleanup_tracker):
    """Test 15: Successfully link an SSH event to an incident via IncidentEvent."""
    evt = create_mock_ssh_event(db_session, cleanup_tracker)
    inc = create_mock_incident(db_session, cleanup_tracker)

    assoc = IncidentEvent(incident_id=inc.incident_id, event_id=evt.event_id)
    cleanup_tracker["incident_events"].append((inc.incident_id, evt.event_id))
    db_session.add(assoc)
    db_session.commit()

    retrieved = db_session.get(IncidentEvent, (inc.incident_id, evt.event_id))
    assert retrieved is not None
    assert retrieved.linked_at is not None


def test_duplicate_association_rejection(db_session, cleanup_tracker):
    """Test 16: Primary key constraint rejects duplicate incident-event pairs."""
    evt = create_mock_ssh_event(db_session, cleanup_tracker)
    inc = create_mock_incident(db_session, cleanup_tracker)

    assoc1 = IncidentEvent(incident_id=inc.incident_id, event_id=evt.event_id)
    cleanup_tracker["incident_events"].append((inc.incident_id, evt.event_id))
    db_session.add(assoc1)
    db_session.commit()

    # Expunge first instance so SQLAlchemy identity map does not warn on duplicate insert attempt
    db_session.expunge(assoc1)

    # Attempt duplicate insert
    assoc2 = IncidentEvent(incident_id=inc.incident_id, event_id=evt.event_id)
    db_session.add(assoc2)
    with pytest.raises(IntegrityError, match="pk_incident_events"):
        db_session.commit()
    db_session.rollback()


def test_foreign_key_integrity(db_session, cleanup_tracker):
    """Test 17: Linking non-existent incident or event violates foreign-key constraint."""
    real_evt = create_mock_ssh_event(db_session, cleanup_tracker)
    fake_inc_id = uuid.uuid4()

    bad_assoc = IncidentEvent(incident_id=fake_inc_id, event_id=real_evt.event_id)
    db_session.add(bad_assoc)
    with pytest.raises(IntegrityError, match="fk_incident_events_incident_id_incidents"):
        db_session.commit()
    db_session.rollback()


def test_referential_integrity_after_attempted_deletion(db_session, cleanup_tracker):
    """Test 18: Attempted deletion of linked SSHEvent or Incident fails (RESTRICT)."""
    evt = create_mock_ssh_event(db_session, cleanup_tracker)
    inc = create_mock_incident(db_session, cleanup_tracker)

    assoc = IncidentEvent(incident_id=inc.incident_id, event_id=evt.event_id)
    cleanup_tracker["incident_events"].append((inc.incident_id, evt.event_id))
    db_session.add(assoc)
    db_session.commit()

    # 1. Attempting to delete the SSHEvent must fail due to ondelete=RESTRICT
    db_session.delete(evt)
    with pytest.raises(IntegrityError, match="fk_incident_events_event_id_ssh_events"):
        db_session.commit()
    db_session.rollback()

    # 2. Attempting to delete the Incident must fail due to ondelete=RESTRICT
    db_session.delete(inc)
    with pytest.raises(IntegrityError, match="fk_incident_events_incident_id_incidents"):
        db_session.commit()
    db_session.rollback()


# ---------------------------------------------------------------------------
# 19-22: DATABASE INTEGRATION TESTS
# ---------------------------------------------------------------------------

def test_incident_retrieval_with_associated_ssh_events(db_session, cleanup_tracker):
    """Test 19: Many-to-many relationship navigates from Incident to all associated SSHEvents."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    events = [create_mock_ssh_event(db_session, cleanup_tracker) for _ in range(3)]

    for evt in events:
        assoc = IncidentEvent(incident_id=inc.incident_id, event_id=evt.event_id)
        cleanup_tracker["incident_events"].append((inc.incident_id, evt.event_id))
        db_session.add(assoc)
    db_session.commit()

    # Clear identity map to verify clean SQL query
    db_session.expire_all()

    retrieved = db_session.get(Incident, inc.incident_id)
    assert len(retrieved.events) == 3
    event_ids = {e.event_id for e in retrieved.events}
    assert event_ids == {e.event_id for e in events}


def test_incident_retrieval_with_associated_detection_results(db_session, cleanup_tracker):
    """Test 20: One-to-many relationship navigates from Incident to associated DetectionResults."""
    inc = create_mock_incident(db_session, cleanup_tracker)
    t0 = datetime(2026, 11, 8, 13, 0, 0, tzinfo=timezone.utc)

    res1_id = uuid.uuid4()
    res2_id = uuid.uuid4()
    cleanup_tracker["detection_results"].extend([res1_id, res2_id])

    r1 = DetectionResult(
        result_id=res1_id,
        incident_id=inc.incident_id,
        source_ip="203.0.113.50",
        window_start=t0,
        window_end=t0 + timedelta(minutes=1),
        detector_type="rule",
        is_suspicious=True,
        triggered_rules=["R001"],
    )
    r2 = DetectionResult(
        result_id=res2_id,
        incident_id=inc.incident_id,
        source_ip="203.0.113.50",
        window_start=t0 + timedelta(minutes=1),
        window_end=t0 + timedelta(minutes=2),
        detector_type="isolation_forest",
        is_suspicious=True,
        normality_score=-0.22,
        calibrated_threshold=0.035,
    )
    db_session.add_all([r1, r2])
    db_session.commit()

    db_session.expire_all()

    retrieved = db_session.get(Incident, inc.incident_id)
    assert len(retrieved.detection_results) == 2
    res_ids = {r.result_id for r in retrieved.detection_results}
    assert res_ids == {res1_id, res2_id}


def test_database_migration_revision_verification(db_engine):
    """Test 21: Verify that database migration revision matches head and incorporates revision c6b1eef00aa0."""
    with db_engine.connect() as conn:
        current_rev = conn.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()

    alembic_cfg = Config("alembic.ini")
    script = ScriptDirectory.from_config(alembic_cfg)
    head_rev = script.get_current_head()

    assert current_rev is not None
    assert current_rev == head_rev
    history_revs = [rev.revision for rev in script.walk_revisions()]
    assert "c6b1eef00aa0" in history_revs


def test_existing_ssh_event_table_remains_unchanged(db_engine):
    """Test 22: Verify that existing ssh_events table schema, columns, and constraints remain intact."""
    insp = inspect(db_engine)
    assert "ssh_events" in insp.get_table_names()

    columns = {col["name"]: col for col in insp.get_columns("ssh_events")}
    expected_cols = {
        "event_id",
        "event_timestamp",
        "source_ip",
        "username",
        "authentication_result",
        "event_type",
        "ingested_at",
    }
    assert expected_cols == set(columns.keys())

    # Constraints intact
    cks = {ck["name"] for ck in insp.get_check_constraints("ssh_events")}
    assert "ck_ssh_events_auth_result" in cks
    assert "ck_ssh_events_username_not_empty" in cks

    # Indexes intact
    ixs = {ix["name"] for ix in insp.get_indexes("ssh_events")}
    assert "ix_ssh_events_event_timestamp" in ixs
    assert "ix_ssh_events_source_ip" in ixs
    assert "ix_ssh_events_source_ip_event_timestamp" in ixs

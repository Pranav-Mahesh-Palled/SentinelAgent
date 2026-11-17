"""Automated Integration Tests for Hybrid Detection Orchestrator (Task 6B).

Covers all 20 required verification tests:
1. Normal events produce no incidents.
2. Rule-only detection creates an incident.
3. ML-only detection creates an incident.
4. Both detectors triggering create one HYBRID incident.
5. Individual detection results are persisted separately.
6. Feature snapshots are preserved.
7. Normality scores are preserved correctly.
8. Existing model training is reused.
9. Missing or uncalibrated ML model fails safely.
10. Same source IP in the same correlation window reuses an incident.
11. Different source IPs create separate incidents.
12. Closed incidents are not reused.
13. Relevant SSH events are associated correctly.
14. Duplicate event associations are prevented.
15. Multiple detection results can link to one incident.
16. Transaction rollback on persistence failure.
17. Concurrent requests do not create duplicate incidents.
18. Severity remains NULL.
19. Incident lifecycle defaults are correct.
20. Database records can be retrieved with their evidence relationships.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db import connection
from app.models.detection_result import DetectionResult
from app.models.incident import Incident
from app.models.incident_event import IncidentEvent
from app.models.ssh_event import SSHEvent
from app.services.detection_orchestrator import (
    DetectionOrchestrator,
    DetectionOrchestratorConfig,
    DetectionOrchestratorConfigurationError,
    OrchestrationResult,
)
from app.services.isolation_forest_detector import (
    IsolationForestConfig,
    IsolationForestDetector,
    generate_synthetic_evaluation_datasets,
)
from app.services.rule_detector import RuleDetector, RuleDetectorConfig


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
        "incident_events": [],  # list of (incident_id, event_id)
        "detection_results": [],  # list of result_id
        "incidents": [],  # list of incident_id
        "ssh_events": [],  # list of event_id
        "source_ips": set(),  # set of source IPs used in test
    }
    yield tracker

    with db_engine.begin() as conn:
        from sqlalchemy import or_

        conds = []
        if tracker["incidents"]:
            conds.append(IncidentEvent.incident_id.in_(tracker["incidents"]))
        if tracker["ssh_events"]:
            conds.append(IncidentEvent.event_id.in_(tracker["ssh_events"]))
        if conds:
            conn.execute(delete(IncidentEvent).where(or_(*conds)))

        dr_conds = []
        if tracker["detection_results"]:
            dr_conds.append(DetectionResult.result_id.in_(tracker["detection_results"]))
        if tracker["source_ips"]:
            dr_conds.append(DetectionResult.source_ip.in_(list(tracker["source_ips"])))
        if dr_conds:
            conn.execute(delete(DetectionResult).where(or_(*dr_conds)))

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
def shared_ml_detector():
    """Pre-train and pre-calibrate an Isolation Forest detector for tests."""
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets()
    detector = IsolationForestDetector(config=IsolationForestConfig(random_state=42))
    detector.train(train_w)
    detector.calibrate(cal_w, target_fpr=0.05)
    return detector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def persist_test_events(
    session: Session,
    tracker: dict,
    *,
    count: int,
    auth_result: str,
    source_ip: str = "192.0.2.100",
    start_time: datetime = None,
    delta_seconds: float = 1.0,
    username: str = "victim_user",
) -> list[SSHEvent]:
    """Helper to generate, persist, and track real SSHEvents in PostgreSQL."""
    t0 = start_time or datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
    events: list[SSHEvent] = []
    if "source_ips" in tracker:
        tracker["source_ips"].add(source_ip)

    for i in range(count):
        eid = uuid.uuid4()
        tracker["ssh_events"].append(eid)
        ev = SSHEvent(
            event_id=eid,
            event_timestamp=t0 + timedelta(seconds=i * delta_seconds),
            source_ip=source_ip,
            username=f"{username}_{i % 3}",
            authentication_result=auth_result,
            event_type="password",
        )
        events.append(ev)

    session.add_all(events)
    session.commit()
    return events


def track_orchestration_outputs(tracker: dict, result: OrchestrationResult):
    """Register all generated incident and detection result IDs in cleanup tracker."""
    tracker["incidents"].extend(result.incidents_created)
    tracker["detection_results"].extend(result.detection_results_persisted)


# ---------------------------------------------------------------------------
# Tests 1-4: Core Detection Modalities (Normal, Rule-only, ML-only, Hybrid)
# ---------------------------------------------------------------------------

def test_normal_events_produce_no_incidents(db_session, cleanup_tracker, shared_ml_detector):
    """Test 1: Clean, normal login events produce detection results but ZERO incidents."""
    # 2 successful logins across 2 distinct 1-minute windows
    t0 = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
    events = persist_test_events(db_session, cleanup_tracker, count=1, auth_result="success", start_time=t0)
    events += persist_test_events(db_session, cleanup_tracker, count=1, auth_result="success", start_time=t0 + timedelta(minutes=1))

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    assert result.total_events_processed == 2
    assert result.total_windows_evaluated == 2
    assert len(result.incidents_created) == 0
    assert len(result.incidents_updated) == 0
    assert result.events_associated_count == 0

    # Verification: 4 detection result rows exist (2 rule, 2 ml), all non-suspicious with NULL incident_id
    assert len(result.detection_results_persisted) == 4
    for rid in result.detection_results_persisted:
        dr = db_session.get(DetectionResult, rid)
        assert dr.is_suspicious is False
        assert dr.incident_id is None


def test_rule_only_detection_creates_incident(db_session, cleanup_tracker, shared_ml_detector):
    """Test 2: Rule detector triggers while ML detector does not -> Incident created with method 'rule'."""
    # 15 failed logins in 1 minute triggers R001 (>10 failures).
    # Configure an ML detector with a very low calibrated threshold so ML does not trigger.
    train_w, cal_w, _, _, _ = generate_synthetic_evaluation_datasets()
    ml_tolerant = IsolationForestDetector(config=IsolationForestConfig(random_state=42))
    ml_tolerant.train(train_w)
    ml_tolerant.calibrate(cal_w, target_fpr=0.05)
    # Manually set a strict threshold lower than the failure score (~ -0.28)
    ml_tolerant._calibrated_threshold = -0.50

    t0 = datetime(2026, 11, 8, 14, 10, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.11",
        start_time=t0,
        delta_seconds=2.0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=ml_tolerant)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    assert len(result.incidents_created) == 1
    inc = db_session.get(Incident, result.incidents_created[0])
    assert inc.detection_method == "rule"
    assert str(inc.source_ip) == "198.51.100.11"
    assert "Brute Force" in inc.title


def test_ml_only_detection_creates_incident(db_session, cleanup_tracker, shared_ml_detector):
    """Test 3: ML detector triggers while Rule detector does not -> Incident created with method 'ml'."""
    # 7 failed logins in 1 minute:
    # - Rule detector: 7 <= 10 (R001 not met), no success (R002 not met) -> Rule is_suspicious = False
    # - ML detector: 7 failures is an anomaly compared to normal 1-login baseline -> ML is_anomaly = True
    t0 = datetime(2026, 11, 8, 14, 20, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=7,
        auth_result="failure",
        source_ip="198.51.100.12",
        start_time=t0,
        delta_seconds=3.0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    assert len(result.incidents_created) == 1
    inc = db_session.get(Incident, result.incidents_created[0])
    assert inc.detection_method == "ml"
    assert str(inc.source_ip) == "198.51.100.12"
    assert "Anomalous SSH Volume Activity" in inc.title


def test_both_detectors_triggering_create_one_hybrid_incident(db_session, cleanup_tracker, shared_ml_detector):
    """Test 4: Both detectors triggering in the same window create a single 'hybrid' incident."""
    # 40 failed logins in 1 minute triggers both R001 (>10) and ML anomaly
    t0 = datetime(2026, 11, 8, 14, 30, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=40,
        auth_result="failure",
        source_ip="198.51.100.13",
        start_time=t0,
        delta_seconds=1.0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    assert len(result.incidents_created) == 1
    inc = db_session.get(Incident, result.incidents_created[0])
    assert inc.detection_method == "hybrid"
    assert str(inc.source_ip) == "198.51.100.13"


# ---------------------------------------------------------------------------
# Tests 5-7: Detection Results Persistence & Scores
# ---------------------------------------------------------------------------

def test_individual_detection_results_persisted_separately(db_session, cleanup_tracker, shared_ml_detector):
    """Test 5: Distinct rows are persisted for 'rule' and 'isolation_forest' for each window."""
    t0 = datetime(2026, 11, 8, 14, 40, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=20,
        auth_result="failure",
        source_ip="198.51.100.14",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    assert len(result.detection_results_persisted) == 2
    r_types = {
        db_session.get(DetectionResult, rid).detector_type
        for rid in result.detection_results_persisted
    }
    assert r_types == {"rule", "isolation_forest"}


def test_feature_snapshots_preserved(db_session, cleanup_tracker, shared_ml_detector):
    """Test 6: DetectionResult.feature_snapshot contains the complete extracted feature map."""
    t0 = datetime(2026, 11, 8, 14, 50, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.15",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    for rid in result.detection_results_persisted:
        dr = db_session.get(DetectionResult, rid)
        snapshot = dr.feature_snapshot
        assert "total_attempts" in snapshot
        assert snapshot["total_attempts"] == 15
        assert snapshot["failed_login_count"] == 15
        assert "failure_ratio" in snapshot


def test_normality_scores_preserved_correctly(db_session, cleanup_tracker, shared_ml_detector):
    """Test 7: Isolation Forest row preserves continuous normality_score while Rule row is NULL."""
    t0 = datetime(2026, 11, 8, 15, 0, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=12,
        auth_result="failure",
        source_ip="198.51.100.16",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    result = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, result)

    for rid in result.detection_results_persisted:
        dr = db_session.get(DetectionResult, rid)
        if dr.detector_type == "isolation_forest":
            assert dr.normality_score is not None
            assert isinstance(dr.normality_score, float)
            assert dr.calibrated_threshold is not None
            assert dr.model_version == "isolation_forest_v1"
        elif dr.detector_type == "rule":
            assert dr.normality_score is None
            assert dr.calibrated_threshold is None
            assert dr.model_version is None


# ---------------------------------------------------------------------------
# Tests 8-9: Dependency Injection & Configuration Validation
# ---------------------------------------------------------------------------

def test_existing_model_training_reused(db_session, cleanup_tracker, shared_ml_detector):
    """Test 8: Injected ML model is strictly reused without in-flight retraining."""
    model_obj_id = id(shared_ml_detector._model)
    threshold = shared_ml_detector.calibrated_threshold

    t0 = datetime(2026, 11, 8, 15, 10, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=5,
        auth_result="success",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res)

    # Assert model instance was not re-fitted or re-instantiated
    assert id(shared_ml_detector._model) == model_obj_id
    assert shared_ml_detector.calibrated_threshold == threshold


def test_missing_or_uncalibrated_ml_model_fails_safely():
    """Test 9: Passing None, untrained, or uncalibrated detector raises clear configuration error."""
    # 1. None
    with pytest.raises(DetectionOrchestratorConfigurationError, match="cannot be None"):
        DetectionOrchestrator(ml_detector=None)

    # 2. Untrained
    untrained = IsolationForestDetector()
    with pytest.raises(DetectionOrchestratorConfigurationError, match="must be trained"):
        DetectionOrchestrator(ml_detector=untrained)

    # 3. Trained but uncalibrated
    train_w, _, _, _, _ = generate_synthetic_evaluation_datasets()
    trained_only = IsolationForestDetector()
    trained_only.train(train_w)
    with pytest.raises(DetectionOrchestratorConfigurationError, match="must be calibrated"):
        DetectionOrchestrator(ml_detector=trained_only)


# ---------------------------------------------------------------------------
# Tests 10-12: Incident Deduplication and Scope
# ---------------------------------------------------------------------------

def test_same_source_ip_in_same_correlation_window_reuses_incident(db_session, cleanup_tracker, shared_ml_detector):
    """Test 10: Suspicious events from same source IP within 5 minutes reuse the existing incident."""
    t0 = datetime(2026, 11, 8, 15, 20, 0, tzinfo=timezone.utc)
    ip = "198.51.100.20"

    # Batch 1: at 15:20
    ev1 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0)
    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res1 = orchestrator.process_events(db_session, ev1)
    track_orchestration_outputs(cleanup_tracker, res1)
    assert len(res1.incidents_created) == 1
    incident_id = res1.incidents_created[0]

    # Batch 2: at 15:22 (2 minutes later, within 5-min correlation window)
    ev2 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0 + timedelta(minutes=2))
    res2 = orchestrator.process_events(db_session, ev2)
    track_orchestration_outputs(cleanup_tracker, res2)

    assert len(res2.incidents_created) == 0
    assert len(res2.incidents_updated) == 1
    assert res2.incidents_updated[0] == incident_id

    # Verify updated_at advanced
    inc = db_session.get(Incident, incident_id)
    assert inc.updated_at >= t0 + timedelta(minutes=2)


def test_different_source_ips_create_separate_incidents(db_session, cleanup_tracker, shared_ml_detector):
    """Test 11: Suspicious events from distinct source IPs create completely distinct incidents."""
    t0 = datetime(2026, 11, 8, 15, 30, 0, tzinfo=timezone.utc)
    ev1 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip="198.51.100.21", start_time=t0)
    ev2 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip="198.51.100.22", start_time=t0)

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, ev1 + ev2)
    track_orchestration_outputs(cleanup_tracker, res)

    assert len(res.incidents_created) == 2
    ips = {str(db_session.get(Incident, iid).source_ip) for iid in res.incidents_created}
    assert ips == {"198.51.100.21", "198.51.100.22"}


def test_closed_incidents_are_not_reused(db_session, cleanup_tracker, shared_ml_detector):
    """Test 12: A closed incident is never reused; a new incident is created."""
    t0 = datetime(2026, 11, 8, 15, 40, 0, tzinfo=timezone.utc)
    ip = "198.51.100.23"

    ev1 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0)
    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res1 = orchestrator.process_events(db_session, ev1)
    track_orchestration_outputs(cleanup_tracker, res1)
    first_inc_id = res1.incidents_created[0]

    # Explicitly close the first incident
    inc1 = db_session.get(Incident, first_inc_id)
    inc1.status = "closed"
    db_session.commit()

    # Second batch 1 minute later
    ev2 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0 + timedelta(minutes=1))
    res2 = orchestrator.process_events(db_session, ev2)
    track_orchestration_outputs(cleanup_tracker, res2)

    assert len(res2.incidents_created) == 1
    second_inc_id = res2.incidents_created[0]
    assert second_inc_id != first_inc_id

    # Verify first incident remains closed
    assert db_session.get(Incident, first_inc_id).status == "closed"
    assert db_session.get(Incident, second_inc_id).status == "open"


# ---------------------------------------------------------------------------
# Tests 13-15: Event Linkage & Deduplication
# ---------------------------------------------------------------------------

def test_relevant_ssh_events_associated_correctly(db_session, cleanup_tracker, shared_ml_detector):
    """Test 13: SSHEvents supporting the suspicious window are linked via incident_events."""
    t0 = datetime(2026, 11, 8, 15, 50, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.24",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res)

    inc_id = res.incidents_created[0]
    linked_event_ids = {
        row.event_id for row in db_session.execute(
            select(IncidentEvent).where(IncidentEvent.incident_id == inc_id)
        ).scalars().all()
    }

    expected_ids = {e.event_id for e in events}
    assert linked_event_ids == expected_ids


def test_duplicate_event_associations_prevented(db_session, cleanup_tracker, shared_ml_detector):
    """Test 14: Processing overlapping/duplicate events avoids primary key collision in incident_events."""
    t0 = datetime(2026, 11, 8, 16, 0, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.25",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    # First pass
    res1 = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res1)

    # Second pass with exact same events
    res2 = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res2)

    # No exception was raised, and count remains 15
    inc_id = res1.incidents_created[0]
    total_links = db_session.scalar(
        select(func.count()).select_from(IncidentEvent).where(IncidentEvent.incident_id == inc_id)
    )
    assert total_links == 15


def test_multiple_detection_results_can_link_to_one_incident(db_session, cleanup_tracker, shared_ml_detector):
    """Test 15: When an incident correlates across multiple windows, all DetectionResults link to it."""
    t0 = datetime(2026, 11, 8, 16, 10, 0, tzinfo=timezone.utc)
    ip = "198.51.100.26"

    ev1 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0)
    ev2 = persist_test_events(db_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0 + timedelta(minutes=1))

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, ev1 + ev2)
    track_orchestration_outputs(cleanup_tracker, res)

    assert len(res.incidents_created) == 1
    inc_id = res.incidents_created[0]

    linked_drs = db_session.execute(
        select(DetectionResult).where(DetectionResult.incident_id == inc_id)
    ).scalars().all()

    # 2 windows * 2 detectors = 4 linked DetectionResult rows
    assert len(linked_drs) == 4


# ---------------------------------------------------------------------------
# Tests 16-20: Transactions, Concurrency, Defaults & Relationships
# ---------------------------------------------------------------------------

def test_transaction_rollback_on_persistence_failure(db_session, cleanup_tracker, shared_ml_detector):
    """Test 16: An unexpected error rolls back all operations, leaving no orphaned rows."""
    t0 = datetime(2026, 11, 8, 16, 20, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.27",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)

    # Corrupt session to force a database error during process_events
    orig_add = db_session.add

    def failing_add(obj):
        if isinstance(obj, DetectionResult):
            raise RuntimeError("Simulated database failure during DetectionResult insert")
        orig_add(obj)

    db_session.add = failing_add

    with pytest.raises(RuntimeError, match="Simulated database failure"):
        orchestrator.process_events(db_session, events, auto_commit=True)

    db_session.add = orig_add

    # Verify no incident or detection result was committed
    inc = db_session.execute(select(Incident).where(Incident.source_ip == "198.51.100.27")).scalar()
    assert inc is None


def test_concurrent_requests_do_not_create_duplicate_incidents(db_engine, cleanup_tracker, shared_ml_detector):
    """Test 17: Concurrent requests for same source IP serialize via SELECT FOR UPDATE, creating only 1 incident."""
    ip = "198.51.100.28"
    t0 = datetime(2026, 11, 8, 16, 30, 0, tzinfo=timezone.utc)

    # Pre-insert events with main connection
    SessionLocal = sessionmaker(bind=db_engine, expire_on_commit=False)
    setup_session = SessionLocal()
    events1 = persist_test_events(setup_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0)
    events2 = persist_test_events(setup_session, cleanup_tracker, count=15, auth_result="failure", source_ip=ip, start_time=t0 + timedelta(seconds=2))
    setup_session.close()

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)

    def run_process(ev_batch):
        sess = SessionLocal()
        try:
            res = orchestrator.process_events(sess, ev_batch, auto_commit=True)
            return res
        finally:
            sess.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_process, events1)
        f2 = executor.submit(run_process, events2)
        res1 = f1.result()
        res2 = f2.result()

    track_orchestration_outputs(cleanup_tracker, res1)
    track_orchestration_outputs(cleanup_tracker, res2)

    # Check total incidents for this IP in database
    verify_session = SessionLocal()
    incidents = verify_session.execute(select(Incident).where(Incident.source_ip == ip)).scalars().all()
    verify_session.close()

    assert len(incidents) == 1, f"Expected exactly 1 incident under concurrency, found {len(incidents)}"


def test_severity_remains_null(db_session, cleanup_tracker, shared_ml_detector):
    """Test 18: Incident severity is strictly initialized to None (NULL) per policy."""
    t0 = datetime(2026, 11, 8, 16, 40, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=25,
        auth_result="failure",
        source_ip="198.51.100.29",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res)

    inc = db_session.get(Incident, res.incidents_created[0])
    assert inc.severity is None


def test_incident_lifecycle_defaults_correct(db_session, cleanup_tracker, shared_ml_detector):
    """Test 19: Incident is initialized with standard default lifecycle states."""
    t0 = datetime(2026, 11, 8, 16, 50, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.30",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res)

    inc = db_session.get(Incident, res.incidents_created[0])
    assert inc.status == "open"
    assert inc.investigation_status == "pending"
    assert inc.response_status == "not_proposed"
    assert inc.verification_status == "not_started"
    assert inc.closed_at is None
    assert inc.created_at is not None
    assert inc.updated_at is not None


def test_database_records_retrievable_with_evidence_relationships(db_session, cleanup_tracker, shared_ml_detector):
    """Test 20: Full navigation from Incident to associated SSHEvents and DetectionResults."""
    t0 = datetime(2026, 11, 8, 17, 0, 0, tzinfo=timezone.utc)
    events = persist_test_events(
        db_session,
        cleanup_tracker,
        count=15,
        auth_result="failure",
        source_ip="198.51.100.31",
        start_time=t0,
    )

    orchestrator = DetectionOrchestrator(ml_detector=shared_ml_detector)
    res = orchestrator.process_events(db_session, events)
    track_orchestration_outputs(cleanup_tracker, res)

    inc_id = res.incidents_created[0]
    db_session.expire_all()

    retrieved = db_session.get(Incident, inc_id)
    assert retrieved is not None

    # Relationship: events (many-to-many)
    assert len(retrieved.events) == 15
    retrieved_eids = {e.event_id for e in retrieved.events}
    assert retrieved_eids == {e.event_id for e in events}

    # Relationship: detection_results (one-to-many)
    assert len(retrieved.detection_results) == 2
    detectors = {dr.detector_type for dr in retrieved.detection_results}
    assert detectors == {"rule", "isolation_forest"}

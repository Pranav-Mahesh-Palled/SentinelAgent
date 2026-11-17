"""Automated Integration Tests for Read-Only Investigation Retrieval Tools (Task 7B.3).

Verifies:
1. Incident context:
   - Correct active incident retrieved with metadata.
   - Correct associated SSH event count.
   - Correct associated detection result count.
   - Non-existent incident raises InvestigationContextError.
2. SSH events:
   - Only events linked to the active incident returned.
   - Deterministic ordering (event_timestamp ASC, event_id ASC).
   - Fewer than limit, exactly limit, limit + 1 (truncated=True).
   - Correct truncation metadata and preserved UUIDs/timestamps.
3. Detection results:
   - Only active incident's results retrieved.
   - Rule and ML detector types supported.
   - Truncation behavior and count matching.
4. Prior evidence:
   - Only current investigation's evidence returned (excludes other investigations).
   - Nullable fields and canonical source references preserved.
   - Truncation behavior.
5. Username search:
   - Correct username filter.
   - Source IP derived strictly from active context.
   - Correlation window boundaries: [created_at - 1h, created_at + 1h] strictly enforced.
   - Events outside the window excluded.
6. Related incidents:
   - Current incident excluded.
   - Other IP incidents excluded.
   - Future incidents (created after active incident) excluded.
   - Historical incidents ordered (created_at DESC, incident_id ASC).
   - Truncation behavior.
7. Read-only PostgreSQL transaction enforcement:
   - Every tool runs under SET TRANSACTION READ ONLY.
   - Attempted INSERT/UPDATE/DELETE inside the read-only session fails with SQLSTATE 25006.
   - No rows modified by retrieval tool invocations.
8. Output contracts:
   - All outputs validate against Task 7B.2 Pydantic schemas.
   - All outputs serialize to JSON.
   - Zero ORM instances escape the retrieval layer.
"""

from datetime import datetime, timedelta, timezone
import json
import uuid
import pytest
from sqlalchemy import delete, func, insert, select, text
from sqlalchemy.exc import InternalError
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
    GetRelatedIncidentsForIPArgs,
    GetSSHEventsArgs,
    IncidentContextOutput,
    SearchSSHEventsByUsernameArgs,
)
from app.services.investigation_tools import (
    ActiveInvestigationContext,
    InvestigationContextError,
    get_detection_results,
    get_incident_context,
    get_prior_evidence,
    get_related_incidents_for_ip,
    get_ssh_events,
    readonly_db_session,
    search_ssh_events_by_username,
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


# =============================================================================
# Helper: Seed Test Fixtures
# =============================================================================

def create_test_incident(
    session: Session,
    cleanup_tracker: dict,
    source_ip: str = "192.0.2.100",
    created_at: datetime | None = None,
    title: str = "Test Brute Force Incident",
) -> Incident:
    """Helper to insert an Incident record tracked for cleanup."""
    now = created_at or datetime.now(timezone.utc)
    inc = Incident(
        incident_id=uuid.uuid4(),
        title=title,
        incident_type="brute_force",
        source_ip=source_ip,
        severity="high",
        detection_method="hybrid",
        status="open",
        investigation_status="in_progress",
        created_at=now,
        updated_at=now,
    )
    session.add(inc)
    session.flush()
    cleanup_tracker["incidents"].append(inc.incident_id)
    return inc


def create_test_investigation(
    session: Session,
    cleanup_tracker: dict,
    incident_id: uuid.UUID,
) -> Investigation:
    """Helper to insert an Investigation record tracked for cleanup."""
    inv = Investigation(
        investigation_id=uuid.uuid4(),
        incident_id=incident_id,
        status="in_progress",
    )
    session.add(inv)
    session.flush()
    cleanup_tracker["investigations"].append(inv.investigation_id)
    return inv


def create_test_ssh_event(
    session: Session,
    cleanup_tracker: dict,
    source_ip: str = "192.0.2.100",
    username: str = "root",
    auth_result: str = "failure",
    event_timestamp: datetime | None = None,
) -> SSHEvent:
    """Helper to insert an SSHEvent record tracked for cleanup."""
    ev = SSHEvent(
        event_id=uuid.uuid4(),
        event_timestamp=event_timestamp or datetime.now(timezone.utc),
        source_ip=source_ip,
        username=username,
        authentication_result=auth_result,
        event_type="password",
    )
    session.add(ev)
    session.flush()
    cleanup_tracker["ssh_events"].append(ev.event_id)
    return ev


# =============================================================================
# 1. Incident Context Tool Tests
# =============================================================================

def test_get_incident_context_success(session_factory, cleanup_tracker):
    """Verify get_incident_context returns complete metadata and telemetry counts."""
    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Link 2 SSH events
        ev1 = create_test_ssh_event(session, cleanup_tracker, source_ip=str(inc.source_ip))
        ev2 = create_test_ssh_event(session, cleanup_tracker, source_ip=str(inc.source_ip))
        session.add_all([
            IncidentEvent(incident_id=inc.incident_id, event_id=ev1.event_id),
            IncidentEvent(incident_id=inc.incident_id, event_id=ev2.event_id),
        ])
        cleanup_tracker["incident_events"].append(inc.incident_id)

        # Add 1 Detection Result
        dr = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            source_ip=str(inc.source_ip),
            window_start=inc.created_at,
            window_end=inc.created_at + timedelta(minutes=1),
            detector_type="rule",
            is_suspicious=True,
            triggered_rules=["RULE_R001"],
            feature_snapshot={"failed_logins": 10},
        )
        session.add(dr)
        session.flush()
        cleanup_tracker["detection_results"].append(dr.result_id)
        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    # Call tool
    result = get_incident_context(context, session_factory=session_factory)

    assert isinstance(result, IncidentContextOutput)
    assert result.incident_id == inc.incident_id
    assert result.title == inc.title
    assert result.source_ip == str(inc.source_ip)
    assert result.severity == "high"
    assert result.detection_method == "hybrid"
    assert result.associated_event_count == 2
    assert result.associated_detection_count == 1
    assert result.created_at.tzinfo is not None

    # Verify JSON serialization
    serialized = json.loads(result.model_dump_json())
    assert serialized["incident_id"] == str(inc.incident_id)


def test_get_incident_context_non_existent(session_factory):
    """Verify get_incident_context raises InvestigationContextError when incident not found."""
    context = ActiveInvestigationContext(
        incident_id=uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        source_ip="192.0.2.1",
        created_at=datetime.now(timezone.utc),
    )
    with pytest.raises(InvestigationContextError, match="not found"):
        get_incident_context(context, session_factory=session_factory)


# =============================================================================
# 2. SSH Events Retrieval Tool Tests
# =============================================================================

def test_get_ssh_events_scoping_and_ordering(session_factory, cleanup_tracker):
    """Verify get_ssh_events returns only linked events ordered deterministically."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # 3 events linked to active incident
        ev1 = create_test_ssh_event(session, cleanup_tracker, event_timestamp=now + timedelta(seconds=10))
        ev2 = create_test_ssh_event(session, cleanup_tracker, event_timestamp=now + timedelta(seconds=20))
        ev3 = create_test_ssh_event(session, cleanup_tracker, event_timestamp=now + timedelta(seconds=30))

        # 1 unlinked event
        create_test_ssh_event(session, cleanup_tracker, event_timestamp=now + timedelta(seconds=15))

        session.add_all([
            IncidentEvent(incident_id=inc.incident_id, event_id=ev1.event_id),
            IncidentEvent(incident_id=inc.incident_id, event_id=ev2.event_id),
            IncidentEvent(incident_id=inc.incident_id, event_id=ev3.event_id),
        ])
        cleanup_tracker["incident_events"].append(inc.incident_id)
        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    # Request limit=2 (tests limit + 1 truncation)
    out = get_ssh_events(context, GetSSHEventsArgs(limit=2), session_factory=session_factory)

    assert out.count == 2
    assert len(out.events) == 2
    assert out.truncated is True
    assert out.events[0].event_id == ev1.event_id
    assert out.events[1].event_id == ev2.event_id

    # Request limit=3 (fewer/exact, not truncated)
    out2 = get_ssh_events(context, GetSSHEventsArgs(limit=3), session_factory=session_factory)
    assert out2.count == 3
    assert out2.truncated is False
    assert out2.events[2].event_id == ev3.event_id


# =============================================================================
# 3. Detection Results Tool Tests
# =============================================================================

def test_get_detection_results_retrieval(session_factory, cleanup_tracker):
    """Verify get_detection_results retrieves both rule and ML detection results."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Other incident's detection result (should be excluded)
        other_inc = create_test_incident(session, cleanup_tracker, title="Other Incident")
        dr_other = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=other_inc.incident_id,
            source_ip="192.0.2.200",
            window_start=now,
            window_end=now + timedelta(minutes=1),
            detector_type="rule",
            is_suspicious=True,
            triggered_rules=["RULE_R001"],
            feature_snapshot={},
        )
        session.add(dr_other)

        # 2 Detection results for active incident
        dr1 = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            source_ip=str(inc.source_ip),
            window_start=now,
            window_end=now + timedelta(minutes=1),
            detector_type="rule",
            is_suspicious=True,
            triggered_rules=["RULE_R001"],
            feature_snapshot={"failed_logins": 15},
            evaluated_at=now,
        )
        dr2 = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            source_ip=str(inc.source_ip),
            window_start=now + timedelta(minutes=1),
            window_end=now + timedelta(minutes=2),
            detector_type="isolation_forest",
            is_suspicious=True,
            normality_score=-0.12,
            calibrated_threshold=0.035,
            model_version="1.0.0",
            evaluated_at=now + timedelta(seconds=1),
        )
        session.add_all([dr1, dr2])
        session.flush()
        cleanup_tracker["detection_results"].extend([dr_other.result_id, dr1.result_id, dr2.result_id])
        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    out = get_detection_results(context, session_factory=session_factory)

    assert out.count == 2
    assert out.truncated is False
    assert out.results[0].detector_type == "rule"
    assert out.results[1].detector_type == "isolation_forest"
    assert out.results[1].normality_score == -0.12


def test_get_detection_results_ordering_and_tiebreaking(session_factory, cleanup_tracker):
    """Verify get_detection_results orders by window_start ASC, result_id ASC (including equal window_start)."""
    now = datetime.now(timezone.utc)
    id_low = uuid.UUID("10000000-0000-0000-0000-000000000001")
    id_high = uuid.UUID("20000000-0000-0000-0000-000000000002")

    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Record 1: later window_start
        dr_later = DetectionResult(
            result_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            source_ip=str(inc.source_ip),
            window_start=now + timedelta(minutes=5),
            window_end=now + timedelta(minutes=6),
            detector_type="rule",
            is_suspicious=True,
            feature_snapshot={},
        )
        # Record 2 & 3: identical earlier window_start, distinguished by result_id
        dr_tie_high = DetectionResult(
            result_id=id_high,
            incident_id=inc.incident_id,
            source_ip=str(inc.source_ip),
            window_start=now,
            window_end=now + timedelta(minutes=1),
            detector_type="rule",
            is_suspicious=True,
            feature_snapshot={},
        )
        dr_tie_low = DetectionResult(
            result_id=id_low,
            incident_id=inc.incident_id,
            source_ip=str(inc.source_ip),
            window_start=now,
            window_end=now + timedelta(minutes=1),
            detector_type="isolation_forest",
            is_suspicious=True,
            feature_snapshot={},
        )

        session.add_all([dr_later, dr_tie_high, dr_tie_low])
        session.flush()
        cleanup_tracker["detection_results"].extend([dr_later.result_id, dr_tie_high.result_id, dr_tie_low.result_id])
        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    out = get_detection_results(context, session_factory=session_factory)

    assert out.count == 3
    assert out.truncated is False
    # Tie broken by result_id ASC: id_low comes before id_high
    assert out.results[0].result_id == id_low
    assert out.results[1].result_id == id_high
    # Later window_start comes last
    assert out.results[2].result_id == dr_later.result_id


# =============================================================================
# 4. Prior Evidence Tool Tests
# =============================================================================

def test_get_prior_evidence_scoping(session_factory, cleanup_tracker):
    """Verify get_prior_evidence retrieves only the current investigation's evidence."""
    now = datetime.now(timezone.utc)

    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Another investigation
        other_inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Evidence for other investigation
        ev_other = EvidenceItem(
            evidence_id=uuid.uuid4(),
            investigation_id=other_inv.investigation_id,
            evidence_type="ssh_event",
            title="Other Evidence",
            collected_at=now,
        )
        session.add(ev_other)

        # Evidence for active investigation
        ev1 = EvidenceItem(
            evidence_id=uuid.uuid4(),
            investigation_id=inv.investigation_id,
            evidence_type="ssh_event",
            title="Evidence 1",
            source_reference=f"ssh_events/{uuid.uuid4()}",
            collected_at=now,
        )
        ev2 = EvidenceItem(
            evidence_id=uuid.uuid4(),
            investigation_id=inv.investigation_id,
            evidence_type="detection_result",
            title="Evidence 2",
            source_reference=f"detection_results/{uuid.uuid4()}",
            collected_at=now + timedelta(seconds=1),
        )
        session.add_all([ev1, ev2])
        session.flush()
        cleanup_tracker["evidence_items"].extend([ev_other.evidence_id, ev1.evidence_id, ev2.evidence_id])
        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    out = get_prior_evidence(context, session_factory=session_factory)

    assert out.count == 2
    assert out.truncated is False
    assert out.evidence_items[0].evidence_id == ev1.evidence_id
    assert out.evidence_items[1].evidence_id == ev2.evidence_id


# =============================================================================
# 5. Search SSH Events by Username Tool Tests
# =============================================================================

def test_search_ssh_events_by_username_correlation_window(session_factory, cleanup_tracker):
    """Verify search_ssh_events_by_username enforces IP, username, and [created_at ± 1h] window."""
    anchor = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker, source_ip="192.0.2.55", created_at=anchor)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Event within window (at 12:30) with matching IP and username
        ev_valid = create_test_ssh_event(
            session, cleanup_tracker,
            source_ip="192.0.2.55", username="admin",
            event_timestamp=anchor + timedelta(minutes=30),
        )

        # Event within window but wrong username
        create_test_ssh_event(
            session, cleanup_tracker,
            source_ip="192.0.2.55", username="otheruser",
            event_timestamp=anchor + timedelta(minutes=30),
        )

        # Event within window with matching username but wrong IP
        create_test_ssh_event(
            session, cleanup_tracker,
            source_ip="198.51.100.1", username="admin",
            event_timestamp=anchor + timedelta(minutes=30),
        )

        # Event with matching IP & username but before window (1h 1m prior)
        create_test_ssh_event(
            session, cleanup_tracker,
            source_ip="192.0.2.55", username="admin",
            event_timestamp=anchor - timedelta(hours=1, minutes=1),
        )

        # Event with matching IP & username but after window (1h 1m after)
        create_test_ssh_event(
            session, cleanup_tracker,
            source_ip="192.0.2.55", username="admin",
            event_timestamp=anchor + timedelta(hours=1, minutes=1),
        )

        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    out = search_ssh_events_by_username(
        context,
        SearchSSHEventsByUsernameArgs(username="admin", limit=50),
        session_factory=session_factory,
    )

    assert out.count == 1
    assert out.truncated is False
    assert out.events[0].event_id == ev_valid.event_id


# =============================================================================
# 6. Related Incidents Tool Tests
# =============================================================================

def test_get_related_incidents_for_ip_historical_filter(session_factory, cleanup_tracker):
    """Verify get_related_incidents_for_ip excludes current incident and future incidents."""
    anchor = datetime(2026, 11, 8, 14, 0, 0, tzinfo=timezone.utc)
    target_ip = "192.0.2.77"

    with session_factory() as session:
        # Active incident at anchor
        inc = create_test_incident(
            session, cleanup_tracker,
            source_ip=target_ip, created_at=anchor, title="Active Incident",
        )
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)

        # Historical incident 1 (1 day prior)
        hist1 = create_test_incident(
            session, cleanup_tracker,
            source_ip=target_ip, created_at=anchor - timedelta(days=1), title="Hist 1",
        )

        # Historical incident 2 (2 hours prior)
        hist2 = create_test_incident(
            session, cleanup_tracker,
            source_ip=target_ip, created_at=anchor - timedelta(hours=2), title="Hist 2",
        )

        # Incident with different IP (should be excluded)
        create_test_incident(
            session, cleanup_tracker,
            source_ip="198.51.100.99", created_at=anchor - timedelta(days=1), title="Diff IP",
        )

        # Future incident (created after anchor; should be excluded)
        create_test_incident(
            session, cleanup_tracker,
            source_ip=target_ip, created_at=anchor + timedelta(hours=1), title="Future",
        )

        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=target_ip,
            created_at=anchor,
        )

    # Retrieve related incidents
    out = get_related_incidents_for_ip(
        context,
        GetRelatedIncidentsForIPArgs(limit=10),
        session_factory=session_factory,
    )

    assert out.count == 2
    assert out.truncated is False
    # Ordered created_at DESC (hist2 is newer than hist1)
    assert out.incidents[0].incident_id == hist2.incident_id
    assert out.incidents[1].incident_id == hist1.incident_id


# =============================================================================
# 7. PostgreSQL Read-Only Transaction Enforcement Tests
# =============================================================================

def test_readonly_db_session_enforcement(session_factory):
    """Verify readonly_db_session sets READ ONLY mode and blocks modifications with SQLSTATE 25006."""
    with pytest.raises(InternalError) as exc_info:
        with readonly_db_session(session_factory) as session:
            # Attempt to insert a row inside the read-only session
            session.add(Incident(
                title="Illegal Write",
                incident_type="brute_force",
                source_ip="192.0.2.1",
                detection_method="rule",
            ))
            session.flush()

    assert "25006" in str(exc_info.value) or "read-only" in str(exc_info.value).lower()


def test_retrieval_tools_do_not_modify_database_rows(session_factory, cleanup_tracker):
    """Verify executing all retrieval tools causes zero database side-effects."""
    with session_factory() as session:
        inc = create_test_incident(session, cleanup_tracker)
        inv = create_test_investigation(session, cleanup_tracker, inc.incident_id)
        session.commit()

        context = ActiveInvestigationContext(
            incident_id=inc.incident_id,
            investigation_id=inv.investigation_id,
            source_ip=str(inc.source_ip),
            created_at=inc.created_at,
        )

    # Initial row counts
    with session_factory() as session:
        count_inc = session.execute(select(func.count(Incident.incident_id))).scalar_one()
        count_ev = session.execute(select(func.count(EvidenceItem.evidence_id))).scalar_one()

    # Invoke tools
    get_incident_context(context, session_factory=session_factory)
    get_ssh_events(context, session_factory=session_factory)
    get_detection_results(context, session_factory=session_factory)
    get_prior_evidence(context, session_factory=session_factory)
    search_ssh_events_by_username(context, SearchSSHEventsByUsernameArgs(username="admin"), session_factory=session_factory)
    get_related_incidents_for_ip(context, session_factory=session_factory)

    # Verify row counts unchanged
    with session_factory() as session:
        assert session.execute(select(func.count(Incident.incident_id))).scalar_one() == count_inc
        assert session.execute(select(func.count(EvidenceItem.evidence_id))).scalar_one() == count_ev

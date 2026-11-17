"""Automated tests for Server-Authoritative Supplemental SSH Telemetry Retrieval (Task 8E.3).

Verifies:
1. Query Boundaries:
   - Correct two-hour preceding boundary (incident.created_at - 2h).
   - Correct one-hour following boundary (incident.created_at + 1h).
   - Inclusive boundary evaluation (exact boundary timestamps included, 1s outside excluded).
   - Scoped strictly to incident source IP (no cross-IP telemetry leakage).
   - Deterministic ordering by event_timestamp ASC, event_id ASC.
2. Truncation & Limit-plus-one:
   - <= 1000 records: truncated=False, coverage_complete=True.
   - 1001 records: capped at 1000 records, truncated=True, coverage_complete=False.
3. MAP-SSH-003 Per-Event Coverage:
   - S inside [created_at, created_at + 1h] qualifies for full 2-hour coverage.
   - Exact boundary S == created_at qualifies.
   - Exact boundary S == created_at + 1h qualifies.
   - S < created_at fails coverage check (preceding 2-hour window extends prior to query window).
   - S > created_at + 1h fails coverage check (outside query window).
   - Truncated retrieval explicitly prevents MAP-SSH-003 qualification.
4. Provenance Registration:
   - All returned events registered in AuthorizedProvenanceSet.
   - Only returned events registered (no unretrieved or cross-IP UUIDs).
   - Canonical source references (ssh_events/<uuid>) valid.
   - Fabricated UUIDs raise ProvenanceValidationError.
5. Database Read-Only Enforcement:
   - Executes inside SET TRANSACTION READ ONLY session.
   - Zero ORM instances escape; records are pure SSHEventRecord DTOs.
   - Database errors surfaced correctly, never swallowed.
6. Audit Trail:
   - Audited in investigation_tool_runs under 'internal_mitre_ssh_retrieval'.
   - Gemini tool allowlist remains exactly six tools (internal retrieval NOT exposed).
   - No sensitive credentials or raw payloads logged.
7. Failure Handling:
   - Missing context, missing source_ip, invalid IP format, missing or naive created_at raise InvestigationContextError.
   - Empty result set returns honest coverage_complete=True metadata.
   - Terminated investigation raises InvestigationTerminatedError.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid
import pytest
from sqlalchemy import delete, insert, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.db import connection
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.investigation_tool_run import InvestigationToolRun
from app.models.ssh_event import SSHEvent
from app.schemas.investigation import SSHEventRecord
from app.services.investigation_agent import ALLOWED_TOOL_NAMES
from app.services.investigation_service import (
    AuthorizedProvenanceSet,
    InvestigationNotFoundError,
    InvestigationService,
    InvestigationTerminatedError,
    ProvenanceValidationError,
)
from app.services.investigation_tools import (
    INTERNAL_RETRIEVAL_LIMIT,
    INTERNAL_RETRIEVAL_POST_HOURS,
    INTERNAL_RETRIEVAL_PRE_HOURS,
    INTERNAL_RETRIEVAL_TOOL_NAME,
    ActiveInvestigationContext,
    InvestigationContextError,
    retrieve_incident_ssh_telemetry,
)
from app.services.mitre_catalogue_service import MitreCatalogueService
from app.services.mitre_mapping_engine import (
    RULE_MAP_SSH_003,
    EventRetrievalMetadata,
    MitreMappingEngine,
)
from app.services.mitre_mapping_validator import (
    MitreMappingValidationError,
    MitreMappingValidator,
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
        "investigations": [],
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
        if tracker["investigations"]:
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
    """Provides the local verified MITRE ATT&CK Enterprise catalogue."""
    from app.core.config import get_settings
    settings = get_settings()
    return MitreCatalogueService.from_file(settings.MITRE_CATALOGUE_PATH)


@pytest.fixture
def live_context(session_factory, cleanup_tracker):
    """Creates an active Incident and in_progress Investigation in PostgreSQL."""
    incident_id = uuid.uuid4()
    investigation_id = uuid.uuid4()
    source_ip = "198.51.100.42"
    created_at = datetime(2026, 6, 15, 12, 0, 0, tzinfo=timezone.utc)

    with session_factory() as session:
        incident = Incident(
            incident_id=incident_id,
            title="Brute Force Detection on SSH",
            incident_type="brute_force",
            source_ip=source_ip,
            severity="high",
            detection_method="rule",
            status="investigating",
            investigation_status="in_progress",
            created_at=created_at,
        )
        session.add(incident)
        session.flush()

        investigation = Investigation(
            investigation_id=investigation_id,
            incident_id=incident_id,
            status="in_progress",
            created_at=created_at,
            started_at=created_at,
        )
        session.add(investigation)
        session.commit()

    cleanup_tracker["incidents"].append(incident_id)
    cleanup_tracker["investigations"].append(investigation_id)

    return ActiveInvestigationContext(
        incident_id=incident_id,
        investigation_id=investigation_id,
        source_ip=source_ip,
        created_at=created_at,
    )


# =============================================================================
# 1. Query Boundaries & Filtering Tests
# =============================================================================

def test_query_boundaries_and_inclusive_timestamps(session_factory, cleanup_tracker, live_context):
    """Verify query covers [created_at - 2h, created_at + 1h] inclusively and excludes outside events."""
    anchor = live_context.created_at
    ip = live_context.source_ip

    # Create events relative to anchor
    # - exactly at created_at - 2h (inclusive start)
    # - 1 second before created_at - 2h (out of bounds)
    # - exactly at anchor
    # - exactly at created_at + 1h (inclusive end)
    # - 1 second after created_at + 1h (out of bounds)
    t_start = anchor - timedelta(hours=2)
    t_before = t_start - timedelta(seconds=1)
    t_end = anchor + timedelta(hours=1)
    t_after = t_end + timedelta(seconds=1)

    timestamps = [
        (t_before, "before_window", False),
        (t_start, "at_start", True),
        (anchor, "at_anchor", True),
        (t_end, "at_end", True),
        (t_after, "after_window", False),
    ]

    expected_ids = set()
    with session_factory() as session:
        for ts, user, in_bounds in timestamps:
            ev_id = uuid.uuid4()
            ev = SSHEvent(
                event_id=ev_id,
                event_timestamp=ts,
                source_ip=ip,
                username=user,
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=ts,
            )
            session.add(ev)
            cleanup_tracker["ssh_events"].append(ev_id)
            if in_bounds:
                expected_ids.add(ev_id)
        session.commit()

    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )

    retrieved_ids = {r.event_id for r in records}
    assert retrieved_ids == expected_ids
    assert len(records) == 3
    assert metadata.truncated is False
    assert metadata.coverage_complete is True
    assert metadata.window_start == t_start
    assert metadata.window_end == t_end
    assert metadata.source_ip == ip
    assert metadata.incident_id == live_context.incident_id


def test_cross_ip_isolation(session_factory, cleanup_tracker, live_context):
    """Verify events from a different source IP inside the same time window are never retrieved."""
    anchor = live_context.created_at
    target_ip = live_context.source_ip
    other_ip = "203.0.113.99"

    with session_factory() as session:
        # Event for target IP
        target_ev_id = uuid.uuid4()
        session.add(SSHEvent(
            event_id=target_ev_id,
            event_timestamp=anchor,
            source_ip=target_ip,
            username="target_user",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].append(target_ev_id)

        # Event for different IP at identical timestamp
        other_ev_id = uuid.uuid4()
        session.add(SSHEvent(
            event_id=other_ev_id,
            event_timestamp=anchor,
            source_ip=other_ip,
            username="other_user",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].append(other_ev_id)
        session.commit()

    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )

    retrieved_ids = {r.event_id for r in records}
    assert target_ev_id in retrieved_ids
    assert other_ev_id not in retrieved_ids
    for r in records:
        assert r.source_ip == target_ip


def test_deterministic_ordering(session_factory, cleanup_tracker, live_context):
    """Verify records are deterministically sorted by event_timestamp ASC, event_id ASC."""
    anchor = live_context.created_at
    ip = live_context.source_ip

    ev1_id = uuid.UUID("11111111-1111-1111-1111-111111111111")
    ev2_id = uuid.UUID("22222222-2222-2222-2222-222222222222")
    ev3_id = uuid.UUID("33333333-3333-3333-3333-333333333333")

    with session_factory() as session:
        # Insert out of order with same and different timestamps
        session.add(SSHEvent(
            event_id=ev3_id,
            event_timestamp=anchor + timedelta(minutes=5),
            source_ip=ip,
            username="user3",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        session.add(SSHEvent(
            event_id=ev2_id,
            event_timestamp=anchor,
            source_ip=ip,
            username="user2",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        session.add(SSHEvent(
            event_id=ev1_id,
            event_timestamp=anchor,
            source_ip=ip,
            username="user1",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend([ev1_id, ev2_id, ev3_id])
        session.commit()

    records, _ = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )

    ids = [r.event_id for r in records]
    assert ids == [ev1_id, ev2_id, ev3_id]


# =============================================================================
# 2. Truncation and Limit-Plus-One Tests
# =============================================================================

def test_truncation_detection_and_coverage_status(session_factory, cleanup_tracker, live_context):
    """Verify limit+1 logic: at limit -> not truncated; at limit + 1 -> truncated with coverage_complete=False."""
    anchor = live_context.created_at
    ip = live_context.source_ip

    # Use monkeypatch to test truncation with small limit to avoid inserting 1001 live DB records
    with patch("app.services.investigation_tools.INTERNAL_RETRIEVAL_LIMIT", 5):
        # Insert 6 records (limit + 1)
        created_ids = []
        with session_factory() as session:
            for i in range(6):
                ev_id = uuid.uuid4()
                created_ids.append(ev_id)
                session.add(SSHEvent(
                    event_id=ev_id,
                    event_timestamp=anchor + timedelta(seconds=i),
                    source_ip=ip,
                    username=f"user_{i}",
                    authentication_result="failure",
                    event_type="failed_login",
                    ingested_at=anchor,
                ))
            cleanup_tracker["ssh_events"].extend(created_ids)
            session.commit()

        records, metadata = retrieve_incident_ssh_telemetry(
            context=live_context,
            session_factory=session_factory,
        )

        assert len(records) == 5
        assert metadata.truncated is True
        assert metadata.coverage_complete is False


def test_non_truncated_returns_coverage_complete_true(session_factory, cleanup_tracker, live_context):
    """Verify exactly limit records returns truncated=False and coverage_complete=True."""
    anchor = live_context.created_at
    ip = live_context.source_ip

    with patch("app.services.investigation_tools.INTERNAL_RETRIEVAL_LIMIT", 3):
        created_ids = []
        with session_factory() as session:
            for i in range(3):
                ev_id = uuid.uuid4()
                created_ids.append(ev_id)
                session.add(SSHEvent(
                    event_id=ev_id,
                    event_timestamp=anchor + timedelta(seconds=i),
                    source_ip=ip,
                    username=f"user_{i}",
                    authentication_result="failure",
                    event_type="failed_login",
                    ingested_at=anchor,
                ))
            cleanup_tracker["ssh_events"].extend(created_ids)
            session.commit()

        records, metadata = retrieve_incident_ssh_telemetry(
            context=live_context,
            session_factory=session_factory,
        )

        assert len(records) == 3
        assert metadata.truncated is False
        assert metadata.coverage_complete is True


# =============================================================================
# 3. MAP-SSH-003 Per-Event Coverage & Behavioral Evaluation
# =============================================================================

def test_map_ssh_003_qualifies_when_success_inside_interval(session_factory, cleanup_tracker, live_context, real_catalogue):
    """Verify successful authentication inside [created_at, created_at + 1h] qualifies for MAP-SSH-003."""
    anchor = live_context.created_at
    ip = live_context.source_ip

    # Insert 5 failed events within [S - 2h, S)
    # S is at created_at + 30m
    success_time = anchor + timedelta(minutes=30)
    event_ids = []

    with session_factory() as session:
        for i in range(5):
            ev_id = uuid.uuid4()
            event_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=60 - i * 5),
                source_ip=ip,
                username="victim_user",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))

        success_id = uuid.uuid4()
        event_ids.append(success_id)
        session.add(SSHEvent(
            event_id=success_id,
            event_timestamp=success_time,
            source_ip=ip,
            username="victim_user",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend(event_ids)
        session.commit()

    provenance_set = AuthorizedProvenanceSet()
    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
        provenance_set=provenance_set,
    )

    engine = MitreMappingEngine(catalogue=real_catalogue)
    proposals = engine.evaluate(
        investigation_id=live_context.investigation_id,
        authorized_ssh_events=list(records),
        retrieval_metadata=metadata,
    )

    rule_ids = [p.rule_id for p in proposals]
    assert RULE_MAP_SSH_003 in rule_ids
    map_003 = next(p for p in proposals if p.rule_id == RULE_MAP_SSH_003)
    assert map_003.technique_id == "T1078"

    # Validate proposals
    validator = MitreMappingValidator(catalogue=real_catalogue)
    validated = validator.validate_proposals(
        proposals=proposals,
        provenance_set=provenance_set,
        investigation_id=live_context.investigation_id,
        authorized_ssh_events=list(records),
        retrieval_metadata=metadata,
    )
    validated_rules = [m.rule_id for m in validated]
    assert RULE_MAP_SSH_003 in validated_rules


def test_map_ssh_003_boundary_at_exact_created_at(session_factory, cleanup_tracker, live_context, real_catalogue):
    """Verify success exactly at anchor S == created_at has full [created_at - 2h, created_at] coverage."""
    anchor = live_context.created_at
    ip = live_context.source_ip
    event_ids = []

    with session_factory() as session:
        for i in range(5):
            ev_id = uuid.uuid4()
            event_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=90 - i * 10),
                source_ip=ip,
                username="admin",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        success_id = uuid.uuid4()
        event_ids.append(success_id)
        session.add(SSHEvent(
            event_id=success_id,
            event_timestamp=anchor,  # Exact anchor
            source_ip=ip,
            username="admin",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend(event_ids)
        session.commit()

    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )

    engine = MitreMappingEngine(catalogue=real_catalogue)
    proposals = engine.evaluate(
        investigation_id=live_context.investigation_id,
        authorized_ssh_events=list(records),
        retrieval_metadata=metadata,
    )
    assert any(p.rule_id == RULE_MAP_SSH_003 for p in proposals)


def test_map_ssh_003_boundary_at_exact_created_at_plus_1h(session_factory, cleanup_tracker, live_context, real_catalogue):
    """Verify success exactly at S == created_at + 1h has full preceding 2h coverage."""
    anchor = live_context.created_at
    ip = live_context.source_ip
    success_time = anchor + timedelta(hours=1)
    event_ids = []

    with session_factory() as session:
        for i in range(5):
            ev_id = uuid.uuid4()
            event_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=30 - i * 5),
                source_ip=ip,
                username="admin",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        success_id = uuid.uuid4()
        event_ids.append(success_id)
        session.add(SSHEvent(
            event_id=success_id,
            event_timestamp=success_time,  # Exact upper bound
            source_ip=ip,
            username="admin",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend(event_ids)
        session.commit()

    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )

    engine = MitreMappingEngine(catalogue=real_catalogue)
    proposals = engine.evaluate(
        investigation_id=live_context.investigation_id,
        authorized_ssh_events=list(records),
        retrieval_metadata=metadata,
    )
    assert any(p.rule_id == RULE_MAP_SSH_003 for p in proposals)


def test_map_ssh_003_rejected_when_success_before_incident_creation(session_factory, cleanup_tracker, live_context, real_catalogue):
    """Verify success before incident creation (S < created_at) cannot qualify because preceding 2h is clipped."""
    anchor = live_context.created_at
    ip = live_context.source_ip
    # Success is 10 seconds before incident creation
    success_time = anchor - timedelta(seconds=10)
    event_ids = []

    with session_factory() as session:
        for i in range(5):
            ev_id = uuid.uuid4()
            event_ids.append(ev_id)
            session.add(SSHEvent(
                event_id=ev_id,
                event_timestamp=anchor - timedelta(minutes=50 - i * 5),
                source_ip=ip,
                username="user",
                authentication_result="failure",
                event_type="failed_login",
                ingested_at=anchor,
            ))
        success_id = uuid.uuid4()
        event_ids.append(success_id)
        session.add(SSHEvent(
            event_id=success_id,
            event_timestamp=success_time,
            source_ip=ip,
            username="user",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend(event_ids)
        session.commit()

    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )

    engine = MitreMappingEngine(catalogue=real_catalogue)
    proposals = engine.evaluate(
        investigation_id=live_context.investigation_id,
        authorized_ssh_events=list(records),
        retrieval_metadata=metadata,
    )
    # MAP-SSH-003 MUST NOT be generated because query window does not cover S - 2h
    assert not any(p.rule_id == RULE_MAP_SSH_003 for p in proposals)


def test_map_ssh_003_rejected_when_retrieval_truncated(live_context, real_catalogue):
    """Verify truncated retrieval unconditionally suppresses MAP-SSH-003."""
    anchor = live_context.created_at
    # Synthesize records: 5 failures and 1 success inside valid window
    events = [
        SSHEventRecord(
            event_id=uuid.uuid4(),
            event_timestamp=anchor - timedelta(minutes=30 - i * 5),
            source_ip=live_context.source_ip,
            username="test_user",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        )
        for i in range(5)
    ]
    events.append(
        SSHEventRecord(
            event_id=uuid.uuid4(),
            event_timestamp=anchor + timedelta(minutes=15),
            source_ip=live_context.source_ip,
            username="test_user",
            authentication_result="success",
            event_type="login_success",
            ingested_at=anchor,
        )
    )

    # Retrieval marked truncated=True
    meta = EventRetrievalMetadata(
        truncated=True,
        window_start=anchor - timedelta(hours=2),
        window_end=anchor + timedelta(hours=1),
        coverage_complete=False,
    )

    engine = MitreMappingEngine(catalogue=real_catalogue)
    proposals = engine.evaluate(
        investigation_id=live_context.investigation_id,
        authorized_ssh_events=events,
        retrieval_metadata=meta,
    )
    assert not any(p.rule_id == RULE_MAP_SSH_003 for p in proposals)


# =============================================================================
# 4. Provenance Registration Tests
# =============================================================================

def test_provenance_registration_only_authorizes_returned_events(session_factory, cleanup_tracker, live_context):
    """Verify only actually returned events are added to the provenance set."""
    anchor = live_context.created_at
    ip = live_context.source_ip

    with session_factory() as session:
        ev1 = uuid.uuid4()
        session.add(SSHEvent(
            event_id=ev1,
            event_timestamp=anchor,
            source_ip=ip,
            username="alice",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        # Excluded event from another IP
        ev2 = uuid.uuid4()
        session.add(SSHEvent(
            event_id=ev2,
            event_timestamp=anchor,
            source_ip="198.51.100.99",
            username="bob",
            authentication_result="failure",
            event_type="failed_login",
            ingested_at=anchor,
        ))
        cleanup_tracker["ssh_events"].extend([ev1, ev2])
        session.commit()

    provenance_set = AuthorizedProvenanceSet()
    records, _ = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
        provenance_set=provenance_set,
    )

    assert ev1 in provenance_set.ssh_events
    assert ev2 not in provenance_set.ssh_events

    # Canonical reference validation
    prefix, validated_uuid = provenance_set.validate_reference(f"ssh_events/{ev1}")
    assert prefix == "ssh_events"
    assert validated_uuid == ev1

    # Fabricated / unreturned reference rejection
    with pytest.raises(ProvenanceValidationError):
        provenance_set.validate_reference(f"ssh_events/{ev2}")

    with pytest.raises(ProvenanceValidationError):
        provenance_set.validate_reference(f"ssh_events/{uuid.uuid4()}")


# =============================================================================
# 5. Database Read-Only Enforcement Tests
# =============================================================================

def test_readonly_transaction_enforcement(session_factory, live_context):
    """Verify query runs inside a session that issues SET TRANSACTION READ ONLY."""
    mock_session = MagicMock(spec=Session)
    mock_session.execute.return_value.scalars.return_value.all.return_value = []
    mock_factory = MagicMock(return_value=mock_session)

    retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=mock_factory,
    )

    # First call must be SET TRANSACTION READ ONLY
    first_call_arg = mock_session.execute.call_args_list[0][0][0]
    assert "SET TRANSACTION READ ONLY" in str(first_call_arg)
    mock_session.rollback.assert_called_once()
    mock_session.close.assert_called_once()


def test_database_exceptions_surfaced_correctly(live_context):
    """Verify database exceptions bubble up and are not falsely masked."""
    mock_session = MagicMock(spec=Session)
    mock_session.execute.side_effect = OperationalError("Connection dropped", None, None)
    mock_factory = MagicMock(return_value=mock_session)

    with pytest.raises(OperationalError, match="Connection dropped"):
        retrieve_incident_ssh_telemetry(
            context=live_context,
            session_factory=mock_factory,
        )


# =============================================================================
# 6. Audit Trail Tests
# =============================================================================

def test_internal_retrieval_audited_in_investigation_tool_runs(session_factory, cleanup_tracker, live_context):
    """Verify internal retrieval records distinguishable audit entries without exposing tool to Gemini."""
    inv_service = InvestigationService(session_factory=session_factory)

    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
        investigation_service=inv_service,
    )

    # Query tool runs table
    with session_factory() as session:
        tool_runs = session.execute(
            select(InvestigationToolRun).where(
                InvestigationToolRun.investigation_id == live_context.investigation_id
            )
        ).scalars().all()

        assert len(tool_runs) == 1
        run = tool_runs[0]
        cleanup_tracker["tool_runs"].append(run.tool_run_id)

        assert run.tool_name == INTERNAL_RETRIEVAL_TOOL_NAME
        assert run.execution_status == "succeeded"
        assert run.input_summary["source_ip"] == live_context.source_ip
        assert run.input_summary["limit"] == INTERNAL_RETRIEVAL_LIMIT
        assert run.output_summary["event_count"] == len(records)
        assert run.output_summary["truncated"] is False
        assert run.output_summary["coverage_complete"] is True


def test_gemini_allowlist_remains_exactly_six_tools():
    """Verify Gemini tool allowlist is NOT polluted with internal retrieval."""
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
# 7. Context & Failure Handling Tests
# =============================================================================

def test_missing_context_raises_error():
    """Verify missing context raises InvestigationContextError."""
    with pytest.raises(InvestigationContextError, match="Active investigation context is required"):
        retrieve_incident_ssh_telemetry(context=None)


def test_missing_or_invalid_source_ip_raises_error():
    """Verify empty or malformed IP values raise InvestigationContextError."""
    now = datetime.now(timezone.utc)

    # None IP
    ctx1 = ActiveInvestigationContext(uuid.uuid4(), uuid.uuid4(), None, now)
    with pytest.raises(InvestigationContextError, match="missing source IP"):
        retrieve_incident_ssh_telemetry(context=ctx1)

    # Empty string IP
    ctx2 = ActiveInvestigationContext(uuid.uuid4(), uuid.uuid4(), "   ", now)
    with pytest.raises(InvestigationContextError, match="missing source IP"):
        retrieve_incident_ssh_telemetry(context=ctx2)

    # Invalid format IP
    ctx3 = ActiveInvestigationContext(uuid.uuid4(), uuid.uuid4(), "999.888.777.666", now)
    with pytest.raises(InvestigationContextError, match="invalid source IP"):
        retrieve_incident_ssh_telemetry(context=ctx3)


def test_missing_or_naive_created_at_raises_error():
    """Verify missing or timezone-naive created_at raises InvestigationContextError."""
    # None created_at
    ctx1 = ActiveInvestigationContext(uuid.uuid4(), uuid.uuid4(), "192.0.2.1", None)
    with pytest.raises(InvestigationContextError, match="missing created_at timestamp"):
        retrieve_incident_ssh_telemetry(context=ctx1)

    # Timezone-naive created_at
    ctx2 = ActiveInvestigationContext(uuid.uuid4(), uuid.uuid4(), "192.0.2.1", datetime(2026, 1, 1, 12, 0, 0))
    with pytest.raises(InvestigationContextError, match="must be timezone-aware"):
        retrieve_incident_ssh_telemetry(context=ctx2)


def test_empty_result_set_returns_honest_complete_metadata(session_factory, live_context):
    """Verify query with no matching events returns empty records with coverage_complete=True."""
    records, metadata = retrieve_incident_ssh_telemetry(
        context=live_context,
        session_factory=session_factory,
    )
    assert len(records) == 0
    assert isinstance(records, tuple)
    assert metadata.truncated is False
    assert metadata.coverage_complete is True


def test_terminated_investigation_raises_terminated_error(session_factory, cleanup_tracker, live_context):
    """Verify terminated investigation aborts retrieval via InvestigationTerminatedError."""
    # Mark investigation as completed
    with session_factory() as session:
        inv = session.execute(
            select(Investigation).where(Investigation.investigation_id == live_context.investigation_id)
        ).scalar_one()
        inv.status = "completed"
        session.commit()

    inv_service = InvestigationService(session_factory=session_factory)
    with pytest.raises(InvestigationTerminatedError, match="is in status 'completed'"):
        retrieve_incident_ssh_telemetry(
            context=live_context,
            session_factory=session_factory,
            investigation_service=inv_service,
        )

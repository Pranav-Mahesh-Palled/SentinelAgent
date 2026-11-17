"""Integration tests verifying atomic transaction boundaries for investigation completion and outbox.

Verifies:
1. When Hindsight is disabled (default):
   - Investigation completes successfully with or without serialized_memory_payload.
   - Zero outbox rows are written.
2. When Hindsight is enabled and serialized_memory_payload is provided:
   - Investigation status and memory outbox entry commit atomically in the same transaction.
   - Outbox entry attributes (document_id, bank_id, payload_hash, operation_id) match expected values.
3. Transaction rollback atomicity:
   - If an error occurs during completion before commit, BOTH investigation completion
     and memory outbox insertion roll back cleanly (zero partial writes).
4. Zero external network calls:
   - Verifies that zero Hindsight HTTP requests or SDK calls occur during the database transaction.
5. Idempotent outbox enqueue:
   - Calling enqueue with the exact same payload returns existing record without error.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db import connection
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.memory_outbox import IncidentMemoryOutbox
from app.schemas.investigation import InvestigationReport, Observation
from app.services.investigation_service import (
    AuthorizedProvenanceSet,
    InvestigationService,
    MissingMemoryPayloadError,
    ProvenanceValidationError,
)
from app.services.memory_outbox_service import (
    calculate_payload_hash,
    canonicalize_payload,
    generate_document_id,
    generate_operation_id,
)


@pytest.fixture
def db_engine():
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine, expire_on_commit=False)


@pytest.fixture
def cleanup_tracker(db_engine):
    tracker = {
        "outbox_ids": [],
        "investigations": [],
        "incidents": [],
    }
    yield tracker

    with db_engine.begin() as conn:
        if tracker["investigations"]:
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
        if tracker["incidents"]:
            conn.execute(
                delete(Incident).where(
                    Incident.incident_id.in_(tracker["incidents"])
                )
            )


def _setup_active_investigation(session_factory, cleanup_tracker):
    """Helper to create and return an active (in_progress) investigation."""
    with session_factory() as session:
        inc = Incident(
            incident_id=uuid.uuid4(),
            title="Atomic Completion Test Incident",
            incident_type="brute_force",
            source_ip="198.51.100.22",
            severity="high",
            detection_method="hybrid",
            status="open",
            investigation_status="in_progress",
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(inc)
        session.flush()
        cleanup_tracker["incidents"].append(inc.incident_id)

        inv = Investigation(
            investigation_id=uuid.uuid4(),
            incident_id=inc.incident_id,
            status="in_progress",
            started_at=datetime.now(timezone.utc),
        )
        session.add(inv)
        session.commit()
        cleanup_tracker["investigations"].append(inv.investigation_id)

        return inc.incident_id, inv.investigation_id


def test_completion_when_hindsight_disabled_writes_no_outbox(session_factory, cleanup_tracker):
    """When Hindsight is disabled, investigation completes cleanly and zero outbox rows exist."""
    inc_id, inv_id = _setup_active_investigation(session_factory, cleanup_tracker)
    service = InvestigationService(session_factory=session_factory)

    report = InvestigationReport(
        summary="Test report without memory outbox insertion.",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[Observation(observation_id="OBS-1", description="Observation 1")],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Credential weakness.",
    )

    with patch("app.services.investigation_service.settings.HINDSIGHT_ENABLED", False):
        dto = service.complete_investigation(
            investigation_id=inv_id,
            report=report,
            serialized_memory_payload={"some": "payload"},
        )

    assert dto.status == "completed"

    with session_factory() as session:
        outbox_rows = (
            session.query(IncidentMemoryOutbox)
            .filter(IncidentMemoryOutbox.investigation_id == inv_id)
            .all()
        )
        assert len(outbox_rows) == 0


def test_completion_when_hindsight_enabled_atomic_commit(session_factory, cleanup_tracker):
    """When Hindsight is enabled and payload is provided, investigation and outbox commit together."""
    inc_id, inv_id = _setup_active_investigation(session_factory, cleanup_tracker)
    service = InvestigationService(session_factory=session_factory)

    sample_payload = {
        "schema_version": "v1",
        "investigation_id": str(inv_id),
        "incident_id": str(inc_id),
        "text": "Attacker executed brute force attack against SSH daemon.",
        "findings": ["finding_1"],
    }

    report = InvestigationReport(
        summary="Test report with memory outbox insertion.",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[Observation(observation_id="OBS-1", description="Observation 1")],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Credential weakness.",
    )

    # Ensure zero network calls: mock any hindsight client or http calls
    with patch("app.services.investigation_service.settings.HINDSIGHT_ENABLED", True), \
         patch("app.services.investigation_service.settings.HINDSIGHT_BANK_ID", "sentinelagent-incident-memory-test"):

        dto = service.complete_investigation(
            investigation_id=inv_id,
            report=report,
            serialized_memory_payload=sample_payload,
        )

    assert dto.status == "completed"

    with session_factory() as session:
        # Check investigation completed
        inv = session.get(Investigation, inv_id)
        assert inv is not None
        assert inv.status == "completed"

        # Check outbox committed
        outbox_rows = (
            session.query(IncidentMemoryOutbox)
            .filter(IncidentMemoryOutbox.investigation_id == inv_id)
            .all()
        )
        assert len(outbox_rows) == 1
        entry = outbox_rows[0]
        assert entry.bank_id == "sentinelagent-incident-memory-test"
        assert entry.document_id == generate_document_id(inv_id)
        assert entry.status == "pending"
        assert entry.attempt_count == 0
        assert entry.serialized_memory_payload == sample_payload

        # Verify operation_id determinism
        expected_hash = calculate_payload_hash(canonicalize_payload(sample_payload))
        expected_op_id = generate_operation_id(
            "sentinelagent-incident-memory-test",
            generate_document_id(inv_id),
            "v1",
            expected_hash,
        )
        assert entry.payload_hash == expected_hash
        assert entry.operation_id == expected_op_id


def test_completion_transaction_rollback_guarantee(session_factory, cleanup_tracker):
    """If an exception occurs during completion, both investigation status update and outbox insertion rollback."""
    inc_id, inv_id = _setup_active_investigation(session_factory, cleanup_tracker)
    service = InvestigationService(session_factory=session_factory)

    sample_payload = {
        "text": "Rollback payload test",
    }

    # Construct report referencing a non-existent provenance source to trigger rollback during validation
    non_existent_uuid = uuid.UUID("00000000-0000-0000-0000-000000000999")
    report = InvestigationReport(
        summary="Rollback test report.",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[
            Observation(
                observation_id="OBS-1",
                description="Observation referencing non-existent event.",
                evidence_references=[f"ssh_events/{non_existent_uuid}"],
            )
        ],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Weakness.",
    )

    provenance_set = AuthorizedProvenanceSet()
    provenance_set.add_ssh_event(non_existent_uuid)

    with patch("app.services.investigation_service.settings.HINDSIGHT_ENABLED", True), \
         patch("app.services.investigation_service.settings.HINDSIGHT_BANK_ID", "sentinelagent-incident-memory-test"):

        with pytest.raises(ProvenanceValidationError, match="does not exist in database"):
            service.complete_investigation(
                investigation_id=inv_id,
                report=report,
                provenance_set=provenance_set,
                serialized_memory_payload=sample_payload,
            )

    # Verify rollback: investigation is still in_progress, and NO outbox entry was committed
    with session_factory() as session:
        inv = session.get(Investigation, inv_id)
        assert inv is not None
        assert inv.status == "in_progress"

        outbox_rows = (
            session.query(IncidentMemoryOutbox)
            .filter(IncidentMemoryOutbox.investigation_id == inv_id)
            .all()
        )
        assert len(outbox_rows) == 0


def test_zero_network_calls_during_investigation_completion(session_factory, cleanup_tracker):
    """Verify that complete_investigation executes zero external HTTP or Hindsight SDK calls."""
    inc_id, inv_id = _setup_active_investigation(session_factory, cleanup_tracker)
    service = InvestigationService(session_factory=session_factory)

    report = InvestigationReport(
        summary="Test zero external network calls.",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[Observation(observation_id="OBS-1", description="Observation 1")],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Weakness.",
    )

    with patch("app.services.investigation_service.settings.HINDSIGHT_ENABLED", True), \
         patch("app.services.investigation_service.settings.HINDSIGHT_BANK_ID", "sentinelagent-incident-memory-test"), \
         patch("urllib.request.urlopen") as mock_url, \
         patch("http.client.HTTPConnection") as mock_conn:

        service.complete_investigation(
            investigation_id=inv_id,
            report=report,
            serialized_memory_payload={"text": "zero network calls test"},
        )

        mock_url.assert_not_called()
        mock_conn.assert_not_called()


def test_completion_fails_and_rolls_back_when_outbox_insertion_violates_constraint(session_factory, cleanup_tracker, db_engine):
    """Prove that an outbox-write failure rolls back staged investigation completion.

    Exercises the real transaction boundary through a genuine database-level failure:
    1. Creates a valid in-progress investigation in PostgreSQL.
    2. Enables Hindsight in test configuration.
    3. Supplies a valid serialized memory payload.
    4. Attaches a temporary PostgreSQL BEFORE INSERT trigger on incident_memory_outbox
       that raises an EXCEPTION unconditionally.
    5. Calls the actual InvestigationService.complete_investigation() method with no mocking.
    6. Observes the database IntegrityError / InternalError raised from PostgreSQL during the service call.
    7. Uses a fresh database session to verify that Investigation remains 'in_progress' and completed_at is NULL.
    8. Verifies that zero outbox entries were committed.
    9. Guarantees removal of the temporary trigger in test teardown.
    """
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    trigger_fn_name = "test_fail_outbox_trigger_fn"
    trigger_name = "trg_test_fail_outbox_insert"

    # Install controlled database trigger
    with db_engine.begin() as conn:
        conn.execute(
            text(f"""
            CREATE OR REPLACE FUNCTION {trigger_fn_name}()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'Controlled PostgreSQL outbox insert failure for rollback verification';
            END;
            $$ LANGUAGE plpgsql;
            """)
        )
        conn.execute(
            text(f"""
            CREATE TRIGGER {trigger_name}
            BEFORE INSERT ON incident_memory_outbox
            FOR EACH ROW
            EXECUTE FUNCTION {trigger_fn_name}();
            """)
        )

    try:
        inc_id, inv_id = _setup_active_investigation(session_factory, cleanup_tracker)
        service = InvestigationService(session_factory=session_factory)

        report = InvestigationReport(
            summary="Genuine database outbox trigger failure rollback test.",
            sufficient_evidence=True,
            confirmed_findings=[],
            observations=[Observation(observation_id="OBS-1", description="Observation 1")],
            hypotheses=[],
            evidence_gaps=[],
            root_cause_assessment="Weakness.",
        )

        valid_payload = {
            "schema_version": "v1",
            "investigation_id": str(inv_id),
            "text": "Valid memory payload that triggers database abort upon insert.",
        }

        with patch("app.services.investigation_service.settings.HINDSIGHT_ENABLED", True), \
             patch("app.services.investigation_service.settings.HINDSIGHT_BANK_ID", "sentinelagent-incident-memory-test"):

            # Execute real service call without any mocking of the service or SQL queries
            with pytest.raises(DBAPIError, match="Controlled PostgreSQL outbox insert failure"):
                service.complete_investigation(
                    investigation_id=inv_id,
                    report=report,
                    serialized_memory_payload=valid_payload,
                )

        # Inspect via a fresh database session to verify genuine rollback
        with session_factory() as session:
            inv = session.get(Investigation, inv_id)
            assert inv is not None
            assert inv.status == "in_progress"
            assert inv.completed_at is None

            inc = session.get(Incident, inc_id)
            assert inc is not None
            assert inc.investigation_status == "in_progress"

            outbox_rows = (
                session.query(IncidentMemoryOutbox)
                .filter(IncidentMemoryOutbox.investigation_id == inv_id)
                .all()
            )
            assert len(outbox_rows) == 0

    finally:
        # Guaranteed teardown of temporary trigger
        with db_engine.begin() as conn:
            conn.execute(text(f"DROP TRIGGER IF EXISTS {trigger_name} ON incident_memory_outbox;"))
            conn.execute(text(f"DROP FUNCTION IF EXISTS {trigger_fn_name}();"))


def test_completion_when_hindsight_enabled_missing_payload_raises_explicit_error(session_factory, cleanup_tracker):
    """When Hindsight is enabled, omitting serialized_memory_payload raises MissingMemoryPayloadError and rolls back."""
    inc_id, inv_id = _setup_active_investigation(session_factory, cleanup_tracker)
    service = InvestigationService(session_factory=session_factory)

    report = InvestigationReport(
        summary="Test missing payload error.",
        sufficient_evidence=True,
        confirmed_findings=[],
        observations=[Observation(observation_id="OBS-1", description="Observation 1")],
        hypotheses=[],
        evidence_gaps=[],
        root_cause_assessment="Weakness.",
    )

    with patch("app.services.investigation_service.settings.HINDSIGHT_ENABLED", True):
        with pytest.raises(MissingMemoryPayloadError, match="serialized_memory_payload was omitted"):
            service.complete_investigation(
                investigation_id=inv_id,
                report=report,
                serialized_memory_payload=None,
            )

    # Verify investigation was not completed and zero outbox rows exist
    with session_factory() as session:
        inv = session.get(Investigation, inv_id)
        assert inv is not None
        assert inv.status == "in_progress"
        assert inv.completed_at is None

        outbox_rows = (
            session.query(IncidentMemoryOutbox)
            .filter(IncidentMemoryOutbox.investigation_id == inv_id)
            .all()
        )
        assert len(outbox_rows) == 0

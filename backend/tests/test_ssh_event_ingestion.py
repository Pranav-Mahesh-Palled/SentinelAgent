"""Automated integration tests for SSH event ingestion API.

Tests single and batch ingestion endpoints against the real PostgreSQL database:
- Valid payload ingestion and database persistence
- Validation rejections (UUID, IP, empty username, auth result, naive timestamp, lengths)
- Conflict handling (HTTP 409) for existing IDs
- Duplicate UUIDs within a batch
- Batch size constraints (empty batch, batch > 500)
- Atomic transaction rollback
- Clean session cleanup after errors
- Rejection of external ingested_at
- Integration with synthetic event generator
"""

from datetime import datetime, timezone
import uuid
import pytest
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, text

from app.db.connection import get_engine
from app.db.session import get_db_session
from app.main import app
from app.models.ssh_event import SSHEvent
from app.services.ssh_event_generator import generate_brute_force_events


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def cleanup_events():
    """Tracks created event IDs and cleans them up from PostgreSQL after tests."""
    created_ids: list[uuid.UUID] = []
    yield created_ids
    if created_ids:
        engine = get_engine()
        if engine:
            with engine.begin() as conn:
                conn.execute(
                    delete(SSHEvent).where(SSHEvent.event_id.in_(created_ids))
                )


def make_event_dict(
    event_id: uuid.UUID = None,
    timestamp: datetime = None,
    source_ip: str = "192.0.2.55",
    username: str = "secops_user",
    authentication_result: str = "success",
    event_type: str = "password",
) -> dict:
    """Helper to construct a valid event payload dictionary."""
    return {
        "event_id": str(event_id or uuid.uuid4()),
        "event_timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "source_ip": source_ip,
        "username": username,
        "authentication_result": authentication_result,
        "event_type": event_type,
    }


# ---------------------------------------------------------------------------
# Test 1 & 14 & 15: Successful Single-Event Ingestion & DB Persistence
# ---------------------------------------------------------------------------

def test_successful_single_event_ingestion(client, cleanup_events):
    """Test 1, 14, 15: Successfully ingest a single event and verify persistence and response format."""
    ev_id = uuid.uuid4()
    cleanup_events.append(ev_id)
    payload = make_event_dict(event_id=ev_id, username="admin_alice", authentication_result="success")

    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_201_CREATED

    data = response.json()
    assert data["event_id"] == str(ev_id)
    assert data["status"] == "created"
    assert "successfully" in data["message"].lower()

    # Verify directly in PostgreSQL
    engine = get_engine()
    with engine.connect() as conn:
        record = conn.execute(
            select(SSHEvent).where(SSHEvent.event_id == ev_id)
        ).mappings().first()

        assert record is not None
        assert record["event_id"] == ev_id
        assert record["username"] == "admin_alice"
        assert record["authentication_result"] == "success"
        assert str(record["source_ip"]) == "192.0.2.55"
        assert record["event_type"] == "password"
        assert record["ingested_at"] is not None


# ---------------------------------------------------------------------------
# Test 2: Successful Batch Ingestion
# ---------------------------------------------------------------------------

def test_successful_batch_ingestion(client, cleanup_events):
    """Test 2: Ingest a valid batch of multiple events in a single transaction."""
    ids = [uuid.uuid4() for _ in range(5)]
    cleanup_events.extend(ids)
    batch_payload = [
        make_event_dict(event_id=eid, username=f"user_{i}", authentication_result="failure")
        for i, eid in enumerate(ids)
    ]

    response = client.post("/api/events/ssh/batch", json=batch_payload)
    assert response.status_code == status.HTTP_201_CREATED

    data = response.json()
    assert data["accepted_count"] == 5
    assert len(data["event_ids"]) == 5
    assert set(data["event_ids"]) == {str(eid) for eid in ids}
    assert data["status"] == "created"

    # Verify all 5 exist in PostgreSQL
    engine = get_engine()
    with engine.connect() as conn:
        count = conn.execute(
            select(SSHEvent).where(SSHEvent.event_id.in_(ids))
        ).all()
        assert len(count) == 5


# ---------------------------------------------------------------------------
# Test 3: Invalid UUID Rejection
# ---------------------------------------------------------------------------

def test_invalid_uuid_rejection(client):
    """Test 3: Reject request with malformed UUID."""
    payload = make_event_dict()
    payload["event_id"] = "not-a-valid-uuid"

    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 4: Invalid IP Rejection
# ---------------------------------------------------------------------------

def test_invalid_ip_rejection(client):
    """Test 4: Reject request with invalid IP address format."""
    payload = make_event_dict(source_ip="999.888.777.666")
    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 5: Empty Username Rejection
# ---------------------------------------------------------------------------

def test_empty_username_rejection(client):
    """Test 5: Reject request with empty username."""
    payload = make_event_dict(username="")
    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 6: Invalid Authentication Result Rejection
# ---------------------------------------------------------------------------

def test_invalid_authentication_result_rejection(client):
    """Test 6: Reject authentication_result other than 'success' or 'failure'."""
    payload = make_event_dict(authentication_result="pending")
    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 7: Invalid Timezone-Naive Timestamp Rejection
# ---------------------------------------------------------------------------

def test_invalid_timezone_naive_timestamp_rejection(client):
    """Test 7: Reject timestamp lacking timezone offset."""
    payload = make_event_dict()
    payload["event_timestamp"] = "2026-11-08T10:30:00"  # Naive (no Z or +00:00)

    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 8: Event-Type Length Validation
# ---------------------------------------------------------------------------

def test_event_type_length_validation(client):
    """Test 8: Reject empty event_type or event_type exceeding 32 characters."""
    # Empty event_type
    payload_empty = make_event_dict(event_type="")
    resp_empty = client.post("/api/events/ssh", json=payload_empty)
    assert resp_empty.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # > 32 characters
    payload_long = make_event_dict(event_type="x" * 33)
    resp_long = client.post("/api/events/ssh", json=payload_long)
    assert resp_long.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 9: Duplicate Event-ID Rejection (HTTP 409)
# ---------------------------------------------------------------------------

def test_duplicate_event_id_rejection(client, cleanup_events):
    """Test 9: Ingesting an already existing event ID returns HTTP 409 Conflict."""
    ev_id = uuid.uuid4()
    cleanup_events.append(ev_id)
    payload = make_event_dict(event_id=ev_id)

    # First ingestion succeeds
    res1 = client.post("/api/events/ssh", json=payload)
    assert res1.status_code == status.HTTP_201_CREATED

    # Second ingestion with same ID fails with 409
    res2 = client.post("/api/events/ssh", json=payload)
    assert res2.status_code == status.HTTP_409_CONFLICT
    assert f"Event with ID '{ev_id}' already exists" in res2.json()["detail"]


# ---------------------------------------------------------------------------
# Test 10: Duplicate IDs Within One Batch (HTTP 422)
# ---------------------------------------------------------------------------

def test_duplicate_ids_within_one_batch(client, cleanup_events):
    """Test 10: Reject batch submission containing duplicate event IDs within itself."""
    duplicate_id = uuid.uuid4()
    cleanup_events.append(duplicate_id)

    batch = [
        make_event_dict(event_id=duplicate_id, username="user_a"),
        make_event_dict(event_id=duplicate_id, username="user_b"),
    ]
    response = client.post("/api/events/ssh/batch", json=batch)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "duplicate" in response.json()["detail"].lower()

    # Confirm neither record was inserted
    engine = get_engine()
    with engine.connect() as conn:
        found = conn.execute(
            select(SSHEvent).where(SSHEvent.event_id == duplicate_id)
        ).first()
        assert found is None


# ---------------------------------------------------------------------------
# Test 11: Batch Size Exceeding 500 (HTTP 422)
# ---------------------------------------------------------------------------

def test_batch_size_exceeding_500(client):
    """Test 11: Reject batches containing more than 500 events."""
    oversized_batch = [make_event_dict() for _ in range(501)]
    response = client.post("/api/events/ssh/batch", json=oversized_batch)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 12: Empty Batch Rejection (HTTP 422)
# ---------------------------------------------------------------------------

def test_empty_batch_rejection(client):
    """Test 12: Reject empty batch submissions."""
    response = client.post("/api/events/ssh/batch", json=[])
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT


# ---------------------------------------------------------------------------
# Test 13: Atomic Rollback Tests (Pre-check & Genuine DB-Level Failure)
# ---------------------------------------------------------------------------

def test_batch_precheck_rejection_for_existing_id(client, cleanup_events):
    """Test 13a: Pre-check rejects batch submission when an ID already exists in DB."""
    pre_existing_id = uuid.uuid4()
    new_id = uuid.uuid4()
    cleanup_events.extend([pre_existing_id, new_id])

    # 1. Ingest pre_existing_id successfully
    pre_payload = make_event_dict(event_id=pre_existing_id, username="existing_user")
    res1 = client.post("/api/events/ssh", json=pre_payload)
    assert res1.status_code == status.HTTP_201_CREATED

    # 2. Submit batch with [new_id, pre_existing_id]
    batch = [
        make_event_dict(event_id=new_id, username="new_user"),
        make_event_dict(event_id=pre_existing_id, username="conflicting_user"),
    ]
    res2 = client.post("/api/events/ssh/batch", json=batch)
    assert res2.status_code == status.HTTP_409_CONFLICT

    # 3. Verify new_id was NOT persisted
    engine = get_engine()
    with engine.connect() as conn:
        new_record = conn.execute(
            select(SSHEvent).where(SSHEvent.event_id == new_id)
        ).first()
        assert new_record is None, "Precheck rejection failed: new_id was persisted!"


def test_genuine_database_level_atomic_rollback(client, cleanup_events):
    """Test 13b: Genuine database-level insertion failure triggers complete atomic rollback.

    Validates that when batch insertion begins inside a database transaction, an
    integrity failure triggered at the PostgreSQL engine level causes the entire
    transaction to roll back, leaving none of the batch records in the database.

    Uses a temporary, reversible check constraint that passes Pydantic validation
    and passes the ID pre-check, but fails during PostgreSQL INSERT execution.
    """
    engine = get_engine()
    assert engine is not None, "Database engine must be available for integration test"
    constraint_name = f"ck_test_atomic_rollback_{uuid.uuid4().hex[:8]}"
    trigger_fail_username = "rollback_trigger_user"

    # 1. Add reversible test-only check constraint directly to PostgreSQL
    with engine.begin() as conn:
        conn.execute(
            text(
                f"ALTER TABLE ssh_events ADD CONSTRAINT {constraint_name} "
                f"CHECK (username != '{trigger_fail_username}')"
            )
        )

    try:
        valid_id = uuid.uuid4()
        failing_id = uuid.uuid4()
        cleanup_events.extend([valid_id, failing_id])

        # 2. Confirm neither ID exists in DB prior to batch submission (bypassing pre-check)
        with engine.connect() as conn:
            pre_exists = conn.execute(
                select(SSHEvent.event_id).where(SSHEvent.event_id.in_([valid_id, failing_id]))
            ).all()
            assert len(pre_exists) == 0

        # 3. Construct batch with at least one valid event followed by the failing event
        # Both satisfy Pydantic schema validation (valid IP, valid UTC time, valid auth, length)
        batch = [
            make_event_dict(event_id=valid_id, username="valid_batch_user_1", authentication_result="success"),
            make_event_dict(event_id=failing_id, username=trigger_fail_username, authentication_result="failure"),
        ]

        # 4. Submit batch: pre-check passes, insertion starts, but PostgreSQL throws CheckViolation (SQLSTATE 23514)
        response = client.post("/api/events/ssh/batch", json=batch)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.json()["detail"] == "Failed to persist batch due to an internal database error."

        # 5. Verify atomic rollback: valid_id was added to the transaction before failing_id,
        # but because db.rollback() was triggered, valid_id MUST NOT exist in PostgreSQL!
        with engine.connect() as conn:
            persisted_valid = conn.execute(
                select(SSHEvent).where(SSHEvent.event_id == valid_id)
            ).first()
            assert persisted_valid is None, "Atomic rollback failed: valid_id was persisted!"

            persisted_failing = conn.execute(
                select(SSHEvent).where(SSHEvent.event_id == failing_id)
            ).first()
            assert persisted_failing is None, "Atomic rollback failed: failing_id was persisted!"

    finally:
        # 6. Clean up temporary test constraint in finally block
        with engine.begin() as conn:
            conn.execute(
                text(f"ALTER TABLE ssh_events DROP CONSTRAINT IF EXISTS {constraint_name}")
            )

    # 7. Verify temporary constraint is completely removed from PostgreSQL catalogs
    with engine.connect() as conn:
        remaining = conn.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "JOIN pg_class ON pg_constraint.conrelid = pg_class.oid "
                f"WHERE pg_class.relname = 'ssh_events' AND conname = '{constraint_name}'"
            )
        ).all()
        assert len(remaining) == 0, f"Temporary constraint {constraint_name} was not removed!"


def test_database_primary_key_uniqueness_final_authority_on_race_condition(client, cleanup_events):
    """Test 13c: PostgreSQL primary key constraint (SQLSTATE 23505) is the final authority.

    Simulates a race condition where the application pre-check observed no conflict,
    but another process committed the duplicate ID before db.commit().
    Verifies that PostgreSQL's pk_ssh_events raises UniqueViolation (23505),
    which the API catches, rolls back, and returns HTTP 409 Conflict.
    """
    from unittest.mock import patch
    from sqlalchemy.orm import Session

    engine = get_engine()
    assert engine is not None
    race_id = uuid.uuid4()
    cleanup_events.append(race_id)

    # Insert race_id directly into PostgreSQL to simulate another process committing it
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO ssh_events (event_id, event_timestamp, source_ip, username, authentication_result, event_type) "
                f"VALUES ('{race_id}', NOW(), '192.0.2.1', 'concurrent_user', 'success', 'password')"
            )
        )

    # Intercept pre-check to return empty list, simulating that pre-check ran before the race commit
    orig_execute = Session.execute

    def mock_execute(self, statement, *args, **kwargs):
        if hasattr(statement, "is_select") and statement.is_select:
            compiled = str(statement)
            if "ssh_events.event_id IN" in compiled:
                class EmptyResult:
                    def scalars(self):
                        return self
                    def all(self):
                        return []
                return EmptyResult()
        return orig_execute(self, statement, *args, **kwargs)

    with patch.object(Session, "execute", mock_execute):
        batch = [make_event_dict(event_id=race_id, username="racing_user")]
        response = client.post("/api/events/ssh/batch", json=batch)

    assert response.status_code == status.HTTP_409_CONFLICT
    assert "already exist" in response.json()["detail"].lower()


def test_single_event_check_constraint_failure_returns_500(client, cleanup_events):
    """Verify genuine PostgreSQL check constraint failure on single-event ingestion returns HTTP 500."""
    engine = get_engine()
    assert engine is not None
    constraint_name = f"ck_test_single_{uuid.uuid4().hex[:8]}"
    fail_user = "single_rollback_user"

    with engine.begin() as conn:
        conn.execute(
            text(
                f"ALTER TABLE ssh_events ADD CONSTRAINT {constraint_name} "
                f"CHECK (username != '{fail_user}')"
            )
        )

    try:
        ev_id = uuid.uuid4()
        cleanup_events.append(ev_id)
        payload = make_event_dict(event_id=ev_id, username=fail_user)

        response = client.post("/api/events/ssh", json=payload)
        assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        assert response.json()["detail"] == "Failed to persist event due to an internal database error."

        # Confirm ev_id was NOT persisted
        with engine.connect() as conn:
            persisted = conn.execute(
                select(SSHEvent).where(SSHEvent.event_id == ev_id)
            ).first()
            assert persisted is None
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(f"ALTER TABLE ssh_events DROP CONSTRAINT IF EXISTS {constraint_name}")
            )

    # Verify temporary constraint removed
    with engine.connect() as conn:
        remaining = conn.execute(
            text(
                "SELECT conname FROM pg_constraint "
                "JOIN pg_class ON pg_constraint.conrelid = pg_class.oid "
                f"WHERE pg_class.relname = 'ssh_events' AND conname = '{constraint_name}'"
            )
        ).all()
        assert len(remaining) == 0


# ---------------------------------------------------------------------------
# Test 16: Generator Integration (Brute Force -> Ingestion API)
# ---------------------------------------------------------------------------

def test_generator_to_ingestion_compatibility(client, cleanup_events):
    """Test 16: Events generated by synthetic generator are accepted by the ingestion API."""
    synthetic_events = generate_brute_force_events(count=10, seed=777)
    cleanup_events.extend([e.event_id for e in synthetic_events])

    payload = [
        {
            "event_id": str(e.event_id),
            "event_timestamp": e.event_timestamp.isoformat(),
            "source_ip": e.source_ip,
            "username": e.username,
            "authentication_result": e.authentication_result,
            "event_type": e.event_type,
        }
        for e in synthetic_events
    ]

    response = client.post("/api/events/ssh/batch", json=payload)
    assert response.status_code == status.HTTP_201_CREATED

    data = response.json()
    assert data["accepted_count"] == 10
    assert len(data["event_ids"]) == 10

    # Verify all 10 records are in PostgreSQL
    engine = get_engine()
    with engine.connect() as conn:
        db_records = conn.execute(
            select(SSHEvent).where(SSHEvent.event_id.in_([e.event_id for e in synthetic_events]))
        ).all()
        assert len(db_records) == 10


# ---------------------------------------------------------------------------
# Test 17: Database Session Cleanup After Errors
# ---------------------------------------------------------------------------

def test_database_session_cleanup_after_errors(client, cleanup_events):
    """Test 17: Database session is cleanly closed on error; subsequent requests succeed."""
    # 1. Trigger an error (invalid UUID)
    bad_res = client.post("/api/events/ssh", json={"event_id": "not-valid"})
    assert bad_res.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

    # 2. Immediate valid request should succeed normally
    valid_id = uuid.uuid4()
    cleanup_events.append(valid_id)
    good_payload = make_event_dict(event_id=valid_id)
    good_res = client.post("/api/events/ssh", json=good_payload)
    assert good_res.status_code == status.HTTP_201_CREATED


# ---------------------------------------------------------------------------
# Test 18: Rejection of External ingested_at
# ---------------------------------------------------------------------------

def test_external_ingested_at_rejected(client):
    """Reject external ingested_at; server default must govern."""
    payload = make_event_dict()
    payload["ingested_at"] = datetime.now(timezone.utc).isoformat()

    response = client.post("/api/events/ssh", json=payload)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT

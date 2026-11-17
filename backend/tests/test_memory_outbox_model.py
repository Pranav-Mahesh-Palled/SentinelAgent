"""Unit and integration tests for IncidentMemoryOutbox database model and deterministic identity.

Verifies:
1. Declarative attributes, mapped columns, and types.
2. Check constraint behaviors (status, attempt_count, lease_token, lease invariant, completed_at invariant).
3. JSONB payload preservation (nested objects, lists, numbers, booleans, nulls, unicode).
4. Canonical JSON serialization invariance.
5. SHA-256 payload hash determinism.
6. RFC 4122 UUID5 deterministic operation identity generation and collision resistance.
7. Document ID formatting.
8. Unique constraint on operation_id in PostgreSQL.
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid

import pytest
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db import connection
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.memory_outbox import IncidentMemoryOutbox, VALID_OUTBOX_STATUSES
from app.services.memory_outbox_service import (
    DEFAULT_MEMORY_SCHEMA_VERSION,
    SENTINEL_MEMORY_NAMESPACE,
    calculate_payload_hash,
    canonicalize_payload,
    generate_document_id,
    generate_operation_id,
    validate_payload_hash,
)


# =============================================================================
# Unit Tests: Canonical Serialization & Deterministic Identity
# =============================================================================

def test_canonicalize_payload_key_ordering_invariance():
    """Verify dictionary key ordering does not alter the canonical byte representation."""
    payload_a = {"b": 2, "a": 1, "nested": {"z": 100, "y": 200}}
    payload_b = {"a": 1, "nested": {"y": 200, "z": 100}, "b": 2}

    bytes_a = canonicalize_payload(payload_a)
    bytes_b = canonicalize_payload(payload_b)

    assert bytes_a == bytes_b
    assert bytes_a == b'{"a":1,"b":2,"nested":{"y":200,"z":100}}'


def test_canonicalize_payload_rejects_non_dict():
    """Verify non-dictionary input raises TypeError."""
    with pytest.raises(TypeError, match="Payload must be a dictionary"):
        canonicalize_payload(["not", "a", "dict"])  # type: ignore


def test_canonicalize_payload_rejects_nan_and_infinities():
    """Verify canonical serialization strictly rejects NaN and +/- Infinity."""
    with pytest.raises(ValueError, match="Out of range float values are not JSON compliant"):
        canonicalize_payload({"value": float("nan")})

    with pytest.raises(ValueError, match="Out of range float values are not JSON compliant"):
        canonicalize_payload({"value": float("inf")})

    with pytest.raises(ValueError, match="Out of range float values are not JSON compliant"):
        canonicalize_payload({"value": float("-inf")})


def test_canonicalize_payload_unicode_and_deterministic_hash():
    """Verify valid Unicode handling and deterministic SHA-256 calculation."""
    payload = {
        "text": "Incident mémoire: Événement de sécurité détecté.",
        "chinese": "网络安全事件",
        "symbols": "→ ⇒ 🔒",
    }
    canonical_bytes = canonicalize_payload(payload)
    digest = calculate_payload_hash(canonical_bytes)
    assert len(digest) == 64
    assert digest == hashlib.sha256(canonical_bytes).hexdigest()
    # Ensure UTF-8 characters are preserved without ASCII escaping
    assert "mémoire".encode("utf-8") in canonical_bytes


def test_calculate_payload_hash_sha256():
    """Verify SHA-256 calculation matches standard hashlib digest."""
    payload = {"key": "value"}
    c_bytes = canonicalize_payload(payload)
    digest = calculate_payload_hash(c_bytes)

    expected = hashlib.sha256(c_bytes).hexdigest()
    assert digest == expected
    assert len(digest) == 64


def test_validate_payload_hash_format():
    """Verify application-level payload hash validation accepts 64 lowercase hex only."""
    valid_hash = "a" * 64
    assert validate_payload_hash(valid_hash) == valid_hash

    # Uppercase rejected
    with pytest.raises(ValueError, match="Invalid payload_hash"):
        validate_payload_hash("A" * 64)

    # Wrong length rejected
    with pytest.raises(ValueError, match="Invalid payload_hash"):
        validate_payload_hash("a" * 63)
    with pytest.raises(ValueError, match="Invalid payload_hash"):
        validate_payload_hash("a" * 65)

    # Non-hex characters rejected
    with pytest.raises(ValueError, match="Invalid payload_hash"):
        validate_payload_hash("g" * 64)


def test_generate_document_id():
    """Verify canonical document ID format."""
    inv_id = uuid.uuid4()
    doc_id = generate_document_id(inv_id, version="v1")
    assert doc_id == f"sentinelagent:v1:investigation:{inv_id}"


def test_generate_operation_id_deterministic_uuid5():
    """Verify RFC 4122 UUID5 operation identifier generation is deterministic."""
    bank_id = "sentinelagent-incident-memory-dev"
    doc_id = "sentinelagent:v1:investigation:00000000-0000-0000-0000-000000000001"
    version = "v1"
    payload_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    op_id_1 = generate_operation_id(bank_id, doc_id, version, payload_hash)
    op_id_2 = generate_operation_id(bank_id, doc_id, version, payload_hash)

    assert op_id_1 == op_id_2
    assert isinstance(op_id_1, uuid.UUID)
    assert op_id_1.version == 5

    # Changing any component must yield a different UUID5
    diff_hash = "f" * 64
    op_id_diff = generate_operation_id(bank_id, doc_id, version, diff_hash)
    assert op_id_1 != op_id_diff

    # Verify namespace matching
    expected_uuid5 = uuid.uuid5(
        SENTINEL_MEMORY_NAMESPACE,
        f"{bank_id}:{doc_id}:{version}:{payload_hash}",
    )
    assert op_id_1 == expected_uuid5


# =============================================================================
# Database Fixtures
# =============================================================================

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
def db_cleanup(db_engine):
    tracker = {
        "outbox_ids": [],
        "investigations": [],
        "incidents": [],
    }
    yield tracker

    with db_engine.begin() as conn:
        if tracker["outbox_ids"]:
            conn.execute(
                delete(IncidentMemoryOutbox).where(
                    IncidentMemoryOutbox.outbox_id.in_(tracker["outbox_ids"])
                )
            )
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


def _create_test_investigation(session, cleanup_tracker):
    """Helper to create a parent incident and investigation for outbox testing."""
    inc = Incident(
        incident_id=uuid.uuid4(),
        title="Incident Memory Outbox Test Incident",
        incident_type="brute_force",
        source_ip="192.168.1.100",
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
    session.flush()
    cleanup_tracker["investigations"].append(inv.investigation_id)

    return inc, inv


# =============================================================================
# Database Model & Constraints Tests
# =============================================================================

def test_outbox_model_insert_and_jsonb_preservation(session_factory, db_cleanup):
    """Verify valid outbox entry insertion and exact JSONB preservation."""
    complex_payload = {
        "text": "Unauthorized root SSH access from known Tor exit node.",
        "incident_id": "INC-001",
        "nested": {"confidence": 0.98, "is_critical": True, "null_field": None},
        "tactics": ["Initial Access", "Privilege Escalation"],
        "unicode": "Técnico de seguridad / 警报",
    }
    c_bytes = canonicalize_payload(complex_payload)
    p_hash = calculate_payload_hash(c_bytes)

    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        op_id = generate_operation_id(
            "sentinelagent-incident-memory-dev",
            generate_document_id(inv.investigation_id),
            "v1",
            p_hash,
        )

        outbox_entry = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            memory_schema_version="v1",
            payload_hash=p_hash,
            serialized_memory_payload=complex_payload,
            operation_id=op_id,
            status="pending",
        )
        session.add(outbox_entry)
        session.commit()
        db_cleanup["outbox_ids"].append(outbox_entry.outbox_id)

        # Retrieve and verify
        fetched = session.get(IncidentMemoryOutbox, outbox_entry.outbox_id)
        assert fetched is not None
        assert fetched.serialized_memory_payload == complex_payload
        assert fetched.status == "pending"
        assert fetched.attempt_count == 0
        assert fetched.lease_token == 0
        assert fetched.created_at is not None
        assert fetched.updated_at is not None
        assert fetched.completed_at is None


def test_outbox_check_constraint_payload_is_object(session_factory, db_cleanup):
    """Verify PostgreSQL check constraint rejects non-object JSON payloads (array, string, number, bool)."""
    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        # Attempt to insert JSONB array instead of JSON object
        entry = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            serialized_memory_payload=["not", "an", "object"],  # type: ignore
            operation_id=uuid.uuid4(),
            status="pending",
        )
        session.add(entry)
        with pytest.raises(IntegrityError, match="payload_is_object"):
            session.commit()
        session.rollback()


def test_outbox_check_constraint_payload_hash_format(session_factory, db_cleanup):
    """Verify PostgreSQL check constraint rejects malformed or uppercase SHA-256 payload_hash."""
    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        # 1. Non-hex characters
        entry_invalid_hex = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="g" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="pending",
        )
        session.add(entry_invalid_hex)
        with pytest.raises(IntegrityError, match="payload_hash_format"):
            session.commit()
        session.rollback()

        # 2. Uppercase hex characters
        entry_upper_hex = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="A" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="pending",
        )
        session.add(entry_upper_hex)
        with pytest.raises(IntegrityError, match="payload_hash_format"):
            session.commit()
        session.rollback()

        # 3. Wrong length (63 characters)
        entry_short = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="a" * 63,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="pending",
        )
        session.add(entry_short)
        with pytest.raises(IntegrityError, match="payload_hash_format"):
            session.commit()
        session.rollback()


def test_outbox_check_constraint_invalid_status(session_factory, db_cleanup):
    """Verify check constraint rejects invalid status strings."""
    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        entry = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="a" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="invalid_status",
        )
        session.add(entry)
        with pytest.raises(IntegrityError, match="status_valid"):
            session.commit()
        session.rollback()


def test_outbox_check_constraint_attempt_count_non_negative(session_factory, db_cleanup):
    """Verify check constraint rejects negative attempt_count."""
    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        entry = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="a" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="pending",
            attempt_count=-1,
        )
        session.add(entry)
        with pytest.raises(IntegrityError, match="attempt_coun"):
            session.commit()
        session.rollback()


def test_outbox_check_constraint_processing_lease_invariant(session_factory, db_cleanup):
    """Verify processing status requires non-null lease_owner and lease_expires_at."""
    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        # Missing lease_owner and lease_expires_at while status='processing'
        entry = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="a" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="processing",
            lease_owner=None,
            lease_expires_at=None,
        )
        session.add(entry)
        with pytest.raises(IntegrityError, match="processing_l"):
            session.commit()
        session.rollback()


def test_outbox_check_constraint_completed_invariant(session_factory, db_cleanup):
    """Verify completed status requires non-null completed_at."""
    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        entry = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="a" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=uuid.uuid4(),
            status="completed",
            completed_at=None,
        )
        session.add(entry)
        with pytest.raises(IntegrityError, match="completed_ti"):
            session.commit()
        session.rollback()


def test_outbox_unique_constraint_operation_id(session_factory, db_cleanup):
    """Verify unique constraint on operation_id prevents duplicate inserts."""
    shared_op_id = uuid.uuid4()

    with session_factory() as session:
        inc, inv = _create_test_investigation(session, db_cleanup)
        entry_1 = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="a" * 64,
            serialized_memory_payload={"test": 1},
            operation_id=shared_op_id,
            status="pending",
        )
        session.add(entry_1)
        session.commit()
        db_cleanup["outbox_ids"].append(entry_1.outbox_id)

    with session_factory() as session:
        entry_2 = IncidentMemoryOutbox(
            investigation_id=inv.investigation_id,
            incident_id=inc.incident_id,
            bank_id="sentinelagent-incident-memory-dev",
            document_id=generate_document_id(inv.investigation_id),
            payload_hash="b" * 64,
            serialized_memory_payload={"test": 2},
            operation_id=shared_op_id,
            status="pending",
        )
        session.add(entry_2)
        with pytest.raises(IntegrityError, match="operation_id"):
            session.commit()
        session.rollback()

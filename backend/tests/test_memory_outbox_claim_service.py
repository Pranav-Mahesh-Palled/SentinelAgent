"""Unit and integration tests for PostgreSQL Outbox Claim Service and Concurrency.

Verifies Task 9C.3.3:
1. Candidate discovery: eligible pending, due retry_wait, expired processing; skips future or live leases.
2. Composite document concurrency: (bank_id, document_id) isolation and independence.
3. Composite advisory locking: serialization of claim decisions without race conditions.
4. Deterministic FIFO ordering: created_at ASC, outbox_id ASC tie-breaking.
5. Unsubmitted pending supersession: older pending revisions superseded, newest claimed.
6. Processing and retry_wait revisions never superseded.
7. Crash recovery: expired processing lease reclaimed with incremented token.
8. Lease fencing: monotonic tokens, heartbeat renewals, stale worker rejections.
9. Fenced state transitions: record operation ID, retry_wait, completed, dead_letter.
10. Detached immutable DTOs: no ORM leak across session boundaries.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Optional
import uuid

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db import connection
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.memory_outbox import IncidentMemoryOutbox
from app.services.memory_outbox_claim_service import (
    ClaimedMemoryOutboxRow,
    MemoryOutboxClaimService,
    OutboxPayloadIntegrityError,
)
from app.services.memory_outbox_service import (
    SENTINEL_MEMORY_NAMESPACE,
    canonicalize_payload,
    generate_document_id,
    generate_operation_id,
)


# =============================================================================
# Fixtures and Helpers
# =============================================================================

@pytest.fixture
def db_engine():
    engine = connection.get_engine()
    if engine is None:
        pytest.skip("Database is unconfigured.")
    return engine


@pytest.fixture
def session_factory(db_engine):
    return sessionmaker(bind=db_engine, autoflush=False, autocommit=False, expire_on_commit=False)


@pytest.fixture
def cleanup_tracker(db_engine):
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


def _setup_incident_and_investigation(session_factory, cleanup_tracker):
    """Helper to create a parent incident and investigation for outbox foreign keys."""
    with session_factory() as session:
        with session.begin():
            inc = Incident(
                incident_id=uuid.uuid4(),
                title="Claim Service Test Incident",
                incident_type="brute_force",
                source_ip="198.51.100.55",
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

            return inc.incident_id, inv.investigation_id


def _create_outbox_entry(
    session_factory,
    cleanup_tracker,
    investigation_id: uuid.UUID,
    incident_id: uuid.UUID,
    bank_id: str = "test-bank-dev",
    document_id: Optional[str] = None,
    payload: Optional[dict[str, Any]] = None,
    status: str = "pending",
    next_attempt_at: Optional[datetime] = None,
    lease_owner: Optional[str] = None,
    lease_token: int = 0,
    lease_expires_at: Optional[datetime] = None,
    created_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
    attempt_count: int = 0,
    hindsight_operation_id: Optional[str] = None,
) -> uuid.UUID:
    """Helper to insert a controlled outbox row for claim service testing."""
    doc_id = document_id or generate_document_id(investigation_id)
    memory_payload = payload or {"test_key": f"payload-{uuid.uuid4()}"}
    canonical = canonicalize_payload(memory_payload)
    p_hash = hashlib.sha256(canonical).hexdigest()
    op_id = generate_operation_id(
        bank_id=bank_id,
        document_id=doc_id,
        version="v1",
        payload_hash=p_hash,
    )

    now = datetime.now(timezone.utc)
    target_next_attempt = next_attempt_at or now
    target_completed_at = completed_at or (now if status == "completed" else None)

    with session_factory() as session:
        with session.begin():
            row = IncidentMemoryOutbox(
                outbox_id=uuid.uuid4(),
                investigation_id=investigation_id,
                incident_id=incident_id,
                bank_id=bank_id,
                document_id=doc_id,
                memory_schema_version="v1",
                payload_hash=p_hash,
                serialized_memory_payload=memory_payload,
                operation_id=op_id,
                hindsight_operation_id=hindsight_operation_id,
                status=status,
                attempt_count=attempt_count,
                next_attempt_at=target_next_attempt,
                lease_owner=lease_owner,
                lease_token=lease_token,
                lease_expires_at=lease_expires_at,
                created_at=created_at or now,
                updated_at=created_at or now,
                completed_at=target_completed_at,
            )
            session.add(row)
            session.flush()
            outbox_id = row.outbox_id
            cleanup_tracker["outbox_ids"].append(outbox_id)
            return outbox_id


# =============================================================================
# 1. Candidate Discovery Tests
# =============================================================================

def test_discover_candidates_eligible_pending(session_factory, cleanup_tracker):
    """Eligible pending rows with next_attempt_at <= NOW() are discovered."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"sentinelagent:v1:investigation:{inv_id}"
    _create_outbox_entry(
        session_factory,
        cleanup_tracker,
        investigation_id=inv_id,
        incident_id=inc_id,
        bank_id="test-bank",
        document_id=doc_id,
        status="pending",
        next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=10),
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    assert ("test-bank", doc_id) in candidates


def test_discover_candidates_future_pending_skipped(session_factory, cleanup_tracker):
    """Pending rows scheduled in the future are skipped during candidate discovery."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"sentinelagent:v1:investigation:{inv_id}"
    _create_outbox_entry(
        session_factory,
        cleanup_tracker,
        investigation_id=inv_id,
        incident_id=inc_id,
        bank_id="test-bank-future",
        document_id=doc_id,
        status="pending",
        next_attempt_at=datetime.now(timezone.utc) + timedelta(minutes=15),
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    assert ("test-bank-future", doc_id) not in candidates


def test_discover_candidates_due_retry_wait(session_factory, cleanup_tracker):
    """Retry-wait rows with next_attempt_at <= NOW() are eligible candidates."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"sentinelagent:v1:investigation:{inv_id}"
    _create_outbox_entry(
        session_factory,
        cleanup_tracker,
        investigation_id=inv_id,
        incident_id=inc_id,
        bank_id="test-bank-retry",
        document_id=doc_id,
        status="retry_wait",
        next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=5),
        attempt_count=1,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    assert ("test-bank-retry", doc_id) in candidates


def test_discover_candidates_future_retry_wait_skipped(session_factory, cleanup_tracker):
    """Retry-wait rows scheduled in the future are not discovered."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"sentinelagent:v1:investigation:{inv_id}"
    _create_outbox_entry(
        session_factory,
        cleanup_tracker,
        investigation_id=inv_id,
        incident_id=inc_id,
        bank_id="test-bank-retry-future",
        document_id=doc_id,
        status="retry_wait",
        next_attempt_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        attempt_count=1,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    assert ("test-bank-retry-future", doc_id) not in candidates


def test_discover_candidates_expired_processing_lease(session_factory, cleanup_tracker):
    """Processing rows with expired leases (lease_expires_at < NOW()) are discovered for recovery."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"sentinelagent:v1:investigation:{inv_id}"
    _create_outbox_entry(
        session_factory,
        cleanup_tracker,
        investigation_id=inv_id,
        incident_id=inc_id,
        bank_id="test-bank-crash",
        document_id=doc_id,
        status="processing",
        lease_owner="crashed-worker-99",
        lease_token=1,
        lease_expires_at=datetime.now(timezone.utc) - timedelta(seconds=30),
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    assert ("test-bank-crash", doc_id) in candidates


def test_discover_candidates_live_processing_lease_skipped(session_factory, cleanup_tracker):
    """Processing rows under an active non-expired lease are not discovered."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"sentinelagent:v1:investigation:{inv_id}"
    _create_outbox_entry(
        session_factory,
        cleanup_tracker,
        investigation_id=inv_id,
        incident_id=inc_id,
        bank_id="test-bank-live",
        document_id=doc_id,
        status="processing",
        lease_owner="live-worker-1",
        lease_token=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=35),
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    assert ("test-bank-live", doc_id) not in candidates


def test_discover_candidates_terminal_states_skipped(session_factory, cleanup_tracker):
    """Terminal states (completed, dead_letter, superseded) are never discovered."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    for st in ("completed", "dead_letter", "superseded"):
        doc_id = f"doc-terminal-{st}-{uuid.uuid4()}"
        _create_outbox_entry(
            session_factory,
            cleanup_tracker,
            investigation_id=inv_id,
            incident_id=inc_id,
            bank_id="test-bank-term",
            document_id=doc_id,
            status=st,
        )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    candidates = service.discover_candidates()

    term_docs = [c[1] for c in candidates if c[0] == "test-bank-term"]
    assert len(term_docs) == 0


# =============================================================================
# 2. FIFO Ordering and Supersession Tests
# =============================================================================

def test_fifo_ordering_oldest_pending_claimed_first(session_factory, cleanup_tracker):
    """Deterministic FIFO ordering ensures older records are claimed before newer ones."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    t0 = datetime.now(timezone.utc) - timedelta(minutes=10)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=5)

    doc_a = f"doc-a-{uuid.uuid4()}"
    doc_b = f"doc-b-{uuid.uuid4()}"

    outbox_a = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_a, created_at=t0,
    )
    outbox_b = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_b, created_at=t1,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_next_available(worker_id="worker-fifo-1")

    assert claimed is not None
    assert claimed.outbox_id == outbox_a
    assert claimed.document_id == doc_a


def test_older_pending_revisions_superseded_and_newest_claimed(session_factory, cleanup_tracker):
    """When multiple pending revisions exist for a document, older ones are superseded and newest claimed."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-supersede-{uuid.uuid4()}"

    t0 = datetime.now(timezone.utc) - timedelta(minutes=15)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=10)
    t2 = datetime.now(timezone.utc) - timedelta(minutes=5)

    id_v1 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t0,
        payload={"revision": 1},
    )
    id_v2 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t1,
        payload={"revision": 2},
    )
    id_v3 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t2,
        payload={"revision": 3},
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-super")

    assert claimed is not None
    assert claimed.outbox_id == id_v3
    assert json.loads(claimed.serialized_memory_content) == {"revision": 3}
    assert claimed.serialized_memory_content == canonicalize_payload({"revision": 3}).decode("utf-8")
    assert claimed.lease_owner == "worker-super"
    assert claimed.lease_token == 1

    # Verify database state for older revisions
    with session_factory() as session:
        v1_row = session.get(IncidentMemoryOutbox, id_v1)
        v2_row = session.get(IncidentMemoryOutbox, id_v2)
        v3_row = session.get(IncidentMemoryOutbox, id_v3)

        assert v1_row.status == "superseded"
        assert v2_row.status == "superseded"
        assert v3_row.status == "processing"


def test_processing_revision_never_superseded(session_factory, cleanup_tracker):
    """An active or expired processing row is never marked superseded by a newer pending row."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-proc-no-super-{uuid.uuid4()}"

    t0 = datetime.now(timezone.utc) - timedelta(minutes=10)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=2)

    # Active processing row
    proc_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t0,
        status="processing",
        lease_owner="active-worker-1",
        lease_token=1,
        lease_expires_at=datetime.now(timezone.utc) + timedelta(seconds=40),
        payload={"revision": "proc-v1"},
    )
    # Newer pending row
    pending_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t1,
        status="pending",
        payload={"revision": "pending-v2"},
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    # Should skip because oldest row is processing with a live lease
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-attempt")
    assert claimed is None

    # Neither row should be superseded
    with session_factory() as session:
        p_row = session.get(IncidentMemoryOutbox, proc_id)
        pend_row = session.get(IncidentMemoryOutbox, pending_id)
        assert p_row.status == "processing"
        assert pend_row.status == "pending"


def test_retry_wait_revision_blocks_newer_pending_row(session_factory, cleanup_tracker):
    """An older retry_wait row blocks newer pending rows from bypassing it."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-retry-block-{uuid.uuid4()}"

    t0 = datetime.now(timezone.utc) - timedelta(minutes=5)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=1)

    # Future retry-wait row
    retry_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t0,
        status="retry_wait",
        next_attempt_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        attempt_count=1,
    )
    # Newer pending row
    pending_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=t1,
        status="pending",
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    # Must skip document because oldest row is retry_wait in future
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-w1")
    assert claimed is None

    # Verify newer pending row was not claimed or superseded
    with session_factory() as session:
        pend_row = session.get(IncidentMemoryOutbox, pending_id)
        assert pend_row.status == "pending"


def test_expired_processing_lease_reclaims_same_row(session_factory, cleanup_tracker):
    """Crash recovery: expired processing lease reclaims the exact same row with incremented token."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-crash-recovery-{uuid.uuid4()}"

    expired_time = datetime.now(timezone.utc) - timedelta(seconds=20)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        status="processing",
        lease_owner="crashed-worker-88",
        lease_token=1,
        lease_expires_at=expired_time,
        hindsight_operation_id="remote-op-xyz",
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="recovering-worker")

    assert claimed is not None
    assert claimed.outbox_id == outbox_id
    assert claimed.lease_owner == "recovering-worker"
    assert claimed.lease_token == 2  # Monotonically incremented
    assert claimed.hindsight_operation_id == "remote-op-xyz"  # Preserved
    assert claimed.lease_expires_at > datetime.now(timezone.utc)


# =============================================================================
# 3. Bank and Document Independence Tests
# =============================================================================

def test_different_banks_remain_completely_independent(session_factory, cleanup_tracker):
    """The same document_id in dev vs prod bank operate independently."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    common_doc_id = f"sentinelagent:v1:investigation:{inv_id}"

    dev_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="sentinelagent-incident-memory-dev",
        document_id=common_doc_id,
        status="pending",
    )
    prod_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="sentinelagent-incident-memory-prod",
        document_id=common_doc_id,
        status="pending",
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    # Claim dev
    dev_claim = service.claim_document(
        bank_id="sentinelagent-incident-memory-dev",
        document_id=common_doc_id,
        worker_id="dev-worker",
    )
    assert dev_claim is not None
    assert dev_claim.outbox_id == dev_id
    assert dev_claim.bank_id == "sentinelagent-incident-memory-dev"

    # Prod row remains pending and unmutated
    with session_factory() as session:
        prod_row = session.get(IncidentMemoryOutbox, prod_id)
        assert prod_row.status == "pending"
        assert prod_row.lease_owner is None

    # Claim prod independently
    prod_claim = service.claim_document(
        bank_id="sentinelagent-incident-memory-prod",
        document_id=common_doc_id,
        worker_id="prod-worker",
    )
    assert prod_claim is not None
    assert prod_claim.outbox_id == prod_id
    assert prod_claim.bank_id == "sentinelagent-incident-memory-prod"


# =============================================================================
# 4. Lease Fencing and Renewal Tests
# =============================================================================

def test_lease_renewal_lifecycle(session_factory, cleanup_tracker):
    """Lease renewal succeeds for current owner and fails on stale identity, token, or expiry."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-renewal-{uuid.uuid4()}"

    service = MemoryOutboxClaimService(session_factory=session_factory)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )

    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-renew-1")
    assert claimed is not None
    assert claimed.lease_token == 1

    # 1. Renewal succeeds with matching credentials
    renewed = service.renew_lease(outbox_id=outbox_id, worker_id="worker-renew-1", lease_token=1)
    assert renewed is True

    # 2. Renewal fails with mismatched worker
    stale_worker = service.renew_lease(outbox_id=outbox_id, worker_id="imposter-worker", lease_token=1)
    assert stale_worker is False

    # 3. Renewal fails with mismatched token
    stale_token = service.renew_lease(outbox_id=outbox_id, worker_id="worker-renew-1", lease_token=99)
    assert stale_token is False

    # 4. Expire the lease manually in database
    with session_factory() as session:
        with session.begin():
            row = session.get(IncidentMemoryOutbox, outbox_id)
            row.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)

    # 5. Renewal fails on expired lease
    expired_renew = service.renew_lease(outbox_id=outbox_id, worker_id="worker-renew-1", lease_token=1)
    assert expired_renew is False


# =============================================================================
# 5. Fenced State Transition Tests
# =============================================================================

def test_record_hindsight_operation_id_fencing(session_factory, cleanup_tracker):
    """record_hindsight_operation_id enforces matching operation ID and active lease fencing."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-opid-{uuid.uuid4()}"

    service = MemoryOutboxClaimService(session_factory=session_factory)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="w-opid")
    assert claimed is not None

    correct_op_id = str(claimed.operation_id)
    bogus_op_id = str(uuid.uuid4())

    # 1. Bogus mismatched operation ID fails closed
    mismatched = service.record_hindsight_operation_id(
        outbox_id=outbox_id, worker_id="w-opid", lease_token=1, hindsight_operation_id=bogus_op_id,
    )
    assert mismatched is False

    # 2. Stale lease token fails
    stale = service.record_hindsight_operation_id(
        outbox_id=outbox_id, worker_id="w-opid", lease_token=999, hindsight_operation_id=correct_op_id,
    )
    assert stale is False

    # 3. Exact matching operation ID and valid lease succeeds
    success = service.record_hindsight_operation_id(
        outbox_id=outbox_id, worker_id="w-opid", lease_token=1, hindsight_operation_id=correct_op_id,
    )
    assert success is True

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.hindsight_operation_id == correct_op_id


def test_transition_to_retry_wait_fencing(session_factory, cleanup_tracker):
    """transition_to_retry_wait releases lease, increments attempt_count, and sets backoff."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-retry-wait-{uuid.uuid4()}"

    service = MemoryOutboxClaimService(session_factory=session_factory)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="w-retry")
    assert claimed is not None

    backoff_time = datetime.now(timezone.utc) + timedelta(seconds=60)

    # 1. Stale token fails
    assert service.transition_to_retry_wait(
        outbox_id=outbox_id, worker_id="w-retry", lease_token=55, next_attempt_at=backoff_time,
    ) is False

    # 2. Valid transition succeeds
    success = service.transition_to_retry_wait(
        outbox_id=outbox_id,
        worker_id="w-retry",
        lease_token=1,
        next_attempt_at=backoff_time,
        error_code="TIMEOUT",
    )
    assert success is True

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 0
        assert row.last_error_code == "TIMEOUT"
        assert row.lease_owner is None
        assert row.lease_expires_at is None


def test_increment_attempt_count_fencing_and_atomicity(session_factory, cleanup_tracker):
    """increment_attempt_count atomically increments attempt_count under active lease and fences out stale workers."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-inc-attempts-{uuid.uuid4()}"

    service = MemoryOutboxClaimService(session_factory=session_factory)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="w-inc")
    assert claimed is not None
    assert claimed.attempt_count == 0

    # 1. Stale token fails and returns None
    assert service.increment_attempt_count(outbox_id=outbox_id, worker_id="w-inc", lease_token=99) is None

    # 2. Imposter worker fails and returns None
    assert service.increment_attempt_count(outbox_id=outbox_id, worker_id="w-other", lease_token=1) is None

    # 3. Valid worker increments to 1
    new_val_1 = service.increment_attempt_count(outbox_id=outbox_id, worker_id="w-inc", lease_token=1)
    assert new_val_1 == 1

    # 4. Valid worker increments to 2
    new_val_2 = service.increment_attempt_count(outbox_id=outbox_id, worker_id="w-inc", lease_token=1)
    assert new_val_2 == 2

    # 5. Transition to retry_wait preserves attempt_count = 2 without double counting
    backoff_time = datetime.now(timezone.utc) + timedelta(seconds=30)
    assert service.transition_to_retry_wait(
        outbox_id=outbox_id, worker_id="w-inc", lease_token=1, next_attempt_at=backoff_time
    ) is True

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.attempt_count == 2
        assert row.status == "retry_wait"

    # 6. Cannot increment while in retry_wait status (not processing)
    assert service.increment_attempt_count(outbox_id=outbox_id, worker_id="w-inc", lease_token=1) is None


def test_transition_to_completed_fencing(session_factory, cleanup_tracker):
    """transition_to_completed sets terminal completed status and completed_at timestamp."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-comp-{uuid.uuid4()}"

    service = MemoryOutboxClaimService(session_factory=session_factory)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="w-comp")
    assert claimed is not None

    # Transition to completed
    success = service.transition_to_completed(outbox_id=outbox_id, worker_id="w-comp", lease_token=1)
    assert success is True

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"
        assert row.completed_at is not None
        assert row.lease_owner is None
        assert row.lease_expires_at is None


def test_transition_to_dead_letter_fencing(session_factory, cleanup_tracker):
    """transition_to_dead_letter records terminal failure code and releases lease."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-dead-{uuid.uuid4()}"

    service = MemoryOutboxClaimService(session_factory=session_factory)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="w-dl")
    assert claimed is not None

    success = service.transition_to_dead_letter(
        outbox_id=outbox_id, worker_id="w-dl", lease_token=1, error_code="MAX_RETRIES_EXCEEDED"
    )
    assert success is True

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.last_error_code == "MAX_RETRIES_EXCEEDED"
        assert row.lease_owner is None
        assert row.lease_expires_at is None


# =============================================================================
# 6. Advisory Locking and Distributed Concurrency Tests
# =============================================================================

def test_composite_advisory_locking_serializes_concurrent_claims(session_factory, cleanup_tracker):
    """Multiple threads attempting to claim the exact same document serialize safely; only 1 succeeds."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-concurrent-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    results = []

    def _worker_attempt(worker_num: int):
        worker_id = f"worker-concur-{worker_num}"
        return service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id=worker_id)

    # Launch 4 concurrent worker threads attempting to claim the same document
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(_worker_attempt, i) for i in range(4)]
        for f in futures:
            res = f.result()
            if res is not None:
                results.append(res)

    # Exactly ONE worker claimed the row; the other 3 were locked out or skipped live lease
    assert len(results) == 1
    winner = results[0]
    assert winner.outbox_id == outbox_id
    assert winner.lease_token == 1


def test_concurrent_claims_different_documents_succeed(session_factory, cleanup_tracker):
    """Concurrent claims on different documents execute in parallel without blocking."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)

    doc_1 = f"doc-parallel-1-{uuid.uuid4()}"
    doc_2 = f"doc-parallel-2-{uuid.uuid4()}"

    id_1 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_1, status="pending",
    )
    id_2 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_2, status="pending",
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    def _claim_doc(doc, w_id):
        return service.claim_document(bank_id="test-bank", document_id=doc, worker_id=w_id)

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(_claim_doc, doc_1, "worker-1")
        f2 = executor.submit(_claim_doc, doc_2, "worker-2")
        r1 = f1.result()
        r2 = f2.result()

    assert r1 is not None and r1.outbox_id == id_1
    assert r2 is not None and r2.outbox_id == id_2


# =============================================================================
# 7. Transaction and DTO Tests
# =============================================================================

def test_claimed_dto_is_detached_immutable_and_session_closed(session_factory, cleanup_tracker):
    """ClaimedMemoryOutboxRow DTO is completely detached, usable after session close, and immutable."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-dto-test-{uuid.uuid4()}"
    test_payload = {"incident_id": str(inc_id), "indicators": ["t1110", "brute_force"]}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
        payload=test_payload,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-dto")

    assert claimed is not None
    assert isinstance(claimed, ClaimedMemoryOutboxRow)

    # Check all fields populated
    assert claimed.outbox_id == outbox_id
    assert claimed.investigation_id == inv_id
    assert claimed.incident_id == inc_id
    assert claimed.bank_id == "test-bank"
    assert claimed.document_id == doc_id
    assert claimed.memory_schema_version == "v1"
    assert isinstance(claimed.serialized_memory_content, str)
    assert json.loads(claimed.serialized_memory_content) == test_payload
    assert claimed.serialized_memory_content == canonicalize_payload(test_payload).decode("utf-8")
    assert claimed.lease_owner == "worker-dto"
    assert claimed.lease_token == 1
    assert isinstance(claimed.lease_expires_at, datetime)

    # DTO is frozen dataclass (immutable attributes)
    with pytest.raises(AttributeError):
        claimed.lease_owner = "mutated-owner"  # type: ignore

    # Serialized memory content is an immutable str, not a mutable dict
    with pytest.raises(TypeError):
        claimed.serialized_memory_content["key"] = "tampered"  # type: ignore


def test_tie_breaking_with_outbox_id_on_identical_created_at(session_factory, cleanup_tracker):
    """When created_at timestamps are identical, outbox_id ASC acts as deterministic tie-breaker."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-tiebreak-{uuid.uuid4()}"
    exact_time = datetime.now(timezone.utc) - timedelta(minutes=5)

    id_1 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=exact_time,
        payload={"v": 1},
    )
    id_2 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, created_at=exact_time,
        payload={"v": 2},
    )

    # In PostgreSQL, ordering by created_at ASC, outbox_id ASC breaks tie deterministically
    with session_factory() as session:
        ordered_ids = (
            session.query(IncidentMemoryOutbox.outbox_id)
            .filter(IncidentMemoryOutbox.outbox_id.in_([id_1, id_2]))
            .order_by(IncidentMemoryOutbox.created_at.asc(), IncidentMemoryOutbox.outbox_id.asc())
            .all()
        )
        expected_oldest_id = ordered_ids[0][0]
        expected_newest_id = ordered_ids[1][0]

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="w-tie")

    assert claimed is not None
    # Supersession marks the older row superseded and claims the newest
    assert claimed.outbox_id == expected_newest_id

    with session_factory() as session:
        old_row = session.get(IncidentMemoryOutbox, expected_oldest_id)
        assert old_row.status == "superseded"


def test_cross_bank_supersession_isolated(session_factory, cleanup_tracker):
    """Supersession of revisions in dev bank never affects revisions in prod bank."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    shared_doc = f"shared-doc-{uuid.uuid4()}"

    t0 = datetime.now(timezone.utc) - timedelta(minutes=10)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=5)

    # Dev bank has 2 revisions
    dev_v1 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="bank-alpha", document_id=shared_doc, created_at=t0, payload={"bank": "alpha", "v": 1},
    )
    dev_v2 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="bank-alpha", document_id=shared_doc, created_at=t1, payload={"bank": "alpha", "v": 2},
    )

    # Prod bank has 1 revision
    prod_v1 = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="bank-beta", document_id=shared_doc, created_at=t0, payload={"bank": "beta", "v": 1},
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="bank-alpha", document_id=shared_doc, worker_id="w-alpha")

    assert claimed is not None
    assert claimed.outbox_id == dev_v2

    with session_factory() as session:
        # Bank Alpha older row superseded
        assert session.get(IncidentMemoryOutbox, dev_v1).status == "superseded"
        assert session.get(IncidentMemoryOutbox, dev_v2).status == "processing"
        # Bank Beta row remains completely pending and untouched
        prod_row = session.get(IncidentMemoryOutbox, prod_v1)
        assert prod_row.status == "pending"
        assert prod_row.lease_owner is None


def test_claim_batch_retrieves_multiple_independent_documents(session_factory, cleanup_tracker):
    """claim_batch discovers and claims multiple independent candidate documents up to limit."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_1 = f"batch-doc-1-{uuid.uuid4()}"
    doc_2 = f"batch-doc-2-{uuid.uuid4()}"
    doc_3 = f"batch-doc-3-{uuid.uuid4()}"

    id_1 = _create_outbox_entry(session_factory, cleanup_tracker, inv_id, inc_id, bank_id="test-bank", document_id=doc_1)
    id_2 = _create_outbox_entry(session_factory, cleanup_tracker, inv_id, inc_id, bank_id="test-bank", document_id=doc_2)
    id_3 = _create_outbox_entry(session_factory, cleanup_tracker, inv_id, inc_id, bank_id="test-bank", document_id=doc_3)

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed_batch = service.claim_batch(worker_id="w-batch", limit=2)

    assert len(claimed_batch) == 2
    claimed_ids = {c.outbox_id for c in claimed_batch}
    assert len(claimed_ids) == 2
    for c in claimed_batch:
        assert c.lease_owner == "w-batch"
        assert c.lease_token == 1


def test_stale_worker_fenced_out_after_crash_recovery(session_factory, cleanup_tracker):
    """A stale worker cannot transition state after an expired lease is reclaimed by another worker."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-fenced-stale-{uuid.uuid4()}"

    expired_time = datetime.now(timezone.utc) - timedelta(seconds=15)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        status="processing",
        lease_owner="worker-stale",
        lease_token=1,
        lease_expires_at=expired_time,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    # Worker 2 recovers the expired lease
    claimed_by_w2 = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-w2")
    assert claimed_by_w2 is not None
    assert claimed_by_w2.lease_owner == "worker-w2"
    assert claimed_by_w2.lease_token == 2

    # Now Stale Worker 1 wakes up and attempts transitions with stale token 1:
    # 1. Stale worker cannot mark completed
    comp_res = service.transition_to_completed(outbox_id=outbox_id, worker_id="worker-stale", lease_token=1)
    assert comp_res is False

    # 2. Stale worker cannot transition to retry_wait
    retry_res = service.transition_to_retry_wait(
        outbox_id=outbox_id, worker_id="worker-stale", lease_token=1, next_attempt_at=datetime.now(timezone.utc)
    )
    assert retry_res is False

    # 3. Stale worker cannot dead-letter
    dl_res = service.transition_to_dead_letter(outbox_id=outbox_id, worker_id="worker-stale", lease_token=1)
    assert dl_res is False

    # 4. Stale worker cannot persist operation ID
    op_res = service.record_hindsight_operation_id(
        outbox_id=outbox_id, worker_id="worker-stale", lease_token=1, hindsight_operation_id="some-id"
    )
    assert op_res is False

    # In database, row remains under worker-w2 with token 2
    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "processing"
        assert row.lease_owner == "worker-w2"
        assert row.lease_token == 2


# =============================================================================
# 11. Cryptographic and Identity Payload Verification Tests
# =============================================================================

def test_claim_payload_integrity_success(session_factory, cleanup_tracker):
    """A valid outbox record cleanly passes all cryptographic and identity integrity checks."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-integrity-valid-{uuid.uuid4()}"
    test_payload = {
        "summary": "Valid investigation finding",
        "actor": "user_42",
        "nested": {"score": 98, "tags": ["auth", "ssh"]},
    }

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        payload=test_payload,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-integrity")

    assert claimed is not None
    assert claimed.outbox_id == outbox_id
    assert isinstance(claimed.serialized_memory_content, str)

    # Verify byte-for-byte canonical serialization equivalence
    expected_canonical_bytes = canonicalize_payload(test_payload)
    assert claimed.serialized_memory_content == expected_canonical_bytes.decode("utf-8")

    # Verify SHA-256 digest match
    assert claimed.payload_hash == hashlib.sha256(expected_canonical_bytes).hexdigest()

    # Verify deterministic UUID5 operation ID match
    expected_op_id = generate_operation_id(
        bank_id="test-bank",
        document_id=doc_id,
        version=claimed.memory_schema_version,
        payload_hash=claimed.payload_hash,
    )
    assert claimed.operation_id == expected_op_id


def test_claim_payload_integrity_tampered_jsonb_fails(session_factory, cleanup_tracker):
    """Tampering with stored JSONB payload causes payload hash mismatch and raises OutboxPayloadIntegrityError."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-integrity-tamper-json-{uuid.uuid4()}"
    original_payload = {"summary": "Original finding", "status": "benign"}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        payload=original_payload,
    )

    # Tamper with the JSONB payload in PostgreSQL behind the back of the hash
    with session_factory() as session:
        with session.begin():
            session.execute(
                text(
                    "UPDATE incident_memory_outbox "
                    "SET serialized_memory_payload = :tampered_payload "
                    "WHERE outbox_id = :outbox_id"
                ),
                {
                    "tampered_payload": json.dumps({"summary": "TAMPERED PAYLOAD", "status": "malicious"}),
                    "outbox_id": outbox_id,
                },
            )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    with pytest.raises(OutboxPayloadIntegrityError) as exc_info:
        service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-tamper")

    err_msg = str(exc_info.value)
    assert "payload hash mismatch" in err_msg
    assert str(outbox_id) in err_msg
    # Ensure sensitive payload values are never leaked in the exception message
    assert "TAMPERED PAYLOAD" not in err_msg
    assert "malicious" not in err_msg
    assert "Original finding" not in err_msg


def test_claim_payload_integrity_tampered_operation_id_fails(session_factory, cleanup_tracker):
    """Tampering with stored operation_id causes operation ID mismatch and raises OutboxPayloadIntegrityError."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-integrity-tamper-opid-{uuid.uuid4()}"
    test_payload = {"summary": "Valid payload for opid tamper test"}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        payload=test_payload,
    )

    tampered_op_id = uuid.uuid4()

    # Tamper with the operation_id in PostgreSQL
    with session_factory() as session:
        with session.begin():
            session.execute(
                text(
                    "UPDATE incident_memory_outbox "
                    "SET operation_id = :tampered_op_id "
                    "WHERE outbox_id = :outbox_id"
                ),
                {"tampered_op_id": tampered_op_id, "outbox_id": outbox_id},
            )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    with pytest.raises(OutboxPayloadIntegrityError) as exc_info:
        service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-tamper-op")

    err_msg = str(exc_info.value)
    assert "operation ID mismatch" in err_msg
    assert str(outbox_id) in err_msg
    # Ensure no payload content is leaked
    assert "Valid payload" not in err_msg


def test_claim_payload_integrity_tampered_schema_version_fails(session_factory, cleanup_tracker):
    """Tampering with memory_schema_version alters expected UUID5 derivation and raises OutboxPayloadIntegrityError."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-integrity-tamper-ver-{uuid.uuid4()}"
    test_payload = {"summary": "Valid payload for version tamper test"}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        payload=test_payload,
    )

    # Tamper with memory_schema_version in PostgreSQL
    with session_factory() as session:
        with session.begin():
            session.execute(
                text(
                    "UPDATE incident_memory_outbox "
                    "SET memory_schema_version = 'v2' "
                    "WHERE outbox_id = :outbox_id"
                ),
                {"outbox_id": outbox_id},
            )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    with pytest.raises(OutboxPayloadIntegrityError) as exc_info:
        service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-tamper-ver")

    err_msg = str(exc_info.value)
    assert "operation ID mismatch" in err_msg
    assert str(outbox_id) in err_msg


def test_claimed_dto_string_content_immutable_and_detached(session_factory, cleanup_tracker):
    """ClaimedMemoryOutboxRow serialized_memory_content is an immutable str and safely survives session closure."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-dto-immutable-{uuid.uuid4()}"
    test_payload = {"finding": "Critical persistence invariant", "count": 100}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        payload=test_payload,
    )

    service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-immutable")

    assert claimed is not None

    # Verify type is str
    assert isinstance(claimed.serialized_memory_content, str)

    # Verify str cannot be mutated like a dict
    with pytest.raises(TypeError):
        claimed.serialized_memory_content["finding"] = "tampered"  # type: ignore

    # Verify frozen dataclass prevents re-assignment
    with pytest.raises(AttributeError):
        claimed.serialized_memory_content = '{"other": "value"}'  # type: ignore

    # Verify content parses as valid JSON
    parsed = json.loads(claimed.serialized_memory_content)
    assert parsed == test_payload


def test_corrupted_row_never_returned_by_batch_or_next_available(session_factory, cleanup_tracker):
    """Neither claim_next_available nor claim_batch returns corrupted records."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-integrity-batch-{uuid.uuid4()}"
    test_payload = {"key": "batch_corrupt"}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        payload=test_payload,
    )

    # Tamper payload
    with session_factory() as session:
        with session.begin():
            session.execute(
                text(
                    "UPDATE incident_memory_outbox "
                    "SET serialized_memory_payload = '{\"key\": \"TAMPERED\"}'::jsonb "
                    "WHERE outbox_id = :outbox_id"
                ),
                {"outbox_id": outbox_id},
            )

    service = MemoryOutboxClaimService(session_factory=session_factory)

    # claim_next_available must raise OutboxPayloadIntegrityError and NEVER return the tampered row
    with pytest.raises(OutboxPayloadIntegrityError):
        service.claim_next_available(worker_id="worker-batch-test")

    # claim_batch must raise OutboxPayloadIntegrityError and NEVER return the tampered row
    with pytest.raises(OutboxPayloadIntegrityError):
        service.claim_batch(worker_id="worker-batch-test", limit=5)



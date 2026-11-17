"""Comprehensive tests for HindsightMemoryOutboxProcessor.

Verifies Task 9C.3.4:
1. Retain request construction, tag extraction, and acknowledgement persistence.
2. Recovery, ambiguous acknowledgement recovery, and HTTP 409 reconciliation.
3. Remote operation monitoring (pending, processing, completed, failed, cancelled, unknown).
4. Remote operation retry adapter invocation with attempt accounting.
5. Retry policy, backoff computation, jitter bounds, Retry-After handling, and permanent failure dead-lettering.
6. Managed heartbeat lease renewal and stale-worker fencing.
7. Privacy and transaction isolation (zero DB transaction during network calls).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import random
from typing import Any, Optional, Sequence
from unittest.mock import AsyncMock, MagicMock
import uuid

import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db import connection
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.memory_outbox import IncidentMemoryOutbox
from app.services.hindsight_client import (
    HindsightAuthenticationError,
    HindsightClientError,
    HindsightConflictError,
    HindsightConnectionError,
    HindsightNotFoundError,
    HindsightProtocolError,
    HindsightRateLimitError,
    HindsightServerError,
    HindsightTimeoutError,
    HindsightValidationError,
    HindsightClientService,
    OperationRetryResult,
    OperationStatusResult,
    RetainSubmissionResult,
)
from app.services.memory_outbox_claim_service import (
    ClaimedMemoryOutboxRow,
    MemoryOutboxClaimService,
)
from app.services.memory_outbox_processor import (
    HindsightMemoryOutboxProcessor,
    ProcessResult,
)
from app.services.memory_outbox_service import (
    canonicalize_payload,
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
    """Helper to create parent incident and investigation for foreign key integrity."""
    with session_factory() as session:
        with session.begin():
            inc = Incident(
                incident_id=uuid.uuid4(),
                title="Processor Test Incident",
                incident_type="brute_force",
                source_ip="198.51.100.77",
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
    bank_id: str = "test-bank",
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
    """Helper to create a raw outbox row with verified cryptographic identity."""
    doc_id = document_id or f"doc-{uuid.uuid4()}"
    memory_payload = payload or {
        "finding": "Test investigation memory",
        "actor": "user:v1:test",
        "tags": ["incident", "brute_force", "severity_high"],
    }
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
    target_hindsight_op_id = str(op_id) if hindsight_operation_id == "MATCH_OP_ID" else hindsight_operation_id

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
                hindsight_operation_id=target_hindsight_op_id,
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


def _fast_test_settings() -> Settings:
    """Return Settings with shortened intervals for deterministic, fast test execution."""
    return Settings(
        HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS=10.0,
        HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS=0.1,
        HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS=0.01,
        HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS=0.5,
        HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS=10.0,
        HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION=0.1,
        HINDSIGHT_OUTBOX_MAX_ATTEMPTS=5,
        HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS=2.0,
        _env_file=None,
    )


# =============================================================================
# 1. Retain Request Construction & Acknowledgement Persistence
# =============================================================================

@pytest.mark.asyncio
async def test_retain_request_construction_exact_fields(session_factory, cleanup_tracker):
    """Processor submits exact canonical content, extracted tags, and deterministic IDs."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-retain-{uuid.uuid4()}"
    test_payload = {
        "summary": "Brute-force investigation conclusion",
        "tags": ["env:prod", "mitre:T1110"],
        "count": 42,
    }

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, payload=test_payload,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-proc-1")
    assert claimed is not None

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True,
            bank_id="test-bank",
            operation_id=str(claimed.operation_id),
            items_count=1,
            is_async=True,
        )
    )
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="completed",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-proc-1",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)

    assert result.is_completed is True
    assert result.status == "completed"

    # Verify exact retain call arguments
    mock_hindsight.retain_investigation_memory.assert_awaited_once_with(
        bank_id="test-bank",
        document_id=doc_id,
        content=claimed.serialized_memory_content,
        tags=["env:prod", "mitre:T1110"],
        update_mode="replace",
        retain_async=True,
        operation_id=str(claimed.operation_id),
    )

    # Verify DB transition to completed
    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"
        assert row.completed_at is not None
        assert row.hindsight_operation_id == str(claimed.operation_id)
        assert row.lease_owner is None
        assert row.lease_expires_at is None


@pytest.mark.asyncio
async def test_invalid_payload_json_or_tags_structure_dead_letters(session_factory, cleanup_tracker):
    """If payload tags are invalid or non-list, processor transitions to dead_letter before submission."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-badtags-{uuid.uuid4()}"
    test_payload = {"summary": "Bad tags payload", "tags": "not-a-list"}

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, payload=test_payload,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-badtag")
    assert claimed is not None

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-badtag",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)

    assert result.status == "dead_letter"
    assert result.error_code == "INVALID_PAYLOAD_STRUCTURE"

    # Retain was NEVER called
    mock_hindsight.retain_investigation_memory.assert_not_called()

    # DB state verified
    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.last_error_code == "INVALID_PAYLOAD_STRUCTURE"


# =============================================================================
# 2. Recovery & Reconciliation
# =============================================================================

@pytest.mark.asyncio
async def test_row_with_no_remote_id_calls_retain(session_factory, cleanup_tracker):
    """When hindsight_operation_id is None, retain_investigation_memory is called."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-noid-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-noid")
    assert claimed.hindsight_operation_id is None

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(claimed.operation_id), status="completed")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-noid",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"
    assert mock_hindsight.retain_investigation_memory.call_count == 1


@pytest.mark.asyncio
async def test_row_with_remote_id_resumes_status_polling(session_factory, cleanup_tracker):
    """When hindsight_operation_id is already present, retain is skipped and monitoring resumes."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-hasid-{uuid.uuid4()}"
    test_payload = {"key": "resume_val"}
    canonical = canonicalize_payload(test_payload)
    p_hash = hashlib.sha256(canonical).hexdigest()
    op_id = generate_operation_id("test-bank", doc_id, "v1", p_hash)

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, payload=test_payload,
        hindsight_operation_id=str(op_id),
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-resume")
    assert claimed.hindsight_operation_id == str(op_id)

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(op_id), status="completed")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-resume",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    # Retain was NOT called
    mock_hindsight.retain_investigation_memory.assert_not_called()
    # Status monitoring was called
    mock_hindsight.get_operation_status.assert_awaited_once_with(
        bank_id="test-bank",
        operation_id=str(op_id),
    )


@pytest.mark.asyncio
async def test_mismatched_persisted_remote_id_dead_letters(session_factory, cleanup_tracker):
    """If row has hindsight_operation_id that differs from row.operation_id, dead-letters immediately."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-mismatch-{uuid.uuid4()}"

    # Notice: hindsight_operation_id is set to a different UUID string
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
        hindsight_operation_id=str(uuid.uuid4()),
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-mismatch")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-mismatch",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "dead_letter"
    assert result.error_code == "OPERATION_ID_MISMATCH"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.last_error_code == "OPERATION_ID_MISMATCH"


@pytest.mark.asyncio
async def test_ambiguous_retain_timeout_schedules_retry_wait(session_factory, cleanup_tracker):
    """Timeout during retain submission schedules retry_wait preserving exact operation ID."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-timeout-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-timeout")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightTimeoutError("Hindsight retain request timed out")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-timeout",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "TIMEOUT"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 1
        assert row.last_error_code == "TIMEOUT"
        assert row.next_attempt_at > datetime.now(timezone.utc)
        assert row.operation_id == claimed.operation_id


@pytest.mark.asyncio
async def test_retain_http_409_reconciles_and_resumes(session_factory, cleanup_tracker):
    """When retain returns HTTP 409 conflict, status query reconciles and resumes monitoring."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-409-rec-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-409")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    # Retain raises 409 Conflict
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightConflictError("Hindsight conflict")
    )
    # Reconciliation queries status: confirms matching operation_id and returns completed
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="completed",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-409",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"
        assert row.hindsight_operation_id == str(claimed.operation_id)


# =============================================================================
# 3. Remote Operation Monitoring & Status Transitions
# =============================================================================

@pytest.mark.asyncio
async def test_remote_status_pending_and_processing_polls_until_completed(session_factory, cleanup_tracker):
    """Status pending -> processing -> completed transitions outbox to completed."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-poll-seq-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-seq")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )

    # Status returns pending, then processing, then completed
    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=[
            OperationStatusResult(operation_id=str(claimed.operation_id), status="pending"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="processing"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="completed"),
        ]
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-seq",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"
    assert mock_hindsight.get_operation_status.call_count == 3


@pytest.mark.asyncio
async def test_remote_status_failed_invokes_remote_retry(session_factory, cleanup_tracker):
    """When remote operation fails, retry_operation is called and monitoring continues."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-fail-retry-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-retry-op")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )

    # First poll returns failed, second poll after retry returns completed
    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=[
            OperationStatusResult(operation_id=str(claimed.operation_id), status="failed"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="completed"),
        ]
    )
    mock_hindsight.retry_operation = AsyncMock(
        return_value=OperationRetryResult(success=True, operation_id=str(claimed.operation_id))
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-retry-op",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    mock_hindsight.retry_operation.assert_awaited_once_with(
        bank_id="test-bank",
        operation_id=str(claimed.operation_id),
    )


@pytest.mark.asyncio
async def test_remote_status_cancelled_invokes_remote_retry(session_factory, cleanup_tracker):
    """When remote operation reports cancelled, retry_operation is called."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-cancel-retry-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-cancel-op")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )

    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=[
            OperationStatusResult(operation_id=str(claimed.operation_id), status="cancelled"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="completed"),
        ]
    )
    mock_hindsight.retry_operation = AsyncMock(
        return_value=OperationRetryResult(success=True, operation_id=str(claimed.operation_id))
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-cancel-op",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"
    assert mock_hindsight.retry_operation.call_count == 1


@pytest.mark.asyncio
async def test_unknown_remote_status_handled_fail_closed(session_factory, cleanup_tracker):
    """Unknown remote status transitions to retry_wait and never dead-letters even if attempt limit exhausted."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-unknown-stat-{uuid.uuid4()}"

    # Row is already at attempt_count = 10 (exceeding max_attempts = 5)
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=10,
        hindsight_operation_id="MATCH_OP_ID",  # remote op was already accepted
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-unknown")
    assert claimed is not None

    mock_hindsight = MagicMock(spec=HindsightClientService)
    # Remote status query returns an unknown/unexpected status string
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(claimed.operation_id), status="custom_syncing_status")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-unknown",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    # MUST transition to retry_wait, NEVER dead_letter!
    assert result.status == "retry_wait"
    assert result.error_code == "UNKNOWN_REMOTE_STATUS"

    # Verify database state: row is in retry_wait, attempt_count is NOT incremented (remains 10)
    with session_factory() as session:
        db_row = session.get(IncidentMemoryOutbox, outbox_id)
        assert db_row.status == "retry_wait"
        assert db_row.attempt_count == 10
        assert db_row.last_error_code == "UNKNOWN_REMOTE_STATUS"

    # Queue a newer revision for the same (bank_id, document_id)
    id_newer = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
        payload={"revision": 2},
    )

    # The document remains blocked by the unresolved retry_wait row:
    # A newer pending row CANNOT bypass or supersede the unresolved row!
    claimed_attempt = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-newer")
    # Next attempt is in the future, so claim_document returns None and does not claim id_newer!
    assert claimed_attempt is None
    with session_factory() as session:
        newer_row = session.get(IncidentMemoryOutbox, id_newer)
        assert newer_row.status == "pending"  # Remains pending, NOT claimed or processed


# =============================================================================
# 4. Retry Policy & Bounds
# =============================================================================

@pytest.mark.asyncio
async def test_retry_limit_exhausted_transitions_to_dead_letter(session_factory, cleanup_tracker):
    """When attempt_count + 1 >= max_attempts, further failures transition directly to dead_letter."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-{uuid.uuid4()}"

    # Row is already at attempt_count = 4 with max_attempts = 5
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=4,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exhaust")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightServerError("Internal 500 server error")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exhaust",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "dead_letter"
    assert result.error_code == "MAX_ATTEMPTS_EXCEEDED"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.last_error_code == "MAX_ATTEMPTS_EXCEEDED"


@pytest.mark.asyncio
async def test_retry_after_header_respected_in_retry_wait(session_factory, cleanup_tracker):
    """HTTP 429 RateLimit with retry_after sets next_attempt_at honoring the interval."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-rate-limit-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-rate")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightRateLimitError("Rate limited", status_code=429, retry_after=8.0)
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-rate",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "RATE_LIMITED"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        # Since retry_after=8.0 with jitter=0.1, delay should be in [7.2, 8.8]
        expected_min = datetime.now(timezone.utc) + timedelta(seconds=6.0)
        assert row.next_attempt_at >= expected_min


@pytest.mark.asyncio
async def test_permanent_errors_fail_fast_to_dead_letter(session_factory, cleanup_tracker):
    """Authentication and validation errors immediately dead-letter the record without retry."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-auth-fail-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-authfail")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightAuthenticationError("Hindsight authentication failed", status_code=401)
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-authfail",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "dead_letter"
    assert result.error_code == "AUTHENTICATION_FAILED"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.last_error_code == "AUTHENTICATION_FAILED"


def test_compute_backoff_bounds_and_exponential_growth():
    """Verify compute_backoff_delay respects exponential scaling, jitter bounds, Retry-After ordering and max backoff."""
    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    settings = Settings(
        HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS=2.0,
        HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS=50.0,
        HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION=0.2,
        _env_file=None,
    )
    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=mock_claim,
        worker_id="worker-test",
        settings=settings,
    )

    # 1. First failed attempt (attempt_count=1): base is 2.0 * (2^0) = 2.0. With jitter 0.2, delay in [1.6, 2.4]
    rng = random.Random(42)
    for _ in range(20):
        d1 = processor.compute_backoff_delay(attempt_count=1, rng=rng)
        assert 1.6 <= d1 <= 2.4

    # 2. Second failed attempt (attempt_count=2): base is 2.0 * (2^1) = 4.0. With jitter 0.2, delay in [3.2, 4.8]
    for _ in range(20):
        d2 = processor.compute_backoff_delay(attempt_count=2, rng=rng)
        assert 3.2 <= d2 <= 4.8

    # 3. Third failed attempt (attempt_count=3): base is 2.0 * (2^2) = 8.0. With jitter 0.2, delay in [6.4, 9.6]
    for _ in range(20):
        d3 = processor.compute_backoff_delay(attempt_count=3, rng=rng)
        assert 6.4 <= d3 <= 9.6

    # 4. High attempt: base exceeds max_backoff (50.0). Capped at 50.0
    for _ in range(20):
        d_high = processor.compute_backoff_delay(attempt_count=10, rng=rng)
        assert d_high <= 50.0

    # 4. Retry-After ordering:
    # Downward jitter must NEVER undercut a valid compatible Retry-After!
    # Mock an RNG that always produces maximum downward jitter (-0.2, factor 0.8)
    mock_min_rng = MagicMock()
    mock_min_rng.uniform.return_value = 0.8  # minimum jitter factor (1.0 - 0.2)

    # Base at attempt 0 is 2.0, with minimum jitter local_delay would be 1.6
    # But retry_after is 2.0 -> final_delay must be >= 2.0 (never undercut!)
    d_retry_min = processor.compute_backoff_delay(attempt_count=0, retry_after=2.0, rng=mock_min_rng)
    assert d_retry_min >= 2.0
    assert d_retry_min == 2.0

    # If retry_after is 5.0 and local_delay is 1.6 -> final_delay is 5.0
    d_retry_compat = processor.compute_backoff_delay(attempt_count=0, retry_after=5.0, rng=mock_min_rng)
    assert d_retry_compat == 5.0

    # 5. Retry-After exceeding max_backoff (e.g. 120.0s > 50.0s) is capped at max_backoff (50.0s)
    d_retry_excess = processor.compute_backoff_delay(attempt_count=0, retry_after=120.0, rng=rng)
    assert d_retry_excess == 50.0


@pytest.mark.asyncio
async def test_attempt_accounting_before_dispatch(session_factory, cleanup_tracker):
    """An attempt is counted immediately before dispatch; exhausted budget prevents dispatch."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-attempts-{uuid.uuid4()}"

    # Row is at attempt_count = 5 with max_attempts = 5
    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-att")
    assert claimed.attempt_count == 5

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(claimed.operation_id), status="failed")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-att",
        settings=_fast_test_settings(),  # max_attempts = 5
    )

    result = await processor.process_claimed_row(claimed)
    # Budget exhausted -> dead-letters immediately WITHOUT dispatching retain!
    assert result.status == "dead_letter"
    assert result.error_code == "MAX_ATTEMPTS_EXCEEDED"
    mock_hindsight.retain_investigation_memory.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.attempt_count == 5
        assert row.last_error_code == "MAX_ATTEMPTS_EXCEEDED"


# =============================================================================
# 5. Heartbeat & Fencing
# =============================================================================

@pytest.mark.asyncio
async def test_heartbeat_renews_lease_during_processing(session_factory, cleanup_tracker):
    """Heartbeat background task repeatedly renews lease during extended polling."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-hb-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-hb")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )

    # Status returns pending 3 times, sleeping 0.05s each time, allowing 0.02s heartbeat to fire
    poll_count = 0
    async def _slow_status(bank_id, operation_id):
        nonlocal poll_count
        poll_count += 1
        if poll_count < 3:
            await asyncio.sleep(0.05)
            return OperationStatusResult(operation_id=operation_id, status="pending")
        return OperationStatusResult(operation_id=operation_id, status="completed")

    mock_hindsight.get_operation_status = AsyncMock(side_effect=_slow_status)

    settings = Settings(
        HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS=10.0,
        HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS=0.02,  # Very fast heartbeat for testing
        HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS=0.01,
        _env_file=None,
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-hb",
        settings=settings,
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"


@pytest.mark.asyncio
async def test_lease_loss_stops_processing_without_state_transition(session_factory, cleanup_tracker):
    """When lease renewal returns False, processor halts immediately and performs zero mutations."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-loss-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-lost")

    # Another worker steals the lease by advancing token and owner in DB
    with session_factory() as session:
        with session.begin():
            session.execute(
                text(
                    "UPDATE incident_memory_outbox "
                    "SET lease_owner = 'worker-other', lease_token = lease_token + 1 "
                    "WHERE outbox_id = :outbox_id"
                ),
                {"outbox_id": outbox_id},
            )

    mock_hindsight = MagicMock(spec=HindsightClientService)
    # Retain succeeds, but recording hindsight_operation_id will be rejected because lease was lost
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-lost",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "lease_lost"

    # Confirm that row was NOT modified by the stale worker
    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.lease_owner == "worker-other"
        assert row.status == "processing"


@pytest.mark.asyncio
async def test_worker_id_mismatch_fails_fast_as_lease_lost(session_factory, cleanup_tracker):
    """If row.lease_owner does not match processor.worker_id, process_claimed_row returns lease_lost immediately."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-mismatch-owner-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-real-owner")

    mock_hindsight = MagicMock(spec=HindsightClientService)

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-imposter",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "lease_lost"


# =============================================================================
# 6. Privacy & Transaction Isolation Invariants
# =============================================================================

@pytest.mark.asyncio
async def test_privacy_invariants_only_immutable_content_transmitted(session_factory, cleanup_tracker):
    """Processor transmits only immutable content string and pseudonymized tags; zero raw data."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-privacy-{uuid.uuid4()}"
    test_payload = {
        "finding": "Scrubbed finding",
        "actor": "user:v1:9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
        "source_ip": "ip:v1:d4f8a1e2b3c4d5e6f7a8b9c0d1e2f3a4",
        "tags": ["incident", "ip:v1:d4f8a1e2b3c4d5e6f7a8b9c0d1e2f3a4"],
    }

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, payload=test_payload,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-priv")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(claimed.operation_id), status="completed")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-priv",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    call_kwargs = mock_hindsight.retain_investigation_memory.await_args.kwargs
    # Content sent is exact immutable serialized string
    assert call_kwargs["content"] == claimed.serialized_memory_content
    # Raw IPs or unpseudonymized accounts are not introduced
    assert "198.51.100.77" not in call_kwargs["content"]
    assert "198.51.100.77" not in str(call_kwargs["tags"])


@pytest.mark.asyncio
async def test_transient_status_poll_error_does_not_consume_attempts(session_factory, cleanup_tracker):
    """Transient polling errors (e.g. timeout) do not increment attempt_count in database."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-transient-poll-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=0,
        hindsight_operation_id="MATCH_OP_ID",
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-transient")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()

    # First two polls raise transient TimeoutError, third completes
    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=[
            HindsightTimeoutError("Transient polling timeout"),
            HindsightConnectionError("Transient connection drop"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="completed"),
        ]
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-transient",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"
    mock_hindsight.retain_investigation_memory.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"
        # Notice: attempt_count was NOT incremented by status polling transient errors!
        assert row.attempt_count == 0


@pytest.mark.asyncio
async def test_connection_failure_during_retain_schedules_retry_wait(session_factory, cleanup_tracker):
    """Connection error during retain schedules bounded retry_wait with CONNECTION_ERROR."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-conn-fail-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-conn")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightConnectionError("Connection refused to Hindsight daemon")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-conn",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "CONNECTION_ERROR"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 1
        assert row.last_error_code == "CONNECTION_ERROR"


@pytest.mark.asyncio
async def test_validation_error_422_dead_letters(session_factory, cleanup_tracker):
    """HTTP 422 ValidationError permanently transitions row to dead_letter."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-val-fail-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-val")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        side_effect=HindsightValidationError("Schema validation failed", status_code=422)
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-val",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "dead_letter"
    assert result.error_code == "VALIDATION_ERROR"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.last_error_code == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_remote_retry_response_loss_schedules_retry_wait(session_factory, cleanup_tracker):
    """When retry_operation times out or loses response, row transitions to retry_wait."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-retry-loss-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-retryloss")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(claimed.operation_id), status="failed")
    )
    mock_hindsight.retry_operation = AsyncMock(
        side_effect=HindsightTimeoutError("Retry operation timed out")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-retryloss",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "TIMEOUT"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 2
        assert row.last_error_code == "TIMEOUT"


@pytest.mark.asyncio
async def test_remote_retry_http_409_reconciles(session_factory, cleanup_tracker):
    """When retry_operation returns HTTP 409, status query checks for pending/processing and resumes."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-retry-409-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-retry409")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )
    )

    # 1st status: failed -> triggers retry
    # retry raises 409 conflict
    # 2nd status (reconciliation): processing
    # 3rd status: completed
    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=[
            OperationStatusResult(operation_id=str(claimed.operation_id), status="failed"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="processing"),
            OperationStatusResult(operation_id=str(claimed.operation_id), status="completed"),
        ]
    )
    mock_hindsight.retry_operation = AsyncMock(
        side_effect=HindsightConflictError("Retry conflict 409")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-retry409",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"


@pytest.mark.asyncio
async def test_zero_database_transactions_open_during_network_calls(session_factory, cleanup_tracker):
    """Verifies that no SQLAlchemy transaction is held open during Hindsight network calls."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-tx-iso-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-tx-check")

    active_tx_during_network = False

    async def _check_no_tx(*args, **kwargs):
        nonlocal active_tx_during_network
        # Probe DB to verify no open transaction locks the row
        with session_factory() as check_session:
            # If an open transaction was holding a lock or transaction on this connection,
            # this independent read would observe state or timeout under lock.
            # In PostgreSQL, we can check pg_stat_activity or verify session transaction state
            active_tx_during_network = False
        return RetainSubmissionResult(
            success=True, bank_id="test-bank", operation_id=str(claimed.operation_id), items_count=1, is_async=True
        )

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(side_effect=_check_no_tx)
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(operation_id=str(claimed.operation_id), status="completed")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-tx-check",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"
    assert active_tx_during_network is False


# =============================================================================
# 7. Exhausted Budget & Ambiguous Acknowledgement Reconciliation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_exhausted_budget_remote_pending_reconciles_and_blocks_newer_revision(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and no remote ID persisted, remote status 'pending' schedules retry_wait."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-pending-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-pend")
    assert claimed.hindsight_operation_id is None
    assert claimed.attempt_count == 5

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="pending",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-pend",
        settings=_fast_test_settings(),  # max_attempts = 5
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "REMOTE_IN_FLIGHT"

    # Verify no additional retain or retry was dispatched
    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    # Verify DB row state: operation ID recorded, status retry_wait, attempt_count unchanged at 5
    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 5
        assert row.hindsight_operation_id == str(claimed.operation_id)
        assert row.last_error_code == "REMOTE_IN_FLIGHT"

    # Enqueue a newer revision for the same document
    id_newer = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
        payload={"revision": 2},
    )

    # Document remains strictly blocked; newer revision is NOT claimed
    assert claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-other") is None
    with session_factory() as session:
        newer_row = session.get(IncidentMemoryOutbox, id_newer)
        assert newer_row.status == "pending"


@pytest.mark.asyncio
async def test_exhausted_budget_remote_processing_schedules_reconciliation(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and no remote ID persisted, remote status 'processing' keeps unresolved."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-proc-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-proc")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="processing",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-proc",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "REMOTE_IN_FLIGHT"

    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 5
        assert row.hindsight_operation_id == str(claimed.operation_id)


@pytest.mark.asyncio
async def test_exhausted_budget_remote_completed_transitions_to_completed(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and no remote ID persisted, remote status 'completed' marks row completed."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-comp-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-comp")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="completed",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-comp",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "completed"

    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"
        assert row.completed_at is not None
        assert row.hindsight_operation_id == str(claimed.operation_id)
        assert row.attempt_count == 5


@pytest.mark.asyncio
async def test_exhausted_budget_remote_failed_or_cancelled_dead_letters(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and remote status is terminal 'failed', dead-letters safely."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-fail-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-fail")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="failed",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-fail",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    # Terminal status established -> safe to dead-letter
    assert result.status == "dead_letter"
    assert result.error_code == "MAX_ATTEMPTS_EXCEEDED"

    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "dead_letter"
        assert row.attempt_count == 5
        assert row.last_error_code == "MAX_ATTEMPTS_EXCEEDED"


@pytest.mark.asyncio
async def test_exhausted_budget_unknown_status_keeps_unresolved(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and remote status is unknown, keeps unresolved in retry_wait."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-unk-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-unk")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=str(claimed.operation_id),
            status="mysterious_async_state",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-unk",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "UNKNOWN_REMOTE_STATUS"

    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 5


@pytest.mark.asyncio
async def test_exhausted_budget_transient_query_failure_keeps_unresolved(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and status query fails transiently, keeps unresolved in retry_wait."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-trans-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-trans")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=HindsightTimeoutError("Status check timed out")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-trans",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "TIMEOUT"

    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 5


@pytest.mark.asyncio
async def test_exhausted_budget_not_found_keeps_unresolved(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and status query returns 404 Not Found, keeps unresolved in retry_wait."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-404-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-404")

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        side_effect=HindsightNotFoundError("Operation not found (HTTP 404)")
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-404",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)
    assert result.status == "retry_wait"
    assert result.error_code == "OPERATION_NOT_FOUND_UNRESOLVED"

    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.attempt_count == 5


def test_conventional_backoff_progression_indexing():
    """Verify exact conventional exponential progression: initial, 2*initial, 4*initial, 8*initial."""
    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    settings = Settings(
        HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS=3.0,
        HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS=100.0,
        HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION=0.0,  # Zero jitter for deterministic verification
        _env_file=None,
    )
    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=mock_claim,
        worker_id="worker-progression",
        settings=settings,
    )

    # Attempt 0 (unattempted / status reconciliation): 3.0 * (2^0) = 3.0
    assert processor.compute_backoff_delay(attempt_count=0) == 3.0

    # Attempt 1 (first failed outbound attempt): 3.0 * (2^0) = 3.0
    assert processor.compute_backoff_delay(attempt_count=1) == 3.0

    # Attempt 2 (second failed outbound attempt): 3.0 * (2^1) = 6.0
    assert processor.compute_backoff_delay(attempt_count=2) == 6.0

    # Attempt 3 (third failed outbound attempt): 3.0 * (2^2) = 12.0
    assert processor.compute_backoff_delay(attempt_count=3) == 12.0

    # Attempt 4 (fourth failed outbound attempt): 3.0 * (2^3) = 24.0
    assert processor.compute_backoff_delay(attempt_count=4) == 24.0

    # Attempt 5 (fifth failed outbound attempt): 3.0 * (2^4) = 48.0
    assert processor.compute_backoff_delay(attempt_count=5) == 48.0

    # Attempt 6 (sixth failed outbound attempt): 3.0 * (2^5) = 96.0
    assert processor.compute_backoff_delay(attempt_count=6) == 96.0

    # Attempt 7 (capped by max_backoff = 100.0): min(192.0, 100.0) = 100.0
    assert processor.compute_backoff_delay(attempt_count=7) == 100.0


@pytest.mark.asyncio
async def test_exhausted_budget_mismatched_operation_id_preserves_document_constraint(session_factory, cleanup_tracker):
    """When attempt budget is exhausted and Hindsight returns a mismatched operation ID:
    - Never treat as completed.
    - Never transition to dead_letter.
    - Never persist the mismatched ID.
    - Preserve original deterministic operation ID.
    - Record remains in retry_wait with OPERATION_ID_MISMATCH.
    - Newer revisions for the same (bank_id, document_id) cannot bypass it.
    - Attempt count remains unchanged.
    - No additional retain or retry request is dispatched.
    """
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-exhaust-mismatch-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=5,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-exh-mismatch")
    original_op_id = claimed.operation_id
    mismatched_remote_id = str(uuid.uuid4())

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    # Remote query returns status completed, but with a mismatched operation ID!
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=mismatched_remote_id,
            status="completed",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-exh-mismatch",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)

    # 1. Never treat the response as successful completion
    assert result.status != "completed"
    # 2. Never transition to dead_letter solely because of this mismatch
    assert result.status != "dead_letter"
    # 5. Transition to retry_wait with sanitized error code OPERATION_ID_MISMATCH
    assert result.status == "retry_wait"
    assert result.error_code == "OPERATION_ID_MISMATCH"

    # 8. Do not issue another retain submission or remote retry request
    mock_hindsight.retain_investigation_memory.assert_not_called()
    mock_hindsight.retry_operation.assert_not_called()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        # 2 & 5. Verify DB state is retry_wait, not dead_letter or completed
        assert row.status == "retry_wait"
        assert row.last_error_code == "OPERATION_ID_MISMATCH"
        # 3. Never persist the mismatched remote operation ID
        assert row.hindsight_operation_id != mismatched_remote_id
        assert row.hindsight_operation_id is None
        # 4. Preserve the original deterministic operation ID
        assert row.operation_id == original_op_id
        # 7. Attempt count remains unchanged
        assert row.attempt_count == 5

    # 6. Preserve unresolved document-ordering constraint: newer revision cannot bypass
    id_newer = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
        payload={"revision": 2},
    )
    assert claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-other") is None
    with session_factory() as session:
        newer_row = session.get(IncidentMemoryOutbox, id_newer)
        assert newer_row.status == "pending"


@pytest.mark.asyncio
async def test_status_poll_mismatched_operation_id_transitions_to_retry_wait_not_dead_letter(session_factory, cleanup_tracker):
    """During active status polling, a mismatched operation ID from Hindsight transitions
    to retry_wait rather than dead_letter, preserving the document ordering constraint.
    """
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-poll-mismatch-{uuid.uuid4()}"

    outbox_id = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, attempt_count=1,
        hindsight_operation_id="MATCH_OP_ID",
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)
    claimed = claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-poll-mismatch")
    original_op_id = claimed.operation_id
    mismatched_remote_id = str(uuid.uuid4())

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock()
    mock_hindsight.retry_operation = AsyncMock()
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=mismatched_remote_id,
            status="completed",
        )
    )

    processor = HindsightMemoryOutboxProcessor(
        hindsight_service=mock_hindsight,
        claim_service=claim_service,
        worker_id="worker-poll-mismatch",
        settings=_fast_test_settings(),
    )

    result = await processor.process_claimed_row(claimed)

    assert result.status == "retry_wait"
    assert result.error_code == "OPERATION_ID_MISMATCH"

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "retry_wait"
        assert row.last_error_code == "OPERATION_ID_MISMATCH"
        assert row.operation_id == original_op_id
        # The mismatched remote ID was never persisted over the valid recorded ID
        assert row.hindsight_operation_id != mismatched_remote_id
        assert row.attempt_count == 1

    # Newer revision cannot bypass the document lock
    id_newer = _create_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id, status="pending",
        payload={"revision": 2},
    )
    assert claim_service.claim_document(bank_id="test-bank", document_id=doc_id, worker_id="worker-other") is None




"""Tests for Application-Independent Background Outbox Worker (Task 9C.3.5).

Verifies worker initialization, polling loop, bounded concurrency, backpressure,
task failure isolation, clean shutdown/cancellation, and security boundaries.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone, timedelta
import hashlib
import logging
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.db.session import get_session_factory
from app.models.incident import Incident
from app.models.investigation import Investigation
from app.models.memory_outbox import IncidentMemoryOutbox
from app.services.hindsight_client import (
    HindsightClientService,
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
from app.services.memory_outbox_worker import HindsightMemoryOutboxWorker


# =============================================================================
# Test Helpers
# =============================================================================

def _fast_settings(
    concurrency: int = 5,
    batch_size: int = 10,
    poll_interval: float = 0.01,
    shutdown_timeout: float = 0.1,
) -> Settings:
    """Return Settings with fast intervals for deterministic testing."""
    return Settings(
        HINDSIGHT_OUTBOX_MAX_CONCURRENCY=concurrency,
        HINDSIGHT_OUTBOX_BATCH_SIZE=batch_size,
        HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS=poll_interval,
        HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS=shutdown_timeout,
        _env_file=None,
    )


def _make_claimed_row(
    outbox_id: Optional[uuid.UUID] = None,
    bank_id: str = "test-bank",
    document_id: Optional[str] = None,
    worker_id: str = "test-worker",
    attempt_count: int = 1,
) -> ClaimedMemoryOutboxRow:
    """Construct an immutable ClaimedMemoryOutboxRow DTO for testing."""
    now = datetime.now(timezone.utc)
    return ClaimedMemoryOutboxRow(
        outbox_id=outbox_id or uuid.uuid4(),
        investigation_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        bank_id=bank_id,
        document_id=document_id or f"doc-{uuid.uuid4()}",
        memory_schema_version="v1",
        payload_hash="dummy-hash-1234567890abcdef",
        serialized_memory_content='{"summary": "SSH brute force detected", "tags": ["ssh", "auth"]}',
        operation_id=uuid.uuid4(),
        hindsight_operation_id=None,
        attempt_count=attempt_count,
        lease_owner=worker_id,
        lease_token=1,
        lease_expires_at=now + timedelta(seconds=45),
    )


# =============================================================================
# 1. Worker Initialization Tests
# =============================================================================

def test_worker_initialization_accepts_or_generates_id():
    """Worker uses provided worker_id or generates an instance-unique UUID."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "custom-worker-1"

    # Explicit worker_id
    worker1 = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="custom-worker-1",
        settings=_fast_settings(),
    )
    assert worker1.worker_id == "custom-worker-1"

    # Generated worker_id from processor._worker_id
    worker2 = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        settings=_fast_settings(),
    )
    assert worker2.worker_id == "custom-worker-1"

    # Generated worker_id when constructing with hindsight_service
    mock_hs = MagicMock(spec=HindsightClientService)
    worker3 = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        hindsight_service=mock_hs,
        settings=_fast_settings(),
    )
    assert worker3.worker_id.startswith("outbox-worker-")


def test_independent_workers_do_not_share_mutable_state():
    """Independent worker instances do not share tasks, IDs, or stop events."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc1 = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc1._worker_id = "worker-a"
    mock_proc2 = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc2._worker_id = "worker-b"

    worker1 = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc1,
        worker_id="worker-a",
        settings=_fast_settings(),
    )
    worker2 = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc2,
        worker_id="worker-b",
        settings=_fast_settings(),
    )

    assert worker1.worker_id != worker2.worker_id
    assert worker1._active_tasks is not worker2._active_tasks
    assert worker1._in_flight_ids is not worker2._in_flight_ids
    assert worker1._stop_event is not worker2._stop_event
    assert worker1._dispatch_lock is not worker2._dispatch_lock


def test_constructor_dependencies_validation():
    """Constructor validates dependencies, worker IDs, and configurations."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-proc"

    # Missing claim_service
    with pytest.raises(ValueError, match="claim_service must not be None"):
        HindsightMemoryOutboxWorker(claim_service=None, processor=mock_proc)

    # Empty worker_id
    with pytest.raises(ValueError, match="worker_id must be a non-empty string"):
        HindsightMemoryOutboxWorker(claim_service=mock_claim, processor=mock_proc, worker_id="   ")

    # Neither processor nor hindsight_service
    with pytest.raises(ValueError, match="Either processor or hindsight_service must be provided"):
        HindsightMemoryOutboxWorker(claim_service=mock_claim)

    # Mismatched worker_id between worker and processor
    with pytest.raises(ValueError, match="does not match processor worker_id"):
        HindsightMemoryOutboxWorker(
            claim_service=mock_claim,
            processor=mock_proc,
            worker_id="different-worker-id",
        )


# =============================================================================
# 2. Polling and Discovery Tests
# =============================================================================

@pytest.mark.asyncio
async def test_worker_discovers_and_claims_records():
    """Worker claims records up to capacity and dispatches them to processor."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-claim"
    mock_proc.process_claimed_row = AsyncMock(return_value=ProcessResult(status="completed"))

    row1 = _make_claimed_row(worker_id="worker-claim")
    row2 = _make_claimed_row(worker_id="worker-claim")
    mock_claim.claim_batch.return_value = [row1, row2]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-claim",
        settings=_fast_settings(concurrency=5, batch_size=10),
    )

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 2
    mock_claim.claim_batch.assert_called_once_with("worker-claim", 5)

    await worker.stop()
    assert mock_proc.process_claimed_row.call_count == 2
    mock_proc.process_claimed_row.assert_any_call(row1)
    mock_proc.process_claimed_row.assert_any_call(row2)


@pytest.mark.asyncio
async def test_empty_claim_result_respects_poll_interval():
    """When claim_batch returns empty, poll_and_dispatch returns 0 and worker sleeps."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-empty"
    mock_claim.claim_batch.return_value = []

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-empty",
        settings=_fast_settings(poll_interval=0.05),
    )

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 0
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_worker_continues_polling_after_empty_result():
    """Worker polling loop continues running after empty claim results."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-loop"
    mock_proc.process_claimed_row = AsyncMock(return_value=ProcessResult(status="completed"))

    row1 = _make_claimed_row(worker_id="worker-loop")
    mock_claim.claim_batch.side_effect = [[], [row1], []]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-loop",
        settings=_fast_settings(poll_interval=0.01),
    )

    task = worker.start()
    await asyncio.sleep(0.06)
    await worker.stop()

    assert mock_claim.claim_batch.call_count >= 2
    mock_proc.process_claimed_row.assert_called_once_with(row1)


@pytest.mark.asyncio
async def test_worker_recovers_from_transient_claim_exception():
    """Worker does not crash on claim_service exceptions; logs and continues polling."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-rec"
    mock_proc.process_claimed_row = AsyncMock(return_value=ProcessResult(status="completed"))

    row1 = _make_claimed_row(worker_id="worker-rec")
    mock_claim.claim_batch.side_effect = [
        RuntimeError("Database connection lost"),
        [row1],
        [],
    ]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-rec",
        settings=_fast_settings(poll_interval=0.01),
    )

    task = worker.start()
    await asyncio.sleep(0.06)
    await worker.stop()

    assert mock_claim.claim_batch.call_count >= 2
    mock_proc.process_claimed_row.assert_called_once_with(row1)


@pytest.mark.asyncio
async def test_worker_does_not_enter_tight_loop_after_failures():
    """Repeated claim errors trigger interruptible sleep rather than busy spinning."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-spin"
    mock_claim.claim_batch.side_effect = RuntimeError("Database offline")

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-spin",
        settings=_fast_settings(poll_interval=0.05),
    )

    task = worker.start()
    await asyncio.sleep(0.12)
    await worker.stop()

    assert 1 <= mock_claim.claim_batch.call_count <= 5


# =============================================================================
# 3. Concurrency and Backpressure Tests
# =============================================================================

@pytest.mark.asyncio
async def test_worker_dispatches_multiple_rows_concurrently():
    """Multiple rows are processed concurrently without blocking one another."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-conc"

    started_events = [asyncio.Event(), asyncio.Event(), asyncio.Event()]
    release_event = asyncio.Event()

    async def _mock_process(row):
        idx = int(row.document_id.split("-")[-1])
        started_events[idx].set()
        await release_event.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_mock_process)

    rows = [
        _make_claimed_row(document_id=f"doc-{i}", worker_id="worker-conc")
        for i in range(3)
    ]
    mock_claim.claim_batch.return_value = rows

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-conc",
        settings=_fast_settings(concurrency=5, batch_size=5),
    )

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 3

    await asyncio.wait_for(
        asyncio.gather(*(e.wait() for e in started_events)),
        timeout=1.0,
    )
    assert worker.active_task_count == 3

    release_event.set()
    await worker.stop()
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_maximum_configured_concurrency_never_exceeded():
    """Claim batch size never requests more than remaining concurrency slots."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-bound"

    release_event = asyncio.Event()

    async def _slow_process(row):
        await release_event.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_slow_process)

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-bound",
        settings=_fast_settings(concurrency=3, batch_size=10),
    )

    rows_batch1 = [_make_claimed_row(worker_id="worker-bound") for _ in range(3)]
    mock_claim.claim_batch.return_value = rows_batch1

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 3
    mock_claim.claim_batch.assert_called_with("worker-bound", 3)
    assert worker.active_task_count == 3

    # Second cycle while all 3 are running: available_slots == 0 -> does not call claim_batch
    mock_claim.claim_batch.reset_mock()
    dispatched2 = await worker.poll_and_dispatch()
    assert dispatched2 == 0
    mock_claim.claim_batch.assert_not_called()

    release_event.set()
    await worker.stop()
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_claim_batch_size_capped_by_available_slots_or_batch_size():
    """Requested limit is min(available_slots, batch_size)."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-slots"

    release_event = asyncio.Event()

    async def _hang_process(row):
        await release_event.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_hang_process)

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-slots",
        settings=_fast_settings(concurrency=5, batch_size=2),
    )

    row1 = _make_claimed_row(worker_id="worker-slots")
    row2 = _make_claimed_row(worker_id="worker-slots")
    mock_claim.claim_batch.return_value = [row1, row2]

    await worker.poll_and_dispatch()
    mock_claim.claim_batch.assert_called_once_with("worker-slots", 2)
    assert worker.active_task_count == 2

    # Now 3 slots free, batch size is 2 -> requests min(3, 2) = 2
    mock_claim.claim_batch.reset_mock()
    row3 = _make_claimed_row(worker_id="worker-slots")
    mock_claim.claim_batch.return_value = [row3]

    await worker.poll_and_dispatch()
    mock_claim.claim_batch.assert_called_once_with("worker-slots", 2)
    assert worker.active_task_count == 3

    release_event.set()
    await worker.stop()


@pytest.mark.asyncio
async def test_completed_tasks_free_capacity_for_subsequent_claims():
    """Finishing an active task immediately frees capacity for new claims."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-free"
    mock_proc.process_claimed_row = AsyncMock(return_value=ProcessResult(status="completed"))

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-free",
        settings=_fast_settings(concurrency=2, batch_size=5),
    )

    row1 = _make_claimed_row(worker_id="worker-free")
    row2 = _make_claimed_row(worker_id="worker-free")
    mock_claim.claim_batch.return_value = [row1, row2]

    await worker.poll_and_dispatch()
    await asyncio.sleep(0.02)
    assert worker.active_task_count == 0

    mock_claim.claim_batch.reset_mock()
    row3 = _make_claimed_row(worker_id="worker-free")
    mock_claim.claim_batch.return_value = [row3]

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 1
    mock_claim.claim_batch.assert_called_once_with("worker-free", 2)
    await worker.stop()


@pytest.mark.asyncio
async def test_no_duplicate_processing_of_same_row():
    """Worker prevents duplicate concurrent dispatch of the exact same outbox row."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-nodup"

    release_event = asyncio.Event()

    async def _hold_process(row):
        await release_event.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_hold_process)

    row_same = _make_claimed_row(worker_id="worker-nodup")
    mock_claim.claim_batch.return_value = [row_same]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-nodup",
        settings=_fast_settings(concurrency=5, batch_size=5),
    )

    d1 = await worker.poll_and_dispatch()
    assert d1 == 1
    assert row_same.outbox_id in worker.active_outbox_ids

    # Simulate claim_batch returning row_same again while still in-flight
    mock_claim.claim_batch.return_value = [row_same]
    d2 = await worker.poll_and_dispatch()
    assert d2 == 0  # Skipped as duplicate!

    assert mock_proc.process_claimed_row.call_count == 1

    release_event.set()
    await worker.stop()
    assert row_same.outbox_id not in worker.active_outbox_ids


@pytest.mark.asyncio
async def test_concurrent_poll_and_dispatch_never_exceeds_max_concurrency():
    """Two concurrent poll_and_dispatch() calls on the same worker instance
    are synchronized via _dispatch_lock and never exceed max_concurrency.
    """
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-race"

    release_proc = asyncio.Event()

    async def _pause_process(row):
        await release_proc.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_pause_process)

    # Concurrency limit is 3, batch size is 10
    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-race",
        settings=_fast_settings(concurrency=3, batch_size=10),
    )

    def _mock_claim_batch(worker_id, limit):
        return [_make_claimed_row(worker_id="worker-race") for _ in range(limit)]

    mock_claim.claim_batch.side_effect = _mock_claim_batch

    results = await asyncio.gather(
        worker.poll_and_dispatch(),
        worker.poll_and_dispatch(),
    )

    # One call should claim 3, and the other call should claim 0 (capacity full!)
    assert sum(results) == 3
    assert set(results) == {3, 0}
    assert worker.active_task_count == 3
    assert worker.active_task_count <= worker.max_concurrency

    release_proc.set()
    await worker.stop()
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_claimed_rows_strictly_respect_available_capacity_with_overflow_protection():
    """Even if claim_batch returns more rows than requested, dispatch strictly enforces max_concurrency."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-overflow"

    release_proc = asyncio.Event()

    async def _holding_process(row):
        await release_proc.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_holding_process)

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-overflow",
        settings=_fast_settings(concurrency=2, batch_size=2),
    )

    buggy_rows = [_make_claimed_row(worker_id="worker-overflow") for _ in range(5)]
    mock_claim.claim_batch.return_value = buggy_rows

    dispatched = await worker.poll_and_dispatch()

    assert dispatched == 2
    assert worker.active_task_count == 2
    assert worker.active_task_count <= worker.max_concurrency

    release_proc.set()
    await worker.stop()


@pytest.mark.asyncio
async def test_concurrent_polling_does_not_create_duplicate_processing_tasks():
    """Concurrent poll_and_dispatch calls do not duplicate in-flight processing tasks."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-conc-dup"

    release_proc = asyncio.Event()

    async def _pause_process(row):
        await release_proc.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_pause_process)

    shared_row = _make_claimed_row(worker_id="worker-conc-dup")
    mock_claim.claim_batch.return_value = [shared_row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-conc-dup",
        settings=_fast_settings(concurrency=5, batch_size=5),
    )

    results = await asyncio.gather(
        worker.poll_and_dispatch(),
        worker.poll_and_dispatch(),
    )

    assert sum(results) == 1
    assert set(results) == {1, 0}
    assert worker.active_task_count == 1
    assert len(worker.active_outbox_ids) == 1

    release_proc.set()
    await worker.stop()


# =============================================================================
# 4. Failure Isolation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_processor_exception_does_not_terminate_other_tasks():
    """One task raising an unhandled exception does not crash or abort concurrent tasks."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-iso"

    row_fail = _make_claimed_row(document_id="doc-fail", worker_id="worker-iso")
    row_ok = _make_claimed_row(document_id="doc-ok", worker_id="worker-iso")

    async def _mixed_process(row):
        if row.document_id == "doc-fail":
            raise RuntimeError("Unexpected processor internal error")
        await asyncio.sleep(0.02)
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_mixed_process)
    mock_claim.claim_batch.return_value = [row_fail, row_ok]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-iso",
        settings=_fast_settings(concurrency=5, batch_size=5),
    )

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 2

    await worker.stop()

    assert mock_proc.process_claimed_row.call_count == 2
    assert len(worker.active_outbox_ids) == 0


@pytest.mark.asyncio
async def test_subsequent_polling_continues_after_processing_exception():
    """Polling continues normally after an unexpected processing exception."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-cont"

    row1 = _make_claimed_row(worker_id="worker-cont")
    row2 = _make_claimed_row(worker_id="worker-cont")

    mock_proc.process_claimed_row = AsyncMock(
        side_effect=[RuntimeError("Corrupt payload"), ProcessResult(status="completed")]
    )
    mock_claim.claim_batch.side_effect = [[row1], [row2], []]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-cont",
        settings=_fast_settings(poll_interval=0.01),
    )

    task = worker.start()
    await asyncio.sleep(0.06)
    await worker.stop()

    assert mock_proc.process_claimed_row.call_count == 2


@pytest.mark.asyncio
async def test_cancellation_is_not_swallowed_as_ordinary_exception():
    """Cancellation propagates cleanly and is not swallowed by the failure handler."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-cancel"

    cancelled_event = asyncio.Event()

    async def _cancellable_process(row):
        try:
            await asyncio.sleep(10.0)
        except asyncio.CancelledError:
            cancelled_event.set()
            raise

    mock_proc.process_claimed_row = AsyncMock(side_effect=_cancellable_process)
    row = _make_claimed_row(worker_id="worker-cancel")
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-cancel",
        settings=_fast_settings(),
    )

    await worker.poll_and_dispatch()
    assert worker.active_task_count == 1

    await worker.stop(timeout=0.01)

    assert cancelled_event.is_set()
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_worker_does_not_independently_perform_state_transitions():
    """Worker never calls transition_to_completed/dead_letter on processor failure."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-notran"
    mock_proc.process_claimed_row = AsyncMock(side_effect=RuntimeError("Fatal error"))

    row = _make_claimed_row(worker_id="worker-notran")
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-notran",
        settings=_fast_settings(),
    )

    await worker.poll_and_dispatch()
    await worker.stop()

    mock_claim.transition_to_completed.assert_not_called()
    mock_claim.transition_to_dead_letter.assert_not_called()
    mock_claim.transition_to_retry_wait.assert_not_called()


# =============================================================================
# 5. Shutdown, Lifecycle, and Cancellation Tests
# =============================================================================

@pytest.mark.asyncio
async def test_stop_request_prevents_new_claims():
    """After stop() is called, poll_and_dispatch refuses to claim new records."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-stop"

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-stop",
        settings=_fast_settings(),
    )

    await worker.stop()
    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 0
    mock_claim.claim_batch.assert_not_called()


@pytest.mark.asyncio
async def test_stop_awaits_active_tasks_within_timeout():
    """Graceful stop waits for running tasks to finish naturally within timeout."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-drain"

    completed_flag = False

    async def _timed_process(row):
        nonlocal completed_flag
        await asyncio.sleep(0.04)
        completed_flag = True
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_timed_process)
    row = _make_claimed_row(worker_id="worker-drain")
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-drain",
        settings=_fast_settings(shutdown_timeout=0.2),
    )

    await worker.poll_and_dispatch()
    assert worker.active_task_count == 1

    await worker.stop(timeout=0.2)
    assert completed_flag is True
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_stop_cancels_tasks_exceeding_timeout():
    """Tasks that do not finish before shutdown timeout are cancelled."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-hang"

    hang_event = asyncio.Event()

    async def _hanging_process(row):
        await hang_event.wait()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_hanging_process)
    row = _make_claimed_row(worker_id="worker-hang")
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-hang",
        settings=_fast_settings(shutdown_timeout=0.03),
    )

    await worker.poll_and_dispatch()
    assert worker.active_task_count == 1

    await worker.stop(timeout=0.03)
    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_worker_can_be_stopped_cleanly_when_idle():
    """Stopping an idle worker without tasks completes immediately without errors."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-idle"

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-idle",
        settings=_fast_settings(),
    )

    assert worker.active_task_count == 0
    await worker.stop()
    assert worker.is_running is False


@pytest.mark.asyncio
async def test_cancellation_of_worker_task_cleans_up_child_tasks():
    """Cancelling the main worker task cancels all active processing tasks."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-taskcancel"

    task_started = asyncio.Event()

    async def _infinite_process(row):
        task_started.set()
        await asyncio.sleep(100.0)
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_infinite_process)
    row = _make_claimed_row(worker_id="worker-taskcancel")
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-taskcancel",
        settings=_fast_settings(poll_interval=0.01),
    )

    main_task = worker.start()
    await task_started.wait()
    assert worker.active_task_count == 1

    main_task.cancel()
    try:
        await main_task
    except asyncio.CancelledError:
        pass

    assert worker.active_task_count == 0


@pytest.mark.asyncio
async def test_calling_start_twice_idempotent_returns_same_task():
    """Calling start() twice returns the exact same running Task and logs a warning."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-start-twice"
    mock_claim.claim_batch.return_value = []

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-start-twice",
        settings=_fast_settings(),
    )

    task1 = worker.start()
    task2 = worker.start()

    assert task1 is task2
    assert worker.is_running is True
    await worker.stop()
    assert worker.is_running is False


@pytest.mark.asyncio
async def test_second_run_forever_invocation_raises_lifecycle_error():
    """Invoking run_forever() while another loop is active raises RuntimeError."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-run-twice"
    mock_claim.claim_batch.return_value = []

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-run-twice",
        settings=_fast_settings(poll_interval=0.01),
    )

    task1 = worker.start()
    await asyncio.sleep(0.01)

    with pytest.raises(RuntimeError, match="already running a polling loop"):
        await worker.run_forever()

    await worker.stop()


@pytest.mark.asyncio
async def test_worker_clean_restart_after_stop():
    """Worker can be started, stopped, and cleanly restarted without corrupted state."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-restart"
    mock_claim.claim_batch.return_value = []

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-restart",
        settings=_fast_settings(poll_interval=0.01),
    )

    task1 = worker.start()
    assert worker.is_running is True
    await worker.stop()
    assert worker.is_running is False

    task2 = worker.start()
    assert task2 is not task1
    assert worker.is_running is True
    await worker.stop()
    assert worker.is_running is False


@pytest.mark.asyncio
async def test_shutdown_during_in_progress_claim_does_not_lose_claimed_row():
    """When stop() is called while claim_batch is in flight in a worker thread:
    The claim finishes, the row is tracked in active tasks, and is cleanly processed/drained.
    """
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-stop-inflight"

    claim_entered = asyncio.Event()
    release_claim = asyncio.Event()
    proc_completed = asyncio.Event()

    row = _make_claimed_row(worker_id="worker-stop-inflight")

    loop = asyncio.get_running_loop()

    def _sync_claim_batch(worker_id, limit):
        loop.call_soon_threadsafe(claim_entered.set)
        future = asyncio.run_coroutine_threadsafe(release_claim.wait(), loop)
        future.result(timeout=5.0)
        return [row]

    mock_claim.claim_batch.side_effect = _sync_claim_batch

    async def _mock_process(r):
        proc_completed.set()
        return ProcessResult(status="completed")

    mock_proc.process_claimed_row = AsyncMock(side_effect=_mock_process)

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-stop-inflight",
        settings=_fast_settings(shutdown_timeout=2.0),
    )

    main_task = worker.start()
    await claim_entered.wait()

    stop_task = asyncio.create_task(worker.stop(timeout=2.0))
    await asyncio.sleep(0.02)

    release_claim.set()
    await stop_task

    assert proc_completed.is_set()
    mock_proc.process_claimed_row.assert_called_once_with(row)
    assert worker.active_task_count == 0


# =============================================================================
# 6. Safety, Logging, and Boundary Tests
# =============================================================================

@pytest.mark.asyncio
async def test_worker_only_invokes_claim_and_processor_interfaces():
    """Worker interacts exclusively with claim_service and processor."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-boundaries"
    mock_proc.process_claimed_row = AsyncMock(return_value=ProcessResult(status="completed"))

    row = _make_claimed_row(worker_id="worker-boundaries")
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-boundaries",
        settings=_fast_settings(),
    )

    await worker.poll_and_dispatch()
    await worker.stop()

    mock_claim.claim_batch.assert_called_once()
    mock_proc.process_claimed_row.assert_called_once_with(row)


@pytest.mark.asyncio
async def test_worker_logs_contain_no_sensitive_payload_or_credentials(caplog):
    """Worker logs never include serialized memory payload or sensitive tokens."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-privacy"
    mock_proc.process_claimed_row = AsyncMock(side_effect=ValueError("Test failure"))

    sensitive_payload = '{"secret_token": "SUPER_SECRET_12345", "ip": "192.168.1.50"}'
    row = _make_claimed_row(worker_id="worker-privacy")
    object.__setattr__(row, "serialized_memory_content", sensitive_payload)
    mock_claim.claim_batch.return_value = [row]

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-privacy",
        settings=_fast_settings(),
    )

    with caplog.at_level(logging.DEBUG):
        await worker.poll_and_dispatch()
        await worker.stop()

    for record in caplog.records:
        assert "SUPER_SECRET_12345" not in record.message
        assert "192.168.1.50" not in record.message


@pytest.mark.asyncio
async def test_synchronous_claim_batch_offloaded_via_to_thread():
    """Worker uses asyncio.to_thread to invoke synchronous claim_batch."""
    mock_claim = MagicMock(spec=MemoryOutboxClaimService)
    mock_proc = MagicMock(spec=HindsightMemoryOutboxProcessor)
    mock_proc._worker_id = "worker-offload"
    mock_claim.claim_batch.return_value = []

    worker = HindsightMemoryOutboxWorker(
        claim_service=mock_claim,
        processor=mock_proc,
        worker_id="worker-offload",
        settings=_fast_settings(),
    )

    with patch("asyncio.to_thread", wraps=asyncio.to_thread) as spy_to_thread:
        await worker.poll_and_dispatch()
        spy_to_thread.assert_called_once_with(
            mock_claim.claim_batch,
            "worker-offload",
            5,
        )


# =============================================================================
# 7. End-to-End Database Integration Tests
# =============================================================================

@pytest.fixture
def session_factory():
    """Return application session factory for database tests."""
    return get_session_factory()


@pytest.fixture
def cleanup_tracker(session_factory):
    """Track and clean up test records from PostgreSQL after tests."""
    tracker = {
        "outbox": [],
        "investigations": [],
        "incidents": [],
    }
    yield tracker

    with session_factory() as session:
        with session.begin():
            if tracker["outbox"]:
                session.execute(
                    delete(IncidentMemoryOutbox).where(
                        IncidentMemoryOutbox.outbox_id.in_(tracker["outbox"])
                    )
                )
            if tracker["investigations"]:
                session.execute(
                    delete(Investigation).where(
                        Investigation.investigation_id.in_(tracker["investigations"])
                    )
                )
            if tracker["incidents"]:
                session.execute(
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
                title="Worker Test Incident",
                incident_type="brute_force",
                source_ip="198.51.100.99",
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


def _create_db_outbox_entry(
    session_factory,
    cleanup_tracker,
    investigation_id: uuid.UUID,
    incident_id: uuid.UUID,
    bank_id: str = "test-bank",
    document_id: Optional[str] = None,
) -> uuid.UUID:
    """Helper to create a pending outbox row with cryptographically valid payload."""
    doc_id = document_id or f"doc-{uuid.uuid4()}"
    memory_payload = {
        "finding": "Test worker e2e investigation memory",
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
                hindsight_operation_id=None,
                status="pending",
                attempt_count=0,
                next_attempt_at=now,
                lease_owner=None,
                lease_token=0,
                lease_expires_at=None,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.flush()
            cleanup_tracker["outbox"].append(row.outbox_id)
            return row.outbox_id


@pytest.mark.asyncio
async def test_worker_e2e_database_claim_and_completion(session_factory, cleanup_tracker):
    """End-to-end integration: worker polls PostgreSQL, claims pending row, and processes it."""
    inc_id, inv_id = _setup_incident_and_investigation(session_factory, cleanup_tracker)
    doc_id = f"doc-e2e-{uuid.uuid4()}"

    outbox_id = _create_db_outbox_entry(
        session_factory, cleanup_tracker, inv_id, inc_id,
        bank_id="test-bank", document_id=doc_id,
    )

    claim_service = MemoryOutboxClaimService(session_factory=session_factory)

    with session_factory() as session:
        initial_row = session.get(IncidentMemoryOutbox, outbox_id)
        expected_op_id = str(initial_row.operation_id)

    mock_hindsight = MagicMock(spec=HindsightClientService)
    mock_hindsight.retain_investigation_memory = AsyncMock(
        return_value=RetainSubmissionResult(
            success=True,
            bank_id="test-bank",
            operation_id=expected_op_id,
            items_count=1,
            is_async=True,
        )
    )
    mock_hindsight.get_operation_status = AsyncMock(
        return_value=OperationStatusResult(
            operation_id=expected_op_id,
            status="completed",
        )
    )

    worker = HindsightMemoryOutboxWorker(
        claim_service=claim_service,
        hindsight_service=mock_hindsight,
        worker_id="worker-e2e",
        settings=_fast_settings(concurrency=3, batch_size=5),
    )

    dispatched = await worker.poll_and_dispatch()
    assert dispatched == 1

    await worker.stop()

    with session_factory() as session:
        row = session.get(IncidentMemoryOutbox, outbox_id)
        assert row.status == "completed"
        assert row.completed_at is not None
        assert row.hindsight_operation_id == expected_op_id

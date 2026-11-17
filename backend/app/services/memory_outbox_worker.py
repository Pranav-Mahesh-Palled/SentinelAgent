"""Application-Independent Background Outbox Worker (Task 9C.3.5).

Coordinates transactional outbox candidate polling, batch claiming,
bounded concurrency dispatching, and task lifecycle management without
implementing Hindsight retention, status reconciliation, or outbox
state transitions directly.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional, Set
import uuid

from app.core.config import Settings, get_settings
from app.services.hindsight_client import HindsightClientService
from app.services.memory_outbox_claim_service import (
    ClaimedMemoryOutboxRow,
    MemoryOutboxClaimService,
)
from app.services.memory_outbox_processor import (
    HindsightMemoryOutboxProcessor,
    ProcessResult,
)

logger = logging.getLogger(__name__)


class HindsightMemoryOutboxWorker:
    """Orchestrates background polling and bounded concurrent dispatch of outbox records.

    Responsibilities:
    - Maintains an instance-unique worker ID for all claims.
    - Periodically queries candidate documents via MemoryOutboxClaimService.
    - Limits concurrency to HINDSIGHT_OUTBOX_MAX_CONCURRENCY.
    - Offloads synchronous SQLAlchemy claim operations via asyncio.to_thread().
    - Dispatches claimed rows to HindsightMemoryOutboxProcessor.
    - Tracks active processing tasks and prevents duplicate in-flight processing.
    - Isolates individual task failures without crashing the polling loop.
    - Provides clean stop and cancellation handling without leaking child tasks.
    """

    def __init__(
        self,
        claim_service: MemoryOutboxClaimService,
        processor: Optional[HindsightMemoryOutboxProcessor] = None,
        hindsight_service: Optional[HindsightClientService] = None,
        worker_id: Optional[str] = None,
        settings: Optional[Settings] = None,
    ) -> None:
        if claim_service is None:
            raise ValueError("claim_service must not be None")

        # Resolve worker identity
        if worker_id is not None:
            if not isinstance(worker_id, str) or not worker_id.strip():
                raise ValueError("worker_id must be a non-empty string")
            clean_worker_id = worker_id.strip()
        elif processor is not None and getattr(processor, "_worker_id", None):
            clean_worker_id = processor._worker_id
        else:
            clean_worker_id = f"outbox-worker-{uuid.uuid4()}"

        self._worker_id: str = clean_worker_id
        self._claim_service: MemoryOutboxClaimService = claim_service

        app_settings = settings or get_settings()
        self._settings: Settings = app_settings
        self._max_concurrency: int = app_settings.HINDSIGHT_OUTBOX_MAX_CONCURRENCY
        self._batch_size: int = app_settings.HINDSIGHT_OUTBOX_BATCH_SIZE
        self._poll_interval: float = app_settings.HINDSIGHT_OUTBOX_POLL_INTERVAL_SECONDS
        self._shutdown_timeout: float = app_settings.HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS

        # Resolve or construct processor
        if processor is not None:
            proc_worker = getattr(processor, "_worker_id", None)
            if proc_worker and proc_worker != self._worker_id:
                raise ValueError(
                    f"worker_id '{self._worker_id}' does not match processor worker_id '{proc_worker}'"
                )
            self._processor: HindsightMemoryOutboxProcessor = processor
        elif hindsight_service is not None:
            self._processor = HindsightMemoryOutboxProcessor(
                hindsight_service=hindsight_service,
                claim_service=claim_service,
                worker_id=self._worker_id,
                settings=app_settings,
            )
        else:
            raise ValueError("Either processor or hindsight_service must be provided")

        # Instance-scoped runtime task state
        self._active_tasks: Set[asyncio.Task] = set()
        self._in_flight_ids: Set[uuid.UUID] = set()
        self._stop_event: asyncio.Event = asyncio.Event()
        self._main_task: Optional[asyncio.Task] = None
        self._dispatch_lock: asyncio.Lock = asyncio.Lock()
        self._is_polling: bool = False

    # -------------------------------------------------------------------------
    # Public Properties
    # -------------------------------------------------------------------------

    @property
    def worker_id(self) -> str:
        """Unique identifier of this worker instance."""
        return self._worker_id

    @property
    def max_concurrency(self) -> int:
        """Maximum number of concurrent outbox records processed by this worker."""
        return self._max_concurrency

    @property
    def batch_size(self) -> int:
        """Maximum number of candidate records requested per claim cycle."""
        return self._batch_size

    @property
    def poll_interval(self) -> float:
        """Idle polling interval in seconds."""
        return self._poll_interval

    @property
    def shutdown_timeout(self) -> float:
        """Graceful shutdown timeout in seconds for draining active tasks."""
        return self._shutdown_timeout

    @property
    def is_running(self) -> bool:
        """True if the worker polling loop is active and not stopped."""
        return (
            not self._stop_event.is_set()
            and (
                (self._main_task is not None and not self._main_task.done())
                or self._is_polling
            )
        )

    @property
    def active_task_count(self) -> int:
        """Number of outbox records currently being processed."""
        return len(self._active_tasks)

    @property
    def active_outbox_ids(self) -> frozenset[uuid.UUID]:
        """Immutable set of outbox IDs currently in-flight."""
        return frozenset(self._in_flight_ids)

    # -------------------------------------------------------------------------
    # Polling & Dispatch Cycle
    # -------------------------------------------------------------------------

    async def poll_and_dispatch(self) -> int:
        """Execute a single polling and dispatch cycle under bounded concurrency.

        Guarantees that active processing tasks never exceed HINDSIGHT_OUTBOX_MAX_CONCURRENCY,
        even when poll_and_dispatch() is called concurrently by multiple tasks on this instance.

        Returns:
            Number of claimed outbox rows successfully dispatched in this cycle.
        """
        async with self._dispatch_lock:
            self._reap_done_tasks()

            if self._stop_event.is_set():
                return 0

            # Calculate available concurrency slots
            available_slots = self._max_concurrency - len(self._active_tasks)
            if available_slots <= 0:
                return 0

            # Never claim more than available slots or configured batch size
            to_claim = min(available_slots, self._batch_size)

            try:
                claimed_rows: list[ClaimedMemoryOutboxRow] = await asyncio.to_thread(
                    self._claim_service.claim_batch,
                    self._worker_id,
                    to_claim,
                )
            except asyncio.CancelledError:
                # Thread cancellation limitation:
                # Cancelling an asyncio task awaiting asyncio.to_thread() cancels the
                # asyncio waiter, but the OS thread continues until the synchronous
                # database transaction completes. Any row claimed before cancellation
                # is safely fenced in PostgreSQL under lease_expires_at and will be
                # reclaimed by crash recovery once the lease expires.
                raise
            except Exception as exc:
                # Catch transient claim exceptions; log sanitized error classification
                logger.error("Claim service failure during polling: %s", type(exc).__name__)
                return 0

            if not claimed_rows:
                return 0

            dispatched_count = 0
            for row in claimed_rows:
                # Check for duplicate dispatch in this worker instance
                if row.outbox_id in self._in_flight_ids:
                    logger.warning(
                        "Outbox row %s already in flight in worker %s; skipping duplicate dispatch",
                        row.outbox_id,
                        self._worker_id,
                    )
                    continue

                # Enforce concurrency boundary strictly in case claim_batch returned extra rows
                if len(self._active_tasks) >= self._max_concurrency:
                    logger.warning(
                        "Concurrency limit reached during dispatch (%d/%d); deferring row %s",
                        len(self._active_tasks),
                        self._max_concurrency,
                        row.outbox_id,
                    )
                    break

                self._dispatch_row(row)
                dispatched_count += 1

            return dispatched_count

    def _dispatch_row(self, row: ClaimedMemoryOutboxRow) -> asyncio.Task:
        """Dispatch a single claimed row to a tracked asynchronous processing task."""
        self._in_flight_ids.add(row.outbox_id)
        task = asyncio.create_task(
            self._process_row_wrapper(row),
            name=f"outbox_proc_{row.outbox_id}",
        )
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)
        return task

    async def _process_row_wrapper(
        self,
        row: ClaimedMemoryOutboxRow,
    ) -> Optional[ProcessResult]:
        """Wrap row processing with failure isolation and resource cleanup."""
        try:
            return await self._processor.process_claimed_row(row)
        except asyncio.CancelledError:
            # Cancellation must propagate cleanly to allow processor cleanup
            raise
        except Exception as exc:
            # Failure isolation: unexpected processor error must not crash the worker
            # or abort other concurrently running tasks. State transition remains
            # uncommitted, allowing lease expiry to trigger crash recovery.
            logger.error(
                "Unexpected error processing outbox_id=%s: %s",
                row.outbox_id,
                type(exc).__name__,
            )
            return None
        finally:
            self._in_flight_ids.discard(row.outbox_id)

    def _reap_done_tasks(self) -> None:
        """Clean up completed tasks and log any unexpected unhandled exceptions."""
        done_tasks = {t for t in self._active_tasks if t.done()}
        for t in done_tasks:
            if not t.cancelled():
                exc = t.exception()
                if exc:
                    logger.error(
                        "Outbox processing task finished with exception: %s",
                        type(exc).__name__,
                    )
            self._active_tasks.discard(t)

    async def _wait_for_capacity_or_stop(self) -> None:
        """Wait until at least one active task completes or the worker is stopped."""
        if not self._active_tasks or self._stop_event.is_set():
            return

        stop_waiter = asyncio.create_task(self._stop_event.wait())
        try:
            await asyncio.wait(
                self._active_tasks | {stop_waiter},
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            if not stop_waiter.done():
                stop_waiter.cancel()
                try:
                    await stop_waiter
                except asyncio.CancelledError:
                    pass

    async def _interruptible_sleep(self, duration: float) -> None:
        """Sleep for duration or until stop_event is set."""
        if self._stop_event.is_set() or duration <= 0:
            return
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=duration)
        except asyncio.TimeoutError:
            pass

    # -------------------------------------------------------------------------
    # Lifecycle: Polling Loop, Start & Stop
    # -------------------------------------------------------------------------

    async def run_forever(self) -> None:
        """Execute the continuous background polling loop until stopped or cancelled.

        Raises:
            RuntimeError: If another polling loop is already actively executing on
                          this worker instance.
        """
        current_task = asyncio.current_task()
        if self._is_polling or (
            self._main_task is not None
            and not self._main_task.done()
            and current_task != self._main_task
        ):
            raise RuntimeError(
                f"Outbox worker {self._worker_id} is already running a polling loop"
            )

        self._is_polling = True
        if self._main_task is None:
            self._stop_event.clear()
        logger.info("Outbox worker %s started polling loop", self._worker_id)
        try:
            while not self._stop_event.is_set():
                self._reap_done_tasks()

                available_slots = self._max_concurrency - len(self._active_tasks)
                if available_slots <= 0:
                    # Concurrency capacity reached: wait for capacity to free up
                    await self._wait_for_capacity_or_stop()
                    continue

                dispatched = await self.poll_and_dispatch()

                if dispatched == 0 and not self._stop_event.is_set():
                    # No records claimed; wait poll interval before re-checking
                    await self._interruptible_sleep(self._poll_interval)

        except asyncio.CancelledError:
            self._stop_event.set()
            # Controlled cancellation: cancel child tasks and await their cleanup
            for t in list(self._active_tasks):
                t.cancel()
            if self._active_tasks:
                await asyncio.gather(*self._active_tasks, return_exceptions=True)
            self._active_tasks.clear()
            self._in_flight_ids.clear()
            raise
        finally:
            self._is_polling = False
            logger.info("Outbox worker %s exited polling loop", self._worker_id)

    def start(self) -> asyncio.Task:
        """Start the worker polling loop as a background asyncio task.

        Calling start() multiple times while running is idempotent and returns
        the existing running Task without creating duplicate polling loops.
        """
        if self._main_task is not None and not self._main_task.done():
            logger.warning("Outbox worker %s is already running", self._worker_id)
            return self._main_task

        self._stop_event.clear()
        self._main_task = asyncio.create_task(
            self.run_forever(),
            name=f"outbox_worker_{self._worker_id}",
        )
        return self._main_task

    async def stop(self, timeout: Optional[float] = None) -> None:
        """Request the worker to stop polling and drain active processing tasks.

        Guarantees that shutdown does not lose in-flight database claims:
        1. Signals stop_event to prevent new claims.
        2. Joins the main polling loop task so any in-flight claim finishes and dispatches.
        3. Synchronizes with the dispatch critical section.
        4. Drains all active child tasks (including newly claimed ones) within timeout.

        Args:
            timeout: Maximum seconds to wait for active tasks to drain.
                     Defaults to HINDSIGHT_OUTBOX_SHUTDOWN_TIMEOUT_SECONDS.
        """
        logger.info("Stopping outbox worker %s...", self._worker_id)
        self._stop_event.set()
        effective_timeout = timeout if timeout is not None else self._shutdown_timeout
        loop = asyncio.get_running_loop()
        start_time = loop.time()

        # 1. Join the main polling loop task first so any in-progress claim completes
        if self._main_task is not None:
            if not self._main_task.done():
                try:
                    await asyncio.wait_for(
                        self._main_task,
                        timeout=effective_timeout,
                    )
                except (asyncio.CancelledError, asyncio.TimeoutError):
                    if not self._main_task.done():
                        self._main_task.cancel()
                        try:
                            await self._main_task
                        except (asyncio.CancelledError, Exception):
                            pass
                except Exception as exc:
                    logger.error("Error awaiting main polling task on worker stop: %s", type(exc).__name__)
            self._main_task = None

        # 2. Acquire dispatch lock briefly to ensure any direct poll_and_dispatch() has completed
        async with self._dispatch_lock:
            pass

        # 3. Drain all active child tasks (including any dispatched from the final claim)
        elapsed = loop.time() - start_time
        remaining_timeout = max(0.0, effective_timeout - elapsed)

        if self._active_tasks:
            logger.info(
                "Waiting up to %.1fs for %d active task(s) to finish...",
                remaining_timeout,
                len(self._active_tasks),
            )
            try:
                done, pending = await asyncio.wait(
                    self._active_tasks,
                    timeout=remaining_timeout,
                )
            except Exception as exc:
                logger.error("Error awaiting active tasks on worker stop: %s", type(exc).__name__)
                pending = set(self._active_tasks)

            # Cancel any tasks that exceeded shutdown timeout
            if pending:
                logger.warning(
                    "Cancelling %d active task(s) that exceeded shutdown timeout (%.1fs)",
                    len(pending),
                    remaining_timeout,
                )
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)

            self._active_tasks.clear()
            self._in_flight_ids.clear()

        logger.info("Outbox worker %s stopped.", self._worker_id)


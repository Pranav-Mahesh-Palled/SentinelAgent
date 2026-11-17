"""Response Orchestration Background Worker Runtime (Task 11.3B).

Coordinates asynchronous polling, batch claiming with FOR UPDATE SKIP LOCKED,
bounded concurrency dispatching to simulation execution and verification workers,
and periodic expiration/recovery sweeps.

Key Invariants:
- Dedicated worker process; not automatically spawned in every web worker.
- Monotonic lease token fencing ensures stale workers cannot corrupt state.
- Bounded concurrency with graceful shutdown and active task draining.
- In-memory operational metrics tracking.
- Structured logging with correlation ID propagation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from typing import Any, Optional, Set
import uuid

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.db.session import get_session_factory
from app.schemas.response import OutboxClaim, SimulationExecutionResult, VerificationRunResult
from app.services.response_outbox_dispatcher import ResponseOutboxDispatcher
from app.services.response_sweeper import ResponseSweeper
from app.services.simulation_execution_worker import SimulationExecutionWorker
from app.services.verification_worker import VerificationWorker

logger = logging.getLogger(__name__)


@dataclass
class WorkerMetrics:
    """Operational telemetry counters for the response background worker runtime."""

    commands_claimed: int = 0
    commands_completed: int = 0
    commands_failed: int = 0
    commands_retried: int = 0
    commands_dead_lettered: int = 0
    expired_leases_recovered: int = 0
    stale_workers_fenced: int = 0
    verifications_verified: int = 0
    verifications_failed: int = 0
    verifications_inconclusive: int = 0
    sweep_cycles: int = 0

    def snapshot(self) -> dict[str, int]:
        """Return an immutable dictionary copy of current metrics."""
        return {
            "commands_claimed": self.commands_claimed,
            "commands_completed": self.commands_completed,
            "commands_failed": self.commands_failed,
            "commands_retried": self.commands_retried,
            "commands_dead_lettered": self.commands_dead_lettered,
            "expired_leases_recovered": self.expired_leases_recovered,
            "stale_workers_fenced": self.stale_workers_fenced,
            "verifications_verified": self.verifications_verified,
            "verifications_failed": self.verifications_failed,
            "verifications_inconclusive": self.verifications_inconclusive,
            "sweep_cycles": self.sweep_cycles,
        }


class ResponseWorkerRuntime:
    """Background runtime managing outbox polling, worker dispatching, and periodic sweeps."""

    def __init__(
        self,
        session_factory: Optional[sessionmaker[Session]] = None,
        worker_id: Optional[str] = None,
        settings: Optional[Settings] = None,
        poll_interval_seconds: Optional[float] = None,
        batch_size: Optional[int] = None,
        max_concurrency: Optional[int] = None,
        lease_duration_seconds: Optional[int] = None,
        sweeper_interval_seconds: Optional[float] = None,
    ) -> None:
        app_settings = settings or get_settings()
        self._settings = app_settings

        self._session_factory: sessionmaker[Session] = (
            session_factory or get_session_factory()
        )
        self._worker_id: str = (
            worker_id.strip() if worker_id and worker_id.strip()
            else f"resp-worker-{uuid.uuid4().hex[:8]}"
        )

        self._poll_interval: float = (
            poll_interval_seconds
            if poll_interval_seconds is not None
            else app_settings.RESPONSE_OUTBOX_POLL_INTERVAL_SECONDS
        )
        self._batch_size: int = (
            batch_size
            if batch_size is not None
            else app_settings.RESPONSE_OUTBOX_BATCH_SIZE
        )
        self._max_concurrency: int = (
            max_concurrency
            if max_concurrency is not None
            else app_settings.RESPONSE_OUTBOX_MAX_CONCURRENCY
        )
        self._lease_duration_seconds: int = (
            lease_duration_seconds
            if lease_duration_seconds is not None
            else app_settings.RESPONSE_OUTBOX_LEASE_DURATION_SECONDS
        )
        self._sweeper_interval: float = (
            sweeper_interval_seconds
            if sweeper_interval_seconds is not None
            else app_settings.RESPONSE_SWEEPER_INTERVAL_SECONDS
        )

        # Worker sub-components
        self._execution_worker = SimulationExecutionWorker(self._session_factory)
        self._verification_worker = VerificationWorker(self._session_factory)
        self._sweeper = ResponseSweeper(
            session_factory=self._session_factory,
            batch_size=self._batch_size * 2,
        )

        # Runtime state
        self._metrics = WorkerMetrics()
        self._stop_event = asyncio.Event()
        self._active_tasks: Set[asyncio.Task] = set()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._loop_task: Optional[asyncio.Task] = None
        self._sweeper_task: Optional[asyncio.Task] = None

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def metrics(self) -> WorkerMetrics:
        return self._metrics

    @property
    def is_running(self) -> bool:
        return self._loop_task is not None and not self._loop_task.done()

    # =========================================================================
    # Synchronous Core Dispatching (also used directly by run_once)
    # =========================================================================

    def process_claim_sync(self, claim: OutboxClaim) -> dict[str, Any]:
        """Process a single OutboxClaim synchronously."""
        logger.info(
            "Worker '%s' processing claim %s: command=%s, action=%s, corr=%s, lease_token=%d",
            self._worker_id,
            claim.outbox_id,
            claim.command_type,
            claim.response_action_id,
            claim.correlation_id,
            claim.lease_token,
        )

        if claim.command_type == "execute_simulation":
            exec_res: SimulationExecutionResult = self._execution_worker.process_claim(claim)
            if exec_res.success:
                self._metrics.commands_completed += 1
                return {"success": True, "command_type": claim.command_type, "result": exec_res}
            else:
                self._metrics.commands_failed += 1
                return {"success": False, "command_type": claim.command_type, "result": exec_res}

        elif claim.command_type == "verify_simulation":
            verif_res: VerificationRunResult = self._verification_worker.process_claim(claim)
            if verif_res.outcome == "verified":
                self._metrics.verifications_verified += 1
                self._metrics.commands_completed += 1
            elif verif_res.outcome == "failed":
                self._metrics.verifications_failed += 1
                self._metrics.commands_completed += 1
            else:
                self._metrics.verifications_inconclusive += 1
                self._metrics.commands_completed += 1

            return {"success": True, "command_type": claim.command_type, "result": verif_res}

        else:
            logger.error("Unknown command type '%s' in claim %s", claim.command_type, claim.outbox_id)
            self._metrics.commands_dead_lettered += 1
            return {"success": False, "command_type": claim.command_type, "error": "UNKNOWN_COMMAND"}

    def run_once(self) -> dict[str, Any]:
        """Perform a single synchronous polling cycle and sweep.

        Ideal for testing and deterministic offline batch processing.
        """
        # 1. Claim available commands
        claims: list[OutboxClaim] = []
        with self._session_factory() as session:
            claims = ResponseOutboxDispatcher.claim_commands(
                session=session,
                worker_id=self._worker_id,
                limit=self._batch_size,
                lease_duration_seconds=self._lease_duration_seconds,
            )
            session.commit()

        self._metrics.commands_claimed += len(claims)

        # 2. Process each claim
        processed_results: list[dict[str, Any]] = []
        for claim in claims:
            res = self.process_claim_sync(claim)
            processed_results.append(res)

        # 3. Run sweeper cycle
        sweep_results = self._sweeper.run_full_sweep()
        self._metrics.sweep_cycles += 1
        self._metrics.expired_leases_recovered += sweep_results["reclaimed_leases"]

        return {
            "claims_processed": len(claims),
            "results": processed_results,
            "sweep": sweep_results,
            "metrics": self._metrics.snapshot(),
        }

    # =========================================================================
    # Asynchronous Runtime Lifecycle
    # =========================================================================

    async def start(self) -> None:
        """Start background polling and sweeper tasks."""
        if self.is_running:
            logger.warning("Worker runtime '%s' is already running.", self._worker_id)
            return

        logger.info(
            "Starting ResponseWorkerRuntime '%s': concurrency=%d, poll=%.1fs, sweeper=%.1fs",
            self._worker_id,
            self._max_concurrency,
            self._poll_interval,
            self._sweeper_interval,
        )

        self._stop_event.clear()
        self._semaphore = asyncio.Semaphore(self._max_concurrency)

        self._loop_task = asyncio.create_task(self._poll_loop(), name=f"{self._worker_id}_poll_loop")
        self._sweeper_task = asyncio.create_task(self._sweeper_loop(), name=f"{self._worker_id}_sweeper_loop")

    async def stop(self, timeout_seconds: float = 15.0) -> None:
        """Gracefully stop polling and await active tasks up to timeout_seconds."""
        logger.info("Stopping ResponseWorkerRuntime '%s'...", self._worker_id)
        self._stop_event.set()

        # Cancel main loops
        if self._loop_task:
            self._loop_task.cancel()
        if self._sweeper_task:
            self._sweeper_task.cancel()

        # Await active in-flight worker tasks
        if self._active_tasks:
            logger.info("Draining %d active worker tasks...", len(self._active_tasks))
            done, pending = await asyncio.wait(self._active_tasks, timeout=timeout_seconds)
            for t in pending:
                t.cancel()

        self._active_tasks.clear()
        self._loop_task = None
        self._sweeper_task = None
        logger.info("ResponseWorkerRuntime '%s' stopped cleanly.", self._worker_id)

    async def _poll_loop(self) -> None:
        """Continuous background polling loop with bounded concurrency."""
        while not self._stop_event.is_set():
            try:
                # 1. Claim batch via thread to avoid blocking event loop
                claims = await asyncio.to_thread(self._claim_batch)

                if claims:
                    self._metrics.commands_claimed += len(claims)
                    for claim in claims:
                        # Dispatch bounded concurrent task
                        task = asyncio.create_task(self._bounded_dispatch(claim))
                        self._active_tasks.add(task)
                        task.add_done_callback(self._active_tasks.discard)
                else:
                    # Sleep when no commands found or wait for stop event
                    try:
                        await asyncio.wait_for(self._stop_event.wait(), timeout=self._poll_interval)
                    except asyncio.TimeoutError:
                        pass

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in worker polling loop: %s", exc, exc_info=True)
                await asyncio.sleep(self._poll_interval)

    def _claim_batch(self) -> list[OutboxClaim]:
        """Synchronously claim up to batch_size commands."""
        with self._session_factory() as session:
            claims = ResponseOutboxDispatcher.claim_commands(
                session=session,
                worker_id=self._worker_id,
                limit=self._batch_size,
                lease_duration_seconds=self._lease_duration_seconds,
            )
            session.commit()
            return claims

    async def _bounded_dispatch(self, claim: OutboxClaim) -> None:
        """Execute claim with concurrency semaphore limit."""
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self._max_concurrency)

        async with self._semaphore:
            try:
                await asyncio.to_thread(self.process_claim_sync, claim)
            except Exception as exc:
                logger.error("Error dispatching claim %s: %s", claim.outbox_id, exc, exc_info=True)

    async def _sweeper_loop(self) -> None:
        """Periodic background sweeper loop."""
        while not self._stop_event.is_set():
            try:
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=self._sweeper_interval)
                except asyncio.TimeoutError:
                    pass

                if self._stop_event.is_set():
                    break

                sweep_res = await asyncio.to_thread(self._sweeper.run_full_sweep)
                self._metrics.sweep_cycles += 1
                self._metrics.expired_leases_recovered += sweep_res.get("reclaimed_leases", 0)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in worker sweeper loop: %s", exc, exc_info=True)
                await asyncio.sleep(self._sweeper_interval)

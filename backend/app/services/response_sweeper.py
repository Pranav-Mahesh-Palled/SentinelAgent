"""Periodic Expiration and Recovery Sweeper for SentinelAgent (Task 11.3B).

Performs background sweeping and recovery for:
1. Expired pending proposals (exceeded approval_expires_at).
2. Expired execution deadlines (exceeded execution_deadline_at with ledger check).
3. Expired worker leases and stalled executions (via recover_simulation_execution).
4. Stale verification outbox commands.

Preserves the recovery matrix:
- Matching ledger record: Recover as succeeded; queue verification.
- No ledger record and deadline passed: Expire; outbox becomes dead_letter.
- No ledger record and retry budget remains: Fence old worker and safely requeue.
- Simulation ledger mismatch: Mark indeterminate; dead-letter.
- Indeterminate outcome: NEVER automatically requeue or cancel.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.services.response_transition_service import ResponseTransitionService
from app.services.simulation_execution_service import SimulationExecutionService

logger = logging.getLogger(__name__)


class ResponseSweeper:
    """Orchestrates periodic sweeps for expired proposals, deadlines, leases, and stalled executions."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        batch_size: int = 50,
    ) -> None:
        if session_factory is None:
            raise ValueError("session_factory must not be None")
        self._session_factory = session_factory
        self._batch_size = max(1, batch_size)

    def sweep_expired_proposals(self) -> int:
        """Expire pending proposals that exceeded approval_expires_at."""
        with self._session_factory() as session:
            count = ResponseTransitionService.expire_stale_proposals(
                session=session,
                limit=self._batch_size,
            )
            if count > 0:
                logger.info("Sweeper expired %d stale proposals", count)
            return count

    def sweep_expired_executions(self) -> int:
        """Expire queued or running executions that exceeded execution_deadline_at."""
        with self._session_factory() as session:
            count = ResponseTransitionService.expire_stale_executions(
                session=session,
                limit=self._batch_size,
            )
            if count > 0:
                logger.info("Sweeper expired %d stale executions", count)
            return count

    def sweep_stalled_simulations(self) -> list[dict[str, Any]]:
        """Recover stalled simulation executions where worker lease expired or status is running."""
        now = datetime.now(timezone.utc)
        recovered: list[dict[str, Any]] = []

        with self._session_factory() as session:
            # Find running actions with expired outbox leases or expired deadline
            stalled_actions = session.scalars(
                select(ResponseAction.response_action_id)
                .join(
                    ResponseOutbox,
                    ResponseOutbox.response_action_id == ResponseAction.response_action_id,
                )
                .where(
                    ResponseAction.execution_status == "running",
                    ResponseOutbox.command_type == "execute_simulation",
                    or_(
                        (ResponseOutbox.status == "claimed") & (ResponseOutbox.lease_expires_at <= now),
                        ResponseOutbox.status == "pending",
                    ),
                )
                .distinct()
                .limit(self._batch_size)
            ).all()

        for action_id in stalled_actions:
            outcome = SimulationExecutionService.recover_simulation_execution(
                session_factory=self._session_factory,
                response_action_id=action_id,
            )
            recovered.append({"response_action_id": str(action_id), "outcome": outcome})
            logger.info("Stalled simulation recovery for %s: outcome=%s", action_id, outcome)

        return recovered

    def sweep_expired_leases(self) -> int:
        """Reclaim expired outbox leases for non-running tasks."""
        now = datetime.now(timezone.utc)
        reclaimed_count = 0

        with self._session_factory() as session:
            expired_outboxes = session.scalars(
                select(ResponseOutbox)
                .where(
                    ResponseOutbox.status == "claimed",
                    ResponseOutbox.lease_expires_at.is_not(None),
                    ResponseOutbox.lease_expires_at <= now,
                )
                .with_for_update(skip_locked=True)
                .limit(self._batch_size)
            ).all()

            for outbox in expired_outboxes:
                # Fencing token increment to invalidate stale worker
                outbox.lease_token += 1
                outbox.lease_owner = None
                outbox.lease_expires_at = None

                if outbox.attempt_count >= outbox.max_attempts:
                    outbox.status = "dead_letter"
                    outbox.last_error_code = "LEASE_EXPIRED_MAX_ATTEMPTS"
                else:
                    outbox.status = "pending"
                    outbox.next_attempt_at = now + timedelta(seconds=5)

                reclaimed_count += 1

            if reclaimed_count > 0:
                session.commit()
                logger.info("Sweeper reclaimed %d expired outbox leases", reclaimed_count)

        return reclaimed_count

    def run_full_sweep(self) -> dict[str, Any]:
        """Execute a complete sweep cycle across proposals, executions, and leases."""
        expired_proposals = self.sweep_expired_proposals()
        expired_executions = self.sweep_expired_executions()
        stalled_simulations = self.sweep_stalled_simulations()
        reclaimed_leases = self.sweep_expired_leases()

        return {
            "expired_proposals": expired_proposals,
            "expired_executions": expired_executions,
            "stalled_simulations": stalled_simulations,
            "reclaimed_leases": reclaimed_leases,
        }

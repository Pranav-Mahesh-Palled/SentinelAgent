"""Simulation Execution Worker for SentinelAgent (Task 11.3B).

Consumes claimed 'execute_simulation' outbox commands and executes the
four-stage simulation lifecycle via SimulationExecutionService.

Invariants:
- Canonical lock hierarchy: Incident -> ResponseAction -> ResponseOutbox -> SimulationEffect.
- Stage 1: Handled by Dispatcher (claim, lease establishment, attempt_count untouched).
- Stage 2: Execution Gate (locks acquired, attempt_count incremented exactly once, queued -> running).
- Transaction A: Simulation effect persisted to immutable simulated_blocklist_entries ledger.
- Transaction B: Result settlement, verification enqueued, audit event appended, outbox completed.
- Stale workers fenced; blind retries prohibited.
"""

import logging
from typing import Optional
import uuid

from sqlalchemy.orm import Session, sessionmaker

from app.schemas.response import OutboxClaim, SimulationExecutionResult
from app.services.response_outbox_service import ResponseOutboxService
from app.services.simulation_execution_service import SimulationExecutionService

logger = logging.getLogger(__name__)


class SimulationExecutionWorker:
    """Worker component executing simulation outbox tasks using the four-stage lifecycle."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        if session_factory is None:
            raise ValueError("session_factory must not be None")
        self._session_factory = session_factory

    def process_claim(self, claim: OutboxClaim) -> SimulationExecutionResult:
        """Process a claimed 'execute_simulation' outbox command.

        Args:
            claim: OutboxClaim produced by ResponseOutboxDispatcher.

        Returns:
            SimulationExecutionResult indicating success or failure details.
        """
        if claim.command_type != "execute_simulation":
            raise ValueError(
                f"SimulationExecutionWorker cannot process command_type '{claim.command_type}'"
            )

        logger.info(
            "Processing simulation execution claim: outbox_id=%s, action_id=%s, correlation_id=%s, lease_token=%d",
            claim.outbox_id,
            claim.response_action_id,
            claim.correlation_id,
            claim.lease_token,
        )

        try:
            result = SimulationExecutionService.execute_simulation_claim(
                session_factory=self._session_factory,
                claim=claim,
            )
            if result.success:
                logger.info(
                    "Simulation execution succeeded for action %s: simulated_entry_id=%s",
                    claim.response_action_id,
                    result.simulated_entry_id,
                )
            else:
                logger.warning(
                    "Simulation execution failed for action %s: error_code=%s, message=%s",
                    claim.response_action_id,
                    result.error_code,
                    result.error_message,
                )
            return result
        except Exception as exc:
            logger.error(
                "Unhandled error during simulation execution for action %s: %s",
                claim.response_action_id,
                exc,
                exc_info=True,
            )
            # Fail outbox command safely if not already settled
            try:
                with self._session_factory() as session:
                    ResponseOutboxService.fail_command(
                        session=session,
                        outbox_id=claim.outbox_id,
                        claimed_lease_token=claim.lease_token,
                        error_code="UNHANDLED_SIMULATION_WORKER_ERROR",
                    )
                    session.commit()
            except Exception as fail_exc:
                logger.error(
                    "Failed to record outbox failure for %s: %s",
                    claim.outbox_id,
                    fail_exc,
                )

            return SimulationExecutionResult(
                success=False,
                response_action_id=claim.response_action_id,
                outbox_id=claim.outbox_id,
                error_code="UNHANDLED_SIMULATION_WORKER_ERROR",
                error_message=str(exc),
            )

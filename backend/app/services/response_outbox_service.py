"""Transactional Outbox Service for SentinelAgent Response Orchestration.

Manages the lifecycle of asynchronous execution and verification commands:
- Enqueuing commands with deterministic deduplication keys.
- Monotonic lease token generation and worker claiming with FOR UPDATE SKIP LOCKED.
- Two-transaction fencing verification.
- Completion, retry with backoff, dead-lettering, and cancellation.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Optional
import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.schemas.response import OutboxClaim
from app.services.response_idempotency_service import FencingTokenError

logger = logging.getLogger(__name__)


class ResponseOutboxService:
    """Service managing transactional outbox queue entries for response dispatch."""

    @staticmethod
    def enqueue_execution_command(
        session: Session,
        action: ResponseAction,
    ) -> ResponseOutbox:
        """Enqueue an 'execute_simulation' command for an approved response action."""
        dedup_key = f"resp_outbox_{action.response_action_id}_execute_simulation_{action.action_version}"
        existing = session.scalar(
            select(ResponseOutbox).where(ResponseOutbox.deduplication_key == dedup_key)
        )
        if existing is not None:
            return existing

        now = datetime.now(timezone.utc)
        outbox = ResponseOutbox(
            outbox_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            command_type="execute_simulation",
            deduplication_key=dedup_key,
            status="pending",
            attempt_count=0,
            max_attempts=3,
            next_attempt_at=now,
            lease_token=0,
            lease_owner=None,
            lease_expires_at=None,
        )
        session.add(outbox)
        return outbox

    @staticmethod
    def enqueue_verification_command(
        session: Session,
        action: ResponseAction,
    ) -> ResponseOutbox:
        """Enqueue a 'verify_simulation' command for a simulated response action."""
        dedup_key = f"resp_outbox_{action.response_action_id}_verify_simulation_{action.action_version}"
        existing = session.scalar(
            select(ResponseOutbox).where(ResponseOutbox.deduplication_key == dedup_key)
        )
        if existing is not None:
            return existing

        now = datetime.now(timezone.utc)
        outbox = ResponseOutbox(
            outbox_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            command_type="verify_simulation",
            deduplication_key=dedup_key,
            status="pending",
            attempt_count=0,
            max_attempts=3,
            next_attempt_at=now,
            lease_token=0,
            lease_owner=None,
            lease_expires_at=None,
        )
        session.add(outbox)
        return outbox

    @staticmethod
    def claim_next_command(
        session: Session,
        worker_id: str,
        lease_duration_seconds: int = 60,
        command_type: Optional[str] = None,
    ) -> Optional[OutboxClaim]:
        """Claim the next eligible outbox command with row locking and monotonic lease token generation."""
        now = datetime.now(timezone.utc)

        stmt = (
            select(ResponseOutbox)
            .where(
                or_(
                    (ResponseOutbox.status == "pending") & (ResponseOutbox.next_attempt_at <= now),
                    (ResponseOutbox.status == "claimed") & (ResponseOutbox.lease_expires_at <= now),
                )
            )
            .with_for_update(skip_locked=True)
            .order_by(ResponseOutbox.next_attempt_at.asc())
            .limit(1)
        )

        if command_type:
            stmt = stmt.where(ResponseOutbox.command_type == command_type)

        outbox = session.scalar(stmt)
        if outbox is None:
            return None

        # Check dead letter limit
        if outbox.attempt_count >= outbox.max_attempts:
            outbox.status = "dead_letter"
            outbox.last_error_code = "MAX_ATTEMPTS_EXCEEDED"
            return None

        # Claim the lease (attempt_count is incremented exactly once at Stage 2 execution gate)
        outbox.lease_token += 1
        outbox.lease_owner = worker_id
        outbox.lease_expires_at = now + timedelta(seconds=lease_duration_seconds)
        outbox.status = "claimed"

        return OutboxClaim(
            outbox_id=outbox.outbox_id,
            response_action_id=outbox.response_action_id,
            correlation_id=outbox.correlation_id,
            command_type=outbox.command_type,
            deduplication_key=outbox.deduplication_key,
            lease_token=outbox.lease_token,
            lease_owner=worker_id,
            lease_expires_at=outbox.lease_expires_at,
            attempt_count=outbox.attempt_count,
        )

    @staticmethod
    def complete_command(
        session: Session,
        outbox_id: uuid.UUID,
        claimed_lease_token: int,
    ) -> bool:
        """Mark an outbox command as completed after validating lease fencing."""
        outbox = session.scalar(
            select(ResponseOutbox)
            .where(ResponseOutbox.outbox_id == outbox_id)
            .with_for_update()
        )
        if outbox is None:
            raise FencingTokenError(f"Outbox entry {outbox_id} not found.")

        if outbox.lease_token != claimed_lease_token:
            raise FencingTokenError(
                f"Fencing violation on outbox {outbox_id}: expected token {claimed_lease_token}, "
                f"found {outbox.lease_token}."
            )

        outbox.status = "completed"
        outbox.completed_at = datetime.now(timezone.utc)
        return True

    @staticmethod
    def fail_command(
        session: Session,
        outbox_id: uuid.UUID,
        claimed_lease_token: int,
        error_code: str,
        retry_delay_seconds: int = 30,
    ) -> bool:
        """Record command failure, scheduling retry or transitioning to dead_letter."""
        outbox = session.scalar(
            select(ResponseOutbox)
            .where(ResponseOutbox.outbox_id == outbox_id)
            .with_for_update()
        )
        if outbox is None:
            return False

        if outbox.lease_token != claimed_lease_token:
            logger.warning(
                f"Ignoring fail_command on outbox {outbox_id} due to mismatched lease token: "
                f"claimed={claimed_lease_token}, current={outbox.lease_token}"
            )
            return False

        now = datetime.now(timezone.utc)
        outbox.last_error_code = error_code

        if outbox.attempt_count >= outbox.max_attempts:
            outbox.status = "dead_letter"
        else:
            outbox.status = "pending"
            outbox.next_attempt_at = now + timedelta(seconds=retry_delay_seconds)
            outbox.lease_owner = None
            outbox.lease_expires_at = None

        return True

    @staticmethod
    def cancel_action_commands(
        session: Session,
        response_action_id: uuid.UUID,
    ) -> int:
        """Cancel any active (pending or claimed) outbox commands for a response action."""
        active_entries = session.scalars(
            select(ResponseOutbox)
            .where(
                ResponseOutbox.response_action_id == response_action_id,
                ResponseOutbox.status.in_(["pending", "claimed"]),
            )
            .with_for_update()
        ).all()

        cancelled_count = 0
        for entry in active_entries:
            entry.status = "cancelled"
            # Invalidate stale leases using monotonic fencing token
            entry.lease_token += 1
            entry.lease_owner = None
            entry.lease_expires_at = None
            cancelled_count += 1

        return cancelled_count

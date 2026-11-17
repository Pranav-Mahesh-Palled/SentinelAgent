"""Response Outbox Dispatcher for SentinelAgent.

Discovers and claims eligible transactional outbox commands using PostgreSQL
FOR UPDATE SKIP LOCKED with short-lived transactions.

Responsibilities:
- Claim commands with monotonic BIGINT lease token increments.
- Assign unique worker ownership and lease expirations.
- Enforce that Stage 1 queue claiming NEVER increments attempt_count.
- Validate command types against supported set:
    * execute_simulation
    * verify_simulation
- Safely reject and dead-letter unknown command types without arbitrary execution.
- Validate response action association.
- Enforce retry limits (attempt_count < max_attempts) and terminal outbox states.
- Preserve deduplication keys.
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

logger = logging.getLogger(__name__)

SUPPORTED_COMMAND_TYPES: frozenset[str] = frozenset({"execute_simulation", "verify_simulation"})


class ResponseOutboxDispatcher:
    """Discovers, validates, and claims eligible outbox commands using PostgreSQL SKIP LOCKED."""

    @classmethod
    def claim_commands(
        cls,
        session: Session,
        worker_id: str,
        limit: int = 1,
        lease_duration_seconds: int = 60,
        command_type: Optional[str] = None,
    ) -> list[OutboxClaim]:
        """Claim eligible outbox commands using FOR UPDATE SKIP LOCKED.

        Invariants:
        1. Atomic, short-lived transaction with row-level SKIP LOCKED.
        2. Assigns worker ownership (lease_owner) and sets lease_expires_at.
        3. Increments monotonic lease_token by exactly 1.
        4. NEVER increments attempt_count during Stage 1 queue claiming.
        5. Validates command_type against SUPPORTED_COMMAND_TYPES; unknown types are dead-lettered.
        6. Validates that the associated ResponseAction exists; missing action dead-letters the command.
        7. Respects retry limits: attempt_count >= max_attempts dead-letters the command.
        8. Ignores terminal outbox states ('completed', 'cancelled', 'dead_letter').
        """
        if not worker_id or not worker_id.strip():
            raise ValueError("worker_id must be a non-empty string")
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if lease_duration_seconds < 1:
            raise ValueError("lease_duration_seconds must be >= 1")

        now = datetime.now(timezone.utc)

        # Select candidates that are either:
        # 1. 'pending' and due for attempt (next_attempt_at <= now)
        # 2. 'claimed' whose worker lease has expired (lease_expires_at <= now)
        stmt = (
            select(ResponseOutbox)
            .where(
                or_(
                    (ResponseOutbox.status == "pending") & (ResponseOutbox.next_attempt_at <= now),
                    (ResponseOutbox.status == "claimed") & (ResponseOutbox.lease_expires_at <= now),
                )
            )
            .with_for_update(skip_locked=True)
            .order_by(ResponseOutbox.next_attempt_at.asc(), ResponseOutbox.created_at.asc())
            .limit(limit * 2)  # Query a larger batch to account for dead-letter filtering
        )

        if command_type:
            stmt = stmt.where(ResponseOutbox.command_type == command_type)

        candidates = session.scalars(stmt).all()
        claims: list[OutboxClaim] = []

        for outbox in candidates:
            if len(claims) >= limit:
                break

            # 1. Retry budget check
            if outbox.attempt_count >= outbox.max_attempts:
                logger.warning(
                    "Outbox command %s exceeded max attempts (%d/%d); dead-lettering.",
                    outbox.outbox_id,
                    outbox.attempt_count,
                    outbox.max_attempts,
                )
                outbox.status = "dead_letter"
                outbox.last_error_code = "MAX_ATTEMPTS_EXCEEDED"
                outbox.lease_owner = None
                outbox.lease_expires_at = None
                continue

            # 2. Supported command type check
            if outbox.command_type not in SUPPORTED_COMMAND_TYPES:
                logger.error(
                    "Outbox command %s has unknown command_type '%s'; dead-lettering.",
                    outbox.outbox_id,
                    outbox.command_type,
                )
                outbox.status = "dead_letter"
                outbox.last_error_code = "UNKNOWN_COMMAND_TYPE"
                outbox.lease_owner = None
                outbox.lease_expires_at = None
                continue

            # 3. Action association check
            action_exists = session.scalar(
                select(ResponseAction.response_action_id).where(
                    ResponseAction.response_action_id == outbox.response_action_id
                )
            )
            if action_exists is None:
                logger.error(
                    "Outbox command %s references non-existent ResponseAction %s; dead-lettering.",
                    outbox.outbox_id,
                    outbox.response_action_id,
                )
                outbox.status = "dead_letter"
                outbox.last_error_code = "ACTION_NOT_FOUND"
                outbox.lease_owner = None
                outbox.lease_expires_at = None
                continue

            # 4. Grant claim lease
            # Stage 1 invariant: attempt_count is NOT incremented here.
            outbox.lease_token += 1
            outbox.lease_owner = worker_id
            outbox.lease_expires_at = now + timedelta(seconds=lease_duration_seconds)
            outbox.status = "claimed"

            claim = OutboxClaim(
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
            claims.append(claim)
            logger.debug(
                "Worker '%s' claimed outbox %s (command=%s, lease_token=%d)",
                worker_id,
                outbox.outbox_id,
                outbox.command_type,
                outbox.lease_token,
            )

        if candidates:
            session.flush()

        return claims

    @classmethod
    def claim_single_command(
        cls,
        session: Session,
        worker_id: str,
        lease_duration_seconds: int = 60,
        command_type: Optional[str] = None,
    ) -> Optional[OutboxClaim]:
        """Convenience method to claim a single eligible outbox command."""
        claims = cls.claim_commands(
            session=session,
            worker_id=worker_id,
            limit=1,
            lease_duration_seconds=lease_duration_seconds,
            command_type=command_type,
        )
        return claims[0] if claims else None

    @classmethod
    def renew_lease(
        cls,
        session: Session,
        claim: OutboxClaim,
        extension_seconds: int = 60,
    ) -> Optional[datetime]:
        """Renew active lease for a claimed command if lease token and owner still match."""
        now = datetime.now(timezone.utc)
        outbox = session.scalar(
            select(ResponseOutbox)
            .where(ResponseOutbox.outbox_id == claim.outbox_id)
            .with_for_update()
        )
        if outbox is None:
            return None

        if outbox.lease_token != claim.lease_token or outbox.lease_owner != claim.lease_owner:
            logger.warning(
                "Lease renewal rejected for outbox %s: expected token %d owner '%s', found token %d owner '%s'",
                claim.outbox_id,
                claim.lease_token,
                claim.lease_owner,
                outbox.lease_token,
                outbox.lease_owner,
            )
            return None

        if outbox.status != "claimed":
            return None

        new_expires_at = now + timedelta(seconds=extension_seconds)
        outbox.lease_expires_at = new_expires_at
        session.flush()
        return new_expires_at

    @classmethod
    def release_claim(
        cls,
        session: Session,
        claim: OutboxClaim,
        retry_delay_seconds: int = 5,
    ) -> bool:
        """Safely release an in-flight claim back to 'pending' without incrementing attempt_count."""
        outbox = session.scalar(
            select(ResponseOutbox)
            .where(ResponseOutbox.outbox_id == claim.outbox_id)
            .with_for_update()
        )
        if outbox is None or outbox.lease_token != claim.lease_token:
            return False

        if outbox.status != "claimed":
            return False

        now = datetime.now(timezone.utc)
        outbox.status = "pending"
        outbox.lease_owner = None
        outbox.lease_expires_at = None
        outbox.next_attempt_at = now + timedelta(seconds=retry_delay_seconds)
        session.flush()
        return True

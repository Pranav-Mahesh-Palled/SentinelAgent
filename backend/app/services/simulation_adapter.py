"""Simulation Execution Adapter for SentinelAgent.

Implements the local PostgreSQL simulation adapter:
- Strictly local database effect writing to simulated_blocklist_entries.
- Enforces worker lease fencing token and deadline checks.
- Enforces exact simulation idempotency key: 'resp_sim_{action_id}'.
- Conflict replay handling with deterministic field verification.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.response_action import ResponseAction
from app.models.response_outbox import ResponseOutbox
from app.models.simulated_blocklist_entry import SimulatedBlocklistEntry
from app.services.response_idempotency_service import FencingTokenError

logger = logging.getLogger(__name__)


class SimulationAdapter:
    """PostgreSQL simulation adapter creating immutable simulated blocklist entries."""

    @staticmethod
    def execute_simulation_effect(
        session: Session,
        action: ResponseAction,
        outbox: ResponseOutbox,
        worker_id: str,
        claimed_lease_token: int,
    ) -> SimulatedBlocklistEntry:
        """Verify fencing invariants and insert simulated blocklist effect.

        Args:
            session: Active database session.
            action: Locked ResponseAction instance.
            outbox: Locked ResponseOutbox claim row.
            worker_id: Claiming worker identity.
            claimed_lease_token: Lease token held by worker.

        Returns:
            Durable SimulatedBlocklistEntry instance.

        Raises:
            FencingTokenError: If any fencing invariant, deadline, or status is violated.
        """
        now = datetime.now(timezone.utc)

        # 1. Strict Fencing Verification
        if action.approval_status != "approved":
            raise FencingTokenError(
                f"Fencing violation on action {action.response_action_id}: approval_status is "
                f"'{action.approval_status}', expected 'approved'."
            )

        if action.execution_status != "running":
            raise FencingTokenError(
                f"Fencing violation on action {action.response_action_id}: execution_status is "
                f"'{action.execution_status}', expected 'running' (Stage 2 execution gate required)."
            )

        if outbox.status != "claimed":
            raise FencingTokenError(
                f"Fencing violation on outbox {outbox.outbox_id}: status is '{outbox.status}', expected 'claimed'."
            )

        if outbox.lease_token != claimed_lease_token:
            raise FencingTokenError(
                f"Fencing violation on outbox {outbox.outbox_id}: lease token {claimed_lease_token} has been "
                f"superseded by {outbox.lease_token}."
            )

        if outbox.lease_owner != worker_id:
            raise FencingTokenError(
                f"Fencing violation on outbox {outbox.outbox_id}: lease owner is '{outbox.lease_owner}', "
                f"expected '{worker_id}'."
            )

        if action.execution_deadline_at is not None and now >= action.execution_deadline_at:
            raise FencingTokenError(
                f"Fencing violation on action {action.response_action_id}: execution deadline "
                f"({action.execution_deadline_at.isoformat()}) expired at {now.isoformat()}."
            )

        # 2. Check for existing simulation effect (idempotency key: resp_sim_{action_id})
        idempotency_key = f"resp_sim_{action.response_action_id}"
        existing = session.scalar(
            select(SimulatedBlocklistEntry).where(
                SimulatedBlocklistEntry.response_action_id == action.response_action_id
            )
        )
        if existing is not None:
            # Replay verification: target_ip and payload_sha256 must match
            if str(existing.target_ip) != str(action.target_value) or existing.payload_sha256 != action.payload_sha256:
                raise FencingTokenError(
                    f"Conflicting simulation effect exists for action {action.response_action_id}: "
                    f"recorded IP={existing.target_ip}, action IP={action.target_value}."
                )
            return existing

        # 3. Insert new simulated blocklist entry
        target_ip_str = str(action.target_value)
        simulated_entry = SimulatedBlocklistEntry(
            entry_id=uuid.uuid4(),
            response_action_id=action.response_action_id,
            correlation_id=action.correlation_id,
            idempotency_key=idempotency_key,
            payload_sha256=action.payload_sha256,
            target_ip=target_ip_str,
            simulated_rule_id=f"rule_sim_{str(action.response_action_id)[:24]}",
            simulated_at=now,
            metadata_json={
                "worker_id": worker_id,
                "lease_token": claimed_lease_token,
                "outbox_id": str(outbox.outbox_id),
                "action_id": str(action.response_action_id),
                "target_ip": target_ip_str,
            },
        )
        session.add(simulated_entry)
        session.flush()

        return simulated_entry

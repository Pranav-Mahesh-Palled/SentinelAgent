"""PostgreSQL Outbox Claim, Lease Management, and Fencing Service.

Implements the Task 9C.3.3 distributed claims engine for SentinelAgent:
- Composite document concurrency (bank_id, document_id).
- Transaction-scoped two-key PostgreSQL advisory locking.
- Strict FIFO document ordering and unsubmitted pending supersession.
- Lease acquisition, heartbeat renewal, and crash recovery.
- Fenced state-transition primitives with monotonic token validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.models.memory_outbox import IncidentMemoryOutbox
from app.services.memory_outbox_service import (
    calculate_payload_hash,
    canonicalize_payload,
    generate_operation_id,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Custom Integrity Exception
# =============================================================================

class OutboxPayloadIntegrityError(Exception):
    """Raised when an outbox record's payload hash or operation ID fails cryptographic verification."""


# =============================================================================
# Typed Response DTO
# =============================================================================

@dataclass(frozen=True)
class ClaimedMemoryOutboxRow:
    """Detached immutable DTO representing an outbox record claimed under lease."""

    outbox_id: uuid.UUID
    investigation_id: uuid.UUID
    incident_id: uuid.UUID
    bank_id: str
    document_id: str
    memory_schema_version: str
    payload_hash: str
    serialized_memory_content: str
    operation_id: uuid.UUID
    hindsight_operation_id: Optional[str]
    attempt_count: int
    lease_owner: str
    lease_token: int
    lease_expires_at: datetime


# =============================================================================
# Claim Service Implementation
# =============================================================================

class MemoryOutboxClaimService:
    """PostgreSQL-backed claim, lease management, and fencing service for incident memory outbox.

    Enforces composite document identity (bank_id, document_id), two-key PostgreSQL
    advisory locking, deterministic FIFO ordering, unsubmitted pending supersession,
    crash recovery of expired processing leases, and monotonic fencing tokens.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        settings: Optional[Settings] = None,
    ) -> None:
        self._session_factory = session_factory
        app_settings = settings or get_settings()
        self._batch_size = app_settings.HINDSIGHT_OUTBOX_BATCH_SIZE
        self._lease_duration_seconds = app_settings.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS

    @property
    def batch_size(self) -> int:
        """Configured candidate discovery batch size."""
        return self._batch_size

    @property
    def lease_duration_seconds(self) -> float:
        """Configured lease duration in seconds."""
        return self._lease_duration_seconds

    # -------------------------------------------------------------------------
    # Candidate Discovery
    # -------------------------------------------------------------------------

    def discover_candidates(self, limit: Optional[int] = None) -> list[tuple[str, str]]:
        """Discover distinct eligible (bank_id, document_id) candidate pairs.

        Eligible candidates have:
        - status = 'pending' and next_attempt_at <= NOW()
        - status = 'retry_wait' and next_attempt_at <= NOW()
        - status = 'processing' and lease_expires_at < NOW()

        Uses database server time (NOW()) and deterministic ordering.
        Candidate discovery performs zero mutations and acquires zero locks.
        """
        bound = limit if (limit is not None and limit > 0) else self._batch_size
        sql = text(
            """
            SELECT bank_id, document_id
              FROM incident_memory_outbox
             WHERE (status = 'pending' AND next_attempt_at <= NOW())
                OR (status = 'retry_wait' AND next_attempt_at <= NOW())
                OR (status = 'processing' AND lease_expires_at < NOW())
             GROUP BY bank_id, document_id
             ORDER BY MIN(created_at) ASC, MIN(outbox_id::text) ASC
             LIMIT :limit
            """
        )
        with self._session_factory() as session:
            rows = session.execute(sql, {"limit": bound}).fetchall()
            return [(str(r[0]), str(r[1])) for r in rows]

    # -------------------------------------------------------------------------
    # Document Claiming & Recovery
    # -------------------------------------------------------------------------

    def claim_document(
        self,
        bank_id: str,
        document_id: str,
        worker_id: str,
    ) -> Optional[ClaimedMemoryOutboxRow]:
        """Attempt to claim the oldest unresolved outbox record for (bank_id, document_id).

        Executes inside a short transaction:
        1. Acquires two-key composite advisory lock on (hashtext(bank_id), hashtext(document_id)).
        2. Inspects all unresolved rows (pending, processing, retry_wait) ordered by (created_at ASC, outbox_id ASC).
        3. Applies FIFO, supersession, crash recovery, or live lease skipping:
           - Case A: Oldest is processing with live lease -> Skip (return None).
           - Case B: Oldest is processing with expired lease -> Reclaim same row with incremented token.
           - Case C: Oldest is retry_wait -> Claim if due; skip if future.
           - Case D: Oldest is pending -> Supersede older pending revisions; claim newest pending revision.
        4. Commits transaction and returns detached ClaimedMemoryOutboxRow.
        """
        if not isinstance(bank_id, str) or not bank_id.strip():
            raise ValueError("bank_id must be a non-empty string")
        if not isinstance(document_id, str) or not document_id.strip():
            raise ValueError("document_id must be a non-empty string")
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise ValueError("worker_id must be a non-empty string")

        clean_bank_id = bank_id.strip()
        clean_doc_id = document_id.strip()
        clean_worker_id = worker_id.strip()

        with self._session_factory() as session:
            with session.begin():
                # 1. Acquire transaction-scoped composite advisory lock
                session.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:bank_id), hashtext(:document_id))"),
                    {"bank_id": clean_bank_id, "document_id": clean_doc_id},
                )

                # 2. Query all unresolved rows for this composite document pair
                rows = (
                    session.query(IncidentMemoryOutbox)
                    .filter(
                        IncidentMemoryOutbox.bank_id == clean_bank_id,
                        IncidentMemoryOutbox.document_id == clean_doc_id,
                        IncidentMemoryOutbox.status.in_(["pending", "processing", "retry_wait"]),
                    )
                    .order_by(
                        IncidentMemoryOutbox.created_at.asc(),
                        IncidentMemoryOutbox.outbox_id.asc(),
                    )
                    .with_for_update()
                    .all()
                )

                if not rows:
                    return None

                # Query database current timestamp for unified clock comparison
                db_now = session.execute(text("SELECT NOW()")).scalar_one()

                oldest = rows[0]

                # Case A & B: Oldest unresolved is processing
                if oldest.status == "processing":
                    if oldest.lease_expires_at is not None and oldest.lease_expires_at >= db_now:
                        # Case A: Live lease held by another worker -> skip
                        return None

                    # Case B: Expired lease -> Reclaim exact row
                    target_row = oldest
                    target_row.lease_owner = clean_worker_id
                    target_row.lease_token = target_row.lease_token + 1
                    target_row.lease_expires_at = session.execute(
                        text("SELECT NOW() + INTERVAL '1 second' * :dur"),
                        {"dur": self._lease_duration_seconds},
                    ).scalar_one()
                    target_row.updated_at = db_now
                    session.flush()
                    session.refresh(target_row)
                    return self._to_dto(target_row)

                # Case C: Oldest unresolved is retry_wait
                if oldest.status == "retry_wait":
                    if oldest.next_attempt_at > db_now:
                        # Not yet due -> skip document (never bypass retry_wait)
                        return None

                    # Due for retry -> claim exact row
                    target_row = oldest
                    target_row.status = "processing"
                    target_row.lease_owner = clean_worker_id
                    target_row.lease_token = target_row.lease_token + 1
                    target_row.lease_expires_at = session.execute(
                        text("SELECT NOW() + INTERVAL '1 second' * :dur"),
                        {"dur": self._lease_duration_seconds},
                    ).scalar_one()
                    target_row.updated_at = db_now
                    session.flush()
                    session.refresh(target_row)
                    return self._to_dto(target_row)

                # Case D: Oldest unresolved is pending
                if oldest.status == "pending":
                    # Invariant verification: Ensure no subsequent row is processing or retry_wait
                    if any(r.status in ("processing", "retry_wait") for r in rows[1:]):
                        logger.warning(
                            "Outbox invariant violation for bank_id=%s document_id=%s: "
                            "found processing/retry_wait row newer than pending row",
                            clean_bank_id,
                            clean_doc_id,
                        )
                        return None

                    pending_rows = [r for r in rows if r.status == "pending"]

                    # If multiple unsubmitted pending revisions exist:
                    # Supersede older pending rows, claim only the newest revision
                    if len(pending_rows) > 1:
                        for older in pending_rows[:-1]:
                            older.status = "superseded"
                            older.lease_owner = None
                            older.lease_expires_at = None
                            older.updated_at = db_now

                    newest_pending = pending_rows[-1]
                    if newest_pending.next_attempt_at > db_now:
                        # Newest pending is not due yet
                        return None

                    newest_pending.status = "processing"
                    newest_pending.lease_owner = clean_worker_id
                    newest_pending.lease_token = newest_pending.lease_token + 1
                    newest_pending.lease_expires_at = session.execute(
                        text("SELECT NOW() + INTERVAL '1 second' * :dur"),
                        {"dur": self._lease_duration_seconds},
                    ).scalar_one()
                    newest_pending.updated_at = db_now
                    session.flush()
                    session.refresh(newest_pending)
                    return self._to_dto(newest_pending)

                # Fallback for unexpected status
                return None

    def claim_next_available(self, worker_id: str) -> Optional[ClaimedMemoryOutboxRow]:
        """Discover eligible candidates and attempt to claim the first claimable document."""
        candidates = self.discover_candidates(limit=self._batch_size)
        for bank_id, doc_id in candidates:
            claimed = self.claim_document(bank_id=bank_id, document_id=doc_id, worker_id=worker_id)
            if claimed is not None:
                return claimed
        return None

    def claim_batch(
        self,
        worker_id: str,
        limit: Optional[int] = None,
    ) -> list[ClaimedMemoryOutboxRow]:
        """Claim up to limit eligible documents across candidate pairs."""
        bound = limit if (limit is not None and limit > 0) else self._batch_size
        candidates = self.discover_candidates(limit=bound * 2)
        claimed_rows: list[ClaimedMemoryOutboxRow] = []
        for bank_id, doc_id in candidates:
            if len(claimed_rows) >= bound:
                break
            claimed = self.claim_document(bank_id=bank_id, document_id=doc_id, worker_id=worker_id)
            if claimed is not None:
                claimed_rows.append(claimed)
        return claimed_rows

    # -------------------------------------------------------------------------
    # Lease Heartbeat Renewal
    # -------------------------------------------------------------------------

    def renew_lease(
        self,
        outbox_id: uuid.UUID,
        worker_id: str,
        lease_token: int,
    ) -> bool:
        """Renew the lease expiration for an active processing row.

        Guards:
        - outbox_id matching
        - lease_owner == worker_id
        - lease_token == lease_token
        - status == 'processing'
        - lease_expires_at >= NOW()

        Returns True if renewed, False if lost or fenced out.
        """
        sql = text(
            """
            UPDATE incident_memory_outbox
               SET lease_expires_at = NOW() + INTERVAL '1 second' * :dur,
                   updated_at = NOW()
             WHERE outbox_id = :outbox_id
               AND lease_owner = :worker_id
               AND lease_token = :lease_token
               AND status = 'processing'
               AND lease_expires_at >= NOW()
            """
        )
        with self._session_factory() as session:
            with session.begin():
                res = session.execute(
                    sql,
                    {
                        "outbox_id": outbox_id,
                        "worker_id": worker_id.strip(),
                        "lease_token": lease_token,
                        "dur": self._lease_duration_seconds,
                    },
                )
                return res.rowcount == 1

    # -------------------------------------------------------------------------
    # Fenced State Transitions
    # -------------------------------------------------------------------------

    def record_hindsight_operation_id(
        self,
        outbox_id: uuid.UUID,
        worker_id: str,
        lease_token: int,
        hindsight_operation_id: str,
    ) -> bool:
        """Persist the remote Hindsight operation ID returned by aretain.

        Enforces:
        - hindsight_operation_id must exactly equal str(operation_id) of the row.
        - Matching outbox_id, lease_owner, lease_token, status='processing', unexpired lease.

        Returns True if updated, False if fenced out or mismatched.
        """
        if not isinstance(hindsight_operation_id, str) or not hindsight_operation_id.strip():
            raise ValueError("hindsight_operation_id must be a non-empty string")

        clean_hindsight_op_id = hindsight_operation_id.strip()

        sql = text(
            """
            UPDATE incident_memory_outbox
               SET hindsight_operation_id = :hindsight_operation_id,
                   updated_at = NOW()
             WHERE outbox_id = :outbox_id
               AND lease_owner = :worker_id
               AND lease_token = :lease_token
               AND status = 'processing'
               AND lease_expires_at >= NOW()
               AND operation_id::text = :hindsight_operation_id
            """
        )
        with self._session_factory() as session:
            with session.begin():
                res = session.execute(
                    sql,
                    {
                        "outbox_id": outbox_id,
                        "worker_id": worker_id.strip(),
                        "lease_token": lease_token,
                        "hindsight_operation_id": clean_hindsight_op_id,
                    },
                )
                return res.rowcount == 1

    def increment_attempt_count(
        self,
        outbox_id: uuid.UUID,
        worker_id: str,
        lease_token: int,
    ) -> Optional[int]:
        """Atomically increment and return attempt_count for an authorized outbound attempt.

        An attempt is counted when an outbound retain submission or remote retry request
        is authorized immediately before external network dispatch, ensuring durability
        even if the process crashes subsequently.

        Guards:
        - outbox_id matching
        - lease_owner == worker_id
        - lease_token == lease_token
        - status == 'processing'
        - lease_expires_at >= NOW()

        Returns:
            The updated integer attempt_count if successfully incremented under valid lease,
            or None if the lease was lost, expired, or fenced out.
        """
        sql = text(
            """
            UPDATE incident_memory_outbox
               SET attempt_count = attempt_count + 1,
                   updated_at = NOW()
             WHERE outbox_id = :outbox_id
               AND lease_owner = :worker_id
               AND lease_token = :lease_token
               AND status = 'processing'
               AND lease_expires_at >= NOW()
            RETURNING attempt_count
            """
        )
        with self._session_factory() as session:
            with session.begin():
                res = session.execute(
                    sql,
                    {
                        "outbox_id": outbox_id,
                        "worker_id": worker_id.strip(),
                        "lease_token": lease_token,
                    },
                ).scalar_one_or_none()
                return int(res) if res is not None else None

    def transition_to_retry_wait(
        self,
        outbox_id: uuid.UUID,
        worker_id: str,
        lease_token: int,
        next_attempt_at: datetime,
        error_code: Optional[str] = None,
    ) -> bool:
        """Transition an outbox row to retry_wait state.

        Releases lease ownership and sets next_attempt_at and optional error_code.
        Does NOT increment attempt_count (attempt_count is incremented atomically
        immediately before outbound dispatch via increment_attempt_count).
        Guarded by active lease ownership and unexpired lease.
        """
        sql = text(
            """
            UPDATE incident_memory_outbox
               SET status = 'retry_wait',
                   next_attempt_at = :next_attempt_at,
                   last_error_code = :error_code,
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   updated_at = NOW()
             WHERE outbox_id = :outbox_id
               AND lease_owner = :worker_id
               AND lease_token = :lease_token
               AND status = 'processing'
               AND lease_expires_at >= NOW()
            """
        )
        with self._session_factory() as session:
            with session.begin():
                res = session.execute(
                    sql,
                    {
                        "outbox_id": outbox_id,
                        "worker_id": worker_id.strip(),
                        "lease_token": lease_token,
                        "next_attempt_at": next_attempt_at,
                        "error_code": error_code,
                    },
                )
                return res.rowcount == 1

    def transition_to_completed(
        self,
        outbox_id: uuid.UUID,
        worker_id: str,
        lease_token: int,
    ) -> bool:
        """Transition an outbox row to terminal completed state.

        Releases lease ownership and records completed_at timestamp.
        Guarded by active lease ownership and unexpired lease.
        """
        sql = text(
            """
            UPDATE incident_memory_outbox
               SET status = 'completed',
                   completed_at = NOW(),
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   updated_at = NOW()
             WHERE outbox_id = :outbox_id
               AND lease_owner = :worker_id
               AND lease_token = :lease_token
               AND status = 'processing'
               AND lease_expires_at >= NOW()
            """
        )
        with self._session_factory() as session:
            with session.begin():
                res = session.execute(
                    sql,
                    {
                        "outbox_id": outbox_id,
                        "worker_id": worker_id.strip(),
                        "lease_token": lease_token,
                    },
                )
                return res.rowcount == 1

    def transition_to_dead_letter(
        self,
        outbox_id: uuid.UUID,
        worker_id: str,
        lease_token: int,
        error_code: Optional[str] = None,
    ) -> bool:
        """Transition an outbox row to terminal dead_letter state.

        Releases lease ownership and records error_code.
        Guarded by active lease ownership and unexpired lease.
        """
        sql = text(
            """
            UPDATE incident_memory_outbox
               SET status = 'dead_letter',
                   last_error_code = :error_code,
                   lease_owner = NULL,
                   lease_expires_at = NULL,
                   updated_at = NOW()
             WHERE outbox_id = :outbox_id
               AND lease_owner = :worker_id
               AND lease_token = :lease_token
               AND status = 'processing'
               AND lease_expires_at >= NOW()
            """
        )
        with self._session_factory() as session:
            with session.begin():
                res = session.execute(
                    sql,
                    {
                        "outbox_id": outbox_id,
                        "worker_id": worker_id.strip(),
                        "lease_token": lease_token,
                        "error_code": error_code,
                    },
                )
                return res.rowcount == 1

    # -------------------------------------------------------------------------
    # Private Helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _to_dto(row: IncidentMemoryOutbox) -> ClaimedMemoryOutboxRow:
        """Convert a live ORM row into an immutable, detached DTO after cryptographic verification."""
        if row.lease_owner is None:
            raise ValueError("Cannot create ClaimedMemoryOutboxRow without lease_owner")
        if row.lease_expires_at is None:
            raise ValueError("Cannot create ClaimedMemoryOutboxRow without lease_expires_at")

        # 1. Canonicalize stored JSONB payload
        try:
            canonical_bytes = canonicalize_payload(row.serialized_memory_payload)
        except Exception as e:
            raise OutboxPayloadIntegrityError(
                f"Outbox entry {row.outbox_id} payload canonicalization failed"
            ) from e

        # 2. Verify payload hash matches SHA-256 digest of canonical bytes
        calculated_hash = calculate_payload_hash(canonical_bytes)
        if calculated_hash != row.payload_hash:
            raise OutboxPayloadIntegrityError(
                f"Outbox entry {row.outbox_id} payload hash mismatch"
            )

        # 3. Verify operation ID matches recomputed deterministic UUID5
        try:
            expected_op_id = generate_operation_id(
                bank_id=row.bank_id,
                document_id=row.document_id,
                version=row.memory_schema_version,
                payload_hash=calculated_hash,
            )
        except Exception as e:
            raise OutboxPayloadIntegrityError(
                f"Outbox entry {row.outbox_id} operation ID derivation failed"
            ) from e

        if expected_op_id != row.operation_id:
            raise OutboxPayloadIntegrityError(
                f"Outbox entry {row.outbox_id} operation ID mismatch"
            )

        serialized_memory_content = canonical_bytes.decode("utf-8")

        return ClaimedMemoryOutboxRow(
            outbox_id=row.outbox_id,
            investigation_id=row.investigation_id,
            incident_id=row.incident_id,
            bank_id=row.bank_id,
            document_id=row.document_id,
            memory_schema_version=row.memory_schema_version,
            payload_hash=row.payload_hash,
            serialized_memory_content=serialized_memory_content,
            operation_id=row.operation_id,
            hindsight_operation_id=row.hindsight_operation_id,
            attempt_count=row.attempt_count,
            lease_owner=row.lease_owner,
            lease_token=row.lease_token,
            lease_expires_at=row.lease_expires_at,
        )

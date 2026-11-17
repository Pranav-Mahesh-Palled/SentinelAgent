"""Asynchronous Single-Row Processor for SentinelAgent Memory Outbox.

Implements Task 9C.3.4 processor architecture:
- Takes one claimed outbox DTO (ClaimedMemoryOutboxRow).
- Maintains database lease via managed asynchronous heartbeat.
- Submits or recovers Hindsight asynchronous retain operations using immutable payload.
- Validates and extracts tags solely from canonical JSON without modifying content.
- Reconciles ambiguous acknowledgements and HTTP 409 responses.
- Monitors remote operation execution and handles failed/cancelled operations with remote retries.
- Performs atomic, fenced state transitions (completed, retry_wait, dead_letter) via claim service.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
import random
from typing import Any, Optional, Sequence
import uuid

from app.core.config import Settings, get_settings
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

logger = logging.getLogger(__name__)


# =============================================================================
# Typed Processing Result
# =============================================================================

@dataclass(frozen=True)
class ProcessResult:
    """Outcome of processing a single claimed outbox record."""

    status: str  # "completed", "retry_wait", "dead_letter", "lease_lost"
    error_code: Optional[str] = None

    @property
    def is_completed(self) -> bool:
        """True if the outbox row reached terminal completed state."""
        return self.status == "completed"

    def __bool__(self) -> bool:
        """Evaluate truthiness based on whether row completed successfully."""
        return self.is_completed


# =============================================================================
# Processor Implementation
# =============================================================================

class HindsightMemoryOutboxProcessor:
    """Asynchronous single-row processor for SentinelAgent memory outbox records."""

    def __init__(
        self,
        hindsight_service: HindsightClientService,
        claim_service: MemoryOutboxClaimService,
        worker_id: str,
        settings: Optional[Settings] = None,
    ) -> None:
        if not isinstance(worker_id, str) or not worker_id.strip():
            raise ValueError("worker_id must be a non-empty string")

        self._hindsight_service = hindsight_service
        self._claim_service = claim_service
        self._worker_id = worker_id.strip()

        app_settings = settings or get_settings()
        self._lease_duration = app_settings.HINDSIGHT_OUTBOX_LEASE_DURATION_SECONDS
        self._heartbeat_interval = app_settings.HINDSIGHT_OUTBOX_LEASE_HEARTBEAT_SECONDS
        self._poll_interval = app_settings.HINDSIGHT_OUTBOX_OPERATION_POLL_INTERVAL_SECONDS
        self._request_timeout = app_settings.HINDSIGHT_OUTBOX_REQUEST_TIMEOUT_SECONDS
        self._max_attempts = app_settings.HINDSIGHT_OUTBOX_MAX_ATTEMPTS
        self._initial_backoff = app_settings.HINDSIGHT_OUTBOX_INITIAL_BACKOFF_SECONDS
        self._max_backoff = app_settings.HINDSIGHT_OUTBOX_MAX_BACKOFF_SECONDS
        self._jitter_fraction = app_settings.HINDSIGHT_OUTBOX_BACKOFF_JITTER_FRACTION

    @property
    def worker_id(self) -> str:
        """Active worker identifier associated with claimed leases."""
        return self._worker_id

    # -------------------------------------------------------------------------
    # Tag Extraction & Validation
    # -------------------------------------------------------------------------

    @staticmethod
    def extract_and_validate_tags(content: str) -> list[str]:
        """Parse canonical JSON solely to validate and extract its top-level tags list.

        Does not modify or reserialize the content string.
        """
        try:
            data = json.loads(content)
        except Exception as exc:
            raise ValueError(f"Malformed JSON content: {exc}") from exc

        if not isinstance(data, dict):
            raise ValueError("Payload must be a JSON object")

        raw_tags = data.get("tags")
        if raw_tags is None:
            return []
        if not isinstance(raw_tags, list):
            raise ValueError("Payload tags must be a list")

        validated: list[str] = []
        for tag in raw_tags:
            if not isinstance(tag, str) or not tag.strip():
                raise ValueError("All tags must be non-empty strings")
            validated.append(tag.strip())
        return validated

    # -------------------------------------------------------------------------
    # Backoff Calculation
    # -------------------------------------------------------------------------

    def compute_backoff_delay(
        self,
        attempt_count: int,
        retry_after: Optional[float] = None,
        rng: Optional[random.Random] = None,
    ) -> float:
        """Compute bounded exponential backoff with jitter and Retry-After support.

        Backoff progression:
        - First failed outbound attempt (attempt_count=1): initial_backoff * (2^0).
        - Second failed outbound attempt (attempt_count=2): 2 * initial_backoff * (2^1).
        - Third failed outbound attempt (attempt_count=3): 4 * initial_backoff * (2^2).

        1. Locally computed exponential backoff is calculated and jittered first:
           base = min(initial_backoff * (2 ** max(0, attempt_count - 1)), max_backoff)
           jittered = base * uniform(1 - jitter, 1 + jitter)
        2. Valid Retry-After minimum is then enforced:
           final_delay >= retry_after (when 0 < retry_after <= max_backoff)
           Ensures downward jitter never undercuts a valid Retry-After interval.
        3. If Retry-After exceeds max_backoff, caps at max_backoff with sanitized logging.
        """
        exponent = max(0, attempt_count - 1) if attempt_count > 0 else 0
        base = min(self._initial_backoff * (2 ** exponent), self._max_backoff)

        if self._jitter_fraction > 0:
            r = rng if rng is not None else random
            factor = r.uniform(1.0 - self._jitter_fraction, 1.0 + self._jitter_fraction)
            local_delay = base * factor
        else:
            local_delay = base

        local_delay = max(0.0, min(local_delay, self._max_backoff))

        if retry_after is not None and retry_after > 0:
            if retry_after > self._max_backoff:
                logger.warning(
                    "Retry-After (%s s) exceeds maximum backoff (%s s); capping at max backoff",
                    retry_after,
                    self._max_backoff,
                )
                final_delay = self._max_backoff
            else:
                # Downward jitter never undercuts a valid compatible Retry-After
                final_delay = max(local_delay, retry_after)
        else:
            final_delay = local_delay

        return max(0.0, min(final_delay, self._max_backoff))

    # -------------------------------------------------------------------------
    # Managed Heartbeat Task
    # -------------------------------------------------------------------------

    async def _heartbeat_loop(
        self,
        row: ClaimedMemoryOutboxRow,
        stop_event: asyncio.Event,
        lease_lost_event: asyncio.Event,
    ) -> None:
        """Periodically renew lease in background until stopped or lease is lost."""
        while not stop_event.is_set() and not lease_lost_event.is_set():
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self._heartbeat_interval)
                break
            except asyncio.TimeoutError:
                pass

            if stop_event.is_set() or lease_lost_event.is_set():
                break

            try:
                renewed = await asyncio.to_thread(
                    self._claim_service.renew_lease,
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                )
            except Exception:
                logger.exception(
                    "Unexpected error during lease renewal for outbox_id=%s",
                    row.outbox_id,
                )
                lease_lost_event.set()
                break

            if not renewed:
                logger.warning(
                    "Lease renewal returned False for outbox_id=%s; lease lost",
                    row.outbox_id,
                )
                lease_lost_event.set()
                break

    # -------------------------------------------------------------------------
    # Single-Row Processing Entrypoint
    # -------------------------------------------------------------------------

    async def process_claimed_row(
        self,
        row: ClaimedMemoryOutboxRow,
        rng: Optional[random.Random] = None,
    ) -> ProcessResult:
        """Process a single claimed outbox row through completion or bounded retry.

        Manages asynchronous heartbeat, submits or reconciles retain operation,
        monitors remote status, handles retries, and performs fenced transitions.
        """
        # Validate worker identity matches claim
        if row.lease_owner != self._worker_id:
            logger.error(
                "Worker ID mismatch for outbox_id=%s: claimed by %s, processor is %s",
                row.outbox_id,
                row.lease_owner,
                self._worker_id,
            )
            return ProcessResult(status="lease_lost")

        # Validate and extract tags from immutable payload text
        try:
            tags = self.extract_and_validate_tags(row.serialized_memory_content)
        except ValueError as exc:
            logger.error(
                "Invalid payload structure for outbox_id=%s; marking dead letter",
                row.outbox_id,
            )
            if self._claim_service.transition_to_dead_letter(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                error_code="INVALID_PAYLOAD_STRUCTURE",
            ):
                return ProcessResult(status="dead_letter", error_code="INVALID_PAYLOAD_STRUCTURE")
            return ProcessResult(status="lease_lost")

        stop_heartbeat = asyncio.Event()
        lease_lost = asyncio.Event()
        heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(row, stop_heartbeat, lease_lost)
        )

        try:
            return await self._execute_processing(
                row=row,
                tags=tags,
                lease_lost=lease_lost,
                rng=rng,
            )
        finally:
            stop_heartbeat.set()
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

    # -------------------------------------------------------------------------
    # Internal Processing Logic
    # -------------------------------------------------------------------------

    async def _execute_processing(
        self,
        row: ClaimedMemoryOutboxRow,
        tags: list[str],
        lease_lost: asyncio.Event,
        rng: Optional[random.Random],
    ) -> ProcessResult:
        """Execute retain submission and monitoring lifecycle under active heartbeat."""
        current_op_id = str(row.operation_id)
        current_attempts = row.attempt_count

        # ---------------------------------------------------------------------
        # 1. Submission / Recovery Phase
        # ---------------------------------------------------------------------
        if row.hindsight_operation_id is None:
            # Row has not yet been acknowledged by Hindsight

            # If attempt budget is already exhausted before retain dispatch,
            # we MUST NOT issue another retain submission.
            # Instead, we reconcile remote status using the deterministic operation_id
            # to verify whether an earlier ambiguous attempt was accepted remotely.
            if current_attempts >= self._max_attempts:
                logger.warning(
                    "Attempt limit exhausted (%s >= %s) for outbox_id=%s with no persisted operation ID; reconciling remote status",
                    current_attempts,
                    self._max_attempts,
                    row.outbox_id,
                )
                return await self._reconcile_exhausted_unacknowledged_row(
                    row=row,
                    current_op_id=current_op_id,
                    current_attempts=current_attempts,
                    lease_lost=lease_lost,
                    rng=rng,
                )

            # Atomically increment attempt_count in PostgreSQL immediately before outbound dispatch
            new_attempts = self._claim_service.increment_attempt_count(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
            )
            if new_attempts is None or lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            current_attempts = new_attempts

            try:
                await self._hindsight_service.retain_investigation_memory(
                    bank_id=row.bank_id,
                    document_id=row.document_id,
                    content=row.serialized_memory_content,
                    tags=tags,
                    update_mode="replace",
                    retain_async=True,
                    operation_id=current_op_id,
                )
            except HindsightConflictError:
                # HTTP 409: Query remote operation status to reconcile
                logger.info(
                    "Retain submission returned HTTP 409 for outbox_id=%s; querying remote status",
                    row.outbox_id,
                )
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")

                try:
                    reconcile_status = await self._hindsight_service.get_operation_status(
                        bank_id=row.bank_id,
                        operation_id=current_op_id,
                    )
                except Exception:
                    # Reconciliation failed
                    if self._claim_service.transition_to_dead_letter(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        error_code="CONFLICT_UNRECONCILED",
                    ):
                        return ProcessResult(status="dead_letter", error_code="CONFLICT_UNRECONCILED")
                    return ProcessResult(status="lease_lost")

                if reconcile_status.operation_id == current_op_id:
                    # Operation identity reconciled; persist operation ID
                    if not self._claim_service.record_hindsight_operation_id(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        hindsight_operation_id=current_op_id,
                    ):
                        return ProcessResult(status="lease_lost")
                else:
                    if self._claim_service.transition_to_dead_letter(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        error_code="CONFLICT_IDENTITY_MISMATCH",
                    ):
                        return ProcessResult(status="dead_letter", error_code="CONFLICT_IDENTITY_MISMATCH")
                    return ProcessResult(status="lease_lost")

            except (
                HindsightTimeoutError,
                HindsightConnectionError,
                HindsightRateLimitError,
                HindsightServerError,
            ) as exc:
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")

                # Ambiguous acknowledgement / retryable failure
                if current_attempts >= self._max_attempts:
                    if self._claim_service.transition_to_dead_letter(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        error_code="MAX_ATTEMPTS_EXCEEDED",
                    ):
                        return ProcessResult(status="dead_letter", error_code="MAX_ATTEMPTS_EXCEEDED")
                    return ProcessResult(status="lease_lost")

                retry_after = getattr(exc, "retry_after", None)
                delay = self.compute_backoff_delay(current_attempts, retry_after=retry_after, rng=rng)
                next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                err_code = getattr(exc, "error_code", "RETAIN_SUBMISSION_FAILED")

                if self._claim_service.transition_to_retry_wait(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    next_attempt_at=next_attempt,
                    error_code=err_code,
                ):
                    return ProcessResult(status="retry_wait", error_code=err_code)
                return ProcessResult(status="lease_lost")

            except (
                HindsightAuthenticationError,
                HindsightValidationError,
                HindsightProtocolError,
                HindsightClientError,
            ) as exc:
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")
                err_code = getattr(exc, "error_code", "PERMANENT_RETAIN_ERROR")
                if self._claim_service.transition_to_dead_letter(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    error_code=err_code,
                ):
                    return ProcessResult(status="dead_letter", error_code=err_code)
                return ProcessResult(status="lease_lost")

            else:
                # Retain submission acknowledged; persist operation ID
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")
                if not self._claim_service.record_hindsight_operation_id(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    hindsight_operation_id=current_op_id,
                ):
                    return ProcessResult(status="lease_lost")

        else:
            # Operation was previously acknowledged; verify identity
            if row.hindsight_operation_id != current_op_id:
                logger.error(
                    "Persisted hindsight_operation_id mismatch for outbox_id=%s: %s != %s",
                    row.outbox_id,
                    row.hindsight_operation_id,
                    current_op_id,
                )
                if self._claim_service.transition_to_dead_letter(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    error_code="OPERATION_ID_MISMATCH",
                ):
                    return ProcessResult(status="dead_letter", error_code="OPERATION_ID_MISMATCH")
                return ProcessResult(status="lease_lost")

        # ---------------------------------------------------------------------
        # 2. Remote Operation Monitoring Phase
        # ---------------------------------------------------------------------
        while True:
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")

            try:
                op_status = await self._hindsight_service.get_operation_status(
                    bank_id=row.bank_id,
                    operation_id=current_op_id,
                )
            except (
                HindsightTimeoutError,
                HindsightConnectionError,
                HindsightServerError,
                HindsightRateLimitError,
            ):
                # Transient network error during polling does not consume attempt count
                logger.warning(
                    "Transient status poll error for outbox_id=%s operation_id=%s; sleeping",
                    row.outbox_id,
                    current_op_id,
                )
                await asyncio.sleep(self._poll_interval)
                continue

            except (
                HindsightAuthenticationError,
                HindsightValidationError,
                HindsightNotFoundError,
                HindsightClientError,
            ) as exc:
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")
                err_code = getattr(exc, "error_code", "STATUS_POLL_FAILED")
                if self._claim_service.transition_to_dead_letter(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    error_code=err_code,
                ):
                    return ProcessResult(status="dead_letter", error_code=err_code)
                return ProcessResult(status="lease_lost")

            # Validate returned operation identity
            if op_status.operation_id != current_op_id:
                logger.warning(
                    "Returned operation_id mismatch during status poll for outbox_id=%s: "
                    "expected %s, got %s; preserving document constraint in retry_wait",
                    row.outbox_id,
                    current_op_id,
                    op_status.operation_id,
                )
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")
                delay = self.compute_backoff_delay(current_attempts, rng=rng)
                next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                if self._claim_service.transition_to_retry_wait(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    next_attempt_at=next_attempt,
                    error_code="OPERATION_ID_MISMATCH",
                ):
                    return ProcessResult(status="retry_wait", error_code="OPERATION_ID_MISMATCH")
                return ProcessResult(status="lease_lost")

            # Check status
            if op_status.status == "completed":
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")
                if self._claim_service.transition_to_completed(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                ):
                    return ProcessResult(status="completed")
                return ProcessResult(status="lease_lost")

            elif op_status.status in ("pending", "processing"):
                await asyncio.sleep(self._poll_interval)
                continue

            elif op_status.status in ("failed", "cancelled"):
                # Remote operation failed or was cancelled
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")

                # Check if attempts are exhausted before dispatching outbound retry request
                if current_attempts >= self._max_attempts:
                    logger.warning(
                        "Attempt limit exhausted (%s >= %s) for outbox_id=%s before remote retry; dead-lettering",
                        current_attempts,
                        self._max_attempts,
                        row.outbox_id,
                    )
                    if self._claim_service.transition_to_dead_letter(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        error_code="MAX_ATTEMPTS_EXCEEDED",
                    ):
                        return ProcessResult(status="dead_letter", error_code="MAX_ATTEMPTS_EXCEEDED")
                    return ProcessResult(status="lease_lost")

                # Atomically increment attempt_count in PostgreSQL immediately before outbound retry dispatch
                new_attempts = self._claim_service.increment_attempt_count(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                )
                if new_attempts is None or lease_lost.is_set():
                    return ProcessResult(status="lease_lost")
                current_attempts = new_attempts

                # Invoke remote retry adapter
                try:
                    retry_res = await self._hindsight_service.retry_operation(
                        bank_id=row.bank_id,
                        operation_id=current_op_id,
                    )
                except HindsightConflictError:
                    # Retry returned 409; query status to verify
                    try:
                        conf_stat = await self._hindsight_service.get_operation_status(
                            bank_id=row.bank_id,
                            operation_id=current_op_id,
                        )
                        if conf_stat.status in ("pending", "processing"):
                            await asyncio.sleep(self._poll_interval)
                            continue
                    except Exception:
                        pass

                    delay = self.compute_backoff_delay(current_attempts, rng=rng)
                    next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                    if self._claim_service.transition_to_retry_wait(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        next_attempt_at=next_attempt,
                        error_code="RETRY_CONFLICT_UNRESOLVED",
                    ):
                        return ProcessResult(status="retry_wait", error_code="RETRY_CONFLICT_UNRESOLVED")
                    return ProcessResult(status="lease_lost")

                except (
                    HindsightTimeoutError,
                    HindsightConnectionError,
                    HindsightRateLimitError,
                    HindsightServerError,
                ) as exc:
                    delay = self.compute_backoff_delay(
                        current_attempts,
                        retry_after=getattr(exc, "retry_after", None),
                        rng=rng,
                    )
                    next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                    err_code = getattr(exc, "error_code", "RETRY_OPERATION_FAILED")
                    if self._claim_service.transition_to_retry_wait(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        next_attempt_at=next_attempt,
                        error_code=err_code,
                    ):
                        return ProcessResult(status="retry_wait", error_code=err_code)
                    return ProcessResult(status="lease_lost")

                except Exception as exc:
                    err_code = getattr(exc, "error_code", "PERMANENT_RETRY_ERROR")
                    if self._claim_service.transition_to_dead_letter(
                        outbox_id=row.outbox_id,
                        worker_id=self._worker_id,
                        lease_token=row.lease_token,
                        error_code=err_code,
                    ):
                        return ProcessResult(status="dead_letter", error_code=err_code)
                    return ProcessResult(status="lease_lost")

                # Retry operation succeeded
                if lease_lost.is_set():
                    return ProcessResult(status="lease_lost")

                # Continue monitoring the same operation ID
                await asyncio.sleep(self._poll_interval)
                continue

            else:
                # Unknown remote status: handle fail-closed
                # Kept strictly unresolved in retry_wait (never dead-lettered solely due to attempt exhaustion)
                logger.error(
                    "Encountered unknown remote operation status '%s' for outbox_id=%s; scheduling status reconciliation",
                    op_status.status,
                    row.outbox_id,
                )
                delay = self.compute_backoff_delay(current_attempts, rng=rng)
                next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
                if self._claim_service.transition_to_retry_wait(
                    outbox_id=row.outbox_id,
                    worker_id=self._worker_id,
                    lease_token=row.lease_token,
                    next_attempt_at=next_attempt,
                    error_code="UNKNOWN_REMOTE_STATUS",
                ):
                    return ProcessResult(status="retry_wait", error_code="UNKNOWN_REMOTE_STATUS")
                return ProcessResult(status="lease_lost")

    async def _reconcile_exhausted_unacknowledged_row(
        self,
        row: ClaimedMemoryOutboxRow,
        current_op_id: str,
        current_attempts: int,
        lease_lost: asyncio.Event,
        rng: Optional[random.Random],
    ) -> ProcessResult:
        """Reconcile an unacknowledged row whose outbound attempt budget is exhausted.

        Does not dispatch retain submissions or remote retries. Queries Hindsight
        using deterministic operation_id to establish remote status:
        - completed: transition to completed.
        - pending / processing: preserve unresolved state in retry_wait for status reconciliation.
        - failed / cancelled: terminal failure established; transition to dead_letter.
        - unknown / transient error / not-found: preserve unresolved state in retry_wait.
        """
        if lease_lost.is_set():
            return ProcessResult(status="lease_lost")

        try:
            op_status = await self._hindsight_service.get_operation_status(
                bank_id=row.bank_id,
                operation_id=current_op_id,
            )
        except (
            HindsightTimeoutError,
            HindsightConnectionError,
            HindsightServerError,
            HindsightRateLimitError,
        ) as exc:
            # Transient error querying status: keep unresolved in retry_wait
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            retry_after = getattr(exc, "retry_after", None)
            delay = self.compute_backoff_delay(current_attempts, retry_after=retry_after, rng=rng)
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            err_code = getattr(exc, "error_code", "STATUS_RECONCILIATION_FAILED")
            if self._claim_service.transition_to_retry_wait(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                next_attempt_at=next_attempt,
                error_code=err_code,
            ):
                return ProcessResult(status="retry_wait", error_code=err_code)
            return ProcessResult(status="lease_lost")

        except HindsightNotFoundError:
            # 404 does not reliably prove the operation was never accepted in Hindsight 1.2.0.
            # Preserve unresolved record and document ordering in retry_wait.
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            delay = self.compute_backoff_delay(current_attempts, rng=rng)
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            if self._claim_service.transition_to_retry_wait(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                next_attempt_at=next_attempt,
                error_code="OPERATION_NOT_FOUND_UNRESOLVED",
            ):
                return ProcessResult(status="retry_wait", error_code="OPERATION_NOT_FOUND_UNRESOLVED")
            return ProcessResult(status="lease_lost")

        except Exception as exc:
            # Unexpected or permanent error querying status: keep unresolved in retry_wait
            # to preserve document ordering and avoid releasing document prematurely
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            err_code = getattr(exc, "error_code", "STATUS_RECONCILIATION_ERROR")
            delay = self.compute_backoff_delay(current_attempts, rng=rng)
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            if self._claim_service.transition_to_retry_wait(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                next_attempt_at=next_attempt,
                error_code=err_code,
            ):
                return ProcessResult(status="retry_wait", error_code=err_code)
            return ProcessResult(status="lease_lost")

        # Returned status object: enforce operation_id match
        if op_status.operation_id != current_op_id:
            logger.warning(
                "Returned operation_id mismatch during reconciliation for outbox_id=%s: "
                "expected %s, got %s; preserving document constraint in retry_wait",
                row.outbox_id,
                current_op_id,
                op_status.operation_id,
            )
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            delay = self.compute_backoff_delay(current_attempts, rng=rng)
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            if self._claim_service.transition_to_retry_wait(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                next_attempt_at=next_attempt,
                error_code="OPERATION_ID_MISMATCH",
            ):
                return ProcessResult(status="retry_wait", error_code="OPERATION_ID_MISMATCH")
            return ProcessResult(status="lease_lost")

        # 1. Remote operation is completed!
        if op_status.status == "completed":
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            self._claim_service.record_hindsight_operation_id(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                hindsight_operation_id=current_op_id,
            )
            if self._claim_service.transition_to_completed(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
            ):
                return ProcessResult(status="completed")
            return ProcessResult(status="lease_lost")

        # 2. Remote operation is in-flight (pending or processing)!
        elif op_status.status in ("pending", "processing"):
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            self._claim_service.record_hindsight_operation_id(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                hindsight_operation_id=current_op_id,
            )
            delay = self.compute_backoff_delay(current_attempts, rng=rng)
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            if self._claim_service.transition_to_retry_wait(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                next_attempt_at=next_attempt,
                error_code="REMOTE_IN_FLIGHT",
            ):
                return ProcessResult(status="retry_wait", error_code="REMOTE_IN_FLIGHT")
            return ProcessResult(status="lease_lost")

        # 3. Remote operation is terminal failed or cancelled!
        elif op_status.status in ("failed", "cancelled"):
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            # Terminal status is established and attempts are exhausted; safe to dead-letter
            if self._claim_service.transition_to_dead_letter(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                error_code="MAX_ATTEMPTS_EXCEEDED",
            ):
                return ProcessResult(status="dead_letter", error_code="MAX_ATTEMPTS_EXCEEDED")
            return ProcessResult(status="lease_lost")

        # 4. Unknown remote status: keep unresolved in retry_wait
        else:
            if lease_lost.is_set():
                return ProcessResult(status="lease_lost")
            delay = self.compute_backoff_delay(current_attempts, rng=rng)
            next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
            if self._claim_service.transition_to_retry_wait(
                outbox_id=row.outbox_id,
                worker_id=self._worker_id,
                lease_token=row.lease_token,
                next_attempt_at=next_attempt,
                error_code="UNKNOWN_REMOTE_STATUS",
            ):
                return ProcessResult(status="retry_wait", error_code="UNKNOWN_REMOTE_STATUS")
            return ProcessResult(status="lease_lost")


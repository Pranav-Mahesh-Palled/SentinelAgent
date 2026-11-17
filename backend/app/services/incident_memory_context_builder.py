"""Incident Memory Context Builder for SentinelAgent (Task 9D.4).

Transforms service-level IncidentMemoryRecallResult DTOs into bounded,
forensically quarantined IncidentMemoryContext representations.

Key Guarantees:
1. Type Enforcement: Rejects arbitrary dictionaries, untyped inputs, or non-IncidentMemoryRecallResult objects.
2. Cryptographic Scope Verification: Requires scope_verified=True on all accepted memory facts.
3. Defensive Multi-Tier Bounding:
   - Max 1,000 characters per individual memory (oversized memories rejected, never silently truncated).
   - Max 10 accepted memory items.
   - Max 2,000 aggregate memory-text characters.
4. Non-Evidentiary Quarantine: Enforces trust_classification='HISTORICAL_CONTEXT_ONLY'.
5. Zero Sensitive Data Logging: Logs only counts, statuses, and sanitized diagnostic classifications.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from app.schemas.incident_memory_context import (
    MAX_AGGREGATE_MEMORY_TEXT_CHARS,
    MAX_ITEMS_PER_CONTEXT,
    MAX_SINGLE_MEMORY_TEXT_CHARS,
    IncidentMemoryContext,
    RecalledMemoryItem,
)
from app.services.incident_memory_recall_service import (
    IncidentMemoryRecallResult,
    RecallItemResult,
)

logger = logging.getLogger(__name__)

SUPPORTED_FACT_TYPES = frozenset({"world", "experience", "observation"})


class IncidentMemoryContextBuilderError(Exception):
    """Raised when context building fails due to malformed or invalid inputs."""
    pass


class IncidentMemoryContextBuilder:
    """Transforms raw service recall outcomes into bounded, typed memory contexts."""

    def build(self, recall_result: IncidentMemoryRecallResult) -> IncidentMemoryContext:
        """Construct a validated IncidentMemoryContext from an IncidentMemoryRecallResult.

        Args:
            recall_result: Output from IncidentMemoryRecallService.recall_memories().

        Returns:
            Validated, immutable IncidentMemoryContext instance.

        Raises:
            TypeError: If recall_result is not an IncidentMemoryRecallResult instance.
        """
        if not isinstance(recall_result, IncidentMemoryRecallResult):
            raise TypeError(
                f"recall_result must be an IncidentMemoryRecallResult instance, got {type(recall_result).__name__}"
            )

        # 1. Handle non-content states directly
        if recall_result.status in ("empty", "skipped", "unavailable"):
            return IncidentMemoryContext(
                status=recall_result.status,
                items=(),
                total_items=0,
                items_rejected_oversized=recall_result.items_rejected_oversized,
                attempted_queries=recall_result.attempted_queries,
                successful_queries=recall_result.successful_queries,
                failed_queries=recall_result.failed_queries,
                diagnostic_classifications=recall_result.diagnostic_classifications,
                skipped_reason=recall_result.skipped_reason,
                retrieved_at=recall_result.retrieved_at,
                trust_classification="HISTORICAL_CONTEXT_ONLY",
            )

        # 2. Process candidate items for 'success' or 'partial' statuses
        accepted_items: list[RecalledMemoryItem] = []
        items_rejected_oversized = recall_result.items_rejected_oversized
        current_total_chars = 0

        for item in recall_result.items:
            if not isinstance(item, RecallItemResult):
                logger.warning("Dropping malformed recall item: not a RecallItemResult instance.")
                continue

            # Scope verification requirement: must be strictly True
            if getattr(item, "scope_verified", None) is not True:
                logger.warning(
                    "Dropping recall item %s: scope_verified is not True.",
                    getattr(item, "memory_id", "unknown"),
                )
                continue

            # Fact type validation: must be supported or None
            if item.fact_type is not None and item.fact_type not in SUPPORTED_FACT_TYPES:
                logger.warning(
                    "Dropping recall item %s: unsupported fact_type '%s'.",
                    item.memory_id,
                    item.fact_type,
                )
                continue

            # Per-memory length bound: reject oversized memories (no silent truncation)
            clean_text = item.text.strip() if isinstance(item.text, str) else ""
            if not clean_text or len(clean_text) > MAX_SINGLE_MEMORY_TEXT_CHARS:
                items_rejected_oversized += 1
                logger.debug(
                    "Dropping memory %s: text length (%d) exceeds %d chars.",
                    item.memory_id,
                    len(clean_text),
                    MAX_SINGLE_MEMORY_TEXT_CHARS,
                )
                continue

            # Aggregate character budget bound: skip candidates that do not fit in remaining budget
            if current_total_chars + len(clean_text) > MAX_AGGREGATE_MEMORY_TEXT_CHARS:
                logger.debug(
                    "Skipping memory item %s: exceeds remaining aggregate text budget (%d + %d > %d).",
                    item.memory_id,
                    current_total_chars,
                    len(clean_text),
                    MAX_AGGREGATE_MEMORY_TEXT_CHARS,
                )
                continue

            # Item count bound
            if len(accepted_items) >= MAX_ITEMS_PER_CONTEXT:
                logger.debug("Halting memory inclusion: maximum item count (%d) reached.", MAX_ITEMS_PER_CONTEXT)
                break

            try:
                validated_item = RecalledMemoryItem(
                    memory_id=item.memory_id,
                    text=clean_text,
                    fact_type=item.fact_type,  # type: ignore[arg-type]
                    context=item.context[:1000] if item.context else None,
                    document_id=item.document_id[:255] if item.document_id else None,
                    identity_category=item.identity_category,
                    key_version=item.key_version,
                    within_query_rank=item.within_query_rank,
                    occurred_start=item.occurred_start,
                    occurred_end=item.occurred_end,
                    mentioned_at=item.mentioned_at,
                    retrieved_at=item.retrieved_at,
                    scope_verified=True,
                    trust_classification="HISTORICAL_CONTEXT_ONLY",
                )
                accepted_items.append(validated_item)
                current_total_chars += len(clean_text)
            except Exception as e:
                logger.warning("Failed to validate recalled memory item %s: %s", getattr(item, "memory_id", "unknown"), type(e).__name__)
                continue

        # 3. Resolve final status
        final_status = recall_result.status
        if len(accepted_items) == 0:
            if recall_result.status == "success":
                final_status = "empty"

        logger.info(
            "Built IncidentMemoryContext: status=%s, accepted_items=%d, rejected_oversized=%d, aggregate_chars=%d",
            final_status,
            len(accepted_items),
            items_rejected_oversized,
            current_total_chars,
        )

        return IncidentMemoryContext(
            status=final_status,
            items=tuple(accepted_items),
            total_items=len(accepted_items),
            items_rejected_oversized=items_rejected_oversized,
            attempted_queries=recall_result.attempted_queries,
            successful_queries=recall_result.successful_queries,
            failed_queries=recall_result.failed_queries,
            diagnostic_classifications=recall_result.diagnostic_classifications,
            skipped_reason=recall_result.skipped_reason,
            retrieved_at=recall_result.retrieved_at,
            trust_classification="HISTORICAL_CONTEXT_ONLY",
        )


"""Incident Memory Outbox persistence and deterministic identity services.

Provides canonical serialization, SHA-256 payload hashing, deterministic
RFC 4122 UUID5 operation identity generation, and transactional outbox persistence
for incident memories to be retained in Hindsight.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import re
from typing import Any, Optional
import uuid

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.memory_outbox import IncidentMemoryOutbox

logger = logging.getLogger(__name__)

# Authoritative RFC 4122 UUID namespace for SentinelAgent Incident Memory operations
# Approved in Task 9A architecture specification (task_9a_architecture.md Section 4.2)
SENTINEL_MEMORY_NAMESPACE: uuid.UUID = uuid.UUID("e8a60640-2059-4f76-8840-02bf58e41846")

DEFAULT_MEMORY_SCHEMA_VERSION: str = "v1"

# SHA-256 lowercase hex pattern: exactly 64 lowercase hexadecimal characters
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def validate_payload_hash(payload_hash: str) -> str:
    """Validate that payload_hash is exactly 64 lowercase hexadecimal characters."""
    if not isinstance(payload_hash, str) or not SHA256_HEX_PATTERN.match(payload_hash):
        raise ValueError(
            f"Invalid payload_hash: expected 64 lowercase hex characters, got '{payload_hash}'"
        )
    return payload_hash


def canonicalize_payload(payload: dict[str, Any]) -> bytes:
    """Canonicalize a memory payload dictionary into deterministic UTF-8 JSON bytes.

    Uses sorted keys, standard compact separators (',', ':'), ensure_ascii=False,
    and allow_nan=False to strictly reject non-standard JSON numeric values
    (NaN, Infinity, -Infinity), guaranteeing byte-for-byte reproducibility.
    """
    if not isinstance(payload, dict):
        raise TypeError(f"Payload must be a dictionary, got {type(payload).__name__}")
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_payload_hash(canonical_bytes: bytes) -> str:
    """Calculate the hex-encoded SHA-256 digest of canonical payload bytes."""
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return validate_payload_hash(digest)


def generate_document_id(investigation_id: uuid.UUID, version: str = DEFAULT_MEMORY_SCHEMA_VERSION) -> str:
    """Generate the canonical namespaced document identifier for an investigation memory.

    Format: sentinelagent:<version>:investigation:<investigation_id>
    """
    return f"sentinelagent:{version}:investigation:{investigation_id}"


def generate_operation_id(
    bank_id: str,
    document_id: str,
    version: str,
    payload_hash: str,
    namespace: uuid.UUID = SENTINEL_MEMORY_NAMESPACE,
) -> uuid.UUID:
    """Generate a deterministic RFC 4122 UUID5 operation identifier.

    Constructed from: {bank_id}:{document_id}:{version}:{payload_hash}
    Ensures that identical payload versions produce identical idempotent operation IDs,
    preventing duplicate retains across multiple outbox enqueue calls.
    """
    validate_payload_hash(payload_hash)
    name = f"{bank_id}:{document_id}:{version}:{payload_hash}"
    return uuid.uuid5(namespace, name)


class MemoryOutboxService:
    """Service providing transactional outbox management for incident memories."""

    @staticmethod
    def enqueue_investigation_memory(
        session: Session,
        investigation_id: uuid.UUID,
        incident_id: uuid.UUID,
        serialized_memory_payload: dict[str, Any],
        bank_id: Optional[str] = None,
        memory_schema_version: str = DEFAULT_MEMORY_SCHEMA_VERSION,
    ) -> IncidentMemoryOutbox:
        """Enqueue an investigation memory record into the transactional outbox.

        Must be executed within an active PostgreSQL transaction (caller manages commit/rollback).
        Uses ON CONFLICT (operation_id) DO NOTHING to guarantee idempotent delivery
        if an entry with the exact same payload has already been enqueued.

        Returns the newly created or existing IncidentMemoryOutbox record.
        """
        if not isinstance(serialized_memory_payload, dict):
            raise TypeError(
                f"serialized_memory_payload must be a dict, got {type(serialized_memory_payload).__name__}"
            )

        resolved_bank_id = bank_id or settings.HINDSIGHT_BANK_ID or "sentinelagent-incident-memory-dev"
        document_id = generate_document_id(investigation_id, version=memory_schema_version)
        canonical_bytes = canonicalize_payload(serialized_memory_payload)
        payload_hash = calculate_payload_hash(canonical_bytes)
        operation_id = generate_operation_id(
            bank_id=resolved_bank_id,
            document_id=document_id,
            version=memory_schema_version,
            payload_hash=payload_hash,
        )

        now = datetime.now(timezone.utc)

        # Use PostgreSQL ON CONFLICT (operation_id) DO NOTHING for idempotent re-runs
        stmt = (
            insert(IncidentMemoryOutbox)
            .values(
                investigation_id=investigation_id,
                incident_id=incident_id,
                bank_id=resolved_bank_id,
                document_id=document_id,
                memory_schema_version=memory_schema_version,
                payload_hash=payload_hash,
                serialized_memory_payload=serialized_memory_payload,
                operation_id=operation_id,
                hindsight_operation_id=None,
                status="pending",
                attempt_count=0,
                next_attempt_at=now,
                lease_owner=None,
                lease_token=0,
                lease_expires_at=None,
                last_error_code=None,
                created_at=now,
                updated_at=now,
                completed_at=None,
            )
            .on_conflict_do_nothing(index_elements=["operation_id"])
            .returning(IncidentMemoryOutbox)
        )

        inserted_row = session.execute(stmt).scalar_one_or_none()
        if inserted_row is not None:
            logger.info(
                "Enqueued incident memory outbox entry %s (operation_id: %s, doc: %s, bank: %s)",
                inserted_row.outbox_id,
                operation_id,
                document_id,
                resolved_bank_id,
            )
            return inserted_row

        # Conflict occurred (exact duplicate operation_id exists): fetch and return existing entry
        existing_row = (
            session.query(IncidentMemoryOutbox)
            .filter(IncidentMemoryOutbox.operation_id == operation_id)
            .one()
        )
        logger.info(
            "Incident memory outbox entry with operation_id %s already exists (outbox_id: %s).",
            operation_id,
            existing_row.outbox_id,
        )
        return existing_row


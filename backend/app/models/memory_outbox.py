"""Incident Memory Outbox declarative model for SentinelAgent.

Implements the transactional outbox pattern for asynchronous persistence of
sanitized incident memories to Hindsight. Ensures that investigation completions
and memory retention events are committed atomically within the same PostgreSQL
transaction, eliminating dual-write failure windows.
"""

from datetime import datetime
from typing import Any, Optional
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_OUTBOX_STATUSES = (
    "pending",
    "processing",
    "retry_wait",
    "completed",
    "dead_letter",
    "superseded",
)


class IncidentMemoryOutbox(Base):
    """Declarative model for persistent incident memory outbox queue."""

    __tablename__ = "incident_memory_outbox"

    outbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "investigations.investigation_id",
            name="fk_memory_outbox_investigation_id_investigations",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "incidents.incident_id",
            name="fk_memory_outbox_incident_id_incidents",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    bank_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    document_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    memory_schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v1",
        server_default=text("'v1'"),
    )
    payload_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    serialized_memory_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    hindsight_operation_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    lease_owner: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    lease_token: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error_code: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="memory_outbox_entries",
    )
    incident: Mapped["Incident"] = relationship(
        "Incident",
    )

    __table_args__ = (
        CheckConstraint(
            f"status IN {VALID_OUTBOX_STATUSES}",
            name="status_valid",
        ),
        CheckConstraint(
            "attempt_count >= 0",
            name="attempt_count_non_negative",
        ),
        CheckConstraint(
            "lease_token >= 0",
            name="lease_token_non_negative",
        ),
        CheckConstraint(
            "status != 'processing' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="processing_lease_invariant",
        ),
        CheckConstraint(
            "status != 'completed' OR completed_at IS NOT NULL",
            name="completed_timestamp_invariant",
        ),
        CheckConstraint(
            "jsonb_typeof(serialized_memory_payload) = 'object'",
            name="payload_is_object",
        ),
        CheckConstraint(
            "payload_hash ~ '^[0-9a-f]{64}$'",
            name="payload_hash_format",
        ),
        UniqueConstraint(
            "operation_id",
            name="uq_incident_memory_outbox_operation_id",
        ),
        Index(
            "ix_memory_outbox_claim",
            "status",
            "next_attempt_at",
            postgresql_where=text("status IN ('pending', 'retry_wait')"),
        ),
        Index(
            "ix_memory_outbox_lease",
            "status",
            "lease_expires_at",
            postgresql_where=text("status = 'processing'"),
        ),
        Index(
            "ix_memory_outbox_doc_status",
            "bank_id",
            "document_id",
            "status",
            "created_at",
            "outbox_id",
        ),
        Index(
            "ix_memory_outbox_investigation_id",
            "investigation_id",
        ),
    )


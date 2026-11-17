"""Response Audit Event declarative model for SentinelAgent.

Implements an append-only, immutable forensic audit trail capturing every state transition,
actor attribution, reconciliation linkage, and response snapshot.
"""

from datetime import datetime
from typing import Any, Optional
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_AUDIT_ACTOR_TYPES = ("operator", "system_worker", "recovery_sweeper")
VALID_AUDIT_ACTOR_ROLES = ("analyst", "approver", "admin", "system")
VALID_AUDIT_EVENT_TYPES = (
    "proposal.created",
    "approval.granted",
    "approval.rejected",
    "proposal.cancelled",
    "proposal.expired",
    "execution.cancelled",
    "execution.expired",
    "execution.claimed",
    "execution.requeued",
    "execution.succeeded",
    "execution.failed",
    "execution.indeterminate",
    "execution.reconciled_success",
    "verification.claimed",
    "verification.replayed",
    "verification.succeeded",
    "verification.failed",
    "verification.inconclusive",
    "verification.reconciled_verified",
    "verification.reconciled_failed",
)


class ResponseAuditEvent(Base):
    """Declarative model for append-only response audit events."""

    __tablename__ = "response_audit_events"

    response_audit_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    response_action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    reconciliation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    sequence_number: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    from_approval_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    to_approval_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    from_execution_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    to_execution_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    from_verification_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    to_verification_status: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    actor_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    actor_operator_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    actor_role_snapshot: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    event_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    payload_sha256_snapshot: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    client_ip: Mapped[Optional[str]] = mapped_column(
        INET,
        nullable=True,
    )
    idempotency_key_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    request_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    response_status_code: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    response_snapshot: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    response_action: Mapped["ResponseAction"] = relationship(
        "ResponseAction",
        back_populates="audit_events",
        primaryjoin="ResponseAuditEvent.response_action_id == ResponseAction.response_action_id",
        foreign_keys="[ResponseAuditEvent.response_action_id]",
    )
    reconciliation_record: Mapped[Optional["VerificationReconciliationRecord"]] = relationship(
        "VerificationReconciliationRecord",
        primaryjoin="ResponseAuditEvent.reconciliation_id == VerificationReconciliationRecord.reconciliation_id",
        foreign_keys="[ResponseAuditEvent.reconciliation_id]",
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["response_action_id", "correlation_id"],
            ["response_actions.response_action_id", "response_actions.correlation_id"],
            name="fk_resp_audit_action_correlation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["reconciliation_id", "response_action_id", "correlation_id"],
            [
                "verification_reconciliation_records.reconciliation_id",
                "verification_reconciliation_records.response_action_id",
                "verification_reconciliation_records.correlation_id",
            ],
            name="fk_resp_audit_reconciliation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("response_action_id", "sequence_number", name="uq_response_audit_sequence"),
        CheckConstraint("sequence_number > 0", name="chk_audit_seq_positive"),
        CheckConstraint(
            "actor_type IN ('operator', 'system_worker', 'recovery_sweeper')",
            name="chk_audit_actor_type",
        ),
        CheckConstraint(
            "actor_role_snapshot IN ('analyst', 'approver', 'admin', 'system')",
            name="chk_audit_actor_role",
        ),
        CheckConstraint("payload_sha256_snapshot ~ '^[0-9a-f]{64}$'", name="chk_audit_payload_sha256_format"),
        CheckConstraint("jsonb_typeof(event_data) = 'object'", name="chk_audit_event_data_is_object"),
        CheckConstraint(
            "idempotency_key_hash IS NULL OR (response_status_code IS NOT NULL AND response_snapshot IS NOT NULL AND jsonb_typeof(response_snapshot) = 'object')",
            name="chk_audit_idempotency_snapshot",
        ),
        CheckConstraint(
            f"event_type IN {VALID_AUDIT_EVENT_TYPES}",
            name="chk_audit_event_type",
        ),
        Index(
            "uq_response_audit_operator_idempotency",
            "actor_operator_id",
            "idempotency_key_hash",
            unique=True,
            postgresql_where=text("idempotency_key_hash IS NOT NULL"),
        ),
        Index(
            "uq_response_audit_reconciliation",
            "reconciliation_id",
            unique=True,
            postgresql_where=text("reconciliation_id IS NOT NULL"),
        ),
        Index("ix_response_audit_action_seq", "response_action_id", "sequence_number"),
        Index("ix_response_audit_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseAuditEvent(event_id={self.response_audit_event_id}, "
            f"action_id={self.response_action_id}, "
            f"seq={self.sequence_number}, "
            f"type='{self.event_type}')>"
        )

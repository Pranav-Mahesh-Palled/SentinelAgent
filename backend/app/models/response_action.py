"""Response Action declarative model for SentinelAgent.

Represents an immutable response proposal, approval state machine,
execution dispatch gate, and verification lifecycle.
"""

from datetime import datetime
from typing import Any, Optional
import uuid

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
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

VALID_ACTION_TYPES = ("simulation.block_source_ip",)
VALID_APPROVAL_STATUSES = ("pending_approval", "approved", "rejected", "cancelled", "expired")
VALID_EXECUTION_STATUSES = (
    "not_queued",
    "queued",
    "running",
    "succeeded",
    "failed",
    "indeterminate",
    "cancelled",
    "expired",
)
VALID_VERIFICATION_STATUSES = ("not_started", "pending", "verified", "failed", "inconclusive")


class ResponseAction(Base):
    """Declarative model representing a cybersecurity response action proposal and execution lifecycle."""

    __tablename__ = "response_actions"

    response_action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.incident_id", name="fk_resp_actions_incident_id_incidents", ondelete="RESTRICT"),
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.investigation_id", name="fk_resp_actions_investigation_id_investigations", ondelete="RESTRICT"),
        nullable=False,
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    action_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="simulation.block_source_ip",
        server_default=text("'simulation.block_source_ip'"),
    )
    action_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    target_kind: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="source_ip",
        server_default=text("'source_ip'"),
    )
    target_value: Mapped[str] = mapped_column(
        INET,
        nullable=False,
    )
    payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    payload_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    approved_payload_sha256: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    justification: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evidence_refs: Mapped[list[Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    policy_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v1",
        server_default=text("'v1'"),
    )
    proposed_by_operator_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    approval_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending_approval",
        server_default=text("'pending_approval'"),
    )
    execution_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="not_queued",
        server_default=text("'not_queued'"),
    )
    verification_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="not_started",
        server_default=text("'not_started'"),
    )
    approval_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    execution_deadline_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    last_audit_sequence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    idempotency_key_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    proposal_response_status_code: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=201,
        server_default=text("201"),
    )
    proposal_response_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
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

    # Relationships
    incident: Mapped["Incident"] = relationship(
        "Incident",
        primaryjoin="ResponseAction.incident_id == Incident.incident_id",
        foreign_keys="[ResponseAction.incident_id]",
    )
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        primaryjoin="ResponseAction.investigation_id == Investigation.investigation_id",
        foreign_keys="[ResponseAction.investigation_id]",
    )
    evidence_associations: Mapped[list["ResponseActionEvidence"]] = relationship(
        "ResponseActionEvidence",
        back_populates="response_action",
        primaryjoin="ResponseAction.response_action_id == ResponseActionEvidence.response_action_id",
        foreign_keys="[ResponseActionEvidence.response_action_id]",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_events: Mapped[list["ResponseAuditEvent"]] = relationship(
        "ResponseAuditEvent",
        back_populates="response_action",
        primaryjoin="ResponseAction.response_action_id == ResponseAuditEvent.response_action_id",
        foreign_keys="[ResponseAuditEvent.response_action_id]",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    outbox_entries: Mapped[list["ResponseOutbox"]] = relationship(
        "ResponseOutbox",
        back_populates="response_action",
        primaryjoin="ResponseAction.response_action_id == ResponseOutbox.response_action_id",
        foreign_keys="[ResponseOutbox.response_action_id]",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    simulated_blocklist_entry: Mapped[Optional["SimulatedBlocklistEntry"]] = relationship(
        "SimulatedBlocklistEntry",
        back_populates="response_action",
        primaryjoin="ResponseAction.response_action_id == SimulatedBlocklistEntry.response_action_id",
        foreign_keys="[SimulatedBlocklistEntry.response_action_id]",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    verification_reconciliation_records: Mapped[list["VerificationReconciliationRecord"]] = relationship(
        "VerificationReconciliationRecord",
        back_populates="response_action",
        primaryjoin="ResponseAction.response_action_id == VerificationReconciliationRecord.response_action_id",
        foreign_keys="[VerificationReconciliationRecord.response_action_id]",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["incident_id", "investigation_id"],
            ["investigations.incident_id", "investigations.investigation_id"],
            name="fk_resp_actions_incident_investigation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("incident_id", "idempotency_key_hash", name="uq_response_actions_incident_idempotency"),
        UniqueConstraint("response_action_id", "investigation_id", name="uq_response_actions_action_investigation"),
        UniqueConstraint("response_action_id", "correlation_id", name="uq_response_actions_action_correlation"),
        CheckConstraint("action_type = 'simulation.block_source_ip'", name="chk_resp_action_type"),
        CheckConstraint("action_version > 0", name="chk_resp_action_version"),
        CheckConstraint("target_kind = 'source_ip'", name="chk_resp_target_kind"),
        CheckConstraint("jsonb_typeof(payload_json) = 'object'", name="chk_resp_payload_json_is_object"),
        CheckConstraint("payload_sha256 ~ '^[0-9a-f]{64}$'", name="chk_resp_payload_sha256_format"),
        CheckConstraint(
            "approved_payload_sha256 IS NULL OR approved_payload_sha256 ~ '^[0-9a-f]{64}$'",
            name="chk_resp_approved_sha256_format",
        ),
        CheckConstraint("version > 0", name="chk_resp_version_positive"),
        CheckConstraint("last_audit_sequence >= 0", name="chk_resp_audit_seq_non_negative"),
        CheckConstraint(
            "approval_status IN ('pending_approval', 'approved', 'rejected', 'cancelled', 'expired')",
            name="chk_resp_approval_status",
        ),
        CheckConstraint(
            "execution_status IN ('not_queued', 'queued', 'running', 'succeeded', 'failed', 'indeterminate', 'cancelled', 'expired')",
            name="chk_resp_execution_status",
        ),
        CheckConstraint(
            "verification_status IN ('not_started', 'pending', 'verified', 'failed', 'inconclusive')",
            name="chk_resp_verification_status",
        ),
        CheckConstraint(
            "((approval_status = 'approved' AND execution_status != 'not_queued') OR (approval_status != 'approved' AND execution_status = 'not_queued'))",
            name="chk_resp_approval_execution_bidirectional",
        ),
        CheckConstraint(
            "((execution_status = 'succeeded' AND verification_status != 'not_started') OR (execution_status != 'succeeded' AND verification_status = 'not_started'))",
            name="chk_resp_execution_verification_bidirectional",
        ),
        CheckConstraint(
            "((approval_status = 'approved' AND approved_payload_sha256 IS NOT NULL AND approved_payload_sha256 = payload_sha256 AND execution_deadline_at IS NOT NULL) OR (approval_status != 'approved' AND approved_payload_sha256 IS NULL AND execution_deadline_at IS NULL))",
            name="chk_resp_approval_digest_deadline_bidirectional",
        ),
        Index(
            "uq_response_actions_single_active_per_incident",
            "incident_id",
            unique=True,
            postgresql_where=text(
                "approval_status = 'pending_approval' "
                "OR execution_status IN ('queued', 'running', 'indeterminate') "
                "OR verification_status IN ('pending', 'inconclusive')"
            ),
        ),
        Index("ix_response_actions_incident_id", "incident_id"),
        Index("ix_response_actions_investigation_id", "investigation_id"),
        Index("ix_response_actions_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseAction(response_action_id={self.response_action_id}, "
            f"incident_id={self.incident_id}, "
            f"approval_status='{self.approval_status}', "
            f"execution_status='{self.execution_status}', "
            f"verification_status='{self.verification_status}')>"
        )

"""Verification Reconciliation Record declarative model for SentinelAgent.

Represents an immutable manual reconciliation decision for inconclusive verification outcomes.
"""

from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
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
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_RECONCILIATION_RESOLUTIONS = ("confirm_verified", "confirm_failed")


class VerificationReconciliationRecord(Base):
    """Declarative model for verification reconciliation audit records."""

    __tablename__ = "verification_reconciliation_records"

    reconciliation_id: Mapped[uuid.UUID] = mapped_column(
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
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    actor_operator_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    resolution: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    synthetic_scenario_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    observation_window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    observation_window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expected_probes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    generated_probes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    captured_probes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    intercepted_probes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    telemetry_coverage_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )
    justification: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    response_action: Mapped["ResponseAction"] = relationship(
        "ResponseAction",
        back_populates="verification_reconciliation_records",
        primaryjoin="VerificationReconciliationRecord.response_action_id == ResponseAction.response_action_id",
        foreign_keys="[VerificationReconciliationRecord.response_action_id]",
    )
    evidence_items: Mapped[list["VerificationReconciliationEvidence"]] = relationship(
        "VerificationReconciliationEvidence",
        back_populates="reconciliation_record",
        primaryjoin="VerificationReconciliationRecord.reconciliation_id == VerificationReconciliationEvidence.reconciliation_id",
        foreign_keys="[VerificationReconciliationEvidence.reconciliation_id]",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    probes: Mapped[list["VerificationReconciliationProbe"]] = relationship(
        "VerificationReconciliationProbe",
        back_populates="reconciliation_record",
        primaryjoin="VerificationReconciliationRecord.reconciliation_id == VerificationReconciliationProbe.reconciliation_id",
        foreign_keys="[VerificationReconciliationProbe.reconciliation_id]",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint("reconciliation_id", "investigation_id", name="uq_verif_rec_record_investigation"),
        UniqueConstraint(
            "reconciliation_id",
            "response_action_id",
            "correlation_id",
            name="uq_verif_rec_action_correlation",
        ),
        ForeignKeyConstraint(
            ["response_action_id", "correlation_id"],
            ["response_actions.response_action_id", "response_actions.correlation_id"],
            name="fk_verif_rec_action_correlation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["response_action_id", "investigation_id"],
            ["response_actions.response_action_id", "response_actions.investigation_id"],
            name="fk_verif_rec_action_investigation",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "resolution IN ('confirm_verified', 'confirm_failed')",
            name="chk_verif_rec_resolution",
        ),
        CheckConstraint(
            "observation_window_end > observation_window_start",
            name="chk_verif_rec_window",
        ),
        CheckConstraint(
            "expected_probes > 0 AND generated_probes = expected_probes AND captured_probes >= generated_probes AND intercepted_probes >= 0",
            name="chk_verif_rec_probes_valid",
        ),
        CheckConstraint(
            "resolution != 'confirm_verified' OR (intercepted_probes = generated_probes)",
            name="chk_verif_rec_verified_math",
        ),
        CheckConstraint(
            "resolution != 'confirm_failed' OR (intercepted_probes = 0 AND telemetry_coverage_verified = TRUE)",
            name="chk_verif_rec_failed_math",
        ),
        Index("ix_verif_rec_action", "response_action_id"),
        Index("ix_verif_rec_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<VerificationReconciliationRecord(reconciliation_id={self.reconciliation_id}, "
            f"action_id={self.response_action_id}, "
            f"resolution='{self.resolution}')>"
        )

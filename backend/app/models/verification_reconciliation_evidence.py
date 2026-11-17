"""Verification Reconciliation Evidence associative model for SentinelAgent.

Associates authoritative forensic evidence items with a verification reconciliation record,
enforcing that the evidence and the reconciliation record share the exact same investigation identity.
"""

from datetime import datetime
from typing import Any
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class VerificationReconciliationEvidence(Base):
    """Associative model binding verification reconciliation decisions to supporting evidence."""

    __tablename__ = "verification_reconciliation_evidence"

    reconciliation_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    reconciliation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    evidence_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    evidence_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    reconciliation_record: Mapped["VerificationReconciliationRecord"] = relationship(
        "VerificationReconciliationRecord",
        back_populates="evidence_items",
        primaryjoin="VerificationReconciliationEvidence.reconciliation_id == VerificationReconciliationRecord.reconciliation_id",
        foreign_keys="[VerificationReconciliationEvidence.reconciliation_id]",
    )
    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem",
        primaryjoin="VerificationReconciliationEvidence.evidence_id == EvidenceItem.evidence_id",
        foreign_keys="[VerificationReconciliationEvidence.evidence_id]",
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["reconciliation_id", "investigation_id"],
            [
                "verification_reconciliation_records.reconciliation_id",
                "verification_reconciliation_records.investigation_id",
            ],
            name="fk_verif_rec_evid_record_investigation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "investigation_id"],
            ["evidence_items.evidence_id", "evidence_items.investigation_id"],
            name="fk_verif_rec_evid_item_investigation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("reconciliation_id", "evidence_id", name="uq_verif_rec_evidence"),
        CheckConstraint("evidence_sha256 ~ '^[0-9a-f]{64}$'", name="chk_verif_rec_evid_sha256"),
        CheckConstraint("jsonb_typeof(evidence_snapshot) = 'object'", name="chk_verif_rec_evid_snapshot_object"),
        Index("ix_verif_rec_evid_rec", "reconciliation_id"),
        Index("ix_verif_rec_evid_item", "evidence_id", "investigation_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<VerificationReconciliationEvidence(rec_id={self.reconciliation_id}, "
            f"evidence_id={self.evidence_id}, "
            f"investigation_id={self.investigation_id})>"
        )

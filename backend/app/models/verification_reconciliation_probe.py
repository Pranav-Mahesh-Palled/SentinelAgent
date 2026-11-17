"""Verification Reconciliation Probe declarative model for SentinelAgent.

Normalizes per-probe synthetic test evidence for verification reconciliation decisions,
establishing an individual 1-to-1 bijection for every expected synthetic probe.
"""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class VerificationReconciliationProbe(Base):
    """Declarative model for individual synthetic probe evidence records."""

    __tablename__ = "verification_reconciliation_probes"

    probe_record_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    reconciliation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    probe_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    generation_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    capture_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    intercepted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )
    interception_evidence_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    reconciliation_record: Mapped["VerificationReconciliationRecord"] = relationship(
        "VerificationReconciliationRecord",
        back_populates="probes",
        primaryjoin="VerificationReconciliationProbe.reconciliation_id == VerificationReconciliationRecord.reconciliation_id",
        foreign_keys="[VerificationReconciliationProbe.reconciliation_id]",
    )
    generation_evidence: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem",
        foreign_keys=[generation_evidence_id],
    )
    capture_evidence: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem",
        foreign_keys=[capture_evidence_id],
    )
    interception_evidence: Mapped[Optional["EvidenceItem"]] = relationship(
        "EvidenceItem",
        foreign_keys=[interception_evidence_id],
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["reconciliation_id", "investigation_id"],
            [
                "verification_reconciliation_records.reconciliation_id",
                "verification_reconciliation_records.investigation_id",
            ],
            name="fk_verif_probe_record_investigation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["generation_evidence_id", "investigation_id"],
            ["evidence_items.evidence_id", "evidence_items.investigation_id"],
            name="fk_verif_probe_gen_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["capture_evidence_id", "investigation_id"],
            ["evidence_items.evidence_id", "evidence_items.investigation_id"],
            name="fk_verif_probe_cap_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["interception_evidence_id", "investigation_id"],
            ["evidence_items.evidence_id", "evidence_items.investigation_id"],
            name="fk_verif_probe_int_evidence",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("reconciliation_id", "probe_id", name="uq_verif_probe_run_probe"),
        CheckConstraint(
            "(intercepted = FALSE AND interception_evidence_id IS NULL) "
            "OR (intercepted = TRUE AND interception_evidence_id IS NOT NULL)",
            name="chk_verif_probe_interception_evidence",
        ),
        Index("ix_verif_probes_reconciliation", "reconciliation_id"),
        Index("ix_verif_probes_probe_id", "probe_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<VerificationReconciliationProbe(rec_id={self.reconciliation_id}, "
            f"probe_id='{self.probe_id}', "
            f"intercepted={self.intercepted})>"
        )

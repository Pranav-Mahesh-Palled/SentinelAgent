"""Response Action Evidence associative model for SentinelAgent.

Binds discrete forensic evidence items gathered during an investigation to a proposed response action,
enforcing that both the action and evidence belong to the exact same investigation.
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


class ResponseActionEvidence(Base):
    """Associative model binding a response action to its supporting forensic evidence."""

    __tablename__ = "response_action_evidence"

    response_action_evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    response_action_id: Mapped[uuid.UUID] = mapped_column(
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
    evidence_type: Mapped[str] = mapped_column(
        String(32),
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
    response_action: Mapped["ResponseAction"] = relationship(
        "ResponseAction",
        back_populates="evidence_associations",
    )
    evidence_item: Mapped["EvidenceItem"] = relationship(
        "EvidenceItem",
        overlaps="response_action",
    )
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        primaryjoin="ResponseActionEvidence.investigation_id == Investigation.investigation_id",
        foreign_keys="[ResponseActionEvidence.investigation_id]",
        viewonly=True,
        overlaps="response_action,evidence_item",
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["response_action_id", "investigation_id"],
            ["response_actions.response_action_id", "response_actions.investigation_id"],
            name="fk_resp_evid_action_investigation",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "investigation_id"],
            ["evidence_items.evidence_id", "evidence_items.investigation_id"],
            name="fk_resp_evid_item_investigation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("response_action_id", "evidence_id", name="uq_response_action_evidence"),
        CheckConstraint("evidence_sha256 ~ '^[0-9a-f]{64}$'", name="chk_resp_evid_sha256"),
        CheckConstraint("jsonb_typeof(evidence_snapshot) = 'object'", name="chk_resp_evid_snapshot_object"),
        Index("ix_resp_action_evid_composite", "response_action_id", "investigation_id"),
        Index("ix_resp_action_evid_item", "evidence_id", "investigation_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseActionEvidence(action_id={self.response_action_id}, "
            f"evidence_id={self.evidence_id}, "
            f"investigation_id={self.investigation_id})>"
        )

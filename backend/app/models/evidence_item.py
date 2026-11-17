"""Evidence Item database model for SentinelAgent.

Stores discrete forensic and context evidence gathered during an AI-assisted
investigation, referencing existing raw events, detection outputs, playbooks, or MITRE techniques.
"""

from datetime import datetime
from typing import Any, Optional
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_EVIDENCE_TYPES = (
    "ssh_event",
    "detection_result",
    "mitre_technique",
    "security_playbook",
    "historical_incident",
)


class EvidenceItem(Base):
    """Declarative model representing a unit of evidence collected during investigation."""

    __tablename__ = "evidence_items"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "investigations.investigation_id",
            name="fk_evidence_items_investigation_id_investigations",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    event_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ssh_events.event_id",
            name="fk_evidence_items_event_id_ssh_events",
            ondelete="RESTRICT",
        ),
        nullable=True,
    )
    evidence_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    evidence_data: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    source_reference: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="evidence_items",
    )
    event: Mapped[Optional["SSHEvent"]] = relationship(
        "SSHEvent",
    )

    __table_args__ = (
        CheckConstraint(
            "evidence_type IN ('ssh_event', 'detection_result', 'mitre_technique', 'security_playbook', 'historical_incident')",
            name="evidence_type_valid",
        ),
        UniqueConstraint("evidence_id", "investigation_id", name="uq_evidence_items_evidence_investigation"),
        Index("ix_evidence_items_investigation_id", "investigation_id"),
        Index("ix_evidence_items_event_id", "event_id"),
        Index("ix_evidence_items_evidence_type", "evidence_type"),
        Index("ix_evidence_items_collected_at", "collected_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceItem(evidence_id={self.evidence_id}, "
            f"investigation_id={self.investigation_id}, "
            f"type='{self.evidence_type}', "
            f"title='{self.title}')>"
        )


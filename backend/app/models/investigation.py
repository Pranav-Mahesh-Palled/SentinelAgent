"""Investigation database model for SentinelAgent.

Represents an AI-assisted cybersecurity investigation associated with an Incident,
storing structured analysis reports, root cause assessments, and investigation lifecycles.
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

VALID_INVESTIGATION_STATUSES = ("pending", "in_progress", "completed", "failed")


class Investigation(Base):
    """Declarative model representing AI-assisted incident investigations."""

    __tablename__ = "investigations"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "incidents.incident_id",
            name="fk_investigations_incident_id_incidents",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    investigation_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    investigation_report: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    root_cause_assessment: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
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

    # Relationships
    incident: Mapped["Incident"] = relationship(
        "Incident",
        back_populates="investigations",
    )
    evidence_items: Mapped[list["EvidenceItem"]] = relationship(
        "EvidenceItem",
        back_populates="investigation",
        passive_deletes=True,
    )
    tool_runs: Mapped[list["InvestigationToolRun"]] = relationship(
        "InvestigationToolRun",
        back_populates="investigation",
        passive_deletes=True,
    )
    memory_outbox_entries: Mapped[list["IncidentMemoryOutbox"]] = relationship(
        "IncidentMemoryOutbox",
        back_populates="investigation",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'in_progress', 'completed', 'failed')",
            name="status_valid",
        ),
        UniqueConstraint("incident_id", "investigation_id", name="uq_investigations_incident_investigation"),
        Index("ix_investigations_incident_id", "incident_id"),
        Index("ix_investigations_status", "status"),
        Index("ix_investigations_started_at", "started_at"),
        Index("ix_investigations_created_at", "created_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<Investigation(investigation_id={self.investigation_id}, "
            f"incident_id={self.incident_id}, "
            f"status='{self.status}', "
            f"started_at={self.started_at})>"
        )


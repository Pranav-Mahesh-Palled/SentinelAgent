"""Incident-Event association model for SentinelAgent.

Associates raw/ingested SSH authentication events with security incidents,
preserving historical audit evidence and referential integrity.
"""

from datetime import datetime
import uuid

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    PrimaryKeyConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class IncidentEvent(Base):
    """Many-to-many association between Incidents and SSHEvents."""

    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "incidents.incident_id",
            name="fk_incident_events_incident_id_incidents",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "ssh_events.event_id",
            name="fk_incident_events_event_id_ssh_events",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    incident: Mapped["Incident"] = relationship("Incident", viewonly=True)
    event: Mapped["SSHEvent"] = relationship("SSHEvent", viewonly=True)

    __table_args__ = (
        PrimaryKeyConstraint("incident_id", "event_id", name="pk_incident_events"),
        Index("ix_incident_events_event_id", "event_id"),
        Index("ix_incident_events_linked_at", "linked_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<IncidentEvent(incident_id={self.incident_id}, "
            f"event_id={self.event_id}, "
            f"linked_at={self.linked_at})>"
        )


"""SSH Event database model for SentinelAgent."""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SSHEvent(Base):
    """Declarative model representing raw and ingested SSH authentication events."""

    __tablename__ = "ssh_events"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    source_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
    )
    username: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    authentication_result: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    event_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident",
        secondary="incident_events",
        back_populates="events",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "authentication_result IN ('success', 'failure')",
            name="auth_result",
        ),
        CheckConstraint(
            "length(username) > 0",
            name="username_not_empty",
        ),
        Index("ix_ssh_events_event_timestamp", "event_timestamp"),
        Index("ix_ssh_events_source_ip", "source_ip"),
        Index("ix_ssh_events_source_ip_event_timestamp", "source_ip", "event_timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<SSHEvent(event_id={self.event_id}, "
            f"timestamp={self.event_timestamp}, "
            f"source_ip='{self.source_ip}', "
            f"username='{self.username}', "
            f"auth='{self.authentication_result}')>"
        )

"""Incident database model for SentinelAgent.

Represents cybersecurity incidents tracked through structured investigation,
response, and verification lifecycles.
"""

from datetime import datetime
from typing import Optional
import uuid

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

VALID_INCIDENT_STATUSES = ("open", "investigating", "resolved", "closed")
VALID_INVESTIGATION_STATUSES = ("pending", "in_progress", "completed", "failed")
VALID_RESPONSE_STATUSES = (
    "not_proposed",
    "pending_approval",
    "approved",
    "rejected",
    "executed",
    "simulated",
    "failed",
    "cancelled",
    "expired",
    "indeterminate",
)
VALID_VERIFICATION_STATUSES = ("not_started", "pending", "verified", "failed", "inconclusive")
VALID_DETECTION_METHODS = ("rule", "ml", "hybrid")
VALID_SEVERITIES = ("low", "medium", "high", "critical")


class Incident(Base):
    """Declarative model representing cybersecurity incidents."""

    __tablename__ = "incidents"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    incident_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    source_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
    )
    severity: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    detection_method: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="open",
        server_default=text("'open'"),
    )
    investigation_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    response_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="not_proposed",
        server_default=text("'not_proposed'"),
    )
    verification_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="not_started",
        server_default=text("'not_started'"),
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
    closed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    detection_results: Mapped[list["DetectionResult"]] = relationship(
        "DetectionResult",
        back_populates="incident",
        foreign_keys="DetectionResult.incident_id",
    )
    events: Mapped[list["SSHEvent"]] = relationship(
        "SSHEvent",
        secondary="incident_events",
        back_populates="incidents",
        passive_deletes=True,
    )
    investigations: Mapped[list["Investigation"]] = relationship(
        "Investigation",
        back_populates="incident",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('open', 'investigating', 'resolved', 'closed')",
            name="status_valid",
        ),
        CheckConstraint(
            "investigation_status IN ('pending', 'in_progress', 'completed', 'failed')",
            name="investigation_status_valid",
        ),
        CheckConstraint(
            "response_status IN ('not_proposed', 'pending_approval', 'approved', 'rejected', 'executed', 'simulated', 'failed', 'cancelled', 'expired', 'indeterminate')",
            name="response_status_valid",
        ),
        CheckConstraint(
            "verification_status IN ('not_started', 'pending', 'verified', 'failed', 'inconclusive')",
            name="verification_status_valid",
        ),
        CheckConstraint(
            "detection_method IN ('rule', 'ml', 'hybrid')",
            name="detection_method_valid",
        ),
        CheckConstraint(
            "severity IS NULL OR severity IN ('low', 'medium', 'high', 'critical')",
            name="severity_valid",
        ),
        Index("ix_incidents_source_ip", "source_ip"),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_created_at", "created_at"),
        Index("ix_incidents_detection_method", "detection_method"),
    )

    def __repr__(self) -> str:
        return (
            f"<Incident(incident_id={self.incident_id}, "
            f"title='{self.title}', "
            f"type='{self.incident_type}', "
            f"source_ip='{self.source_ip}', "
            f"status='{self.status}', "
            f"method='{self.detection_method}')>"
        )


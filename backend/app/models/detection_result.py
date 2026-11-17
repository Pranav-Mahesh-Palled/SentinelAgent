"""Detection Result database model for SentinelAgent.

Stores detection evaluations produced by the independent detection engines
(rule-based and Isolation Forest ML) for 1-minute time windows.
"""

from datetime import datetime
from typing import Any, Optional
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_DETECTOR_TYPES = ("rule", "isolation_forest")


class DetectionResult(Base):
    """Declarative model representing single-window anomaly detection outcomes."""

    __tablename__ = "detection_results"

    result_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "incidents.incident_id",
            name="fk_detection_results_incident_id_incidents",
            ondelete="SET NULL",
        ),
        nullable=True,
    )
    source_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
    )
    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    window_end: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    detector_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    is_suspicious: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )
    triggered_rules: Mapped[list[Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    feature_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    normality_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    calibrated_threshold: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    model_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships
    incident: Mapped[Optional["Incident"]] = relationship(
        "Incident",
        back_populates="detection_results",
    )

    __table_args__ = (
        CheckConstraint(
            "detector_type IN ('rule', 'isolation_forest')",
            name="detector_type_valid",
        ),
        CheckConstraint(
            "window_end > window_start",
            name="window_order",
        ),
        Index("ix_detection_results_source_ip", "source_ip"),
        Index("ix_detection_results_detector_type", "detector_type"),
        Index("ix_detection_results_window_start_window_end", "window_start", "window_end"),
        Index("ix_detection_results_evaluated_at", "evaluated_at"),
        Index("ix_detection_results_incident_id", "incident_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<DetectionResult(result_id={self.result_id}, "
            f"detector='{self.detector_type}', "
            f"source_ip='{self.source_ip}', "
            f"suspicious={self.is_suspicious}, "
            f"evaluated_at={self.evaluated_at})>"
        )


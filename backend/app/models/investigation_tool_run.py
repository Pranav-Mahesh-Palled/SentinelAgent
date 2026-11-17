"""Investigation Tool Run database model for SentinelAgent.

Maintains observable audit metadata about the investigation agent's tool executions,
recording structured input/output summaries, durations, and statuses without storing
raw prompts, private credentials, or internal chain-of-thought.
"""

from datetime import datetime
from typing import Any, Optional
import uuid

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_TOOL_RUN_STATUSES = ("pending", "running", "succeeded", "failed")


class InvestigationToolRun(Base):
    """Declarative model representing a tool execution performed during an investigation."""

    __tablename__ = "investigation_tool_runs"

    tool_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "investigations.investigation_id",
            name="fk_investigation_tool_runs_investigation_id_investigations",
            ondelete="RESTRICT",
        ),
        nullable=False,
    )
    tool_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )
    execution_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    input_summary: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    output_summary: Mapped[Optional[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=True,
    )
    error_code: Mapped[Optional[str]] = mapped_column(
        String(64),
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
    duration_ms: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )

    # Relationships
    investigation: Mapped["Investigation"] = relationship(
        "Investigation",
        back_populates="tool_runs",
    )

    __table_args__ = (
        CheckConstraint(
            "execution_status IN ('pending', 'running', 'succeeded', 'failed')",
            name="execution_status_valid",
        ),
        CheckConstraint(
            "duration_ms IS NULL OR duration_ms >= 0",
            name="duration_ms_non_negative",
        ),
        Index("ix_investigation_tool_runs_investigation_id", "investigation_id"),
        Index("ix_investigation_tool_runs_tool_name", "tool_name"),
        Index("ix_investigation_tool_runs_execution_status", "execution_status"),
        Index("ix_investigation_tool_runs_started_at", "started_at"),
    )

    def __repr__(self) -> str:
        return (
            f"<InvestigationToolRun(tool_run_id={self.tool_run_id}, "
            f"tool_name='{self.tool_name}', "
            f"status='{self.execution_status}', "
            f"duration_ms={self.duration_ms})>"
        )


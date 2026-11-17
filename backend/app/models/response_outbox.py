"""Response Outbox declarative model for SentinelAgent.

Implements transactional outbox queue for asynchronous dispatch of response action
execution and verification commands.
"""

from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

VALID_OUTBOX_COMMAND_TYPES = ("execute_simulation", "verify_simulation")
VALID_OUTBOX_STATUSES = ("pending", "claimed", "completed", "dead_letter", "cancelled")


class ResponseOutbox(Base):
    """Declarative model for persistent response command outbox queue."""

    __tablename__ = "response_outbox"

    outbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    response_action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    correlation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )
    command_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    deduplication_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default=text("3"),
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    lease_owner: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    lease_token: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_error_code: Mapped[Optional[str]] = mapped_column(
        String(64),
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
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    response_action: Mapped["ResponseAction"] = relationship(
        "ResponseAction",
        back_populates="outbox_entries",
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["response_action_id", "correlation_id"],
            ["response_actions.response_action_id", "response_actions.correlation_id"],
            name="fk_resp_outbox_action_correlation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("deduplication_key", name="uq_response_outbox_dedup"),
        CheckConstraint(
            "command_type IN ('execute_simulation', 'verify_simulation')",
            name="chk_outbox_command_type",
        ),
        CheckConstraint(
            "status IN ('pending', 'claimed', 'completed', 'dead_letter', 'cancelled')",
            name="chk_outbox_status",
        ),
        CheckConstraint("attempt_count >= 0", name="chk_outbox_attempt_count"),
        CheckConstraint("max_attempts > 0", name="chk_outbox_max_attempts"),
        CheckConstraint("lease_token >= 0", name="chk_outbox_lease_token"),
        CheckConstraint(
            "status != 'claimed' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name="chk_outbox_claimed_lease",
        ),
        CheckConstraint(
            "status != 'completed' OR completed_at IS NOT NULL",
            name="chk_outbox_completed_at",
        ),
        Index(
            "ix_response_outbox_claim",
            "status",
            "next_attempt_at",
            postgresql_where=text("status IN ('pending')"),
        ),
        Index(
            "ix_response_outbox_lease",
            "status",
            "lease_expires_at",
            postgresql_where=text("status = 'claimed'"),
        ),
        Index("ix_response_outbox_action_id", "response_action_id"),
    )

    def __repr__(self) -> str:
        return (
            f"<ResponseOutbox(outbox_id={self.outbox_id}, "
            f"action_id={self.response_action_id}, "
            f"command='{self.command_type}', "
            f"status='{self.status}', "
            f"token={self.lease_token})>"
        )

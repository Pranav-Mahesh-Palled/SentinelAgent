"""Simulated Blocklist Entry declarative model for SentinelAgent.

Represents an immutable, durable simulation-effect ledger record.
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
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class SimulatedBlocklistEntry(Base):
    """Declarative model for durable simulated IP blocklist records."""

    __tablename__ = "simulated_blocklist_entries"

    entry_id: Mapped[uuid.UUID] = mapped_column(
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
    idempotency_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    payload_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    target_ip: Mapped[str] = mapped_column(
        INET,
        nullable=False,
    )
    simulated_rule_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    simulated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    # Relationships
    response_action: Mapped["ResponseAction"] = relationship(
        "ResponseAction",
        back_populates="simulated_blocklist_entry",
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["response_action_id", "correlation_id"],
            ["response_actions.response_action_id", "response_actions.correlation_id"],
            name="fk_sim_blocklist_action_correlation",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("response_action_id", name="uq_sim_blocklist_action"),
        UniqueConstraint("idempotency_key", name="uq_sim_blocklist_idempotency"),
        CheckConstraint("payload_sha256 ~ '^[0-9a-f]{64}$'", name="chk_sim_payload_sha256"),
        CheckConstraint("jsonb_typeof(metadata) = 'object'", name="chk_sim_metadata_is_object"),
        CheckConstraint(
            "idempotency_key = ('resp_sim_' || response_action_id::text)",
            name="chk_sim_idempotency_key_exact",
        ),
        Index("ix_sim_blocklist_target_ip", "target_ip"),
    )

    def __repr__(self) -> str:
        return (
            f"<SimulatedBlocklistEntry(entry_id={self.entry_id}, "
            f"action_id={self.response_action_id}, "
            f"target_ip='{self.target_ip}', "
            f"rule_id='{self.simulated_rule_id}')>"
        )

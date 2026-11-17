"""create_incident_memory_outbox_table

Revision ID: c92d43956a00
Revises: 73ce52b4ca79
Create Date: 2026-11-09 15:19:19.667547

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c92d43956a00'
down_revision: Union[str, Sequence[str], None] = '73ce52b4ca79'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: create incident_memory_outbox table, constraints, and indexes."""
    op.create_table(
        'incident_memory_outbox',
        sa.Column('outbox_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('bank_id', sa.String(length=128), nullable=False),
        sa.Column('document_id', sa.String(length=255), nullable=False),
        sa.Column('memory_schema_version', sa.String(length=32), server_default=sa.text("'v1'"), nullable=False),
        sa.Column('payload_hash', sa.String(length=64), nullable=False),
        sa.Column('serialized_memory_payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('operation_id', sa.UUID(), nullable=False),
        sa.Column('hindsight_operation_id', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=32), server_default=sa.text("'pending'"), nullable=False),
        sa.Column('attempt_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('lease_owner', sa.String(length=128), nullable=True),
        sa.Column('lease_token', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error_code', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending', 'processing', 'retry_wait', 'completed', 'dead_letter', 'superseded')",
            name=op.f('ck_incident_memory_outbox_status_valid'),
        ),
        sa.CheckConstraint('attempt_count >= 0', name=op.f('ck_incident_memory_outbox_attempt_count_non_negative')),
        sa.CheckConstraint('lease_token >= 0', name=op.f('ck_incident_memory_outbox_lease_token_non_negative')),
        sa.CheckConstraint(
            "status != 'processing' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name=op.f('ck_incident_memory_outbox_processing_lease_invariant'),
        ),
        sa.CheckConstraint(
            "status != 'completed' OR completed_at IS NOT NULL",
            name=op.f('ck_incident_memory_outbox_completed_timestamp_invariant'),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(serialized_memory_payload) = 'object'",
            name=op.f('ck_incident_memory_outbox_payload_is_object'),
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[0-9a-f]{64}$'",
            name=op.f('ck_incident_memory_outbox_payload_hash_format'),
        ),
        sa.ForeignKeyConstraint(
            ['incident_id'],
            ['incidents.incident_id'],
            name='fk_memory_outbox_incident_id_incidents',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['investigation_id'],
            ['investigations.investigation_id'],
            name='fk_memory_outbox_investigation_id_investigations',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('outbox_id', name=op.f('pk_incident_memory_outbox')),
        sa.UniqueConstraint('operation_id', name=op.f('uq_incident_memory_outbox_operation_id')),
    )

    op.create_index(
        'ix_memory_outbox_claim',
        'incident_memory_outbox',
        ['status', 'next_attempt_at'],
        unique=False,
        postgresql_where=sa.text("status IN ('pending', 'retry_wait')"),
    )
    op.create_index(
        'ix_memory_outbox_lease',
        'incident_memory_outbox',
        ['status', 'lease_expires_at'],
        unique=False,
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.create_index(
        'ix_memory_outbox_doc_status',
        'incident_memory_outbox',
        ['bank_id', 'document_id', 'status', 'created_at', 'outbox_id'],
        unique=False,
    )
    op.create_index(
        'ix_memory_outbox_investigation_id',
        'incident_memory_outbox',
        ['investigation_id'],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema: drop incident_memory_outbox table and indexes."""
    op.drop_index('ix_memory_outbox_investigation_id', table_name='incident_memory_outbox')
    op.drop_index('ix_memory_outbox_doc_status', table_name='incident_memory_outbox')
    op.drop_index(
        'ix_memory_outbox_lease',
        table_name='incident_memory_outbox',
        postgresql_where=sa.text("status = 'processing'"),
    )
    op.drop_index(
        'ix_memory_outbox_claim',
        table_name='incident_memory_outbox',
        postgresql_where=sa.text("status IN ('pending', 'retry_wait')"),
    )
    op.drop_table('incident_memory_outbox')

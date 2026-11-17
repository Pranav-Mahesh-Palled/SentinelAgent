"""create_phase_11_response_orchestration_tables

Revision ID: 34ea070e907d
Revises: c92d43956a00
Create Date: 2026-11-15 14:01:49.088157

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '34ea070e907d'
down_revision: Union[str, Sequence[str], None] = 'c92d43956a00'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: create Phase 11 response orchestration models, constraints, and immutability triggers."""
    # 1. Update check constraints on incidents table for expanded statuses
    op.execute("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS ck_incidents_response_status_valid;")
    op.execute(
        "ALTER TABLE incidents ADD CONSTRAINT ck_incidents_response_status_valid "
        "CHECK (response_status IN ('not_proposed', 'pending_approval', 'approved', 'rejected', 'executed', 'simulated', 'failed', 'cancelled', 'expired', 'indeterminate'));"
    )

    op.execute("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS ck_incidents_verification_status_valid;")
    op.execute(
        "ALTER TABLE incidents ADD CONSTRAINT ck_incidents_verification_status_valid "
        "CHECK (verification_status IN ('not_started', 'pending', 'verified', 'failed', 'inconclusive'));"
    )

    # 2. Composite unique constraints on parent tables for cross-table referential integrity
    op.create_unique_constraint(
        'uq_investigations_incident_investigation',
        'investigations',
        ['incident_id', 'investigation_id'],
    )
    op.create_unique_constraint(
        'uq_evidence_items_evidence_investigation',
        'evidence_items',
        ['evidence_id', 'investigation_id'],
    )

    # 3. Create response_actions table
    op.create_table(
        'response_actions',
        sa.Column('response_action_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('incident_id', sa.UUID(), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('correlation_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('action_type', sa.String(length=64), server_default=sa.text("'simulation.block_source_ip'"), nullable=False),
        sa.Column('action_version', sa.Integer(), server_default=sa.text('1'), nullable=False),
        sa.Column('target_kind', sa.String(length=32), server_default=sa.text("'source_ip'"), nullable=False),
        sa.Column('target_value', postgresql.INET(), nullable=False),
        sa.Column('payload_json', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('payload_sha256', sa.String(length=64), nullable=False),
        sa.Column('approved_payload_sha256', sa.String(length=64), nullable=True),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('evidence_refs', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('policy_version', sa.String(length=32), server_default=sa.text("'v1'"), nullable=False),
        sa.Column('proposed_by_operator_id', sa.String(length=128), nullable=False),
        sa.Column('approval_status', sa.String(length=32), server_default=sa.text("'pending_approval'"), nullable=False),
        sa.Column('execution_status', sa.String(length=32), server_default=sa.text("'not_queued'"), nullable=False),
        sa.Column('verification_status', sa.String(length=32), server_default=sa.text("'not_started'"), nullable=False),
        sa.Column('approval_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('execution_deadline_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('version', sa.BigInteger(), server_default=sa.text('1'), nullable=False),
        sa.Column('last_audit_sequence', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('idempotency_key_hash', sa.String(length=64), nullable=False),
        sa.Column('proposal_response_status_code', sa.Integer(), server_default=sa.text('201'), nullable=False),
        sa.Column('proposal_response_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['incident_id', 'investigation_id'],
            ['investigations.incident_id', 'investigations.investigation_id'],
            name='fk_resp_actions_incident_investigation',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.incident_id'], name='fk_resp_actions_incident_id_incidents', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['investigation_id'], ['investigations.investigation_id'], name='fk_resp_actions_investigation_id_investigations', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('response_action_id', name='pk_response_actions'),
        sa.UniqueConstraint('incident_id', 'idempotency_key_hash', name='uq_response_actions_incident_idempotency'),
        sa.UniqueConstraint('response_action_id', 'investigation_id', name='uq_response_actions_action_investigation'),
        sa.UniqueConstraint('response_action_id', 'correlation_id', name='uq_response_actions_action_correlation'),
        sa.CheckConstraint("action_type = 'simulation.block_source_ip'", name='chk_resp_action_type'),
        sa.CheckConstraint('action_version > 0', name='chk_resp_action_version'),
        sa.CheckConstraint("target_kind = 'source_ip'", name='chk_resp_target_kind'),
        sa.CheckConstraint("jsonb_typeof(payload_json) = 'object'", name='chk_resp_payload_json_is_object'),
        sa.CheckConstraint("payload_sha256 ~ '^[0-9a-f]{64}$'", name='chk_resp_payload_sha256_format'),
        sa.CheckConstraint(
            "approved_payload_sha256 IS NULL OR approved_payload_sha256 ~ '^[0-9a-f]{64}$'",
            name='chk_resp_approved_sha256_format',
        ),
        sa.CheckConstraint('version > 0', name='chk_resp_version_positive'),
        sa.CheckConstraint('last_audit_sequence >= 0', name='chk_resp_audit_seq_non_negative'),
        sa.CheckConstraint(
            "approval_status IN ('pending_approval', 'approved', 'rejected', 'cancelled', 'expired')",
            name='chk_resp_approval_status',
        ),
        sa.CheckConstraint(
            "execution_status IN ('not_queued', 'queued', 'running', 'succeeded', 'failed', 'indeterminate', 'cancelled', 'expired')",
            name='chk_resp_execution_status',
        ),
        sa.CheckConstraint(
            "verification_status IN ('not_started', 'pending', 'verified', 'failed', 'inconclusive')",
            name='chk_resp_verification_status',
        ),
        sa.CheckConstraint(
            "((approval_status = 'approved' AND execution_status != 'not_queued') OR (approval_status != 'approved' AND execution_status = 'not_queued'))",
            name='chk_resp_approval_execution_bidirectional',
        ),
        sa.CheckConstraint(
            "((execution_status = 'succeeded' AND verification_status != 'not_started') OR (execution_status != 'succeeded' AND verification_status = 'not_started'))",
            name='chk_resp_execution_verification_bidirectional',
        ),
        sa.CheckConstraint(
            "((approval_status = 'approved' AND approved_payload_sha256 IS NOT NULL AND approved_payload_sha256 = payload_sha256 AND execution_deadline_at IS NOT NULL) OR (approval_status != 'approved' AND approved_payload_sha256 IS NULL AND execution_deadline_at IS NULL))",
            name='chk_resp_approval_digest_deadline_bidirectional',
        ),
    )

    op.create_index('ix_response_actions_incident_id', 'response_actions', ['incident_id'], unique=False)
    op.create_index('ix_response_actions_investigation_id', 'response_actions', ['investigation_id'], unique=False)
    op.create_index('ix_response_actions_created_at', 'response_actions', ['created_at'], unique=False)

    # Unique partial index: exactly one active response action per incident
    op.create_index(
        'uq_response_actions_single_active_per_incident',
        'response_actions',
        ['incident_id'],
        unique=True,
        postgresql_where=sa.text(
            "approval_status = 'pending_approval' "
            "OR execution_status IN ('queued', 'running', 'indeterminate') "
            "OR verification_status IN ('pending', 'inconclusive')"
        ),
    )

    # 4. Create response_action_evidence associative table
    op.create_table(
        'response_action_evidence',
        sa.Column('response_action_evidence_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('response_action_id', sa.UUID(), nullable=False),
        sa.Column('evidence_id', sa.UUID(), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('evidence_type', sa.String(length=32), nullable=False),
        sa.Column('evidence_sha256', sa.String(length=64), nullable=False),
        sa.Column('evidence_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['response_action_id', 'investigation_id'],
            ['response_actions.response_action_id', 'response_actions.investigation_id'],
            name='fk_resp_evid_action_investigation',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['evidence_id', 'investigation_id'],
            ['evidence_items.evidence_id', 'evidence_items.investigation_id'],
            name='fk_resp_evid_item_investigation',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('response_action_evidence_id', name='pk_response_action_evidence'),
        sa.UniqueConstraint('response_action_id', 'evidence_id', name='uq_response_action_evidence'),
        sa.CheckConstraint("evidence_sha256 ~ '^[0-9a-f]{64}$'", name='chk_resp_evid_sha256'),
        sa.CheckConstraint("jsonb_typeof(evidence_snapshot) = 'object'", name='chk_resp_evid_snapshot_object'),
    )
    op.create_index('ix_resp_action_evid_composite', 'response_action_evidence', ['response_action_id', 'investigation_id'], unique=False)
    op.create_index('ix_resp_action_evid_item', 'response_action_evidence', ['evidence_id', 'investigation_id'], unique=False)

    # 5. Create response_outbox table
    op.create_table(
        'response_outbox',
        sa.Column('outbox_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('response_action_id', sa.UUID(), nullable=False),
        sa.Column('correlation_id', sa.UUID(), nullable=False),
        sa.Column('command_type', sa.String(length=64), nullable=False),
        sa.Column('deduplication_key', sa.String(length=128), nullable=False),
        sa.Column('status', sa.String(length=32), server_default=sa.text("'pending'"), nullable=False),
        sa.Column('attempt_count', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('max_attempts', sa.Integer(), server_default=sa.text('3'), nullable=False),
        sa.Column('next_attempt_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('lease_owner', sa.String(length=128), nullable=True),
        sa.Column('lease_token', sa.BigInteger(), server_default=sa.text('0'), nullable=False),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error_code', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ['response_action_id', 'correlation_id'],
            ['response_actions.response_action_id', 'response_actions.correlation_id'],
            name='fk_resp_outbox_action_correlation',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('outbox_id', name='pk_response_outbox'),
        sa.UniqueConstraint('deduplication_key', name='uq_response_outbox_dedup'),
        sa.CheckConstraint(
            "command_type IN ('execute_simulation', 'verify_simulation')",
            name='chk_outbox_command_type',
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'claimed', 'completed', 'dead_letter', 'cancelled')",
            name='chk_outbox_status',
        ),
        sa.CheckConstraint('attempt_count >= 0', name='chk_outbox_attempt_count'),
        sa.CheckConstraint('max_attempts > 0', name='chk_outbox_max_attempts'),
        sa.CheckConstraint('lease_token >= 0', name='chk_outbox_lease_token'),
        sa.CheckConstraint(
            "status != 'claimed' OR (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)",
            name='chk_outbox_claimed_lease',
        ),
        sa.CheckConstraint(
            "status != 'completed' OR completed_at IS NOT NULL",
            name='chk_outbox_completed_at',
        ),
    )
    op.create_index(
        'ix_response_outbox_claim',
        'response_outbox',
        ['status', 'next_attempt_at'],
        unique=False,
        postgresql_where=sa.text("status = 'pending'"),
    )
    op.create_index(
        'ix_response_outbox_lease',
        'response_outbox',
        ['status', 'lease_expires_at'],
        unique=False,
        postgresql_where=sa.text("status = 'claimed'"),
    )
    op.create_index('ix_response_outbox_action', 'response_outbox', ['response_action_id'], unique=False)

    # 6. Create simulated_blocklist_entries table (ledger)
    op.create_table(
        'simulated_blocklist_entries',
        sa.Column('entry_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('response_action_id', sa.UUID(), nullable=False),
        sa.Column('correlation_id', sa.UUID(), nullable=False),
        sa.Column('idempotency_key', sa.String(length=128), nullable=False),
        sa.Column('payload_sha256', sa.String(length=64), nullable=False),
        sa.Column('target_ip', postgresql.INET(), nullable=False),
        sa.Column('simulated_rule_id', sa.String(length=64), nullable=False),
        sa.Column('simulated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('metadata', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.ForeignKeyConstraint(
            ['response_action_id', 'correlation_id'],
            ['response_actions.response_action_id', 'response_actions.correlation_id'],
            name='fk_sim_blocklist_action_correlation',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('entry_id', name='pk_simulated_blocklist_entries'),
        sa.UniqueConstraint('response_action_id', name='uq_sim_blocklist_action'),
        sa.UniqueConstraint('idempotency_key', name='uq_sim_blocklist_idempotency'),
        sa.CheckConstraint("payload_sha256 ~ '^[0-9a-f]{64}$'", name='chk_sim_payload_sha256'),
        sa.CheckConstraint("jsonb_typeof(metadata) = 'object'", name='chk_sim_metadata_is_object'),
        sa.CheckConstraint(
            "idempotency_key = ('resp_sim_' || response_action_id::text)",
            name='chk_sim_idempotency_key_exact',
        ),
    )
    op.create_index('ix_sim_blocklist_target_ip', 'simulated_blocklist_entries', ['target_ip'], unique=False)

    # 7. Create verification_reconciliation_records table
    op.create_table(
        'verification_reconciliation_records',
        sa.Column('reconciliation_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('response_action_id', sa.UUID(), nullable=False),
        sa.Column('correlation_id', sa.UUID(), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('actor_operator_id', sa.String(length=128), nullable=False),
        sa.Column('resolution', sa.String(length=32), nullable=False),
        sa.Column('synthetic_scenario_id', sa.String(length=128), nullable=False),
        sa.Column('observation_window_start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('observation_window_end', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expected_probes', sa.Integer(), nullable=False),
        sa.Column('generated_probes', sa.Integer(), nullable=False),
        sa.Column('captured_probes', sa.Integer(), nullable=False),
        sa.Column('intercepted_probes', sa.Integer(), nullable=False),
        sa.Column('telemetry_coverage_verified', sa.Boolean(), nullable=False),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['response_action_id', 'correlation_id'],
            ['response_actions.response_action_id', 'response_actions.correlation_id'],
            name='fk_verif_rec_action_correlation',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['response_action_id', 'investigation_id'],
            ['response_actions.response_action_id', 'response_actions.investigation_id'],
            name='fk_verif_rec_action_investigation',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('reconciliation_id', name='pk_verification_reconciliation_records'),
        sa.UniqueConstraint('reconciliation_id', 'investigation_id', name='uq_verif_rec_record_investigation'),
        sa.UniqueConstraint(
            'reconciliation_id',
            'response_action_id',
            'correlation_id',
            name='uq_verif_rec_action_correlation',
        ),
        sa.CheckConstraint(
            "resolution IN ('confirm_verified', 'confirm_failed')",
            name='chk_verif_rec_resolution',
        ),
        sa.CheckConstraint(
            'observation_window_end > observation_window_start',
            name='chk_verif_rec_window',
        ),
        sa.CheckConstraint(
            'expected_probes > 0 AND generated_probes = expected_probes AND captured_probes >= generated_probes AND intercepted_probes >= 0',
            name='chk_verif_rec_probes_valid',
        ),
        sa.CheckConstraint(
            "resolution != 'confirm_verified' OR (intercepted_probes = generated_probes)",
            name='chk_verif_rec_verified_math',
        ),
        sa.CheckConstraint(
            "resolution != 'confirm_failed' OR (intercepted_probes = 0 AND telemetry_coverage_verified = TRUE)",
            name='chk_verif_rec_failed_math',
        ),
    )
    op.create_index('ix_verif_rec_action', 'verification_reconciliation_records', ['response_action_id'], unique=False)
    op.create_index('ix_verif_rec_created_at', 'verification_reconciliation_records', ['created_at'], unique=False)

    # 8. Create verification_reconciliation_evidence associative table
    op.create_table(
        'verification_reconciliation_evidence',
        sa.Column('reconciliation_evidence_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('reconciliation_id', sa.UUID(), nullable=False),
        sa.Column('evidence_id', sa.UUID(), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('evidence_sha256', sa.String(length=64), nullable=False),
        sa.Column('evidence_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['reconciliation_id', 'investigation_id'],
            ['verification_reconciliation_records.reconciliation_id', 'verification_reconciliation_records.investigation_id'],
            name='fk_verif_rec_evid_record_investigation',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['evidence_id', 'investigation_id'],
            ['evidence_items.evidence_id', 'evidence_items.investigation_id'],
            name='fk_verif_rec_evid_item_investigation',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('reconciliation_evidence_id', name='pk_verification_reconciliation_evidence'),
        sa.UniqueConstraint('reconciliation_id', 'evidence_id', name='uq_verif_rec_evidence'),
        sa.CheckConstraint("evidence_sha256 ~ '^[0-9a-f]{64}$'", name='chk_verif_rec_evid_sha256'),
        sa.CheckConstraint("jsonb_typeof(evidence_snapshot) = 'object'", name='chk_verif_rec_evid_snapshot_object'),
    )
    op.create_index('ix_verif_rec_evid_rec', 'verification_reconciliation_evidence', ['reconciliation_id'], unique=False)
    op.create_index('ix_verif_rec_evid_item', 'verification_reconciliation_evidence', ['evidence_id', 'investigation_id'], unique=False)

    # 9. Create verification_reconciliation_probes table (normalized per-probe synthetic test evidence)
    op.create_table(
        'verification_reconciliation_probes',
        sa.Column('probe_record_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('reconciliation_id', sa.UUID(), nullable=False),
        sa.Column('investigation_id', sa.UUID(), nullable=False),
        sa.Column('probe_id', sa.String(length=64), nullable=False),
        sa.Column('generation_evidence_id', sa.UUID(), nullable=False),
        sa.Column('capture_evidence_id', sa.UUID(), nullable=False),
        sa.Column('intercepted', sa.Boolean(), nullable=False),
        sa.Column('interception_evidence_id', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['reconciliation_id', 'investigation_id'],
            ['verification_reconciliation_records.reconciliation_id', 'verification_reconciliation_records.investigation_id'],
            name='fk_verif_probe_record_investigation',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['generation_evidence_id', 'investigation_id'],
            ['evidence_items.evidence_id', 'evidence_items.investigation_id'],
            name='fk_verif_probe_gen_evidence',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['capture_evidence_id', 'investigation_id'],
            ['evidence_items.evidence_id', 'evidence_items.investigation_id'],
            name='fk_verif_probe_cap_evidence',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['interception_evidence_id', 'investigation_id'],
            ['evidence_items.evidence_id', 'evidence_items.investigation_id'],
            name='fk_verif_probe_int_evidence',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('probe_record_id', name='pk_verification_reconciliation_probes'),
        sa.UniqueConstraint('reconciliation_id', 'probe_id', name='uq_verif_probe_run_probe'),
        sa.CheckConstraint(
            "(intercepted = FALSE AND interception_evidence_id IS NULL) OR (intercepted = TRUE AND interception_evidence_id IS NOT NULL)",
            name='chk_verif_probe_interception_evidence',
        ),
    )
    op.create_index('ix_verif_probes_reconciliation', 'verification_reconciliation_probes', ['reconciliation_id'], unique=False)
    op.create_index('ix_verif_probes_probe_id', 'verification_reconciliation_probes', ['probe_id'], unique=False)

    # 10. Create response_audit_events table
    op.create_table(
        'response_audit_events',
        sa.Column('response_audit_event_id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('response_action_id', sa.UUID(), nullable=False),
        sa.Column('correlation_id', sa.UUID(), nullable=False),
        sa.Column('reconciliation_id', sa.UUID(), nullable=True),
        sa.Column('sequence_number', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=64), nullable=False),
        sa.Column('from_approval_status', sa.String(length=32), nullable=True),
        sa.Column('to_approval_status', sa.String(length=32), nullable=True),
        sa.Column('from_execution_status', sa.String(length=32), nullable=True),
        sa.Column('to_execution_status', sa.String(length=32), nullable=True),
        sa.Column('from_verification_status', sa.String(length=32), nullable=True),
        sa.Column('to_verification_status', sa.String(length=32), nullable=True),
        sa.Column('actor_type', sa.String(length=32), nullable=False),
        sa.Column('actor_operator_id', sa.String(length=128), nullable=False),
        sa.Column('actor_role_snapshot', sa.String(length=32), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('event_data', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column('payload_sha256_snapshot', sa.String(length=64), nullable=False),
        sa.Column('client_ip', postgresql.INET(), nullable=True),
        sa.Column('idempotency_key_hash', sa.String(length=64), nullable=True),
        sa.Column('request_fingerprint', sa.String(length=64), nullable=True),
        sa.Column('response_status_code', sa.Integer(), nullable=True),
        sa.Column('response_snapshot', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(
            ['response_action_id', 'correlation_id'],
            ['response_actions.response_action_id', 'response_actions.correlation_id'],
            name='fk_resp_audit_action_correlation',
            ondelete='RESTRICT',
        ),
        sa.ForeignKeyConstraint(
            ['reconciliation_id', 'response_action_id', 'correlation_id'],
            [
                'verification_reconciliation_records.reconciliation_id',
                'verification_reconciliation_records.response_action_id',
                'verification_reconciliation_records.correlation_id',
            ],
            name='fk_resp_audit_reconciliation',
            ondelete='RESTRICT',
        ),
        sa.PrimaryKeyConstraint('response_audit_event_id', name='pk_response_audit_events'),
        sa.UniqueConstraint('response_action_id', 'sequence_number', name='uq_response_audit_sequence'),
        sa.CheckConstraint('sequence_number > 0', name='chk_audit_seq_positive'),
        sa.CheckConstraint(
            "actor_type IN ('operator', 'system_worker', 'recovery_sweeper')",
            name='chk_audit_actor_type',
        ),
        sa.CheckConstraint(
            "actor_role_snapshot IN ('analyst', 'approver', 'admin', 'system')",
            name='chk_audit_actor_role',
        ),
        sa.CheckConstraint("payload_sha256_snapshot ~ '^[0-9a-f]{64}$'", name='chk_audit_payload_sha256_format'),
        sa.CheckConstraint("jsonb_typeof(event_data) = 'object'", name='chk_audit_event_data_is_object'),
        sa.CheckConstraint(
            "idempotency_key_hash IS NULL OR (response_status_code IS NOT NULL AND response_snapshot IS NOT NULL AND jsonb_typeof(response_snapshot) = 'object')",
            name='chk_audit_idempotency_snapshot',
        ),
        sa.CheckConstraint(
            "event_type IN ("
            "'proposal.created', 'approval.granted', 'approval.rejected', 'proposal.cancelled', 'proposal.expired', "
            "'execution.cancelled', 'execution.expired', 'execution.claimed', 'execution.requeued', 'execution.succeeded', "
            "'execution.failed', 'execution.indeterminate', 'execution.reconciled_success', 'verification.claimed', "
            "'verification.replayed', 'verification.succeeded', 'verification.failed', 'verification.inconclusive', "
            "'verification.reconciled_verified', 'verification.reconciled_failed')",
            name='chk_audit_event_type',
        ),
    )
    op.create_index(
        'uq_response_audit_operator_idempotency',
        'response_audit_events',
        ['actor_operator_id', 'idempotency_key_hash'],
        unique=True,
        postgresql_where=sa.text("idempotency_key_hash IS NOT NULL"),
    )
    op.create_index(
        'uq_response_audit_reconciliation',
        'response_audit_events',
        ['reconciliation_id'],
        unique=True,
        postgresql_where=sa.text("reconciliation_id IS NOT NULL"),
    )
    op.create_index('ix_response_audit_action_seq', 'response_audit_events', ['response_action_id', 'sequence_number'], unique=False)
    op.create_index('ix_response_audit_created_at', 'response_audit_events', ['created_at'], unique=False)

    # 11. Create PostgreSQL immutability protection functions and triggers
    op.execute("""
    CREATE OR REPLACE FUNCTION fn_prevent_immutable_modification()
    RETURNS TRIGGER AS $$
    BEGIN
        IF current_setting('sentinel.allow_immutable_cleanup', true) = 'on' THEN
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            ELSE
                RETURN NEW;
            END IF;
        END IF;
        RAISE EXCEPTION 'Modifications and deletions are strictly forbidden on immutable audit and simulation ledger tables.';
    END;
    $$ LANGUAGE plpgsql;
    """)

    op.execute("""
    CREATE TRIGGER trg_protect_response_audit_immutability
    BEFORE UPDATE OR DELETE ON response_audit_events
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_response_audit_truncate
    BEFORE TRUNCATE ON response_audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_sim_blocklist_immutability
    BEFORE UPDATE OR DELETE ON simulated_blocklist_entries
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_sim_blocklist_truncate
    BEFORE TRUNCATE ON simulated_blocklist_entries
    FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_verif_rec_immutability
    BEFORE UPDATE OR DELETE ON verification_reconciliation_records
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_verif_rec_truncate
    BEFORE TRUNCATE ON verification_reconciliation_records
    FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_verif_rec_evid_immutability
    BEFORE UPDATE OR DELETE ON verification_reconciliation_evidence
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_verif_rec_evid_truncate
    BEFORE TRUNCATE ON verification_reconciliation_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_verif_probe_immutability
    BEFORE UPDATE OR DELETE ON verification_reconciliation_probes
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_verif_probe_truncate
    BEFORE TRUNCATE ON verification_reconciliation_probes
    FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_resp_action_evid_immutability
    BEFORE UPDATE OR DELETE ON response_action_evidence
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_immutable_modification();

    CREATE TRIGGER trg_protect_resp_action_evid_truncate
    BEFORE TRUNCATE ON response_action_evidence
    FOR EACH STATEMENT EXECUTE FUNCTION fn_prevent_immutable_modification();
    """)

    # Trigger preventing alteration of response action core parameters and identity relationships
    op.execute("""
    CREATE OR REPLACE FUNCTION fn_prevent_response_action_rel_update()
    RETURNS TRIGGER AS $$
    BEGIN
        IF current_setting('sentinel.allow_immutable_cleanup', true) = 'on' THEN
            RETURN NEW;
        END IF;
        IF OLD.incident_id IS DISTINCT FROM NEW.incident_id
           OR OLD.investigation_id IS DISTINCT FROM NEW.investigation_id
           OR OLD.correlation_id IS DISTINCT FROM NEW.correlation_id
           OR OLD.action_type IS DISTINCT FROM NEW.action_type
           OR OLD.target_kind IS DISTINCT FROM NEW.target_kind
           OR OLD.target_value IS DISTINCT FROM NEW.target_value
           OR OLD.payload_json IS DISTINCT FROM NEW.payload_json
           OR OLD.payload_sha256 IS DISTINCT FROM NEW.payload_sha256
           OR OLD.idempotency_key_hash IS DISTINCT FROM NEW.idempotency_key_hash
           OR OLD.proposal_response_status_code IS DISTINCT FROM NEW.proposal_response_status_code
           OR OLD.proposal_response_snapshot IS DISTINCT FROM NEW.proposal_response_snapshot THEN
            RAISE EXCEPTION 'Immutable identity and payload attributes of response_actions cannot be altered.';
        END IF;
        RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;

    CREATE TRIGGER trg_protect_response_action_relationships
    BEFORE UPDATE ON response_actions
    FOR EACH ROW EXECUTE FUNCTION fn_prevent_response_action_rel_update();
    """)

    # 12. Privilege grants for sentinel_app_role (conditional on role presence)
    op.execute("""
    DO $$
    BEGIN
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app_role') THEN
            GRANT SELECT, INSERT, UPDATE ON response_actions TO sentinel_app_role;
            GRANT SELECT, INSERT, UPDATE, DELETE ON response_outbox TO sentinel_app_role;
            GRANT SELECT, INSERT ON response_audit_events TO sentinel_app_role;
            GRANT SELECT, INSERT ON simulated_blocklist_entries TO sentinel_app_role;
            GRANT SELECT, INSERT ON verification_reconciliation_records TO sentinel_app_role;
            GRANT SELECT, INSERT ON verification_reconciliation_evidence TO sentinel_app_role;
            GRANT SELECT, INSERT ON verification_reconciliation_probes TO sentinel_app_role;
            GRANT SELECT, INSERT ON response_action_evidence TO sentinel_app_role;
        END IF;
    END $$;
    """)


def downgrade() -> None:
    """Downgrade schema: verify safety guards, drop Phase 11 triggers, tables, constraints, and revert incident checks."""
    conn = op.get_bind()

    # Safety Guard: Ensure no response data exists and no incidents have Phase 11 statuses
    res = conn.execute(sa.text("""
        SELECT 
            (SELECT COUNT(*) FROM response_actions) +
            (SELECT COUNT(*) FROM response_action_evidence) +
            (SELECT COUNT(*) FROM response_outbox) +
            (SELECT COUNT(*) FROM simulated_blocklist_entries) +
            (SELECT COUNT(*) FROM verification_reconciliation_records) +
            (SELECT COUNT(*) FROM verification_reconciliation_evidence) +
            (SELECT COUNT(*) FROM verification_reconciliation_probes) +
            (SELECT COUNT(*) FROM response_audit_events) AS row_count,
            (SELECT COUNT(*) FROM incidents WHERE response_status IN ('simulated', 'failed', 'cancelled', 'expired', 'indeterminate') OR verification_status = 'inconclusive') AS incident_count
    """)).fetchone()

    if res and (res[0] > 0 or res[1] > 0):
        raise RuntimeError(
            f"Downgrade blocked by safety guard: Phase 11 tables contain {res[0]} rows or {res[1]} incidents possess Phase 11 statuses. "
            "Manual review and purge is required before dropping Phase 11 tables."
        )

    # 1. Drop triggers and functions
    op.execute("""
    DROP TRIGGER IF EXISTS trg_protect_response_action_relationships ON response_actions;
    DROP FUNCTION IF EXISTS fn_prevent_response_action_rel_update();

    DROP TRIGGER IF EXISTS trg_protect_response_audit_immutability ON response_audit_events;
    DROP TRIGGER IF EXISTS trg_protect_response_audit_truncate ON response_audit_events;
    DROP TRIGGER IF EXISTS trg_protect_sim_blocklist_immutability ON simulated_blocklist_entries;
    DROP TRIGGER IF EXISTS trg_protect_sim_blocklist_truncate ON simulated_blocklist_entries;
    DROP TRIGGER IF EXISTS trg_protect_verif_rec_immutability ON verification_reconciliation_records;
    DROP TRIGGER IF EXISTS trg_protect_verif_rec_truncate ON verification_reconciliation_records;
    DROP TRIGGER IF EXISTS trg_protect_verif_rec_evid_immutability ON verification_reconciliation_evidence;
    DROP TRIGGER IF EXISTS trg_protect_verif_rec_evid_truncate ON verification_reconciliation_evidence;
    DROP TRIGGER IF EXISTS trg_protect_verif_probe_immutability ON verification_reconciliation_probes;
    DROP TRIGGER IF EXISTS trg_protect_verif_probe_truncate ON verification_reconciliation_probes;
    DROP TRIGGER IF EXISTS trg_protect_resp_action_evid_immutability ON response_action_evidence;
    DROP TRIGGER IF EXISTS trg_protect_resp_action_evid_truncate ON response_action_evidence;

    DROP FUNCTION IF EXISTS fn_prevent_immutable_modification();
    """)

    # 2. Drop tables in reverse dependency order without CASCADE
    op.drop_table('response_audit_events')
    op.drop_table('verification_reconciliation_probes')
    op.drop_table('verification_reconciliation_evidence')
    op.drop_table('verification_reconciliation_records')
    op.drop_table('simulated_blocklist_entries')
    op.drop_table('response_outbox')
    op.drop_table('response_action_evidence')
    op.drop_table('response_actions')

    # 3. Drop prerequisite unique constraints
    op.drop_constraint('uq_evidence_items_evidence_investigation', 'evidence_items', type_='unique')
    op.drop_constraint('uq_investigations_incident_investigation', 'investigations', type_='unique')

    # 4. Revert incident status check constraints
    op.execute("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS ck_incidents_verification_status_valid;")
    op.execute(
        "ALTER TABLE incidents ADD CONSTRAINT ck_incidents_verification_status_valid "
        "CHECK (verification_status IN ('not_started', 'pending', 'verified', 'failed'));"
    )

    op.execute("ALTER TABLE incidents DROP CONSTRAINT IF EXISTS ck_incidents_response_status_valid;")
    op.execute(
        "ALTER TABLE incidents ADD CONSTRAINT ck_incidents_response_status_valid "
        "CHECK (response_status IN ('not_proposed', 'pending_approval', 'approved', 'rejected', 'executed'));"
    )

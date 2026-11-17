"""Unit and integration tests for database role least-privilege alignment (Task 12.1.2.1)."""

from unittest.mock import MagicMock, patch
import pytest
from sqlalchemy import text

from app.db.align_roles import (
    ALL_CLASSIFIED_TABLES,
    IMMUTABLE_FORENSIC_TABLES,
    OPERATIONAL_TABLES,
    QUEUE_TABLES,
    QUEUE_AND_JOIN_TABLES,
    SYSTEM_INTERNAL_TABLES,
    UnclassifiedTableError,
    align_role_privileges,
)


def test_table_classification_disjoint():
    """Ensure immutable, queue, operational, and system tables are strictly pairwise disjoint sets."""
    immutable_set = set(IMMUTABLE_FORENSIC_TABLES)
    queue_set = set(QUEUE_TABLES)
    operational_set = set(OPERATIONAL_TABLES)
    system_set = set(SYSTEM_INTERNAL_TABLES)

    assert len(immutable_set.intersection(queue_set)) == 0
    assert len(immutable_set.intersection(operational_set)) == 0
    assert len(immutable_set.intersection(system_set)) == 0
    assert len(queue_set.intersection(operational_set)) == 0
    assert len(queue_set.intersection(system_set)) == 0
    assert len(operational_set.intersection(system_set)) == 0


def test_all_database_tables_classified():
    """Verify that all 17 tables in SentinelAgent are accounted for in ALL_CLASSIFIED_TABLES."""
    expected_all = {
        "alembic_version",
        "detection_results",
        "evidence_items",
        "incident_events",
        "incident_memory_outbox",
        "incidents",
        "investigation_tool_runs",
        "investigations",
        "response_action_evidence",
        "response_actions",
        "response_audit_events",
        "response_outbox",
        "simulated_blocklist_entries",
        "ssh_events",
        "verification_reconciliation_evidence",
        "verification_reconciliation_probes",
        "verification_reconciliation_records",
    }
    assert ALL_CLASSIFIED_TABLES == expected_all
    assert len(ALL_CLASSIFIED_TABLES) == 17


def test_immutable_tables_coverage():
    """Verify all forensic append-only and association tables are categorized as immutable."""
    expected_immutables = {
        "response_audit_events",
        "simulated_blocklist_entries",
        "verification_reconciliation_records",
        "verification_reconciliation_evidence",
        "verification_reconciliation_probes",
        "response_action_evidence",
        "incident_events",
        "evidence_items",
    }
    assert set(IMMUTABLE_FORENSIC_TABLES) == expected_immutables


def test_queue_tables_coverage():
    """Verify transactional outboxes are categorized as queue tables."""
    expected_queues = {
        "response_outbox",
        "incident_memory_outbox",
    }
    assert set(QUEUE_TABLES) == expected_queues
    assert set(QUEUE_AND_JOIN_TABLES) == expected_queues


def test_operational_tables_coverage():
    """Verify core domain entities are categorized as operational tables."""
    expected_operational = {
        "incidents",
        "investigations",
        "response_actions",
        "ssh_events",
        "detection_results",
        "investigation_tool_runs",
    }
    assert set(OPERATIONAL_TABLES) == expected_operational


def test_system_internal_tables_coverage():
    """Verify migration tracking table is categorized as system internal."""
    assert set(SYSTEM_INTERNAL_TABLES) == {"alembic_version"}


def test_align_role_privileges_missing_role(monkeypatch):
    """When the target role does not exist, align_role_privileges returns False without error."""
    mock_conn = MagicMock()
    mock_conn.execute.return_value.scalar.return_value = None  # role_exists = None
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    with patch("app.db.align_roles.get_engine", return_value=mock_engine):
        result = align_role_privileges("nonexistent_role")
        assert result is False


def test_align_role_privileges_fail_closed_on_unclassified_table():
    """When an unclassified table exists in schema public, align_role_privileges raises UnclassifiedTableError."""
    mock_conn = MagicMock()

    class MockScalar:
        def scalar(self):
            return 1

    def mock_execute(stmt, params=None):
        sql = str(stmt)
        if "SELECT 1 FROM pg_roles" in sql:
            return MockScalar()
        if "SELECT table_name FROM information_schema.tables" in sql:
            mock_res = MagicMock()
            # Return known tables PLUS an unknown unclassified table
            tables = [(tbl,) for tbl in ALL_CLASSIFIED_TABLES] + [("unclassified_secret_table",)]
            mock_res.fetchall.return_value = tables
            return mock_res
        return MockScalar()

    mock_conn.execute.side_effect = mock_execute
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    with patch("app.db.align_roles.get_engine", return_value=mock_engine):
        with pytest.raises(UnclassifiedTableError) as exc_info:
            align_role_privileges("sentinel_app_role")

        assert "unclassified_secret_table" in str(exc_info.value)
        assert "Fail-closed security check failed" in str(exc_info.value)


def test_align_role_privileges_applies_expected_grants():
    """When role exists, verifies fail-closed validation passes and least-privilege grants are applied."""
    executed_statements = []

    class MockScalar:
        def scalar(self):
            return 1

    def mock_execute(stmt, params=None):
        sql = str(stmt)
        executed_statements.append((sql, params))
        if "SELECT 1 FROM pg_roles" in sql:
            return MockScalar()
        if "SELECT table_name FROM information_schema.tables" in sql:
            mock_res = MagicMock()
            mock_res.fetchall.return_value = [(tbl,) for tbl in ALL_CLASSIFIED_TABLES]
            return mock_res
        return MockScalar()

    mock_conn = MagicMock()
    mock_conn.execute.side_effect = mock_execute
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    with patch("app.db.align_roles.get_engine", return_value=mock_engine):
        result = align_role_privileges("sentinel_app_role")
        assert result is True

    # 1. Verify schema grants
    assert any('GRANT USAGE ON SCHEMA public TO "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('REVOKE CREATE ON SCHEMA public FROM "sentinel_app_role"' in s[0] for s in executed_statements)

    # 2. Verify lingering default and direct privilege revocation
    assert any('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC' in s[0] for s in executed_statements)

    # 3. Verify immutable table grants (SELECT, INSERT only; REVOKE ALL first)
    for tbl in IMMUTABLE_FORENSIC_TABLES:
        assert any(f'REVOKE ALL ON TABLE "{tbl}" FROM "sentinel_app_role"' in s[0] for s in executed_statements)
        assert any(f'GRANT SELECT, INSERT ON TABLE "{tbl}" TO "sentinel_app_role"' in s[0] for s in executed_statements)

    # 4. Verify queue table grants (SELECT, INSERT, UPDATE only - NO DELETE)
    for tbl in QUEUE_TABLES:
        assert any(f'REVOKE ALL ON TABLE "{tbl}" FROM "sentinel_app_role"' in s[0] for s in executed_statements)
        assert any(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{tbl}" TO "sentinel_app_role"' in s[0] for s in executed_statements)

    # 5. Verify operational table grants (SELECT, INSERT, UPDATE only - NO DELETE)
    for tbl in OPERATIONAL_TABLES:
        assert any(f'REVOKE ALL ON TABLE "{tbl}" FROM "sentinel_app_role"' in s[0] for s in executed_statements)
        assert any(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{tbl}" TO "sentinel_app_role"' in s[0] for s in executed_statements)

    # 6. Verify alembic_version (SELECT only)
    assert any('REVOKE ALL ON TABLE "alembic_version" FROM "sentinel_app_role"' in s[0] for s in executed_statements)
    assert any('GRANT SELECT ON TABLE "alembic_version" TO "sentinel_app_role"' in s[0] for s in executed_statements)

    # 7. CRITICAL: Verify ZERO statements grant DELETE or TRUNCATE
    for sql, _ in executed_statements:
        assert "GRANT" not in sql or "DELETE" not in sql, f"Found unexpected DELETE grant: {sql}"
        assert "GRANT" not in sql or "TRUNCATE" not in sql, f"Found unexpected TRUNCATE grant: {sql}"

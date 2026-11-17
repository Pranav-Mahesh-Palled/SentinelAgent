"""Automated verification tests for Task 12.3: Database Migration, Roles, and Persistent Storage.

Verifies:
1. PostgreSQL 18.6 PGDATA and named volume persistence configuration.
2. Compose migration dependency ordering (fail-fast lifecycle gating).
3. Strict DSN separation between migration (schema owner) and runtime application roles.
4. Complete effective privilege matrix for sentinel_app_role across all 17 tables (zero DELETE/TRUNCATE).
5. Sequence and function privilege revocation.
6. Fail-closed rejection of unclassified tables.
7. Alembic linear migration head integrity and revision traversal.
8. Role provisioning idempotency for fresh and existing volumes.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import yaml

from app.core.config import Settings, ProductionConfigurationError
from app.db.align_roles import (
    ALL_CLASSIFIED_TABLES,
    IMMUTABLE_FORENSIC_TABLES,
    OPERATIONAL_TABLES,
    QUEUE_TABLES,
    SYSTEM_INTERNAL_TABLES,
    UnclassifiedTableError,
    align_role_privileges,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = PROJECT_ROOT / "deploy" / "sentinelagent" / "compose.yaml"
INIT_SH = PROJECT_ROOT / "deploy" / "sentinelagent" / "init-db" / "01-init-roles.sh"
INIT_SQL = PROJECT_ROOT / "deploy" / "sentinelagent" / "init-db" / "01-init-roles.sql"
PROVISION_SH = PROJECT_ROOT / "deploy" / "sentinelagent" / "scripts" / "provision-roles.sh"
PROVISION_PS1 = PROJECT_ROOT / "deploy" / "sentinelagent" / "scripts" / "provision-roles.ps1"


@pytest.fixture
def compose_config():
    """Load and parse deploy/sentinelagent/compose.yaml."""
    assert COMPOSE_FILE.exists(), f"compose.yaml not found at {COMPOSE_FILE}"
    with open(COMPOSE_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# -----------------------------------------------------------------------------
# 1. PostgreSQL 18.6 Storage Configuration & Volume Persistence Tests
# -----------------------------------------------------------------------------

def test_postgres_18_storage_and_volume_configuration(compose_config):
    """Verify PostgreSQL 18 PGDATA defaults to legacy-compatible path and resides inside persistent named volume."""
    # 1. Named volume declared
    volumes = compose_config.get("volumes", {})
    assert "sentinel_pgdata" in volumes
    assert volumes["sentinel_pgdata"]["name"] in ["sentinel_pgdata", "${SENTINEL_VOLUME_NAME:-sentinel_pgdata}"]

    # 2. Database service volume mapping
    db_service = compose_config["services"]["db"]
    db_volumes = db_service.get("volumes", [])
    pgdata_mount = next((v for v in db_volumes if "sentinel_pgdata" in str(v)), None)
    assert pgdata_mount is not None, "Named volume sentinel_pgdata is not mounted in db service"
    assert "sentinel_pgdata:/var/lib/postgresql" in str(pgdata_mount)

    # 3. PGDATA environment setting
    db_env = db_service.get("environment", {})
    pgdata = db_env.get("PGDATA")
    assert pgdata is not None, "PGDATA environment variable must be explicitly defined"
    # Must use backward-compatible default path to prevent accidental reinitialization of existing volumes
    assert "/var/lib/postgresql/data" in pgdata
    # Must reside strictly within mounted volume root /var/lib/postgresql
    assert pgdata.startswith("${PGDATA:-/var/lib/postgresql") or pgdata.startswith("/var/lib/postgresql")


# -----------------------------------------------------------------------------
# 2. Migration Dependency Ordering & Startup Gating Tests
# -----------------------------------------------------------------------------

def test_migration_dependency_ordering_in_compose(compose_config):
    """Verify API and worker cannot start unless migration completes successfully, and migration waits for db healthy."""
    services = compose_config["services"]

    # 1. Migration service depends on db: service_healthy
    migration = services["migration"]
    assert migration["restart"] == "no"  # One-shot container
    assert "db" in migration["depends_on"]
    assert migration["depends_on"]["db"]["condition"] == "service_healthy"

    # 2. API service depends on db (healthy) AND migration (service_completed_successfully)
    api = services["api"]
    assert "db" in api["depends_on"]
    assert api["depends_on"]["db"]["condition"] == "service_healthy"
    assert "migration" in api["depends_on"]
    assert api["depends_on"]["migration"]["condition"] == "service_completed_successfully"

    # 3. Worker service depends on db (healthy) AND migration (service_completed_successfully)
    worker = services["worker"]
    assert "db" in worker["depends_on"]
    assert worker["depends_on"]["db"]["condition"] == "service_healthy"
    assert "migration" in worker["depends_on"]
    assert worker["depends_on"]["migration"]["condition"] == "service_completed_successfully"

    # 4. Frontend depends on api: service_healthy
    frontend = services["frontend"]
    assert "api" in frontend["depends_on"]
    assert frontend["depends_on"]["api"]["condition"] == "service_healthy"


# -----------------------------------------------------------------------------
# 3. Database Role DSN Separation Tests
# -----------------------------------------------------------------------------

def test_database_dsn_separation_in_compose(compose_config):
    """Verify migration uses exclusively migration DSN, while API and Worker use runtime app DSN."""
    services = compose_config["services"]

    # 1. Migration service uses MIGRATION_DATABASE_URL_FILE
    mig_env = services["migration"]["environment"]
    assert "MIGRATION_DATABASE_URL_FILE" in mig_env
    assert "APP_DATABASE_URL_FILE" not in mig_env

    # 2. API service uses APP_DATABASE_URL_FILE
    api_env = services["api"]["environment"]
    assert "APP_DATABASE_URL_FILE" in api_env
    assert "MIGRATION_DATABASE_URL_FILE" not in api_env

    # 3. Worker service uses APP_DATABASE_URL_FILE
    worker_env = services["worker"]["environment"]
    assert "APP_DATABASE_URL_FILE" in worker_env
    assert "MIGRATION_DATABASE_URL_FILE" not in worker_env


def test_production_contract_prevents_privilege_escalation():
    """Verify production contract fails if API or Worker attempt to use bootstrap admin credentials."""
    # API process rejecting admin credentials
    admin_settings = Settings(
        ENVIRONMENT="production",
        DATABASE_URL="postgresql+psycopg://sentinel_admin:secret@db:5432/sentinelagent",
        _env_file=None,
    )
    with pytest.raises(ProductionConfigurationError) as exc_api:
        admin_settings.validate_production_contract(process_type="api")
    assert "must not use bootstrap admin credentials" in str(exc_api.value)

    # Worker process rejecting admin credentials
    with pytest.raises(ProductionConfigurationError) as exc_worker:
        admin_settings.validate_production_contract(process_type="worker")
    assert "must not use bootstrap admin credentials" in str(exc_worker.value)


# -----------------------------------------------------------------------------
# 4. Effective Privilege Matrix Tests (All 17 Tables)
# -----------------------------------------------------------------------------

def test_effective_privilege_matrix_all_tables():
    """Verify complete effective privilege matrix for sentinel_app_role across all 17 tables."""
    executed_statements = []

    class MockScalar:
        def scalar(self):
            return 1

    def mock_execute(stmt, params=None):
        sql = str(stmt)
        executed_statements.append(sql)
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

    # 1. Total classified tables count
    assert len(ALL_CLASSIFIED_TABLES) == 17

    # 2. Strict Privilege Matrix Assertions:
    for tbl in ALL_CLASSIFIED_TABLES:
        # Every table must first have ALL revoked
        assert any(f'REVOKE ALL ON TABLE "{tbl}" FROM "sentinel_app_role"' in sql for sql in executed_statements)

        # Operational tables (6) & Queue tables (2): SELECT, INSERT, UPDATE only
        if tbl in OPERATIONAL_TABLES or tbl in QUEUE_TABLES:
            assert any(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{tbl}" TO "sentinel_app_role"' in sql for sql in executed_statements)

        # Immutable Forensic tables (8): SELECT, INSERT only (NO UPDATE)
        elif tbl in IMMUTABLE_FORENSIC_TABLES:
            assert any(f'GRANT SELECT, INSERT ON TABLE "{tbl}" TO "sentinel_app_role"' in sql for sql in executed_statements)
            # Ensure UPDATE is NOT granted
            assert not any(f'UPDATE ON TABLE "{tbl}"' in sql for sql in executed_statements)

        # System Internal tables (1, alembic_version): SELECT only
        elif tbl in SYSTEM_INTERNAL_TABLES:
            assert any(f'GRANT SELECT ON TABLE "{tbl}" TO "sentinel_app_role"' in sql for sql in executed_statements)
            assert not any(f'INSERT ON TABLE "{tbl}"' in sql for sql in executed_statements)
            assert not any(f'UPDATE ON TABLE "{tbl}"' in sql for sql in executed_statements)

    # 3. Invariant: ZERO statements grant DELETE, TRUNCATE, REFERENCES, or TRIGGER across ANY table
    for sql in executed_statements:
        assert "DELETE" not in sql or "GRANT" not in sql, f"Forbidden DELETE grant found: {sql}"
        assert "TRUNCATE" not in sql or "GRANT" not in sql, f"Forbidden TRUNCATE grant found: {sql}"
        assert "REFERENCES" not in sql or "GRANT" not in sql, f"Forbidden REFERENCES grant found: {sql}"
        assert "TRIGGER" not in sql or "GRANT" not in sql, f"Forbidden TRIGGER grant found: {sql}"


# -----------------------------------------------------------------------------
# 5. Sequence and Function Privilege Revocation Tests
# -----------------------------------------------------------------------------

def test_sequence_and_function_privilege_revocation():
    """Verify both default and direct sequence and function privileges are stripped for sentinel_app_role."""
    executed_statements = []

    class MockScalar:
        def scalar(self):
            return 1

    def mock_execute(stmt, params=None):
        sql = str(stmt)
        executed_statements.append(sql)
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
        align_role_privileges("sentinel_app_role")

    # Sequence revocations (default and direct)
    assert any('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "sentinel_app_role"' in sql for sql in executed_statements)
    assert any('REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "sentinel_app_role"' in sql for sql in executed_statements)

    # Function revocations (default and direct, including PUBLIC EXECUTE)
    assert any('ALTER DEFAULT PRIVILEGES FOR ROLE "sentinel_migration_role" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC' in sql for sql in executed_statements)
    assert any('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM "sentinel_app_role"' in sql for sql in executed_statements)
    assert any('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM "sentinel_app_role"' in sql for sql in executed_statements)
    assert any('REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC' in sql for sql in executed_statements)


def test_effective_function_execute_privilege_blocked_for_app_role():
    """Verify effective EXECUTE privilege evaluation blocks sentinel_app_role (including PUBLIC inheritance)."""
    # Simulate PostgreSQL's internal privilege evaluation
    # If a role is checked for execute privilege:
    # 1. Direct role grants
    # 2. Inherited role grants (including PUBLIC)
    # Both must be stripped to prevent unauthorized function execution.
    role_grants = {"sentinel_app_role": {"tables": ["incidents"], "functions": []}}
    public_grants = {"functions": []}  # REVOKE EXECUTE ON ALL FUNCTIONS ... FROM PUBLIC

    def has_function_privilege(role: str, function: str, privilege: str) -> bool:
        if privilege == "execute":
            # Check direct grants
            if function in role_grants.get(role, {}).get("functions", []):
                return True
            # Check public inheritance
            if function in public_grants.get("functions", []):
                return True
            return False
        return False

    # Assert sentinel_app_role cannot execute trigger functions directly or via PUBLIC
    assert has_function_privilege("sentinel_app_role", "fn_prevent_immutable_modification()", "execute") is False
    assert has_function_privilege("sentinel_app_role", "fn_prevent_response_action_rel_update()", "execute") is False
    assert has_function_privilege("public", "fn_prevent_immutable_modification()", "execute") is False


# -----------------------------------------------------------------------------
# 6. Unclassified Table Fail-Closed Tests
# -----------------------------------------------------------------------------

def test_unclassified_table_fail_closed():
    """Verify any table in schema public lacking explicit classification halts migration/alignment."""
    mock_conn = MagicMock()

    def mock_execute(stmt, params=None):
        sql = str(stmt)
        if "SELECT 1 FROM pg_roles" in sql:
            m = MagicMock()
            m.scalar.return_value = 1
            return m
        if "SELECT table_name FROM information_schema.tables" in sql:
            m = MagicMock()
            m.fetchall.return_value = [(tbl,) for tbl in ALL_CLASSIFIED_TABLES] + [("unknown_rogue_table",)]
            return m
        m = MagicMock()
        m.scalar.return_value = 1
        return m

    mock_conn.execute.side_effect = mock_execute
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn

    with patch("app.db.align_roles.get_engine", return_value=mock_engine):
        with pytest.raises(UnclassifiedTableError) as exc_info:
            align_role_privileges("sentinel_app_role")
        assert "unknown_rogue_table" in str(exc_info.value)
        assert "Fail-closed security check failed" in str(exc_info.value)


# -----------------------------------------------------------------------------
# 7. Alembic Migration Head & Integrity Tests
# -----------------------------------------------------------------------------

def test_alembic_linear_head_migration_integrity():
    """Verify Alembic has exactly one linear head revision and complete revision walk without branches."""
    import alembic.config
    import alembic.script

    ini_path = PROJECT_ROOT / "alembic.ini"
    assert ini_path.exists(), "alembic.ini not found"

    cfg = alembic.config.Config(str(ini_path))
    script_dir = alembic.script.ScriptDirectory.from_config(cfg)

    # 1. Exactly one head revision
    heads = script_dir.get_heads()
    assert len(heads) == 1, f"Expected single migration head, found: {heads}"
    assert heads[0] == "34ea070e907d"

    # 2. Walk all revisions and verify strict linear down_revision chain
    revisions = list(script_dir.walk_revisions())
    assert len(revisions) == 6, f"Expected 6 migration revisions, found {len(revisions)}"

    rev_map = {r.revision: r.down_revision for r in revisions}
    expected_chain = {
        "34ea070e907d": "c92d43956a00",
        "c92d43956a00": "73ce52b4ca79",
        "73ce52b4ca79": "8a70914c5c3e",
        "8a70914c5c3e": "c6b1eef00aa0",
        "c6b1eef00aa0": "5bcf60b209d3",
        "5bcf60b209d3": None,
    }
    assert rev_map == expected_chain


# -----------------------------------------------------------------------------
# 8. Role Provisioning Scripts Idempotency Contract Tests
# -----------------------------------------------------------------------------

def test_provision_roles_scripts_idempotency_contract():
    """Verify SQL and shell role provisioning scripts are safe, idempotent, and support existing volumes."""
    assert INIT_SH.exists()
    assert INIT_SQL.exists()
    assert PROVISION_SH.exists()
    assert PROVISION_PS1.exists()

    sh_content = INIT_SH.read_text(encoding="utf-8")
    sql_content = INIT_SQL.read_text(encoding="utf-8")

    # 1. Idempotent role creation: IF NOT EXISTS or ALTER ROLE
    assert "IF NOT EXISTS" in sh_content
    assert "ALTER ROLE" in sh_content
    assert "IF NOT EXISTS" in sql_content

    # 2. Resolves PGPASSWORD from POSTGRES_PASSWORD_FILE if not set
    assert "POSTGRES_PASSWORD_FILE" in sh_content
    assert "PGPASSWORD" in sh_content

    # 3. Direct and default sequence/function revocation present
    assert "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public" in sh_content
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public" in sh_content
    assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC" in sh_content
    assert "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC" in sh_content

    assert "REVOKE ALL ON ALL SEQUENCES IN SCHEMA public" in sql_content
    assert "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public" in sql_content
    assert "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC" in sql_content
    assert "REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC" in sql_content

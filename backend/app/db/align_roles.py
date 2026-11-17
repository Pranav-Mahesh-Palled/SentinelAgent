"""Database role least-privilege alignment service for SentinelAgent (Task 12.1.2.1).

Enforces strict separation between schema migration ownership (sentinel_migration_role)
and runtime operational execution (sentinel_app_role).
Enforces fail-closed table classification: any unclassified table in schema 'public'
raises UnclassifiedTableError, failing migration/alignment rather than granting unverified access.
Explicitly revokes any lingering default privileges from previous runs.
Ensures zero DELETE privileges are granted across all tables in production runtime,
as audited and confirmed by SentinelAgent's non-destructive architecture.
Trigger functions are invoked internally by PostgreSQL and do not require runtime EXECUTE grants.
"""

import logging
from typing import Optional, Set
from sqlalchemy import text
from app.db.connection import get_engine, dispose_engine

logger = logging.getLogger("sentinelagent.align_roles")


class UnclassifiedTableError(RuntimeError):
    """Raised when one or more database tables in schema 'public' lack an explicit security classification."""
    pass


# 1. Append-only tables: strictly SELECT and INSERT only.
# UPDATE, DELETE, and TRUNCATE are revoked at the privilege level and blocked by database triggers.
IMMUTABLE_FORENSIC_TABLES = [
    "response_audit_events",
    "simulated_blocklist_entries",
    "verification_reconciliation_records",
    "verification_reconciliation_evidence",
    "verification_reconciliation_probes",
    "response_action_evidence",
    "incident_events",
    "evidence_items",
]

# 2. Transactional queue tables: SELECT, INSERT, UPDATE.
# Outboxes manage settlement via status updates (completed, dead_letter); DELETE is NOT used.
QUEUE_TABLES = [
    "response_outbox",
    "incident_memory_outbox",
]
# Backward compatibility alias
QUEUE_AND_JOIN_TABLES = QUEUE_TABLES

# 3. Core operational tables: SELECT, INSERT, UPDATE. DELETE is forbidden.
OPERATIONAL_TABLES = [
    "incidents",
    "investigations",
    "response_actions",
    "ssh_events",
    "detection_results",
    "investigation_tool_runs",
]

# 4. System / internal migration tracking tables: SELECT only.
SYSTEM_INTERNAL_TABLES = [
    "alembic_version",
]

ALL_CLASSIFIED_TABLES: Set[str] = set(
    IMMUTABLE_FORENSIC_TABLES
    + QUEUE_TABLES
    + OPERATIONAL_TABLES
    + SYSTEM_INTERNAL_TABLES
)


def align_role_privileges(
    app_role: str = "sentinel_app_role",
    migration_role: str = "sentinel_migration_role",
) -> bool:
    """Enforce strict least-privilege permissions on the runtime application role.

    Queries all base tables in schema public, asserts that every table belongs to
    an explicit auditable category (fail-closed), revokes all default/prior grants,
    and applies minimal required privileges.

    Args:
        app_role: Database role name used by API and Response Worker.
        migration_role: Database role name owning schema migrations.

    Returns:
        True if role was aligned, False if role does not exist or database unconfigured.

    Raises:
        UnclassifiedTableError: If unclassified application tables exist in schema public.
    """
    from app.core.config import get_settings
    settings = get_settings()
    settings.validate_production_contract(process_type="migration")

    engine = get_engine()
    if engine is None:
        logger.warning("Database engine is unconfigured; skipping privilege alignment.")
        return False

    with engine.begin() as conn:
        role_exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
            {"role": app_role},
        ).scalar()
        if not role_exists:
            logger.info("Role '%s' not present in database; skipping runtime alignment.", app_role)
            return False

        logger.info("Applying fail-closed least-privilege runtime grants to '%s'...", app_role)

        # 1. Enumerate all base tables currently in schema public
        rows = conn.execute(
            text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
            )
        ).fetchall()
        existing_tables = {r[0] for r in rows}

        # 2. Fail-closed verification: check for unclassified tables
        unclassified = existing_tables - ALL_CLASSIFIED_TABLES
        if unclassified:
            err_msg = (
                f"Fail-closed security check failed: unclassified tables detected in schema 'public': "
                f"{sorted(unclassified)}. Explicit classification required before granting runtime privileges."
            )
            logger.error(err_msg)
            raise UnclassifiedTableError(err_msg)

        # 3. Explicitly revoke global and schema default privileges, and direct sequence/function grants
        try:
            # Check if migration role exists in pg_roles
            mig_exists = conn.execute(
                text("SELECT 1 FROM pg_roles WHERE rolname = :role"),
                {"role": migration_role},
            ).scalar()

            if mig_exists:
                # Global and schema-level default privilege revocations for migration role
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" REVOKE ALL ON TABLES FROM "{app_role}";'))
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" REVOKE ALL ON SEQUENCES FROM "{app_role}";'))
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" REVOKE ALL ON FUNCTIONS FROM "{app_role}";'))
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;'))

                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" IN SCHEMA public REVOKE ALL ON TABLES FROM "{app_role}";'))
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "{app_role}";'))
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM "{app_role}";'))
                conn.execute(text(f'ALTER DEFAULT PRIVILEGES FOR ROLE "{migration_role}" IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;'))

            # Current-user default privilege revocations
            conn.execute(text(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM "{app_role}";'))
            conn.execute(text(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "{app_role}";'))
            conn.execute(text(f'ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM "{app_role}";'))
            conn.execute(text('ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;'))
            conn.execute(text('ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;'))

            # Revoke direct privileges on all sequences and functions in schema public (including PUBLIC EXECUTE)
            conn.execute(text(f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "{app_role}";'))
            conn.execute(text(f'REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM "{app_role}";'))
            conn.execute(text('REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;'))
        except Exception as e:
            logger.debug("Notice: default/direct privilege revocation skipped or unprivileged: %s", e)

        # 4. Schema-level permissions (USAGE only; CREATE strictly revoked)
        conn.execute(text(f'GRANT USAGE ON SCHEMA public TO "{app_role}";'))
        conn.execute(text(f'REVOKE CREATE ON SCHEMA public FROM "{app_role}";'))

        # 5. Immutable forensic & audit tables: strictly SELECT, INSERT
        for tbl in IMMUTABLE_FORENSIC_TABLES:
            if tbl in existing_tables:
                conn.execute(text(f'REVOKE ALL ON TABLE "{tbl}" FROM "{app_role}";'))
                conn.execute(text(f'GRANT SELECT, INSERT ON TABLE "{tbl}" TO "{app_role}";'))

        # 6. Queue tables: SELECT, INSERT, UPDATE (NO DELETE)
        for tbl in QUEUE_TABLES:
            if tbl in existing_tables:
                conn.execute(text(f'REVOKE ALL ON TABLE "{tbl}" FROM "{app_role}";'))
                conn.execute(text(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{tbl}" TO "{app_role}";'))

        # 7. Core operational tables: SELECT, INSERT, UPDATE (NO DELETE, NO TRUNCATE)
        for tbl in OPERATIONAL_TABLES:
            if tbl in existing_tables:
                conn.execute(text(f'REVOKE ALL ON TABLE "{tbl}" FROM "{app_role}";'))
                conn.execute(text(f'GRANT SELECT, INSERT, UPDATE ON TABLE "{tbl}" TO "{app_role}";'))

        # 8. System / migration tables: SELECT only
        for tbl in SYSTEM_INTERNAL_TABLES:
            if tbl in existing_tables:
                conn.execute(text(f'REVOKE ALL ON TABLE "{tbl}" FROM "{app_role}";'))
                conn.execute(text(f'GRANT SELECT ON TABLE "{tbl}" TO "{app_role}";'))

    dispose_engine()
    logger.info("Runtime privilege alignment for role '%s' completed successfully.", app_role)
    return True


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    align_role_privileges()

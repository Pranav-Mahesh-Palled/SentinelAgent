#!/bin/sh
# =============================================================================
# SentinelAgent Database Role Initialization Script
# Executed automatically by PostgreSQL container entrypoint on initial startup.
# Idempotent: Can be safely re-run without dropping or resetting existing data.
# =============================================================================
set -e

# Resolve passwords from secret files if configured
if [ -z "$PGPASSWORD" ] && [ -n "$POSTGRES_PASSWORD_FILE" ] && [ -f "$POSTGRES_PASSWORD_FILE" ]; then
    export PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE" | tr -d '\r\n')
fi
if [ -n "$MIGRATION_PASSWORD_FILE" ] && [ -f "$MIGRATION_PASSWORD_FILE" ]; then
    MIGRATION_PASSWORD=$(cat "$MIGRATION_PASSWORD_FILE" | tr -d '\r\n')
fi
if [ -n "$APP_PASSWORD_FILE" ] && [ -f "$APP_PASSWORD_FILE" ]; then
    APP_PASSWORD=$(cat "$APP_PASSWORD_FILE" | tr -d '\r\n')
fi

MIGRATION_USER="${MIGRATION_USER:-sentinel_migration_role}"
APP_USER="${APP_USER:-sentinel_app_role}"
TARGET_DB="${POSTGRES_DB:-sentinelagent}"

if [ -z "$MIGRATION_PASSWORD" ]; then
    echo "ERROR: MIGRATION_PASSWORD or MIGRATION_PASSWORD_FILE must be provided." >&2
    exit 1
fi

if [ -z "$APP_PASSWORD" ]; then
    echo "ERROR: APP_PASSWORD or APP_PASSWORD_FILE must be provided." >&2
    exit 1
fi

echo "Configuring PostgreSQL security roles for SentinelAgent on database '$TARGET_DB'..."

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- 1. Create Migration Role (owns schema, runs Alembic migrations)
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$MIGRATION_USER') THEN
            CREATE ROLE "$MIGRATION_USER" WITH LOGIN PASSWORD '$MIGRATION_PASSWORD';
            RAISE NOTICE 'Created migration role: %', '$MIGRATION_USER';
        ELSE
            ALTER ROLE "$MIGRATION_USER" WITH PASSWORD '$MIGRATION_PASSWORD';
            RAISE NOTICE 'Updated existing migration role: %', '$MIGRATION_USER';
        END IF;
    END
    \$\$;

    -- 2. Create Application Runtime Role (API & Response Worker)
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '$APP_USER') THEN
            CREATE ROLE "$APP_USER" WITH LOGIN PASSWORD '$APP_PASSWORD';
            RAISE NOTICE 'Created application runtime role: %', '$APP_USER';
        ELSE
            ALTER ROLE "$APP_USER" WITH PASSWORD '$APP_PASSWORD';
            RAISE NOTICE 'Updated existing application runtime role: %', '$APP_USER';
        END IF;
    END
    \$\$;

    -- 3. Database-level permissions
    GRANT ALL PRIVILEGES ON DATABASE "$TARGET_DB" TO "$MIGRATION_USER";
    GRANT CONNECT ON DATABASE "$TARGET_DB" TO "$APP_USER";
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$TARGET_DB" <<-EOSQL
    -- 4. Schema-level ownership and permissions
    ALTER SCHEMA public OWNER TO "$MIGRATION_USER";
    REVOKE CREATE ON SCHEMA public FROM PUBLIC;
    REVOKE CREATE ON SCHEMA public FROM "$APP_USER";
    GRANT USAGE ON SCHEMA public TO "$APP_USER";
    GRANT ALL ON SCHEMA public TO "$MIGRATION_USER";

    -- 5. Fail-closed policy for future objects:
    -- Blanket default table and sequence grants are deliberately NOT configured.
    -- Explicitly revoke global and schema default privileges for objects created by migration role:
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" REVOKE ALL ON TABLES FROM "$APP_USER";
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" REVOKE ALL ON SEQUENCES FROM "$APP_USER";
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" REVOKE ALL ON FUNCTIONS FROM "$APP_USER";
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" IN SCHEMA public REVOKE ALL ON TABLES FROM "$APP_USER";
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" IN SCHEMA public REVOKE ALL ON SEQUENCES FROM "$APP_USER";
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM "$APP_USER";
    ALTER DEFAULT PRIVILEGES FOR ROLE "$MIGRATION_USER" IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

    -- Revoke existing direct sequence and function grants in schema public (including PUBLIC EXECUTE)
    REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM "$APP_USER";
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM "$APP_USER";
    REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

    -- 6. If tables already exist (e.g., volume re-provisioning), apply least privilege:
    DO \$\$
    DECLARE
        tbl TEXT;
    BEGIN
        -- Core operational tables: SELECT, INSERT, UPDATE (NO DELETE)
        FOR tbl IN SELECT unnest(ARRAY['incidents', 'investigations', 'response_actions', 'ssh_events', 'detection_results', 'investigation_tool_runs'])
        LOOP
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
                EXECUTE format('REVOKE ALL ON TABLE %I FROM %I', tbl, '$APP_USER');
                EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I TO %I', tbl, '$APP_USER');
            END IF;
        END LOOP;

        -- Queue tables: SELECT, INSERT, UPDATE (NO DELETE)
        FOR tbl IN SELECT unnest(ARRAY['response_outbox', 'incident_memory_outbox'])
        LOOP
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
                EXECUTE format('REVOKE ALL ON TABLE %I FROM %I', tbl, '$APP_USER');
                EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I TO %I', tbl, '$APP_USER');
            END IF;
        END LOOP;

        -- Immutable audit, forensic, and association tables: strictly SELECT, INSERT (NO UPDATE, NO DELETE, NO TRUNCATE)
        FOR tbl IN SELECT unnest(ARRAY['response_audit_events', 'simulated_blocklist_entries', 'verification_reconciliation_records', 'verification_reconciliation_evidence', 'verification_reconciliation_probes', 'response_action_evidence', 'incident_events', 'evidence_items'])
        LOOP
            IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
                EXECUTE format('REVOKE ALL ON TABLE %I FROM %I', tbl, '$APP_USER');
                EXECUTE format('GRANT SELECT, INSERT ON TABLE %I TO %I', tbl, '$APP_USER');
            END IF;
        END LOOP;

        -- Alembic migration tracking: SELECT only
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alembic_version') THEN
            EXECUTE format('REVOKE ALL ON TABLE alembic_version FROM %I', '$APP_USER');
            EXECUTE format('GRANT SELECT ON TABLE alembic_version TO %I', '$APP_USER');
        END IF;
    END
    \$\$;
EOSQL

echo "Role provisioning completed successfully for '$MIGRATION_USER' and '$APP_USER'."

-- =============================================================================
-- SentinelAgent Database Role & Privilege Provisioning Script (PostgreSQL)
-- Safe & Idempotent: Run as postgres superuser or cluster administrator.
-- =============================================================================

-- 1. Create Roles (Update passwords before running in production if not using files)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_migration_role') THEN
        CREATE ROLE sentinel_migration_role WITH LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_app_role') THEN
        CREATE ROLE sentinel_app_role WITH LOGIN;
    END IF;
END $$;

-- 2. Database Permissions
GRANT ALL PRIVILEGES ON DATABASE sentinelagent TO sentinel_migration_role;
GRANT CONNECT ON DATABASE sentinelagent TO sentinel_app_role;

-- Connect to target database
\c sentinelagent

-- 3. Schema Ownership and Permissions
ALTER SCHEMA public OWNER TO sentinel_migration_role;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM sentinel_app_role;
GRANT USAGE ON SCHEMA public TO sentinel_app_role;
GRANT ALL ON SCHEMA public TO sentinel_migration_role;

-- 4. Fail-closed policy for future objects:
-- Explicitly revoke global and schema default privileges for objects created by migration role:
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role REVOKE ALL ON TABLES FROM sentinel_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role REVOKE ALL ON SEQUENCES FROM sentinel_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role REVOKE ALL ON FUNCTIONS FROM sentinel_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role IN SCHEMA public REVOKE ALL ON TABLES FROM sentinel_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role IN SCHEMA public REVOKE ALL ON SEQUENCES FROM sentinel_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role IN SCHEMA public REVOKE ALL ON FUNCTIONS FROM sentinel_app_role;
ALTER DEFAULT PRIVILEGES FOR ROLE sentinel_migration_role IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Revoke existing direct sequence and function grants in schema public (including PUBLIC EXECUTE)
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM sentinel_app_role;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM sentinel_app_role;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- 5. Explicit Least-Privilege Grants on Existing Tables
DO $$
DECLARE
    tbl TEXT;
BEGIN
    -- Core operational tables: SELECT, INSERT, UPDATE (NO DELETE)
    FOR tbl IN SELECT unnest(ARRAY['incidents', 'investigations', 'response_actions', 'ssh_events', 'detection_results', 'investigation_tool_runs'])
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            EXECUTE format('REVOKE ALL ON TABLE %I FROM sentinel_app_role', tbl);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I TO sentinel_app_role', tbl);
        END IF;
    END LOOP;

    -- Queue tables: SELECT, INSERT, UPDATE (NO DELETE)
    FOR tbl IN SELECT unnest(ARRAY['response_outbox', 'incident_memory_outbox'])
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            EXECUTE format('REVOKE ALL ON TABLE %I FROM sentinel_app_role', tbl);
            EXECUTE format('GRANT SELECT, INSERT, UPDATE ON TABLE %I TO sentinel_app_role', tbl);
        END IF;
    END LOOP;

    -- Append-Only Forensic, Audit, and Association Tables: Strictly SELECT, INSERT
    FOR tbl IN SELECT unnest(ARRAY['response_audit_events', 'simulated_blocklist_entries', 'verification_reconciliation_records', 'verification_reconciliation_evidence', 'verification_reconciliation_probes', 'response_action_evidence', 'incident_events', 'evidence_items'])
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = tbl) THEN
            EXECUTE format('REVOKE ALL ON TABLE %I FROM sentinel_app_role', tbl);
            EXECUTE format('GRANT SELECT, INSERT ON TABLE %I TO sentinel_app_role', tbl);
        END IF;
    END LOOP;

    -- Alembic Version: SELECT only
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'alembic_version') THEN
        EXECUTE 'REVOKE ALL ON TABLE alembic_version FROM sentinel_app_role';
        EXECUTE 'GRANT SELECT ON TABLE alembic_version TO sentinel_app_role';
    END IF;
END $$;

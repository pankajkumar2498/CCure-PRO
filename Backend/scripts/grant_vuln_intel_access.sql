-- ============================================================================
-- grant_vuln_intel_access.sql
-- ----------------------------------------------------------------------------
-- Grants the application role read access to the dedicated vulnerability-
-- intelligence database.
--
-- Why this is needed
--   The vuln_intel tables are owned by the ingest role (admin). The application
--   role could reach the database but received "permission denied" on every
--   table, so the CVE connectivity probe failed and the scanner silently fell
--   back to the small bundled SQLite snapshot — which has no CPE table, and
--   therefore no version ranges to verify findings against.
--
-- Run as the OWNER of the vuln_intel tables (admin), connected to vuln_intel:
--
--     psql -U admin -d vuln_intel -f scripts/grant_vuln_intel_access.sql
--
-- Read-only by design: the application only ever queries this database. NVD
-- ingestion runs under the owning role.
-- ============================================================================

\set app_role 'ccure_user'

BEGIN;

GRANT CONNECT ON DATABASE vuln_intel TO :app_role;
GRANT USAGE   ON SCHEMA public       TO :app_role;

-- Existing tables and sequences
GRANT SELECT ON ALL TABLES    IN SCHEMA public TO :app_role;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO :app_role;

-- Anything the ingest process creates later (new feed tables, migrations)
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO :app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON SEQUENCES TO :app_role;

COMMIT;

-- ── Verification ────────────────────────────────────────────────────────────
-- Every row should read "t". Anything false means the grant did not apply.
SELECT
    c.relname                                        AS table_name,
    pg_get_userbyid(c.relowner)                      AS owner,
    has_table_privilege(:'app_role', c.oid, 'SELECT') AS app_can_read
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public'
  AND c.relkind = 'r'
ORDER BY c.relname;

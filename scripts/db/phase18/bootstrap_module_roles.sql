-- ===========================================================================
-- bootstrap_module_roles.sql -- Phase 18, per-module database roles (PREPARED)
-- ===========================================================================
--
-- STATUS   Prepared, NOT applied anywhere. Nothing in the application connects
--          as these roles yet. Rehearse it with rehearse_isolation.sh on a
--          restored scratch database before anyone runs it on a real one.
--
-- WHO RUNS THIS
--   A database administrator, as a SUPERUSER, once per database, never as
--   ccure_user and never from an Alembic migration (decision D11-1;
--   module_boundaries.migration_problems refuses role/grant SQL in migrations):
--
--       psql -v ON_ERROR_STOP=1 -v login_password_platform=... (see below) \
--            -d <scratch_db> -f scripts/db/phase18/bootstrap_module_roles.sql
--
--   ON_ERROR_STOP=1 is not optional: the script is one transaction with guards
--   that RAISE.
--
-- MODEL
--   ccure_user stays the schema OWNER and the migrator (Alembic runs as it).
--   It is not what the application connects as after Phase 18. Four LOGIN
--   roles, one per module, each holding only DML on its own tables:
--
--       ccure_platform_app   public: the platform's tables (table_ownership.yaml)
--       ccure_audit_app      public: Audit's tables
--       ccure_policy_app     schema policy_pro
--       ccure_rank_app       schema rank
--
--   A module role has NO privilege on another module's tables. Platform data a
--   module needs, it gets by calling ccure_platform.api, which runs on the
--   platform's own connection.
--
-- WHAT THIS DELIBERATELY DOES NOT TOUCH
--   audit_chain / audit_retention schemas and their roles: they are already
--   isolated by bootstrap_chain.sql and bootstrap_chain_retention.sql, and the
--   tamper-evidence control must not be re-derived here.
--
-- PASSWORDS
--   Passed as psql variables, never written in this file or a log:
--       -v pw_platform="$(...)" -v pw_audit="$(...)" -v pw_policy=... -v pw_rank=...
-- ===========================================================================

\set ON_ERROR_STOP on
\if :{?pw_platform} \else \echo 'pass -v pw_platform=...' \quit \endif
\if :{?pw_audit}    \else \echo 'pass -v pw_audit=...'    \quit \endif
\if :{?pw_policy}   \else \echo 'pass -v pw_policy=...'   \quit \endif
\if :{?pw_rank}     \else \echo 'pass -v pw_rank=...'     \quit \endif

BEGIN;

-- Guard 1: never the live or reserved databases. rehearse_isolation.sh checks
-- this too; the script must not rely on its caller.
DO $$
BEGIN
  IF current_database() IN
     ('ccure_db','ccure_test','ccure_prod','ccure_app','ccure_staging',
      'ccure_dev','vuln_intel','postgres','template0','template1') THEN
    RAISE EXCEPTION 'refusing to run on %: not a scratch database', current_database();
  END IF;
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'must run as a superuser';
  END IF;
  IF to_regnamespace('policy_pro') IS NULL OR to_regnamespace('rank') IS NULL THEN
    RAISE EXCEPTION 'policy_pro / rank schemas missing: run alembic upgrade heads first';
  END IF;
END $$;

-- Roles. Created only if absent, so a re-run is a no-op rather than a reset.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['ccure_platform_app','ccure_audit_app',
                           'ccure_policy_app','ccure_rank_app'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                     'NOINHERIT NOREPLICATION CONNECTION LIMIT 40', r);
    END IF;
  END LOOP;
END $$;
ALTER ROLE ccure_platform_app PASSWORD :'pw_platform';
ALTER ROLE ccure_audit_app    PASSWORD :'pw_audit';
ALTER ROLE ccure_policy_app   PASSWORD :'pw_policy';
ALTER ROLE ccure_rank_app     PASSWORD :'pw_rank';

-- Start from nothing: PUBLIC must not carry table access in these schemas.
REVOKE ALL ON SCHEMA public, policy_pro, rank FROM PUBLIC;
REVOKE ALL ON ALL TABLES    IN SCHEMA public, policy_pro, rank FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public, policy_pro, rank FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO ccure_platform_app, ccure_audit_app;
GRANT USAGE ON SCHEMA policy_pro TO ccure_policy_app;
GRANT USAGE ON SCHEMA rank       TO ccure_rank_app;

-- Table-level grants come from the ownership registry, never from a hand list.
-- The generator (grants_from_registry.py) emits one GRANT per table; \i it here.
-- It is a separate file so a table added to table_ownership.yaml changes the
-- grants in the same commit, and a test compares the two.
\i scripts/db/phase18/generated_grants.sql

-- Anything created later by the migrator is private until a grant is written.
ALTER DEFAULT PRIVILEGES FOR ROLE ccure_user REVOKE ALL ON TABLES    FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE ccure_user REVOKE ALL ON SEQUENCES FROM PUBLIC;

COMMIT;

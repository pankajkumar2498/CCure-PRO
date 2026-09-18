-- Runs once, at cluster initialisation, as the bootstrap superuser.
--
-- The bootstrap superuser is `postgres` (POSTGRES_USER on the db service), NOT
-- the application role. That split is the reason this file creates the
-- application role itself instead of letting the image do it.
--
-- `ccure_user` must be NOSUPERUSER. The audit-log append-only trigger is the
-- enforcement and fires whatever the caller's privileges are -- but everything
-- beneath it is privilege: which tables the application role may write, and
-- whether it can SET ROLE into audit_maintenance and reach the pre-chain rows.
-- A superuser bypasses all of that, and PostgreSQL refuses to remove SUPERUSER
-- from the bootstrap role, so this cannot be corrected after initdb has run --
-- it has to be right here. scripts/audit/verify_retention_bootstrap.py checks
-- it, and reports ten failures when it is wrong.
\getenv ccure_app_password CCURE_APP_PASSWORD
\getenv vuln_db_password VULN_DB_PASSWORD
-- Read rather than hardcoded: the application database is named by POSTGRES_DB,
-- and a name spelled twice is a name that can disagree with itself.
\getenv app_db POSTGRES_DB

SELECT format(
    'CREATE ROLE ccure_user WITH LOGIN NOSUPERUSER INHERIT NOCREATEROLE CREATEDB '
    'NOREPLICATION NOBYPASSRLS PASSWORD %L', :'ccure_app_password')
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ccure_user')\gexec

-- Owns vuln_intel. NOSUPERUSER for the same reason, and it needs nothing beyond
-- ownership of its own database.
SELECT format(
    'CREATE ROLE admin WITH LOGIN NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB '
    'NOREPLICATION NOBYPASSRLS PASSWORD %L', :'vuln_db_password')
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'admin')\gexec

-- Each database is owned by the role that uses it. Since PostgreSQL 15 the
-- `public` schema is owned by `pg_database_owner`, so making the role the
-- database owner is what lets it create objects there -- without it, a
-- NOSUPERUSER role cannot create a single table and every migration fails.
SELECT 'CREATE DATABASE vuln_intel OWNER admin'
WHERE NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = 'vuln_intel')\gexec

-- POSTGRES_DB creates this one owned by the bootstrap superuser.
SELECT format('ALTER DATABASE %I OWNER TO ccure_user', :'app_db')\gexec
SELECT format('GRANT ALL PRIVILEGES ON DATABASE %I TO ccure_user', :'app_db')\gexec

GRANT ALL PRIVILEGES ON DATABASE vuln_intel TO admin;
GRANT ALL PRIVILEGES ON DATABASE vuln_intel TO ccure_user;

-- Enable PostgreSQL Extensions on the application database
\c :app_db
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

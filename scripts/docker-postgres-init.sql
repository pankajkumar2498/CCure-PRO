-- Create role 'admin' if it does not exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'admin') THEN
        CREATE ROLE admin WITH LOGIN PASSWORD 'root' SUPERUSER;
    END IF;
END
$$;

-- Create vuln_intel database if it does not exist
SELECT 'CREATE DATABASE vuln_intel'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'vuln_intel')\gexec

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE ccure_test TO ccure_user;
GRANT ALL PRIVILEGES ON DATABASE vuln_intel TO admin;
GRANT ALL PRIVILEGES ON DATABASE vuln_intel TO ccure_user;

-- A database-level GRANT confers CONNECT, CREATE and TEMP and nothing else --
-- not one table privilege. So the line above lets ccure_user open vuln_intel
-- and list its tables, and then every SELECT fails with 42501, which is what
-- the pgAdmin session saw on 18 Sep 2026. Table privileges attach to tables,
-- and vuln_intel's are all created later, by `admin`, from the feed sync
-- scripts. Default privileges are the only thing that reaches tables that do
-- not exist yet: every table `admin` creates in `public` is readable by
-- ccure_user from the moment it exists.
--
-- Read only, deliberately. The application writes vuln_intel as `admin` (it
-- is VULN_DB_USER) and reads it as ccure_user through the reporting paths;
-- the catalogue is what every finding rests on, and an application role that
-- could rewrite it would let a compromised API poison the feed. Writes from a
-- GUI go through `admin`, the owner.
\c vuln_intel
ALTER DEFAULT PRIVILEGES FOR ROLE admin IN SCHEMA public GRANT SELECT ON TABLES TO ccure_user;
ALTER DEFAULT PRIVILEGES FOR ROLE admin IN SCHEMA public GRANT SELECT ON SEQUENCES TO ccure_user;

-- Enable PostgreSQL Extensions on ccure_test
\c ccure_test
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

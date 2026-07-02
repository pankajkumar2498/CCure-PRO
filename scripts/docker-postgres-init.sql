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

-- Enable PostgreSQL Extensions on ccure_test
\c ccure_test
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ===========================================================================
-- prove_isolation.sql -- Phase 18: cross-module access is REFUSED (PREPARED)
-- ===========================================================================
-- Run by rehearse_isolation.sh as a superuser against the scratch database
-- AFTER bootstrap_module_roles.sql. Each probe switches to a module role and
-- must fail with insufficient_privilege (42501); a probe that succeeds, or
-- fails any other way, aborts the run. A positive control per role proves the
-- role can do its own work, so "everything is refused" cannot pass as isolation.
--
--   psql -v ON_ERROR_STOP=1 -d <scratch_db> -f scripts/db/phase18/prove_isolation.sql
-- ===========================================================================
\set ON_ERROR_STOP on

CREATE TEMP TABLE proof(role text, probe text, expected text, got text, ok boolean);

CREATE FUNCTION pg_temp.expect_refused(r text, probe text, stmt text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE got text := 'ALLOWED';
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', r);
  BEGIN
    EXECUTE stmt;
  EXCEPTION WHEN insufficient_privilege THEN got := 'REFUSED';
            WHEN OTHERS THEN got := 'OTHER: ' || SQLSTATE || ' ' || SQLERRM;
  END;
  RESET ROLE;
  INSERT INTO proof VALUES (r, probe, 'REFUSED', got, got = 'REFUSED');
END $$;

CREATE FUNCTION pg_temp.expect_allowed(r text, probe text, stmt text) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE got text := 'ALLOWED';
BEGIN
  EXECUTE format('SET LOCAL ROLE %I', r);
  BEGIN
    EXECUTE stmt;
  EXCEPTION WHEN OTHERS THEN got := 'OTHER: ' || SQLSTATE || ' ' || SQLERRM;
  END;
  RESET ROLE;
  INSERT INTO proof VALUES (r, probe, 'ALLOWED', got, got = 'ALLOWED');
END $$;

BEGIN;

-- positive controls: each role reaches what is its own
SELECT pg_temp.expect_allowed('ccure_platform_app','read own: users','SELECT 1 FROM public.users LIMIT 1');
SELECT pg_temp.expect_allowed('ccure_audit_app','read own: scans','SELECT 1 FROM public.scans LIMIT 1');

-- Audit may not read or write the platform's identity or RBAC tables
SELECT pg_temp.expect_refused('ccure_audit_app','read users','SELECT 1 FROM public.users LIMIT 1');
SELECT pg_temp.expect_refused('ccure_audit_app','read rbac_roles','SELECT 1 FROM public.rbac_roles LIMIT 1');
SELECT pg_temp.expect_refused('ccure_audit_app','write rbac_user_roles','DELETE FROM public.rbac_user_roles');
SELECT pg_temp.expect_refused('ccure_audit_app','write audit_logs','DELETE FROM public.audit_logs');

-- The platform may not reach Audit's data
SELECT pg_temp.expect_refused('ccure_platform_app','read scans','SELECT 1 FROM public.scans LIMIT 1');
SELECT pg_temp.expect_refused('ccure_platform_app','read assets','SELECT 1 FROM public.assets LIMIT 1');

-- Policy Pro and Rank: nothing in public, and nothing in each other's schema
SELECT pg_temp.expect_refused('ccure_policy_app','read users','SELECT 1 FROM public.users LIMIT 1');
SELECT pg_temp.expect_refused('ccure_policy_app','read scans','SELECT 1 FROM public.scans LIMIT 1');
SELECT pg_temp.expect_refused('ccure_rank_app','read scans','SELECT 1 FROM public.scans LIMIT 1');
SELECT pg_temp.expect_refused('ccure_policy_app','create in rank','CREATE TABLE rank.intruder(x int)');
SELECT pg_temp.expect_refused('ccure_rank_app','create in policy_pro','CREATE TABLE policy_pro.intruder(x int)');
SELECT pg_temp.expect_refused('ccure_audit_app','create in policy_pro','CREATE TABLE policy_pro.intruder(x int)');

-- No module role may change the schema, the chain or retention machinery
SELECT pg_temp.expect_refused('ccure_audit_app','drop table','DROP TABLE public.scans');
SELECT pg_temp.expect_refused('ccure_platform_app','alter table','ALTER TABLE public.users ADD COLUMN intruder int');
SELECT pg_temp.expect_refused('ccure_audit_app','audit_chain schema','SELECT 1 FROM audit_chain.chain_head LIMIT 1');
SELECT pg_temp.expect_refused('ccure_audit_app','purge function','SELECT audit_retention.purge_legacy_v1(NULL)');

-- Role membership, not SET ROLE: the probes run from a superuser session, which can
-- SET ROLE to anything, so a SET ROLE probe would prove nothing. Check the grants.
INSERT INTO proof
SELECT r, 'is not a member of ' || t, 'NOT MEMBER',
       CASE WHEN pg_has_role(r, t, 'MEMBER') THEN 'MEMBER' ELSE 'NOT MEMBER' END,
       NOT pg_has_role(r, t, 'MEMBER')
FROM unnest(ARRAY['ccure_platform_app','ccure_audit_app','ccure_policy_app','ccure_rank_app']) r,
     unnest(ARRAY['ccure_user','audit_chain_writer','audit_maintenance',
                  'ccure_platform_app','ccure_audit_app','ccure_policy_app','ccure_rank_app']) t
WHERE r <> t;

SELECT role, probe, expected, got FROM proof ORDER BY ok, role, probe;
DO $$
DECLARE bad int;
BEGIN
  SELECT count(*) INTO bad FROM proof WHERE NOT ok;
  IF bad > 0 THEN RAISE EXCEPTION 'isolation NOT proven: % probe(s) behaved differently', bad; END IF;
  RAISE NOTICE 'isolation proven: % probes, all as expected', (SELECT count(*) FROM proof);
END $$;
ROLLBACK;  -- the probes change nothing; nothing here is ever committed

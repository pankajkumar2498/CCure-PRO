-- ===========================================================================
-- bootstrap_chain.sql -- audit-log tamper-evidence chain, privileged objects
-- ===========================================================================
--
-- WHO RUNS THIS
--   A database administrator, once per deployment, as a SUPERUSER:
--
--       psql -h 127.0.0.1 -p 5432 -U postgres -d ccure_test \
--            -v ON_ERROR_STOP=1 -f bootstrap_chain.sql
--
--   ON_ERROR_STOP=1 is not optional. The whole script is one transaction and
--   several steps are guards that RAISE; without it psql would carry on past
--   a refusal and COMMIT a half-built chain.
--
-- WHY IT IS NOT AN ALEMBIC MIGRATION
--   Alembic connects as the application role, which on this deployment is
--   ccure_user. Measured:
--
--       CREATE ROLE probe_chain_writer  -> permission denied to create role
--       ALTER TABLE audit_logs OWNER TO admin
--                                       -> must be able to SET ROLE "admin"
--
--   ccure_user holds neither SUPERUSER nor CREATEROLE, and granting it
--   CREATEROLE would defeat the entire control: from PostgreSQL 16 a
--   CREATEROLE role becomes admin of the roles it creates, so it could
--   SET ROLE audit_chain_writer and write chain heads directly.
--
-- WHAT THIS BUYS, PRECISELY
--   The application role cannot write audit_chain_heads, cannot grant itself
--   the privilege to (it neither owns the table nor belongs to the owning
--   role), and cannot redefine the canonical hash algorithm.
--
--   It does own audit_logs, so it retains the ability to DROP the chain
--   trigger and append unchained rows. That is DETECTED, not prevented: such
--   rows carry a NULL record_hash after genesis and never advance the head,
--   so verify_chain reports both a post-genesis hash gap and an event_count
--   mismatch. Closing that would require moving audit_logs ownership away
--   from ccure_user, which breaks Alembic and the phase-3 hardening, both of
--   which run as ccure_user.
--
--   This is tamper-evidence under normal application-role privileges. It is
--   not absolute immutability, and no in-database control can be.
--
-- RERUN SAFETY
--   Idempotent, and structurally incapable of resetting or reconstructing
--   chain state:
--     * the role, the table and the head rows are never dropped or recreated;
--     * the legacy seed is INSERT ... ON CONFLICT DO NOTHING, so it can never
--       overwrite event_count, last_record_hash or genesis_event_id;
--     * step 5 refuses the whole transaction if the functions in this file no
--       longer reproduce the hashes already stored.
--   Rerunning is also the supported REPAIR path if the trigger was dropped.
-- ===========================================================================

\set ON_ERROR_STOP on

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Freeze audit_logs for the duration.
--
-- SHARE ROW EXCLUSIVE conflicts with the ROW EXCLUSIVE that INSERT takes, so
-- no audit event can be written while this runs. Without it a row inserted
-- between the legacy seed (step 9) and the trigger creation would be legacy
-- but uncounted -- a permanent off-by-N in legacy_event_count that nothing
-- would ever correct.
-- ---------------------------------------------------------------------------
LOCK TABLE public.audit_logs IN SHARE ROW EXCLUSIVE MODE;

-- The application role is derived from the owner of audit_logs rather than
-- hardcoded, so this script cannot be run against a deployment whose app role
-- has a different name and silently protect the wrong account.
SELECT set_config(
    'bootstrap.app_role',
    (SELECT pg_get_userbyid(relowner)
       FROM pg_class WHERE oid = 'public.audit_logs'::regclass),
    true
);

DO $init$ BEGIN
    RAISE NOTICE 'application role detected as: %', current_setting('bootstrap.app_role');
END $init$;

-- ---------------------------------------------------------------------------
-- 1. The writer role. NOLOGIN: nothing ever connects as it; it exists only to
--    own objects and to be the effective user inside SECURITY DEFINER.
--
--    The application role is deliberately NOT granted membership. That is what
--    closes the SET ROLE escape, and it is stronger than WITH SET FALSE.
-- ---------------------------------------------------------------------------
DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_chain_writer') THEN
        CREATE ROLE audit_chain_writer NOLOGIN;
        RAISE NOTICE 'created role audit_chain_writer';
    ELSE
        RAISE NOTICE 'role audit_chain_writer already exists (left alone)';
    END IF;
END $role$;

-- ---------------------------------------------------------------------------
-- 2. The chain head table. One row per organisation.
--
--    Never dropped, never recreated. CREATE TABLE IF NOT EXISTS is the only
--    creation path in this file precisely so that a rerun cannot lose state.
--
--    A per-org head, rather than deriving the tip with ORDER BY created_at:
--    created_at is set client-side in Python, so two events in the same
--    millisecond, or a clock adjustment, make "newest by timestamp"
--    ambiguous. last_event_id is exact. It is also lockable AS DATA, which is
--    what serialises concurrent writers.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.audit_chain_heads (
    org_id             varchar(100) PRIMARY KEY
                       REFERENCES public.organizations(id)
                       ON DELETE CASCADE ON UPDATE CASCADE,
    last_event_id      varchar(200),
    last_record_hash   varchar(64),
    event_count        bigint      NOT NULL DEFAULT 0,
    -- The first cryptographically chained event for this organisation. Makes
    -- the legacy boundary a recorded fact rather than an inference.
    genesis_event_id   varchar(200),
    chain_started_at   timestamptz,
    -- How many pre-chain events this organisation had when the chain was
    -- installed. Those rows are NOT verifiable and must never be reported as
    -- if they were.
    legacy_event_count bigint      NOT NULL DEFAULT 0,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE public.audit_chain_heads IS
    'Per-organisation hash-chain tip. Written only by audit_chain_advance_v1 (SECURITY DEFINER). The application role holds SELECT only.';

ALTER TABLE public.audit_chain_heads OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 3. Privileges on the head table.
--
--    The application role gets SELECT and nothing else. Because it neither
--    owns the table nor belongs to audit_chain_writer, it cannot GRANT the
--    rest back to itself -- which is exactly the weakness the phase-3
--    REVOKE-only approach had, where the owner could re-grant at will.
-- ---------------------------------------------------------------------------
REVOKE ALL ON TABLE public.audit_chain_heads FROM PUBLIC;

-- USAGE on the schema, explicitly.
--
-- This is not optional and must not be left to inheritance. A SECURITY DEFINER
-- function runs as audit_chain_writer, so that role needs USAGE on the schema
-- holding the objects it touches — including the table it owns itself.
--
-- Whether it already has USAGE depends entirely on how the database was
-- created, which is exactly why relying on it is wrong. Measured on this
-- deployment:
--
--   ccure_test       public owned by pg_database_owner,
--                    acl {...,=U/pg_database_owner}  -> USAGE granted to PUBLIC,
--                    so audit_chain_writer inherited it and the seed worked.
--
--   ccure_pytest_db  public owned by ccure_user, acl NULL -> owner only.
--                    audit_chain_writer had no USAGE and the seeding function
--                    failed with:
--                        ERROR: permission denied for schema public
--                        CONTEXT: PL/pgSQL function audit_chain_seed_legacy_v1()
--
-- The first case worked by accident. An installation where the application
-- role owns the public schema is entirely normal, and there the whole chain is
-- inert without this grant.
GRANT USAGE ON SCHEMA public TO audit_chain_writer;

-- Assert it, rather than assume the GRANT above was sufficient. Without this
-- the failure surfaces much later and much less clearly — as
-- `permission denied for schema public` raised from inside a PL/pgSQL function
-- during the legacy seed, which reads as a problem with the seed rather than
-- with a missing schema privilege.
DO $usage$
DECLARE
    schema_owner text;
    app_role     text := current_setting('bootstrap.app_role');
BEGIN
    IF NOT has_schema_privilege('audit_chain_writer', 'public', 'USAGE') THEN
        RAISE EXCEPTION
            'audit_chain_writer does not hold USAGE on schema public even after '
            'GRANT. The SECURITY DEFINER functions run as that role and cannot '
            'reach audit_chain_heads without it. Check the schema owner and its '
            'ACL: SELECT nspowner::regrole, nspacl FROM pg_namespace '
            'WHERE nspname = ''public'';';
    END IF;
    RAISE NOTICE 'audit_chain_writer holds USAGE on schema public';

    -- The boundary has a second, less obvious dependency: **a schema owner can
    -- DROP any object in that schema**, including objects owned by another
    -- role. So if the application role owns the schema holding the chain
    -- objects, it can drop the hash functions and the head table outright —
    -- ownership of those objects by audit_chain_writer does not stop it.
    --
    -- Measured, same cluster, same roles:
    --   ccure_test      public owned by pg_database_owner
    --                   -> DROP FUNCTION audit_record_hash_v1 = must be owner
    --   ccure_pytest_db public owned by ccure_user
    --                   -> DROP FUNCTION audit_record_hash_v1 = ALLOWED
    --
    -- This is reported rather than refused, because it does not make the chain
    -- wrong — hashes are still computed and verified, and tampering with
    -- existing rows is still detected. What it weakens is the guarantee that
    -- the application role cannot *remove* the machinery. Deployments that care
    -- about that must not let the application role own the schema.
    SELECT nspowner::regrole::text INTO schema_owner
      FROM pg_namespace WHERE nspname = 'public';

    IF schema_owner = app_role THEN
        RAISE WARNING
            'schema public is owned by the application role (%). A schema owner '
            'can DROP objects in that schema regardless of who owns them, so '
            'this role can remove the chain functions and head table. The chain '
            'still computes and verifies correctly, but it is NOT protected '
            'against deliberate removal by the application role on this '
            'database. For that guarantee the schema must be owned by another '
            'role (on this cluster, ccure_test uses pg_database_owner).',
            app_role;
    ELSE
        RAISE NOTICE
            'schema public is owned by % (not the application role) — chain '
            'objects are protected from removal by %', schema_owner, app_role;
    END IF;
END $usage$;

DO $grants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('REVOKE ALL ON TABLE public.audit_chain_heads FROM %I', app_role);
    EXECUTE format('GRANT SELECT ON TABLE public.audit_chain_heads TO %I', app_role);
    -- The seeding function reads audit_logs as audit_chain_writer.
    EXECUTE 'GRANT SELECT ON TABLE public.audit_logs TO audit_chain_writer';
END $grants$;

-- ---------------------------------------------------------------------------
-- 4. The canonical serialisation and hash.
--
--    ONE definition, used by both the insert trigger and verify_chain.py.
--    A verifier that reimplemented this in Python would be a second
--    implementation that can drift -- and drift reads as tampering.
--
--    Serialisation rules, each of which exists for a measured reason:
--
--    * Length-prefixed, not delimited. A delimiter-joined string is not
--      injective: ('a|b','c') and ('a','b|c') would hash identically, letting
--      one event be substituted for another. Verified: f('a:b')||f('c') is
--      distinct from f('a')||f('b:c').
--    * NULL emits '~'; empty string emits '0:'. Without this, resource_id
--      NULL and '' collide.
--    * created_at is rendered AT TIME ZONE 'UTC' with to_char and an explicit
--      .US. This is the largest determinism hazard in the whole design:
--      timestamptz::text renders in the session's TimeZone GUC. Measured, the
--      same row renders as
--          2026-08-24 16:03:06.55087+00     (UTC)
--          2026-08-24 21:33:06.55087+05:30  (Asia/Kolkata)
--      so a verifier connecting from a different session would compute
--      different hashes for unmodified rows. .US also forces six digits, so
--      .55087 cannot render differently from .550870.
--    * ip_address uses ::text, which yields the masked form (10.180.6.14/32).
--      host() would strip the mask and collide 10.0.0.1/8 with 10.0.0.1/32.
--    * changes uses jsonb::text, whose output is already canonical -- keys
--      sorted, duplicates removed, whitespace and numerics normalised.
--      Never jsonb_pretty (whitespace) and never a cast through json, which
--      preserves input formatting and duplicate keys verbatim.
--    * convert_to(..., 'UTF8') so client_encoding cannot vary the bytes.
--
--    STABLE rather than IMMUTABLE on the two that call to_char: to_char on a
--    timestamp is itself STABLE in PostgreSQL. The chosen format contains no
--    locale-dependent element, but claiming IMMUTABLE would assert something
--    the catalogue does not support, and STABLE is sufficient here.
--
--    THE FIELD SET IS FIXED AND ORDERED HERE, not derived from the catalogue.
--    ALTER TABLE ADD COLUMN changes attnum ordering, so anything reading
--    to_jsonb(NEW) key order would silently invalidate every historical hash
--    the next time a column is added.
--
--    user_id is DELIBERATELY ABSENT. It is legitimately mutated to NULL when
--    an account is deleted; hashing it would turn every account deletion into
--    a mass tamper alarm for every event that user ever produced. The frozen
--    actor_user_id / actor_username snapshots carry the same forensic value
--    and never change -- which is what makes actor identity hashable at all.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public._audit_field_v1(v text) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, public
AS $fn$
    SELECT CASE WHEN v IS NULL THEN '~'
                ELSE octet_length(v)::text || ':' || v END
$fn$;

CREATE OR REPLACE FUNCTION public.audit_canonical_payload_v1(rec public.audit_logs)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $fn$
    SELECT concat(
        public._audit_field_v1(rec.id),
        public._audit_field_v1(rec.org_id),
        public._audit_field_v1(rec.actor_user_id),
        public._audit_field_v1(rec.actor_username),
        public._audit_field_v1(rec.action),
        public._audit_field_v1(rec.resource_type),
        public._audit_field_v1(rec.resource_id),
        public._audit_field_v1(rec.status),
        public._audit_field_v1(rec.severity),
        public._audit_field_v1(rec.ip_address::text),
        public._audit_field_v1(rec.user_agent),
        public._audit_field_v1(rec.changes::text),
        public._audit_field_v1(rec.request_id),
        public._audit_field_v1(
            to_char(rec.created_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US')
        )
    )
$fn$;

-- prev is length-prefixed too, for the same injectivity reason as every other
-- field: a bare 64-hex prefix concatenated with the payload would be
-- re-parseable in more than one way.
CREATE OR REPLACE FUNCTION public.audit_record_hash_v1(prev text, rec public.audit_logs)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog, public
AS $fn$
    SELECT encode(
        sha256(convert_to(
            public._audit_field_v1(prev) || public.audit_canonical_payload_v1(rec),
            'UTF8'
        )),
        'hex'
    )
$fn$;

ALTER FUNCTION public._audit_field_v1(text)                         OWNER TO audit_chain_writer;
ALTER FUNCTION public.audit_canonical_payload_v1(public.audit_logs) OWNER TO audit_chain_writer;
ALTER FUNCTION public.audit_record_hash_v1(text, public.audit_logs) OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 5. THE RERUN GUARD.
--
--    Behavioural, not textual: it asks whether the functions just installed
--    still reproduce the hashes already stored. That catches any edit to the
--    algorithm -- reordering a field, changing the timestamp format, dropping
--    a length prefix -- which a source-text comparison could miss and which
--    would silently render every historical event unverifiable.
--
--    It fires on genuine tampering too. That is correct: either way a human
--    must look before the chain is re-blessed.
-- ---------------------------------------------------------------------------
DO $guard$
DECLARE
    checked bigint;
    bad     bigint;
BEGIN
    SELECT count(*) INTO checked FROM public.audit_logs WHERE record_hash IS NOT NULL;

    IF checked = 0 THEN
        RAISE NOTICE 'rerun guard: no chained events yet, nothing to reproduce';
        RETURN;
    END IF;

    SELECT count(*) INTO bad
      FROM public.audit_logs a
     WHERE a.record_hash IS NOT NULL
       AND a.record_hash IS DISTINCT FROM public.audit_record_hash_v1(a.prev_hash, a);

    IF bad > 0 THEN
        RAISE EXCEPTION
            'Refusing to bootstrap: the canonical hash functions in this file do not reproduce % of % existing record_hash values. Either the algorithm in this script differs from the one that wrote them (which would make all historical events unverifiable), or those rows have been tampered with. Investigate with verify_chain.py before rerunning. Nothing has been changed.',
            bad, checked;
    END IF;

    RAISE NOTICE 'rerun guard: all % existing chained events still reproduce', checked;
END $guard$;

-- ---------------------------------------------------------------------------
-- 6. Chain advance -- the only thing that ever writes audit_chain_heads.
--
--    SECURITY DEFINER so it runs as audit_chain_writer, the owner, while the
--    application role that fired the trigger holds no write privilege at all.
--
--    search_path is pinned so a caller cannot shadow a table or operator name
--    -- the standard SECURITY DEFINER hijack. lock_timeout is pinned so a
--    blocked chain write fails loudly instead of hanging a request forever;
--    see the second-session prohibition in core/audit.py.
--
--    Lock ordering: lock the head, read it, compute, then advance it, all in
--    the caller's transaction. Writers for the SAME organisation serialise
--    here; writers for other organisations touch different rows and never
--    block. The fork the design exists to prevent --
--        A reads H100, B reads H100, A writes H101, B writes H102
--    -- cannot occur, because B blocks at the FOR UPDATE until A commits.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.audit_chain_advance_v1() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET lock_timeout = '3s'
AS $fn$
DECLARE
    prev_hash_v text;
BEGIN
    SELECT h.last_record_hash
      INTO prev_hash_v
      FROM public.audit_chain_heads h
     WHERE h.org_id = NEW.org_id
       FOR UPDATE;

    IF NOT FOUND THEN
        -- First ever event for this organisation. Two concurrent first events
        -- both find nothing here, so the race is resolved in the database
        -- rather than in an IF branch: the loser's INSERT no-ops, and the
        -- LOCKED RE-READ below blocks until the winner commits and then reads
        -- the winner's head. Without the re-read both transactions would
        -- proceed with prev_hash = NULL and start two separate chains.
        INSERT INTO public.audit_chain_heads (org_id, event_count, legacy_event_count)
        VALUES (NEW.org_id, 0, 0)
        ON CONFLICT (org_id) DO NOTHING;

        SELECT h.last_record_hash
          INTO prev_hash_v
          FROM public.audit_chain_heads h
         WHERE h.org_id = NEW.org_id
           FOR UPDATE;
    END IF;

    -- Unconditional: whatever the client supplied in these columns is
    -- discarded. The chain is computed here or not at all.
    NEW.prev_hash   := prev_hash_v;
    NEW.record_hash := public.audit_record_hash_v1(prev_hash_v, NEW);

    UPDATE public.audit_chain_heads
       SET last_event_id    = NEW.id,
           last_record_hash = NEW.record_hash,
           event_count      = event_count + 1,
           genesis_event_id = COALESCE(genesis_event_id, NEW.id),
           chain_started_at = COALESCE(chain_started_at, now()),
           updated_at       = now()
     WHERE org_id = NEW.org_id;

    RETURN NEW;
END
$fn$;

ALTER FUNCTION public.audit_chain_advance_v1() OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 7. Legacy seed. Records, per organisation, how many events predate the
--    chain -- so "not verified" can be reported as a number rather than
--    inferred.
--
--    ON CONFLICT DO NOTHING is load-bearing: on a rerun this must not touch an
--    existing head row. Overwriting event_count or last_record_hash would
--    break the chain outright.
--
--    Not granted to the application role: only the bootstrap calls it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.audit_chain_seed_legacy_v1() RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $fn$
DECLARE seeded integer;
BEGIN
    INSERT INTO public.audit_chain_heads (org_id, event_count, legacy_event_count)
    SELECT a.org_id, 0, count(*)
      FROM public.audit_logs a
     WHERE a.record_hash IS NULL
     GROUP BY a.org_id
    ON CONFLICT (org_id) DO NOTHING;

    GET DIAGNOSTICS seeded = ROW_COUNT;
    RETURN seeded;
END
$fn$;

ALTER FUNCTION public.audit_chain_seed_legacy_v1() OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 8. Function privileges.
--
--    PostgreSQL grants EXECUTE to PUBLIC on every new function by default --
--    verified on this database against the phase-3 trigger functions -- so
--    these REVOKEs are required, not belt-and-braces.
--
--    The application role gets EXECUTE on the four it legitimately needs
--    (verify_chain.py recomputes hashes; the trigger function must be
--    executable by the role whose statement fires it). It does NOT get
--    audit_chain_seed_legacy_v1.
--
--    EXECUTE on audit_chain_advance_v1 grants nothing on its own: called
--    outside a trigger it errors immediately, and the head table stays
--    unreachable either way.
-- ---------------------------------------------------------------------------
REVOKE ALL ON FUNCTION public._audit_field_v1(text)                         FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_canonical_payload_v1(public.audit_logs) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_record_hash_v1(text, public.audit_logs) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_chain_advance_v1()                      FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_chain_seed_legacy_v1()                  FROM PUBLIC;

DO $fgrants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('GRANT EXECUTE ON FUNCTION public._audit_field_v1(text) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.audit_canonical_payload_v1(public.audit_logs) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.audit_record_hash_v1(text, public.audit_logs) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION public.audit_chain_advance_v1() TO %I', app_role);
END $fgrants$;

-- ---------------------------------------------------------------------------
-- 9. Seed, then arm the trigger. Order matters: seeding first means every
--    pre-chain event is counted as legacy before any new event can be chained.
-- ---------------------------------------------------------------------------
DO $seed$
DECLARE seeded integer;
BEGIN
    seeded := public.audit_chain_seed_legacy_v1();
    RAISE NOTICE 'legacy seed: % new head row(s) created (existing rows untouched)', seeded;
END $seed$;

-- Stateless, so recreating it is safe and is the supported repair path if the
-- trigger was dropped. A row-level trigger on a partitioned parent is cloned
-- to every existing partition and to any partition created later, so one
-- statement covers all eight leaves.
DROP TRIGGER IF EXISTS audit_logs_chain ON public.audit_logs;
CREATE TRIGGER audit_logs_chain
    BEFORE INSERT ON public.audit_logs
    FOR EACH ROW EXECUTE FUNCTION public.audit_chain_advance_v1();

-- ---------------------------------------------------------------------------
-- 10. Report.
-- ---------------------------------------------------------------------------
DO $report$
DECLARE
    app_role text := current_setting('bootstrap.app_role');
    heads    bigint;
    legacy   bigint;
    chained  bigint;
BEGIN
    SELECT count(*), coalesce(sum(legacy_event_count), 0), coalesce(sum(event_count), 0)
      INTO heads, legacy, chained FROM public.audit_chain_heads;
    RAISE NOTICE '--------------------------------------------------------';
    RAISE NOTICE 'audit chain bootstrap complete';
    RAISE NOTICE '  application role      : %', app_role;
    RAISE NOTICE '  chain head rows       : %', heads;
    RAISE NOTICE '  legacy (unverifiable) : %', legacy;
    RAISE NOTICE '  chained events        : %', chained;
    RAISE NOTICE '  trigger armed         : audit_logs_chain';
    RAISE NOTICE ' ';
    RAISE NOTICE 'NEXT: run  python scripts/audit/verify_chain_bootstrap.py';
    RAISE NOTICE 'as the APPLICATION role. Until it passes, the cross-role';
    RAISE NOTICE 'SECURITY DEFINER path is unproven.';
    RAISE NOTICE '--------------------------------------------------------';
END $report$;

COMMIT;

-- ===========================================================================
-- bootstrap_chain.sql -- audit-log tamper-evidence chain, privileged objects
-- ===========================================================================
--
-- WHO RUNS THIS
--   A database administrator, as a SUPERUSER, once per database:
--
--       psql "postgresql://postgres@127.0.0.1:5432/<db>?sslmode=verify-full&sslrootcert=D:/PostgreSQL/18/data/root.crt" \
--            -v ON_ERROR_STOP=1 -f Backend/scripts/audit/bootstrap_chain.sql
--
--   ON_ERROR_STOP=1 is not optional. The whole script is one transaction and
--   several steps are guards that RAISE; without it psql would carry on past
--   a refusal and COMMIT a half-built chain.
--
-- WHY A DBA
--   The chain's security rests on the application role being *unable* to write
--   or remove the chain machinery. That needs a dedicated audit_chain_writer
--   role owning both the objects and the schema that contains them, and
--   ccure_user holds neither SUPERUSER nor CREATEROLE. Measured:
--
--       CREATE ROLE audit_chain_writer -> permission denied to create role
--       ALTER TABLE ... OWNER TO       -> must be able to SET ROLE
--
--   Granting ccure_user CREATEROLE would defeat the control: from PostgreSQL
--   16 a CREATEROLE role becomes admin of the roles it creates and could
--   SET ROLE into the writer. Do not do it.
--
-- WHY A DEDICATED SCHEMA
--   Owning the objects is necessary but NOT sufficient. **A PostgreSQL schema
--   owner may DROP any object in that schema, regardless of who owns the
--   object.** Measured on this cluster, same roles, same objects:
--
--       ccure_test       public owned by pg_database_owner
--                        -> DROP FUNCTION audit_record_hash_v1 = must be owner
--       ccure_pytest_db  public owned by ccure_user
--                        -> DROP FUNCTION audit_record_hash_v1 = ALLOWED
--
--   (ALTER ... RENAME is refused in both -- that one does require object
--   ownership. It is specifically DROP that a schema owner inherits.)
--
--   So the chain machinery lives in its own schema, `audit_chain`, owned by
--   audit_chain_writer. The application role owns nothing there and is a
--   member of no role that does, so it can remove neither the objects nor the
--   schema.
--
--   `public.audit_logs`, its eight partitions, its append-only triggers, and
--   every other application table stay exactly where they are, owned by
--   whoever owns them now. **This script never changes the ownership of
--   audit_logs, of public, or of any application table.**
--
-- WHAT THIS SCRIPT NEVER DOES
--   * It never DROPs the chain trigger. A trigger binds to its function by
--     OID, so `ALTER FUNCTION ... SET SCHEMA` carries the binding across, and
--     `CREATE OR REPLACE` preserves the OID. Verified on a replica: the
--     trigger continued firing through both operations without being touched.
--     There is therefore no instant, even inside the transaction, at which the
--     trigger points at a missing function.
--   * It never DROPs or recreates `audit_chain_heads`. Moving schemas is
--     `ALTER TABLE ... SET SCHEMA`, a catalogue update: rows, event_count,
--     last_record_hash, genesis_event_id and legacy_event_count all survive.
--   * It never recomputes or backfills a hash. Existing `record_hash` and
--     `prev_hash` values are read for verification only.
--   * It never touches `audit_logs` beyond taking a lock and reading it.
--
-- RERUN SAFETY
--   Idempotent by construction, and structurally unable to reset chain state:
--     * the role, the schema, the table and the head rows are never dropped;
--     * every move is guarded on "is it still in public?";
--     * the legacy seed is INSERT ... ON CONFLICT DO NOTHING;
--     * step 8 refuses the whole transaction if the functions in this file no
--       longer reproduce the hashes already stored.
--   Rerunning is also the supported REPAIR path.
-- ===========================================================================

\set ON_ERROR_STOP on

BEGIN;

-- ---------------------------------------------------------------------------
-- 0. Freeze audit_logs for the duration.
--
-- SHARE ROW EXCLUSIVE conflicts with the ROW EXCLUSIVE that INSERT takes, so
-- no audit event can be written while this runs. That matters twice: the
-- legacy seed must see a stable count, and between the table move and the
-- function replacement below a concurrent insert would hit a function whose
-- body still names the old location.
-- ---------------------------------------------------------------------------
LOCK TABLE public.audit_logs IN SHARE ROW EXCLUSIVE MODE;

-- The application role is derived from the owner of audit_logs rather than
-- hardcoded, so this script cannot be pointed at a deployment whose app role
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
--    The application role is deliberately granted NO membership. That is what
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

-- Belt and braces: if a previous administrator granted the application role
-- membership, the entire boundary is decorative. Refuse rather than proceed.
DO $membership$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    IF pg_has_role(app_role, 'audit_chain_writer', 'MEMBER') THEN
        RAISE EXCEPTION
            'The application role (%) is a member of audit_chain_writer. It '
            'could SET ROLE into the owner and write or remove chain state at '
            'will, which makes every other control here meaningless. Revoke '
            'the membership (REVOKE audit_chain_writer FROM %) and rerun.',
            app_role, app_role;
    END IF;
END $membership$;

-- ---------------------------------------------------------------------------
-- 2. The dedicated schema, owned by the writer role.
--
--    AUTHORIZATION is the entire point: the application role must not own this
--    schema, or it could drop everything inside it regardless of object
--    ownership.
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS audit_chain AUTHORIZATION audit_chain_writer;

-- If the schema already existed under different ownership, correct it. This is
-- the one ownership change the script makes, and it applies only to the
-- audit_chain schema it created for this purpose.
ALTER SCHEMA audit_chain OWNER TO audit_chain_writer;

COMMENT ON SCHEMA audit_chain IS
    'Audit tamper-evidence chain machinery. Owned by audit_chain_writer so the application role can neither modify nor remove it. Application tables stay in public.';

REVOKE ALL ON SCHEMA audit_chain FROM PUBLIC;

DO $schema_grants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    -- USAGE only: resolve and call, never create or drop.
    EXECUTE format('GRANT USAGE ON SCHEMA audit_chain TO %I', app_role);
    -- The writer role reads audit_logs from inside SECURITY DEFINER.
    EXECUTE 'GRANT USAGE ON SCHEMA public TO audit_chain_writer';
    EXECUTE 'GRANT SELECT ON TABLE public.audit_logs TO audit_chain_writer';
END $schema_grants$;

DO $ownercheck$
DECLARE owner_name text;
BEGIN
    SELECT nspowner::regrole::text INTO owner_name
      FROM pg_namespace WHERE nspname = 'audit_chain';
    IF owner_name <> 'audit_chain_writer' THEN
        RAISE EXCEPTION
            'schema audit_chain is owned by % rather than audit_chain_writer; '
            'a schema owner can drop objects it does not own, so the boundary '
            'would not hold', owner_name;
    END IF;
    IF owner_name = current_setting('bootstrap.app_role') THEN
        RAISE EXCEPTION 'schema audit_chain must not be owned by the application role';
    END IF;
    RAISE NOTICE 'schema audit_chain owned by audit_chain_writer';
END $ownercheck$;

-- ---------------------------------------------------------------------------
-- 3. MOVE existing chain objects out of public, if they are still there.
--
--    This is the one-time migration path for a database bootstrapped before
--    the dedicated schema existed. Each move is guarded on the object still
--    being in public, so a rerun is a no-op.
--
--    ALTER FUNCTION ... SET SCHEMA is used rather than drop-and-recreate
--    precisely because the chain trigger binds to the function by OID: moving
--    it carries the binding, so `audit_logs_chain` keeps working and is never
--    touched by this script.
--
--    ALTER TABLE ... SET SCHEMA is a catalogue update. Rows are not copied,
--    not rewritten and not reconstructed -- event_count, last_record_hash,
--    genesis_event_id and legacy_event_count all move exactly as they are.
-- ---------------------------------------------------------------------------
DO $move$
DECLARE
    moved int := 0;
    sig   text;
BEGIN
    FOREACH sig IN ARRAY ARRAY[
        'public._audit_field_v1(text)',
        'public.audit_canonical_payload_v1(public.audit_logs)',
        'public.audit_record_hash_v1(text, public.audit_logs)',
        'public.audit_chain_advance_v1()',
        'public.audit_chain_seed_legacy_v1()'
    ] LOOP
        -- Nested block: `CAST(... AS regprocedure)` raises undefined_function
        -- when the function is not in public, which is both the fresh-install
        -- case and the already-migrated case. A LOOP cannot carry an EXCEPTION
        -- clause of its own, so the handler needs its own BEGIN/END.
        BEGIN
            EXECUTE format('ALTER FUNCTION %s SET SCHEMA audit_chain', sig);
            moved := moved + 1;
        EXCEPTION
            WHEN undefined_function THEN
                NULL;   -- not in public: nothing to move
        END;
    END LOOP;

    IF to_regclass('public.audit_chain_heads') IS NOT NULL THEN
        ALTER TABLE public.audit_chain_heads SET SCHEMA audit_chain;
        RAISE NOTICE 'moved audit_chain_heads from public to audit_chain '
                     '(catalogue update -- no rows copied, nothing recomputed)';
    END IF;

    IF moved > 0 THEN
        RAISE NOTICE 'moved % chain function(s) from public to audit_chain '
                     '(trigger binding follows the function OID)', moved;
    END IF;
END $move$;

-- ---------------------------------------------------------------------------
-- 4. The chain head table. One row per organisation.
--
--    CREATE TABLE IF NOT EXISTS is the only creation path in this file, so a
--    rerun -- or a run after the move above -- cannot lose state.
--
--    A per-org head, rather than deriving the tip with ORDER BY created_at:
--    created_at is set client-side in Python, so two events in the same
--    millisecond, or a clock adjustment, make "newest by timestamp"
--    ambiguous. last_event_id is exact. It is also lockable AS DATA, which is
--    what serialises concurrent writers.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_chain.audit_chain_heads (
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

COMMENT ON TABLE audit_chain.audit_chain_heads IS
    'Per-organisation hash-chain tip. Written only by audit_chain.audit_chain_advance_v1 (SECURITY DEFINER). The application role holds SELECT only and cannot drop it: this schema is owned by audit_chain_writer.';

ALTER TABLE audit_chain.audit_chain_heads OWNER TO audit_chain_writer;

REVOKE ALL ON TABLE audit_chain.audit_chain_heads FROM PUBLIC;

DO $table_grants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('REVOKE ALL ON TABLE audit_chain.audit_chain_heads FROM %I', app_role);
    EXECUTE format('GRANT SELECT ON TABLE audit_chain.audit_chain_heads TO %I', app_role);
END $table_grants$;

-- ---------------------------------------------------------------------------
-- 5. The canonical serialisation and hash.
--
--    ONE definition, used by both the insert trigger and verify_chain.py. A
--    verifier that reimplemented this in Python would be a second definition
--    that can drift -- and drift reads as tampering.
--
--    **Every reference below is fully schema-qualified.** search_path is set
--    as well, but it is defence in depth, not the boundary: the application
--    role owns `public` on some databases and could create a shadow
--    `public.audit_chain_heads`. Qualification is what makes that shadow
--    irrelevant. Verified on a replica: with the real table in audit_chain and
--    a shadow created in public, inserts continued to advance the real chain
--    and the shadow stayed empty.
--
--    Serialisation rules, each for a measured reason:
--
--    * Length-prefixed, not delimited. A delimiter-joined string is not
--      injective: ('a|b','c') and ('a','b|c') would hash identically, letting
--      one event be substituted for another.
--    * NULL emits '~'; empty string emits '0:'. Without this, resource_id
--      NULL and '' collide.
--    * created_at is rendered AT TIME ZONE 'UTC' with to_char and an explicit
--      .US. timestamptz::text renders in the session's TimeZone GUC -- the
--      same row renders as 2026-08-24 16:03:06.55087+00 under UTC and
--      2026-08-24 21:33:06.55087+05:30 under Asia/Kolkata -- so a verifier
--      connecting from a different session would compute different hashes for
--      completely unmodified rows. .US forces six digits.
--    * ip_address uses ::text, which yields the masked form (10.180.6.14/32).
--      host() would strip the mask and collide 10.0.0.1/8 with 10.0.0.1/32.
--    * changes uses jsonb::text. JSONB normalises on input -- note that it
--      orders keys by LENGTH then bytewise, not alphabetically, so
--      {"alpha":1,"beta":2} normalises to {"beta": 2, "alpha": 1}. That is
--      still canonical, which is all this depends on. Never jsonb_pretty
--      (whitespace) and never a cast through json, which preserves input
--      formatting and duplicate keys verbatim.
--    * convert_to(..., 'UTF8') so client_encoding cannot vary the bytes.
--
--    STABLE rather than IMMUTABLE on the two that call to_char: to_char on a
--    timestamp is itself STABLE in PostgreSQL.
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
--    and never change.
--
--    CREATE OR REPLACE, never DROP + CREATE: it preserves the function OID, so
--    the chain trigger's binding survives untouched.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain._audit_field_v1(v text) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, audit_chain, public
AS $fn$
    SELECT CASE WHEN v IS NULL THEN '~'
                ELSE octet_length(v)::text || ':' || v END
$fn$;

CREATE OR REPLACE FUNCTION audit_chain.audit_canonical_payload_v1(rec public.audit_logs)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog, audit_chain, public
AS $fn$
    SELECT concat(
        audit_chain._audit_field_v1(rec.id),
        audit_chain._audit_field_v1(rec.org_id),
        audit_chain._audit_field_v1(rec.actor_user_id),
        audit_chain._audit_field_v1(rec.actor_username),
        audit_chain._audit_field_v1(rec.action),
        audit_chain._audit_field_v1(rec.resource_type),
        audit_chain._audit_field_v1(rec.resource_id),
        audit_chain._audit_field_v1(rec.status),
        audit_chain._audit_field_v1(rec.severity),
        audit_chain._audit_field_v1(rec.ip_address::text),
        audit_chain._audit_field_v1(rec.user_agent),
        audit_chain._audit_field_v1(rec.changes::text),
        audit_chain._audit_field_v1(rec.request_id),
        audit_chain._audit_field_v1(
            to_char(rec.created_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US')
        )
    )
$fn$;

-- prev is length-prefixed too, for the same injectivity reason as every other
-- field: a bare 64-hex prefix concatenated with the payload would be
-- re-parseable in more than one way.
CREATE OR REPLACE FUNCTION audit_chain.audit_record_hash_v1(prev text, rec public.audit_logs)
RETURNS text
LANGUAGE sql STABLE
SET search_path = pg_catalog, audit_chain, public
AS $fn$
    SELECT encode(
        sha256(convert_to(
            audit_chain._audit_field_v1(prev)
              || audit_chain.audit_canonical_payload_v1(rec),
            'UTF8'
        )),
        'hex'
    )
$fn$;

ALTER FUNCTION audit_chain._audit_field_v1(text)                         OWNER TO audit_chain_writer;
ALTER FUNCTION audit_chain.audit_canonical_payload_v1(public.audit_logs) OWNER TO audit_chain_writer;
ALTER FUNCTION audit_chain.audit_record_hash_v1(text, public.audit_logs) OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 6. Chain advance -- the only thing that ever writes audit_chain_heads.
--
--    SECURITY DEFINER so it runs as audit_chain_writer, the owner, while the
--    application role that fired the trigger holds no write privilege at all.
--
--    search_path is pinned so a caller cannot shadow a name -- the standard
--    SECURITY DEFINER hijack -- and every reference is qualified anyway.
--    lock_timeout is pinned so a blocked chain write fails loudly instead of
--    hanging a request forever; see the second-session prohibition in
--    core/audit.py.
--
--    Lock ordering: lock the head, read it, compute, then advance it, all in
--    the caller's transaction. Writers for the SAME organisation serialise
--    here; writers for other organisations touch different rows and never
--    block. The fork this exists to prevent --
--        A reads H100, B reads H100, A writes H101, B writes H102
--    -- cannot occur, because B blocks at the FOR UPDATE until A commits.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain.audit_chain_advance_v1() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_chain, public
SET lock_timeout = '3s'
AS $fn$
DECLARE
    prev_hash_v text;
BEGIN
    SELECT h.last_record_hash
      INTO prev_hash_v
      FROM audit_chain.audit_chain_heads h
     WHERE h.org_id = NEW.org_id
       FOR UPDATE;

    IF NOT FOUND THEN
        -- First ever event for this organisation. Two concurrent first events
        -- both find nothing here, so the race is resolved in the database
        -- rather than in an IF branch: the loser's INSERT no-ops, and the
        -- LOCKED RE-READ below blocks until the winner commits and then reads
        -- the winner's head. Without the re-read both transactions would
        -- proceed with prev_hash = NULL and start two separate chains.
        INSERT INTO audit_chain.audit_chain_heads (org_id, event_count, legacy_event_count)
        VALUES (NEW.org_id, 0, 0)
        ON CONFLICT (org_id) DO NOTHING;

        SELECT h.last_record_hash
          INTO prev_hash_v
          FROM audit_chain.audit_chain_heads h
         WHERE h.org_id = NEW.org_id
           FOR UPDATE;
    END IF;

    -- Unconditional: whatever the client supplied in these columns is
    -- discarded. The chain is computed here or not at all.
    NEW.prev_hash   := prev_hash_v;
    NEW.record_hash := audit_chain.audit_record_hash_v1(prev_hash_v, NEW);

    UPDATE audit_chain.audit_chain_heads
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

ALTER FUNCTION audit_chain.audit_chain_advance_v1() OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 7. Legacy seed. Records, per organisation, how many events predate the
--    chain -- so "not verified" is a number rather than an inference.
--
--    ON CONFLICT DO NOTHING is load-bearing: on a rerun this must not touch an
--    existing head row. Overwriting event_count or last_record_hash would
--    break the chain outright.
--
--    Not granted to the application role: only the bootstrap calls it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain.audit_chain_seed_legacy_v1() RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_chain, public
AS $fn$
DECLARE seeded integer;
BEGIN
    INSERT INTO audit_chain.audit_chain_heads (org_id, event_count, legacy_event_count)
    SELECT a.org_id, 0, count(*)
      FROM public.audit_logs a
     WHERE a.record_hash IS NULL
     GROUP BY a.org_id
    ON CONFLICT (org_id) DO NOTHING;

    GET DIAGNOSTICS seeded = ROW_COUNT;
    RETURN seeded;
END
$fn$;

ALTER FUNCTION audit_chain.audit_chain_seed_legacy_v1() OWNER TO audit_chain_writer;

-- ---------------------------------------------------------------------------
-- 8. THE RERUN / MOVE GUARD.
--
--    Behavioural, not textual: it asks whether the functions now installed
--    still reproduce the hashes already stored. That catches any edit to the
--    algorithm -- reordering a field, changing the timestamp format, dropping
--    a length prefix -- and, critically for this revision, it proves the
--    schema move did not disturb a single byte of the existing chain.
--
--    It fires on genuine tampering too. Either way a human must look before
--    the chain is re-blessed. The whole transaction rolls back, so a failure
--    leaves the database exactly as it was, chain objects included.
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
       AND a.record_hash IS DISTINCT FROM
           audit_chain.audit_record_hash_v1(a.prev_hash, a);

    IF bad > 0 THEN
        RAISE EXCEPTION
            'Refusing to bootstrap: the canonical hash functions do not reproduce % of % existing record_hash values. Either the algorithm differs from the one that wrote them, or those rows have been tampered with, or the schema move disturbed the data. Investigate with verify_chain.py. The transaction is rolled back and nothing has changed.',
            bad, checked;
    END IF;

    RAISE NOTICE 'rerun guard: all % existing chained events still reproduce '
                 'byte-for-byte after the move', checked;
END $guard$;

-- ---------------------------------------------------------------------------
-- 9. Function privileges.
--
--    PostgreSQL grants EXECUTE to PUBLIC on every new function by default --
--    verified on this database -- so these REVOKEs are required, not
--    defensive. CREATE OR REPLACE above does not reset them, but they are
--    re-applied unconditionally so a rerun repairs a hand-edited grant.
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
REVOKE ALL ON FUNCTION audit_chain._audit_field_v1(text)                         FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_chain.audit_canonical_payload_v1(public.audit_logs) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_chain.audit_record_hash_v1(text, public.audit_logs) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_chain.audit_chain_advance_v1()                      FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_chain.audit_chain_seed_legacy_v1()                  FROM PUBLIC;

DO $fgrants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_chain._audit_field_v1(text) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_chain.audit_canonical_payload_v1(public.audit_logs) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_chain.audit_record_hash_v1(text, public.audit_logs) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_chain.audit_chain_advance_v1() TO %I', app_role);
    -- audit_chain_seed_legacy_v1 is deliberately omitted.
END $fgrants$;

-- ---------------------------------------------------------------------------
-- 10. Seed legacy counts, then make sure the trigger exists.
--
--     Seeding first means every pre-chain event is counted as legacy before
--     any new event can be chained.
-- ---------------------------------------------------------------------------
DO $seed$
DECLARE seeded integer;
BEGIN
    seeded := audit_chain.audit_chain_seed_legacy_v1();
    RAISE NOTICE 'legacy seed: % new head row(s) created (existing rows untouched)', seeded;
END $seed$;

-- The trigger is created ONLY if it does not already exist.
--
-- On a database bootstrapped before this revision the trigger is already
-- present and, because ALTER FUNCTION ... SET SCHEMA carried its binding, it
-- already points at audit_chain.audit_chain_advance_v1. Dropping and
-- recreating it would be pointless churn on a live audit table, and would
-- momentarily -- even if only within this transaction -- leave audit_logs
-- without chain enforcement. It is left strictly alone.
--
-- A row-level trigger on a partitioned parent is cloned to every existing
-- partition and to any partition created later, so one statement covers all
-- eight leaves.
DO $trigger$
DECLARE points_at text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_chain') THEN
        CREATE TRIGGER audit_logs_chain
            BEFORE INSERT ON public.audit_logs
            FOR EACH ROW EXECUTE FUNCTION audit_chain.audit_chain_advance_v1();
        RAISE NOTICE 'created trigger audit_logs_chain';
    ELSE
        SELECT n.nspname || '.' || p.proname INTO points_at
          FROM pg_trigger t
          JOIN pg_proc p ON p.oid = t.tgfoid
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE t.tgname = 'audit_logs_chain'
         LIMIT 1;
        RAISE NOTICE 'trigger audit_logs_chain already present, left untouched '
                     '(points at %)', points_at;
        IF points_at <> 'audit_chain.audit_chain_advance_v1' THEN
            RAISE EXCEPTION
                'trigger audit_logs_chain points at % rather than '
                'audit_chain.audit_chain_advance_v1. The function move did not '
                'carry the binding as expected; refusing to continue.', points_at;
        END IF;
    END IF;
END $trigger$;

-- ---------------------------------------------------------------------------
-- 11. Assert nothing was left behind in public.
--
--     A stale copy would be harmless to the chain (every reference is
--     qualified) but confusing to a reviewer, and a stale *function* in public
--     could still be executed by anyone holding EXECUTE on it.
-- ---------------------------------------------------------------------------
DO $residue$
DECLARE leftovers text;
BEGIN
    SELECT string_agg(name, ', ') INTO leftovers FROM (
        SELECT 'table public.audit_chain_heads' AS name
         WHERE to_regclass('public.audit_chain_heads') IS NOT NULL
        UNION ALL
        SELECT 'function public.' || p.proname
          FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND p.proname IN ('_audit_field_v1', 'audit_canonical_payload_v1',
                             'audit_record_hash_v1', 'audit_chain_advance_v1',
                             'audit_chain_seed_legacy_v1')
    ) AS x;

    IF leftovers IS NOT NULL THEN
        RAISE WARNING
            'chain objects still present in public after the move: %. The real '
            'chain in audit_chain is authoritative and every reference is '
            'schema-qualified, so these are inert -- but they should be removed '
            'by hand once verified.', leftovers;
    ELSE
        RAISE NOTICE 'no chain objects remain in schema public';
    END IF;
END $residue$;

-- ---------------------------------------------------------------------------
-- 12. Report.
-- ---------------------------------------------------------------------------
DO $report$
DECLARE
    app_role  text := current_setting('bootstrap.app_role');
    heads     bigint;
    legacy    bigint;
    chained   bigint;
    can_drop  boolean;
BEGIN
    SELECT count(*), coalesce(sum(legacy_event_count), 0), coalesce(sum(event_count), 0)
      INTO heads, legacy, chained FROM audit_chain.audit_chain_heads;

    -- The property this revision exists to establish, stated from the
    -- catalogue rather than assumed.
    SELECT nspowner::regrole::text = app_role INTO can_drop
      FROM pg_namespace WHERE nspname = 'audit_chain';

    RAISE NOTICE '--------------------------------------------------------';
    RAISE NOTICE 'audit chain bootstrap complete';
    RAISE NOTICE '  application role      : %', app_role;
    RAISE NOTICE '  chain schema          : audit_chain (owner audit_chain_writer)';
    RAISE NOTICE '  chain head rows       : %', heads;
    RAISE NOTICE '  legacy (unverifiable) : %', legacy;
    RAISE NOTICE '  chained events        : %', chained;
    RAISE NOTICE '  app role can remove   : %', CASE WHEN can_drop THEN 'YES -- BOUNDARY NOT HELD' ELSE 'no' END;
    RAISE NOTICE ' ';
    RAISE NOTICE 'NEXT: run  python scripts/audit/verify_chain_bootstrap.py';
    RAISE NOTICE 'as the APPLICATION role. Until it passes, the cross-role';
    RAISE NOTICE 'SECURITY DEFINER path and the removal-resistance property';
    RAISE NOTICE 'are unproven.';
    RAISE NOTICE '--------------------------------------------------------';
END $report$;

COMMIT;

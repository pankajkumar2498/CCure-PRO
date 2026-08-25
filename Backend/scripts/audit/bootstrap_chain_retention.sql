-- ===========================================================================
-- scripts/audit/bootstrap_chain_retention.sql
-- ---------------------------------------------------------------------------
-- Phase 6a. The privileged half of audit-log retention: the role, the schema,
-- the anchor and hold tables, and the one function permitted to delete an
-- audit row.
--
-- Run as a SUPERUSER, once per database:
--
--     psql -v ON_ERROR_STOP=1 \
--          -v app_role=ccure_user \
--          -d <database> \
--          -f Backend/scripts/audit/bootstrap_chain_retention.sql
--
-- Then verify:
--
--     docker exec ccure-api python scripts/audit/verify_retention_bootstrap.py
--
-- **No credential appears in this file** and none should be added. The
-- connection is the DBA's own; `app_role` is a role NAME, not a secret.
--
-- ---------------------------------------------------------------------------
-- What this establishes, and why each part is where it is
-- ---------------------------------------------------------------------------
--
-- **A dedicated `audit_maintenance` role, never `audit_chain_writer`.**
-- Separation of duties: one role computes hashes and owns the chain, a
-- different one is permitted to delete audit rows. Collapsing them would mean
-- the role that decides what a row's hash is could also make the row go away.
--
-- **A dedicated `audit_retention` schema owned by that role.** A PostgreSQL
-- schema owner may DROP any object in the schema regardless of who owns the
-- object -- the finding that drove the phase-4 schema move. The application
-- role therefore must not own the schema holding the purge function, or it
-- could remove the very thing that constrains it. `audit_chain` is owned by
-- `audit_chain_writer` and is deliberately left alone here.
--
-- **The function is the boundary; the trigger is defence in depth.** The
-- application role may EXECUTE `purge_legacy_v1` -- the Celery task has to be
-- able to call it -- but cannot alter what it does, cannot drop it, and cannot
-- become `audit_maintenance`. Every precondition lives inside the function,
-- where the caller cannot reach it.
--
-- **The 6a scope limit is a database constraint, not a convention.** The
-- append-only trigger permits a maintenance DELETE only when
-- `OLD.record_hash IS NULL`. During phase 6a the maintenance role cannot
-- delete a chained row even through this function, even if the function's own
-- predicate were wrong.
--
-- **What a legacy anchor is and is not.** Rows with no `record_hash` have no
-- cryptographic continuity to preserve: `prev_hash` references a `record_hash`
-- value, and a legacy row has none, so nothing can ever link to one. A legacy
-- anchor is therefore an ACCOUNTING RECORD of what was removed -- organisation,
-- range, count, resulting head state -- and **not** continuity evidence, and
-- **not** a copy of the deleted events. It preserves no audit content
-- whatsoever. It exists in 6a so the anchor machinery is exercised on the half
-- of the problem where a mistake cannot break a chain, before phase 6b makes
-- anchors load-bearing for chained rows.
--
-- ---------------------------------------------------------------------------
-- Idempotence and rerun safety
-- ---------------------------------------------------------------------------
-- Every object is created with IF NOT EXISTS or CREATE OR REPLACE. **There is
-- not one DROP statement in this file.** A rerun must never remove an anchor
-- or a hold: an anchor is the only record that a purge happened, and a hold is
-- somebody's instruction not to delete. The whole file is one transaction, so
-- a failure part-way leaves nothing behind.
-- ===========================================================================

\set ON_ERROR_STOP on
\if :{?app_role}
\else
  \set app_role ccure_user
\endif

BEGIN;

SELECT set_config('bootstrap.app_role', :'app_role', false);

-- ---------------------------------------------------------------------------
-- 0. Refuse to run unless the caller can actually complete the job.
--
--    A partial bootstrap is worse than none: the Python layer decides whether
--    retention is installed by looking for the function, so a run that created
--    the role and stopped would leave a database that reports "not installed"
--    while carrying half the objects.
-- ---------------------------------------------------------------------------
DO $preconditions$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION
            'bootstrap_chain_retention.sql must be run by a superuser; '
            'current_user is %', current_user
            USING HINT = 'psql -U postgres -v ON_ERROR_STOP=1 -f ...';
    END IF;

    IF to_regclass('public.audit_logs') IS NULL THEN
        RAISE EXCEPTION 'public.audit_logs does not exist; run the application '
                        'migrations before bootstrapping retention';
    END IF;

    -- Phase 4 must already be in place. Retention reads and adjusts the chain
    -- head, and a database with no chain has no head to adjust.
    IF to_regclass('audit_chain.audit_chain_heads') IS NULL THEN
        RAISE EXCEPTION
            'audit_chain.audit_chain_heads does not exist: phase 4 has not been '
            'bootstrapped in this database'
            USING HINT = 'Run bootstrap_chain.sql first.';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_setting('bootstrap.app_role')) THEN
        RAISE EXCEPTION 'application role % does not exist',
                        current_setting('bootstrap.app_role');
    END IF;
END $preconditions$;

-- ---------------------------------------------------------------------------
-- 1. Behavioural rerun guard.
--
--    Modelled on bootstrap_chain.sql's. If retention is already installed and
--    anchors exist, this run must be a no-op on that state -- it must not be
--    able to reset a counter or re-point a grant in a way that changes what
--    already happened. Everything below is additive, so the guard checks the
--    one thing that would indicate otherwise: an anchor table that exists but
--    is not owned by the maintenance role, which would mean something else
--    created it.
-- ---------------------------------------------------------------------------
DO $rerun_guard$
DECLARE
    owner_now text;
BEGIN
    IF to_regclass('audit_retention.retention_anchors') IS NOT NULL THEN
        SELECT pg_get_userbyid(relowner) INTO owner_now
          FROM pg_class WHERE oid = 'audit_retention.retention_anchors'::regclass;

        IF owner_now <> 'audit_maintenance' THEN
            RAISE EXCEPTION
                'Refusing to bootstrap: audit_retention.retention_anchors exists '
                'but is owned by %, not audit_maintenance. Investigate before '
                'proceeding -- this is not a state this script creates.',
                owner_now;
        END IF;
    END IF;
END $rerun_guard$;

-- ---------------------------------------------------------------------------
-- 2. The maintenance role.
--
--    NOLOGIN: nothing ever connects as this role. It exists to own the purge
--    function and to be what `current_user` reports inside it, which is what
--    the append-only trigger keys on. A role that could log in would be a
--    credential to steal for no benefit.
--
--    NOINHERIT and no membership granted to anyone. The application role must
--    not be able to SET ROLE to this.
-- ---------------------------------------------------------------------------
DO $role$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_maintenance') THEN
        CREATE ROLE audit_maintenance NOLOGIN NOINHERIT;
        RAISE NOTICE 'created role audit_maintenance (NOLOGIN)';
    ELSE
        RAISE NOTICE 'role audit_maintenance already exists';
    END IF;
END $role$;

-- Assert the separation the design depends on. If the application role is a
-- member of audit_maintenance -- granted by hand at some point, perhaps to
-- make something work -- the entire privilege boundary is gone, and it would
-- be gone silently.
DO $separation$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    IF pg_has_role(app_role, 'audit_maintenance', 'MEMBER') THEN
        RAISE EXCEPTION
            'Refusing to bootstrap: % is a member of audit_maintenance. The '
            'purge function would then be callable with the application role''s '
            'own privileges and the boundary would not exist.', app_role
            USING HINT = 'REVOKE audit_maintenance FROM ' || app_role;
    END IF;

    IF pg_has_role('audit_maintenance', 'audit_chain_writer', 'MEMBER')
       OR pg_has_role('audit_chain_writer', 'audit_maintenance', 'MEMBER') THEN
        RAISE EXCEPTION
            'Refusing to bootstrap: audit_maintenance and audit_chain_writer are '
            'members of one another. They must stay separate roles.';
    END IF;
END $separation$;

-- ---------------------------------------------------------------------------
-- 3. The retention schema, owned by the maintenance role.
-- ---------------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS audit_retention AUTHORIZATION audit_maintenance;

COMMENT ON SCHEMA audit_retention IS
    'Phase 6a audit retention. Owned by audit_maintenance so the application '
    'role cannot drop the objects that constrain it -- a schema owner may drop '
    'any object in the schema regardless of who owns the object.';

-- USAGE only. The application role may reach into the schema to call the
-- function and read the tables; it may not create anything here.
DO $schema_grants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('REVOKE ALL ON SCHEMA audit_retention FROM PUBLIC');
    EXECUTE format('GRANT USAGE ON SCHEMA audit_retention TO %I', app_role);
END $schema_grants$;

-- The maintenance role must be able to read `public` to evaluate its own
-- predicates. Granted explicitly rather than relying on USAGE having been
-- granted to PUBLIC, which is true on some databases here and not others.
GRANT USAGE ON SCHEMA public TO audit_maintenance;

-- USAGE on audit_chain, and USAGE only. It is what lets the purge function
-- *reach* the two chain functions below; it grants nothing on the head table.
--
-- Without this, an EXECUTE grant on a function in that schema reports true from
-- `has_function_privilege` and is unusable in practice — the call fails with
-- "permission denied for schema audit_chain". That is the same shape as the
-- GRANT-without-grant-option trap the phase-4 verifier documents: metadata that
-- says yes over a path that does not work.
GRANT USAGE ON SCHEMA audit_chain TO audit_maintenance;

-- Stated as an assertion rather than left implicit. `audit_maintenance` must
-- never hold a write privilege on the chain head: with one it could rewrite
-- `last_record_hash` — a chain tip — which is the single thing this whole
-- separation of roles exists to prevent.
DO $head_privileges$
BEGIN
    IF has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'INSERT')
    OR has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'UPDATE')
    OR has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'DELETE')
    OR has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'TRUNCATE')
    THEN
        RAISE EXCEPTION
            'Refusing to bootstrap: audit_maintenance holds a write privilege on '
            'audit_chain.audit_chain_heads. Retention must reach the head only '
            'through the SECURITY DEFINER functions owned by audit_chain_writer.';
    END IF;
END $head_privileges$;

-- ---------------------------------------------------------------------------
-- 4. Anchors. One row per (organisation, purge transaction), append-only.
--
--    Written INSIDE the same transaction as the delete and BEFORE it, so an
--    anchor without its deletion is impossible and a deletion without its
--    anchor is impossible.
--
--    Read the column comments carefully before using this table as evidence:
--    for kind='legacy' the hash columns are NULL and there is nothing to
--    verify. See the header.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_retention.retention_anchors (
    id                          bigserial PRIMARY KEY,
    org_id                      varchar(100) NOT NULL,
    -- 'legacy'  : rows with no record_hash. No continuity evidence exists or
    --             is needed; nothing could ever have linked to them.
    -- 'chained' : phase 6b. Not written by this phase.
    kind                        varchar(16)  NOT NULL
                                CHECK (kind IN ('legacy', 'chained')),
    purge_started_at            timestamptz  NOT NULL,
    purge_completed_at          timestamptz  NOT NULL DEFAULT now(),
    cutoff                      timestamptz  NOT NULL,
    range_from                  timestamptz,
    range_to                    timestamptz,
    deleted_count               bigint       NOT NULL,
    last_deleted_event_id       varchar(200),
    -- NULL for kind='legacy', necessarily: a legacy row has no record_hash.
    -- This is the column that would carry continuity evidence in 6b.
    last_deleted_record_hash    varchar(64),
    first_surviving_event_id    varchar(200),
    first_surviving_record_hash varchar(64),
    head_event_count_after      bigint,
    head_legacy_count_after     bigint,
    head_genesis_after          varchar(200),
    head_tip_after              varchar(200),
    operator_db_user            text         NOT NULL DEFAULT session_user,
    operator_identity           text,
    audit_event_id              varchar(200),
    -- Phase 6b makes this NOT NULL for kind='chained': the verified export
    -- that is the archival evidence for the deleted rows. Deliberately unused
    -- and NULL in 6a, because a legacy row carries nothing an export could
    -- verify.
    archive_artifact            jsonb,
    backup_reference            text
);

COMMENT ON TABLE audit_retention.retention_anchors IS
    'Append-only record of every retention purge. For kind=''legacy'' this is '
    'an ACCOUNTING record only: legacy rows carry no record_hash, so the anchor '
    'provides no cryptographic continuity evidence and preserves no deleted '
    'audit content. Phase 6b introduces kind=''chained'', where the anchor does '
    'carry continuity evidence and an archive artefact is mandatory.';

COMMENT ON COLUMN audit_retention.retention_anchors.last_deleted_record_hash IS
    'Always NULL for kind=''legacy'' -- such rows have no hash. Continuity '
    'evidence for kind=''chained'' in phase 6b.';

CREATE INDEX IF NOT EXISTS ix_retention_anchors_org
    ON audit_retention.retention_anchors (org_id, purge_completed_at DESC);

ALTER TABLE audit_retention.retention_anchors OWNER TO audit_maintenance;

-- ---------------------------------------------------------------------------
-- 5. Holds. A tenant under legal or investigative hold is never purged.
--
--    Append-only in the same sense the audit trail is: a hold is RELEASED by
--    setting released_at, never by deleting the row. The record that a hold
--    existed is itself evidence, and deleting it would erase the reason a
--    purge did not happen.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_retention.retention_holds (
    id           bigserial PRIMARY KEY,
    org_id       varchar(100) NOT NULL,
    reason       text         NOT NULL,
    placed_by    varchar(200) NOT NULL,
    placed_at    timestamptz  NOT NULL DEFAULT now(),
    released_by  varchar(200),
    released_at  timestamptz,
    CONSTRAINT retention_hold_release_is_complete
        CHECK ((released_at IS NULL) = (released_by IS NULL))
);

COMMENT ON TABLE audit_retention.retention_holds IS
    'Organisations that must never be purged. Released by setting released_at, '
    'never by DELETE: the record that a hold existed is why a purge did not '
    'happen, and is itself evidence.';

CREATE UNIQUE INDEX IF NOT EXISTS ux_retention_holds_active
    ON audit_retention.retention_holds (org_id)
    WHERE released_at IS NULL;

ALTER TABLE audit_retention.retention_holds OWNER TO audit_maintenance;

-- The application role reads both tables (the preview endpoint and the task
-- report on them) and writes NEITHER directly. Holds are placed and released
-- through the SECURITY DEFINER functions below, which cannot delete.
DO $table_grants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('REVOKE ALL ON TABLE audit_retention.retention_anchors FROM PUBLIC');
    EXECUTE format('REVOKE ALL ON TABLE audit_retention.retention_holds   FROM PUBLIC');
    EXECUTE format('REVOKE ALL ON TABLE audit_retention.retention_anchors FROM %I', app_role);
    EXECUTE format('REVOKE ALL ON TABLE audit_retention.retention_holds   FROM %I', app_role);
    EXECUTE format('GRANT SELECT ON TABLE audit_retention.retention_anchors TO %I', app_role);
    EXECUTE format('GRANT SELECT ON TABLE audit_retention.retention_holds   TO %I', app_role);
END $table_grants$;

-- ---------------------------------------------------------------------------
-- 6. The maintenance role's privileges on audit_logs.
--
--    DELETE and SELECT, nothing else. No UPDATE: retention removes rows, it
--    never rewrites one, and a role that could do both could rewrite history
--    and then remove the evidence. No TRUNCATE, ever -- the statement-level
--    trigger refuses it anyway, but the grant is not there to be found.
--
--    The row-level trigger still fires for this role. The grant is what lets
--    the statement be attempted; the trigger is what decides whether the row
--    may go, and it permits only `record_hash IS NULL`.
-- ---------------------------------------------------------------------------
DO $audit_logs_grants$
DECLARE part record;
BEGIN
    GRANT SELECT, DELETE ON TABLE public.audit_logs TO audit_maintenance;

    -- Partitions do not inherit table privileges. A DELETE routed to a leaf
    -- needs the privilege on that leaf.
    FOR part IN
        SELECT c.relname
          FROM pg_inherits i
          JOIN pg_class c ON c.oid = i.inhrelid
         WHERE i.inhparent = 'public.audit_logs'::regclass
    LOOP
        EXECUTE format('GRANT SELECT, DELETE ON TABLE public.%I TO audit_maintenance',
                       part.relname);
    END LOOP;

    GRANT SELECT ON TABLE public.organizations TO audit_maintenance;
END $audit_logs_grants$;

-- ---------------------------------------------------------------------------
-- 6b. Locking the chain head, owned by the CHAIN role.
--
--     The purge must take the same `FOR UPDATE` row lock on the head that the
--     insert trigger takes, or a purge and an insert for one organisation can
--     interleave. It cannot take that lock directly:
--
--       **PostgreSQL requires UPDATE privilege to lock a row.** Measured on
--       this schema — a role holding SELECT but not UPDATE on
--       audit_chain_heads is refused `SELECT ... FOR UPDATE` with "permission
--       denied for table audit_chain_heads". So "grant SELECT and let it lock"
--       does not work, and granting UPDATE would hand retention the ability to
--       rewrite a chain tip.
--
--     Hence this function. It is owned by audit_chain_writer, which owns the
--     table and therefore may lock it; audit_maintenance holds EXECUTE and no
--     table privilege whatsoever. The lock is a row lock held to the end of the
--     *calling* transaction — SECURITY DEFINER changes whose privileges apply,
--     not transaction scope — so the serialisation is exactly as strong as a
--     direct `FOR UPDATE` would have been.
--
--     It returns state and locks. It cannot write: no UPDATE, INSERT or DELETE
--     statement appears in it, so EXECUTE on it confers no ability to alter the
--     head.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain.audit_chain_lock_head_v1(
    p_org varchar(100)
) RETURNS TABLE (
    last_event_id      varchar(200),
    last_record_hash   varchar(64),
    event_count        bigint,
    legacy_event_count bigint,
    genesis_event_id   varchar(200)
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_chain, public
-- The same 3s ceiling audit_chain_advance_v1 pins. A purge that cannot get the
-- head lock must fail loudly and quickly rather than sit behind a long-running
-- writer; the run reports it and tries again on the next schedule.
SET lock_timeout = '3s'
AS $fn$
BEGIN
    RETURN QUERY
    SELECT h.last_event_id, h.last_record_hash, h.event_count,
           h.legacy_event_count, h.genesis_event_id
      FROM audit_chain.audit_chain_heads h
     WHERE h.org_id = p_org
       FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no chain head for organisation %', p_org
            USING ERRCODE = 'no_data_found';
    END IF;
END
$fn$;

ALTER FUNCTION audit_chain.audit_chain_lock_head_v1(varchar)
    OWNER TO audit_chain_writer;

REVOKE ALL ON FUNCTION audit_chain.audit_chain_lock_head_v1(varchar) FROM PUBLIC;

-- audit_maintenance only. Deliberately **not** the application role: locking a
-- tenant's chain head blocks every audit write for that tenant until the
-- transaction ends, which is a denial of service anything reachable from a
-- request must not be able to cause.
GRANT EXECUTE ON FUNCTION audit_chain.audit_chain_lock_head_v1(varchar)
    TO audit_maintenance;

-- ---------------------------------------------------------------------------
-- 7. Head adjustment, owned by the CHAIN role, not the maintenance role.
--
--    `audit_chain_heads` is owned by audit_chain_writer and only functions it
--    owns may write to it. Granting audit_maintenance a direct UPDATE would
--    let retention rewrite `last_record_hash` -- a chain tip -- which is
--    exactly what must remain impossible.
--
--    So the decrement goes through a SECURITY DEFINER function owned by
--    audit_chain_writer, executable only by audit_maintenance, that can touch
--    `legacy_event_count` and nothing else. Note the columns it does NOT
--    mention: last_event_id, last_record_hash, genesis_event_id, event_count.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain.audit_chain_note_legacy_purge_v1(
    p_org   varchar(100),
    p_count bigint
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_chain, public
SET lock_timeout = '3s'
AS $fn$
DECLARE
    remaining bigint;
BEGIN
    IF p_count < 0 THEN
        RAISE EXCEPTION 'legacy purge count must not be negative (got %)', p_count;
    END IF;

    -- GREATEST(...,0) rather than a bare subtraction. legacy_event_count was
    -- seeded from a COUNT at bootstrap time; if anything ever removed a legacy
    -- row outside this path the counter would be ahead of reality, and a
    -- negative count is a nonsense value that would then be reported to a
    -- reviewer as fact.
    UPDATE audit_chain.audit_chain_heads
       SET legacy_event_count = GREATEST(legacy_event_count - p_count, 0),
           updated_at         = now()
     WHERE org_id = p_org
    RETURNING legacy_event_count INTO remaining;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no chain head for organisation %', p_org;
    END IF;

    RETURN remaining;
END
$fn$;

ALTER FUNCTION audit_chain.audit_chain_note_legacy_purge_v1(varchar, bigint)
    OWNER TO audit_chain_writer;

REVOKE ALL ON FUNCTION audit_chain.audit_chain_note_legacy_purge_v1(varchar, bigint)
    FROM PUBLIC;

GRANT EXECUTE ON FUNCTION audit_chain.audit_chain_note_legacy_purge_v1(varchar, bigint)
    TO audit_maintenance;

-- ---------------------------------------------------------------------------
-- 8. Hold management. INSERT and release only -- never DELETE.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_retention.place_hold_v1(
    p_org    varchar(100),
    p_reason text,
    p_by     varchar(200)
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_retention, public
AS $fn$
DECLARE new_id bigint;
BEGIN
    IF p_reason IS NULL OR btrim(p_reason) = '' THEN
        RAISE EXCEPTION 'a retention hold must carry a reason';
    END IF;

    INSERT INTO audit_retention.retention_holds (org_id, reason, placed_by)
    VALUES (p_org, p_reason, p_by)
    ON CONFLICT DO NOTHING
    RETURNING id INTO new_id;

    IF new_id IS NULL THEN
        SELECT id INTO new_id FROM audit_retention.retention_holds
         WHERE org_id = p_org AND released_at IS NULL;
    END IF;

    RETURN new_id;
END
$fn$;

CREATE OR REPLACE FUNCTION audit_retention.release_hold_v1(
    p_org varchar(100),
    p_by  varchar(200)
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_retention, public
AS $fn$
BEGIN
    UPDATE audit_retention.retention_holds
       SET released_at = now(), released_by = p_by
     WHERE org_id = p_org AND released_at IS NULL;
    RETURN FOUND;
END
$fn$;

ALTER FUNCTION audit_retention.place_hold_v1(varchar, text, varchar)
    OWNER TO audit_maintenance;
ALTER FUNCTION audit_retention.release_hold_v1(varchar, varchar)
    OWNER TO audit_maintenance;

REVOKE ALL ON FUNCTION audit_retention.place_hold_v1(varchar, text, varchar) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_retention.release_hold_v1(varchar, varchar) FROM PUBLIC;

DO $hold_grants$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_retention.place_hold_v1(varchar, text, varchar) TO %I', app_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION audit_retention.release_hold_v1(varchar, varchar) TO %I', app_role);
END $hold_grants$;

-- ---------------------------------------------------------------------------
-- 9. The purge. One batch, one transaction, anchor first.
--
--    The caller supplies a cutoff and a batch size and nothing else. There is
--    no code path through this function that can delete a chained row, an
--    arbitrary organisation, a row newer than the cutoff, or everything.
--
--    Ordering inside the transaction is the whole design:
--
--      lock the chain head  -> so a purge cannot interleave with an insert
--      select the batch     -> legacy only, older than cutoff, oldest first
--      refuse if it would   -> tip / chained / empty-batch guards
--      INSERT the anchor    -> BEFORE any row is removed
--      DELETE by id         -> exactly the ids selected, nothing else
--      assert the row count -> a mismatch rolls the whole thing back
--      adjust the head
--
--    The caller's transaction is what commits. This function does not commit,
--    so a failure anywhere above -- including in the caller, after this
--    returns -- takes the anchor and the deletion down together.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_retention.purge_legacy_v1(
    p_org         varchar(100),
    p_cutoff      timestamptz,
    p_batch       integer,
    p_min_days    integer,
    p_operator    text        DEFAULT NULL,
    p_audit_event varchar(200) DEFAULT NULL,
    p_backup_ref  text        DEFAULT NULL
) RETURNS TABLE (
    deleted_count      bigint,
    anchor_id          bigint,
    range_from         timestamptz,
    range_to           timestamptz,
    legacy_remaining   bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_retention, audit_chain, public
SET lock_timeout = '10s'
AS $fn$
DECLARE
    started_at   timestamptz := clock_timestamp();
    ids          varchar(200)[];
    n            bigint;
    r_from       timestamptz;
    r_to         timestamptz;
    last_id      varchar(200);
    surv_id      varchar(200);
    surv_hash    varchar(64);
    head         record;
    new_anchor   bigint;
    remaining    bigint;
BEGIN
    -- --- Preconditions, all inside the boundary ----------------------------
    IF p_cutoff IS NULL OR p_cutoff >= now() THEN
        RAISE EXCEPTION 'retention cutoff must be strictly in the past (got %)',
                        p_cutoff;
    END IF;

    IF p_min_days IS NULL OR p_min_days < 1 THEN
        RAISE EXCEPTION 'a retention floor of at least one day is required';
    END IF;

    IF p_cutoff > now() - make_interval(days => p_min_days) THEN
        RAISE EXCEPTION
            'retention cutoff % is younger than the % day floor', p_cutoff, p_min_days
            USING HINT = 'AUDIT_RETENTION_MIN_DAYS is a floor the caller cannot '
                         'lower; a cutoff nearer than this is refused.';
    END IF;

    IF p_batch IS NULL OR p_batch < 1 THEN
        RAISE EXCEPTION 'batch size must be at least 1 (got %)', p_batch;
    END IF;

    IF EXISTS (
        SELECT 1 FROM audit_retention.retention_holds
         WHERE org_id = p_org AND released_at IS NULL
    ) THEN
        RAISE EXCEPTION 'organisation % is under a retention hold', p_org
            USING ERRCODE = '55006';
    END IF;

    -- --- Serialise against the chain --------------------------------------
    -- The same row lock the insert trigger takes, so a purge and an insert for
    -- one organisation cannot interleave; different organisations do not
    -- contend.
    --
    -- Taken **through a function owned by audit_chain_writer**, not with a
    -- direct `SELECT ... FOR UPDATE` here. PostgreSQL requires UPDATE privilege
    -- to lock a row, and audit_maintenance must never hold a write privilege on
    -- the head — with one it could rewrite a chain tip. The lock is a row lock
    -- held to the end of THIS transaction; SECURITY DEFINER changes whose
    -- privileges apply, not transaction scope.
    SELECT * INTO head FROM audit_chain.audit_chain_lock_head_v1(p_org);

    -- --- Select the batch --------------------------------------------------
    -- `record_hash IS NULL` is the legacy predicate. Oldest first, so a purge
    -- always works from the old end and can never reach the newest rows.
    SELECT array_agg(a.id ORDER BY a.created_at, a.id),
           min(a.created_at), max(a.created_at), count(*)
      INTO ids, r_from, r_to, n
      FROM (
            SELECT l.id, l.created_at
              FROM public.audit_logs l
             WHERE l.org_id = p_org
               AND l.record_hash IS NULL
               AND l.created_at < p_cutoff
             ORDER BY l.created_at, l.id
             LIMIT p_batch
           ) a;

    IF n IS NULL OR n = 0 THEN
        RETURN QUERY SELECT 0::bigint, NULL::bigint, NULL::timestamptz,
                            NULL::timestamptz, head.legacy_event_count;
        RETURN;
    END IF;

    -- --- Guards that must hold even if the query above were wrong ----------
    IF head.last_event_id = ANY (ids) THEN
        RAISE EXCEPTION
            'refusing to purge: the batch contains the chain tip (%)',
            head.last_event_id;
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.audit_logs
         WHERE org_id = p_org AND id = ANY (ids) AND record_hash IS NOT NULL
    ) THEN
        RAISE EXCEPTION
            'refusing to purge: the batch contains a chained row. Phase 6a '
            'removes legacy rows only.';
    END IF;

    last_id := ids[array_length(ids, 1)];

    -- --- The anchor, BEFORE the delete, in this transaction ----------------
    -- For kind='legacy' the hash columns stay NULL: these rows have no hash,
    -- so there is nothing to record and nothing to verify later. The anchor
    -- accounts for the deletion; it does not preserve it.
    INSERT INTO audit_retention.retention_anchors (
        org_id, kind, purge_started_at, cutoff, range_from, range_to,
        deleted_count, last_deleted_event_id, last_deleted_record_hash,
        operator_identity, audit_event_id, backup_reference
    ) VALUES (
        p_org, 'legacy', started_at, p_cutoff, r_from, r_to,
        n, last_id, NULL,
        p_operator, p_audit_event, p_backup_ref
    )
    RETURNING id INTO new_anchor;

    -- --- The deletion ------------------------------------------------------
    DELETE FROM public.audit_logs
     WHERE org_id = p_org
       AND id = ANY (ids)
       AND record_hash IS NULL;          -- restated: belt and braces

    GET DIAGNOSTICS remaining = ROW_COUNT;
    IF remaining <> n THEN
        RAISE EXCEPTION
            'refusing to complete: selected % rows but deleted % -- rolling back',
            n, remaining;
    END IF;

    -- --- Resulting state, recorded on the anchor ---------------------------
    SELECT s.id, s.record_hash INTO surv_id, surv_hash
      FROM public.audit_logs s
     WHERE s.org_id = p_org
     ORDER BY s.created_at, s.id
     LIMIT 1;

    remaining := audit_chain.audit_chain_note_legacy_purge_v1(p_org, n);

    UPDATE audit_retention.retention_anchors
       SET first_surviving_event_id    = surv_id,
           first_surviving_record_hash = surv_hash,
           head_event_count_after      = head.event_count,
           head_legacy_count_after     = remaining,
           head_genesis_after          = head.genesis_event_id,
           head_tip_after              = head.last_event_id,
           purge_completed_at          = now()
     WHERE id = new_anchor;

    RETURN QUERY SELECT n, new_anchor, r_from, r_to, remaining;
END
$fn$;

ALTER FUNCTION audit_retention.purge_legacy_v1(
    varchar, timestamptz, integer, integer, text, varchar, text)
    OWNER TO audit_maintenance;

REVOKE ALL ON FUNCTION audit_retention.purge_legacy_v1(
    varchar, timestamptz, integer, integer, text, varchar, text) FROM PUBLIC;

DO $purge_grant$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_retention.purge_legacy_v1('
        'varchar, timestamptz, integer, integer, text, varchar, text) TO %I',
        app_role);
END $purge_grant$;

-- ---------------------------------------------------------------------------
-- 10. A read-only preview, so the application can report what WOULD be
--     deleted without holding any privilege that could delete it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_retention.preview_legacy_v1(
    p_cutoff timestamptz
) RETURNS TABLE (
    org_id            varchar(100),
    eligible_count    bigint,
    oldest            timestamptz,
    newest            timestamptz,
    on_hold           boolean,
    legacy_total      bigint,
    chained_total     bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, audit_retention, public
AS $fn$
    SELECT a.org_id,
           count(*) FILTER (WHERE a.record_hash IS NULL AND a.created_at < p_cutoff),
           min(a.created_at) FILTER (WHERE a.record_hash IS NULL AND a.created_at < p_cutoff),
           max(a.created_at) FILTER (WHERE a.record_hash IS NULL AND a.created_at < p_cutoff),
           EXISTS (SELECT 1 FROM audit_retention.retention_holds h
                    WHERE h.org_id = a.org_id AND h.released_at IS NULL),
           count(*) FILTER (WHERE a.record_hash IS NULL),
           count(*) FILTER (WHERE a.record_hash IS NOT NULL)
      FROM public.audit_logs a
     GROUP BY a.org_id
     ORDER BY a.org_id
$fn$;

ALTER FUNCTION audit_retention.preview_legacy_v1(timestamptz)
    OWNER TO audit_maintenance;
REVOKE ALL ON FUNCTION audit_retention.preview_legacy_v1(timestamptz) FROM PUBLIC;

DO $preview_grant$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_retention.preview_legacy_v1(timestamptz) TO %I',
        app_role);
END $preview_grant$;

COMMIT;

\echo ''
\echo 'Phase 6a retention bootstrap complete.'
\echo 'Verify with:'
\echo '  docker exec ccure-api python scripts/audit/verify_retention_bootstrap.py'
\echo ''
\echo 'Retention remains DISABLED until AUDIT_LOG_RETENTION_DAYS is set to a'
\echo 'non-zero value agreed with the business/compliance owner. This script'
\echo 'installs the machinery; it does not purge anything and does not enable'
\echo 'anything.'

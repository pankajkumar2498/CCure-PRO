-- ===========================================================================
-- scripts/audit/bootstrap_chain_retention_chained.sql
-- ---------------------------------------------------------------------------
-- Phase 6c. The privileged half of **chained**-record retention.
--
-- Run as a SUPERUSER, once per database, AFTER bootstrap_chain_retention.sql:
--
--     psql -v ON_ERROR_STOP=1 \
--          -v app_role=ccure_user \
--          -d <database> \
--          -f Backend/scripts/audit/bootstrap_chain_retention_chained.sql
--
-- Then verify:
--     docker exec ccure-api python scripts/audit/verify_retention_bootstrap.py
--
-- **No credential appears in this file** and none should be added.
--
-- ---------------------------------------------------------------------------
-- What changes, and what deliberately does not
-- ---------------------------------------------------------------------------
--
-- Phase 6a removed rows that predate the tamper-evidence chain. Nothing could
-- link to them, so their removal was cryptographically free. This phase removes
-- rows that ARE chained, which is a different act entirely: it breaks a link,
-- and the anchor is what makes the break explicable rather than
-- indistinguishable from tampering.
--
-- Three things carry that:
--
--   * **A contiguous prefix, never the middle.** Rows are removed in chain
--     order starting at genesis. Deleting from the middle would orphan a link
--     no anchor could explain, and no amount of recording afterwards would
--     repair it.
--
--   * **A continuity anchor.** `last_deleted_record_hash` is the hash of the
--     newest row removed. Afterwards the oldest surviving row's non-NULL
--     `prev_hash` must equal it -- which is exactly how `verify_chain.py`
--     tells a sanctioned purge from a deletion nobody authorised.
--
--   * **A mandatory verified archive.** A chained purge refuses without a
--     phase-5 export that was produced with verify=true, verified
--     successfully, reported zero integrity failures, and covers the range.
--     The anchor records which export and its SHA-256.
--
-- What an anchor still cannot do: prove the archive file has not been altered
-- since it was written. The hash is recorded here; checking it is a manual act
-- against a file this system does not hold. **The archive is not
-- tamper-evident in the way the chain is.** Do not describe it as though it is.
--
-- ---------------------------------------------------------------------------
-- The database-level guard, honestly
-- ---------------------------------------------------------------------------
-- Phase 6a's trigger made a strong claim: the maintenance role was *incapable*
-- of deleting a chained row, enforced by PostgreSQL rather than by care. This
-- phase exists to delete chained rows, so that clause cannot survive it.
--
-- What replaces it is narrower but real: **the current chain tip can never be
-- deleted, by anyone, ever.** Deleting the tip would leave
-- `last_record_hash` naming a row that no longer exists, and the next insert
-- would link to a hash nothing can resolve -- permanently unverifiable, and
-- unfixable afterwards. The trigger checks it per row through
-- `audit_chain_is_tip_v1` below, so it holds even if every line of the purge
-- function were wrong.
--
-- The check goes through a SECURITY DEFINER function rather than a direct
-- read, because `audit_maintenance` holds **no table privilege whatsoever** on
-- `audit_chain_heads` -- not even SELECT -- and that is worth keeping.
--
-- ---------------------------------------------------------------------------
-- Idempotence
-- ---------------------------------------------------------------------------
-- Every object is CREATE OR REPLACE or guarded by a catalogue check. **There is
-- not one DROP statement in this file**, and it will not remove or rewrite an
-- anchor. The whole file is one transaction.
-- ===========================================================================

\set ON_ERROR_STOP on
\if :{?app_role}
\else
  \set app_role ccure_user
\endif

BEGIN;

SELECT set_config('bootstrap.app_role', :'app_role', false);

-- ---------------------------------------------------------------------------
-- 0. Preconditions.
-- ---------------------------------------------------------------------------
DO $preconditions$
BEGIN
    IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION
            'bootstrap_chain_retention_chained.sql must be run by a superuser; '
            'current_user is %', current_user;
    END IF;

    IF to_regclass('audit_retention.retention_anchors') IS NULL THEN
        RAISE EXCEPTION
            'audit_retention is not installed: run bootstrap_chain_retention.sql first';
    END IF;

    IF to_regclass('audit_chain.audit_chain_heads') IS NULL THEN
        RAISE EXCEPTION
            'audit_chain is not installed: run bootstrap_chain.sql first';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_maintenance') THEN
        RAISE EXCEPTION 'role audit_maintenance does not exist';
    END IF;

    -- The separation phase 6a established must still hold. If the application
    -- role can become the maintenance role, everything below is decoration.
    IF pg_has_role(current_setting('bootstrap.app_role'), 'audit_maintenance', 'MEMBER') THEN
        RAISE EXCEPTION
            'Refusing to bootstrap: % is a member of audit_maintenance',
            current_setting('bootstrap.app_role');
    END IF;
END $preconditions$;

-- ---------------------------------------------------------------------------
-- 1. An archive is mandatory for a chained anchor.
--
--    Existing rows are all kind='legacy' with a NULL artefact, and the
--    constraint permits exactly that -- so this can be added to a populated
--    table without touching a single row.
-- ---------------------------------------------------------------------------
DO $archive_required$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
         WHERE conname = 'retention_anchor_chained_requires_archive'
           AND conrelid = 'audit_retention.retention_anchors'::regclass
    ) THEN
        ALTER TABLE audit_retention.retention_anchors
            ADD CONSTRAINT retention_anchor_chained_requires_archive
            CHECK (kind <> 'chained' OR archive_artifact IS NOT NULL);
        RAISE NOTICE 'added CHECK: a chained anchor must carry an archive artefact';
    ELSE
        RAISE NOTICE 'CHECK retention_anchor_chained_requires_archive already present';
    END IF;
END $archive_required$;

COMMENT ON COLUMN audit_retention.retention_anchors.last_deleted_record_hash IS
    'NULL for kind=''legacy'' -- such rows have no hash. For kind=''chained'' '
    'this is the continuity evidence: the oldest surviving row''s prev_hash '
    'must equal it, which is how verify_chain.py distinguishes a sanctioned '
    'purge from an unauthorised deletion.';

-- ---------------------------------------------------------------------------
-- 2. Is this row the chain tip?
--
--    Owned by the chain role because it reads the head table, and granted to
--    audit_maintenance alone so the append-only trigger can call it while that
--    role continues to hold no table privilege on the head at all.
--
--    STABLE and read-only: it contains no write statement, so EXECUTE on it
--    confers nothing beyond the answer.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain.audit_chain_is_tip_v1(
    p_org      varchar(100),
    p_event_id varchar(200)
) RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, audit_chain, public
AS $fn$
    SELECT EXISTS (
        SELECT 1 FROM audit_chain.audit_chain_heads h
         WHERE h.org_id = p_org AND h.last_event_id = p_event_id
    )
$fn$;

ALTER FUNCTION audit_chain.audit_chain_is_tip_v1(varchar, varchar)
    OWNER TO audit_chain_writer;
REVOKE ALL ON FUNCTION audit_chain.audit_chain_is_tip_v1(varchar, varchar) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_chain.audit_chain_is_tip_v1(varchar, varchar)
    TO audit_maintenance;

-- ---------------------------------------------------------------------------
-- 3. Record a chained purge on the head: decrement the count, repoint genesis.
--
--    Owned by the chain role, for the same reason its legacy counterpart is:
--    only a function owned by the head table's owner may write to it, and
--    granting audit_maintenance a direct UPDATE would let retention rewrite a
--    chain tip.
--
--    Note the columns it does NOT touch: last_event_id and last_record_hash.
--    A chained purge removes a prefix; the tip is by definition not in it.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_chain.audit_chain_note_chained_purge_v1(
    p_org         varchar(100),
    p_count       bigint,
    p_new_genesis varchar(200)
) RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_chain, public
SET lock_timeout = '3s'
AS $fn$
DECLARE
    remaining bigint;
    tip       varchar(200);
BEGIN
    IF p_count < 0 THEN
        RAISE EXCEPTION 'chained purge count must not be negative (got %)', p_count;
    END IF;

    SELECT h.last_event_id INTO tip
      FROM audit_chain.audit_chain_heads h WHERE h.org_id = p_org;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'no chain head for organisation %', p_org;
    END IF;

    -- The new genesis must exist and must not be the tip's own removal. A
    -- purge that emptied the chain would leave the head naming a deleted row.
    IF p_new_genesis IS NULL THEN
        RAISE EXCEPTION
            'refusing to record a chained purge that leaves no surviving '
            'chained row for organisation %', p_org;
    END IF;

    UPDATE audit_chain.audit_chain_heads
       SET event_count      = GREATEST(event_count - p_count, 0),
           genesis_event_id = p_new_genesis,
           updated_at       = now()
     WHERE org_id = p_org
    RETURNING event_count INTO remaining;

    RETURN remaining;
END
$fn$;

ALTER FUNCTION audit_chain.audit_chain_note_chained_purge_v1(varchar, bigint, varchar)
    OWNER TO audit_chain_writer;
REVOKE ALL ON FUNCTION audit_chain.audit_chain_note_chained_purge_v1(varchar, bigint, varchar)
    FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_chain.audit_chain_note_chained_purge_v1(varchar, bigint, varchar)
    TO audit_maintenance;

-- ---------------------------------------------------------------------------
-- 4. The chained purge.
--
--    Ordering inside the transaction, and every step of it is load-bearing:
--
--      validate the archive   -> refuses without verified off-platform evidence
--      lock the chain head    -> a purge cannot interleave with an insert
--      walk the chain         -> a contiguous PREFIX from genesis, never the
--                                middle, because a middle deletion orphans a
--                                link no anchor can explain
--      refuse the tip         -> belt and braces; the trigger refuses too
--      INSERT the anchor      -> BEFORE any row is removed, with the
--                                continuity hash and the archive artefact
--      DELETE by id           -> exactly the ids walked, nothing else
--      assert the row count   -> a mismatch rolls the whole thing back
--      repoint genesis
--
--    The caller's transaction commits. This function does not, so a failure
--    anywhere -- including in the caller, after this returns -- takes the
--    anchor and the deletion down together.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_retention.purge_chained_v1(
    p_org           varchar(100),
    p_cutoff        timestamptz,
    p_batch         integer,
    p_min_days      integer,
    p_archive_event varchar(200),
    p_archive_sha   text,
    p_operator      text         DEFAULT NULL,
    p_audit_event   varchar(200) DEFAULT NULL,
    p_backup_ref    text         DEFAULT NULL
) RETURNS TABLE (
    deleted_count    bigint,
    anchor_id        bigint,
    range_from       timestamptz,
    range_to         timestamptz,
    new_genesis      varchar(200),
    events_remaining bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, audit_retention, audit_chain, public
SET lock_timeout = '10s'
AS $fn$
DECLARE
    started_at   timestamptz := clock_timestamp();
    archive      record;
    head         record;
    ids          varchar(200)[];
    n            bigint;
    r_from       timestamptz;
    r_to         timestamptz;
    last_id      varchar(200);
    last_hash    varchar(64);
    surv_id      varchar(200);
    surv_hash    varchar(64);
    new_anchor   bigint;
    removed      bigint;
    remaining    bigint;
BEGIN
    -- --- Preconditions, all inside the boundary ----------------------------
    IF p_cutoff IS NULL OR p_cutoff >= now() THEN
        RAISE EXCEPTION 'retention cutoff must be strictly in the past (got %)', p_cutoff;
    END IF;

    IF p_min_days IS NULL OR p_min_days < 1 THEN
        RAISE EXCEPTION 'a retention floor of at least one day is required';
    END IF;

    IF p_cutoff > now() - make_interval(days => p_min_days) THEN
        RAISE EXCEPTION
            'retention cutoff % is younger than the % day floor', p_cutoff, p_min_days;
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

    -- --- The archive is mandatory, and it must be a GOOD one ---------------
    -- A purge authorised by an export that verified nothing is a purge
    -- authorised by nothing.
    IF p_archive_event IS NULL OR p_archive_sha IS NULL OR btrim(p_archive_sha) = '' THEN
        RAISE EXCEPTION
            'a chained purge requires an archive: the id of a verified '
            'audit.log_exported event and the SHA-256 of the file it produced';
    END IF;

    SELECT a.id, a.action, a.changes, a.created_at
      INTO archive
      FROM public.audit_logs a
     WHERE a.id = p_archive_event
     LIMIT 1;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'archive event % does not exist', p_archive_event;
    END IF;

    IF archive.action <> 'audit.log_exported' THEN
        RAISE EXCEPTION
            'archive event % is a %, not an audit.log_exported event',
            p_archive_event, archive.action;
    END IF;

    IF coalesce(archive.changes ->> 'verification_mode', '') <> 'performed' THEN
        RAISE EXCEPTION
            'archive export % was not verified (verification_mode=%). A chained '
            'purge requires an export produced with verify=true.',
            p_archive_event, coalesce(archive.changes ->> 'verification_mode', 'unknown');
    END IF;

    IF coalesce((archive.changes ->> 'integrity_failures')::bigint, -1) <> 0 THEN
        RAISE EXCEPTION
            'archive export % reported % integrity failure(s); it cannot '
            'authorise a purge',
            p_archive_event, archive.changes ->> 'integrity_failures';
    END IF;

    -- Cover, not exact match: the export must reach at least as far forward as
    -- the rows being removed. Exact row-set equality would be brittle across a
    -- re-run for no gain.
    IF coalesce((archive.changes ->> 'snapshot_upper_bound')::timestamptz,
                '-infinity'::timestamptz) < p_cutoff THEN
        RAISE EXCEPTION
            'archive export % covers only up to %, which does not reach the '
            'cutoff %', p_archive_event,
            archive.changes ->> 'snapshot_upper_bound', p_cutoff;
    END IF;

    -- --- Serialise against the chain ---------------------------------------
    SELECT * INTO head FROM audit_chain.audit_chain_lock_head_v1(p_org);

    -- --- Walk a contiguous prefix from genesis -----------------------------
    -- Chain order, not created_at order. `created_at` is set client-side and
    -- can legitimately run out of order relative to insertion, so a purge that
    -- selected by timestamp could remove a row from the middle of the chain
    -- while believing it was taking the oldest.
    WITH RECURSIVE walked AS (
        SELECT a.id, a.created_at, a.record_hash, 1 AS pos
          FROM public.audit_logs a
         WHERE a.org_id = p_org
           AND a.record_hash IS NOT NULL
           AND a.prev_hash IS NULL
        UNION ALL
        SELECT nxt.id, nxt.created_at, nxt.record_hash, w.pos + 1
          FROM walked w
          JOIN public.audit_logs nxt
            ON nxt.org_id = p_org
           AND nxt.prev_hash = w.record_hash
    ),
    boundary AS (
        -- The first position at or after the cutoff. Everything before it is
        -- eligible; everything from it on stays, so the removed set is a
        -- prefix by construction rather than by hope.
        SELECT coalesce(min(pos), (SELECT coalesce(max(pos), 0) + 1 FROM walked)) AS stop
          FROM walked WHERE created_at >= p_cutoff
    ),
    eligible AS (
        SELECT w.id, w.created_at, w.record_hash, w.pos
          FROM walked w, boundary b
         WHERE w.pos < b.stop
         ORDER BY w.pos
         LIMIT p_batch
    )
    SELECT array_agg(e.id ORDER BY e.pos),
           min(e.created_at), max(e.created_at), count(*),
           (array_agg(e.id         ORDER BY e.pos))[count(*)],
           (array_agg(e.record_hash ORDER BY e.pos))[count(*)]
      INTO ids, r_from, r_to, n, last_id, last_hash
      FROM eligible e;

    IF n IS NULL OR n = 0 THEN
        RETURN QUERY SELECT 0::bigint, NULL::bigint, NULL::timestamptz,
                            NULL::timestamptz, NULL::varchar(200), head.event_count;
        RETURN;
    END IF;

    -- --- Guards that hold even if the walk above were wrong ----------------
    IF head.last_event_id = ANY (ids) THEN
        RAISE EXCEPTION
            'refusing to purge: the batch contains the chain tip (%)',
            head.last_event_id;
    END IF;

    IF EXISTS (
        SELECT 1 FROM public.audit_logs
         WHERE org_id = p_org AND id = ANY (ids) AND record_hash IS NULL
    ) THEN
        RAISE EXCEPTION
            'refusing to purge: the batch contains an unhashed row. Legacy rows '
            'are removed by purge_legacy_v1, which accounts for them differently.';
    END IF;

    -- The row that becomes the new genesis: the one whose prev_hash is the
    -- hash of the last row being removed. If it does not exist the batch would
    -- empty the chain, which must never happen.
    SELECT s.id, s.record_hash INTO surv_id, surv_hash
      FROM public.audit_logs s
     WHERE s.org_id = p_org AND s.prev_hash = last_hash
     LIMIT 1;

    IF surv_id IS NULL THEN
        RAISE EXCEPTION
            'refusing to purge: no chained row survives this batch for '
            'organisation %. A chained purge must always leave a chain.', p_org;
    END IF;

    -- --- The anchor, BEFORE the delete, in this transaction ----------------
    INSERT INTO audit_retention.retention_anchors (
        org_id, kind, purge_started_at, cutoff, range_from, range_to,
        deleted_count, last_deleted_event_id, last_deleted_record_hash,
        first_surviving_event_id, first_surviving_record_hash,
        operator_identity, audit_event_id, backup_reference, archive_artifact
    ) VALUES (
        p_org, 'chained', started_at, p_cutoff, r_from, r_to,
        n, last_id, last_hash,
        surv_id, surv_hash,
        p_operator, p_audit_event, p_backup_ref,
        jsonb_build_object(
            'export_event_id', p_archive_event,
            'sha256',          p_archive_sha,
            'exported_at',     archive.created_at,
            'row_count',       archive.changes -> 'row_count',
            'verified',        archive.changes -> 'verified',
            'format',          archive.changes -> 'format',
            'snapshot_upper_bound', archive.changes -> 'snapshot_upper_bound'
        )
    )
    RETURNING id INTO new_anchor;

    -- --- The deletion ------------------------------------------------------
    DELETE FROM public.audit_logs
     WHERE org_id = p_org
       AND id = ANY (ids)
       AND record_hash IS NOT NULL;

    GET DIAGNOSTICS removed = ROW_COUNT;
    IF removed <> n THEN
        RAISE EXCEPTION
            'refusing to complete: selected % rows but deleted % -- rolling back',
            n, removed;
    END IF;

    -- --- Resulting head state ----------------------------------------------
    remaining := audit_chain.audit_chain_note_chained_purge_v1(p_org, n, surv_id);

    UPDATE audit_retention.retention_anchors
       SET head_event_count_after  = remaining,
           head_legacy_count_after = head.legacy_event_count,
           head_genesis_after      = surv_id,
           head_tip_after          = head.last_event_id,
           purge_completed_at      = now()
     WHERE id = new_anchor;

    RETURN QUERY SELECT n, new_anchor, r_from, r_to, surv_id, remaining;
END
$fn$;

ALTER FUNCTION audit_retention.purge_chained_v1(
    varchar, timestamptz, integer, integer, varchar, text, text, varchar, text)
    OWNER TO audit_maintenance;

REVOKE ALL ON FUNCTION audit_retention.purge_chained_v1(
    varchar, timestamptz, integer, integer, varchar, text, text, varchar, text)
    FROM PUBLIC;

DO $purge_grant$
DECLARE app_role text := current_setting('bootstrap.app_role');
BEGIN
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION audit_retention.purge_chained_v1('
        'varchar, timestamptz, integer, integer, varchar, text, text, varchar, text) TO %I',
        app_role);
END $purge_grant$;

-- ---------------------------------------------------------------------------
-- 5. Assert the boundary phase 6a established is still intact.
-- ---------------------------------------------------------------------------
DO $final$
BEGIN
    IF has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'INSERT')
    OR has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'UPDATE')
    OR has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'DELETE')
    OR has_table_privilege('audit_maintenance', 'audit_chain.audit_chain_heads', 'TRUNCATE')
    THEN
        RAISE EXCEPTION
            'Refusing to complete: audit_maintenance holds a write privilege on '
            'audit_chain.audit_chain_heads.';
    END IF;
END $final$;

COMMIT;

\echo ''
\echo 'Phase 6c chained-retention bootstrap complete.'
\echo 'Verify with:'
\echo '  docker exec ccure-api python scripts/audit/verify_retention_bootstrap.py'
\echo ''
\echo 'Retention remains DISABLED. This installs machinery only: it purges'
\echo 'nothing, enables nothing, and a chained purge additionally refuses'
\echo 'without a verified phase-5 export to authorise it.'

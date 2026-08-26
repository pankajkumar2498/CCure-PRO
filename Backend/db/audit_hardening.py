"""
db/audit_hardening.py
─────────────────────────────────────────────────────────────────────────────
Append-only enforcement for ``audit_logs``, at the database level.

Why this lives here rather than only in the migration
────────────────────────────────────────────────────
This project builds its schema two ways (see ``tests/repo/test_schema_drift.py``):
a fresh install runs ``Base.metadata.create_all()`` and stamps Alembic head, an
existing install runs ``alembic upgrade head``. Triggers and grants cannot be
expressed in SQLAlchemy metadata, so DDL written only inside a migration would
never execute on a fresh install — the exact fresh-vs-migrated divergence that
test exists to catch, except invisible, because the missing thing is a security
control rather than a column.

Both callers use the functions here:

  * ``alembic/versions/f5a6b7c8d9e0_audit_immutability.py``
  * ``db/migrate_production_schema.py`` (the ``is_database_empty`` branch)

The three layers, and what each actually stops
──────────────────────────────────────────────
Measured against PostgreSQL 18 on a 1,000,000-row copy of this schema:

1. **Grants** — ``TRUNCATE`` is revoked from the application's runtime role.
   Only TRUNCATE: see below for why ``UPDATE`` and ``DELETE`` cannot be.

2. **A row-level trigger** — rejects ``UPDATE`` and ``DELETE`` regardless of
   privilege. This is the layer that still holds when the grant does not,
   because the application role *owns* these tables and an owner can re-grant
   to itself. Verified: with ``UPDATE`` re-granted, the trigger still refused.

3. **Statement-level TRUNCATE triggers** — a row-level trigger never fires for
   ``TRUNCATE``, so without these a re-granted owner could empty the table.

**UPDATE and DELETE are deliberately NOT revoked**, and this is not an
oversight. PostgreSQL performs a referential action with the privileges of the
role issuing the statement, not the table owner, and ``audit_logs`` is on the
receiving end of two:

* ``user_id`` is ``ON DELETE SET NULL`` — an account deletion updates audit
  rows. Revoking ``UPDATE`` was measured to break it:
  ``DELETE user -> permission denied for table audit_logs``.
* ``org_id`` is ``ON DELETE CASCADE`` — an organisation deletion removes its
  audit rows. Revoking ``DELETE`` breaks that the same way.

So the trigger carries both layers alone, permitting exactly those two
referential actions and nothing else. It is the stronger control regardless:
it still refuses after an owner re-grants itself the privilege, which a REVOKE
does not survive.

Honest scope
────────────
A database superuser, or anyone holding the owning role, can drop a trigger or
re-grant a privilege. No in-database control changes that. The accurate claim
is: *the application and its runtime role cannot modify or delete audit records
through any application path, and doing so out of band requires deliberate DDL
that leaves its own trace.* Tamper **evidence** for that case is the hash chain
in phase 4, not this module.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager

from sqlalchemy import text

log = logging.getLogger("ccure.audit.hardening")

PARENT = "audit_logs"

#: Rejects UPDATE and DELETE on an audit row, with exactly two exceptions —
#: both of them the database's own referential-integrity actions, neither of
#: them reachable as a way to alter history.
#:
#: **The permitted UPDATE** is the ``user_id`` foreign key's ``ON DELETE SET
#: NULL`` firing when an account is deleted. It is recognised by comparing the
#: whole row with ``user_id`` removed — ``to_jsonb(NEW) - 'user_id'`` — rather
#: than by listing columns, so a column added later is protected automatically
#: instead of silently falling outside the check. Re-pointing ``user_id`` at a
#: *different* user is refused: that would reattribute an action to someone who
#: did not perform it.
#:
#: **The permitted DELETE** is the ``org_id`` foreign key's ``ON DELETE
#: CASCADE`` firing when an organisation is deleted. It is recognised by the
#: organisation row already being gone: PostgreSQL runs the cascade as an AFTER
#: trigger on the parent, so by the time this fires the ``organizations`` row
#: no longer exists. Measured:
#:
#:     direct DELETE FROM audit_logs  -> depth=1, organisation row still present
#:     DELETE FROM organizations      -> depth=2, organisation row already gone
#:
#: The organisation-row test is used rather than ``pg_trigger_depth()`` because
#: it means something — "the owning organisation is being removed" — whereas a
#: depth of 2 is incidental and would also be reached by any future trigger
#: that happened to nest.
#:
#: This deliberately leaves one thing possible: deleting an organisation
#: destroys its audit history. That is the schema's pre-existing CASCADE and is
#: not made worse here — but it does mean "immutable" has an asterisk, and the
#: asterisk is a superadmin deleting a whole tenant. Blocking it instead would
#: break organisation deletion outright.
_REJECT_MUTATION_FN = """
CREATE OR REPLACE FUNCTION audit_logs_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $fn$
DECLARE
    owning_org_is_gone boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN
        SELECT NOT EXISTS (
            SELECT 1 FROM organizations WHERE id = OLD.org_id
        ) INTO owning_org_is_gone;

        IF owning_org_is_gone THEN
            RETURN OLD;
        END IF;

        -- Retention. `current_user = 'audit_maintenance'` is true only inside
        -- audit_retention.purge_legacy_v1() and purge_chained_v1(), both
        -- SECURITY DEFINER and owned by that role. `current_user` reflects the
        -- definer during the function's execution and is not settable by the
        -- caller, so the application role executing ordinary SQL never
        -- satisfies it.
        --
        -- **The chain tip can never be deleted, by anyone, ever.**
        --
        -- Phase 6a made a stronger claim here -- `OLD.record_hash IS NULL`,
        -- so the maintenance role was *incapable* of removing a chained row.
        -- Phase 6c exists to remove chained rows, so that clause could not
        -- survive it. What replaces it is narrower but real, and it guards the
        -- one deletion that is unrecoverable: removing the tip would leave
        -- `last_record_hash` naming a row that no longer exists, and the next
        -- insert would link to a hash nothing can resolve. Permanently
        -- unverifiable, and unfixable afterwards.
        --
        -- Checked per row, so it holds even if the purge function's own
        -- predicate is wrong, even if it is called with the wrong arguments.
        --
        -- Routed through a SECURITY DEFINER function rather than a direct read
        -- because `audit_maintenance` holds **no table privilege whatsoever**
        -- on `audit_chain_heads` -- not even SELECT -- and that is worth
        -- keeping. This trigger function is not SECURITY DEFINER, so it runs
        -- with the invoker's privileges and could not read the head itself.
        IF current_user = 'audit_maintenance' THEN
            -- Degrade to the phase-6a rule when the phase-6c half is absent.
            --
            -- The tip guard lives in `audit_chain_is_tip_v1`, which a DBA
            -- installs with bootstrap_chain_retention_chained.sql, while this
            -- trigger arrives with an Alembic revision. The two are applied by
            -- different people at different times, so a database will sit in
            -- between -- and calling a function that is not there yet would
            -- break the *legacy* purge that already worked.
            --
            -- So the absence of the guard narrows what is permitted rather
            -- than widening it: pre-chain rows only, exactly as phase 6a. Fail
            -- closed, and no ordering hazard between the migration and the
            -- bootstrap in either direction.
            IF to_regprocedure(
                   'audit_chain.audit_chain_is_tip_v1(character varying,character varying)'
               ) IS NULL THEN
                IF OLD.record_hash IS NULL THEN
                    RETURN OLD;
                END IF;
                RAISE EXCEPTION
                    'audit_logs: chained retention is not installed in this '
                    'database, so only pre-chain rows may be removed'
                    USING ERRCODE = '42501',
                          HINT = 'Run bootstrap_chain_retention_chained.sql as '
                                 'a superuser to enable chained retention.';
            END IF;

            IF audit_chain.audit_chain_is_tip_v1(OLD.org_id, OLD.id) THEN
                RAISE EXCEPTION
                    'audit_logs: refusing to delete the current chain tip (%)',
                    OLD.id
                    USING ERRCODE = '42501',
                          HINT = 'Retention removes a contiguous prefix from '
                                 'genesis. The tip is never eligible.';
            END IF;
            RETURN OLD;
        END IF;

        RAISE EXCEPTION
            'audit_logs is append-only: DELETE is not permitted (attempted by %)',
            current_user
            USING ERRCODE = '42501',
                  HINT = 'Audit events are removed only when their owning '
                         'organisation is deleted, or by the retention '
                         'procedure.';
    END IF;

    IF NEW.user_id IS NULL
       AND OLD.user_id IS NOT NULL
       AND (to_jsonb(NEW) - 'user_id') = (to_jsonb(OLD) - 'user_id') THEN
        RETURN NEW;
    END IF;

    RAISE EXCEPTION
        'audit_logs is append-only: UPDATE is not permitted (attempted by %)',
        current_user
        USING ERRCODE = '42501',
              HINT = 'The only permitted update is the user_id foreign key '
                     'being set to NULL when an account is deleted.';
END;
$fn$
"""

_REJECT_TRUNCATE_FN = """
CREATE OR REPLACE FUNCTION audit_logs_reject_truncate() RETURNS trigger
LANGUAGE plpgsql AS $fn$
BEGIN
    RAISE EXCEPTION
        'audit_logs is append-only: TRUNCATE is not permitted (attempted by %)',
        current_user
        USING ERRCODE = '42501';
END;
$fn$
"""


def leaf_partitions(conn, parent: str = PARENT) -> list[str]:
    """Every current leaf partition of `parent`, discovered not assumed.

    The partition count is a deployment detail (``create_partitions`` makes
    eight today). Hardcoding that number would silently leave a ninth
    unprotected.
    """
    return [
        r[0]
        for r in conn.execute(
            text(
                """
                SELECT c.relname
                  FROM pg_inherits i
                  JOIN pg_class c ON c.oid = i.inhrelid
                 WHERE i.inhparent = CAST(:p AS regclass)
                 ORDER BY c.relname
                """
            ),
            {"p": parent},
        )
    ]


def _create_mutation_trigger(conn) -> None:
    """(Re)create the append-only row trigger on the partitioned parent.

    Row-level triggers on a partitioned parent are cloned to every existing
    partition, and to any partition created later, so one statement covers all
    eight leaves. Defined once here because two callers install it:
    `apply_audit_immutability` and `suspended_immutability`'s exit.
    """
    conn.execute(text(f"DROP TRIGGER IF EXISTS audit_logs_immutable ON {PARENT}"))
    conn.execute(
        text(
            f"""
            CREATE TRIGGER audit_logs_immutable
            BEFORE UPDATE OR DELETE ON {PARENT}
            FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation()
            """
        )
    )


@contextmanager
def suspended_immutability(conn):
    """
    Drop the append-only trigger, run the caller's block, put it back.

    This exists for exactly one purpose: a migration that has to write to
    existing ``audit_logs`` rows. The phase-4 actor-snapshot backfill is such a
    migration — ``UPDATE audit_logs SET actor_user_id = …`` is refused by the
    very trigger this module installs.

    **Everything here must run inside one transaction**, which is what makes it
    safe. ``DROP TRIGGER`` takes ACCESS EXCLUSIVE on ``audit_logs``, and DDL in
    PostgreSQL is transactional, so no other session ever observes a window in
    which the table is mutable — concurrent writers block on the lock and are
    released against the final state, whatever it turns out to be.

    On failure the trigger is restored by the caller's ``ROLLBACK``, not by
    this function. That is deliberate: after an error the transaction is
    aborted and any statement issued inside a ``finally`` would itself fail
    with ``current transaction is aborted``, converting a clear error into a
    confusing one. Re-creating only on the success path means the two possible
    end states are "backfilled, trigger present" and "nothing changed, trigger
    present" — never "trigger missing".

    The rejected alternative was widening ``audit_logs_reject_mutation`` to
    permit the backfill's shape. That would leave a permanent hole allowing
    ``actor_username`` to be rewritten on any row at any time, to buy a
    one-off migration convenience.
    """
    conn.execute(text(f"DROP TRIGGER IF EXISTS audit_logs_immutable ON {PARENT}"))
    log.warning(
        "audit_logs append-only trigger suspended for a maintenance block; "
        "it is restored before this transaction commits"
    )
    yield
    _create_mutation_trigger(conn)
    log.info("audit_logs append-only trigger restored")


def apply_audit_immutability(conn, app_role: str | None = None) -> dict:
    """
    Install all three layers. Idempotent — safe to run on every boot.

    `app_role` defaults to the role executing this, which is the application's
    own role in both callers.
    """
    if app_role is None:
        app_role = conn.execute(text("SELECT current_user")).scalar()

    conn.execute(text(_REJECT_MUTATION_FN))
    conn.execute(text(_REJECT_TRUNCATE_FN))

    _create_mutation_trigger(conn)

    # TRUNCATE triggers are statement-level and are *not* cloned to partitions,
    # so each leaf needs its own. A partition added later needs one too — see
    # tests/audit/test_audit_immutability.py, which fails if one is missing.
    partitions = leaf_partitions(conn, PARENT)
    conn.execute(text(f"DROP TRIGGER IF EXISTS audit_logs_no_truncate ON {PARENT}"))
    conn.execute(
        text(
            f"""
            CREATE TRIGGER audit_logs_no_truncate
            BEFORE TRUNCATE ON {PARENT}
            FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_reject_truncate()
            """
        )
    )
    for part in partitions:
        conn.execute(text(f"DROP TRIGGER IF EXISTS {part}_no_truncate ON {part}"))
        conn.execute(
            text(
                f"""
                CREATE TRIGGER {part}_no_truncate
                BEFORE TRUNCATE ON {part}
                FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_reject_truncate()
                """
            )
        )

    # TRUNCATE only.
    #
    # UPDATE and DELETE both have to stay granted, and the reason is the same
    # for each: PostgreSQL performs a referential action with the privileges of
    # the role issuing the statement, not the table owner. Revoking UPDATE was
    # measured to break account deletion, and revoking DELETE breaks
    # organisation deletion — both with `permission denied for table
    # audit_logs`. The trigger carries those two layers instead, and it is the
    # stronger control anyway: it still refuses after an owner re-grants itself
    # the privilege, which a REVOKE does not survive.
    #
    # TRUNCATE has no legitimate caller in the running application, so it is
    # revoked as well as trigger-guarded.
    conn.execute(text(f'REVOKE TRUNCATE ON {PARENT} FROM "{app_role}"'))
    for part in partitions:
        conn.execute(text(f'REVOKE TRUNCATE ON {part} FROM "{app_role}"'))

    log.info(
        "audit_logs append-only enforcement applied "
        "(row trigger + %d truncate triggers, DELETE/TRUNCATE revoked from %s)",
        len(partitions) + 1,
        app_role,
    )
    return {"partitions": len(partitions), "app_role": app_role}


def remove_audit_immutability(conn, app_role: str | None = None) -> None:
    """Reverse `apply_audit_immutability`. Used by the migration's downgrade."""
    if app_role is None:
        app_role = conn.execute(text("SELECT current_user")).scalar()

    partitions = leaf_partitions(conn, PARENT)
    for part in partitions:
        conn.execute(text(f"DROP TRIGGER IF EXISTS {part}_no_truncate ON {part}"))
        conn.execute(text(f'GRANT TRUNCATE ON {part} TO "{app_role}"'))
    conn.execute(text(f"DROP TRIGGER IF EXISTS audit_logs_no_truncate ON {PARENT}"))
    conn.execute(text(f"DROP TRIGGER IF EXISTS audit_logs_immutable ON {PARENT}"))
    conn.execute(text("DROP FUNCTION IF EXISTS audit_logs_reject_truncate()"))
    conn.execute(text("DROP FUNCTION IF EXISTS audit_logs_reject_mutation()"))
    conn.execute(text(f'GRANT TRUNCATE ON {PARENT} TO "{app_role}"'))
    log.info("audit_logs append-only enforcement removed")


#: Where the chain machinery can legitimately live. `audit_chain` is the
#: current home; `public` is where it was installed before the schema-isolation
#: change and is still accepted so a database that has not been migrated yet is
#: recognised rather than reported as having no chain at all.
CHAIN_SCHEMAS = ("audit_chain", "public")


def chain_objects_installed(conn) -> dict:
    """
    Where the chain machinery is, if anywhere — checked in **both** schemas.

    This exists because the schema move would otherwise create a silent and
    dangerous false negative. Migration ``a7b8c9d0e1f2``'s downgrade refuses to
    run while the chain is installed, and it decides that by looking for
    ``public.audit_chain_heads``. Once the table moves to ``audit_chain`` that
    lookup returns NULL, the guard concludes there is no chain, and a downgrade
    is permitted that drops ``record_hash`` and ``prev_hash`` out from under a
    live, armed chain.

    That migration is already applied and is deliberately **not** edited. The
    correction is forward-compatible instead: revision ``b8c9d0e1f2a3`` sits on
    top of it and refuses to downgrade past itself while the chain exists
    anywhere. Alembic unwinds newest-first, so that guard is reached before
    ``a7b8c9d0e1f2.downgrade()`` can run.

    Returns a dict rather than a bool because callers need to distinguish
    "not installed" from "installed in the old location" — the second is a
    prompt to run the bootstrap again, not an error.

    Invoked from:
      * ``alembic/versions/b8c9d0e1f2a3_audit_chain_schema_guard.py``
        (downgrade refusal — the load-bearing use),
      * ``log_audit_chain_state()`` below (startup reporting),
      * ``scripts/audit/verify_chain.py`` and ``verify_chain_bootstrap.py``.
    """
    state = {
        "schema": None,
        "table": False,
        "trigger": False,
        "trigger_points_at": None,
        "installed": False,
        "needs_migration": False,
    }

    for schema in CHAIN_SCHEMAS:
        found = conn.execute(
            text("SELECT to_regclass(:q)"), {"q": f"{schema}.audit_chain_heads"}
        ).scalar()
        if found:
            state["schema"] = schema
            state["table"] = True
            break

    points_at = conn.execute(
        text(
            "SELECT n.nspname || '.' || p.proname "
            "  FROM pg_trigger t "
            "  JOIN pg_proc p ON p.oid = t.tgfoid "
            "  JOIN pg_namespace n ON n.oid = p.pronamespace "
            " WHERE t.tgname = 'audit_logs_chain' LIMIT 1"
        )
    ).scalar()
    state["trigger"] = points_at is not None
    state["trigger_points_at"] = points_at

    state["installed"] = state["table"] and state["trigger"]
    # Installed, but still in the pre-isolation location: the application role
    # may be able to drop it, depending on who owns `public`.
    state["needs_migration"] = state["installed"] and state["schema"] == "public"
    return state


def log_audit_chain_state() -> None:
    """
    Report at startup whether the tamper-evidence chain is armed.

    Called from `main.py`'s lifespan, not at import, for the same reason
    `log_trust_boundary()` is: `main.py` imports every router before it reaches
    `logging.basicConfig`, so anything logged at import time is emitted with no
    handlers installed — INFO vanishes entirely and WARNING survives only via
    `logging.lastResort`, unformatted and without the logger name.

    Reaching Alembic head does **not** mean the chain is installed. Its
    privileged half is applied by a database administrator running
    `scripts/audit/bootstrap_chain.sql` as a superuser, because the application
    role holds neither SUPERUSER nor CREATEROLE. A deployment that migrated but
    never ran it behaves completely normally while writing audit events that
    carry no hash and can never be verified — which is precisely the kind of
    silent gap this whole phase exists to close, so it is logged at WARNING
    rather than left to be noticed.

    Never raises: an unavailable database at startup is already handled below
    this call, and a diagnostic must not be the thing that stops the API from
    booting.
    """
    try:
        from db.base import engine

        with engine.connect() as conn:
            state = chain_objects_installed(conn)
            if state["installed"]:
                # Schema-qualified from the discovered location, never bare:
                # the application role owns `public` on some databases and
                # could create a shadow `audit_chain_heads` there.
                stats = conn.execute(
                    text(
                        "SELECT count(*), coalesce(sum(event_count), 0), "
                        "       coalesce(sum(legacy_event_count), 0) "
                        f"  FROM {state['schema']}.audit_chain_heads"
                    )
                ).fetchone()
                log.info(
                    "Audit tamper-evidence chain ARMED — %s organisation(s), "
                    "%s chained event(s), %s legacy event(s) predating the chain "
                    "(not verifiable) [schema: %s]",
                    stats[0],
                    stats[1],
                    stats[2],
                    state["schema"],
                )
                if state["needs_migration"]:
                    # Installed and working, but in the pre-isolation location.
                    # Whether the application role can remove it depends on who
                    # owns `public`, so this is a prompt rather than an alarm.
                    log.warning(
                        "Audit chain is installed in schema `public` rather than "
                        "`audit_chain`. Where the application role owns `public` "
                        "it can DROP the chain machinery, because a schema owner "
                        "may drop objects it does not own. Re-run "
                        "scripts/audit/bootstrap_chain.sql as a superuser to move "
                        "it; existing chain state is preserved."
                    )
            else:
                unchained = conn.execute(
                    text("SELECT count(*) FROM audit_logs WHERE record_hash IS NULL")
                ).scalar()
                log.warning(
                    "Audit tamper-evidence chain NOT INSTALLED — %s audit event(s) "
                    "carry no hash and cannot be verified. A database "
                    "administrator must run scripts/audit/bootstrap_chain.sql as "
                    "a superuser; the application role cannot install it. "
                    "(head table: %s, insert trigger: %s)",
                    unchained,
                    "present" if has_table else "missing",
                    "present" if has_trigger else "missing",
                )
    except Exception as exc:  # noqa: BLE001 - a diagnostic must never block boot
        log.warning(
            "Could not determine audit chain state at startup: %s: %s",
            exc.__class__.__name__,
            exc,
        )

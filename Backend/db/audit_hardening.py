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
            has_table = bool(
                conn.execute(
                    text("SELECT to_regclass('public.audit_chain_heads')")
                ).scalar()
            )
            has_trigger = bool(
                conn.execute(
                    text(
                        "SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_chain' "
                        "LIMIT 1"
                    )
                ).scalar()
            )
            if has_table and has_trigger:
                stats = conn.execute(
                    text(
                        "SELECT count(*), coalesce(sum(event_count), 0), "
                        "       coalesce(sum(legacy_event_count), 0) "
                        "  FROM audit_chain_heads"
                    )
                ).fetchone()
                log.info(
                    "Audit tamper-evidence chain ARMED — %s organisation(s), "
                    "%s chained event(s), %s legacy event(s) predating the chain "
                    "(not verifiable)",
                    stats[0],
                    stats[1],
                    stats[2],
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

"""audit_logs append-only trigger: narrow DELETE escape for phase 6a retention

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-08-25

What this changes
─────────────────
One branch of ``audit_logs_reject_mutation``. The DELETE path gains a second
escape beside the existing "the owning organisation is already gone" one:

    IF current_user = 'audit_maintenance'
       AND OLD.record_hash IS NULL THEN RETURN OLD; END IF;

Both halves are load-bearing.

``current_user = 'audit_maintenance'`` is true only inside
``audit_retention.purge_legacy_v1()``, which is SECURITY DEFINER and owned by
that role. ``current_user`` reflects the definer during the function's
execution and is not settable by the caller, so the application role running
ordinary SQL never satisfies it. This is not a session variable — the first
draft of the phase-3 design used one, and a GUC the application's own role can
set is not an authorization boundary.

``OLD.record_hash IS NULL`` is the phase boundary, enforced by PostgreSQL
rather than by care. Phase 6a removes **legacy** rows — those written before
the tamper-evidence chain existed. Nothing can ever have linked to one:
``prev_hash`` references a ``record_hash`` value and a legacy row has none. So
their removal cannot break a chain for any dataset, past or future. With this
clause the maintenance role is *incapable* of deleting a chained row, even
through its own function, even if that function's predicate were wrong.
Widening it is phase 6b and needs its own approval and its own revision.

What this does not change
─────────────────────────
UPDATE and TRUNCATE protection are untouched. The application role's ability
to delete or update an audit row is unchanged — it has neither, and gains
neither. No chain object, no ``audit_chain`` function, no column.

Why the change lives in ``db/audit_hardening.py`` and not in this file
─────────────────────────────────────────────────────────────────────
This project builds its schema two ways: a fresh install runs
``Base.metadata.create_all()`` plus ``db/migrate_production_schema.py``, an
existing install runs ``alembic upgrade head``. DDL written only here would
never execute on a fresh install. Both paths call
``apply_audit_immutability``, so the trigger body has exactly one definition
and this revision simply re-applies it.

Downgrade
─────────
Reinstates the trigger without the escape, which is safe and complete: the
retention objects live in the ``audit_retention`` schema and are created by a
privileged bootstrap this migration does not manage. After downgrading, a
purge attempt fails at the trigger — refusing to delete is always the safe
direction. The bootstrap's own objects are deliberately left alone: an anchor
is the only record that a purge happened, and dropping the table that holds it
would erase the history of the deletions it describes.
"""

from alembic import op
from db.audit_hardening import apply_audit_immutability

revision = "c9d0e1f2a3b4"
down_revision = "b8c9d0e1f2a3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    # CREATE OR REPLACE FUNCTION, then re-create the trigger. Idempotent, and
    # it does not touch the chain trigger, the head table or any data.
    result = apply_audit_immutability(conn)
    print(
        f"  audit_logs append-only trigger re-applied with the phase 6a "
        f"retention escape ({result})"
    )


def downgrade() -> None:
    """Reinstate the trigger without the retention escape.

    Done by rewriting the function body inline rather than by importing an old
    version of it: the module always carries the *current* definition, so
    importing from it would reinstall the escape this downgrade exists to
    remove.
    """
    conn = op.get_bind()
    from sqlalchemy import text

    conn.execute(
        text(
            """
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
                        'audit_logs is append-only: DELETE is not permitted '
                        '(attempted by %)', current_user
                        USING ERRCODE = '42501';
                END IF;

                IF NEW.user_id IS NULL
                   AND OLD.user_id IS NOT NULL
                   AND (to_jsonb(NEW) - 'user_id') = (to_jsonb(OLD) - 'user_id') THEN
                    RETURN NEW;
                END IF;

                RAISE EXCEPTION
                    'audit_logs is append-only: UPDATE is not permitted '
                    '(attempted by %)', current_user
                    USING ERRCODE = '42501';
            END;
            $fn$
            """
        )
    )
    print(
        "  audit_logs append-only trigger reinstated WITHOUT the retention "
        "escape; any purge attempt will now be refused by the trigger"
    )

"""audit_logs append-only trigger: chained retention behind a tip guard

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-08-26

What this changes
─────────────────
The DELETE branch of ``audit_logs_reject_mutation``. Revision
``c9d0e1f2a3b4`` permitted a maintenance DELETE only when
``OLD.record_hash IS NULL`` — so the maintenance role was *incapable* of
removing a chained row, enforced by PostgreSQL rather than by care.

Phase 6c exists to remove chained rows, so that clause cannot survive it.
What replaces it is narrower but real, and it guards the one deletion that is
genuinely unrecoverable:

    IF current_user = 'audit_maintenance' THEN
        IF audit_chain.audit_chain_is_tip_v1(OLD.org_id, OLD.id) THEN
            RAISE EXCEPTION 'refusing to delete the current chain tip';
        END IF;
        RETURN OLD;
    END IF;

**The chain tip can never be deleted, by anyone, ever.** Removing it would
leave ``last_record_hash`` naming a row that no longer exists, and the next
insert would link to a hash nothing can resolve — permanently unverifiable,
and unfixable afterwards. Checked per row, so it holds even if the purge
function's predicate is wrong or it is called with the wrong arguments.

Be clear-eyed about the trade: this **is** a reduction in what the database
guarantees by itself. Phase 6a's guard could not be kept by a phase whose
purpose is chained deletion. The compensating controls all live in
``audit_retention.purge_chained_v1`` — a mandatory verified archive, a
contiguous prefix from genesis, an anchor written before the deletion — and
those are function-level, not database-level. The tip guard is what remains
enforced regardless of them.

``audit_chain_is_tip_v1`` is resolved at runtime, not at function creation, so
this revision applies cleanly to a database that has never had the retention
bootstrap. On such a database the branch is unreachable anyway:
``current_user`` can only be ``audit_maintenance`` inside a function owned by
that role, and no such function exists until a DBA installs one.

What this does not change
─────────────────────────
UPDATE and TRUNCATE protection. The application role's privileges — it has
neither DELETE nor UPDATE through any application path, and gains neither. No
chain object, no ``audit_chain`` function, no column, no grant.

Downgrade
─────────
Reinstates the phase-6a form, in which a maintenance DELETE is permitted only
for unhashed rows. That is safe and complete on its own: after downgrading, a
chained purge fails at the trigger, which is the safe direction.

It deliberately does **not** touch ``audit_retention``. Dropping an anchor
would erase the continuity evidence for a chained purge that already happened,
leaving the affected organisations permanently unverifiable — so the anchors
stay, and ``verify_chain.py`` keeps reading them.
"""

from alembic import op
from db.audit_hardening import apply_audit_immutability

revision = "d0e1f2a3b4c5"
down_revision = "c9d0e1f2a3b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    result = apply_audit_immutability(conn)
    print(
        f"  audit_logs append-only trigger re-applied with the phase 6c tip "
        f"guard ({result})"
    )


def downgrade() -> None:
    """Reinstate the phase-6a form: maintenance may delete unhashed rows only.

    Written inline rather than imported from ``db/audit_hardening.py``: that
    module always carries the *current* definition, so importing from it would
    reinstall the very clause this downgrade exists to remove.
    """
    from sqlalchemy import text

    conn = op.get_bind()

    chained = conn.execute(
        text(
            "SELECT count(*) FROM audit_retention.retention_anchors "
            " WHERE kind = 'chained'"
        )
        if conn.execute(
            text("SELECT to_regclass('audit_retention.retention_anchors')")
        ).scalar()
        else text("SELECT 0")
    ).scalar()

    if chained:
        # Not a blanket refusal — the trigger change itself is reversible, and
        # narrowing it is safe. This is a loud warning because the state it
        # describes is one an operator should know they are in: chained rows
        # have already been removed under anchors this downgrade leaves in
        # place, and `verify_chain.py` will keep relying on them.
        print(
            f"  WARNING: {chained} chained retention anchor(s) exist. Their "
            f"organisations' chains start above a purge boundary and remain "
            f"verifiable ONLY through those anchors. This downgrade leaves them "
            f"intact; do not drop audit_retention."
        )

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

                    IF current_user = 'audit_maintenance'
                       AND OLD.record_hash IS NULL THEN
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
        "  audit_logs append-only trigger narrowed to the phase-6a form; "
        "chained purges will now be refused by the trigger"
    )

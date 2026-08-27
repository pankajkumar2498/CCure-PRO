"""audit chain schema-location guard

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-08-25

A guard revision. It changes no schema and writes no data.

Why it exists
─────────────
Revision ``a7b8c9d0e1f2`` adds ``prev_hash``/``record_hash`` to ``audit_logs``
and its ``downgrade()`` refuses to run while the chain is installed — dropping
those columns under a live chain would destroy every link irrecoverably. It
decides "is the chain installed?" by looking for ``public.audit_chain_heads``.

The chain machinery has since moved to a dedicated ``audit_chain`` schema, so
that lookup now returns NULL on a fully-hardened database. The guard would
conclude there is no chain and permit exactly the destructive downgrade it was
written to prevent.

``a7b8c9d0e1f2`` is already applied and is **not** edited: rewriting applied
history is how two databases end up believing different things about the same
revision. The fix is forward-compatible instead. This revision sits on top of
it, and Alembic unwinds newest-first — so ``downgrade()`` here runs *before*
``a7b8c9d0e1f2.downgrade()`` can, and refuses first.

The check is ``db.audit_hardening.chain_objects_installed()``, which looks in
both ``audit_chain`` and ``public``. A database in either state is protected,
including one that has not had the schema move applied yet.

Note that this revision therefore has real teeth despite being a schema no-op:
downgrading past it is blocked whenever a chain exists, in either location.
"""

import sqlalchemy as sa
from alembic import op
from db.audit_hardening import chain_objects_installed

revision = "b8c9d0e1f2a3"
down_revision = "a7b8c9d0e1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """
    No schema change.

    The guard lives in ``downgrade()``. Upgrading simply records that this
    database understands the chain may live in either schema; it reports where
    the chain currently is so the migration log carries that fact.
    """
    conn = op.get_bind()
    state = chain_objects_installed(conn)

    if not state["installed"]:
        print(
            "[b8c9d0e1f2a3] audit chain is not installed on this database. "
            "Downgrade protection is armed regardless — it will refuse if a "
            "chain appears in either `audit_chain` or `public`."
        )
        return

    print(
        f"[b8c9d0e1f2a3] audit chain detected in schema `{state['schema']}` "
        f"(trigger -> {state['trigger_points_at']}). Downgrades past this "
        f"revision are now refused while it exists."
    )
    if state["needs_migration"]:
        print(
            "[b8c9d0e1f2a3] NOTE: the chain is still in `public`. Where the "
            "application role owns that schema it can drop the chain "
            "machinery, because a schema owner may drop objects it does not "
            "own. Re-run scripts/audit/bootstrap_chain.sql as a superuser to "
            "move it into `audit_chain`; existing chain state is preserved."
        )


def downgrade() -> None:
    """
    Refuse while a chain exists in **either** schema.

    This is the whole point of the revision. Alembic unwinds newest-first, so
    raising here stops the run before ``a7b8c9d0e1f2.downgrade()`` can drop
    ``prev_hash`` and ``record_hash``.

    Removing the chain is a deliberate, privileged act: only a database
    administrator can do it, because the objects are owned by
    ``audit_chain_writer``. Requiring that step before a destructive downgrade
    is the intended friction, not an obstacle to work around.
    """
    conn = op.get_bind()
    state = chain_objects_installed(conn)

    if state["installed"]:
        chained = conn.execute(
            sa.text("SELECT count(*) FROM audit_logs WHERE record_hash IS NOT NULL")
        ).scalar()
        raise RuntimeError(
            "Refusing to downgrade: the audit tamper-evidence chain is "
            f"installed in schema `{state['schema']}` and {chained} event(s) "
            "carry hashes.\n"
            "\n"
            "Downgrading past this revision reaches a7b8c9d0e1f2, which drops "
            "`prev_hash` and `record_hash` from audit_logs. Those links cannot "
            "be reconstructed afterwards — re-upgrading would leave every "
            "existing event permanently unverifiable.\n"
            "\n"
            "If the removal is genuinely intended, a database administrator "
            "must first remove the chain objects (see the 'To undo' section of "
            "docs/AUDIT_CHAIN_DBA_HANDOFF.md), take a verified backup, and then "
            "retry. This guard checks both `audit_chain` and `public`, so "
            "moving the schema does not bypass it."
        )

    print(
        "[b8c9d0e1f2a3] no audit chain installed; downgrade permitted to "
        "continue to a7b8c9d0e1f2."
    )

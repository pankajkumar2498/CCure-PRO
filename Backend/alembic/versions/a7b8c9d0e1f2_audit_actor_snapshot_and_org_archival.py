"""audit actor snapshot, chain columns, and organisation archival

Revision ID: a7b8c9d0e1f2
Revises: f5a6b7c8d9e0
Create Date: 2026-08-24

Phase 4, step 1 — everything the application's own database role is able to do.

What this migration deliberately does NOT do
────────────────────────────────────────────
It does not create the hash chain. The chain needs a dedicated
``audit_chain_writer`` role that owns ``audit_chain_heads`` and the canonical
hash functions, and ``ccure_user`` — the role Alembic connects as — holds
neither SUPERUSER nor CREATEROLE. Measured on this deployment:

    CREATE ROLE probe_chain_writer   -> permission denied to create role
    ALTER TABLE audit_logs OWNER TO admin
                                     -> must be able to SET ROLE "admin"

Granting ``ccure_user`` CREATEROLE to work around this would defeat the
control it exists to build: from PostgreSQL 16 a CREATEROLE role becomes admin
of the roles it creates, so it could ``SET ROLE audit_chain_writer`` and write
chain heads directly.

So the chain lands in ``scripts/audit/bootstrap_chain.sql``, run once by a
database administrator as ``postgres``. **Reaching this revision does not mean
the chain is active.** ``main.py``'s lifespan logs loudly when it is not, and
``scripts/audit/verify_chain_bootstrap.py`` reports it.

The actor snapshot, and why it needs the trigger suspended
─────────────────────────────────────────────────────────
``audit_logs.user_id`` is ``ON DELETE SET NULL``, so deleting an account
erases the actor from every event it ever produced. On this deployment that had
already happened to **88 of 511 events (17%)** before this migration — and not
to anonymous ones: the affected actions include 27 successful ``user.login``,
11 ``user.logout`` and 11 ``user.profile_updated``, every call site of which
passes a real user object.

``actor_user_id`` / ``actor_username`` are frozen copies carrying no foreign
key, so no referential action can reach them.

Backfilling them is an ``UPDATE`` on ``audit_logs``, which the append-only
trigger installed by revision ``f5a6b7c8d9e0`` refuses outright. It is
therefore performed inside ``suspended_immutability()``. That is safe because
``DROP TRIGGER`` takes ACCESS EXCLUSIVE and DDL is transactional in
PostgreSQL: no other session can observe a mutable window — concurrent writers
block on the lock and are released against whichever end state this
transaction reaches. ``alembic/env.py`` wraps the whole upgrade in a single
``context.begin_transaction()``, so that guarantee holds across every statement
here.

The 88 already-orphaned rows are **not** backfilled and never can be — the
identity is gone. They remain legacy and unattributable, and that is reported
rather than papered over.

Downgrade
─────────
Schema-reversible, **not** data-loss-free. Dropping these columns permanently
discards every actor snapshot and, once the chain is live, every hash — and
re-upgrading cannot reconstruct the chain, because the ``prev_hash`` links are
gone. Requires a verified backup and explicit approval.

The downgrade **refuses to run while chain objects exist**, because the
canonical hash function takes ``audit_logs`` as a row type and the trigger
reads these columns; removing them underneath would leave a function that
fails at runtime rather than at drop time. Chain objects are owned by
``audit_chain_writer`` and can only be removed by the DBA.
"""

import sqlalchemy as sa
from alembic import op
from db.audit_hardening import suspended_immutability

revision = "a7b8c9d0e1f2"
down_revision = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def _chain_is_installed(conn) -> bool:
    return bool(
        conn.execute(
            sa.text("SELECT 1 FROM pg_trigger WHERE tgname = 'audit_logs_chain'")
        ).scalar()
        or conn.execute(
            sa.text("SELECT to_regclass('public.audit_chain_heads')")
        ).scalar()
    )


def upgrade() -> None:
    conn = op.get_bind()

    # ── audit_logs: actor snapshot + chain columns ───────────────────────────
    # Nullable with no default, so this is a catalogue-only change in
    # PostgreSQL 11+ and does not rewrite the table. Adding to the partitioned
    # parent propagates to all eight leaves automatically.
    #
    # VARCHAR(64) rather than CHAR(64) for the hashes: the values are always
    # exactly 64 hex characters, but `char(n)` blank-pads and strips trailing
    # spaces when cast to text, which is a hazard in columns whose whole
    # purpose is exact comparison.
    op.add_column(
        "audit_logs", sa.Column("actor_user_id", sa.String(150), nullable=True)
    )
    op.add_column(
        "audit_logs", sa.Column("actor_username", sa.String(100), nullable=True)
    )
    op.add_column("audit_logs", sa.Column("prev_hash", sa.String(64), nullable=True))
    op.add_column("audit_logs", sa.Column("record_hash", sa.String(64), nullable=True))

    # ── organizations: archival ──────────────────────────────────────────────
    op.add_column(
        "organizations",
        sa.Column("archived_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "organizations", sa.Column("archived_by_user_id", sa.String(150), nullable=True)
    )
    op.add_column(
        "organizations", sa.Column("archive_reason", sa.Text(), nullable=True)
    )

    # ── backfill the snapshot from the live relationship only ───────────────
    with suspended_immutability(conn):
        result = conn.execute(
            sa.text(
                """
                UPDATE audit_logs AS a
                   SET actor_user_id  = u.id,
                       actor_username = u.username
                  FROM users AS u
                 WHERE a.user_id = u.id
                   AND a.actor_user_id IS NULL
                """
            )
        )
        backfilled = result.rowcount

    orphaned = conn.execute(
        sa.text("SELECT count(*) FROM audit_logs WHERE user_id IS NULL")
    ).scalar()
    print(
        f"[a7b8c9d0e1f2] actor snapshot backfilled for {backfilled} rows; "
        f"{orphaned} rows remain legacy/unattributable (actor already erased)"
    )


def downgrade() -> None:
    conn = op.get_bind()

    if _chain_is_installed(conn):
        raise RuntimeError(
            "Refusing to downgrade: audit chain objects are installed. The "
            "canonical hash function takes audit_logs as a row type and the "
            "chain trigger reads the columns this downgrade removes. Have a "
            "database administrator remove the chain objects first "
            "(scripts/audit/bootstrap_chain.sql documents them), then retry. "
            "This downgrade permanently discards actor snapshots and hashes — "
            "take a verified backup before proceeding."
        )

    op.drop_column("organizations", "archive_reason")
    op.drop_column("organizations", "archived_by_user_id")
    op.drop_column("organizations", "archived_at")

    op.drop_column("audit_logs", "record_hash")
    op.drop_column("audit_logs", "prev_hash")
    op.drop_column("audit_logs", "actor_username")
    op.drop_column("audit_logs", "actor_user_id")

"""Account approval gate, email verification tokens, per-org scan scope.

Revision ID: b1c2d3e4f5a6
Revises: c3h4i5j6k7l8
Create Date: 2026-08-17

Closes the two unauthorised-access paths that self-service registration opened.

1. ``POST /auth/register`` created an account and returned working access and
   refresh tokens in the same response, in the ``analyst`` role — which carries
   ``scans:execute``. Anyone able to reach the endpoint could issue themselves a
   credential that runs Nmap, Scapy and Nuclei from a worker holding raw-socket
   privileges on the host network. ``users.approved_at`` adds the second gate:
   an account is inert until a human with admin rights stamps it.

   Existing rows are backfilled with ``approved_at = created_at``. They were all
   provisioned by an administrator, and leaving them NULL would lock out the
   entire current userbase on deploy.

2. ``email_verification_tokens`` gives registration somewhere to prove control
   of the mailbox. It mirrors ``password_reset_tokens`` — SHA-256 hash only,
   ``expires_at``, single-use by row deletion — deliberately as a separate table
   rather than a ``purpose`` column, so a bug in one flow cannot mint a token
   the other accepts.

3. ``organizations.scan_scope_cidrs`` is the authorisation boundary that did not
   previously exist for scan targets. NULL means unconfigured; the column is
   nullable precisely so this migration does not stop every existing
   organisation from scanning the moment it lands. Populate it, then set
   ``REQUIRE_SCAN_SCOPE=True`` to make NULL fail closed.

The downgrade drops all three. It cannot restore ``approved_at`` values, but
nothing reads them once the column is gone.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "b1c2d3e4f5a6"
down_revision = "c3h4i5j6k7l8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    user_columns = {col["name"] for col in inspector.get_columns("users")}

    if "approved_at" not in user_columns:
        op.add_column(
            "users",
            sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        )
        # Backfill before anything reads the column: every pre-existing account
        # was admin-provisioned and must keep working.
        op.execute(
            "UPDATE users SET approved_at = created_at WHERE approved_at IS NULL"
        )

    if "approved_by" not in user_columns:
        op.add_column(
            "users", sa.Column("approved_by", sa.String(length=150), nullable=True)
        )

    org_columns = {col["name"] for col in inspector.get_columns("organizations")}
    if "scan_scope_cidrs" not in org_columns:
        op.add_column(
            "organizations",
            sa.Column("scan_scope_cidrs", postgresql.JSONB(), nullable=True),
        )

    if "email_verification_tokens" not in inspector.get_table_names():
        op.create_table(
            "email_verification_tokens",
            sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
            sa.Column("user_id", sa.String(length=150), nullable=False),
            sa.Column("token_hash", sa.String(length=255), nullable=False),
            sa.Column("email", sa.String(length=320), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("CURRENT_TIMESTAMP"),
                nullable=False,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(
                ["user_id"],
                ["users.id"],
                ondelete="CASCADE",
                onupdate="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "ix_email_verification_tokens_user_id",
            "email_verification_tokens",
            ["user_id"],
        )
        op.create_index(
            "ix_email_verification_tokens_token_hash",
            "email_verification_tokens",
            ["token_hash"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    if "email_verification_tokens" in inspector.get_table_names():
        op.drop_index(
            "ix_email_verification_tokens_token_hash",
            table_name="email_verification_tokens",
        )
        op.drop_index(
            "ix_email_verification_tokens_user_id",
            table_name="email_verification_tokens",
        )
        op.drop_table("email_verification_tokens")

    org_columns = {col["name"] for col in inspector.get_columns("organizations")}
    if "scan_scope_cidrs" in org_columns:
        op.drop_column("organizations", "scan_scope_cidrs")

    user_columns = {col["name"] for col in inspector.get_columns("users")}
    if "approved_by" in user_columns:
        op.drop_column("users", "approved_by")
    if "approved_at" in user_columns:
        op.drop_column("users", "approved_at")

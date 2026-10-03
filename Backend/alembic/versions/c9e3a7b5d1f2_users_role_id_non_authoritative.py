"""users.role_id becomes nullable and non-authoritative (RBAC-8).

Revision ID: c9e3a7b5d1f2
Revises: b8d2f6a4c0e1
Create Date: 2026-10-04

Authorization is the RBAC engine over ``rbac_user_roles``; ``users.role_id`` (a foreign
key into the legacy ``roles`` table) no longer decides what an account may do. It is kept
as historical/reporting data and as the source the cutover's reconciliation maps from,
but it is no longer required: a new account holds no legacy role. The column and the
``roles`` / ``permissions`` / ``role_permissions`` tables are *retained, non-authoritative*
(docs/architecture/RBAC_CUTOVER.md); nothing is dropped, so no history is lost and the
migration is trivially reversible.
"""

from alembic import op

revision = "c9e3a7b5d1f2"
down_revision = "b8d2f6a4c0e1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("users", "role_id", nullable=True)
    op.execute(
        "COMMENT ON COLUMN users.role_id IS "
        "'DEPRECATED, non-authoritative: authorization is rbac_user_roles (RBAC-8)'"
    )


def downgrade() -> None:
    # Re-imposing NOT NULL is only possible while every account still has a legacy role.
    op.execute("COMMENT ON COLUMN users.role_id IS NULL")
    op.alter_column("users", "role_id", nullable=False)

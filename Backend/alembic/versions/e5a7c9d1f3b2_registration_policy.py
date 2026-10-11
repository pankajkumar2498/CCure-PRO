"""Persist the administrator's platform-wide registration policy.

Revision ID: e5a7c9d1f3b2
Revises: d4f8b2c6e0a1
"""

from alembic import op
import sqlalchemy as sa

revision = "e5a7c9d1f3b2"
down_revision = "d4f8b2c6e0a1"
branch_labels = None
depends_on = None


def upgrade():
    table = op.create_table(
        "platform_registration_policy",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("self_registration_enabled", sa.Boolean(), nullable=True),
        sa.Column(
            "revision", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(150), nullable=True),
        sa.CheckConstraint("id = 1", name="ck_registration_policy_singleton"),
        sa.CheckConstraint("revision >= 0", name="ck_registration_policy_revision"),
    )
    # Preserve the deployment's effective policy; do not turn signup on.
    op.bulk_insert(table, [{"id": 1, "revision": 0}])


def downgrade():
    op.drop_table("platform_registration_policy")

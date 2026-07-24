"""add updated_at to services

Revision ID: c4e5f6g7h8i9
Revises: b3d4e5f6h7i8
Create Date: 2026-05-22 19:45:00.000000

"""

import sqlalchemy as sa
from alembic import op
from db.base import TIMESTAMPTZ

# revision identifiers, used by Alembic.
revision = "c4e5f6g7h8i9"
down_revision = "b3d4e5f6h7i8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "services",
        sa.Column(
            "updated_at", TIMESTAMPTZ, nullable=True, server_default=sa.text("NOW()")
        ),
    )
    op.execute(
        "UPDATE services SET updated_at = COALESCE(updated_at, created_at, NOW())"
    )
    op.alter_column("services", "updated_at", nullable=False, server_default=None)


def downgrade() -> None:
    op.drop_column("services", "updated_at")

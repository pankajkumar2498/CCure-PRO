"""A migration: the module's own Alembic branch, creating its schema and table.

Revision ID: ex0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "ex0001"
down_revision = None
branch_labels = ("example",)
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS example")
    op.create_table(
        "example_item",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("label", sa.String(50), nullable=False),
        schema="example",
    )


def downgrade() -> None:
    op.drop_table("example_item", schema="example")
    op.execute("DROP SCHEMA IF EXISTS example")

"""add current_task_id to scans

Revision ID: b3d4e5f6h7i8
Revises: a1b2c3d4e5f6
Create Date: 2026-05-19 23:30:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b3d4e5f6h7i8'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'scans',
        sa.Column('current_task_id', sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('scans', 'current_task_id')

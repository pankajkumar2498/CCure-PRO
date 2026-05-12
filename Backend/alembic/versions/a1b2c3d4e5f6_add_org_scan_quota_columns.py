"""add_org_scan_quota_columns

Revision ID: a1b2c3d4e5f6
Revises: 7f96fc2fa41a
Create Date: 2026-05-11 09:33:00.000000

Adds two nullable Integer columns to the organizations table:
  - max_scans_per_day    : per-org override for the rolling 24-h scan limit
  - max_concurrent_scans : per-org override for max simultaneous running scans

NULL means "use the plan default from core/quota.py".
Superadmins can set these to grant or restrict quota per org.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '7f96fc2fa41a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'organizations',
        sa.Column('max_scans_per_day', sa.Integer(), nullable=True),
    )
    op.add_column(
        'organizations',
        sa.Column('max_concurrent_scans', sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('organizations', 'max_concurrent_scans')
    op.drop_column('organizations', 'max_scans_per_day')

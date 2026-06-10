"""add amt inventory records and provenance

Revision ID: j1k2l3m4n5o6
Revises: i0j1k2l3m4n5
Create Date: 2026-06-09 23:55:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'j1k2l3m4n5o6'
down_revision = 'i0j1k2l3m4n5'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # 1. Add provenance column to assets table
    op.add_column(
        'assets',
        sa.Column('provenance', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb"))
    )

    # 2. Create amt_inventory_records table
    op.create_table(
        'amt_inventory_records',
        sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('org_id', sa.String(length=100), nullable=False),
        sa.Column('mac_address_1', postgresql.MACADDR(), nullable=False),
        sa.Column('mac_address_2', postgresql.MACADDR(), nullable=True),
        sa.Column('asset_tag', sa.String(length=100), nullable=True),
        sa.Column('asset_name', sa.String(length=255), nullable=True),
        sa.Column('serial', sa.String(length=255), nullable=True),
        sa.Column('vendor', sa.String(length=255), nullable=True),
        sa.Column('asset_type', sa.String(length=255), nullable=True),
        sa.Column('asset_user', sa.String(length=255), nullable=True),
        sa.Column('emp_id', sa.String(length=100), nullable=True),
        sa.Column('status', sa.String(length=100), nullable=True),
        sa.Column('location', sa.String(length=255), nullable=True),
        sa.Column('location_id', sa.Integer(), nullable=True),
        sa.Column('company_name', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], name='fk_amt_inventory_records_org_id', ondelete='CASCADE')
    )

    # 3. Create indexes
    op.create_index('ix_amt_org_mac1', 'amt_inventory_records', ['org_id', 'mac_address_1'], unique=True)
    op.create_index('ix_amt_org_mac2', 'amt_inventory_records', ['org_id', 'mac_address_2'], unique=False)

def downgrade() -> None:
    op.drop_index('ix_amt_org_mac2', table_name='amt_inventory_records')
    op.drop_index('ix_amt_org_mac1', table_name='amt_inventory_records')
    op.drop_table('amt_inventory_records')
    op.drop_column('assets', 'provenance')

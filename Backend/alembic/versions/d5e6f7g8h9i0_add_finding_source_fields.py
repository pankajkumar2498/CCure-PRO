"""add finding source fields

Revision ID: d5e6f7g8h9i0
Revises: c4e5f6g7h8i9
Create Date: 2026-05-22 23:35:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd5e6f7g8h9i0'
down_revision = 'c4e5f6g7h8i9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'asset_vulnerabilities',
        sa.Column('source_family', sa.String(length=50), nullable=False, server_default='unknown'),
    )
    op.add_column(
        'asset_vulnerabilities',
        sa.Column('evidence_source', sa.String(length=50), nullable=False, server_default='unknown'),
    )

    op.execute(
        """
        UPDATE asset_vulnerabilities
        SET
            source_family = CASE
                WHEN proof ILIKE '%Source_Family:credentialed_package%' OR proof ILIKE '%Package:%'
                    THEN 'credentialed_package'
                WHEN proof ILIKE '%Source_Family:network_service%'
                    THEN 'network_service'
                ELSE 'unknown'
            END,
            evidence_source = CASE
                WHEN proof ILIKE '%Source_Family:credentialed_package%' OR proof ILIKE '%Package:%'
                    THEN 'credentialed'
                WHEN proof ILIKE '%Source_Family:network_service%'
                    THEN 'advanced'
                ELSE 'unknown'
            END
        """
    )

    op.create_index('ix_asset_vuln_source_family', 'asset_vulnerabilities', ['source_family'])
    op.create_index('ix_asset_vuln_evidence_source', 'asset_vulnerabilities', ['evidence_source'])
    op.alter_column('asset_vulnerabilities', 'source_family', server_default=None)
    op.alter_column('asset_vulnerabilities', 'evidence_source', server_default=None)


def downgrade() -> None:
    op.drop_index('ix_asset_vuln_evidence_source', table_name='asset_vulnerabilities')
    op.drop_index('ix_asset_vuln_source_family', table_name='asset_vulnerabilities')
    op.drop_column('asset_vulnerabilities', 'evidence_source')
    op.drop_column('asset_vulnerabilities', 'source_family')

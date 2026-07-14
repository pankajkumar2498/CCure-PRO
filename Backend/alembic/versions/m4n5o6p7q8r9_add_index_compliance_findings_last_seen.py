"""add index on compliance_findings.last_seen

Revision ID: m4n5o6p7q8r9
Revises: l3m4n5o6p7q8
Create Date: 2026-07-08 15:05:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "m4n5o6p7q8r9"
down_revision = "l3m4n5o6p7q8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_compliance_findings_last_seen",
        "compliance_findings",
        ["last_seen"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_compliance_findings_last_seen", table_name="compliance_findings")

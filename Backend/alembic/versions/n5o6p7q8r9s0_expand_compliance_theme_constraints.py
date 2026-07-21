"""expand compliance theme constraints and add crosswalk/evidence fields

Revision ID: n5o6p7q8r9s0
Revises: m4n5o6p7q8r9
Create Date: 2026-07-21 18:00:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "n5o6p7q8r9s0"
down_revision = "m4n5o6p7q8r9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add crosswalk and evidence_checklist JSONB columns to compliance_controls if not present
    conn = op.get_bind()

    # Add crosswalk column
    op.add_column(
        "compliance_controls",
        sa.Column("crosswalk", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        "compliance_controls",
        sa.Column(
            "evidence_checklist", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
    )

    # 2. Update PostgreSQL check constraints if running on postgresql
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ('ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ('ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC'));"
            )
        )


def downgrade() -> None:
    op.drop_column("compliance_controls", "evidence_checklist")
    op.drop_column("compliance_controls", "crosswalk")

    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "UPDATE compliance_controls SET theme = 'ORG' WHERE theme NOT IN ('ORG', 'PPL', 'PHY', 'TECH');"
            )
        )
        conn.execute(
            sa.text(
                "UPDATE compliance_scores SET theme = 'ORG' WHERE theme NOT IN ('ORG', 'PPL', 'PHY', 'TECH');"
            )
        )
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ('ORG', 'PPL', 'PHY', 'TECH'));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ('ORG', 'PPL', 'PHY', 'TECH'));"
            )
        )

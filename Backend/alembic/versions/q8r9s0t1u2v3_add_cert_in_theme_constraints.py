"""add CERT-In Directions 2022 & CCMP theme constraints to compliance_controls

Revision ID: q8r9s0t1u2v3
Revises: p7q8r9s0t1u2
Create Date: 2026-07-22 15:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "q8r9s0t1u2v3"
down_revision = "p7q8r9s0t1u2"
branch_labels = None
depends_on = None

CERT_IN_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP'"
)

PREV_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P'"
)


def upgrade() -> None:
    conn = op.get_bind()

    # Update PostgreSQL check constraints if running on postgresql
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ({CERT_IN_THEMES}));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ({CERT_IN_THEMES}));"
            )
        )


def downgrade() -> None:
    conn = op.get_bind()

    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "DELETE FROM compliance_findings WHERE control_id LIKE 'cct_cert_in_%';"
            )
        )
        conn.execute(
            sa.text("DELETE FROM compliance_scores WHERE theme LIKE 'CERT_%';")
        )
        conn.execute(
            sa.text("DELETE FROM compliance_controls WHERE theme LIKE 'CERT_%';")
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ({PREV_THEMES}));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ({PREV_THEMES}));"
            )
        )

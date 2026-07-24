"""add PCI-DSS v4.0 theme constraints, CDE scoping columns, and SAQ profiles

Revision ID: r9s0t1u2v3w4
Revises: q8r9s0t1u2v3
Create Date: 2026-07-22 17:10:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "r9s0t1u2v3w4"
down_revision = "q8r9s0t1u2v3"
branch_labels = None
depends_on = None

PCI_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', "
    "'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', "
    "'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12'"
)

PREV_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP'"
)


def upgrade() -> None:
    conn = op.get_bind()

    # 1. Add CDE scope column to compliance_scan_runs
    op.add_column(
        "compliance_scan_runs",
        sa.Column("cde_scope", sa.String(50), nullable=True),
    )

    # 2. Add CDE scope column to compliance_findings
    op.add_column(
        "compliance_findings",
        sa.Column("cde_scope", sa.String(50), nullable=True),
    )

    # 3. Add SAQ profiles JSONB array column to compliance_controls
    op.add_column(
        "compliance_controls",
        sa.Column(
            "saq_profiles",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
            server_default="[]",
        ),
    )

    # 4. Update PostgreSQL check constraints to include PCI themes
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ({PCI_THEMES}));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ({PCI_THEMES}));"
            )
        )


def downgrade() -> None:
    conn = op.get_bind()

    if conn.dialect.name == "postgresql":
        # Purge PCI-DSS v4.0 findings, scores, and controls
        conn.execute(
            sa.text(
                "DELETE FROM compliance_findings WHERE control_id LIKE 'cct_pci_%';"
            )
        )
        conn.execute(sa.text("DELETE FROM compliance_scores WHERE theme LIKE 'PCI_%';"))
        conn.execute(
            sa.text("DELETE FROM compliance_controls WHERE theme LIKE 'PCI_%';")
        )

        # Restore previous check constraints
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

    # Drop newly added columns (reversible cleanup)
    op.drop_column("compliance_controls", "saq_profiles")
    op.drop_column("compliance_findings", "cde_scope")
    op.drop_column("compliance_scan_runs", "cde_scope")

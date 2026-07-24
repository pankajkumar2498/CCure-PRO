"""add DPDP Act 2023 and GDPR theme constraints, sdf_scope, and privacy_role columns

Revision ID: s0t1u2v3w4x5
Revises: r9s0t1u2v3w4
Create Date: 2026-07-23 10:30:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "s0t1u2v3w4x5"
down_revision = "r9s0t1u2v3w4"
branch_labels = None
depends_on = None

DPDP_GDPR_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', "
    "'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', "
    "'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12', "
    "'DPDP_CN', 'DPDP_PL', 'DPDP_DR', 'DPDP_BN', 'DPDP_PS', 'DPDP_GV', "
    "'GDPR_LT', 'GDPR_PL', 'GDPR_DM', 'GDPR_AY', 'GDPR_SL', 'GDPR_IC', 'GDPR_AC'"
)

PREV_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', "
    "'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', "
    "'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12'"
)


def upgrade() -> None:
    conn = op.get_bind()

    # 1. Add sdf_scope and privacy_role columns to compliance_scan_runs
    op.add_column(
        "compliance_scan_runs",
        sa.Column("sdf_scope", sa.String(50), nullable=True),
    )
    op.add_column(
        "compliance_scan_runs",
        sa.Column("privacy_role", sa.String(50), nullable=True),
    )

    # 2. Add sdf_scope and privacy_role columns to compliance_findings
    op.add_column(
        "compliance_findings",
        sa.Column("sdf_scope", sa.String(50), nullable=True),
    )
    op.add_column(
        "compliance_findings",
        sa.Column("privacy_role", sa.String(50), nullable=True),
    )

    # 3. Add sdf_scope and privacy_role columns to compliance_controls
    op.add_column(
        "compliance_controls",
        sa.Column("sdf_scope", sa.String(50), nullable=True),
    )
    op.add_column(
        "compliance_controls",
        sa.Column("privacy_role", sa.String(50), nullable=True),
    )

    # 4. Update PostgreSQL check constraints to include DPDP and GDPR themes
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ({DPDP_GDPR_THEMES}));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ({DPDP_GDPR_THEMES}));"
            )
        )


def downgrade() -> None:
    conn = op.get_bind()

    if conn.dialect.name == "postgresql":
        # Purge DPDP 2023 & GDPR findings, scores, and controls
        conn.execute(
            sa.text(
                "DELETE FROM compliance_findings WHERE control_id LIKE 'cct_dpdp_%' OR control_id LIKE 'cct_gdpr_%';"
            )
        )
        conn.execute(
            sa.text(
                "DELETE FROM compliance_scores WHERE theme LIKE 'DPDP_%' OR theme LIKE 'GDPR_%';"
            )
        )
        conn.execute(
            sa.text(
                "DELETE FROM compliance_controls WHERE theme LIKE 'DPDP_%' OR theme LIKE 'GDPR_%';"
            )
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

    # Drop newly added columns
    op.drop_column("compliance_controls", "privacy_role")
    op.drop_column("compliance_controls", "sdf_scope")
    op.drop_column("compliance_findings", "privacy_role")
    op.drop_column("compliance_findings", "sdf_scope")
    op.drop_column("compliance_scan_runs", "privacy_role")
    op.drop_column("compliance_scan_runs", "sdf_scope")

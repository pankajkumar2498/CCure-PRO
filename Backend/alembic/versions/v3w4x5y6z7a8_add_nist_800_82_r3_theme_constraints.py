"""add NIST SP 800-82 Rev. 3 theme constraints

Revision ID: v3w4x5y6z7a8
Revises: u2v3w4x5y6z7
Create Date: 2026-07-23 19:55:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "v3w4x5y6z7a8"
down_revision = "u2v3w4x5y6z7"
branch_labels = None
depends_on = None

NIST_800_82_R3_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', "
    "'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', "
    "'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12', "
    "'DPDP_CN', 'DPDP_PL', 'DPDP_DR', 'DPDP_BN', 'DPDP_PS', 'DPDP_GV', "
    "'GDPR_LT', 'GDPR_PL', 'GDPR_DM', 'GDPR_AY', 'GDPR_SL', 'GDPR_IC', 'GDPR_AC', "
    "'SP53_AC', 'SP53_AT', 'SP53_AU', 'SP53_CA', 'SP53_CM', 'SP53_CP', 'SP53_IA', "
    "'SP53_IR', 'SP53_MA', 'SP53_MP', 'SP53_PE', 'SP53_PL', 'SP53_PM', 'SP53_PS', "
    "'SP53_PT', 'SP53_RA', 'SP53_SA', 'SP53_SC', 'SP53_SI', 'SP53_SR', "
    "'IEC_2_1', 'IEC_2_3', 'IEC_2_4', 'FR1_IAC', 'FR2_UC', 'FR3_SI', 'FR4_DC', "
    "'FR5_RDF', 'FR6_TRE', 'FR7_RA', "
    "'SP82_AC', 'SP82_AU', 'SP82_CM', 'SP82_IA', 'SP82_IR', 'SP82_SC', "
    "'SP82_SI', 'SP82_RA', 'SP82_SA'"
)

PREV_THEMES = (
    "'ORG', 'PPL', 'PHY', 'TECH', 'GV', 'ID', 'PR', 'DE', 'RS', 'RC', "
    "'CIS_01', 'CIS_02', 'CIS_03', 'CIS_04', 'CIS_05', 'CIS_06', 'CIS_07', "
    "'CIS_08', 'CIS_09', 'CIS_10', 'CIS_11', 'CIS_12', 'CIS_13', 'CIS_14', "
    "'CIS_15', 'CIS_16', 'CIS_17', 'CIS_18', "
    "'SOC2_CC', 'SOC2_A', 'SOC2_PI', 'SOC2_C', 'SOC2_P', "
    "'CERT_IR', 'CERT_LOG', 'CERT_AM', 'CERT_VM', 'CERT_AC', 'CERT_DP', "
    "'PCI_01', 'PCI_02', 'PCI_03', 'PCI_04', 'PCI_05', 'PCI_06', 'PCI_07', "
    "'PCI_08', 'PCI_09', 'PCI_10', 'PCI_11', 'PCI_12', "
    "'DPDP_CN', 'DPDP_PL', 'DPDP_DR', 'DPDP_BN', 'DPDP_PS', 'DPDP_GV', "
    "'GDPR_LT', 'GDPR_PL', 'GDPR_DM', 'GDPR_AY', 'GDPR_SL', 'GDPR_IC', 'GDPR_AC', "
    "'SP53_AC', 'SP53_AT', 'SP53_AU', 'SP53_CA', 'SP53_CM', 'SP53_CP', 'SP53_IA', "
    "'SP53_IR', 'SP53_MA', 'SP53_MP', 'SP53_PE', 'SP53_PL', 'SP53_PM', 'SP53_PS', "
    "'SP53_PT', 'SP53_RA', 'SP53_SA', 'SP53_SC', 'SP53_SI', 'SP53_SR', "
    "'IEC_2_1', 'IEC_2_3', 'IEC_2_4', 'FR1_IAC', 'FR2_UC', 'FR3_SI', 'FR4_DC', "
    "'FR5_RDF', 'FR6_TRE', 'FR7_RA'"
)


def upgrade() -> None:
    conn = op.get_bind()

    # Update PostgreSQL check constraints to include NIST SP 800-82 Rev. 3 themes
    if conn.dialect.name == "postgresql":
        conn.execute(
            sa.text(
                "ALTER TABLE compliance_controls DROP CONSTRAINT IF EXISTS ck_control_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_controls ADD CONSTRAINT ck_control_theme CHECK (theme IN ({NIST_800_82_R3_THEMES}));"
            )
        )

        conn.execute(
            sa.text(
                "ALTER TABLE compliance_scores DROP CONSTRAINT IF EXISTS ck_score_theme;"
            )
        )
        conn.execute(
            sa.text(
                f"ALTER TABLE compliance_scores ADD CONSTRAINT ck_score_theme CHECK (theme IN ({NIST_800_82_R3_THEMES}));"
            )
        )


def downgrade() -> None:
    conn = op.get_bind()

    if conn.dialect.name == "postgresql":
        # FK-ordered purge: findings -> scores -> rule_controls -> controls -> tenant_frameworks
        conn.execute(
            sa.text(
                "DELETE FROM compliance_findings WHERE control_id LIKE 'cct_nist_800_82_r3_%';"
            )
        )
        conn.execute(
            sa.text(
                "DELETE FROM compliance_scores WHERE theme IN ('SP82_AC', 'SP82_AU', 'SP82_CM', 'SP82_IA', 'SP82_IR', 'SP82_SC', 'SP82_SI', 'SP82_RA', 'SP82_SA');"
            )
        )
        conn.execute(
            sa.text(
                "DELETE FROM compliance_rule_controls WHERE control_id LIKE 'cct_nist_800_82_r3_%';"
            )
        )
        conn.execute(
            sa.text(
                "DELETE FROM compliance_controls WHERE theme IN ('SP82_AC', 'SP82_AU', 'SP82_CM', 'SP82_IA', 'SP82_IR', 'SP82_SC', 'SP82_SI', 'SP82_RA', 'SP82_SA');"
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

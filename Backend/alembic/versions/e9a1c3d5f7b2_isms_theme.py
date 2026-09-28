"""compliance_controls / compliance_scores: an ``ISMS`` theme

Revision ID: e9a1c3d5f7b2
Revises: d6e7f8a9b0c2
Create Date: 2026-09-28

ISO/IEC 27001:2022's management-system clauses (4.1 … 10.2) join the ISO
catalogue as attestation controls. Until now the catalogue held Annex A only,
so every Policy Pro baseline naming a clause was answered ``UNKNOWN_CONTROL``
— 25 of the 118 requirements in PolicyPro's ISO library.

They need a theme of their own. They are not Annex A controls: they are
mandatory for conformity, never selected or excluded through the Statement of
Applicability, and scoring them under one of Annex A's four themes would move
that theme's figure with requirements it does not contain.

``ck_control_theme`` and ``ck_score_theme`` gain one value, ``ISMS``; the 127
existing values are kept verbatim. The list is spelled out rather than
imported, because a migration must describe the schema as it was.

Downgrade refuses while any control uses the theme: narrowing over such a row
fails at the ALTER with a Postgres error naming the constraint but not the row.
"""

import sqlalchemy as sa
from alembic import op

revision = "e9a1c3d5f7b2"
down_revision = "d6e7f8a9b0c2"
branch_labels = None
depends_on = None

#: Must render byte-identically to ``db.models.compliance.CONTROL_THEMES``.
CONTROL_THEMES = (
    "ORG",
    "PPL",
    "PHY",
    "TECH",
    "GV",
    "ID",
    "PR",
    "DE",
    "RS",
    "RC",
    "CIS_01",
    "CIS_02",
    "CIS_03",
    "CIS_04",
    "CIS_05",
    "CIS_06",
    "CIS_07",
    "CIS_08",
    "CIS_09",
    "CIS_10",
    "CIS_11",
    "CIS_12",
    "CIS_13",
    "CIS_14",
    "CIS_15",
    "CIS_16",
    "CIS_17",
    "CIS_18",
    "SOC2_CC",
    "SOC2_A",
    "SOC2_PI",
    "SOC2_C",
    "SOC2_P",
    "CERT_IR",
    "CERT_LOG",
    "CERT_AM",
    "CERT_VM",
    "CERT_AC",
    "CERT_DP",
    "PCI_01",
    "PCI_02",
    "PCI_03",
    "PCI_04",
    "PCI_05",
    "PCI_06",
    "PCI_07",
    "PCI_08",
    "PCI_09",
    "PCI_10",
    "PCI_11",
    "PCI_12",
    "DPDP_CN",
    "DPDP_PL",
    "DPDP_DR",
    "DPDP_BN",
    "DPDP_PS",
    "DPDP_GV",
    "GDPR_LT",
    "GDPR_PL",
    "GDPR_DM",
    "GDPR_AY",
    "GDPR_SL",
    "GDPR_IC",
    "GDPR_AC",
    "SP53_AC",
    "SP53_AT",
    "SP53_AU",
    "SP53_CA",
    "SP53_CM",
    "SP53_CP",
    "SP53_IA",
    "SP53_IR",
    "SP53_MA",
    "SP53_MP",
    "SP53_PE",
    "SP53_PL",
    "SP53_PM",
    "SP53_PS",
    "SP53_PT",
    "SP53_RA",
    "SP53_SA",
    "SP53_SC",
    "SP53_SI",
    "SP53_SR",
    "IEC_2_1",
    "IEC_2_3",
    "IEC_2_4",
    "FR1_IAC",
    "FR2_UC",
    "FR3_SI",
    "FR4_DC",
    "FR5_RDF",
    "FR6_TRE",
    "FR7_RA",
    "SP82_AC",
    "SP82_AU",
    "SP82_CM",
    "SP82_IA",
    "SP82_IR",
    "SP82_SC",
    "SP82_SI",
    "SP82_RA",
    "SP82_SA",
    "CIP_002",
    "CIP_003",
    "CIP_004",
    "CIP_005",
    "CIP_006",
    "CIP_007",
    "CIP_008",
    "CIP_009",
    "CIP_010",
    "CIP_011",
    "CIP_012",
    "CIP_013",
    "CIP_014",
    "NIS2_GOV",
    "NIS2_INC",
    "NIS2_BC",
    "NIS2_SUPPLY",
    "NIS2_SEC",
    "NIS2_AUDIT",
    "NIS2_HYGIENE",
    "NIS2_CRYPTO",
    "NIS2_IAM",
    "NIS2_MFA",
    "BENCHMARK",
    "ISMS",
)

OLD_CONTROL_THEMES = tuple(t for t in CONTROL_THEMES if t != "ISMS")


def _sql_in_list(values) -> str:
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


def _replace_theme_check(values) -> None:
    condition = "theme IN %s" % _sql_in_list(values)
    op.drop_constraint("ck_control_theme", "compliance_controls", type_="check")
    op.create_check_constraint("ck_control_theme", "compliance_controls", condition)
    op.drop_constraint("ck_score_theme", "compliance_scores", type_="check")
    op.create_check_constraint("ck_score_theme", "compliance_scores", condition)


def upgrade() -> None:
    _replace_theme_check(CONTROL_THEMES)


def downgrade() -> None:
    bind = op.get_bind()
    blockers = bind.execute(
        sa.text("SELECT id FROM compliance_controls WHERE theme = 'ISMS' LIMIT 10")
    ).fetchall()
    if blockers:
        raise RuntimeError(
            "Cannot downgrade: %d control(s) use the ISMS theme (%s). Remove the "
            "ISO management-system clauses first."
            % (len(blockers), ", ".join(r[0] for r in blockers))
        )
    _replace_theme_check(OLD_CONTROL_THEMES)

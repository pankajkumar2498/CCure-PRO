"""compliance_controls: a generic profile membership column

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-08-28

Phase 4 — benchmark assessment on the Phase 3 engine.

What this changes
─────────────────
``compliance_controls`` gains ``profiles``, a NOT NULL JSONB array defaulting
to ``[]``. It records which profile(s) of its framework a control belongs to —
``["L1"]`` or ``["L1", "L2"]`` for a CIS benchmark, and whatever the equivalent
is for the standards that arrive later.

No existing row changes meaning: every control today belongs to no named
profile, and ``[]`` says exactly that. An empty list means "in scope whatever
profile you selected", which is the only reading that leaves the 153 CIS
Controls v8.1 safeguards and the ISO Annex A controls behaving as they do now.

Why a column rather than a tag
──────────────────────────────
``tags`` would hold ``"profile:L1"`` and work. It would also make profile
membership a string convention that nothing validates, that no index helps, and
that every caller has to know how to spell — and the first misspelling silently
removes a control from a profile rather than failing. Profile scope decides
which controls a customer is assessed against, so it is part of the control
model, not an annotation on it.

Why not reuse ``saq_profiles``
──────────────────────────────
``saq_profiles`` holds the same *idea* — which profile of this framework does
this control belong to — and is already filtered in three queries. It is named
for PCI-DSS's Self-Assessment Questionnaire, and a CIS control carrying
``saq_profiles: ["L1"]`` reads as a mistake to anyone who knows what an SAQ is.

Renaming it is the tidier end state and is deliberately not done here: it is
read by the PCI scoping queries in ``routers/compliance.py`` and
``core/compliance_tasks.py``, and rewriting those to gain a better column name
is churn in code Phase 4 does not otherwise touch. ``profiles`` is the generic
one; new content uses it, and
``tests/compliance/test_benchmark_loader.py::test_new_frameworks_do_not_use_saq_profiles``
pins that direction so the two do not quietly diverge into two conventions.

A second change: the ``BENCHMARK`` theme
────────────────────────────────────────
``ck_control_theme`` gains one value, ``BENCHMARK``, and the 126 existing ones
are kept verbatim.

A hardening benchmark carries its own section numbering — "1 Account Policies",
"2 Local Policies", "9 Windows Defender Firewall" — which differs per benchmark
*and* per platform. Minting a theme per section would add roughly eighty values
for the four platforms Phase 4 targets and more for every benchmark after them,
and each addition rewrites the whole 126-value SQL string by hand. One generic
value stops that; the benchmark's own section travels in ``tags``.

The list moved to ``db/models/compliance.CONTROL_THEMES`` in the same change,
so adding a theme is now a tuple entry rather than a retyped SQL literal. It is
duplicated here rather than imported because a migration must describe the
schema as it was, not as the models currently are.

Downgrade
─────────
Drops the column and narrows the theme list back. Refuses if any control is
using ``BENCHMARK`` or carries a non-empty ``profiles``, because narrowing over
such a row would fail at the ALTER with a Postgres error naming the constraint
but not the row — and dropping ``profiles`` from a loaded benchmark would
silently widen every profile-scoped control into scope.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
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
)

OLD_CONTROL_THEMES = tuple(t for t in CONTROL_THEMES if t != "BENCHMARK")


def _sql_in_list(values) -> str:
    """See db/models/compliance.py — str(("k",)) yields an invalid SQL list."""
    return "(" + ", ".join("'%s'" % v for v in values) + ")"


def _replace_theme_check(values) -> None:
    """
    Both tables that constrain ``theme``.

    ``compliance_scores`` carries the same vocabulary because a score row is
    written per theme; leaving it behind would let a benchmark control load and
    then fail when its score was computed — a failure one whole scan away from
    the change that caused it.
    """
    condition = "theme IN %s" % _sql_in_list(values)
    op.drop_constraint("ck_control_theme", "compliance_controls", type_="check")
    op.create_check_constraint("ck_control_theme", "compliance_controls", condition)
    op.drop_constraint("ck_score_theme", "compliance_scores", type_="check")
    op.create_check_constraint("ck_score_theme", "compliance_scores", condition)


def upgrade() -> None:
    _replace_theme_check(CONTROL_THEMES)
    op.add_column(
        "compliance_controls",
        sa.Column(
            "profiles",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    # A GIN index because the only query shape is containment — "which controls
    # are in profile L1" — which a btree cannot serve.
    op.create_index(
        "ix_compliance_controls_profiles",
        "compliance_controls",
        ["profiles"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    bind = op.get_bind()
    blockers = bind.execute(
        sa.text(
            "SELECT id FROM compliance_controls "
            " WHERE theme = 'BENCHMARK' "
            "    OR (profiles IS NOT NULL AND jsonb_array_length(profiles) > 0) "
            " LIMIT 10"
        )
    ).fetchall()
    if blockers:
        raise RuntimeError(
            "Cannot downgrade: %d control(s) use the BENCHMARK theme or carry a "
            "profile (%s). Remove the loaded benchmark first — narrowing the "
            "theme constraint would otherwise fail without naming the rows, and "
            "dropping `profiles` would widen every profile-scoped control into "
            "scope." % (len(blockers), ", ".join(r[0] for r in blockers))
        )
    op.drop_index("ix_compliance_controls_profiles", table_name="compliance_controls")
    op.drop_column("compliance_controls", "profiles")
    _replace_theme_check(OLD_CONTROL_THEMES)

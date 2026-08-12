"""Finding fidelity: canonical severity, CVSS version separation, detection evidence.

Revision ID: z9e0f1g2h3i4
Revises: y8d9e0f1g2h3
Create Date: 2026-08-11

Three problems are corrected here, all of which caused the product to report
numbers that disagreed with its own scan results.

1. ``severity`` was stored in mixed case. ``GROUP BY severity`` returned
   "critical" and "Critical" as separate rows, and the dashboard's
   ``{row.severity.lower(): row.count}`` collapsed them so the last row silently
   overwrote the first — 100 of 146 findings vanished from the summary. Severity
   is normalised to lower case and pinned there with a CHECK constraint.

2. 751 rows held a CVSS **v2** score in ``cvss_v3_score``. Their vectors prove
   it: a v2 vector carries the ``Au:`` metric and no ``CVSS:3.x/`` prefix. Two
   different band tables were then applied to the same number in different code
   paths. The score is moved to ``cvss_v2_score`` and the version each row was
   actually published in is recorded.

3. The scan pipeline computes confidence, quality-of-detection, CVSS vector,
   KEV membership, EPSS and the version it fingerprinted — and the findings
   table stored none of it, so the API had to hardcode ``epss_score = 0.0`` and
   infer KEV from a source value no row ever holds. Columns are added so the
   evidence a finding was raised on survives to the API and the UI.
"""

from alembic import op
import sqlalchemy as sa


revision = "z9e0f1g2h3i4"
down_revision = "y8d9e0f1g2h3"
branch_labels = None
depends_on = None


SEVERITY_VALUES = ("critical", "high", "medium", "low", "none", "unscored")


def upgrade() -> None:
    # ── 1. CVSS version recorded on the catalogue ────────────────────────────
    op.add_column(
        "vulnerability_definitions",
        sa.Column("cvss_version", sa.String(length=8), nullable=True),
    )

    # Recover the version from the vector, which is self-describing for v3/v4
    # and identifiable by the v2-only Au: metric otherwise.
    op.execute(
        """
        UPDATE vulnerability_definitions SET cvss_version = CASE
            WHEN upper(cvss_vector) LIKE 'CVSS:4%%'   THEN '4.0'
            WHEN upper(cvss_vector) LIKE 'CVSS:3.1%%' THEN '3.1'
            WHEN upper(cvss_vector) LIKE 'CVSS:3.0%%' THEN '3.0'
            WHEN upper(cvss_vector) LIKE 'CVSS:2%%'   THEN '2.0'
            WHEN cvss_vector LIKE '%%Au:%%'           THEN '2.0'
            ELSE NULL
        END
        WHERE cvss_vector IS NOT NULL AND cvss_vector <> '';
        """
    )

    # ── 2. Move misfiled v2 scores out of the v3 column ──────────────────────
    # Only rows whose own vector says v2. A row keeping a genuine v3 score is
    # left alone.
    op.execute(
        """
        UPDATE vulnerability_definitions
           SET cvss_v2_score = COALESCE(cvss_v2_score, cvss_v3_score),
               cvss_v3_score = NULL
         WHERE cvss_version = '2.0'
           AND cvss_v3_score IS NOT NULL;
        """
    )

    # ── 3. Canonical severity, derived from the authoritative score ──────────
    # Severity is normalised onto the CVSS v3.1 qualitative scale for every
    # finding regardless of the version its score was published in. This is a
    # deliberate choice: a single scale is what triage and filtering need, and
    # the version is recorded alongside so a report can still state the basis.
    # (CVSS v2 has no Critical tier, so a v2 9.0 shown on its own scale as
    # "High" beside a v3 9.0 shown as "Critical" is precisely the inconsistency
    # this migration exists to remove.)
    op.execute(
        """
        UPDATE vulnerability_definitions SET severity = CASE
            WHEN COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) IS NULL
                THEN 'unscored'
            WHEN COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) >= 9.0
                THEN 'critical'
            WHEN COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) >= 7.0
                THEN 'high'
            WHEN COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) >= 4.0
                THEN 'medium'
            WHEN COALESCE(cvss_v4_score, cvss_v3_score, cvss_v2_score) > 0.0
                THEN 'low'
            ELSE 'none'
        END;
        """
    )

    op.execute(
        """
        UPDATE asset_vulnerabilities SET severity = CASE
            WHEN lower(trim(severity)) IN ('critical','crit') THEN 'critical'
            WHEN lower(trim(severity)) = 'high'               THEN 'high'
            WHEN lower(trim(severity)) IN ('medium','moderate','med')
                                                              THEN 'medium'
            WHEN lower(trim(severity)) = 'low'                THEN 'low'
            WHEN lower(trim(severity)) IN ('none','info','informational')
                                                              THEN 'none'
            ELSE 'unscored'
        END;
        """
    )

    # A finding's severity must agree with its own score. Where the two had
    # drifted apart (the four Oracle CVEs carrying a v2 9.0/10.0 labelled
    # "High" while the catalogue called them critical), the score wins.
    op.execute(
        """
        UPDATE asset_vulnerabilities SET severity = CASE
            WHEN cvss_score IS NULL  THEN severity
            WHEN cvss_score >= 9.0   THEN 'critical'
            WHEN cvss_score >= 7.0   THEN 'high'
            WHEN cvss_score >= 4.0   THEN 'medium'
            WHEN cvss_score >  0.0   THEN 'low'
            ELSE 'none'
        END
        WHERE cvss_score IS NOT NULL;
        """
    )

    op.create_check_constraint(
        "ck_vuln_def_severity_canonical",
        "vulnerability_definitions",
        "severity IN %s" % str(SEVERITY_VALUES),
    )
    op.create_check_constraint(
        "ck_asset_vuln_severity_canonical",
        "asset_vulnerabilities",
        "severity IN %s" % str(SEVERITY_VALUES),
    )

    # Filtering and grouping by severity happens on every dashboard load.
    op.create_index(
        "ix_asset_vuln_severity_status",
        "asset_vulnerabilities",
        ["severity", "status"],
    )

    # ── 4. Detection evidence and exploit intelligence on the finding ────────
    for column in (
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("qod", sa.Integer(), nullable=True),
        sa.Column("detection_method", sa.String(length=40), nullable=True),
        sa.Column("detected_version", sa.String(length=160), nullable=True),
        sa.Column("cvss_vector", sa.String(length=200), nullable=True),
        sa.Column("cvss_version", sa.String(length=8), nullable=True),
        sa.Column("attack_surface", sa.String(length=16), nullable=True),
        sa.Column("in_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("epss_score", sa.Numeric(precision=7, scale=5), nullable=True),
        sa.Column("epss_percentile", sa.Numeric(precision=7, scale=5), nullable=True),
        sa.Column(
            "has_exploit", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("evidence", sa.Text(), nullable=True),
        # The scan a finding was first attributed to. ``scan_id`` is re-pointed
        # on every re-scan, which left "which findings did scan 11 report?"
        # unanswerable from this table.
        sa.Column("first_scan_id", sa.String(length=64), nullable=True),
    ):
        op.add_column("asset_vulnerabilities", column)

    op.execute(
        "UPDATE asset_vulnerabilities SET first_scan_id = scan_id "
        "WHERE first_scan_id IS NULL;"
    )

    op.create_index("ix_asset_vuln_in_kev", "asset_vulnerabilities", ["in_kev"])


def downgrade() -> None:
    op.drop_index("ix_asset_vuln_in_kev", table_name="asset_vulnerabilities")
    for name in (
        "first_scan_id",
        "evidence",
        "has_exploit",
        "epss_percentile",
        "epss_score",
        "kev_due_date",
        "in_kev",
        "attack_surface",
        "cvss_version",
        "cvss_vector",
        "detected_version",
        "detection_method",
        "qod",
        "confidence",
    ):
        op.drop_column("asset_vulnerabilities", name)

    op.drop_index("ix_asset_vuln_severity_status", table_name="asset_vulnerabilities")
    op.drop_constraint(
        "ck_asset_vuln_severity_canonical", "asset_vulnerabilities", type_="check"
    )
    op.drop_constraint(
        "ck_vuln_def_severity_canonical", "vulnerability_definitions", type_="check"
    )
    op.drop_column("vulnerability_definitions", "cvss_version")

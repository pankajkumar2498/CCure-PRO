"""Record the component each finding is about, so findings can be grouped by it.

Revision ID: a1f2g3h4i5j6
Revises: z9e0f1g2h3i4
Create Date: 2026-08-11

A finding is raised against a *component* — a running service or an installed
package — but nothing on the row said which. The only grouping key available
was the CVE, so one outdated application produced one row per CVE published
against it: a single Chrome 138 install, twelve major versions behind, filled
the vulnerability list with 1,736 separate rows. The information was correct
and the presentation was unusable, and the executive report inherited the same
shape.

``component`` is the product or package name the finding was matched on, and
``component_version`` the version observed for it. Together they make "one
outdated Chrome" expressible as one row that resolves 1,736 CVEs, which is how
every comparable scanner presents it.
"""

from alembic import op
import sqlalchemy as sa


revision = "a1f2g3h4i5j6"
down_revision = "z9e0f1g2h3i4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("component", sa.String(length=200), nullable=True),
    )
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("component_version", sa.String(length=160), nullable=True),
    )

    # Backfill from the bound service, which is where existing network findings
    # already carry their product identity.
    op.execute(
        """
        UPDATE asset_vulnerabilities av
           SET component = COALESCE(
                   NULLIF(s.service_product, ''),
                   NULLIF(s.service_name, '')
               ),
               component_version = NULLIF(s.service_version, '')
          FROM services s
         WHERE s.id = av.service_id
           AND av.component IS NULL;
        """
    )

    op.create_index(
        "ix_asset_vuln_component",
        "asset_vulnerabilities",
        ["asset_id", "component"],
    )


def downgrade() -> None:
    op.drop_index("ix_asset_vuln_component", table_name="asset_vulnerabilities")
    op.drop_column("asset_vulnerabilities", "component_version")
    op.drop_column("asset_vulnerabilities", "component")

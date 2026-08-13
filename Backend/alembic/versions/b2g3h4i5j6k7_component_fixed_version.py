"""Record the version that resolves a finding, so a grouped row can name the action.

Findings already roll up to the component that would be remediated — one
outdated Chrome presented as one row rather than the 1,736 CVE rows it
generates. But the rolled-up row could only say *what* was wrong, never *what
to do*: it carried the installed version and no target, so it read

    Google Chrome   138.0.7204.184   1,736 findings   CVSS 10.0   KEV

and left "upgrade to what?" unanswered. The fixed version was known at
detection time — it is written into the finding's evidence text — but prose is
not queryable, so the grouped view could not reach it.

Nullable because it genuinely is: a vulnerability with no published fix is a
real and important state, and it must stay distinguishable from one whose fix
simply was not recorded.

Revision ID: b2g3h4i5j6k7
Revises: a1f2g3h4i5j6
"""

from alembic import op
import sqlalchemy as sa

revision = "b2g3h4i5j6k7"
down_revision = "a1f2g3h4i5j6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("component_fixed_version", sa.String(160), nullable=True),
    )
    # The grouped view reads this alongside `component`, which is what it
    # already groups by.
    op.create_index(
        "idx_asset_vuln_component_fix",
        "asset_vulnerabilities",
        ["component", "component_fixed_version"],
    )


def downgrade() -> None:
    # IF EXISTS: a fresh install builds from Base.metadata and stamps head
    # without running upgrade(). The index is now declared on
    # AssetVulnerability so fresh installs get it, but databases bootstrapped
    # before that change do not have it.
    op.execute("DROP INDEX IF EXISTS idx_asset_vuln_component_fix")
    op.drop_column("asset_vulnerabilities", "component_fixed_version")

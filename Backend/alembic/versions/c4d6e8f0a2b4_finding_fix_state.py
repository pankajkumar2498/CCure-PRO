"""Record whether the matched advisory says a fix has been released.

``component_fixed_version`` is NULL both when a distribution's advisory says the
installed package is affected and no fix has been released, and when no fixed
version was recorded at all. Ubuntu marks most CVEs it tracks the first way, so
on one Ubuntu 24.04 desktop 2,241 of 2,355 package findings carried no fixed
version (14 Oct 2026) and nothing could separate them from findings that simply
lacked one.

``fix_state`` is ``fix_released``, ``no_fix_released`` or NULL (not
established). Nullable, no default and no backfill: the advisory that matched
was never stored, so an existing row cannot be classified after the fact, and
NULL is the honest answer until its host is scanned again.
"""

from alembic import op
import sqlalchemy as sa

revision = "c4d6e8f0a2b4"
down_revision = "a7c9e1b3d5f8"
branch_labels = None
depends_on = None

FIX_STATE_SQL = "fix_state IN ('fix_released', 'no_fix_released')"


def upgrade() -> None:
    op.add_column(
        "asset_vulnerabilities",
        sa.Column("fix_state", sa.String(length=20), nullable=True),
    )
    op.create_check_constraint(
        "ck_asset_vuln_fix_state", "asset_vulnerabilities", FIX_STATE_SQL
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_asset_vuln_fix_state", "asset_vulnerabilities", type_="check"
    )
    op.drop_column("asset_vulnerabilities", "fix_state")

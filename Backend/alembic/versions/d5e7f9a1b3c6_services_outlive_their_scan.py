"""A service row outlives the scan that last observed it.

``services`` is a current-state projection: one row per asset, port and
protocol, re-pointed to whichever scan saw it last. ``services.scan_id`` was
NOT NULL and ON DELETE CASCADE, so purging a scan deleted the asset's whole
service inventory whenever that scan happened to be the latest to see it. On
14 Oct 2026 purging 25 test scans emptied two kept assets' inventories: 104
rows, 85 of them observable only through credentialed collection.

The column becomes nullable and the foreign key ON DELETE SET NULL. A detached
row keeps describing the asset until the next scan re-points it.

Downgrade restores NOT NULL and CASCADE. It cannot hold a detached row, so it
deletes those first: exactly the rows the old rule would already have deleted.
"""

from alembic import op
import sqlalchemy as sa

revision = "d5e7f9a1b3c6"
down_revision = "c4d6e8f0a2b4"
branch_labels = None
depends_on = None

FK = "services_scan_id_fkey"


def upgrade() -> None:
    op.drop_constraint(FK, "services", type_="foreignkey")
    op.alter_column(
        "services", "scan_id", existing_type=sa.String(length=100), nullable=True
    )
    op.create_foreign_key(
        FK,
        "services",
        "scans",
        ["scan_id"],
        ["id"],
        ondelete="SET NULL",
        onupdate="CASCADE",
    )


def downgrade() -> None:
    op.execute("DELETE FROM services WHERE scan_id IS NULL")
    op.drop_constraint(FK, "services", type_="foreignkey")
    op.alter_column(
        "services", "scan_id", existing_type=sa.String(length=100), nullable=False
    )
    op.create_foreign_key(
        FK,
        "services",
        "scans",
        ["scan_id"],
        ["id"],
        ondelete="CASCADE",
        onupdate="CASCADE",
    )

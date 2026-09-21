"""web_parameters attack-surface table (Phase 23b)

The attack surface was queryable only through ``web_assets.parameters`` (a JSONB
blob, not join-able or indexable at parameter granularity) and the coverage
ledger embedded in ``scans.options`` (per-scan, not cross-scan). Neither can
answer, in SQL, the questions a mature DAST is expected to — every endpoint
across every scan exposing an untested parameter of a given name, which
locations carry the most untested surface, whether a parameter joins to a
finding.

This adds ``web_parameters``: one first-class row per (endpoint, location, name)
carrying its own coverage (tested / by which engines / why skipped). It is
purely additive — no existing table is altered, existing scans are unaffected,
and the row is idempotent by (asset, location, name). Populated by the DETECT
phase from the finalised coverage ledger.

Revision ID: f1a2b3c4d5e6
Revises: e0f1a2b3c4d5
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "f1a2b3c4d5e6"
down_revision = "e0f1a2b3c4d5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "web_parameters" in insp.get_table_names():
        return  # idempotent: environment patched by hand before the migration

    op.create_table(
        "web_parameters",
        sa.Column("id", sa.String(length=300), primary_key=True),
        sa.Column(
            "web_scan_id",
            sa.String(length=100),
            sa.ForeignKey("web_scans.id", ondelete="CASCADE", onupdate="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "web_asset_id",
            sa.String(length=250),
            sa.ForeignKey("web_assets.id", ondelete="CASCADE", onupdate="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "org_id",
            sa.String(length=50),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("location", sa.String(length=20), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column(
            "source", sa.String(length=50), nullable=False, server_default="crawler"
        ),
        sa.Column(
            "tested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "tested_by",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("skipped_reason", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "web_asset_id",
            "location",
            "name",
            name="uq_web_parameters_asset_loc_name",
        ),
        sa.CheckConstraint(
            "location IN ('query','form','json','path','cookie','header','soap')",
            name="ck_web_parameters_location",
        ),
    )
    op.create_index("ix_web_parameters_scan_id", "web_parameters", ["web_scan_id"])
    op.create_index("ix_web_parameters_asset_id", "web_parameters", ["web_asset_id"])
    op.create_index("ix_web_parameters_org_id", "web_parameters", ["org_id"])
    op.create_index("ix_web_parameters_name", "web_parameters", ["name"])
    op.create_index("ix_web_parameters_tested", "web_parameters", ["tested"])
    op.create_index(
        "ix_web_parameters_tested_by_gin",
        "web_parameters",
        ["tested_by"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "web_parameters" not in insp.get_table_names():
        return
    for ix in (
        "ix_web_parameters_tested_by_gin",
        "ix_web_parameters_tested",
        "ix_web_parameters_name",
        "ix_web_parameters_org_id",
        "ix_web_parameters_asset_id",
        "ix_web_parameters_scan_id",
    ):
        op.drop_index(ix, table_name="web_parameters")
    op.drop_table("web_parameters")

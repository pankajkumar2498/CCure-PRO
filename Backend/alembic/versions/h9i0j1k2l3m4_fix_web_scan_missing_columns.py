"""fix web scan missing columns

Revision ID: h9i0j1k2l3m4
Revises: g8h9i0j1k2l3
Create Date: 2026-05-24 14:25:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "h9i0j1k2l3m4"
down_revision = "g8h9i0j1k2l3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Web Scans ─────────────────────────────────────────────────────────────
    # Missing columns identified from INSERT error
    op.add_column(
        "web_scans",
        sa.Column(
            "queued_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.add_column(
        "web_scans", sa.Column("report_pdf_path", sa.String(length=512), nullable=True)
    )
    op.add_column(
        "web_scans", sa.Column("report_json_path", sa.String(length=512), nullable=True)
    )
    op.add_column(
        "web_scans",
        sa.Column(
            "is_archived", sa.Boolean(), nullable=False, server_default=sa.text("false")
        ),
    )
    op.add_column(
        "web_scans", sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "web_scans", sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True)
    )

    # ── Web Assets ────────────────────────────────────────────────────────────
    op.add_column(
        "web_assets",
        sa.Column(
            "response_headers",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.add_column(
        "web_assets",
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Fix technology column type: String(100) -> JSONB
    op.execute(
        "ALTER TABLE web_assets ALTER COLUMN technology TYPE JSONB USING technology::jsonb"
    )
    op.alter_column("web_assets", "technology", nullable=False, server_default="[]")

    # ── Web Findings ──────────────────────────────────────────────────────────
    # Missing columns
    op.add_column(
        "web_findings", sa.Column("web_asset_id", sa.String(length=250), nullable=True)
    )
    op.create_foreign_key(
        "fk_web_findings_web_asset_id",
        "web_findings",
        "web_assets",
        ["web_asset_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.add_column(
        "web_findings",
        sa.Column(
            "first_found_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.add_column(
        "web_findings",
        sa.Column(
            "last_found_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # Fix header columns type: JSON -> Text (to match model and prevent insertion errors for raw headers)
    op.execute(
        "ALTER TABLE web_findings ALTER COLUMN request_headers TYPE TEXT USING request_headers::text"
    )
    op.execute(
        "ALTER TABLE web_findings ALTER COLUMN response_headers TYPE TEXT USING response_headers::text"
    )


def downgrade() -> None:
    # ── Web Findings ──────────────────────────────────────────────────────────
    op.execute(
        "ALTER TABLE web_findings ALTER COLUMN response_headers TYPE JSON USING response_headers::json"
    )
    op.execute(
        "ALTER TABLE web_findings ALTER COLUMN request_headers TYPE JSON USING request_headers::json"
    )
    op.drop_column("web_findings", "last_found_at")
    op.drop_column("web_findings", "first_found_at")
    # IF EXISTS, because only the *name* matches on an upgraded database. The
    # model declares the same foreign key without naming it, so a fresh install
    # — which builds from Base.metadata and stamps head, never running
    # upgrade() — has the constraint under PostgreSQL's generated name
    # (web_findings_web_asset_id_fkey) and not this one. Dropping the column
    # immediately below removes whichever name it carries either way.
    op.execute(
        "ALTER TABLE web_findings "
        "DROP CONSTRAINT IF EXISTS fk_web_findings_web_asset_id"
    )
    op.drop_column("web_findings", "web_asset_id")

    # ── Web Assets ────────────────────────────────────────────────────────────
    op.alter_column("web_assets", "technology", nullable=True, server_default=None)
    # WebAsset declares Index("idx_web_assets_tech_gin", "technology",
    # postgresql_using="gin") and no migration creates it, so it exists only on
    # databases built from Base.metadata. Converting the column back to
    # VARCHAR forces PostgreSQL to rebuild that index, and there is no GIN
    # operator class for character varying — the ALTER below failed with
    # UndefinedObject on exactly those databases. Drop it first; a fresh
    # install recreates it from the model, and on an upgraded database the
    # index was never there and this is a no-op.
    op.execute("DROP INDEX IF EXISTS idx_web_assets_tech_gin")
    op.execute(
        "ALTER TABLE web_assets ALTER COLUMN technology TYPE VARCHAR(100) USING technology::text"
    )
    op.drop_column("web_assets", "updated_at")
    op.drop_column("web_assets", "response_headers")

    # ── Web Scans ─────────────────────────────────────────────────────────────
    op.drop_column("web_scans", "deleted_at")
    op.drop_column("web_scans", "archived_at")
    op.drop_column("web_scans", "is_archived")
    op.drop_column("web_scans", "report_json_path")
    op.drop_column("web_scans", "report_pdf_path")
    op.drop_column("web_scans", "queued_at")

"""web_forms + web_api_operations site-map tables (Phase 23c, Codex item 1)

Completes the first-class attack-surface / site-map model. Forms and API
operations were captured only as WebAssets flagged is_form / is_api with their
structure in JSONB — enough to test, not enough to present as the queryable
form inventory and API operation inventory industry scanners put front and
centre. This adds two first-class tables. Purely additive; existing scans are
unaffected. (WebEndpoint = web_assets, WebParameter/WebCoverage = web_parameters,
WebRequest/WebResponse = the in-memory request model + web_findings evidence.)

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "a2b3c4d5e6f7"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = insp.get_table_names()

    if "web_forms" not in existing:
        op.create_table(
            "web_forms",
            sa.Column("id", sa.String(length=250), primary_key=True),
            sa.Column(
                "web_scan_id",
                sa.String(length=100),
                sa.ForeignKey("web_scans.id", ondelete="CASCADE", onupdate="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "org_id",
                sa.String(length=50),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("action_url", sa.Text(), nullable=False),
            sa.Column(
                "method", sa.String(length=10), nullable=False, server_default="GET"
            ),
            sa.Column("page_url", sa.Text(), nullable=True),
            sa.Column(
                "inputs", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
            ),
            sa.Column("input_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "has_file_upload",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
            sa.Column(
                "has_password", sa.Boolean(), nullable=False, server_default=sa.false()
            ),
            sa.Column(
                "source", sa.String(length=50), nullable=False, server_default="crawler"
            ),
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
                "web_scan_id",
                "action_url",
                "method",
                name="uq_web_forms_scan_action_method",
            ),
        )
        op.create_index("ix_web_forms_scan_id", "web_forms", ["web_scan_id"])
        op.create_index("ix_web_forms_org_id", "web_forms", ["org_id"])
        op.create_index("ix_web_forms_file_upload", "web_forms", ["has_file_upload"])

    if "web_api_operations" not in existing:
        op.create_table(
            "web_api_operations",
            sa.Column("id", sa.String(length=250), primary_key=True),
            sa.Column(
                "web_scan_id",
                sa.String(length=100),
                sa.ForeignKey("web_scans.id", ondelete="CASCADE", onupdate="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "org_id",
                sa.String(length=50),
                sa.ForeignKey("organizations.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("identity", sa.String(length=512), nullable=False),
            sa.Column("url", sa.Text(), nullable=False),
            sa.Column(
                "method", sa.String(length=10), nullable=False, server_default="POST"
            ),
            sa.Column("operation_name", sa.String(length=255), nullable=True),
            sa.Column("spec_source", sa.String(length=50), nullable=True),
            sa.Column(
                "parameters",
                JSONB(),
                nullable=False,
                server_default=sa.text("'{}'::jsonb"),
            ),
            sa.Column("secured", sa.Boolean(), nullable=True),
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
                "web_scan_id",
                "kind",
                "identity",
                name="uq_web_api_ops_scan_kind_identity",
            ),
            sa.CheckConstraint(
                "kind IN ('rest','graphql','soap')", name="ck_web_api_ops_kind"
            ),
        )
        op.create_index("ix_web_api_ops_scan_id", "web_api_operations", ["web_scan_id"])
        op.create_index("ix_web_api_ops_org_id", "web_api_operations", ["org_id"])
        op.create_index("ix_web_api_ops_kind", "web_api_operations", ["kind"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = insp.get_table_names()
    if "web_api_operations" in existing:
        for ix in (
            "ix_web_api_ops_kind",
            "ix_web_api_ops_org_id",
            "ix_web_api_ops_scan_id",
        ):
            op.drop_index(ix, table_name="web_api_operations")
        op.drop_table("web_api_operations")
    if "web_forms" in existing:
        for ix in (
            "ix_web_forms_file_upload",
            "ix_web_forms_org_id",
            "ix_web_forms_scan_id",
        ):
            op.drop_index(ix, table_name="web_forms")
        op.drop_table("web_forms")

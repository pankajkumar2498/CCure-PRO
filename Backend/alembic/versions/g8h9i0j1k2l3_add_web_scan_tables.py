"""add web scan tables

Revision ID: g8h9i0j1k2l3
Revises: f7g8h9i0j1k2
Create Date: 2026-05-24 13:42:00.000000

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "g8h9i0j1k2l3"
down_revision = "f7g8h9i0j1k2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Web Scans ─────────────────────────────────────────────────────────────
    op.create_table(
        "web_scans",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("org_id", sa.String(length=100), nullable=False),
        sa.Column("created_by", sa.String(length=100), nullable=True),
        sa.Column("scan_name", sa.String(length=255), nullable=True),
        sa.Column("target_url", sa.String(length=2048), nullable=False),
        sa.Column("target_domain", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=True),
        sa.Column("pipeline_phase", sa.String(length=50), nullable=True),
        sa.Column("scan_scope", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("auth_config", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("options", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("authorization_confirmed", sa.Boolean(), nullable=False),
        sa.Column("rate_limit", sa.Integer(), nullable=True),
        sa.Column("waf_detected", sa.String(length=255), nullable=True),
        sa.Column("tech_stack", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("subdomains", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("current_task_id", sa.String(length=255), nullable=True),
        sa.Column("recon_status", sa.String(length=50), nullable=True),
        sa.Column("recon_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recon_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("crawl_status", sa.String(length=50), nullable=True),
        sa.Column("crawl_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("crawl_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detect_status", sa.String(length=50), nullable=True),
        sa.Column("detect_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detect_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("audit_status", sa.String(length=50), nullable=True),
        sa.Column("audit_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("audit_completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("total_endpoints", sa.Integer(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=True),
        sa.Column("critical_count", sa.Integer(), nullable=True),
        sa.Column("high_count", sa.Integer(), nullable=True),
        sa.Column("medium_count", sa.Integer(), nullable=True),
        sa.Column("low_count", sa.Integer(), nullable=True),
        sa.Column("info_count", sa.Integer(), nullable=True),
        sa.Column("failure_reason", sa.String(length=1000), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_deleted", sa.Boolean(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_web_scans_org_id"), "web_scans", ["org_id"], unique=False)

    # ── Web Assets ────────────────────────────────────────────────────────────
    op.create_table(
        "web_assets",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("web_scan_id", sa.String(length=100), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("method", sa.String(length=20), nullable=True),
        sa.Column("content_type", sa.String(length=100), nullable=True),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column("parameters", postgresql.JSON(astext_type=sa.Text()), nullable=True),
        sa.Column("auth_required", sa.Boolean(), nullable=True),
        sa.Column("is_api", sa.Boolean(), nullable=True),
        sa.Column("is_form", sa.Boolean(), nullable=True),
        sa.Column("has_file_upload", sa.Boolean(), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=True),
        sa.Column("technology", sa.String(length=100), nullable=True),
        sa.Column("response_size", sa.Integer(), nullable=True),
        sa.Column("response_time", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["web_scan_id"], ["web_scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_web_assets_web_scan_id"), "web_assets", ["web_scan_id"], unique=False
    )

    # ── Web Findings ──────────────────────────────────────────────────────────
    op.create_table(
        "web_findings",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("web_scan_id", sa.String(length=100), nullable=False),
        sa.Column("org_id", sa.String(length=100), nullable=False),
        sa.Column("finding_type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=100), nullable=True),
        sa.Column("detected_by", sa.String(length=100), nullable=True),
        sa.Column("template_id", sa.String(length=255), nullable=True),
        sa.Column("matched_at", sa.String(length=2048), nullable=True),
        sa.Column("request_method", sa.String(length=20), nullable=True),
        sa.Column("request_url", sa.String(length=2048), nullable=True),
        sa.Column(
            "request_headers", postgresql.JSON(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("request_body", sa.Text(), nullable=True),
        sa.Column("response_code", sa.Integer(), nullable=True),
        sa.Column(
            "response_headers", postgresql.JSON(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("response_body", sa.Text(), nullable=True),
        sa.Column("payload_used", sa.Text(), nullable=True),
        sa.Column("curl_command", sa.Text(), nullable=True),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column(
            "reference_links", postgresql.JSON(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("owasp_category", sa.String(length=100), nullable=True),
        sa.Column(
            "compliance_tags", postgresql.JSON(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("cve_id", sa.String(length=50), nullable=True),
        sa.Column("cwe_id", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=True),
        sa.Column("is_verified", sa.Boolean(), nullable=True),
        sa.Column("false_positive_reason", sa.String(length=500), nullable=True),
        sa.Column("accepted_risk_reason", sa.String(length=500), nullable=True),
        sa.Column("accepted_by", sa.String(length=100), nullable=True),
        sa.Column("fixed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["web_scan_id"], ["web_scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_web_findings_web_scan_id"),
        "web_findings",
        ["web_scan_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_web_findings_org_id"), "web_findings", ["org_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_web_findings_org_id"), table_name="web_findings")
    op.drop_index(op.f("ix_web_findings_web_scan_id"), table_name="web_findings")
    op.drop_table("web_findings")
    op.drop_index(op.f("ix_web_assets_web_scan_id"), table_name="web_assets")
    op.drop_table("web_assets")
    op.drop_index(op.f("ix_web_scans_org_id"), table_name="web_scans")
    op.drop_table("web_scans")

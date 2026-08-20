"""Compliance engine: scan-run timestamps, attestation fields, evidence files.

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-08-19

Three groups of changes, all in service of making the ISO 27001 assessment
workflow actually completable:

1. `compliance_scan_runs.created_at` / `.error_message`. `run_scheduled_scans`
   has always passed `created_at=` to the model constructor and the column has
   never existed, so every scheduled compliance scan raised TypeError, was
   swallowed by a bare `except`, and reported `{"success": False}`. No
   scheduled scan has ever run. `error_message` gives a failed run somewhere to
   say why, which the UI had no way of learning.

2. `compliance_findings.justification` / `.owner` / `.next_review_at`.
   ISO/IEC 27001:2022 clause 6.1.3(d) requires the Statement of Applicability
   to record the justification for including each control and for excluding
   any control. There was nowhere to put either, so the exported SoA could not
   be used for certification. Owner and review date are what let an ISMS
   manager run an attestation cycle rather than a one-off sweep.

3. `compliance_evidence_files`. `evidence_file_ids` has been on the finding
   since the first compliance migration with no table behind it and no upload
   route. Attestation without attached evidence is an assertion, not an audit
   record.

Backfill: `created_at` is seeded from `started_at` where present so existing
runs keep a sensible ordering in scan history, and falls back to `now()`.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "d3e4f5a6b7c8"
down_revision = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── 1. Scan run timestamps ───────────────────────────────────────────────
    op.add_column(
        "compliance_scan_runs",
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "compliance_scan_runs",
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    # An existing run's best available creation time is when it started; a run
    # that never started gets now(), which at least orders it after everything
    # that did.
    op.execute(
        "UPDATE compliance_scan_runs "
        "SET created_at = COALESCE(started_at, finished_at, now()) "
        "WHERE created_at IS NULL"
    )
    op.alter_column(
        "compliance_scan_runs",
        "created_at",
        nullable=False,
        server_default=sa.text("now()"),
    )
    op.create_index(
        "ix_compliance_scan_runs_tenant_created",
        "compliance_scan_runs",
        ["tenant_id", "created_at"],
    )

    # ── 2. Attestation / SoA fields on findings ──────────────────────────────
    op.add_column(
        "compliance_findings", sa.Column("justification", sa.Text(), nullable=True)
    )
    op.add_column(
        "compliance_findings", sa.Column("owner", sa.String(length=150), nullable=True)
    )
    op.add_column(
        "compliance_findings",
        sa.Column("next_review_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_compliance_findings_owner",
        "compliance_findings",
        "users",
        ["owner"],
        ["id"],
        ondelete="SET NULL",
    )

    # ── 3. Evidence files ────────────────────────────────────────────────────
    op.create_table(
        "compliance_evidence_files",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("tenant_id", sa.String(length=100), nullable=False),
        sa.Column("control_id", sa.String(length=100), nullable=False),
        sa.Column("finding_id", sa.String(length=250), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("content_type", sa.String(length=120), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_path", sa.String(length=1024), nullable=False),
        sa.Column("uploaded_by", sa.String(length=150), nullable=True),
        sa.Column(
            "uploaded_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["organizations.id"],
            name="fk_evidence_files_tenant",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["control_id"],
            ["compliance_controls.id"],
            name="fk_evidence_files_control",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["compliance_findings.id"],
            name="fk_evidence_files_finding",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["uploaded_by"],
            ["users.id"],
            name="fk_evidence_files_uploader",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_compliance_evidence_files_tenant",
        "compliance_evidence_files",
        ["tenant_id"],
    )
    op.create_index(
        "ix_compliance_evidence_files_control",
        "compliance_evidence_files",
        ["tenant_id", "control_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_compliance_evidence_files_control", table_name="compliance_evidence_files"
    )
    op.drop_index(
        "ix_compliance_evidence_files_tenant", table_name="compliance_evidence_files"
    )
    op.drop_table("compliance_evidence_files")

    op.drop_constraint(
        "fk_compliance_findings_owner", "compliance_findings", type_="foreignkey"
    )
    op.drop_column("compliance_findings", "next_review_at")
    op.drop_column("compliance_findings", "owner")
    op.drop_column("compliance_findings", "justification")

    op.drop_index(
        "ix_compliance_scan_runs_tenant_created", table_name="compliance_scan_runs"
    )
    op.drop_column("compliance_scan_runs", "error_message")
    op.drop_column("compliance_scan_runs", "created_at")

"""web finding remediation column (Phase 21)

Persist the engine/central-supplied remediation guidance for web findings.
Phase 20 found the detection engines produce remediation text but the
`web_findings` table had nowhere to store it, so the API, UI and PDF report
could not render it. This adds a single nullable Text column following the same
convention as the sibling `remediation_notes` column; existing rows keep NULL
(honest absence) and are unaffected.

Revision ID: e0f1a2b3c4d5
Revises: d8e9f0a1b2c3
Create Date: 2026-09-19
"""

from alembic import op
import sqlalchemy as sa

revision = "e0f1a2b3c4d5"
down_revision = "d8e9f0a1b2c3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent guard: the column may already exist on an environment that was
    # patched by hand before the migration ran.
    bind = op.get_bind()
    cols = [c["name"] for c in sa.inspect(bind).get_columns("web_findings")]
    if "remediation" not in cols:
        op.add_column(
            "web_findings",
            sa.Column("remediation", sa.Text(), nullable=True),
        )


def downgrade() -> None:
    bind = op.get_bind()
    cols = [c["name"] for c in sa.inspect(bind).get_columns("web_findings")]
    if "remediation" in cols:
        op.drop_column("web_findings", "remediation")

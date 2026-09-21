"""web_findings proof-based evidence columns (Phase 23c, Codex item 10)

A finding is only as credible as what it lets a reviewer reproduce and judge.
The evidence stored request/response/payload but lost the confidence, a
ready-to-run curl, the authenticated identity tested under, and any screenshot
proving execution — so the API and PDF report could not show them. Four nullable
columns, purely additive; existing rows keep NULL (honest absence).

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa

revision = "c4d5e6f7a8b9"
down_revision = "b3c4d5e6f7a8"
branch_labels = None
depends_on = None

_COLS = {
    "confidence": sa.String(length=20),
    "curl_command": sa.Text(),
    "auth_context": sa.String(length=120),
    "screenshot_path": sa.String(length=512),
}


def upgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("web_findings")}
    for name, coltype in _COLS.items():
        if name not in existing:
            op.add_column("web_findings", sa.Column(name, coltype, nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("web_findings")}
    for name in _COLS:
        if name in existing:
            op.drop_column("web_findings", name)

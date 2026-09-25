"""compliance_scan_runs: a `not_assessed` status (Phase 1, finding F6)

A compliance run whose scope resolved to no assets was recorded as `completed`
with the message "No assets in scope." — a run that assessed nothing stored as
a finished assessment, the "no data is not an empty result" defect class. It
now ends `not_assessed`, so neither the workspace nor `_latest_run_id` can read
it as a set of results.

The CHECK constraint is the only schema change. Downgrade folds any
`not_assessed` rows back to `completed` — what they were recorded as before —
so the narrower constraint can be restored.

Revision ID: d6e7f8a9b0c2
Revises: c4d5e6f7a8b9
Create Date: 2026-09-25
"""

from alembic import op

revision = "d6e7f8a9b0c2"
down_revision = "c4d5e6f7a8b9"
branch_labels = None
depends_on = None

_TABLE = "compliance_scan_runs"
_NAME = "ck_run_status"


def upgrade() -> None:
    op.drop_constraint(_NAME, _TABLE, type_="check")
    op.create_check_constraint(
        _NAME,
        _TABLE,
        "status IN ('queued', 'running', 'completed', 'failed', 'not_assessed')",
    )


def downgrade() -> None:
    op.execute(
        f"UPDATE {_TABLE} SET status = 'completed' WHERE status = 'not_assessed'"
    )
    op.drop_constraint(_NAME, _TABLE, type_="check")
    op.create_check_constraint(
        _NAME,
        _TABLE,
        "status IN ('queued', 'running', 'completed', 'failed')",
    )

"""rename scan report path columns to name the audience

The two vulnerability-audit PDFs were stored as ``report_json_path`` and
``report_xml_path``. Those names came from the internal payload parser each
report was built from, not from what the report is: one is the executive
summary, the other the technical report. Operators reading the API or the
database could not tell which was which, and the same naming leaked into the
generated filenames.

This renames the columns to match the artefact. ``web_scans.report_json_path``
is deliberately left alone: nothing writes it, so renaming it would only move a
dead column around.

Revision ID: w6b7c8d9e0f1
Revises: v5a6b7c8d9e0
Create Date: 2026-07-30 10:40:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "w6b7c8d9e0f1"
down_revision = "v5a6b7c8d9e0"
branch_labels = None
depends_on = None


#: (old name, new name) for the scans table.
RENAMES = (
    ("report_json_path", "report_executive_path"),
    ("report_xml_path", "report_technical_path"),
)


def _existing_columns(table: str) -> set:
    """Column names currently present on ``table``."""
    bind = op.get_bind()
    from sqlalchemy import inspect

    return {col["name"] for col in inspect(bind).get_columns(table)}


def upgrade() -> None:
    # Guarded so the migration is safe to re-run against a database that was
    # stamped or partially migrated by hand.
    present = _existing_columns("scans")
    for old, new in RENAMES:
        if old in present and new not in present:
            op.alter_column("scans", old, new_column_name=new)


def downgrade() -> None:
    present = _existing_columns("scans")
    for old, new in RENAMES:
        if new in present and old not in present:
            op.alter_column("scans", new, new_column_name=old)

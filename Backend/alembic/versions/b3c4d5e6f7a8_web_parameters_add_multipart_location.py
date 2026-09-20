"""web_parameters: add 'multipart' to the location CHECK (Phase 23c, Codex item 2)

Parameter discovery now distinguishes multipart/form-data fields (file uploads
and multipart text fields) from url-encoded form fields, because the injection
layer must send them with a different body encoding. That adds a new value to
the location vocabulary, so the CHECK constraint is widened. Purely additive.

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa

revision = "b3c4d5e6f7a8"
down_revision = "a2b3c4d5e6f7"
branch_labels = None
depends_on = None

_OLD = "location IN ('query','form','json','path','cookie','header','soap')"
_NEW = (
    "location IN " "('query','form','json','path','cookie','header','soap','multipart')"
)


def _swap_check(expr: str) -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "web_parameters" not in insp.get_table_names():
        return
    op.drop_constraint("ck_web_parameters_location", "web_parameters", type_="check")
    op.create_check_constraint("ck_web_parameters_location", "web_parameters", expr)


def upgrade() -> None:
    _swap_check(_NEW)


def downgrade() -> None:
    # Only safe if no row already uses 'multipart'; a downgrade over such rows
    # would violate the narrower CHECK, so it is left to the operator to clear
    # them first. The swap itself mirrors upgrade.
    _swap_check(_OLD)

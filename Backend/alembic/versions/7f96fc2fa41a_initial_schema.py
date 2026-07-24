"""initial_schema

Revision ID: 7f96fc2fa41a
Revises:
Create Date: 2026-05-09 12:20:19.312202

"""

from collections.abc import Sequence
from typing import Union

# revision identifiers, used by Alembic.
revision: str = "7f96fc2fa41a"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Baseline schema migration.

    This revision is a no-op baseline for the existing production/test schema.
    Future schema changes should be created as incremental Alembic revisions.
    """


def downgrade() -> None:
    """Downgrade schema."""

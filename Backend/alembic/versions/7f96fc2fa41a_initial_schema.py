"""initial_schema

Revision ID: 7f96fc2fa41a
Revises: 
Create Date: 2026-05-09 12:20:19.312202

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '7f96fc2fa41a'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Baseline schema migration.

    This revision is a no-op baseline for the existing production/test schema.
    Future schema changes should be created as incremental Alembic revisions.
    """
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass


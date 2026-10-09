"""Ccure Rank: the module's own Alembic branch — create its empty schema.

Revision ID: rank_0001
Revises:
Create Date: 2026-09-30

Phase 11.3. The base of the ``rank`` branch: it creates the schema the module's
tables will live in, and nothing else. No table is created here; the Rank team
adds its tables in later revisions on this branch
(``alembic revision --head=rank@head``).

The downgrade drops the schema with RESTRICT (PostgreSQL's default), so it
refuses while any object is still inside it — a branch can only be taken back to
base after its own later revisions have removed their tables.
"""

from alembic import op

revision = "rank_0001"
down_revision = None
branch_labels = ("rank",)
depends_on = None


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS rank")


def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS rank RESTRICT")

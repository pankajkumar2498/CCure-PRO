"""Remove retired organisation subscription metadata.

Organisation identity, authorised scan scope, remediation settings and all
assessment data remain intact. Restoring removed values requires a backup;
downgrade refuses to invent subscription settings for existing organisations.
"""

from alembic import op

revision = "f6a8c0e2b4d7"
down_revision = "e5a7c9d1f3b2"
branch_labels = None
depends_on = None


def upgrade():
    for column in (
        "plan",
        "max_assets",
        "max_users",
        "max_scans_per_day",
        "max_concurrent_scans",
    ):
        op.drop_column("organizations", column)


def downgrade():
    raise RuntimeError(
        "Removed organisation subscription metadata cannot be reconstructed. "
        "Restore a pre-migration backup to roll back this migration."
    )

"""add service discovery provenance and reachability

Records which observation produced each service row and what it established.

Before this, a credentialed audit's listening sockets were written into the
same table as a port scan's results with state forced to "open", so a service
bound to 127.0.0.1 was indistinguishable from one confirmed reachable across
the network. Existing rows are backfilled as network_scan/reachable, which is
what every row written by the port-scan path genuinely was; credentialed rows
predating this change cannot be told apart retrospectively and are left with
network_reachable NULL rather than being given a value that was never observed.

Revision ID: x7c8d9e0f1g2
Revises: w6b7c8d9e0f1
Create Date: 2026-08-01 10:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "x7c8d9e0f1g2"
down_revision = "w6b7c8d9e0f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "services",
        sa.Column(
            "discovery_source",
            sa.String(length=30),
            nullable=False,
            server_default="network_scan",
        ),
    )
    op.add_column(
        "services", sa.Column("network_reachable", sa.Boolean(), nullable=True)
    )
    op.add_column(
        "services", sa.Column("bind_scope", sa.String(length=24), nullable=True)
    )
    op.add_column(
        "services",
        sa.Column(
            "credentialed_confirmed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )

    op.create_index("ix_services_discovery_source", "services", ["discovery_source"])

    # Every pre-existing row in an "open" state was written by the port-scan
    # path, which only records a port after something answered on it. That is a
    # network-confirmed observation, so the backfill states it as one.
    op.execute(
        """
        UPDATE services
        SET network_reachable = TRUE
        WHERE state = 'open'
        """
    )

    op.alter_column("services", "discovery_source", server_default=None)
    op.alter_column("services", "credentialed_confirmed", server_default=None)


def downgrade() -> None:
    # Reachability and provenance are not representable in the old schema, so
    # the states this migration introduced collapse back to "open" — the value
    # they would have carried before it.
    op.execute(
        """
        UPDATE services
        SET state = 'open'
        WHERE state IN ('listening', 'host_only')
        """
    )
    op.drop_index("ix_services_discovery_source", table_name="services")
    op.drop_column("services", "credentialed_confirmed")
    op.drop_column("services", "bind_scope")
    op.drop_column("services", "network_reachable")
    op.drop_column("services", "discovery_source")

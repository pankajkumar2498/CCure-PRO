"""Asset data hygiene: float latency, null out scanner placeholders, lowercase MACs

Three data-quality corrections that belong together because they all clean up
values the discovery pipeline wrote as if they were observations:

  1. ``assets.response_time_ms`` becomes double precision. LAN round-trips are
     routinely well under a millisecond, so an integer column rounded 0.19 ms to
     0 and 0.81 ms to 1 — discarding nearly all of the signal.

  2. Scanner placeholders ("Unknown", "unknown", "N/A", …) stored in identity and
     classification columns are set to NULL. They were written by the asset
     create path, which bypassed the placeholder filter the update path applies;
     because that update filter then skips empty incoming values, a placeholder
     once written could never be corrected by a later scan.

  3. Historic ``asset_change_log`` rows that record a MAC "change" which is only
     a difference in letter case are deleted. PostgreSQL's macaddr type stores
     lowercase while the syncer wrote uppercase, so every scan logged a change
     that never happened, on every host.

Revision ID: y8d9e0f1g2h3
Revises: x7c8d9e0f1g2
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "y8d9e0f1g2h3"
down_revision = "x7c8d9e0f1g2"
branch_labels = None
depends_on = None


# Matched case-insensitively against the columns below.
PLACEHOLDERS = ("unknown", "n/a", "none", "not determined", "not available", "-", "--")

# Columns that describe what a scan observed. A placeholder in any of these is
# an absence of data, not a finding.
TEXT_COLUMNS = (
    "hostname",
    "dns_name",
    "fqdn",
    "netbios_name",
    "os_name",
    "os_family",
    "os_version",
    "vendor",
    "manufacturer",
    "device_category",
)


def upgrade() -> None:
    # ── 1. Sub-millisecond latency ────────────────────────────────────────────
    op.alter_column(
        "assets",
        "response_time_ms",
        existing_type=sa.Integer(),
        type_=sa.Float(),
        existing_nullable=True,
        postgresql_using="response_time_ms::double precision",
    )

    # ── 2. Null out stored placeholders ───────────────────────────────────────
    placeholder_list = ", ".join(f"'{value}'" for value in PLACEHOLDERS)
    for column in TEXT_COLUMNS:
        op.execute(
            f"""
            UPDATE assets
               SET {column} = NULL
             WHERE {column} IS NOT NULL
               AND lower(btrim({column})) IN ({placeholder_list})
            """
        )

    # ── 3. Purge the fictional MAC-case change history ────────────────────────
    op.execute(
        """
        DELETE FROM asset_change_log
         WHERE field_name = 'mac_address'
           AND old_value IS NOT NULL
           AND new_value IS NOT NULL
           AND lower(old_value->>'val') = lower(new_value->>'val')
        """
    )

    # ── 4. Repair impossible first_seen/last_seen ordering ────────────────────
    # On the old create path first_seen_at came from the column default, which
    # fires at INSERT — after last_seen_at had already been computed in Python.
    # The result was assets first seen a few milliseconds after they were last
    # seen. The create path now sets both explicitly; this fixes the rows it
    # already produced.
    op.execute(
        """
        UPDATE assets
           SET first_seen_at = last_seen_at
         WHERE first_seen_at > last_seen_at
        """
    )


def downgrade() -> None:
    # Nulled placeholders and deleted noise rows are not restored: reinstating
    # them would mean re-inserting data that was never a real observation.
    op.alter_column(
        "assets",
        "response_time_ms",
        existing_type=sa.Float(),
        type_=sa.Integer(),
        existing_nullable=True,
        postgresql_using="round(response_time_ms)::integer",
    )

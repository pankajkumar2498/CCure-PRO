"""Remove obsolete RBAC structures after native authorization is established.

Revision ID: d4f8b2c6e0a1
Revises: c9e3a7b5d1f2
Create Date: 2026-10-04

Only legacy objects are removed. Historical migrations and all native RBAC
tables, grants, revision records and audit protections remain intact.
"""

from alembic import op
from sqlalchemy import inspect

revision = "d4f8b2c6e0a1"
down_revision = "c9e3a7b5d1f2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspector = inspect(op.get_bind())
    tables = set(inspector.get_table_names(schema="public"))
    for name in ("rbac_legacy_map", "role_permissions"):
        if name in tables:
            op.drop_table(name, schema="public")

    if "users" in tables and "role_id" in {
        c["name"] for c in inspector.get_columns("users", schema="public")
    }:
        for fk in inspector.get_foreign_keys("users", schema="public"):
            if "role_id" in fk["constrained_columns"]:
                op.drop_constraint(
                    fk["name"], "users", type_="foreignkey", schema="public"
                )
        for index in inspector.get_indexes("users", schema="public"):
            if "role_id" in index["column_names"]:
                op.drop_index(index["name"], table_name="users", schema="public")
        op.drop_column("users", "role_id", schema="public")

    for name in ("roles", "permissions"):
        if name in tables:
            # PostgreSQL's default RESTRICT catches any unreviewed dependency.
            op.drop_table(name, schema="public")


def downgrade() -> None:
    raise RuntimeError(
        "Legacy RBAC data was intentionally removed. Restore a verified recovery "
        "snapshot into a separate database; this revision cannot reconstruct it."
    )

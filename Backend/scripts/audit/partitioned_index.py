"""
scripts/audit/partitioned_index.py
─────────────────────────────────────────────────────────────────────────────
Build an index on the partitioned ``audit_logs`` table without holding a write
lock over the whole table.

PostgreSQL **rejects** ``CREATE INDEX CONCURRENTLY`` on a partitioned parent.
The supported sequence, and the one used here, is:

  1. ``CREATE INDEX ... ON ONLY parent`` — creates an *invalid* parent index
     with no partitions attached. No data is read; this is near-instant.
  2. ``CREATE INDEX CONCURRENTLY ... ON <each leaf partition>`` — the only
     place ``CONCURRENTLY`` legally appears, and the only step that reads data.
  3. ``ALTER INDEX <parent> ATTACH PARTITION <child>`` for each partition.
     When the last one attaches, the parent index becomes valid automatically.

Steps 2 and 3 must run outside a transaction block, which is why the migration
that calls this uses ``op.get_context().autocommit_block()``.

Partitions are discovered from ``pg_inherits`` rather than assumed to be
``_p0``..``_p7``: the count is a deployment detail, and hardcoding eight would
silently skip a ninth.
"""

from __future__ import annotations

from sqlalchemy import text

#: The parent table. Everything here is scoped to it deliberately.
PARENT = "audit_logs"


def leaf_partitions(conn, parent: str = PARENT) -> list[str]:
    """Every current leaf partition of `parent`, in a stable order."""
    rows = conn.execute(
        text(
            """
            SELECT c.relname
              FROM pg_inherits i
              JOIN pg_class c ON c.oid = i.inhrelid
             WHERE i.inhparent = CAST(:parent AS regclass)
             ORDER BY c.relname
            """
        ),
        {"parent": parent},
    ).fetchall()
    return [r[0] for r in rows]


def index_exists(conn, name: str) -> bool:
    return bool(
        conn.execute(
            text("SELECT 1 FROM pg_class WHERE relname = :n AND relkind = 'i'"),
            {"n": name},
        ).scalar()
    )


def create_partitioned_index(
    conn,
    index_name: str,
    columns: str,
    parent: str = PARENT,
    echo=print,
) -> None:
    """
    Create `index_name` over `columns` on `parent`, concurrently per partition.

    `conn` must be in autocommit — ``CREATE INDEX CONCURRENTLY`` cannot run
    inside a transaction block.
    """
    partitions = leaf_partitions(conn, parent)
    echo(f"  {index_name}: {len(partitions)} partitions")

    # 1. The parent index, ON ONLY so no partition is touched and no data read.
    if not index_exists(conn, index_name):
        conn.execute(text(f"CREATE INDEX {index_name} ON ONLY {parent} ({columns})"))
        echo("    parent index created (invalid until every child attaches)")

    for part in partitions:
        child = f"{part}_{index_name.replace('ix_' + parent + '_', '')}_idx"
        child = child[:63]  # PostgreSQL identifier limit

        # 2. The only CONCURRENTLY in the whole procedure, and it names a leaf.
        if not index_exists(conn, child):
            conn.execute(
                text(f"CREATE INDEX CONCURRENTLY {child} ON {part} ({columns})")
            )

        # 3. Attach. Idempotent: attaching an already-attached index is a no-op
        #    error, so it is checked first.
        attached = conn.execute(
            text(
                """
                SELECT 1 FROM pg_inherits
                 WHERE inhrelid  = CAST(:child  AS regclass)
                   AND inhparent = CAST(:parent AS regclass)
                """
            ),
            {"child": child, "parent": index_name},
        ).scalar()
        if not attached:
            conn.execute(text(f"ALTER INDEX {index_name} ATTACH PARTITION {child}"))

    valid = conn.execute(
        text(
            "SELECT indisvalid FROM pg_index WHERE indexrelid = " "CAST(:n AS regclass)"
        ),
        {"n": index_name},
    ).scalar()
    echo(f"    all partitions attached; parent index valid={valid}")
    if not valid:
        raise RuntimeError(
            f"{index_name} is still invalid after attaching every partition — "
            "the planner will ignore it. Investigate before proceeding."
        )


def drop_partitioned_index(conn, index_name: str, echo=print) -> None:
    """Dropping the parent index cascades to every attached partition index."""
    conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
    echo(f"  dropped {index_name}")

"""audit_logs: measured indexes and append-only enforcement

Phase 3. Two parts, both additive to an existing table's *behaviour* rather
than its columns:

  1. Two indexes, each justified by a measurement at 1,000,000 rows.
  2. Append-only enforcement — grants plus triggers.

Indexes: why these two and not the others
─────────────────────────────────────────
Measured with ``scripts/audit/bench_audit_queries.py`` against a disposable
1,000,000-row copy of this schema (12 organisations, one holding ~40%,
18 months of history), using ``EXPLAIN (ANALYZE, BUFFERS)`` plus five timed
runs per query. Medians:

    query                          before      after     decision
    ─────────────────────────────  ─────────  ────────   ────────────────────
    filter by user_id, newest 50    461.6ms     4.4ms    ADD (user_id, created_at)
    lookup by request_id            267.5ms     2.9ms    ADD (request_id)
    tenant page 1 (largest tenant)    3.5ms        —     no index needed
    tenant page 1 (smallest tenant)   3.6ms        —     no index needed
    severity = critical (rarest)      3.9ms        —     no index needed
    status = blocked_malware          4.8ms        —     no index needed
    action = organization.deleted     3.7ms        —     no index needed
    ip prefix match                   7.4ms        —     no index needed
    q substring search               20.1ms        —     no index needed

The rejections matter as much as the additions:

* **No ``(org_id, created_at)``.** The obvious index for the most common query,
  and unnecessary: the table is HASH partitioned on ``org_id``, so a tenant's
  rows are already concentrated in one partition and the existing
  ``created_at`` index finds the newest 50 immediately. It was measured at
  3.5ms for the largest tenant *and* 3.6ms for the smallest — the case a
  partial index would have been meant to rescue.

* **No ``severity`` / ``status`` / ``action`` indexes.** None of these values is
  selective enough to matter: the rarest severity is still 4.5% of rows, so
  walking ``created_at`` DESC finds 50 matches within a few hundred rows. Every
  one measured under 5ms.

* **``ix_audit_logs_user_id`` is left in place** even though the new composite
  supersedes it for lookups. Dropping it changed single-row INSERT median from
  2.613ms to 2.551ms — inside the noise of a WAL fsync, and not worth a model
  change.

Both indexes are built with ``CREATE INDEX CONCURRENTLY`` **on each leaf
partition only**. PostgreSQL rejects ``CONCURRENTLY`` against a partitioned
parent; the parent index is created ``ON ONLY`` (no data read) and each
partition's index is then attached, at which point the parent becomes valid.
See ``scripts/audit/partitioned_index.py``.

Immutability
────────────
See ``db/audit_hardening.py`` for the full rationale, including why ``UPDATE``
is deliberately *not* revoked (the ``user_id`` foreign key is ``ON DELETE SET
NULL`` and PostgreSQL runs that referential action with the deleting role's
privileges — revoking ``UPDATE`` was measured to break account deletion).

Reversibility
─────────────
``downgrade()`` drops both indexes, both triggers, both functions and restores
the two grants. **No audit data is read, written or deleted in either
direction**, so this migration is genuinely reversible — unlike
``e4f5a6b7c8d9``, whose downgrade discards column values.

The one caveat: while downgraded, ``audit_logs`` is mutable again. Do not run
the downgrade on production to "fix" an unrelated problem without knowing that.
"""

import sys
from pathlib import Path

from alembic import op

# The hardening DDL and the partitioned-index procedure are shared with
# db/migrate_production_schema.py, which applies them on a fresh install where
# no migration ever runs. Keeping one copy is what stops the two install paths
# diverging.
_BACKEND = Path(__file__).resolve().parents[2]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from db.audit_hardening import (  # noqa: E402
    apply_audit_immutability,
    remove_audit_immutability,
)
from scripts.audit.partitioned_index import (  # noqa: E402
    create_partitioned_index,
    drop_partitioned_index,
)

# revision identifiers, used by Alembic.
revision = "f5a6b7c8d9e0"
down_revision = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None

_INDEXES = [
    ("ix_audit_logs_user_created", "user_id, created_at DESC"),
    ("ix_audit_logs_request_id", "request_id"),
]


def upgrade():
    # CREATE INDEX CONCURRENTLY cannot run inside a transaction block.
    with op.get_context().autocommit_block():
        conn = op.get_bind()
        for name, columns in _INDEXES:
            create_partitioned_index(conn, name, columns, echo=print)

    # The trigger and grant work is ordinary transactional DDL.
    conn = op.get_bind()
    result = apply_audit_immutability(conn)
    print(
        f"  append-only enforcement applied to audit_logs "
        f"({result['partitions']} partitions, role {result['app_role']})"
    )


def downgrade():
    conn = op.get_bind()
    remove_audit_immutability(conn)
    for name, _ in _INDEXES:
        drop_partitioned_index(conn, name, echo=print)

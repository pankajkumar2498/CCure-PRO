"""
scripts/audit/bench_audit_retention.py
─────────────────────────────────────────────────────────────────────────────
Measure what a legacy purge costs at 100,000 and 1,000,000 rows: per-batch
latency, how long the organisation's chain-head lock is actually held, and the
per-row cost of the append-only trigger's ``EXISTS`` against ``organizations``.

    docker exec ccure-api python -m scripts.audit.bench_audit_retention
    docker exec ccure-api python -m scripts.audit.bench_audit_retention --rows 100000

The 1,000,000-row run is an **offline one-off**, not CI. It takes minutes and
writes a million rows into a scratch database.

Why the head-lock hold time is the number that matters
──────────────────────────────────────────────────────
The purge takes the same ``FOR UPDATE`` lock on ``audit_chain_heads`` that the
insert trigger takes, so for as long as it holds that lock **no audit event can
be written for that organisation**. One transaction for a whole run would
therefore block a tenant's entire audit trail for the duration; batching exists
to bound it. This measures the bound rather than assuming it.

Safety
──────
Identical discipline to ``bench_audit_export.py``:

  * the database name must be a recognised disposable one; live names are
    refused outright;
  * every insert happens inside **one transaction that is unconditionally
    rolled back**, so nothing this script writes is ever committed;
  * there is no DELETE, TRUNCATE or DROP written in this file — the only
    deletion is the one performed by ``audit_retention.purge_legacy_v1``, whose
    own guards are part of what is being measured, and it is rolled back with
    everything else.

`CLAUDE.md` records what happened the last time a run of anything inherited the
application's ``DATABASE_URL``.
"""

from __future__ import annotations

import argparse
import os
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from sqlalchemy import text  # noqa: E402
from sqlalchemy.engine.url import make_url  # noqa: E402

_FORBIDDEN = {"ccure_test", "ccure_db", "vuln_intel", "postgres"}
_ALLOWED_EXACT = {"ccure_pytest_db"}
_ALLOWED_PREFIX = "pytest_"

BENCH_ORG = "org_bench_retention"


def _assert_disposable(url: str) -> str:
    name = make_url(url).database or ""
    if name in _FORBIDDEN:
        raise SystemExit(f"REFUSING to run against the live database {name!r}.")
    if name not in _ALLOWED_EXACT and not name.startswith(_ALLOWED_PREFIX):
        raise SystemExit(
            f"REFUSING to run against {name!r}: not a recognised disposable "
            f"database."
        )
    return name


def _ensure_org(db) -> None:
    from db.models import Organization

    if db.query(Organization).filter(Organization.id == BENCH_ORG).first():
        return
    db.add(
        Organization(
            id=BENCH_ORG,
            name="Retention Benchmark",
            slug="retention-benchmark",
            max_assets=1,
            max_users=1,
            is_active=True,
        )
    )
    db.flush()


def _seed_legacy(db, first: int, last: int) -> float:
    """Insert aged, unhashed rows — the shape retention actually removes.

    The chain trigger is disabled for the insert, which is both how real
    pre-chain history came to exist and the only way to produce an unhashed row
    at all: the trigger hashes every insert unconditionally and discards
    whatever the client supplied in those columns.
    """
    rows = last - first + 1
    base = datetime.now(timezone.utc) - timedelta(days=800)
    started = time.perf_counter()

    db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
    db.execute(
        text(
            """
            INSERT INTO audit_logs (
                id, org_id, action, resource_type, resource_id,
                status, severity, ip_address, user_agent, created_at
            )
            SELECT 'retbench_' || g, :org,
                   (ARRAY['user.login','user.logout','scan.created'])[1 + (g % 3)],
                   'user', 'res_' || g,
                   'success',
                   (ARRAY['info','low','medium'])[1 + (g % 3)],
                   ('10.180.6.' || (g % 254))::inet,
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/138.0.0.0',
                   :base + (g || ' seconds')::interval
            FROM generate_series(:first, :last) AS g
            """
        ),
        {"org": BENCH_ORG, "first": first, "last": last, "base": base},
    )
    db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))
    elapsed = time.perf_counter() - started
    print(f"  seeded {rows:,} unhashed rows in {elapsed:.1f}s")
    return elapsed


def _ensure_head(db) -> None:
    """A chain head must exist: the purge locks it and refuses without one."""
    present = db.execute(
        text("SELECT 1 FROM audit_chain.audit_chain_heads WHERE org_id = :o"),
        {"o": BENCH_ORG},
    ).scalar()
    if present:
        return
    db.execute(
        text(
            "INSERT INTO audit_logs (id, org_id, action, status, severity, created_at) "
            "VALUES ('retbench_anchor_evt', :o, 'user.login', 'success', 'info', now())"
        ),
        {"o": BENCH_ORG},
    )
    db.flush()


def _measure(db, batch: int, batches: int) -> None:
    """Run `batches` purge batches of `batch` rows and report the distribution."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=365)
    timings: list[float] = []
    lock_holds: list[float] = []
    deleted_total = 0

    for _ in range(batches):
        # The head lock is taken by the function itself; time the call, which is
        # exactly the window during which no audit write for this organisation
        # can proceed.
        started = time.perf_counter()
        row = db.execute(
            text(
                "SELECT deleted_count FROM audit_retention.purge_legacy_v1("
                "  :org, :cutoff, :batch, 90, 'bench', NULL, 'bench')"
            ),
            {"org": BENCH_ORG, "cutoff": cutoff, "batch": batch},
        ).fetchone()
        elapsed = time.perf_counter() - started
        timings.append(elapsed)
        lock_holds.append(elapsed)
        deleted_total += int(row.deleted_count or 0)
        if not row.deleted_count:
            break

    if not timings:
        print("    nothing eligible")
        return

    print(f"    batches run           : {len(timings)}")
    print(f"    rows deleted          : {deleted_total:,}")
    print(f"    batch median          : {statistics.median(timings) * 1000:8.1f} ms")
    print(
        f"    batch p95             : {sorted(timings)[int(len(timings) * 0.95) - 1] * 1000:8.1f} ms"
    )
    print(f"    batch max             : {max(timings) * 1000:8.1f} ms")
    print(
        f"    per row               : {sum(timings) / max(deleted_total, 1) * 1e6:8.1f} us"
    )
    print(
        f"    max head-lock hold    : {max(lock_holds) * 1000:8.1f} ms"
        "   <- audit writes for this org block for at most this long"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, action="append")
    parser.add_argument("--batch", type=int, default=1000)
    parser.add_argument(
        "--batches", type=int, default=20, help="how many batches to time"
    )
    args = parser.parse_args()
    sizes = args.rows or [100_000, 1_000_000]

    from core.audit_retention import retention_installed
    from db.base import SessionLocal

    db = SessionLocal()
    name = _assert_disposable(str(db.get_bind().url))
    print(f"audit retention benchmark — database {name}")

    try:
        state = retention_installed(db)
        if not state["installed"]:
            print(
                "\n  RETENTION NOT INSTALLED in this database. The purge cannot "
                "be measured here.\n  NOT VERIFIED — a DBA must run "
                "bootstrap_chain_retention.sql first."
            )
            return 2

        _ensure_org(db)
        _ensure_head(db)

        seeded = 0
        for size in sizes:
            print(f"\n── {size:,} legacy rows " + "─" * 40)
            _seed_legacy(db, seeded + 1, size)
            seeded = size
            print(f"  batch size {args.batch}:")
            _measure(db, args.batch, args.batches)
        return 0
    finally:
        db.rollback()
        db.close()
        print("\n  rolled back — nothing was committed")


if __name__ == "__main__":
    sys.exit(main())

"""
scripts/audit/bench_audit_retention.py
─────────────────────────────────────────────────────────────────────────────
Measure what a legacy purge actually costs in production: per-batch latency,
total runtime, and how long the organisation's chain-head lock is held.

    docker exec ccure-api python -m scripts.audit.bench_audit_retention
    docker exec ccure-api python -m scripts.audit.bench_audit_retention --rows 100000

DESTRUCTIVE — to its own synthetic data only
────────────────────────────────────────────
Unlike the read-only probes in this directory, this harness **commits**. It
creates one throwaway organisation, writes synthetic pre-chain rows for it,
purges them through ``audit_retention.purge_legacy_v1``, and removes the
organisation afterwards. Every row it touches is one it created.

**It must never touch `users` or `organizations` beyond the single synthetic
organisation it adds and then removes.** That is asserted, not assumed: the
count and a SHA-256 fingerprint of both tables are taken before and after, and
the run fails loudly if either moved. `users` is never written at all — the
synthetic organisation has no members, so its removal cascades to nothing in
that table.

Why it commits, and why the previous version's number was wrong
───────────────────────────────────────────────────────────────
The first version wrapped every batch in one transaction and rolled back, for
safety. That looked strictly better and quietly destroyed the measurement:
dead tuples from earlier batches accumulate and cannot be vacuumed while the
transaction is open, so each later selection skips more of them. It reported
**3,089 ms** per 1,000-row batch at a million rows and 189 ms at a hundred
thousand — a superlinear collapse that sent an index recommendation to review.

There is no index problem. Measured with per-batch commits, which is what
`core.audit_retention._purge_one_batch` actually does, the same batch at
200,000 rows takes **55 ms and does not grow**. The safety property and the
fidelity property were in tension and the harness took safety without noticing
it had invalidated the one number it exists to produce.

So this version commits per batch, exactly as production does, and buys its
safety back a different way: an isolated synthetic tenant, cleanup through the
real retention mechanism rather than a direct DELETE, and the protected-table
fingerprint check above.

What it does not clean up, and why
──────────────────────────────────
The retention anchors its own purges write **persist**. They are append-only by
design — nobody, including this harness, holds DELETE on
``audit_retention.retention_anchors``, and they carry no foreign key to
``organizations`` because an anchor is the record that a purge happened and
must outlive the tenant it describes. The count is reported at the end so the
residue is visible rather than silent.
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

#: Live databases, refused outright. This harness commits, so the guard matters
#: more here than in the read-only probes.
_FORBIDDEN = {"ccure_test", "ccure_db", "vuln_intel", "postgres"}
_ALLOWED_EXACT = {"ccure_pytest_db"}
_ALLOWED_PREFIX = "pytest_"

#: Never written to. Fingerprinted before and after; a difference fails the run.
_PROTECTED = ("users", "organizations")

#: Cleanup drains in large batches — it is not being timed, and a thousand
#: round trips to remove the tail would dominate the runtime.
_CLEANUP_BATCH = 10_000


def _assert_disposable(url: str) -> str:
    name = make_url(url).database or ""
    if name in _FORBIDDEN:
        raise SystemExit(
            f"REFUSING to run against {name!r}. This harness COMMITS; it may "
            f"only run against a disposable database."
        )
    if name not in _ALLOWED_EXACT and not name.startswith(_ALLOWED_PREFIX):
        raise SystemExit(
            f"REFUSING to run against {name!r}: not a recognised disposable "
            f"database. Expected one of {sorted(_ALLOWED_EXACT)} or a name "
            f"starting with {_ALLOWED_PREFIX!r}."
        )
    return name


def _fingerprint_protected(db) -> dict:
    """Count and SHA-256 of every protected table, for a before/after check."""
    out = {}
    for table in _PROTECTED:
        row = (
            db.execute(
                text(
                    f"""
                SELECT count(*) AS n,
                       encode(sha256(convert_to(
                         coalesce(string_agg(t.txt, '|' ORDER BY t.txt), ''),
                         'UTF8')), 'hex') AS fp
                  FROM (SELECT x::text AS txt FROM {table} x) t
                """
                )
            )
            .mappings()
            .one()
        )
        out[table] = (row["n"], row["fp"])
    return out


def _seed(db, org_id: str, rows: int) -> float:
    """Synthetic pre-chain rows for the throwaway tenant, plus its chain head.

    The chain trigger is disabled around the bulk insert — the only way to
    produce an unhashed row, and how genuinely pre-chain history came to exist.
    It is re-enabled in the same transaction, so no other session ever observes
    ``audit_logs`` unchained.
    """
    base = datetime.now(timezone.utc) - timedelta(days=800)
    started = time.perf_counter()

    db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_chain"))
    db.execute(
        text(
            """
            INSERT INTO audit_logs (id, org_id, action, resource_type,
                                    resource_id, status, severity, ip_address,
                                    user_agent, created_at)
            SELECT 'retbench_' || g, :org,
                   (ARRAY['user.login','user.logout','scan.created'])[1 + (g % 3)],
                   'user', 'res_' || g, 'success',
                   (ARRAY['info','low','medium'])[1 + (g % 3)],
                   ('10.180.6.' || (g % 254))::inet,
                   'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/138.0.0.0',
                   :base + (g || ' seconds')::interval
            FROM generate_series(1, :rows) AS g
            """
        ),
        {"org": org_id, "rows": rows, "base": base},
    )
    db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_chain"))

    # One ordinary event so the chain trigger creates the head the purge locks.
    db.execute(
        text(
            "INSERT INTO audit_logs (id, org_id, action, status, severity, "
            "                        created_at) "
            "VALUES ('retbench_head', :org, 'user.login', 'success', 'info', now())"
        ),
        {"org": org_id},
    )
    db.commit()
    db.execute(text("ANALYZE audit_logs"))
    db.commit()
    return time.perf_counter() - started


def _purge_batch(db, org_id: str, cutoff, batch: int) -> tuple[int, float, float]:
    """One batch, committed. Returns (deleted, call_ms, commit_ms).

    The chain-head lock is taken inside the function and released by the
    COMMIT, so the head-lock hold is call + commit — which is exactly the
    window during which no audit event can be written for this organisation.
    """
    started = time.perf_counter()
    row = db.execute(
        text(
            "SELECT deleted_count FROM audit_retention.purge_legacy_v1("
            "  :org, :cutoff, :batch, 90, 'bench', NULL, 'bench')"
        ),
        {"org": org_id, "cutoff": cutoff, "batch": batch},
    ).fetchone()
    call_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    db.commit()
    commit_ms = (time.perf_counter() - started) * 1000

    return int(row.deleted_count or 0), call_ms, commit_ms


def _measure(db, org_id: str, batch: int, batches: int) -> dict:
    cutoff = datetime.now(timezone.utc) - timedelta(days=365)
    latencies: list[float] = []
    holds: list[float] = []
    deleted_total = 0
    run_started = time.perf_counter()

    for _ in range(batches):
        deleted, call_ms, commit_ms = _purge_batch(db, org_id, cutoff, batch)
        if not deleted:
            break
        deleted_total += deleted
        latencies.append(call_ms + commit_ms)
        holds.append(call_ms + commit_ms)

    return {
        "batches": len(latencies),
        "deleted": deleted_total,
        "total_s": time.perf_counter() - run_started,
        "latencies": latencies,
        "holds": holds,
    }


def _report(label: str, result: dict) -> None:
    print(f"\n  {label}")
    if not result["latencies"]:
        print("    nothing eligible")
        return
    lat = sorted(result["latencies"])
    p95 = lat[max(int(len(lat) * 0.95) - 1, 0)]
    print(f"    batches committed     : {result['batches']}")
    print(f"    rows deleted          : {result['deleted']:,}")
    print(
        f"    batch first / last    : {result['latencies'][0]:8.1f} / {result['latencies'][-1]:8.1f} ms"
    )
    print(f"    batch median          : {statistics.median(lat):8.1f} ms")
    print(f"    batch p95             : {p95:8.1f} ms")
    print(f"    batch max             : {max(lat):8.1f} ms")
    print(
        f"    per row               : {result['total_s'] * 1e6 / max(result['deleted'], 1):8.1f} us"
    )
    print(f"    TOTAL RUNTIME         : {result['total_s']:8.2f} s")
    print(f"    head-lock median      : {statistics.median(result['holds']):8.1f} ms")
    print(
        f"    head-lock MAX         : {max(result['holds']):8.1f} ms"
        "   <- audit writes for this org block for at most this long"
    )


def _cleanup(db, org_id: str, cutoff) -> dict:
    """Remove every synthetic row **through the retention mechanism**, then the org.

    Not a direct DELETE: the point of the harness is to exercise the real path,
    and a TRUNCATE or a hand-written DELETE would both be refused by the
    append-only trigger anyway. What the purge cannot remove — the chained
    events it wrote about itself — goes when the organisation does, through the
    schema's own ``ON DELETE CASCADE``.
    """
    removed = 0
    while True:
        deleted, _, _ = _purge_batch(db, org_id, cutoff, _CLEANUP_BATCH)
        if not deleted:
            break
        removed += deleted

    chained = db.execute(
        text("SELECT count(*) FROM audit_logs WHERE org_id = :o"), {"o": org_id}
    ).scalar()

    # Guard the protected table explicitly: a synthetic tenant must never have
    # acquired members, and removing an organisation cascades into `users`.
    members = db.execute(
        text("SELECT count(*) FROM users WHERE org_id = :o"), {"o": org_id}
    ).scalar()
    if members:
        raise SystemExit(
            f"REFUSING to remove {org_id}: it has {members} user(s). Deleting "
            f"an organisation cascades into `users`, which this harness must "
            f"never touch. Remove the users first, by hand, deliberately."
        )

    db.execute(text("DELETE FROM organizations WHERE id = :o"), {"o": org_id})
    db.commit()

    anchors = db.execute(
        text(
            "SELECT count(*) FROM audit_retention.retention_anchors WHERE org_id = :o"
        ),
        {"o": org_id},
    ).scalar()
    return {"purged": removed, "cascaded": chained, "anchors_left": anchors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, action="append")
    parser.add_argument("--batch", type=int, default=1000)
    parser.add_argument(
        "--batches", type=int, default=30, help="how many batches to time"
    )
    args = parser.parse_args()
    sizes = args.rows or [100_000, 1_000_000]

    from ccure_platform.audit_log.retention import retention_installed
    from db.base import SessionLocal, gen_uuid
    from db.models import Organization

    db = SessionLocal()
    name = _assert_disposable(str(db.get_bind().url))
    print(f"audit retention benchmark — database {name}")
    print("  DESTRUCTIVE to its own synthetic data; commits per batch.")

    before = _fingerprint_protected(db)
    for table, (count, fingerprint) in before.items():
        print(f"  protected {table:14s} count={count:<6} sha256={fingerprint[:16]}…")

    try:
        state = retention_installed(db)
        if not state["installed"]:
            print(
                "\n  RETENTION NOT INSTALLED. NOT VERIFIED — a DBA must run "
                "bootstrap_chain_retention.sql first."
            )
            return 2

        cutoff = datetime.now(timezone.utc) - timedelta(days=365)
        for size in sizes:
            org_id = f"org_retbench_{gen_uuid()[:8]}"
            print(f"\n── {size:,} legacy rows ({org_id}) " + "─" * 24)

            db.add(
                Organization(
                    id=org_id,
                    name="Retention benchmark",
                    slug=f"{org_id}-slug",
                    is_active=True,
                )
            )
            db.flush()
            print(f"  seeded {size:,} rows in {_seed(db, org_id, size):.1f}s")

            _report(
                f"batch size {args.batch}, committed per batch:",
                _measure(db, org_id, args.batch, args.batches),
            )

            outcome = _cleanup(db, org_id, cutoff)
            print(
                f"\n    cleanup: {outcome['purged']:,} rows via the retention "
                f"mechanism, {outcome['cascaded']} more with the organisation"
            )
            print(
                f"    anchors retained (append-only by design): {outcome['anchors_left']}"
            )

        return 0
    finally:
        db.rollback()
        after = _fingerprint_protected(db)
        print("\n  PROTECTED TABLES")
        failed = False
        for table in _PROTECTED:
            same = before.get(table) == after[table]
            failed = failed or not same
            print(
                f"    [{'OK  ' if same else 'FAIL'}] {table:14s} "
                f"count={after[table][0]:<6} sha256={after[table][1][:16]}…"
            )
        if failed:
            print(
                "    A PROTECTED TABLE CHANGED. Investigate before trusting this run."
            )
        db.close()


if __name__ == "__main__":
    sys.exit(main())

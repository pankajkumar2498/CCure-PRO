"""
scripts/audit/bench_audit_export.py
─────────────────────────────────────────────────────────────────────────────
Measure what the audit export costs at 10,000 and 50,000 rows, in both
verification modes, and prove its memory does not grow with the export.

    docker exec ccure-api python -m scripts.audit.bench_audit_export
    docker exec ccure-api python -m scripts.audit.bench_audit_export --rows 10000

Why this does not reuse ``bench_audit_queries.py``
─────────────────────────────────────────────────
That harness builds its own ``pytest_audit_bench`` database from the model
definitions, which is right for measuring index shapes. It cannot be used here:
verification calls ``audit_chain.audit_record_hash_v1``, installed by a
superuser-only bootstrap the application role cannot run, so a freshly created
database has no chain and ``verify=true`` would silently degrade to
``unavailable`` — the benchmark would report the cheap path and call it the
expensive one. Re-creating the function locally is worse: two definitions of a
canonical form drift, and this file would become the second one.

Safety
──────
This measures against a **disposable** database that already carries the chain,
and it writes nothing that survives:

  * the database name must match the pytest pattern; live names are refused;
  * every insert happens inside **one transaction that is unconditionally
    rolled back** in a ``finally``, so nothing is ever committed;
  * there is no DELETE, TRUNCATE or DROP anywhere in this file — the rows the
    benchmark creates are removed by the ROLLBACK, not by a destructive
    statement that could be pointed somewhere else.

`CLAUDE.md` records what happened the last time a run of anything inherited the
application's ``DATABASE_URL``.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import tracemalloc
from datetime import datetime, timedelta, timezone

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from sqlalchemy import text  # noqa: E402
from sqlalchemy.engine.url import make_url  # noqa: E402

#: Live databases, refused outright even if a URL somehow names one.
_FORBIDDEN = {"ccure_test", "ccure_db", "vuln_intel", "postgres"}

#: The disposable databases this may run against. `ccure_pytest_db` is the
#: suite's own scratch database and is the only one with the chain installed.
_ALLOWED_EXACT = {"ccure_pytest_db"}
_ALLOWED_PREFIX = "pytest_"

BENCH_ORG = "org_bench_export"


def _assert_disposable(url: str) -> str:
    name = make_url(url).database or ""
    if name in _FORBIDDEN:
        raise SystemExit(f"REFUSING to run against the live database {name!r}.")
    if name not in _ALLOWED_EXACT and not name.startswith(_ALLOWED_PREFIX):
        raise SystemExit(
            f"REFUSING to run against {name!r}: not a recognised disposable "
            f"database. Expected one of {sorted(_ALLOWED_EXACT)} or a name "
            f"starting with {_ALLOWED_PREFIX!r}."
        )
    return name


def _ensure_org(db) -> None:
    """The throwaway tenant every benchmark row belongs to.

    Built through the ``Organization`` model rather than hand-written SQL so
    the column defaults come from one place. A literal INSERT here has to
    restate every NOT NULL column and goes stale the moment one is added.
    """
    from db.models import Organization

    if db.query(Organization).filter(Organization.id == BENCH_ORG).first():
        return
    db.add(
        Organization(
            id=BENCH_ORG,
            name="Export Benchmark",
            slug="export-benchmark",
            max_assets=1,
            max_users=1,
            is_active=True,
        )
    )
    db.flush()


def _seed(db, first: int, last: int) -> None:
    """Insert chained audit events numbered `first`..`last` inclusive.

    A single ``INSERT ... SELECT generate_series`` rather than one round trip
    per row: the per-row chain trigger still fires on every row, so the hashes
    are real, but the client/server turnarounds do not dominate the setup.

    Numbered by an explicit range rather than a count, because the sizes are
    measured cumulatively — the 50,000-row run tops up the 10,000 already
    present, and restarting the series at 1 collides on the primary key.
    """
    if last < first:
        return
    rows = last - first + 1
    base = datetime.now(timezone.utc) - timedelta(days=30)
    started = time.perf_counter()
    db.execute(
        text(
            """
            INSERT INTO audit_logs (
                id, org_id, user_id, action, resource_type, resource_id,
                changes, ip_address, user_agent, status, severity,
                request_id, actor_user_id, actor_username, created_at
            )
            SELECT
                'bench_' || g,
                :org,
                NULL,
                (ARRAY['user.login','user.logout','user.login_failed',
                       'scan.created','user.role_changed','report.downloaded'
                      ])[1 + (g % 6)],
                'user',
                'res_' || g,
                jsonb_build_object('n', g, 'note', 'benchmark row'),
                ('10.180.6.' || (g % 254))::inet,
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/138.0.0.0',
                CASE WHEN g % 11 = 0 THEN 'failure' ELSE 'success' END,
                (ARRAY['info','low','medium','high','critical'])[1 + (g % 5)],
                'req_' || g,
                'usr_bench_actor',
                'bench_actor',
                :base + (g || ' seconds')::interval
            FROM generate_series(:first, :last) AS g
            """
        ),
        {"org": BENCH_ORG, "first": first, "last": last, "base": base},
    )
    print(f"  seeded {rows:,} chained rows in {time.perf_counter() - started:.1f}s")


def _principal(db):
    """A superadmin, so the export is not additionally narrowed by tenancy.

    Created here if the database has none — the test database is truncated
    between runs, so it usually does not. Like everything else this script
    writes, the row disappears with the ROLLBACK; it is a real ``User`` rather
    than a stand-in because ``_scoped_query`` reads the ``role`` relationship,
    and a shim that answered those two attributes would be measuring a
    different query from the one the endpoint runs.
    """
    from db.models import Role, User

    user = (
        db.query(User).join(User.role).filter(User.role.has(name="superadmin")).first()
    )
    if user is not None:
        return user

    role = db.query(Role).filter(Role.name == "superadmin").first()
    if role is None:
        raise SystemExit("no superadmin role in this database; run the RBAC seed first")
    user = User(
        id="usr_bench_superadmin",
        username="bench_superadmin",
        email="bench_superadmin@benchmark.invalid",
        password_hash="not-a-usable-hash",
        org_id=BENCH_ORG,
        role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db.add(user)
    db.flush()
    print("  created a transient superadmin (removed by the rollback)")
    return user


def _measure(db, principal, rows: int, chain_schema: str | None, label: str) -> None:
    from db.models import AuditLog
    from reporting.audit_export import (
        VERIFICATION_NOT_REQUESTED,
        VERIFICATION_PERFORMED,
        iter_csv,
    )
    from routers.audit import (
        _apply_filters,
        _integrity_counts,
        _iter_export_rows,
        _scoped_query,
    )
    from sqlalchemy import func as sa_func

    def build():
        scoped = _scoped_query(db, principal, needs_user_join=False)
        return _apply_filters(
            scoped,
            user_id=None,
            action=None,
            resource_type=None,
            status=None,
            severity=None,
            ip_address=None,
            date_from=None,
            date_to=None,
            q=None,
        ).filter(AuditLog.org_id == BENCH_ORG)

    query = build()

    started = time.perf_counter()
    total = query.with_entities(sa_func.count(AuditLog.id)).order_by(None).scalar()
    count_ms = (time.perf_counter() - started) * 1000

    started = time.perf_counter()
    counts = _integrity_counts(db, query, chain_schema)
    tally_ms = (time.perf_counter() - started) * 1000

    meta = {
        "generated_at": datetime.now(timezone.utc),
        "exported_by": principal.username,
        "exported_by_user_id": principal.id,
        "organization_scope": BENCH_ORG,
        "row_count": total,
        "snapshot_upper_bound": datetime.now(timezone.utc),
        "filters": {},
        "request_id": "bench",
        "verification_mode": (
            VERIFICATION_PERFORMED if chain_schema else VERIFICATION_NOT_REQUESTED
        ),
        "verified_count": counts["verified"],
        "not_verified_count": counts["not_verified"],
        "legacy_unverifiable_count": counts["legacy_unverifiable"],
        "integrity_failure_count": counts["INTEGRITY_FAILURE"],
        "chain_schema": chain_schema,
    }

    # Consume the stream chunk by chunk and drop each one, exactly as an ASGI
    # server does. `tracemalloc` peak is the figure that matters: if it tracks
    # the export size, the generator is materialising and the cap is the only
    # thing standing between a large export and the API's memory.
    tracemalloc.start()
    started = time.perf_counter()
    written = 0
    emitted = 0

    def counted(source):
        """Count rows as they pass, rather than counting newlines afterwards.

        Newline counting looked equivalent and is not: the preamble is twenty
        lines of its own, and a `user_agent` or `changes` value containing a
        newline is quoted by the CSV writer and legitimately spans several.
        """
        nonlocal emitted
        for record in source:
            emitted += 1
            yield record

    for chunk in iter_csv(
        meta, counted(_iter_export_rows(db, query, chain_schema, page_size=1000))
    ):
        written += len(chunk)
    stream_s = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"\n  {label}  (n={total:,})")
    print(f"    count pass            : {count_ms:8.1f} ms")
    print(f"    integrity tally       : {tally_ms:8.1f} ms")
    print(f"    stream + render       : {stream_s * 1000:8.1f} ms")
    print(
        f"    total                 : {count_ms + tally_ms + stream_s * 1000:8.1f} ms"
    )
    print(
        f"    per row               : {(count_ms + tally_ms + stream_s * 1000) / max(total, 1) * 1000:8.1f} us"
    )
    print(f"    bytes produced        : {written:,}")
    print(f"    rows emitted          : {emitted:,}")
    print(f"    peak python heap      : {peak / 1024 / 1024:8.2f} MiB")
    print(f"    counts                : {counts}")
    assert emitted == total, f"stream emitted {emitted} rows for a count of {total}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rows",
        type=int,
        action="append",
        help="row count to measure; repeatable. Default: 10000 and 50000",
    )
    args = parser.parse_args()
    sizes = args.rows or [10_000, 50_000]

    from db.base import SessionLocal
    from routers.audit import _chain_hash_schema

    db = SessionLocal()
    name = _assert_disposable(str(db.get_bind().url))
    print(f"audit export benchmark — database {name}")

    try:
        chain_schema = _chain_hash_schema(db)
        if chain_schema is None:
            print(
                "\n  CHAIN NOT INSTALLED in this database. The verified mode "
                "cannot be measured here and would report as `unavailable`.\n"
                "  NOT VERIFIED — run the bootstrap first."
            )
            return 2
        print(f"  chain functions in    : {chain_schema}")

        _ensure_org(db)
        principal = _principal(db)
        seeded = 0
        for size in sizes:
            _seed(db, seeded + 1, size)
            seeded = size
            print(f"\n── {size:,} rows " + "─" * 46)
            _measure(db, principal, size, chain_schema, "verify=true  (performed)")
            _measure(db, principal, size, None, "verify=false (not_requested)")
        return 0
    finally:
        # Unconditional. Nothing this script wrote is ever committed, which is
        # what makes it safe to run against a database that holds real rows.
        db.rollback()
        db.close()
        print("\n  rolled back — nothing was committed")


if __name__ == "__main__":
    sys.exit(main())

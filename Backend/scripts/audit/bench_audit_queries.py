"""
scripts/audit/bench_audit_queries.py
─────────────────────────────────────────────────────────────────────────────
Measure the audit-log query shapes at realistic volumes, so index decisions are
made from `EXPLAIN (ANALYZE, BUFFERS)` rather than from intuition.

Safety
──────
This script **refuses to run against anything but a disposable database**. The
name must start with ``pytest_`` — the same pattern ``tests/conftest.py``
enforces — and the live names are rejected outright. `CLAUDE.md` records what
happened the last time a destructive run inherited the application's
``DATABASE_URL``.

Usage
─────
    python -m scripts.audit.bench_audit_queries --rows 10000   --setup
    python -m scripts.audit.bench_audit_queries --rows 100000  --setup
    python -m scripts.audit.bench_audit_queries --rows 1000000 --setup
    python -m scripts.audit.bench_audit_queries --rows 100000            # re-measure

``--setup`` rebuilds the table at the requested size. Without it the existing
data is measured, which is how the same dataset is compared before and after an
index.

Fidelity
────────
The queries are built by importing ``routers.audit``'s own ``_scoped_query`` and
``_apply_filters``. Hand-written SQL would drift from the endpoint the moment
either changed, and the point of the exercise is to measure what the API
actually runs — including the ``users`` outer join and the ``DISTINCT`` that the
non-superadmin path adds.
"""

from __future__ import annotations

import argparse
import os
import random
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from sqlalchemy import create_engine, func, text  # noqa: E402
from sqlalchemy.engine.url import make_url  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

#: Only a database whose name matches this may be touched.
_DISPOSABLE_PREFIX = "pytest_"

#: Rejected even if renamed into the pattern.
_FORBIDDEN = {"ccure_test", "ccure_db", "vuln_intel", "postgres", "ccure_pytest_db"}

_ORGS = [f"org_bench_{i:02d}" for i in range(12)]
_ACTIONS = [
    ("user.login", "info", "success"),
    ("user.logout", "info", "success"),
    ("user.login_failed", "medium", "failure"),
    ("scan.created", "low", "success"),
    ("scan.completed", "info", "success"),
    ("user.created", "medium", "success"),
    ("user.role_changed", "high", "success"),
    ("user.password_reset", "high", "success"),
    ("report.downloaded", "low", "success"),
    ("organization.deleted", "critical", "success"),
    ("user.mfa_disabled", "high", "success"),
    ("upload_evidence", "low", "blocked_malware"),
]


def _bench_url() -> str:
    url = os.environ.get("BENCH_DATABASE_URL")
    if not url:
        base = os.environ["DATABASE_URL"]
        u = make_url(base)
        # `str(URL)` renders the password as "***"; the URL has to be
        # rendered explicitly or the connection fails auth.
        url = u.set(database="pytest_audit_bench").render_as_string(hide_password=False)
    name = make_url(url).database or ""
    if name in _FORBIDDEN or not name.startswith(_DISPOSABLE_PREFIX):
        raise SystemExit(
            f"REFUSING to run against {name!r}. The benchmark database name must "
            f"start with {_DISPOSABLE_PREFIX!r} and must not be a live database."
        )
    return url


def ensure_database(url: str) -> None:
    """Create the benchmark database if it does not exist."""
    target = make_url(url)
    admin = create_engine(
        target.set(database="postgres").render_as_string(hide_password=False),
        isolation_level="AUTOCOMMIT",
    )
    with admin.connect() as c:
        exists = c.execute(
            text("SELECT 1 FROM pg_database WHERE datname = :n"),
            {"n": target.database},
        ).scalar()
        if not exists:
            c.execute(text(f'CREATE DATABASE "{target.database}"'))
            print(f"  created database {target.database}")
        else:
            print(f"  database {target.database} already exists")
    admin.dispose()


def build_schema(engine) -> None:
    """
    Create the tables these queries touch, using the **real** model definitions
    for ``organizations``, ``roles`` and ``users``.

    A hand-written minimal ``users`` table is not good enough: the endpoint uses
    ``joinedload(AuditLog.user)``, so the real query selects every user column,
    and row width is part of what is being measured. ``audit_logs`` is created
    by hand only because ``create_all`` cannot express ``PARTITION BY HASH``.
    """
    from db.models import Organization, Role, User

    with engine.begin() as c:
        c.execute(text("DROP TABLE IF EXISTS audit_logs CASCADE"))
    for table in (User.__table__, Role.__table__, Organization.__table__):
        table.drop(engine, checkfirst=True)
    for table in (Organization.__table__, Role.__table__, User.__table__):
        table.create(engine, checkfirst=True)

    with engine.begin() as c:
        # Same declaration as db/models/users.py: HASH partitioned on org_id,
        # composite primary key, and the phase-1 columns.
        c.execute(
            text(
                """
                CREATE TABLE audit_logs (
                    id            VARCHAR(200) NOT NULL,
                    org_id        VARCHAR(100) NOT NULL REFERENCES organizations(id),
                    user_id       VARCHAR(150) REFERENCES users(id),
                    action        VARCHAR(100) NOT NULL,
                    resource_type VARCHAR(100),
                    resource_id   VARCHAR(255),
                    changes       JSONB,
                    ip_address    INET,
                    user_agent    TEXT,
                    status        VARCHAR(20) NOT NULL DEFAULT 'success',
                    severity      VARCHAR(20) NOT NULL DEFAULT 'medium',
                    request_id    VARCHAR(64),
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (id, org_id)
                ) PARTITION BY HASH (org_id)
                """
            )
        )
        for i in range(8):
            c.execute(
                text(
                    f"CREATE TABLE audit_logs_p{i} PARTITION OF audit_logs "
                    f"FOR VALUES WITH (MODULUS 8, REMAINDER {i})"
                )
            )
        # Exactly the indexes the model declares today. Anything beyond these is
        # what this exercise exists to decide.
        c.execute(text("CREATE INDEX ix_audit_logs_action ON audit_logs (action)"))
        c.execute(text("CREATE INDEX ix_audit_logs_created ON audit_logs (created_at)"))
        c.execute(text("CREATE INDEX ix_audit_logs_org_id ON audit_logs (org_id)"))
        c.execute(text("CREATE INDEX ix_audit_logs_user_id ON audit_logs (user_id)"))
    print("  schema built (8 hash partitions, baseline indexes only)")


def seed(engine, rows: int) -> None:
    """Generate `rows` audit events spread over 12 orgs and 18 months."""
    # Seeded through the ORM so every model-side default applies. Hand-written
    # INSERTs here meant guessing which columns are NOT NULL, and getting it
    # wrong is a failed run rather than a wrong measurement — but it is still
    # wasted time.
    from db.models import Organization, Role, User

    with Session(engine) as db:
        if not db.get(Role, 1):
            db.add(
                Role(
                    id=1, name="bench_admin", description="bench", is_system_role=False
                )
            )
            db.flush()
        for org_id in _ORGS:
            if not db.get(Organization, org_id):
                db.add(
                    Organization(
                        id=org_id,
                        name=f"Bench Org {org_id}",
                        slug=f"bench-{org_id}",
                        max_assets=1000,
                        max_users=100,
                        is_active=True,
                    )
                )
        db.flush()
        for org_id in _ORGS:
            for n in range(10):
                uid = f"usr_{org_id}_{n}"
                if not db.get(User, uid):
                    db.add(
                        User(
                            id=uid,
                            username=f"user{n}_{org_id}",
                            email=f"user{n}@{org_id}.example.com",
                            full_name=f"User {n}",
                            password_hash="x",
                            org_id=org_id,
                            role_id=1,
                            is_active=True,
                            is_verified=True,
                        )
                    )
        db.commit()

    # generate_series in the database: shipping a million rows over the wire
    # from Python would measure the driver, not the schema.
    print(f"  seeding {rows:,} rows...")
    started = time.perf_counter()
    actions = ",".join(f"'{a}'" for a, _, _ in _ACTIONS)
    sevs = ",".join(f"'{s}'" for _, s, _ in _ACTIONS)
    stats = ",".join(f"'{st}'" for _, _, st in _ACTIONS)
    orgs = ",".join(f"'{o}'" for o in _ORGS)

    # The random picks are made in a derived table over generate_series, NOT in
    # a CROSS JOIN LATERAL. A lateral whose body does not reference the outer
    # row is evaluated once and treated as a constant: the first version of this
    # seed put all 100,000 rows in a single organisation and a single action,
    # which silently made every tenant-scoped measurement meaningless.
    #
    # The org distribution is deliberately skewed — one dominant tenant holding
    # ~40% — because that is what a real deployment looks like, and an even
    # 1/12 spread would flatter the tenant-scoped queries.
    sql = f"""
        INSERT INTO audit_logs
            (id, org_id, user_id, action, resource_type, resource_id,
             changes, ip_address, user_agent, status, severity,
             request_id, created_at)
        SELECT
            gen_random_uuid()::text,
            s.org_id,
            CASE WHEN s.r_user < 0.9
                 THEN 'usr_' || s.org_id || '_' || (s.r_user * 10)::int
                 ELSE NULL END,
            (ARRAY[{actions}])[s.k],
            'user',
            'res_' || (s.r_res * 10000)::int,
            CASE WHEN s.r_chg < 0.3
                 THEN jsonb_build_object('field',
                      jsonb_build_object('old', 'a', 'new', 'b'))
                 ELSE NULL END,
            ('10.180.' || (s.r_ip * 6)::int || '.'
                       || (s.r_ip2 * 254)::int)::inet,
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120',
            (ARRAY[{stats}])[s.k],
            (ARRAY[{sevs}])[s.k],
            gen_random_uuid()::text,
            now() - (s.r_age * interval '540 days')
        FROM (
            SELECT
                CASE WHEN random() < 0.4
                     THEN 'org_bench_00'
                     ELSE (ARRAY[{orgs}])[2 + (random() * 10)::int] END AS org_id,
                1 + (random() * {len(_ACTIONS) - 1})::int AS k,
                random() AS r_user, random() AS r_res,  random() AS r_chg,
                random() AS r_ip,   random() AS r_ip2,  random() AS r_age
            FROM generate_series(1, :n) AS g(i)
        ) s
    """
    with engine.begin() as c:
        c.execute(text(sql), {"n": rows})
    print(f"  seeded in {time.perf_counter() - started:.1f}s")

    print("  ANALYZE...")
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:
        c.execute(text("ANALYZE audit_logs"))
        c.execute(text("ANALYZE users"))


# ─── The queries under test, built from the router's own helpers ─────────────


class _FakeRole:
    def __init__(self, name):
        self.name = name


class _FakeUser:
    def __init__(self, org_id, role):
        self.org_id = org_id
        self.role = _FakeRole(role)


def query_shapes(db: Session):
    """(label, sqlalchemy_query) for every access pattern the API exposes."""
    from routers.audit import _apply_filters, _scoped_query

    tenant = _FakeUser(_ORGS[0], "org_admin")
    root = _FakeUser(_ORGS[0], "superadmin")
    since = datetime.now(timezone.utc) - timedelta(days=7)

    def build(user, *, q=None, **filters):
        base = _scoped_query(db, user, needs_user_join=bool(q))
        args = dict(
            user_id=None,
            action=None,
            resource_type=None,
            status=None,
            severity=None,
            ip_address=None,
            date_from=None,
            date_to=None,
            q=q,
        )
        args.update(filters)
        return _apply_filters(base, **args)

    from db.models import AuditLog

    order = AuditLog.created_at.desc()

    return [
        ("tenant list, page 1", build(tenant).order_by(order).limit(50)),
        (
            "tenant list, page 20 (offset 1000)",
            build(tenant).order_by(order).offset(1000).limit(50),
        ),
        # The pager's count, expressed exactly as list_audit_logs builds it.
        # An earlier version of this benchmark listed `build(tenant)` here,
        # which measured *fetching all 40,000 matching rows* rather than
        # counting them — a number six times larger than the endpoint's real
        # cost, attached to the wrong label.
        (
            "tenant COUNT(*) (the pager)",
            build(tenant).with_entities(func.count()).order_by(None),
        ),
        (
            "tenant fetch-all (not an endpoint; scale reference)",
            build(tenant),
        ),
        ("superadmin list, page 1", build(root).order_by(order).limit(50)),
        ("severity=high", build(tenant, severity="high").order_by(order).limit(50)),
        ("status=failure", build(tenant, status="failure").order_by(order).limit(50)),
        (
            "action=user.login",
            build(tenant, action="user.login").order_by(order).limit(50),
        ),
        (
            "user_id=<one user>",
            build(tenant, user_id=f"usr_{_ORGS[0]}_3").order_by(order).limit(50),
        ),
        (
            "date range: last 7 days",
            build(tenant, date_from=since).order_by(order).limit(50),
        ),
        (
            "severity=high AND last 7 days",
            build(tenant, severity="high", date_from=since).order_by(order).limit(50),
        ),
        (
            "ip prefix 10.180.3.",
            build(tenant, ip_address="10.180.3.").order_by(order).limit(50),
        ),
        (
            "q = substring 'role_chang'",
            build(tenant, q="role_chang").order_by(order).limit(50),
        ),
        (
            "q = substring, bounded by 7d",
            build(tenant, q="role_chang", date_from=since).order_by(order).limit(50),
        ),
    ]


def explain(db: Session, query, label: str, repeats: int = 5) -> dict:
    """Run EXPLAIN (ANALYZE, BUFFERS) and time the query `repeats` times."""
    compiled = query.statement.compile(db.bind, compile_kwargs={"literal_binds": True})
    sql = str(compiled)

    plan_rows = db.execute(
        text(f"EXPLAIN (ANALYZE, BUFFERS, TIMING ON) {sql}")
    ).fetchall()
    plan = "\n".join(r[0] for r in plan_rows)

    timings = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        db.execute(text(sql)).fetchall()
        timings.append((time.perf_counter() - t0) * 1000)

    scans = []
    for line in plan.splitlines():
        s = line.strip()
        if s.startswith("->") or s.startswith("Seq Scan") or s.startswith("Index"):
            head = s.lstrip("-> ").split("  (")[0]
            if head.startswith(
                (
                    "Seq Scan",
                    "Index Scan",
                    "Index Only Scan",
                    "Bitmap Heap Scan",
                    "Bitmap Index Scan",
                )
            ):
                scans.append(head)

    shared_read = sum(
        int(p.split("read=")[1].split()[0])
        for p in plan.split("shared")[1:]
        if "read=" in p
    )
    return {
        "label": label,
        "median_ms": statistics.median(timings),
        "min_ms": min(timings),
        "max_ms": max(timings),
        "seq_scans": sum(1 for s in scans if s.startswith("Seq Scan")),
        "scan_summary": "; ".join(dict.fromkeys(scans))[:150],
        "shared_read": shared_read,
        "plan": plan,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=100000)
    ap.add_argument("--setup", action="store_true", help="rebuild and reseed")
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--plans", action="store_true", help="print full plans")
    ap.add_argument("--label", default="", help="tag for this run, e.g. 'after-idx'")
    args = ap.parse_args()

    url = _bench_url()
    print(f"benchmark database: {make_url(url).database}")

    if args.setup:
        ensure_database(url)

    engine = create_engine(url)
    if args.setup:
        build_schema(engine)
        seed(engine, args.rows)

    with Session(engine) as db:
        actual = db.execute(text("SELECT count(*) FROM audit_logs")).scalar()
        # A partitioned parent stores nothing itself, so
        # pg_total_relation_size('audit_logs') is 0. Sum the leaves.
        size = db.execute(
            text(
                """
                SELECT pg_size_pretty(sum(pg_total_relation_size(inhrelid)))
                  FROM pg_inherits WHERE inhparent = 'audit_logs'::regclass
                """
            )
        ).scalar()
        print(
            f"\nrows={actual:,}  total relation size={size}"
            f"{'  [' + args.label + ']' if args.label else ''}\n"
        )

        print(
            f"{'QUERY':<38} {'MEDIAN':>9} {'MIN':>8} {'MAX':>8} "
            f"{'SEQ':>4} {'READ':>8}  PLAN"
        )
        print("-" * 135)
        results = []
        for label, q in query_shapes(db):
            r = explain(db, q, label, repeats=args.repeats)
            results.append(r)
            print(
                f"{r['label']:<38} {r['median_ms']:>8.1f}ms {r['min_ms']:>7.1f}ms "
                f"{r['max_ms']:>7.1f}ms {r['seq_scans']:>4} {r['shared_read']:>8} "
                f" {r['scan_summary'][:60]}"
            )
            if args.plans:
                print("\n" + r["plan"] + "\n")

        slow = [r for r in results if r["median_ms"] > 200]
        print("\n" + "=" * 135)
        print(f"queries slower than 200ms: {len(slow)}")
        for r in sorted(slow, key=lambda x: -x["median_ms"]):
            print(
                f"  {r['median_ms']:>8.1f}ms  {r['label']}  "
                f"[{r['scan_summary'][:70]}]"
            )


if __name__ == "__main__":
    main()

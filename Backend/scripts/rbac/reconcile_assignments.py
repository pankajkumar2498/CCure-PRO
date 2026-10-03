"""
Report (and, in a controlled environment only, close) the gap between legacy roles and
RBAC assignments.

    python -m scripts.rbac.reconcile_assignments                 # read-only report
    python -m scripts.rbac.reconcile_assignments --json
    python -m scripts.rbac.reconcile_assignments --apply --allow-database NAME

The report is the default and writes nothing. ``--apply`` assigns **only** accounts that
have no live RBAC assignment, the role the golden mapping names for their legacy role.
It is refused unless ``--allow-database`` names the connected database exactly, and is
never offered for the live application database: production users are not assigned
automatically. Run the report first and read every list.

RBAC-4. docs/architecture/RBAC_AUTHORITY_MIGRATION.md
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

LIVE_DATABASES = {"ccure_db", "ccure_test", "vuln_intel"}


def _database_name(db) -> str:
    from sqlalchemy import text

    return str(db.execute(text("SELECT current_database()")).scalar())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--allow-database", metavar="NAME")
    args = ap.parse_args(argv)

    from ccure_platform.rbac import reconcile
    from db.base import SessionLocal

    db = SessionLocal()
    try:
        name = _database_name(db)
        report = reconcile.reconcile(db)
        planned = reconcile.plan(db, report)
        if args.json:
            print(
                json.dumps(
                    {
                        "database": name,
                        "counts": report.counts(),
                        "missing": [asdict(f) for f in report.missing],
                        "incorrect": [asdict(f) for f in report.incorrect],
                        "duplicate": [asdict(f) for f in report.duplicate],
                        "revoked_but_assigned": [
                            asdict(f) for f in report.revoked_but_assigned
                        ],
                        "without_legacy": [asdict(f) for f in report.without_legacy],
                        "planned": [asdict(p) for p in planned],
                    },
                    indent=2,
                    default=str,
                )
            )
        else:
            print(f"database: {name}")
            for k, v in report.counts().items():
                print(f"  {k:22} {v}")
            print(f"  would assign           {len(planned)}")
        if not args.apply:
            return 0 if report.consistent else 2
        if name in LIVE_DATABASES or args.allow_database != name:
            print(
                f"refused: --apply needs --allow-database {name!r} and is never "
                "permitted on the live application database",
                file=sys.stderr,
            )
            return 3
        n = reconcile.apply(db, planned)
        db.commit()
        print(f"assigned {n} account(s)")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())

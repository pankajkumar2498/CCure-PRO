"""
scripts/audit/purge_audit_retention.py
─────────────────────────────────────────────────────────────────────────────
Phase 6a. Report what audit retention would remove, and — only when told
explicitly — remove it.

    # what would happen (writes nothing)
    docker exec ccure-api python -m scripts.audit.purge_audit_retention

    # actually delete
    docker exec ccure-api python -m scripts.audit.purge_audit_retention --apply

**Dry run is the default**, and a dry run writes nothing at all: no delete, no
anchor, no chain-head update, no audit event. It reaches a read-only preview
function and stops. ``--apply`` is the only way into the mutating path, and it
is deliberately a word rather than a flag character — ``-y`` on the wrong line
of a runbook is how this kind of thing goes wrong.

Legacy rows only. A row with no ``record_hash`` predates the tamper-evidence
chain and nothing can ever have linked to it, so removing it cannot break a
chain. Chained rows are phase 6b; the database refuses them here regardless of
what this script asks for.

Exit codes: 0 completed (or would have), 1 refused by a precondition,
2 retention not installed in this database.
"""

from __future__ import annotations

import argparse
import os
import sys

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

from config import AppConfig  # noqa: E402
from core.audit_retention import (  # noqa: E402
    NOT_INSTALLED_HINT,
    RetentionRefused,
    newest_backup,
    retention_installed,
    run_retention,
)
from db.base import SessionLocal  # noqa: E402


def _print_settings() -> None:
    print("SETTINGS")
    print(
        f"  AUDIT_LOG_RETENTION_DAYS            : {AppConfig.AUDIT_LOG_RETENTION_DAYS}"
    )
    print(
        f"  AUDIT_RETENTION_MIN_DAYS            : {AppConfig.AUDIT_RETENTION_MIN_DAYS}"
    )
    print(
        f"  AUDIT_RETENTION_BATCH_SIZE          : {AppConfig.AUDIT_RETENTION_BATCH_SIZE}"
    )
    print(
        f"  AUDIT_RETENTION_MAX_ROWS_PER_RUN    : {AppConfig.AUDIT_RETENTION_MAX_ROWS_PER_RUN}"
    )
    print(
        f"  AUDIT_RETENTION_REQUIRE_BACKUP_HOURS: {AppConfig.AUDIT_RETENTION_REQUIRE_BACKUP_HOURS}"
    )
    print(
        f"  AUDIT_RETENTION_DRY_RUN             : {AppConfig.AUDIT_RETENTION_DRY_RUN}"
    )
    path, age = newest_backup()
    if path is None:
        print("  newest backup                       : none found")
    else:
        print(f"  newest backup                       : {path.name} ({age:.1f}h old)")


def _print_preview(rows: list[dict]) -> None:
    print("\nPER ORGANISATION")
    print(
        f"  {'organisation':28s} {'eligible':>9s} {'legacy':>8s} "
        f"{'chained':>8s}  {'hold':>5s}  oldest eligible"
    )
    for row in rows:
        print(
            f"  {row['org_id']:28s} {row['eligible_count']:9d} "
            f"{row['legacy_total']:8d} {row['chained_total']:8d}  "
            f"{'YES' if row['on_hold'] else '-':>5s}  "
            f"{row['oldest'].isoformat() if row['oldest'] else '-'}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually delete. Without this nothing is written.",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        state = retention_installed(db)
        print(f"audit retention — database {db.get_bind().url.database}")
        print(
            f"  installed: {state['installed']}  "
            f"(schema={state['schema']} role={state['role']} "
            f"anchors={state['anchors']} holds={state['holds']} "
            f"purge_fn={state['purge_function']})"
        )
        if not state["installed"]:
            print("\n" + NOT_INSTALLED_HINT)
            return 2

        print()
        _print_settings()

        try:
            report = run_retention(db, dry_run=not args.apply, operator="cli")
        except RetentionRefused as refusal:
            print(f"\nREFUSED\n  {refusal}")
            return 1

        _print_preview(report["preview"])

        print()
        if report["dry_run"]:
            print("DRY RUN — nothing was written.")
            print(f"  would delete : {report['would_delete_total']} legacy row(s)")
            print(f"  across       : {len(report['eligible_orgs'])} organisation(s)")
            print(f"  cutoff       : {report['cutoff']}")
            print("\n  Re-run with --apply to perform the deletion.")
        else:
            print("APPLIED")
            print(f"  deleted      : {report['deleted_total']} legacy row(s)")
            print(f"  organisations: {report['purged']}")
            print(f"  backup       : {report['backup_reference']}")
            if report["capped"]:
                print(
                    f"  NOTE: stopped at the {report['max_rows']}-row per-run cap; "
                    "the remainder is removed on the next run."
                )

        if report["held_orgs"]:
            print("\n  HELD (never purged, and the skip is audited):")
            for org in sorted(report["held_orgs"]):
                print(f"    {org}")
        if report["deferred_orgs"]:
            print("\n  DEFERRED (an export held the shared lock):")
            for org in report["deferred_orgs"]:
                print(f"    {org}")

        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())

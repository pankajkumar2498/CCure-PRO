"""
Delete scan/test data from the ccure_test database.

This script is intentionally scoped to a fixed allowlist of tables and refuses
to run unless DATABASE_URL points at the ccure_test database.

Usage:
    python Backend/scripts/admin/clear_ccure_test_data.py --dry-run
    python Backend/scripts/admin/clear_ccure_test_data.py --yes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from config import AppConfig

EXPECTED_DATABASE = "ccure_test"

# Delete children before parents so foreign-key checks stay happy.
TABLES_TO_CLEAR = (
    "notifications",
    "refresh_token_sessions",
    "audit_logs",
    "asset_vulnerabilities",
    "scan_phases",
    "services",
    "assets",
    "scans",
    "vulnerability_definitions",
)


def _database_name(database_url: str) -> str:
    return make_url(database_url).database or ""


def _quoted_table_list() -> str:
    return ", ".join(TABLES_TO_CLEAR)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Delete all rows from selected ccure_test tables only: "
            f"{_quoted_table_list()}"
        )
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Actually delete rows. Without this, the script only prints counts.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print row counts without deleting anything.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database_url = AppConfig.DATABASE_URL
    database_name = _database_name(database_url)

    if database_name != EXPECTED_DATABASE:
        print(
            "Refusing to run: DATABASE_URL must point to "
            f"{EXPECTED_DATABASE!r}, but points to {database_name!r}."
        )
        return 1

    if args.yes and args.dry_run:
        print("Use either --yes or --dry-run, not both.")
        return 1

    dry_run = args.dry_run or not args.yes
    engine = create_engine(database_url, pool_pre_ping=True)

    print(f"Database: {database_name}")
    print(f"Tables: {_quoted_table_list()}")

    with engine.begin() as conn:
        counts = {
            table: conn.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar_one()
            for table in TABLES_TO_CLEAR
        }

        print("\nRows before cleanup:")
        for table, count in counts.items():
            print(f"  {table}: {count}")

        if dry_run:
            print("\nDry run only. Re-run with --yes to delete these rows.")
            return 0

        print("\nDeleting rows...")
        deleted_counts = {}
        for table in TABLES_TO_CLEAR:
            result = conn.execute(text(f'DELETE FROM "{table}"'))
            deleted_counts[table] = result.rowcount

        print("\nRows deleted:")
        for table, count in deleted_counts.items():
            print(f"  {table}: {count}")

    print("\nCleanup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""
scripts/verification/check_cve_source.py
─────────────────────────────────────────────────────────────────────────────
Reports which CVE data source the scanner will actually use, and why.

This exists because the failure it detects is silent: when the dedicated
vulnerability-intelligence database is unreachable — wrong URL, missing
privileges, container not up — the scanner degrades to a small bundled SQLite
snapshot that has no CPE table. Findings then cannot be checked against any
version range, so a fully patched host still collects decades-old CVEs. The
only visible symptom is a log line nobody reads.

Run it before trusting a report:

    python scripts/verification/check_cve_source.py

Exit codes:  0 = using the dedicated database
             1 = degraded (SQLite or hardcoded hints)
             2 = no CVE data available at all
"""

from __future__ import annotations

import os
import re
import sys

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
)

#: Tables the version-gating logic depends on. Without `cpe` there are no
#: version ranges, and every finding is unverifiable.
REQUIRED_TABLES = ("cve", "cpe", "cvss")
OPTIONAL_TABLES = ("epss", "kev", "exploits", "cwe", "cve_references")


def _mask(url: str) -> str:
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:***@", str(url or ""))


def main() -> int:
    from config import AppConfig
    from core.cve_database import get_cve_database
    from core.vuln_intel import get_vuln_engine
    from sqlalchemy import text

    vuln_url = AppConfig.VULN_DB_URL
    app_url = AppConfig.DATABASE_URL

    print("CVE data source check")
    print("=" * 66)
    print(f"  Application database : {_mask(app_url)}")
    print(f"  Vulnerability intel  : {_mask(vuln_url)}")

    if str(vuln_url) == str(app_url):
        print(
            "\n  WARNING: the vulnerability-intel URL is identical to the\n"
            "  application database. Set VULN_DB_NAME / VULN_DB_USER (or\n"
            "  VULNERABILITY_INTEL_DATABASE_URL) to point at the dedicated\n"
            "  CVE database."
        )

    # ── Reachability and privileges, table by table ─────────────────────────
    print("\n  Dedicated CVE database:")
    reachable, readable, counts = False, [], {}
    denied = []

    try:
        engine = get_vuln_engine()
        with engine.connect() as conn:
            reachable = True
            for table in REQUIRED_TABLES + OPTIONAL_TABLES:
                try:
                    n = conn.execute(text(f'SELECT count(*) FROM "{table}"')).scalar()
                    readable.append(table)
                    counts[table] = n
                except Exception as exc:
                    conn.rollback()
                    if "permission denied" in str(exc).lower():
                        denied.append(table)
                    else:
                        counts[table] = None
    except Exception as exc:
        print(f"    NOT REACHABLE: {str(exc).splitlines()[0][:88]}")

    if reachable:
        print("    connection: OK")
        for table in REQUIRED_TABLES + OPTIONAL_TABLES:
            if table in counts and counts[table] is not None:
                print(f"      {table:16s} {counts[table]:>12,} rows")
            elif table in denied:
                print(f"      {table:16s} {'--':>12}  PERMISSION DENIED")
            else:
                print(f"      {table:16s} {'--':>12}  missing")

    if denied:
        print(
            f"\n    {len(denied)} table(s) unreadable by this role.\n"
            f"    Fix: run scripts/grant_vuln_intel_access.sql as the table owner."
        )

    # ── What the scanner will actually do ───────────────────────────────────
    db = get_cve_database()
    print("\n" + "=" * 66)
    print(f"  SCANNER WILL USE: {db.backend.upper()}")

    if db.backend == "postgresql":
        missing = [t for t in REQUIRED_TABLES if t not in readable]
        if missing:
            print(f"  Degraded: required table(s) unreadable: {', '.join(missing)}")
            return 1
        print("  Full CPE version ranges available - findings can be verified")
        print("  and patched hosts ruled out.")
        return 0

    if db.backend == "sqlite":
        print(f"  Source: {db.db_path}")
        print(
            "\n  DEGRADED. This snapshot has no CPE table, so no finding can be\n"
            "  checked against a version range. Reports will contain unverified\n"
            "  matches and patched hosts will not be ruled out.\n"
            "  Do not treat reports produced in this state as authoritative."
        )
        return 1

    print(
        "\n  NO CVE DATA. The scanner will fall back to a handful of hardcoded\n"
        "  hints. Vulnerability results will be effectively meaningless."
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

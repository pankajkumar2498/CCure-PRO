"""
Backend/scripts/verification/check_scan_records.py
──────────────────────────────────────────────────────────────────────────────
Print the scans, users and organizations a database currently holds, and
optionally the full detail of one scan.

Was tests/test_debug_scan.py, where it was a diagnostic wearing a test's name:
its only assertion was `assert True`, so it ran on every CI pass and could
never fail. It is a probe, not a test, and lives with the other probes now.

Usage
─────
  # From the Backend directory:
  python scripts/verification/check_scan_records.py
  python scripts/verification/check_scan_records.py scn_king_fe394fd3_06jul26_fscr
"""

import os
import sys

# Ensure the root of the project is in python path
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from db.base import SessionLocal
from db.models.rbac import Organization
from db.models.scans import Scan
from db.models.users import User


def check_scan_records(scan_id: str | None = None):
    db = SessionLocal()
    try:
        scans = db.query(Scan).all()
        print("=== Scans ===")
        print(f"Total scans: {len(scans)}")
        for s in scans:
            print(
                f"ID: {s.id} | org_id: {s.org_id} | created_by: {s.created_by} | status: {s.status}"
            )

        # The scan id used to be a hardcoded constant left over from one July
        # investigation, so this block printed "NOT FOUND" on every run
        # everywhere else. It is an argument now.
        if scan_id:
            target = db.query(Scan).filter(Scan.id == scan_id).first()
            print(f"\n=== Scan detail: {scan_id} ===")
            if target:
                print(f"ID: {target.id}")
                print(f"org_id: {target.org_id}")
                print(f"created_by: {target.created_by}")
                print(f"status: {target.status}")
                print(f"scan_type: {target.scan_type}")
                print(f"pipeline_mode: {target.pipeline_mode}")
            else:
                print("Not found.")

        print("\n=== Users ===")
        users = db.query(User).all()
        for u in users:
            print(
                f"ID: {u.id} | username: {u.username} | email: {u.email} | org_id: {u.org_id}"
            )

        print("\n=== Organizations ===")
        orgs = db.query(Organization).all()
        for o in orgs:
            print(f"ID: {o.id} | slug: {o.slug} | name: {o.name}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    check_scan_records(sys.argv[1] if len(sys.argv) > 1 else None)

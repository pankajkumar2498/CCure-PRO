from db.base import SessionLocal
from db.models.rbac import Organization
from db.models.scans import Scan
from db.models.users import User


def test_debug_scan():
    db = SessionLocal()
    try:
        # Check all scans in the DB
        scans = db.query(Scan).all()
        print("\n=== DEBUG: SCANS IN DATABASE ===")
        print(f"Total scans: {len(scans)}")
        for s in scans:
            print(
                f"ID: {s.id} | org_id: {s.org_id} | created_by: {s.created_by} | status: {s.status}"
            )

        # Check specific scan
        target_scan = (
            db.query(Scan).filter(Scan.id == "scn_king_fe394fd3_06jul26_fscr").first()
        )
        if target_scan:
            print("\n=== TARGET SCAN DETAIL ===")
            print(f"ID: {target_scan.id}")
            print(f"org_id: {target_scan.org_id}")
            print(f"created_by: {target_scan.created_by}")
            print(f"status: {target_scan.status}")
            print(f"scan_type: {target_scan.scan_type}")
            print(f"pipeline_mode: {target_scan.pipeline_mode}")
        else:
            print("\n=== TARGET SCAN NOT FOUND ===")

        # Check users
        users = db.query(User).all()
        print("\n=== DEBUG: USERS IN DATABASE ===")
        for u in users:
            print(
                f"ID: {u.id} | username: {u.username} | email: {u.email} | org_id: {u.org_id}"
            )

        # Check organizations
        orgs = db.query(Organization).all()
        print("\n=== DEBUG: ORGS IN DATABASE ===")
        for o in orgs:
            print(f"ID: {o.id} | slug: {o.slug} | name: {o.name}")

        # Assert True to avoid blocking CI
        assert True, "Debug output check"
    finally:
        db.close()

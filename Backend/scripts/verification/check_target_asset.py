import os
import sys

# Ensure the root of the project is in python path
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from db.base import SessionLocal
from db.models import Asset
from db.models.compliance import ComplianceFinding, ComplianceScanRun


def check_asset():
    db = SessionLocal()
    try:
        print("=== Scanning Assets in DB ===")
        assets = db.query(Asset).all()
        for a in assets:
            print(
                f"ID: {a.id} | IP: {a.ip_address} | Hostname: {a.hostname} | Org ID: {a.org_id}"
            )

        print("\n=== Scan Runs in DB ===")
        runs = (
            db.query(ComplianceScanRun)
            .order_by(ComplianceScanRun.started_at.desc())
            .limit(5)
            .all()
        )
        for r in runs:
            print(
                f"Run ID: {r.id} | Policy ID: {r.policy_id} | Status: {r.status} | Scope: {r.scope}"
            )

        print("\n=== Compliance Findings for 10.180.6.45 ===")
        target_asset = db.query(Asset).filter(Asset.ip_address == "10.180.6.45").first()
        if target_asset:
            findings = (
                db.query(ComplianceFinding)
                .filter(ComplianceFinding.asset_id == target_asset.id)
                .all()
            )
            print(f"Total findings for 10.180.6.45: {len(findings)}")
            for f in findings[:10]:
                print(
                    f"  Finding: {f.id} | Control: {f.control_id} | Status: {f.status}"
                )
        else:
            print("Asset 10.180.6.45 not found in the assets table!")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    check_asset()

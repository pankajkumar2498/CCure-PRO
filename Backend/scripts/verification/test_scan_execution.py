import os
import sys
import logging

# Ensure root directory is in Python path
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

logging.basicConfig(level=logging.INFO)

from db.base import SessionLocal
from db.models.compliance import ComplianceScanRun
from core.compliance_tasks import run_scan_task


def run_test():
    db = SessionLocal()
    try:
        # Get the latest queued scan run
        latest_run = (
            db.query(ComplianceScanRun)
            .filter(ComplianceScanRun.status == "queued")
            .order_by(ComplianceScanRun.started_at.desc())
            .first()
        )

        if not latest_run:
            print(
                "No queued scan runs found in the database. Creating a new mock run..."
            )
            from db.models import Organization

            org = db.query(Organization).first()
            if not org:
                print("Error: No organizations found!")
                return

            from db.models.compliance import CompliancePolicy

            policy = db.query(CompliancePolicy).first()
            if not policy:
                print("Error: No policies found!")
                return

            from datetime import datetime, timezone

            run_id = f"csr_test_{datetime.now().strftime('%M%S')}"
            latest_run = ComplianceScanRun(
                id=run_id,
                tenant_id=org.id,
                framework_id=policy.framework_id,
                policy_id=policy.id,
                status="queued",
                scope={"asset_ids": [], "asset_tags": []},
                started_at=datetime.now(timezone.utc),
            )
            db.add(latest_run)
            db.commit()
            print(f"Created new test scan run: {latest_run.id}")

        print(
            f"\n---> Executing compliance scan: {latest_run.id} for Org: {latest_run.tenant_id}..."
        )
        db.close()  # Close session before task opens its own

        result = run_scan_task(latest_run.id, latest_run.tenant_id)
        print(f"\n---> Execution finished! Result: {result}")

    except Exception:
        print("\n=== SCAN CRASHED ===")
        import traceback

        traceback.print_exc()
    finally:
        db = SessionLocal()
        # Verify status after run
        if "latest_run" in locals():
            run_status = (
                db.query(ComplianceScanRun)
                .filter(ComplianceScanRun.id == latest_run.id)
                .first()
            )
            if run_status:
                print(f"\nFinal Scan Run Status in DB: {run_status.status}")
        db.close()


if __name__ == "__main__":
    run_test()

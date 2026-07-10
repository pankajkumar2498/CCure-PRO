"""
Script: seed_mock_findings.py
Purpose: Seed the database with mock compliance findings and recalculate scores
         for ALL organizations in the database so that the dashboard displays
         populated data regardless of which organization is logged in.
Usage:   python -m scripts.seed_mock_findings
"""

import os
import sys
from datetime import datetime, timezone, timedelta

# Ensure the root of the project is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.base import SessionLocal
from db.models import User
from db.models.rbac import Organization
from db.models.compliance import (
    ComplianceFramework, ComplianceTenantFramework, ComplianceControl,
    CompliancePolicy, ComplianceFinding, ComplianceScore, ComplianceScanRun
)
from core.compliance_tasks import _calculate_compliance_score

def seed_mock_compliance_data():
    db = SessionLocal()
    try:
        # Get all organizations
        orgs = db.query(Organization).all()
        if not orgs:
            print("Error: No organizations found in the database.")
            return

        framework_id = "cfw_iso27001_2022"
        framework = db.query(ComplianceFramework).filter(ComplianceFramework.id == framework_id).first()
        if not framework:
            print("Error: ISO 27001 framework not found. Please run seed_compliance first.")
            return

        controls = db.query(ComplianceControl).filter(ComplianceControl.framework_id == framework_id).all()
        if not controls:
            print("Error: No controls found. Please run seed_compliance first.")
            return

        now = datetime.now(timezone.utc)

        for org in orgs:
            print(f"\n--- Seeding compliance data for Organization: {org.name} ({org.id}) ---")

            # Find a user belonging to this org
            user = db.query(User).filter(User.org_id == org.id).first()
            if not user:
                # Fallback to any user
                user = db.query(User).first()
                if not user:
                    print(f"Skipping org {org.name}: No users exist in the database.")
                    continue

            print(f"  - Using User: {user.username} ({user.id})")

            # Register Framework
            tenant_fw = db.query(ComplianceTenantFramework).filter(
                ComplianceTenantFramework.tenant_id == org.id,
                ComplianceTenantFramework.framework_id == framework_id
            ).first()

            if not tenant_fw:
                tenant_fw_id = f"ctf_{org.id}_{framework_id}"
                tenant_fw = ComplianceTenantFramework(
                    id=tenant_fw_id,
                    tenant_id=org.id,
                    framework_id=framework_id,
                    is_enabled=True,
                    enabled_by=user.id,
                    enabled_at=now
                )
                db.add(tenant_fw)
                print(f"  - Registered framework to org.")

            # Create Policy
            policy_id = f"cpl_{org.id}_iso_v1"
            policy = db.query(CompliancePolicy).filter(CompliancePolicy.id == policy_id).first()
            if not policy:
                policy = CompliancePolicy(
                    id=policy_id,
                    framework_id=framework_id,
                    tenant_id=org.id,
                    policy_family_code=f"POL-ISO-{org.id.upper()[:25]}",
                    version_number=1,
                    name="ISO 27001 Hardening Policy",
                    target_platform="any",
                    status="active",
                    is_active=True,
                    created_by=user.id,
                    created_at=now
                )
                db.add(policy)
                print(f"  - Created compliance policy: {policy.name}")

            db.flush()

            # Create Scan Run
            scan_run_id = f"run_mock_{org.id}"
            run = db.query(ComplianceScanRun).filter(ComplianceScanRun.id == scan_run_id).first()
            if not run:
                run = ComplianceScanRun(
                    id=scan_run_id,
                    tenant_id=org.id,
                    framework_id=framework_id,
                    policy_id=policy_id,
                    status="completed",
                    scope={},
                    started_at=now - timedelta(hours=1),
                    finished_at=now
                )
                db.add(run)
                print(f"  - Created scan run record: {scan_run_id}")

            db.flush()

            # Seed Findings
            findings_seeded = 0
            for idx, ctrl in enumerate(controls):
                # Ensure the finding_id is unique and fits within 100 characters
                short_ctrl_id = ctrl.id.split('_')[-1]
                finding_id = f"cfnd_{org.id[:15]}_{short_ctrl_id}"
                
                # Delete old finding if exists to overwrite
                db.query(ComplianceFinding).filter(ComplianceFinding.id == finding_id).delete()

                if idx % 10 in (0, 1):
                    status = "fail"
                elif idx % 10 == 2:
                    status = "exception"
                else:
                    status = "pass"

                finding = ComplianceFinding(
                    id=finding_id,
                    scan_run_id=scan_run_id,
                    tenant_id=org.id,
                    asset_id=None,
                    control_id=ctrl.id,
                    rule_id=None,
                    source="auto_scan",
                    status=status,
                    evidence={"message": "Mock verification matching criteria."},
                    first_seen=now - timedelta(days=2),
                    last_seen=now
                )
                db.add(finding)
                findings_seeded += 1

            db.flush()

            # Calculate score
            _calculate_compliance_score(db, org.id, framework_id, None, scan_run_id)
            print(f"  - Seeded {findings_seeded} findings and calculated org compliance scores.")

        db.commit()
        print("\nAll organizations successfully seeded/synchronized!")

    except Exception as e:
        db.rollback()
        print(f"Error seeding mock data: {str(e)}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_mock_compliance_data()

import os
import sys

# Ensure the root of the project is in python path
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from db.base import SessionLocal
from db.models import Asset, User
from db.models.compliance import ComplianceFinding, ComplianceScore
from db.models.rbac import Organization


def diagnostics():
    db = SessionLocal()
    try:
        print("=== Organizations ===")
        orgs = db.query(Organization).all()
        for o in orgs:
            print(f"ID: {o.id} | Name: {o.name}")

        print("\n=== Users ===")
        users = db.query(User).all()
        for u in users:
            print(f"ID: {u.id} | Username: {u.username} | Org ID: {u.org_id}")

        print("\n=== Assets ===")
        assets = db.query(Asset).all()
        for a in assets:
            print(f"ID: {a.id} | IP: {a.ip_address} | Org ID: {a.org_id}")

        print("\n=== Compliance Scores ===")
        scores = db.query(ComplianceScore).all()
        for s in scores:
            print(
                f"ID: {s.id} | Tenant ID: {s.tenant_id} | Asset ID: {s.asset_id} | Score: {s.score_pct}% | Weighted: {s.weighted_score_pct}%"
            )

        print("\n=== Compliance Findings ===")
        findings = db.query(ComplianceFinding).all()
        print(f"Total findings in database: {len(findings)}")

        status_counts: dict[str, int] = {}
        for f in findings:
            status_counts[f.status] = status_counts.get(f.status, 0) + 1
        print(f"Status breakdown: {status_counts}")

        for f in findings[:10]:
            print(
                f"ID: {f.id} | Tenant ID: {f.tenant_id} | Control: {f.control_id} | Status: {f.status}"
            )

        failed = [f for f in findings if f.status == "fail"]
        print(f"\n=== Failed findings (first 10 of {len(failed)}) ===")
        for f in failed[:10]:
            print(
                f"ID: {f.id} | Tenant: {f.tenant_id} | Asset: {f.asset_id} | Control: {f.control_id}"
            )

    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    diagnostics()

from db.base import SessionLocal
from db.models import Asset
from db.models.compliance import ComplianceFinding, ComplianceScore
from db.models.rbac import Organization


def test_run_diagnostics():
    db = SessionLocal()
    try:
        print("\n=== DIAGNOSTICS ===")
        print("--- Organizations ---")
        orgs = db.query(Organization).all()
        for o in orgs:
            print(f"Org ID: {o.id} | Name: {o.name}")

        print("\n--- Assets ---")
        assets = db.query(Asset).all()
        for a in assets:
            print(
                f"Asset ID: {a.id} | IP: {a.ip_address} | Hostname: {a.hostname} | Org ID: {a.org_id}"
            )

        print("\n--- Compliance Findings ---")
        findings = db.query(ComplianceFinding).all()
        print(f"Total findings in DB: {len(findings)}")
        status_counts = {}
        for f in findings:
            status_counts[f.status] = status_counts.get(f.status, 0) + 1
        print(f"Finding Statuses: {status_counts}")

        # Print sample failed findings
        failed_findings = [f for f in findings if f.status == "fail"]
        print(f"\nFailed findings sample (first 10 of {len(failed_findings)}):")
        for f in failed_findings[:10]:
            print(
                f"Finding ID: {f.id} | Tenant: {f.tenant_id} | Asset ID: {f.asset_id} | Control ID: {f.control_id} | Status: {f.status}"
            )

        print("\n--- Compliance Scores ---")
        scores = db.query(ComplianceScore).all()
        print(f"Total scores in DB: {len(scores)}")
        for s in scores:
            print(
                f"Score ID: {s.id} | Tenant ID: {s.tenant_id} | Asset ID: {s.asset_id} | Theme: {s.theme} | Score: {s.score_pct}% | Pass: {s.pass_count} | Fail: {s.fail_count} | Pending: {s.pending_count}"
            )

    except Exception as e:
        print(f"Error during diagnostics: {e}")
        raise
    finally:
        db.close()

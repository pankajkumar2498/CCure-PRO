"""
Backend/scripts/verification/verify_compliance_scan_execution.py
──────────────────────────────────────────────────────────────────────────────
Run one compliance scan synchronously, outside Celery, and report its outcome:
the end-to-end check that the compliance engine executes against a database.

Was ``test_scan_execution.py``. It is an operator probe, not a test — it has no
assertions and pytest never collected it (``pytest.ini`` scopes collection to
``tests/``) — and ``pytest.ini`` says scripts must not be named ``test_*.py``.

    # From the Backend directory; the database name must be stated:
    python scripts/verification/verify_compliance_scan_execution.py --allow-database ccure_scratch
    python scripts/verification/verify_compliance_scan_execution.py --allow-database ccure_scratch \\
        --org-id ORG --policy-id POLICY
    python scripts/verification/verify_compliance_scan_execution.py --allow-database ccure_scratch \\
        --run-id csr_...            # execute one specific queued run

**It writes.** A new run creates a ``compliance_scan_runs`` row and the scan
writes its findings, history and scores, exactly as a scheduled scan would. Its
scope is empty, and an empty scope means *every asset of the organisation*.
The verdicts are the engine's own, from evidence already collected — nothing
here is invented — but they land in that organisation's register, so:

* ``--allow-database NAME`` is required and must equal ``current_database()``;
  a run never reaches a database by default;
* the live databases (``ccure_db``, ``ccure_test``, ``vuln_intel``) are refused
  unless ``--live-approved REFERENCE`` records why;
* an existing queued run is executed only when named with ``--run-id``. The old
  script ran the newest queued run, which a worker may already be executing;
* the policy is the organisation's own (or a shared one), never another
  tenant's. The old script took ``CompliancePolicy.first()`` with no tenant
  filter and could scan one organisation's assets against another's policy.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import uuid
from datetime import datetime, timezone

# Ensure the Backend directory is on the import path (the script's grandparent).
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

#: Databases a run must not reach without a recorded reason. Mirrors
#: ``scripts/rbac/bootstrap_admin.LIVE_DATABASES``.
LIVE_DATABASES = {"ccure_db", "ccure_test", "vuln_intel"}


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Run one compliance scan synchronously and report its outcome. "
        "Writes a run and its findings; see the module docstring."
    )
    ap.add_argument("--allow-database", required=True, metavar="NAME")
    ap.add_argument("--live-approved", metavar="REFERENCE")
    ap.add_argument("--run-id", help="execute this queued run instead of creating one")
    ap.add_argument("--org-id", help="organisation for a new run")
    ap.add_argument(
        "--policy-id", help="policy for a new run (the org's own or shared)"
    )
    return ap.parse_args(argv)


def _pick_org(db, org_id):
    from db.models import Organization

    if org_id:
        return db.query(Organization).filter(Organization.id == org_id).first()
    orgs = db.query(Organization).order_by(Organization.id).limit(2).all()
    if len(orgs) == 1:
        return orgs[0]
    if orgs:
        print("refused: several organisations exist; name one with --org-id")
    return None


def _pick_policy(db, org, policy_id):
    from db.models.compliance import CompliancePolicy
    from sqlalchemy import or_

    query = db.query(CompliancePolicy).filter(
        or_(
            CompliancePolicy.tenant_id == org.id,
            CompliancePolicy.tenant_id.is_(None),
        )
    )
    if policy_id:
        return query.filter(CompliancePolicy.id == policy_id).first()
    # The organisation's own active policy first, then a shared one.
    return (
        query.filter(CompliancePolicy.status == "active")
        .order_by(CompliancePolicy.tenant_id.is_(None), CompliancePolicy.id)
        .first()
    )


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO)

    from core.compliance_tasks import run_scan_task
    from db.base import SessionLocal
    from db.models.compliance import ComplianceScanRun
    from sqlalchemy import text

    db = SessionLocal()
    try:
        name = str(db.execute(text("SELECT current_database()")).scalar())
        if args.allow_database != name:
            print(
                f"refused: this would write to {name!r}; pass --allow-database {name!r}"
            )
            return 3
        if name in LIVE_DATABASES and not args.live_approved:
            print(
                f"refused: {name!r} is a live database; pass --live-approved REFERENCE"
            )
            return 3

        if args.run_id:
            run = (
                db.query(ComplianceScanRun)
                .filter(ComplianceScanRun.id == args.run_id)
                .first()
            )
            if run is None:
                print(f"refused: no compliance scan run {args.run_id!r}")
                return 2
            if run.status != "queued":
                print(f"refused: run {run.id} is {run.status!r}, not 'queued'")
                return 2
        else:
            org = _pick_org(db, args.org_id)
            if org is None:
                print("refused: no organisation to scan")
                return 2
            policy = _pick_policy(db, org, args.policy_id)
            if policy is None:
                print(f"refused: no policy for organisation {org.id} (own or shared)")
                return 2
            run = ComplianceScanRun(
                id=f"csr_verify_{uuid.uuid4().hex[:12]}",
                tenant_id=org.id,
                framework_id=policy.framework_id,
                policy_id=policy.id,
                status="queued",
                scope={"asset_ids": [], "asset_tags": []},
                started_at=datetime.now(timezone.utc),
            )
            db.add(run)
            db.commit()
            print(
                f"Created run {run.id}: organisation {org.id}, policy {policy.id}, "
                "empty scope (every asset of the organisation)."
            )

        run_id, tenant_id = run.id, run.tenant_id
        print(
            f"\n---> Executing compliance scan {run_id} for {tenant_id} in {name!r}..."
        )
    finally:
        db.close()  # the task opens its own session

    try:
        result = run_scan_task(run_id, tenant_id)
        print(f"\n---> Execution finished. Result: {result}")
    except Exception:
        print("\n=== SCAN CRASHED ===")
        import traceback

        traceback.print_exc()

    db = SessionLocal()
    try:
        final = (
            db.query(ComplianceScanRun).filter(ComplianceScanRun.id == run_id).first()
        )
        status = final.status if final else "missing"
        print(f"\nFinal scan run status: {status}")
        # Exit 0 means the engine ran the scan to an honest end. `not_assessed`
        # is one (nothing in scope could be assessed), not a failure to run.
        return 0 if status in ("completed", "not_assessed") else 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

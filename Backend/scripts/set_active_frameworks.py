"""
Script: set_active_frameworks.py
Purpose: Bring `compliance_tenant_frameworks.is_enabled` into line with the
         installation's active framework list in `core.compliance_frameworks`.
Usage:   python -m scripts.set_active_frameworks [--apply]

Defaults to a dry run. Nothing is written without `--apply`.

What this does and does not do
──────────────────────────────
It flips one boolean per (tenant, framework) row. It does **not** delete
frameworks, controls, rules, findings, scores, policies or evidence — parking a
framework has to be reversible in one command, and the parked catalogues are
still the targets of ISO's and NIST's crosswalks, which `/compliance/gap-analysis`
and the rule mapper both read.

`is_enabled=False` is already honoured across the whole working surface: the
controls register, policy list, scan trigger, findings, attestation, evidence
upload, schedules and the dashboard all filter on it. The report endpoints did
not, which is what `routers.compliance.require_active_framework` now covers.

Re-enabling a framework later is: add its id to
`core.compliance_frameworks.DEFAULT_ACTIVE_FRAMEWORK_IDS` (or set
`COMPLIANCE_ACTIVE_FRAMEWORKS`), run this with `--apply`, and its scores and
findings are exactly where they were left.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.compliance_frameworks import (  # noqa: E402
    active_framework_ids,
    parked_framework_ids,
)
from db.base import SessionLocal  # noqa: E402
from db.models.compliance import ComplianceTenantFramework  # noqa: E402
from db.models.rbac import Organization  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enable the active compliance frameworks and park the rest."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the changes. Without it the script only reports.",
    )
    parser.add_argument(
        "--tenant",
        default=None,
        help="Limit to one organisation id. Default: every organisation.",
    )
    args = parser.parse_args()

    active = set(active_framework_ids())
    parked = set(parked_framework_ids())

    db = SessionLocal()
    try:
        orgs = db.query(Organization)
        if args.tenant:
            orgs = orgs.filter(Organization.id == args.tenant)
        orgs = orgs.all()
        if not orgs:
            print("No organisations matched.")
            return 1

        print(f"Active : {', '.join(sorted(active))}")
        print(f"Parked : {len(parked)} catalogues")
        print()

        enabled_n = disabled_n = 0
        for org in orgs:
            rows = (
                db.query(ComplianceTenantFramework)
                .filter(ComplianceTenantFramework.tenant_id == org.id)
                .all()
            )
            changes = []
            for row in rows:
                want = row.framework_id in active
                if row.is_enabled == want:
                    continue
                changes.append((row.framework_id, row.is_enabled, want))
                if want:
                    enabled_n += 1
                else:
                    disabled_n += 1
                if args.apply:
                    row.is_enabled = want

            missing = [f for f in active if f not in {r.framework_id for r in rows}]
            print(
                f"{org.id} ({org.name}): {len(rows)} installed, {len(changes)} changing"
            )
            for framework_id, was, want in sorted(changes):
                print(f"    {framework_id:26} {was} -> {want}")
            if missing:
                # An active framework with no installation row cannot be
                # scanned or attested against. Reported rather than created,
                # because the install path also seeds a default policy and
                # doing that silently here would hide a broken bootstrap.
                print(f"    NOT INSTALLED: {', '.join(missing)} — run seed_real_rules")

        print()
        print(
            f"Would enable {enabled_n}, disable {disabled_n}."
            if not args.apply
            else f"Enabled {enabled_n}, disabled {disabled_n}."
        )

        if args.apply:
            db.commit()
            print("Applied.")
        else:
            db.rollback()
            print("Dry run — nothing written. Re-run with --apply.")
        return 0
    except Exception as exc:  # pragma: no cover - operational script
        db.rollback()
        print(f"ERROR: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

"""
Script: cleanup_iso27001.py
Purpose: Report — and optionally repair — ISO/IEC 27001:2022 rows that leave a
         control unable to reach a verdict.
Usage:   python -m scripts.cleanup_iso27001 [--apply]

Defaults to a dry run. Nothing is written without `--apply`.

`seed_real_rules.py` now converges these itself, so on a healthy installation
this script reports nothing. It exists for the case the seeder cannot reach:
a rule that is no longer generated (because its control has since gained a real
check) and so never passes through the seeder's upsert loop again, and for
answering "is ISO actually assessable right now" without reading the seeder's
output.

What it looks for
─────────────────
1. **A control whose only rule is `archived`.** `run_scan_task` evaluates
   `active` rules only, which is correct — a draft is unpublished and an
   archived version has been replaced. But an archived rule that supersedes
   nothing and names no successor is not a lifecycle state, it is a check
   switched off by accident. 24 of the 93 Annex A controls were in exactly that
   position, including A.5.1, A.5.2, A.5.24, A.5.26, A.5.29, A.5.35 and A.5.36.
   They stayed attestable, but produced no finding on any run, never reached
   the reviewer's findings queue, and the Statement of Applicability printed
   them as "Not assessed".

2. **An attestation placeholder sharing a control with a real check.**
   `manual_review` outranks `pass` in `roll_up_statuses`, so the placeholder
   silently suppresses the verdict the check produces.

3. **A control with no rule at all**, which no repair here can fix — it needs a
   re-seed, so it is reported rather than papered over.

Nothing is deleted except the redundant placeholder *links* in case 2 and the
findings behind them, which are not evidence of anything once the rule no
longer applies to the control.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.base import SessionLocal  # noqa: E402
from db.models.compliance import (  # noqa: E402
    ComplianceControl,
    ComplianceFinding,
    ComplianceRule,
    ComplianceRuleControl,
)

FRAMEWORK_ID = "cfw_iso27001_2022"
PLACEHOLDER_PREFIX = "crl_auto_gen_"

AUTOMATED_SOURCES = {
    "vulnerability_audit",
    "malware_scan",
    "services_ports",
    "tls_certificates",
    "network_topology",
    "credential_validation",
    "offline_configuration",
    "web_vulnerability_audit",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report or repair unassessable ISO 27001:2022 controls."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the repairs. Without it the script only reports.",
    )
    args = parser.parse_args()
    apply_changes = args.apply

    db = SessionLocal()
    try:
        controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == FRAMEWORK_ID)
            .order_by(ComplianceControl.control_number)
            .all()
        )
        if not controls:
            print(f"{FRAMEWORK_ID} is not seeded.")
            return 1

        print(f"Annex A controls in database: {len(controls)}")

        reactivated = 0
        unlinked = 0
        unlinked_findings = 0
        no_rule: list = []
        stranded: list = []

        for ctrl in controls:
            links = (
                db.query(ComplianceRuleControl, ComplianceRule)
                .join(
                    ComplianceRule,
                    ComplianceRule.id == ComplianceRuleControl.rule_id,
                )
                .filter(ComplianceRuleControl.control_id == ctrl.id)
                .all()
            )
            if not links:
                no_rule.append(ctrl.control_number)
                continue

            rules = [rule for _link, rule in links]
            active = [r for r in rules if r.status == "active"]

            # ── 1. Nothing runnable: reactivate orphaned archived rules ──────
            if not active:
                stranded.append(ctrl.control_number)
                repairable = [
                    r
                    for r in rules
                    if r.status == "archived" and not r.superseded_by_rule_id
                ]
                for rule in repairable:
                    print(
                        f"  {ctrl.control_number:9} only rule is archived with no "
                        f"successor: {rule.id}"
                    )
                    reactivated += 1
                    if apply_changes:
                        rule.status = "active"
                if not repairable:
                    print(
                        f"  {ctrl.control_number:9} has no runnable rule and none "
                        "is repairable — re-seed required"
                    )
                continue

            # ── 2. Placeholder alongside a real check ───────────────────────
            has_automation = any(r.evidence_source in AUTOMATED_SOURCES for r in active)
            if not has_automation:
                continue
            for link, rule in links:
                if not rule.id.startswith(PLACEHOLDER_PREFIX):
                    continue
                n = (
                    db.query(ComplianceFinding)
                    .filter(
                        ComplianceFinding.control_id == ctrl.id,
                        ComplianceFinding.rule_id == rule.id,
                    )
                    .count()
                )
                print(
                    f"  {ctrl.control_number:9} placeholder {rule.id} sits beside "
                    f"automated checks ({n} findings suppressing a verdict)"
                )
                unlinked += 1
                unlinked_findings += n
                if apply_changes:
                    db.query(ComplianceFinding).filter(
                        ComplianceFinding.control_id == ctrl.id,
                        ComplianceFinding.rule_id == rule.id,
                    ).delete(synchronize_session=False)
                    db.query(ComplianceRuleControl).filter(
                        ComplianceRuleControl.rule_id == rule.id,
                        ComplianceRuleControl.control_id == ctrl.id,
                    ).delete(synchronize_session=False)

        print()
        print(f"  controls with no rule at all      : {len(no_rule)} {no_rule or ''}")
        print(f"  controls with no runnable rule    : {len(stranded)} {stranded or ''}")
        print(f"  archived rules to reactivate      : {reactivated}")
        print(
            f"  redundant placeholder links       : {unlinked} "
            f"({unlinked_findings} findings)"
        )

        if apply_changes:
            db.commit()
            print("\nApplied.")
        else:
            db.rollback()
            if reactivated or unlinked:
                print("\nDry run — nothing written. Re-run with --apply.")
            else:
                print("\nNothing to repair.")
        return 0
    except Exception as exc:  # pragma: no cover - operational script
        db.rollback()
        print(f"ERROR: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

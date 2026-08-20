"""
Script: cleanup_nist_csf_v2.py
Purpose: Remove NIST CSF 2.0 rows an earlier seeder left behind that a re-seed
         cannot fix on its own — `seed_compliance.py` upserts and never deletes.
Usage:   python -m scripts.cleanup_nist_csf_v2 [--apply]

Defaults to a dry run. Nothing is written without `--apply`.

Three classes of stale row
──────────────────────────
1. **Subcategories that are not in CSF 2.0.** `RC.RP-07` was invented; RC.RP has
   exactly six Subcategories. Its rule links, findings, evidence files and
   exceptions go with it.

2. **Attestation placeholders on automated Subcategories.** The old NIST branch
   of `seed_real_rules.py` set its "already mapped" flag only when it *inserted*
   a crosswalk link, so on every run after the first nothing set the flag and
   all 106 Subcategories were handed a `crl_nist_auto_gen_*` manual placeholder
   — including the ones carrying real automated checks. A `manual_review`
   finding outranks `pass` in `roll_up_statuses`, so those Subcategories could
   never report compliant no matter what the scan found. Measured on the live
   catalogue: 106 placeholders against 106 Subcategories.

3. **NIST placeholders that leaked into other frameworks.** The NIS2 crosswalk
   resolver copies every rule linked to a NIST control onto the NIS2 control,
   which pulled 20 NIST attestation placeholders into NIS2 — where they carry a
   NIST Subcategory's wording under a NIS2 requirement.

The corresponding findings are deleted with the links, because a finding whose
rule no longer applies to the control is not evidence of anything and would keep
suppressing the rollup.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import func  # noqa: E402

from db.base import SessionLocal  # noqa: E402
from db.models.compliance import (  # noqa: E402
    ComplianceControl,
    ComplianceEvidenceFile,
    ComplianceException,
    ComplianceFinding,
    ComplianceRemediation,
    ComplianceRule,
    ComplianceRuleControl,
)

FRAMEWORK_ID = "cfw_nist_csf_v2"
PLACEHOLDER_PREFIX = "crl_nist_auto_gen_"


def _seed_subcategory_ids() -> set:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "nist_csf_v2_controls_seed.json")
    with open(path, encoding="utf-8") as fh:
        return {c["id"] for c in json.load(fh)["controls"]}


def _delete_control(db, control, apply_changes: bool) -> dict:
    """Removes one control and everything that hangs off it."""
    counts = {
        "findings": db.query(ComplianceFinding)
        .filter(ComplianceFinding.control_id == control.id)
        .count(),
        "evidence_files": db.query(ComplianceEvidenceFile)
        .filter(ComplianceEvidenceFile.control_id == control.id)
        .count(),
        "exceptions": db.query(ComplianceException)
        .filter(ComplianceException.control_id == control.id)
        .count(),
        "rule_links": db.query(ComplianceRuleControl)
        .filter(ComplianceRuleControl.control_id == control.id)
        .count(),
    }
    if apply_changes:
        db.query(ComplianceFinding).filter(
            ComplianceFinding.control_id == control.id
        ).delete(synchronize_session=False)
        db.query(ComplianceEvidenceFile).filter(
            ComplianceEvidenceFile.control_id == control.id
        ).delete(synchronize_session=False)
        db.query(ComplianceException).filter(
            ComplianceException.control_id == control.id
        ).delete(synchronize_session=False)
        db.query(ComplianceRuleControl).filter(
            ComplianceRuleControl.control_id == control.id
        ).delete(synchronize_session=False)
        db.delete(control)
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove stale NIST CSF 2.0 catalogue and rule-wiring rows."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the deletions. Without it the script only reports.",
    )
    args = parser.parse_args()
    apply_changes = args.apply

    valid_ids = _seed_subcategory_ids()
    db = SessionLocal()
    try:
        # ── 1. Subcategories that CSF 2.0 does not define ────────────────────
        controls = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == FRAMEWORK_ID)
            .all()
        )
        obsolete = [c for c in controls if c.control_number not in valid_ids]
        print(
            f"Subcategories in database: {len(controls)}  (CSF 2.0 defines {len(valid_ids)})"
        )
        for c in obsolete:
            counts = _delete_control(db, c, apply_changes)
            print(
                f"  - {c.control_number} is not a CSF 2.0 Subcategory: "
                f"{counts['rule_links']} rule links, {counts['findings']} findings, "
                f"{counts['evidence_files']} evidence files, "
                f"{counts['exceptions']} exceptions"
            )
        if not obsolete:
            print("  (no obsolete Subcategories)")

        missing = valid_ids - {c.control_number for c in controls}
        if missing:
            print(
                f"\n{len(missing)} Subcategories are missing and need a re-seed: "
                f"{sorted(missing)}"
            )

        # ── 2. Placeholders on Subcategories that carry automated checks ─────
        obsolete_ids = {c.id for c in obsolete}
        remaining = [c for c in controls if c.id not in obsolete_ids]
        redundant = 0
        redundant_findings = 0
        for c in remaining:
            links = (
                db.query(ComplianceRuleControl, ComplianceRule)
                .join(
                    ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id
                )
                .filter(ComplianceRuleControl.control_id == c.id)
                .all()
            )
            automated = [
                r
                for _, r in links
                if r.evidence_source and r.evidence_source != "manual"
            ]
            placeholders = [
                link for link, r in links if r.id.startswith(PLACEHOLDER_PREFIX)
            ]
            if not automated or not placeholders:
                continue
            for link in placeholders:
                n = (
                    db.query(ComplianceFinding)
                    .filter(
                        ComplianceFinding.control_id == c.id,
                        ComplianceFinding.rule_id == link.rule_id,
                    )
                    .count()
                )
                redundant_findings += n
                redundant += 1
                if apply_changes:
                    db.query(ComplianceFinding).filter(
                        ComplianceFinding.control_id == c.id,
                        ComplianceFinding.rule_id == link.rule_id,
                    ).delete(synchronize_session=False)
                    db.query(ComplianceRuleControl).filter(
                        ComplianceRuleControl.rule_id == link.rule_id,
                        ComplianceRuleControl.control_id == c.id,
                    ).delete(synchronize_session=False)
        print(
            f"\nAttestation placeholders on automated Subcategories: {redundant} "
            f"({redundant_findings} findings suppressing a real verdict)"
        )

        # ── 3. NIST placeholders linked to other frameworks' controls ────────
        leaked = (
            db.query(ComplianceRuleControl, ComplianceControl)
            .join(
                ComplianceControl,
                ComplianceControl.id == ComplianceRuleControl.control_id,
            )
            .filter(
                ComplianceRuleControl.rule_id.like(f"{PLACEHOLDER_PREFIX}%"),
                ComplianceControl.framework_id != FRAMEWORK_ID,
            )
            .all()
        )
        by_framework: dict = {}
        for link, ctrl in leaked:
            by_framework[ctrl.framework_id] = by_framework.get(ctrl.framework_id, 0) + 1
            if apply_changes:
                db.query(ComplianceFinding).filter(
                    ComplianceFinding.control_id == ctrl.id,
                    ComplianceFinding.rule_id == link.rule_id,
                ).delete(synchronize_session=False)
                db.query(ComplianceRuleControl).filter(
                    ComplianceRuleControl.rule_id == link.rule_id,
                    ComplianceRuleControl.control_id == ctrl.id,
                ).delete(synchronize_session=False)
        print(
            f"NIST placeholders linked outside NIST CSF: {len(leaked)} {by_framework or ''}"
        )

        # ── 4. Placeholder rules no longer linked to anything ────────────────
        linked_rule_ids = {
            r_id
            for (r_id,) in db.query(ComplianceRuleControl.rule_id)
            .filter(ComplianceRuleControl.rule_id.like(f"{PLACEHOLDER_PREFIX}%"))
            .distinct()
        }
        orphan_rules = [
            r
            for r in db.query(ComplianceRule).filter(
                ComplianceRule.id.like(f"{PLACEHOLDER_PREFIX}%")
            )
            if r.id not in linked_rule_ids
        ]
        print(f"Orphaned placeholder rules: {len(orphan_rules)}")
        if apply_changes:
            for r in orphan_rules:
                db.query(ComplianceRemediation).filter(
                    ComplianceRemediation.rule_id == r.id
                ).delete(synchronize_session=False)
                db.query(ComplianceFinding).filter(
                    ComplianceFinding.rule_id == r.id
                ).delete(synchronize_session=False)
                db.delete(r)

        # ── 5. Diagnostics: rules switched off with no replacement ──────────
        #
        # Not repaired here — the seeder converges the placeholders it owns.
        # This reports the wider condition, which is not NIST-specific: rules
        # across every seeded framework carry status `archived` with a NULL
        # `superseded_by_rule_id`, and `run_scan_task` evaluates `active` only.
        # Where such a rule is a control's only rule, that control can never
        # reach a verdict and shows as "not assessed" with no reason given.
        dead = (
            db.query(ComplianceControl.framework_id, func.count())
            .join(
                ComplianceRuleControl,
                ComplianceRuleControl.control_id == ComplianceControl.id,
            )
            .join(ComplianceRule, ComplianceRule.id == ComplianceRuleControl.rule_id)
            .filter(
                ComplianceRule.status == "archived",
                ComplianceRule.superseded_by_rule_id.is_(None),
            )
            .group_by(ComplianceControl.framework_id)
            .all()
        )
        if dead:
            print("\nArchived-with-no-successor rule links, by framework:")
            for framework, count in sorted(dead):
                marker = "   <- this framework" if framework == FRAMEWORK_ID else ""
                print(f"  {framework:<28} {count:>5}{marker}")

        if apply_changes:
            db.commit()
            print("\nApplied.")
        else:
            db.rollback()
            print("\nDry run — nothing written. Re-run with --apply.")
        return 0
    except Exception as exc:  # pragma: no cover - operational script
        db.rollback()
        print(f"ERROR: {exc}")
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

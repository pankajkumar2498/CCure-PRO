"""
Script: seed_compliance.py
Purpose: Seed the database with the ISO 27001:2022 framework and its 93 controls.
Usage:   python -m scripts.seed_compliance [--seed-file PATH]
"""

import os
import json
import argparse
from sqlalchemy.orm import Session

# Import SQLAlchemy session and models
# Ensure the root of the project is in python path
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.base import SessionLocal
from db.models.compliance import ComplianceFramework, ComplianceControl


def seed_framework_and_controls(db: Session, seed_file_path: str):
    """Parses the JSON seed file and upserts records into PostgreSQL."""
    if not os.path.exists(seed_file_path):
        print(f"Error: Seed file not found at {seed_file_path}")
        return

    with open(seed_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    fw_data = data["framework"]
    framework_id = f"cfw_{fw_data['code'].lower()}"

    # 1. Seed Compliance Framework
    framework = (
        db.query(ComplianceFramework)
        .filter(ComplianceFramework.id == framework_id)
        .first()
    )
    if not framework:
        framework = ComplianceFramework(
            id=framework_id,
            tenant_id=None,  # Global standard, available to all
            code=fw_data["code"],
            name=fw_data["name"],
            version=fw_data["version"],
            is_active=True,
        )
        db.add(framework)
        print(f"Seeding framework: {fw_data['name']} ({framework_id})")
    else:
        print(f"Framework {framework_id} already exists. Synchronizing controls...")

    db.flush()

    # 2. Seed Compliance Controls
    controls_seeded = 0
    for ctrl in data["controls"]:
        raw_num = str(ctrl["id"])
        ctrl_num = (
            f"A.{raw_num}"
            if (framework_id == "cfw_iso27001_2022" and not raw_num.startswith("A."))
            else raw_num
        )
        control_id = f"cct_{fw_data['code'].lower()}_{raw_num.lower().replace('.', '_').replace('-', '_')}"
        control = (
            db.query(ComplianceControl)
            .filter(
                ComplianceControl.framework_id == framework_id,
                ComplianceControl.id == control_id,
            )
            .first()
        )

        description = ctrl.get("description", ctrl.get("note", ctrl["title"]))
        crosswalk = ctrl.get("crosswalk", [])
        evidence_checklist = ctrl.get("evidence_checklist", [])
        raw_tags = ctrl.get("tags", []) or []
        if isinstance(raw_tags, str):
            tags = [t.strip() for t in raw_tags.split(",") if t.strip()]
        elif isinstance(raw_tags, list):
            tags = list(raw_tags)
        else:
            tags = [str(raw_tags)]

        impl_keys = (
            "implementation_group",
            "implementation_groups",
            "ig",
            "implementationGroup",
        )
        for k in impl_keys:
            if k in ctrl and ctrl[k]:
                ig_val = ctrl[k]
                if isinstance(ig_val, str):
                    igs = [g.strip() for g in ig_val.split(",") if g.strip()]
                elif isinstance(ig_val, list):
                    igs = [str(g).strip() for g in ig_val if str(g).strip()]
                else:
                    igs = [str(ig_val)]
                for ig in igs:
                    if ig not in tags:
                        tags.append(ig)

        ot_meta_keys = ("purdue_levels", "component_types", "sl_levels", "zone_types")
        for ot_key in ot_meta_keys:
            if ot_key in ctrl and ctrl[ot_key]:
                ot_vals = ctrl[ot_key]
                if isinstance(ot_vals, str):
                    vals = [v.strip() for v in ot_vals.split(",") if v.strip()]
                elif isinstance(ot_vals, list):
                    vals = [str(v).strip() for v in ot_vals if str(v).strip()]
                else:
                    vals = [str(ot_vals)]
                for val in vals:
                    if val not in tags:
                        tags.append(val)

        if not control:
            control = ComplianceControl(
                id=control_id,
                framework_id=framework_id,
                control_number=ctrl_num,
                theme=ctrl["theme"],
                title=ctrl["title"],
                description=description,
                scannability=ctrl["scannability"],
                scan_module_hint=ctrl.get("scan_module_hint"),
                crosswalk=crosswalk,
                evidence_checklist=evidence_checklist,
                tags=tags,
                saq_profiles=ctrl.get("saq_profiles", []),
                sdf_scope=ctrl.get("sdf_scope"),
                privacy_role=ctrl.get("privacy_role"),
            )
            db.add(control)
            controls_seeded += 1
        else:
            control.control_number = ctrl_num
            control.title = ctrl["title"]
            control.description = description
            control.scannability = ctrl["scannability"]
            control.scan_module_hint = ctrl.get("scan_module_hint")
            control.crosswalk = crosswalk
            control.evidence_checklist = evidence_checklist
            control.tags = tags
            control.saq_profiles = ctrl.get("saq_profiles", [])
            control.sdf_scope = ctrl.get("sdf_scope")
            control.privacy_role = ctrl.get("privacy_role")
            controls_seeded += 1

    db.commit()
    print(
        f"Successfully seeded/synchronized {controls_seeded} compliance controls for {fw_data['code']}."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed compliance controls standard catalog."
    )
    parser.add_argument(
        "--seed-file",
        type=str,
        default=None,
        help="Path to specific JSON seed file containing controls metadata.",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        if args.seed_file:
            seed_framework_and_controls(db, args.seed_file)
        else:
            iso_path = os.path.join(base_dir, "iso27001_2022_controls_seed.json")
            nist_path = os.path.join(base_dir, "nist_csf_v2_controls_seed.json")
            cis_path = os.path.join(base_dir, "cis_v8_1_controls_seed.json")
            soc2_path = os.path.join(base_dir, "soc2_type2_controls_seed.json")
            certin_path = os.path.join(base_dir, "cert_in_2022_controls_seed.json")
            pci_path = os.path.join(base_dir, "pci_dss_v4_controls_seed.json")
            dpdp_path = os.path.join(base_dir, "dpdp_2023_controls_seed.json")
            gdpr_path = os.path.join(base_dir, "gdpr_controls_seed.json")
            if os.path.exists(iso_path):
                seed_framework_and_controls(db, iso_path)
            if os.path.exists(nist_path):
                seed_framework_and_controls(db, nist_path)
            if os.path.exists(cis_path):
                seed_framework_and_controls(db, cis_path)
            if os.path.exists(soc2_path):
                seed_framework_and_controls(db, soc2_path)
            if os.path.exists(certin_path):
                seed_framework_and_controls(db, certin_path)
            if os.path.exists(pci_path):
                seed_framework_and_controls(db, pci_path)
            if os.path.exists(dpdp_path):
                seed_framework_and_controls(db, dpdp_path)
            if os.path.exists(gdpr_path):
                seed_framework_and_controls(db, gdpr_path)
    finally:
        db.close()

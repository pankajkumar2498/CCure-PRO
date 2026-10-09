"""
Script: seed_compliance.py
Purpose: Seed the database with the ISO 27001:2022 framework and its 93 controls.
Usage:   python -m scripts.seed_compliance [--seed-file PATH]
"""

import argparse
import json
import os

# Import SQLAlchemy session and models
# Ensure the root of the project is in python path
import sys

from sqlalchemy.orm import Session

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.compliance_seeds import SEED_GLOB, SEEDS_DIR, all_seed_paths
from db.base import SessionLocal
from db.models.compliance import ComplianceControl, ComplianceFramework


#: Catalogues whose seed ``control_number`` is honoured. See ``_control_number``.
#:
#: CERT-In, NIS 2 and NIST SP 800-53 also carry a ``control_number`` that
#: differs from their ``id`` (``CERT-IR-01`` against ``cert_in_ir_1``,
#: ``NIS2-Art20-01`` against ``gov_01``, ``AC-1`` against ``ac-1``), and their
#: stored numbers are the ids — the same defect. They are deliberately not in
#: this set: their stored numbers feed crosswalk resolution and rule seeding
#: for three parked catalogues, and changing them needs its own verification
#: rather than riding along with a change for two others.
EXPLICIT_NUMBER_FRAMEWORKS = frozenset(
    {"cfw_iso27001_2022", "cfw_hipaa_security_rule", "cfw_pci_dss_v4"}
)


def _control_number(framework_id: str, ctrl: dict) -> str:
    """
    The identifier the control is published under — what a report prints and
    what another module names the control by (the contract's ``control_id``).

    For the catalogues in ``EXPLICIT_NUMBER_FRAMEWORKS`` an explicit
    ``control_number`` in the seed wins. Otherwise the seed's ``id`` is used,
    and ISO/IEC 27001 ids gain the ``A.`` of Annex A.

    The explicit field exists because ``id`` doubles as the row-id suffix and
    cannot always be the published number:

    * PCI DSS ids are ``pci_10_1_1``; storing that as the number published an
      internal key where the standard's ``10.1.1`` belonged.
    * ISO/IEC 27001's management-system clauses (4.1 … 10.2) share numbers with
      Annex A (clause 5.1 against control A.5.1), so their ids must differ
      (``clause_5.1``) while their published number stays ``5.1`` — never
      ``A.5.1``, which the implicit prefix would make it.
    """
    explicit = ctrl.get("control_number")
    if explicit and framework_id in EXPLICIT_NUMBER_FRAMEWORKS:
        return str(explicit)
    raw_num = str(ctrl["id"])
    if framework_id == "cfw_iso27001_2022" and not raw_num.startswith("A."):
        return f"A.{raw_num}"
    return raw_num


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
        # Name and version follow the seed. They used to be written on creation
        # only, so a catalogue moving to a new edition (PCI DSS 4.0 → 4.0.1)
        # kept announcing the old one for ever.
        framework.name = fw_data["name"]
        framework.version = fw_data["version"]
        print(f"Framework {framework_id} already exists. Synchronizing controls...")

    db.flush()

    # 2. Seed Compliance Controls
    controls_seeded = 0
    for ctrl in data["controls"]:
        raw_num = str(ctrl["id"])
        ctrl_num = _control_number(framework_id, ctrl)
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
            if ctrl.get(k):
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

        ot_meta_keys = (
            "purdue_levels",
            "component_types",
            "sl_levels",
            "zone_types",
            "bes_impact_levels",
            "standard_number",
        )
        for ot_key in ot_meta_keys:
            if ctrl.get(ot_key):
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


def main() -> int:
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
        base_dir = str(SEEDS_DIR)
        if args.seed_file:
            seed_framework_and_controls(db, args.seed_file)
            return 0

        # Every *_controls_seed.json in this directory is seeded. The list
        # used to be hand-maintained and had drifted: `iec_62443` and
        # `nist_800_53_r5` seed files existed, were referenced by the router's
        # report endpoints and by seeded rules, and were never loaded — so
        # those two frameworks were present in code and absent from any
        # database built by running this script. Globbing removes the failure
        # mode entirely: adding a framework is adding its file.
        seed_files = all_seed_paths()
        if not seed_files:
            print(f"No {SEED_GLOB} files found in {base_dir}")
            return 1

        for path in seed_files:
            seed_framework_and_controls(db, path)

        print(f"\nSeeded {len(seed_files)} framework catalogues.")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())

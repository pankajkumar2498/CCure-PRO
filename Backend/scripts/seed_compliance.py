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
        print(f"Framework {framework_id} already exists. Skipping framework seed.")

    db.flush()

    # 2. Seed Compliance Controls
    controls_seeded = 0
    for ctrl in data["controls"]:
        control_id = f"cct_{fw_data['code'].lower()}_{ctrl['id']}"
        control = (
            db.query(ComplianceControl)
            .filter(ComplianceControl.id == control_id)
            .first()
        )

        # Determine description
        description = ctrl.get("note", ctrl["title"])

        if not control:
            control = ComplianceControl(
                id=control_id,
                framework_id=framework_id,
                control_number=ctrl["id"],
                theme=ctrl["theme"],
                title=ctrl["title"],
                description=description,
                scannability=ctrl["scannability"],
                scan_module_hint=ctrl.get("scan_module_hint"),
            )
            db.add(control)
            controls_seeded += 1
        else:
            # Update fields if already exists to keep sync
            control.title = ctrl["title"]
            control.description = description
            control.scannability = ctrl["scannability"]
            control.scan_module_hint = ctrl.get("scan_module_hint")

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
        default=os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "iso27001_2022_controls_seed.json",
        ),
        help="Path to the JSON seed file containing controls metadata.",
    )
    args = parser.parse_args()

    db = SessionLocal()
    try:
        seed_framework_and_controls(db, args.seed_file)
    finally:
        db.close()

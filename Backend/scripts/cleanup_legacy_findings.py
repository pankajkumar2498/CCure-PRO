"""
Backend/scripts/cleanup_legacy_findings.py
One-off database cleanup script to purge legacy format compliance findings
and resolve duplicate UI cards.
"""

import sys
import os
from pathlib import Path

# Add Backend to PYTHONPATH
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from db.base import SessionLocal
from db.models.compliance import ComplianceFinding, ComplianceFindingHistory


def purge_legacy_findings():
    db = SessionLocal()
    try:
        print("=" * 60)
        print("  Ccure Audit — Legacy Findings Database Cleanup  ")
        print("=" * 60)

        # 1. Query all findings
        findings = db.query(ComplianceFinding).all()
        print(f"Total findings in database: {len(findings)}")

        # 2. Identify bad finding IDs
        bad_finding_ids = []
        for f in findings:
            if f.rule_id and f.rule_id[-8:] not in f.id:
                bad_finding_ids.append(f.id)

        if not bad_finding_ids:
            print("[SUCCESS] No legacy-format findings found. Database is clean!")
            return

        print(f"Found {len(bad_finding_ids)} legacy-format findings to delete.")

        # 3. Clean up history trails first (FK constraints)
        db.query(ComplianceFindingHistory).filter(
            ComplianceFindingHistory.finding_id.in_(bad_finding_ids)
        ).delete(synchronize_session=False)

        # 4. Clean up the findings themselves
        db.query(ComplianceFinding).filter(
            ComplianceFinding.id.in_(bad_finding_ids)
        ).delete(synchronize_session=False)

        db.commit()
        print(f"[SUCCESS] Successfully purged {len(bad_finding_ids)} old findings and their history trails.")

    except Exception as e:
        db.rollback()
        print(f"[FAIL] Cleanup failed: {e}")
    finally:
        db.close()


if __name__ == "__main__":
    purge_legacy_findings()

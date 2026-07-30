"""
CVSS Vector Sanity-Checker & Integrity Validator.
"""

from typing import List
from .models import CveRecord


def integrity_warnings(cve: CveRecord) -> List[str]:
    warnings = []
    v = cve.cvss

    if v.is_locally_exploitable_only and v.base_score >= 9.0:
        warnings.append(
            f"{cve.cve_id}: CVSS base score is {v.base_score} (Critical) but "
            f"attack vector is '{v.attack_vector}' (local/adjacent only)."
        )

    if v.privileges_required == "H" and v.base_score >= 9.0:
        warnings.append(
            f"{cve.cve_id}: scored Critical but requires high privileges pre-exploitation."
        )

    return warnings

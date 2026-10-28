"""
core/compliance_catalogue/reads.py
─────────────────────────────────────────────────────────────────────────────
What another capability may ask of the compliance catalogue, answered here so
that it never queries a compliance table itself.

Scan-policy validation (``core/scan_policy/validation.py``) is the reader:
whether the frameworks a policy names exist, whether this installation offers
them, whether an organisation installed them, and how many active rules each
holds. It ran those queries against five compliance tables itself until G4
(C4 of docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md), which moved them
here unchanged.

Each answer is a plain value — a set, a dict, a bool — never a row, so the
caller holds nothing of the compliance models.
"""

from __future__ import annotations

from typing import Dict, Iterable, Set

from sqlalchemy.orm import Session

from core.compliance_frameworks import is_active
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)

__all__ = [
    "active_rule_link_counts",
    "existing_framework_ids",
    "installed_framework_ids",
    "is_offered",
]


def existing_framework_ids(db: Session, framework_ids: Iterable[str]) -> Set[str]:
    """The ids among *framework_ids* the catalogue holds."""
    named = set(framework_ids)
    return {
        row[0]
        for row in db.query(ComplianceFramework.id)
        .filter(ComplianceFramework.id.in_(named))
        .all()
    }


def is_offered(framework_id: str) -> bool:
    """Whether this installation offers the framework (not parked).

    ``core.compliance_frameworks.is_active``: a shipped catalogue on the
    active list, or a loaded benchmark.
    """
    return is_active(framework_id)


def installed_framework_ids(
    db: Session, org_id: str, framework_ids: Iterable[str]
) -> Set[str]:
    """The ids among *framework_ids* that *org_id* has installed and enabled."""
    named = set(framework_ids)
    return {
        row[0]
        for row in db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == org_id,
            ComplianceTenantFramework.framework_id.in_(named),
            ComplianceTenantFramework.is_enabled.is_(True),
        )
        .all()
    }


def active_rule_link_counts(
    db: Session, framework_ids: Iterable[str]
) -> Dict[str, int]:
    """
    For each framework, how many (control, active rule) links it has.

    Every framework asked about is a key, so a framework with no active rule
    answers 0 rather than being missing. A rule linked to two controls of one
    framework counts twice: the caller asks only whether the count is zero.
    """
    framework_ids = list(framework_ids)
    rows = (
        db.query(ComplianceControl.framework_id, ComplianceRule.id)
        .join(ComplianceRuleControl, ComplianceRuleControl.rule_id == ComplianceRule.id)
        .join(
            ComplianceControl,
            ComplianceControl.id == ComplianceRuleControl.control_id,
        )
        .filter(
            ComplianceControl.framework_id.in_(framework_ids),
            ComplianceRule.status == "active",
        )
        .all()
    )
    seen: Dict[str, int] = {fid: 0 for fid in framework_ids}
    for framework_id, _rule_id in rows:
        seen[framework_id] = seen.get(framework_id, 0) + 1
    return seen

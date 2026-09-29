"""
Scan limits (quota) — a plan feature.

What an organisation's plan allows a scan to be: how many per rolling 24 hours,
how many at once, the largest subnet, the most IPs and the most custom ports.
Moved from ``core.quota._PLAN_LIMITS`` in Phase 8.4; the figures are unchanged.

Only the *limits* are here. Counting an organisation's scans against them is
Audit's, in ``core.quota`` — the one Audit module allowed to call this feature.

Removable: see ``ccure_platform/plan/__init__.py``.
"""

from __future__ import annotations

from dataclasses import dataclass

from ccure_platform.plan.catalogue import DEFAULT_PLAN, plan_of
from db.models import Organization
from sqlalchemy.orm import Session


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanLimits:
    #: ``None`` means unlimited.
    scans_per_day: int | None
    concurrent_scans: int
    largest_subnet_prefix: int
    ips_per_scan: int
    custom_ports: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ScanLimitsView:
    """
    An organisation's scan limits.

    ``effective`` is what admission enforces: an organisation's override where a
    superadmin set one, else the plan's figure. ``plan_defaults`` is the plan's
    own figure, which is what the quota bar and the dashboard have always shown
    (finding F2 in the design — preserved, not fixed, in Phase 8.4).
    """

    org_id: str
    #: The plan name as recorded, or the default plan.
    plan: str
    effective: ScanLimits
    plan_defaults: ScanLimits


_PLAN_SCAN_LIMITS: dict[str, ScanLimits] = {
    "community": ScanLimits(
        scans_per_day=5,
        concurrent_scans=1,
        largest_subnet_prefix=24,
        ips_per_scan=254,
        custom_ports=100,
    ),
    "pro": ScanLimits(
        scans_per_day=50,
        concurrent_scans=5,
        largest_subnet_prefix=16,
        ips_per_scan=65_534,
        custom_ports=1000,
    ),
    "enterprise": ScanLimits(
        scans_per_day=None,
        concurrent_scans=20,
        largest_subnet_prefix=8,
        ips_per_scan=16_777_214,
        custom_ports=65535,
    ),
}


def plan_default_scan_limits(plan: str | None) -> ScanLimits:
    """A plan's limits. The name is matched case-insensitively; an unknown one
    gets the default plan's, as it always did."""
    return _PLAN_SCAN_LIMITS.get((plan or "").lower(), _PLAN_SCAN_LIMITS[DEFAULT_PLAN])


def scan_limits(db: Session, org_id: str) -> ScanLimitsView:
    """
    The organisation's scan limits. An organisation that does not exist is
    treated as being on the default plan with no overrides — the behaviour
    admission has always had.
    """
    row = (
        db.query(Organization).filter(Organization.id == org_id).first()
        if org_id
        else None
    )
    plan = plan_of(row)
    defaults = plan_default_scan_limits(plan)
    per_day = defaults.scans_per_day
    concurrent = defaults.concurrent_scans
    if row is not None and row.max_scans_per_day is not None:
        per_day = row.max_scans_per_day
    if row is not None and row.max_concurrent_scans is not None:
        concurrent = row.max_concurrent_scans
    return ScanLimitsView(
        org_id=str(org_id),
        plan=plan,
        effective=ScanLimits(
            scans_per_day=per_day,
            concurrent_scans=concurrent,
            largest_subnet_prefix=defaults.largest_subnet_prefix,
            ips_per_scan=defaults.ips_per_scan,
            custom_ports=defaults.custom_ports,
        ),
        plan_defaults=defaults,
    )

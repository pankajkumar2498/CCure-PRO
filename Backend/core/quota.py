"""
core/quota.py
─────────────────────────────────────────────────────────────────────────────
Per-Organisation Scan Quota & Rate-Limit Enforcement

Plan tiers and their hard limits
─────────────────────────────────
  community  →  5  scans/day,  /24  max target  (254 IPs)
  pro        →  50 scans/day,  /16  max target  (65 534 IPs)
  enterprise →  unlimited,     /8   max target  (16 M IPs — practical cap only)

"scans/day" is a rolling 24-hour window (not a calendar-day reset), so a user
who hits the limit at 23:59 has to wait until 23:59 the following day.

Concurrent scan limit
──────────────────────
  community  →  1 running scan at a time
  pro        →  5 running scans at a time
  enterprise →  20 running scans at a time

Usage
──────
    from core.quota import check_scan_quota

    # raises HTTPException(429) if quota exceeded, HTTPException(400) if
    # the target subnet is too large for the plan.
    check_scan_quota(db, org_id=user.org_id, targets=["192.168.1.0/24"])
"""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.quota")


# ─────────────────────────────────────────────────────────────────────────────
# Plan definitions
# ─────────────────────────────────────────────────────────────────────────────

_PLAN_LIMITS = {
    # plan         max_scans_per_day  max_concurrent  max_prefix  max_ips_per_scan
    "community":  (5,                1,              24,         254),
    "pro":        (50,               5,              16,         65_534),
    "enterprise": (None,             20,             8,          16_777_214),
}

_DEFAULT_PLAN = "community"


def _limits(plan: str) -> tuple:
    """Return (max_day, max_concurrent, max_prefix, max_ips) for a plan."""
    return _PLAN_LIMITS.get((plan or "").lower(), _PLAN_LIMITS[_DEFAULT_PLAN])


# ─────────────────────────────────────────────────────────────────────────────
# IP count helper
# ─────────────────────────────────────────────────────────────────────────────

def _count_target_ips(targets: List[str]) -> int:
    """
    Estimate total unique IPs across all targets.
    Handles single IPs, CIDR subnets, and dash-ranges.
    """
    total = 0
    for t in targets:
        t = t.strip()
        try:
            if "/" in t:
                total += max(ipaddress.ip_network(t, strict=False).num_addresses - 2, 1)
            elif "-" in t:
                # e.g. "192.168.1.1-50" or "192.168.1.1-192.168.1.50"
                parts = t.split("-")
                if len(parts) == 2:
                    try:
                        # Format: base-last_octet  e.g. 192.168.1.1-50
                        base = parts[0].strip()
                        end_octet = int(parts[1].strip())
                        start_octet = int(base.rsplit(".", 1)[-1])
                        count = max(end_octet - start_octet + 1, 1)
                    except ValueError:
                        # Format: full-ip-full-ip  e.g. 192.168.1.1-192.168.1.50
                        start_ip = ipaddress.ip_address(parts[0].strip())
                        end_ip   = ipaddress.ip_address(parts[1].strip())
                        count = int(end_ip) - int(start_ip) + 1
                    total += max(count, 1)
            else:
                total += 1  # single IP
        except (ValueError, TypeError):
            total += 1  # treat unparseable as single IP
    return total


def _smallest_prefix(targets: List[str]) -> int:
    """
    Return the smallest prefix length across all subnet targets.
    A /8 is smaller (larger network) than a /24.
    Returns 32 if no subnet targets are found.
    """
    min_prefix = 32
    for t in targets:
        t = t.strip()
        if "/" in t:
            try:
                net = ipaddress.ip_network(t, strict=False)
                if net.prefixlen < min_prefix:
                    min_prefix = net.prefixlen
            except ValueError:
                pass
    return min_prefix


# ─────────────────────────────────────────────────────────────────────────────
# DB queries
# ─────────────────────────────────────────────────────────────────────────────

def _scans_in_last_24h(db: Session, org_id: str) -> int:
    """Count non-deleted scans started in the last 24 hours for this org."""
    from db.models.scans import Scan
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    return (
        db.query(Scan)
        .filter(
            Scan.org_id == org_id,
            Scan.is_deleted.is_(False),
            Scan.created_at >= cutoff,
        )
        .count()
    )


def _running_scans(db: Session, org_id: str) -> int:
    """Count scans currently in 'running' status for this org."""
    from db.models.scans import Scan
    return (
        db.query(Scan)
        .filter(
            Scan.org_id == org_id,
            Scan.status == "running",
            Scan.is_deleted.is_(False),
        )
        .count()
    )


def _get_org(db: Session, org_id: str):
    """Return the Organisation ORM row (or None)."""
    from db.models.rbac import Organization
    return db.query(Organization).filter(Organization.id == org_id).first()


def _get_org_plan(db: Session, org_id: str) -> str:
    """Return the plan string for the organisation."""
    org = _get_org(db, org_id)
    return (org.plan or _DEFAULT_PLAN) if org else _DEFAULT_PLAN


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def check_scan_quota(
    db: Session,
    org_id: str,
    targets: Optional[List[str]] = None,
) -> None:
    """
    Enforce plan-based scan quotas.  Raises HTTPException on violation.

    Per-org overrides (set by superadmin on the Organization row) take
    precedence over plan-level defaults for max_scans_per_day and
    max_concurrent_scans.

    Checks (in order):
      1. Max IPs per scan  — is the target too large for the plan?
      2. Concurrent scans  — is the org already at max running scans?
      3. Daily scan quota  — has the org hit their 24-hour scan limit?

    Args:
        db:      Active SQLAlchemy session.
        org_id:  Organization ID of the user initiating the scan.
        targets: List of target strings (IPs / CIDRs / ranges).  Pass None
                 to skip the per-scan IP-size check (e.g. Phase 2 / 3 only).

    Raises:
        HTTPException 400 — target subnet exceeds plan limit.
        HTTPException 429 — concurrent or daily quota exceeded.
    """
    org = _get_org(db, org_id)
    plan = (org.plan or _DEFAULT_PLAN) if org else _DEFAULT_PLAN
    max_day, max_concurrent, max_prefix, max_ips = _limits(plan)

    # Per-org overrides (superadmin can raise/lower limits per org)
    if org and getattr(org, "max_scans_per_day", None) is not None:
        max_day = org.max_scans_per_day
    if org and getattr(org, "max_concurrent_scans", None) is not None:
        max_concurrent = org.max_concurrent_scans

    # ── 1. Target size check ──────────────────────────────────────────────────
    if targets:
        total_ips = _count_target_ips(targets)
        smallest_prefix = _smallest_prefix(targets)

        if total_ips > max_ips:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Your '{plan}' plan allows a maximum of {max_ips:,} IPs per scan. "
                    f"The requested target contains ~{total_ips:,} IPs. "
                    f"Please reduce the scope or upgrade your plan."
                ),
            )

        if smallest_prefix < max_prefix:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Your '{plan}' plan allows subnets no larger than /{max_prefix}. "
                    f"The requested target uses a /{smallest_prefix}. "
                    f"Please reduce the scope or upgrade your plan."
                ),
            )

    # ── 2. Concurrent scan limit ──────────────────────────────────────────────
    running = _running_scans(db, org_id)
    if running >= max_concurrent:
        raise HTTPException(
            status_code=429,
            detail=(
                f"Your '{plan}' plan allows at most {max_concurrent} concurrent scan(s). "
                f"You currently have {running} running. "
                f"Please wait for an existing scan to complete."
            ),
        )

    # ── 3. Daily quota ────────────────────────────────────────────────────────
    if max_day is not None:
        used_today = _scans_in_last_24h(db, org_id)
        if used_today >= max_day:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Your '{plan}' plan allows {max_day} scan(s) per 24 hours. "
                    f"You have used {used_today} in the last 24 hours. "
                    f"Please wait before starting a new scan or upgrade your plan."
                ),
            )

    log.info(
        "Quota OK — org=%s plan=%s running=%d/%d daily_used=%s/%s targets=%s",
        org_id, plan, running, max_concurrent,
        _scans_in_last_24h(db, org_id) if max_day else "∞",
        max_day or "∞",
        targets,
    )


def get_quota_status(db: Session, org_id: str) -> dict:
    """
    Return a quota status dict for the org — used by the frontend to display
    usage meters.  Never raises; always returns a safe dict.

    Returns::

        {
          "plan": "community",
          "scans_used_24h": 3,
          "scans_limit_24h": 5,
          "concurrent_running": 1,
          "concurrent_limit": 1,
          "max_ips_per_scan": 254,
          "max_subnet_prefix": 24,
          "quota_exceeded": false,
          "concurrent_exceeded": false,
        }
    """
    try:
        plan = _get_org_plan(db, org_id)
        max_day, max_concurrent, max_prefix, max_ips = _limits(plan)

        used_day = _scans_in_last_24h(db, org_id)
        running  = _running_scans(db, org_id)

        return {
            "plan":                plan,
            "scans_used_24h":      used_day,
            "scans_limit_24h":     max_day,        # None = unlimited
            "concurrent_running":  running,
            "concurrent_limit":    max_concurrent,
            "max_ips_per_scan":    max_ips,
            "max_subnet_prefix":   max_prefix,
            "quota_exceeded":      (max_day is not None and used_day >= max_day),
            "concurrent_exceeded": (running >= max_concurrent),
        }
    except Exception as exc:
        log.warning("get_quota_status failed for org=%s: %s", org_id, exc)
        return {
            "plan": "unknown", "scans_used_24h": 0, "scans_limit_24h": None,
            "concurrent_running": 0, "concurrent_limit": 1,
            "max_ips_per_scan": 254, "max_subnet_prefix": 24,
            "quota_exceeded": False, "concurrent_exceeded": False,
        }

"""
core/quota.py
─────────────────────────────────────────────────────────────────────────────
Per-Organisation Scan Quota & Rate-Limit Enforcement

**The Audit seam of the scan-limits plan feature (Phase 8.4).** The limits
belong to the organisation's plan, which is platform-owned
(``ccure_platform.plan.scan_limits``, reached through ``ccure_platform.api``).
What is Audit's is here: counting this organisation's own scans against those
limits and refusing with a message. This module is the only Audit code that
asks the platform for scan limits
(``tests/repo/test_plan_feature_containment.py``), so removing quota is this
module, its callers' calls into it, and the platform feature — nothing in the
scan pipeline.

Plan tiers and their hard limits (defined in ccure_platform.plan.scan_limits)
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
    check_scan_quota(db, org_id=user.org_id, targets=["10.180.6.0/24"])
"""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from ccure_platform import api as platform_api
from fastapi import HTTPException
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.quota")


# ─────────────────────────────────────────────────────────────────────────────
# The plan's limits — asked of the platform, never read from the organisation row
# ─────────────────────────────────────────────────────────────────────────────


def effective_scan_limits(db: Session, org_id: str):
    """The organisation's limits as admission enforces them (overrides applied)."""
    return platform_api.scan_limits(db, org_id)


def displayed_scan_limits(db: Session, org_id: str) -> tuple:
    """
    ``(plan, max_scans_per_day, max_concurrent_scans)`` as the dashboard shows
    them: the plan's own figures, without the per-organisation overrides that
    admission applies. That difference is finding F2 of the Phase 8.4 design,
    kept exactly as it was until it is decided.
    """
    limits = platform_api.scan_limits(db, org_id)
    return (
        limits.plan,
        limits.plan_defaults.scans_per_day,
        limits.plan_defaults.concurrent_scans,
    )


# ─────────────────────────────────────────────────────────────────────────────
# IP count helper
# ─────────────────────────────────────────────────────────────────────────────


def _count_target_ips(targets: list[str]) -> int:
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
                # e.g. "10.180.6.14-50" or "10.180.6.14-192.168.1.50"
                parts = t.split("-")
                if len(parts) == 2:
                    try:
                        # Format: base-last_octet  e.g. 10.180.6.14-50
                        base = parts[0].strip()
                        end_octet = int(parts[1].strip())
                        start_octet = int(base.rsplit(".", 1)[-1])
                        count = max(end_octet - start_octet + 1, 1)
                    except ValueError:
                        # Format: full-ip-full-ip  e.g. 10.180.6.14-192.168.1.50
                        start_ip = ipaddress.ip_address(parts[0].strip())
                        end_ip = ipaddress.ip_address(parts[1].strip())
                        count = int(end_ip) - int(start_ip) + 1
                    total += max(count, 1)
            else:
                total += 1  # single IP
        except (ValueError, TypeError):
            total += 1  # treat unparseable as single IP
    return total


def _smallest_prefix(targets: list[str]) -> int:
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
                min_prefix = min(min_prefix, net.prefixlen)
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


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────


def check_scan_quota(
    db: Session,
    org_id: str,
    targets: list[str] | None = None,
    custom_ports: str | None = None,
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
        custom_ports: Custom ports list (if any) to validate port limits.

    Raises:
        HTTPException 400 — target subnet exceeds plan limit or custom ports limit.
        HTTPException 429 — concurrent or daily quota exceeded.
    """
    # The plan's limits with any per-organisation override a superadmin set.
    limits = effective_scan_limits(db, org_id)
    plan = limits.plan
    max_day = limits.effective.scans_per_day
    max_concurrent = limits.effective.concurrent_scans
    max_prefix = limits.effective.largest_subnet_prefix
    max_ips = limits.effective.ips_per_scan
    max_ports = limits.effective.custom_ports

    # ── 1b. Custom Ports limit check ──────────────────────────────────────────
    if custom_ports:
        from core.utils import InputValidator

        try:
            parsed_ports = InputValidator.parse_custom_ports(custom_ports)
            ports_count = len(parsed_ports)
            if ports_count > max_ports:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Your '{plan}' plan allows a maximum of {max_ports:,} ports per custom scan. "
                        f"The requested scan contains {ports_count:,} ports. "
                        f"Please reduce the number of ports or upgrade your plan."
                    ),
                )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

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
        org_id,
        plan,
        running,
        max_concurrent,
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
        # The plan's own figures, not the overrides admission applies (F2).
        limits = platform_api.scan_limits(db, org_id)
        plan = limits.plan
        max_day = limits.plan_defaults.scans_per_day
        max_concurrent = limits.plan_defaults.concurrent_scans
        max_prefix = limits.plan_defaults.largest_subnet_prefix
        max_ips = limits.plan_defaults.ips_per_scan
        max_ports = limits.plan_defaults.custom_ports

        used_day = _scans_in_last_24h(db, org_id)
        running = _running_scans(db, org_id)

        return {
            "plan": plan,
            "scans_used_24h": used_day,
            "scans_limit_24h": max_day,  # None = unlimited
            "concurrent_running": running,
            "concurrent_limit": max_concurrent,
            "max_ips_per_scan": max_ips,
            "max_subnet_prefix": max_prefix,
            "max_ports_per_scan": max_ports,
            "quota_exceeded": (max_day is not None and used_day >= max_day),
            "concurrent_exceeded": (running >= max_concurrent),
        }
    except Exception as exc:
        log.warning("get_quota_status failed for org=%s: %s", org_id, exc)
        return {
            "plan": "unknown",
            "scans_used_24h": 0,
            "scans_limit_24h": None,
            "concurrent_running": 0,
            "concurrent_limit": 1,
            "max_ips_per_scan": 254,
            "max_subnet_prefix": 24,
            "quota_exceeded": False,
            "concurrent_exceeded": False,
        }

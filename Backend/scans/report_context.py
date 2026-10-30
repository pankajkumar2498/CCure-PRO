"""
scans/report_context.py
─────────────────────────────────────────────────────────────────────────────
What a scan's report says about the scan itself: its target as the user gave
it, the discovery method, the first phase's host counts and the coverage
parameters a later phase carries forward (G2, the remainder of C7 in
docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

Moved unchanged out of ``scan_helpers``, which re-exports every name, so the
report download route reads it from the scans capability rather than from the
module that also loads the network orchestrator.
"""

import logging

from db.models import Scan
from sqlalchemy.orm import Session

log = logging.getLogger("ccure.api")


def _normalize_scan_method(value: str | None) -> str | None:
    token = str(value or "").strip().upper()
    if not token:
        return None
    if "ADAPTIVE" in token:
        return "ADAPTIVE"
    if "STEALTH" in token:
        return "STEALTH"
    if "FULL" in token:
        return "FULL"
    if "ARP" in token:
        return "ARP"
    if "PING" in token or "ICMP" in token:
        return "PING"
    if "TCP" in token:
        return "TCP"
    return None


def _extract_host_ip(host: dict) -> str | None:
    return host.get("ip_address") or host.get("ip")


def _target_from_hosts(hosts: list[dict]) -> str | None:
    ips = []
    for host in hosts or []:
        ip = _extract_host_ip(host)
        if ip and ip not in ips:
            ips.append(ip)
    if not ips:
        return None
    return ", ".join(ips)


def _scan_method_from_hosts(hosts: list[dict]) -> str | None:
    for host in hosts or []:
        method = (
            host.get("scan_method")
            or host.get("discovery_method")
            or host.get("method")
        )
        normalized = _normalize_scan_method(method)
        if normalized:
            return normalized
    return None


# ─── Report context resolution ───────────────────────────────────────────────


def resolve_report_context(
    db: Session,
    user_id: str,
    *,
    scan_id: str | None = None,
    hosts: list[dict] | None = None,
    requested_targets: list[str] | None = None,
    requested_scan_type: str | None = None,
) -> dict:
    """
    Build report metadata with human-meaningful context:
      - target (prefer original user input)
      - scan_method/discovery_scan_method (discovery strategy)
    """
    context: dict = {}
    scan_row: Scan | None = None
    summary_blob: dict = {}

    if scan_id:
        scan_row = (
            db.query(Scan)
            .filter(Scan.id == scan_id, Scan.created_by == user_id)
            .first()
        )
    if scan_row:
        # Both halves of the report's "Scan reference": a scan number alone is
        # a row counter (two organisations both have a scan 1).
        context["scan_no"] = scan_row.scan_no
        context["scan_id"] = str(scan_row.id)
        summary_blob = phase1_summary_from_scan(scan_row)

    # Target priority: request targets > scan row target/original_targets > host list
    if requested_targets:
        context["target"] = ", ".join(
            [str(t).strip() for t in requested_targets if str(t).strip()]
        )
        context["original_targets"] = requested_targets
    elif scan_row:
        target = (scan_row.target_str or "").strip()
        if target:
            context["target"] = target
        original_targets = summary_blob.get("original_targets") or (
            scan_row.target_hosts or []
        )
        if original_targets:
            context["original_targets"] = original_targets
            if "target" not in context:
                context["target"] = ", ".join(
                    [str(t).strip() for t in original_targets if str(t).strip()]
                )
    elif hosts:
        host_target = _target_from_hosts(hosts)
        if host_target:
            context["target"] = host_target

    # Scan strategy priority: request scan_type > stored scan_type > host-level method
    scan_method = _normalize_scan_method(requested_scan_type)
    if not scan_method and scan_row:
        scan_method = (
            _normalize_scan_method(scan_row.scan_type)
            or _normalize_scan_method(summary_blob.get("discovery_scan_method"))
            or _normalize_scan_method(summary_blob.get("scan_method"))
            or _normalize_scan_method(summary_blob.get("scan_type"))
        )
    if not scan_method and hosts:
        scan_method = _scan_method_from_hosts(hosts)

    if scan_method:
        context["scan_method"] = scan_method
        context["discovery_scan_method"] = scan_method

    # The feed date every vulnerability report states. Only the
    # regenerate-on-download path added it, so a report written at scan
    # completion printed "Vulnerability feed: Not recorded".
    try:
        from core.vuln_intel import get_feed_freshness

        freshness = get_feed_freshness()
        if freshness.get("last_modified"):
            context["cve_feed_updated"] = freshness["last_modified"]
        if freshness.get("cve_count"):
            context["cve_feed_size"] = freshness["cve_count"]
    except Exception as exc:  # never block a report on this
        log.debug("Feed freshness unavailable for the report: %s", exc)

    return context


#: Parameters describing what a scan examined. They bound every conclusion
#: drawn from it, so they travel with the scan record from the phase that knows
#: them to any later phase or report that has to state the scan's coverage.
SCAN_COVERAGE_KEYS = (
    "port_range",
    "timing_template",
    "scanner",
    "service_detection",
    "os_detection",
)


def phase_summary_from_scan(scan_row: Scan, *phase_keys: str) -> dict:
    """The stored summary for the first matching phase, or an empty dict."""
    wanted = set(phase_keys)
    for phase_row in getattr(scan_row, "phases", []) or []:
        if getattr(phase_row, "phase_key", "") not in wanted:
            continue
        summary = getattr(phase_row, "summary", {}) or {}
        if isinstance(summary, dict):
            return summary
    return {}


def carry_scan_coverage(result: dict, source_summary: dict) -> None:
    """
    Copy an earlier phase's coverage parameters onto a later phase's result.

    A vulnerability assessment does not choose ports — it assesses whatever the
    asset discovery phase found. Its report still has to state which ports were
    examined, and only the phase that scanned them knows. Without this the
    report either says "not recorded" against every parameter or, worse, falls
    back to a default that reads as a statement of fact.
    """
    if not source_summary:
        return
    summary = result.setdefault("summary", {})
    meta = result.setdefault("metadata", {})
    for key in SCAN_COVERAGE_KEYS:
        value = source_summary.get(key)
        if value in (None, ""):
            continue
        summary.setdefault(key, value)
        meta.setdefault(key, value)


def phase1_summary_from_scan(scan_row: Scan) -> dict:
    for phase_row in getattr(scan_row, "phases", []) or []:
        if getattr(phase_row, "phase_key", "") not in ("host_discovery", "phase1"):
            continue
        summary = getattr(phase_row, "summary", {}) or {}
        if isinstance(summary, dict):
            return summary
    return {}


def apply_phase1_summary_hints(
    result: dict,
    db: Session,
    user_id: str,
    scan_id: str | None,
) -> None:
    if not scan_id:
        return
    scan_row = (
        db.query(Scan).filter(Scan.id == scan_id, Scan.created_by == user_id).first()
    )
    if not scan_row:
        return
    phase1_summary = phase1_summary_from_scan(scan_row)
    if not phase1_summary:
        return

    summary = result.setdefault("summary", {})
    for key in ("total_hosts", "active_hosts", "inactive_hosts"):
        if phase1_summary.get(key) is not None:
            summary[key] = phase1_summary[key]

    discovery_scan_method = _normalize_scan_method(
        phase1_summary.get("discovery_scan_method") or phase1_summary.get("scan_type")
    )
    if discovery_scan_method:
        summary["discovery_scan_method"] = discovery_scan_method
        metadata = result.setdefault("metadata", {})
        metadata.setdefault("scan_method", discovery_scan_method)
        metadata.setdefault("discovery_scan_method", discovery_scan_method)

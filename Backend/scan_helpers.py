"""
scan_helpers.py
───────────────────────────────────────────────────────────────────────────────
Shared helpers, constants, and pipeline logic used by multiple router modules.

Located at the Backend root (not inside routers/) to avoid circular imports,
since the lifespan function in main.py also depends on these symbols.
"""

import logging
from typing import Dict, List, Optional

from orchestrator.host_discovery_api import HostDiscoveryAPI
from db.models import Scan

log = logging.getLogger("ccure.api")


# The limiter moved to core/rate_limiter.py (Phase 3). Re-exported here so
# every `from scan_helpers import limiter` gets the same instance. Application
# modules import it from core.rate_limiter (B1, 16 Oct 2026), which does not
# load the network orchestrator; tests and scripts still use this alias.
from core.rate_limiter import (  # noqa: F401  (re-export)
    _HeaderSafeLimiter,
    _rate_limit_key,
    limiter,
)

from scans.progress import (
    finish_progress as _db_finish_progress,
)
from sqlalchemy.orm import Session

# ─── Application state ──────────────────────────────────────────────────────
_api_instance: HostDiscoveryAPI | None = None


def set_api(api: HostDiscoveryAPI) -> None:
    """Called once from lifespan to register the singleton."""
    global _api_instance
    _api_instance = api


def get_api() -> HostDiscoveryAPI:
    """Return the HostDiscoveryAPI singleton or raise 503."""
    from fastapi import HTTPException

    if _api_instance is None:
        raise HTTPException(status_code=503, detail="API not initialised yet.")
    return _api_instance


# ─── Pipeline configuration ─────────────────────────────────────────────────
# Defined in scans/pipeline.py since C6, with the network phases and the one
# function that hands a phase its hosts. Re-exported here unchanged, as the
# same objects, for the routes and tests that read them from this module.
from scans.pipeline import (  # noqa: E402,F401  (re-export)
    PIPELINE_MODE_ALIASES,
    PIPELINE_PHASES,
    VALID_PIPELINE_MODES,
    _normalize_pipeline_mode,
    get_terminal_phase,
    is_phase_in_pipeline,
    resolve_pipeline_mode,
)


# ─── Misc helpers ────────────────────────────────────────────────────────────


def _is_scannable_address(value: str) -> bool:
    """A real network destination, as opposed to the scanner's own vantage point."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(str(value).strip())
    except ValueError:
        # Hostnames are resolved upstream by expand_target; anything still
        # unparseable here is not this function's to reject.
        return True
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
        or addr.is_multicast
    )


# Distinguishes "this caller does not do scope enforcement" from "this caller
# enforces scope and the organisation does not exist" (scope=None). The second
# must still be denied under REQUIRE_SCAN_SCOPE, so it cannot share a default
# with the first.
_SCOPE_NOT_CHECKED = object()


def validate_custom_ports(custom_ports: str | None) -> None:
    """Reject malformed custom ports before a scan is dispatched."""
    if custom_ports:
        from core.utils import InputValidator
        from fastapi import HTTPException

        try:
            InputValidator.parse_custom_ports(custom_ports)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


def validate_scan_targets(
    targets: list[str] | None, scope=_SCOPE_NOT_CHECKED
) -> list[str]:
    """
    Reject a scan request that can never produce results, before it costs anything.

    An unparseable target used to be accepted with HTTP 200: the API created a
    scan row and only failed asynchronously
    seconds later with a reason the API never returned. A typo should come back
    as an error the operator can fix, not as a scan that quietly dies.

    When `scope` is supplied — the organisation's ``ScanScopeView`` from
    ``core.scan_scope.org_scan_scope`` — the targets are additionally checked
    against it. The two checks are distinct and both belong here: everything
    above `scope` is a usability filter answering "can this scan work?", the
    scope check is an authorisation boundary answering "is this scan
    permitted?". Callers that omit `scope` get validation only — which is why
    every scan-creating route passes it.

    Returns the cleaned target list.
    """
    from core.utils import InputValidator
    from fastapi import HTTPException

    cleaned = [str(t).strip() for t in (targets or []) if str(t).strip()]
    if not cleaned:
        raise HTTPException(
            status_code=422,
            detail="At least one scan target is required.",
        )

    invalid: list[str] = []
    unscannable: list[str] = []
    total = 0
    for target in cleaned:
        expanded = InputValidator.expand_target(target)
        if not expanded:
            invalid.append(target)
            continue
        # A loopback or link-local target describes the scanner's own vantage
        # point, not a host on the network. Scanning one produced an
        # "unreachable" scan at best; at worst it resolved to the same MAC as a
        # real asset and rewrote that asset's address to 127.0.0.1, detaching
        # its findings from the address they belong to.
        if all(not _is_scannable_address(ip) for ip in expanded):
            unscannable.append(target)
            continue
        total += len(expanded)

    if invalid:
        raise HTTPException(
            status_code=422,
            detail=(
                "Not a valid IP address, range, CIDR block or resolvable hostname: "
                + ", ".join(invalid)
            ),
        )

    if unscannable:
        raise HTTPException(
            status_code=422,
            detail=(
                "Loopback and link-local addresses are not scannable targets: "
                + ", ".join(unscannable)
                + ". Use the address the host is reachable on from this network."
            ),
        )

    if total > InputValidator.MAX_HOSTS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Total requested hosts ({total}) exceeds the global limit of "
                f"{InputValidator.MAX_HOSTS}."
            ),
        )

    if scope is not _SCOPE_NOT_CHECKED:
        from core.scan_scope import ScanScopeError, enforce_org_scan_scope

        try:
            enforce_org_scan_scope(cleaned, scope)
        except ScanScopeError as exc:
            # 403, not 422: the request is well-formed and the operator is
            # authenticated. What is missing is authorisation for this target.
            raise HTTPException(status_code=403, detail=exc.message) from exc

    return cleaned


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


def finish_progress(scan_id: str, db: Session = None):
    """Mark a scan as finished in the database (multi-worker safe)."""
    if db:
        _db_finish_progress(db, scan_id)
    else:
        from db.base import SessionLocal

        session = SessionLocal()
        try:
            _db_finish_progress(session, scan_id)
        finally:
            session.close()


def __getattr__(name: str):
    # make_pdf_cve_paragraph is a renderer's helper and lives in
    # reporting/report_helpers.py since G6. The old name stays, imported on
    # first use so that loading this module does not load ReportLab.
    if name == "make_pdf_cve_paragraph":
        from reporting.report_helpers import make_pdf_cve_paragraph

        return make_pdf_cve_paragraph
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

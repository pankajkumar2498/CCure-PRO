"""
scan_helpers.py
───────────────────────────────────────────────────────────────────────────────
Shared helpers, constants, and pipeline logic used by multiple router modules.

Located at the Backend root (not inside routers/) to avoid circular imports,
since the lifespan function in main.py also depends on these symbols.
"""

import json
import logging
from typing import Dict, List, Optional

from orchestrator.host_discovery_api import HostDiscoveryAPI
from config import AppConfig
from core.ip_resolver import get_client_ip
from db.models import Scan
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.responses import Response

log = logging.getLogger("ccure.api")


def _rate_limit_key(request) -> str:
    """
    Identify the client a rate limit should apply to.

    slowapi's get_remote_address returns the socket peer. Behind the nginx
    gateway that is always the proxy container, so every user shared a single
    bucket and one analyst's burst locked scanning for the whole organisation.
    get_client_ip walks the X-Forwarded-For chain from the nearest hop outward
    and stops at the first address that is not a trusted proxy, so a client
    cannot spoof its way into someone else's bucket either.
    """
    try:
        resolved = get_client_ip(request)
        if resolved:
            return resolved
    except Exception:  # never let limiter bookkeeping break a request
        log.debug("Falling back to socket address for rate limiting", exc_info=True)
    return get_remote_address(request)


# ─── Rate limiter (shared across routers) ────────────────────────────────────
#
# Counters live in the same Redis instance as Celery, which is what makes the
# limit a real limit: an in-process counter would be multiplied by the number of
# API worker processes, so "3/minute" would mean 3 per minute *per worker*.
#
# `in_memory_fallback` decides what happens when that Redis is unreachable, and
# the previous answer was bad in a way that is easy to miss. slowapi is built
# with swallow_errors=False, so a storage failure propagated straight out of the
# decorator: login, registration and every scan endpoint answered 500. That is
# not a fail-closed rate limit, it is an outage of the authentication system,
# and it hands anyone who can disrupt Redis a way to take the product down.
#
# With a fallback configured, slowapi switches to process-local counters for the
# duration and re-probes the backend periodically. Two honest caveats: the
# counters are per worker process, and slowapi applies the *fallback* limit in
# place of each route's own while the backend is down. The control is degraded,
# not absent — which is the right trade for an outage nobody chose.
_fallback_limits = (
    [AppConfig.RATE_LIMIT_MEMORY_FALLBACK]
    if AppConfig.RATE_LIMIT_MEMORY_FALLBACK
    else []
)


class _HeaderSafeLimiter(Limiter):
    """A Limiter whose header injection cannot take an endpoint down.

    With ``headers_enabled=True`` slowapi writes X-RateLimit-* onto the
    response after the handler returns. It finds that response one of two
    ways: the handler returned a ``Response`` object, or the handler declared
    a ``response: Response`` parameter that FastAPI filled in. A handler that
    does neither — the overwhelming majority, since returning a dict and
    letting FastAPI serialise it is the normal style — hands slowapi ``None``,
    and upstream `_inject_headers` answers that with a bare
    ``raise Exception(...)`` from inside the endpoint call.

    That is a 500 on every single request to the route, caused by a missing
    parameter, and it is invisible until the route is exercised on a live
    server: the test suite sets ``limiter.enabled = False``, which skips
    injection entirely. Twenty-one routes shipped in exactly that state,
    including `/scan/host-discovery` and `/auth/reset-password`, because
    adding a limit to a route requires a change to its signature that nothing
    checked for.

    Missing rate-limit headers are a cosmetic loss; a 500 on scan dispatch is
    an outage. So the same trade this module already makes for a Redis outage
    applies here — degrade, log, and keep answering. `_route_limits` is
    untouched, so the limit itself is still enforced; only the advisory
    headers go missing.

    `tests/security/test_rate_limit_headers.py` is what keeps this from
    becoming a silent excuse for never declaring the parameter.
    """

    # Endpoints already warned about. The condition is a property of the route,
    # not of the request, so it is logged once per endpoint — the same reason
    # RATE_LIMIT_DEGRADED is logged on transition rather than per request. A
    # line every request would bury the log of a busy route in a message about
    # a missing header.
    _warned_endpoints: set[str] = set()

    def _inject_headers(self, response, current_limit):  # type: ignore[override]
        if not isinstance(response, Response):
            if self.enabled and self._headers_enabled and current_limit is not None:
                # current_limit[1] is [key, scope]; the scope is the endpoint
                # slowapi registered the limit against, which is the one piece
                # of information that makes this actionable.
                scope = current_limit[1][-1] if len(current_limit[1]) > 1 else "?"
                if scope not in self._warned_endpoints:
                    self._warned_endpoints.add(scope)
                    log.warning(
                        "Rate limit headers skipped for %s: the endpoint "
                        "neither returned a Response nor declared a "
                        "`response: Response` parameter. The limit is still "
                        "enforced. See tests/security/test_rate_limit_headers.py",
                        scope,
                    )
            return response
        return super()._inject_headers(response, current_limit)


limiter = _HeaderSafeLimiter(
    key_func=_rate_limit_key,
    storage_uri=AppConfig.CELERY_BROKER_URL,
    in_memory_fallback=_fallback_limits,
    # X-RateLimit-* on every limited response. Clients can back off before they
    # are refused, and an auditor can confirm a limit is live from the wire
    # rather than from the source.
    headers_enabled=True,
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


# ─── Pipeline configuration (mirrors src/config/scanConfig.js) ───────────────
# Phase 4 (topology_mapping) is eligible to run at the end of any pipeline.
# It is only executed if SNMP credentials are provided in scan.options.
PIPELINE_PHASES: dict[str, list[int]] = {
    "basic": [1, 4],
    "asset": [1, 2, 4],
    "vulnerability_audit": [1, 2, 3, 4],
    # A standalone credentialed audit runs no discovery and no port scan. It
    # was previously recorded as "vulnerability_audit", which claimed three
    # phases it never executed — the scan record has to describe what ran.
    "credentialed": [3],
}

VALID_PIPELINE_MODES = set(PIPELINE_PHASES.keys()) | {"advanced"}
PIPELINE_MODE_ALIASES = {
    "advanced": "vulnerability_audit",
}


def _normalize_pipeline_mode(raw: str | None) -> str:
    token = str(raw or "").strip().lower()
    if not token:
        return "basic"
    return PIPELINE_MODE_ALIASES.get(token, token)


def get_terminal_phase(pipeline_mode: str) -> int:
    """Return the last *core* phase number for a given pipeline mode.
    Phase 4 (topology_mapping) is an optional bolt-on and does NOT
    count as the terminal phase for scan completion logic."""
    pipeline_mode = _normalize_pipeline_mode(pipeline_mode)
    phases = PIPELINE_PHASES.get(pipeline_mode, [1])
    # Exclude Phase 4 (topology) — it's an optional add-on, not core pipeline
    core_phases = [p for p in phases if p != 4]
    return max(core_phases) if core_phases else max(phases)


def is_phase_in_pipeline(pipeline_mode: str, phase: int) -> bool:
    """Return True if the given phase belongs to the declared pipeline."""
    pipeline_mode = _normalize_pipeline_mode(pipeline_mode)
    return phase in PIPELINE_PHASES.get(pipeline_mode, [1])


def resolve_pipeline_mode(raw: str | None) -> str:
    """
    Normalise and validate the pipeline_mode from a request.
    Falls back to 'basic' for unknown / missing values.
    """
    token = _normalize_pipeline_mode(raw)
    if token in VALID_PIPELINE_MODES:
        return token
    if raw:
        log.warning("Unknown pipeline_mode '%s' — defaulting to 'basic'.", raw)
    return "basic"


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
# enforces scope and the org row could not be loaded". The second must still be
# denied under REQUIRE_SCAN_SCOPE, so it cannot share a default with the first.
_SCOPE_NOT_CHECKED = object()


def validate_scan_targets(
    targets: list[str] | None, org=_SCOPE_NOT_CHECKED
) -> list[str]:
    """
    Reject a scan request that can never produce results, before it costs anything.

    An unparseable target used to be accepted with HTTP 200: the API created a
    scan row, consumed the organisation's quota, and only failed asynchronously
    seconds later with a reason the API never returned. A typo should come back
    as an error the operator can fix, not as a scan that quietly dies.

    When `org` is supplied the targets are additionally checked against that
    organisation's authorised scan scope (see core/scan_scope.py). The two
    checks are distinct and both belong here: everything above `org` is a
    usability filter answering "can this scan work?", the scope check is an
    authorisation boundary answering "is this scan permitted?". Callers that
    omit `org` get validation only — which is why every scan-creating route
    passes it.

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

    if org is not _SCOPE_NOT_CHECKED:
        from core.scan_scope import ScanScopeError, enforce_org_scan_scope

        try:
            enforce_org_scan_scope(cleaned, org)
        except ScanScopeError as exc:
            # 403, not 422: the request is well-formed and the operator is
            # authenticated. What is missing is authorisation for this target.
            raise HTTPException(status_code=403, detail=exc.message) from exc

    return cleaned


def validate_total_targets(targets: list[str]) -> None:
    """Backwards-compatible wrapper — prefer validate_scan_targets."""
    validate_scan_targets(targets)


def _safe_json_loads(text: str | None, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


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
        context["scan_no"] = scan_row.scan_no
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


def get_cve_redirection_url(cve_id: str) -> str:
    """Return the authoritative NIST NVD URL for a CVE ID."""
    clean_id = str(cve_id).strip()
    return f"https://nvd.nist.gov/vuln/detail/{clean_id.upper()}"


def make_pdf_cve_paragraph(cve_id: str, style) -> "Paragraph":
    """
    Constructs a ReportLab Paragraph containing a secure, clickable hyperlink
    directing the user to the NVD reference page for the specified CVE.
    """
    import html

    from reportlab.platypus import Paragraph

    clean_id = str(cve_id).strip()
    # Guard check: if it's not a valid CVE ID, return plain styled Paragraph
    if not clean_id.upper().startswith("CVE-"):
        return Paragraph(html.escape(clean_id), style)

    safe_id = html.escape(clean_id.upper())
    url = f"https://nvd.nist.gov/vuln/detail/{safe_id}"

    # Branded blue link markup
    link_html = f'<a href="{url}" color="#0066CC"><b>{safe_id}</b></a>'
    return Paragraph(link_html, style)

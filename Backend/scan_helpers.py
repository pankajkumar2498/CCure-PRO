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


# What a report says about its scan moved to scans/report_context.py (G2).
# Re-exported here for the scan tasks and anything else that imported it
# from this module.
from scans.report_context import (  # noqa: E402,F401  (re-export)
    _normalize_scan_method,
    _extract_host_ip,
    _target_from_hosts,
    _scan_method_from_hosts,
    resolve_report_context,
    SCAN_COVERAGE_KEYS,
    phase_summary_from_scan,
    carry_scan_coverage,
    phase1_summary_from_scan,
    apply_phase1_summary_hints,
)


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

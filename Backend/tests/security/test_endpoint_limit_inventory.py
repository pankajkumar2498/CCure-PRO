"""
tests/security/test_endpoint_limit_inventory.py
───────────────────────────────────────────────
Every unauthenticated or expensive endpoint must carry an explicit
abuse-control decision.

This is the standing version of an audit done by hand in August 2026. That
audit found `/auth/reset-password` running unlimited, and it found it *once* —
the same review a month later would have had to be done again from scratch, and
the route added next week would not be in it.

So the rule is enforced here instead. A new unauthenticated route, or a new
route that dispatches a scan, renders a report or changes a remote host, fails
this test until somebody either gives it a limit or writes down why it does not
need one. **Adding a name to the allowlists below is a legitimate answer** —
the goal is a decision on the record, not a limiter on every path. What is not
allowed is silence.

The 600/minute baseline in `core/rate_limit_middleware.py` is not a substitute
and is deliberately not consulted here. It is a backstop against a route being
*entirely* unbounded; at 10 requests a second it is far too loose to be the
control protecting a login form or a PDF renderer.
"""

import pytest
from fastapi.routing import APIRoute

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Dependencies that establish who the caller is. A route reaching none of these
# is reachable by anybody who can reach the port.
AUTH_MARKERS = {
    "get_current_user",
    "get_current_user_flexible",
    "get_current_active_user",
    "require_permission",
    "require_role",
    "require_active_framework",
    "verify_ws_ticket",
    "_verify_admin",
}

# ── Allowlists: routes with a deliberate decision not to add a limit ─────────

UNAUTHENTICATED_WITHOUT_LIMIT = {
    # Static text. No database access, no side effect, no secrets, and the
    # first is what monitoring polls for liveness — limiting it would make a
    # health check into a source of false alarms.
    "routers.health.root",
    "routers.scan_progress.pipeline_modes",
    "routers.scan_progress.workflow_example",
    # One public policy boolean via an indexed singleton, with no account lookup, side effects or
    # secrets. Do not share the registration probes' enumeration quota with
    # login-page initialization; the baseline and edge ceilings still apply.
    "auth.router.public_auth_config",
}

SENSITIVE_WITHOUT_LIMIT = {
    # Deletes and state flips. Cheap, permission-gated, and bounded by the
    # number of rows the tenant actually owns — a loop cannot manufacture more
    # work than the data it is deleting.
    "routers.reports.delete_report",
    "routers.scan_history.delete_scan",
    "routers.scan_history.purge_scan",
    "routers.scan_history.archive_scan",
    "routers.scan_history.restore_scan",
    "routers.scan_history.stop_scan",
    "routers.web_scans.cancel_web_scan",
    "routers.web_scans.triage_finding",
    "routers.compliance.delete_control_evidence",
    # Matched by the word "scan" in the path, but this is configuration CRUD
    # on one row — it stores which subnets an organisation may scan. It does not
    # start anything. The scope it writes is enforced at dispatch, where the
    # 5/minute limits are.
    "routers.admin_orgs.get_scan_scope",
    "routers.admin_orgs.set_scan_scope",
    # Reads of the caller's own tenant data. Listing is not generation — the
    # upload that creates these rows is limited, the file download is
    # allowlisted below, and this returns metadata.
    "routers.compliance.list_control_evidence",
    "routers.compliance.list_scan_runs",
    "routers.compliance.get_scan_run",
    "routers.compliance.list_remediation_requests",
    "routers.web_scans.list_web_scans",
    "routers.web_scans.get_web_scan",
    "routers.web_scans.get_web_scan_assets",
    "routers.web_scans.get_web_scan_findings",
    # The attack-surface reads of one scan the caller already owns. Each returns
    # rows a completed scan persisted (parameters, forms, API operations) or a
    # single stored screenshot file — bounded by that scan's data, paginated,
    # permission-gated, and generating nothing. Same rationale as the two above.
    "routers.web_scans.get_web_scan_parameters",
    "routers.web_scans.get_web_scan_forms",
    "routers.web_scans.get_web_scan_api_operations",
    "routers.web_scans.get_finding_screenshot",
    "routers.scan_history.list_scans",
    "routers.scan_history.get_scan",
    "routers.dashboard.get_scan_activity",
    "routers.dashboard.get_web_scan_summary",
    "routers.dashboard.get_web_scan_trends",
    "routers.topology.get_topology_map_by_scan",
    "routers.compliance.download_control_evidence",
    # Polled by the SPA for the duration of a scan. A limit tight enough to
    # matter would break the progress display; a limit loose enough not to
    # would measure nothing.
    "routers.scan_progress.get_scan_progress",
    "routers.phase_scans.get_scan_quota",
    # One long-lived SSE connection rather than a stream of requests, so a
    # per-request ceiling does not describe it. Bounded by limit_conn in nginx.
    "routers.scan_history.stream_scan_history",
    # Administrative, idempotent, and bounded by the size of the shipped
    # catalogue rather than by anything the caller supplies.
    "routers.compliance.install_marketplace_framework",
    "routers.compliance.uninstall_marketplace_framework",
    "routers.compliance.approve_remediation_request",
    "routers.compliance.cancel_remediation_request",
    "routers.compliance.rollback_remediation_request",
    # Feed synchronisation. Superadmin-only, and the sync scripts hold their
    # own advisory lock, so a second concurrent call returns rather than
    # starting a second sync.
    "routers.admin_nvd.trigger_nvd_sync",
    "routers.admin_nvd.get_sync_status",
}

# Paths whose cost is not proportional to the request: they dispatch work to a
# worker, reach out over the network, or render a document synchronously.
SENSITIVE_PATH_WORDS = (
    "scan",
    "report",
    "export",
    "import",
    "sync",
    "remediat",
    "evidence",
    "install",
)


def _dependency_names(dependant, seen=None):
    names = set()
    seen = seen if seen is not None else set()
    if id(dependant) in seen:
        return names
    seen.add(id(dependant))
    call = getattr(dependant, "call", None)
    if call is not None:
        names.add(getattr(call, "__name__", ""))
    for sub in getattr(dependant, "dependencies", []) or []:
        names |= _dependency_names(sub, seen)
    return names


@pytest.fixture(scope="module")
def inventory():
    from main import app
    from scan_helpers import limiter

    registry = limiter._route_limits
    rows = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        key = f"{route.endpoint.__module__}.{route.endpoint.__name__}"
        methods = {m for m in route.methods if m not in {"HEAD", "OPTIONS"}}
        rows.append(
            {
                "key": key,
                "path": route.path,
                "methods": methods,
                "authenticated": bool(
                    _dependency_names(route.dependant) & AUTH_MARKERS
                ),
                "limited": bool(registry.get(key)),
            }
        )
    return rows


def test_every_unauthenticated_route_has_a_limit_or_a_recorded_reason(inventory):
    """
    An unauthenticated route is reachable by anyone who can reach the port, so
    it is the only thing standing between the internet and whatever it does.
    """
    offenders = sorted(
        f"{'/'.join(sorted(r['methods']))} {r['path']}  ({r['key']})"
        for r in inventory
        if not r["authenticated"]
        and not r["limited"]
        and r["key"] not in UNAUTHENTICATED_WITHOUT_LIMIT
    )
    assert not offenders, (
        "Unauthenticated route with no rate limit and no recorded decision:\n  "
        + "\n  ".join(offenders)
        + "\n\nAdd @limiter.limit(...), or add the handler to "
        "UNAUTHENTICATED_WITHOUT_LIMIT in this file with a reason."
    )


def test_every_expensive_route_has_a_limit_or_a_recorded_reason(inventory):
    """
    The endpoints whose cost is not proportional to the request: scan dispatch,
    report rendering, feed sync, remediation against a live host.

    A permission check bounds *who* can call these. It does not bound how often,
    and the accounts that hold `compliance:export_report` or `scans:execute` are
    exactly the ones whose credentials are worth stealing.
    """
    offenders = sorted(
        f"{'/'.join(sorted(r['methods']))} {r['path']}  ({r['key']})"
        for r in inventory
        if not r["limited"]
        and r["key"] not in SENSITIVE_WITHOUT_LIMIT
        and any(word in r["path"].lower() for word in SENSITIVE_PATH_WORDS)
    )
    assert not offenders, (
        "Expensive route with no rate limit and no recorded decision:\n  "
        + "\n  ".join(offenders)
        + "\n\nAdd @limiter.limit(...), or add the handler to "
        "SENSITIVE_WITHOUT_LIMIT in this file with a reason."
    )


def test_scan_dispatch_routes_are_all_limited_together(inventory):
    """
    Every route that starts a scan sends packets at a target the caller named,
    from this host's address. `POST /web-scans` was the one that had no limit
    while its eight siblings all carried 5/minute — the kind of gap that opens
    when a limit is a per-route decoration rather than a property of a class of
    endpoint.
    """
    dispatch = {
        "routers.traditional_scans.scan_host",
        "routers.traditional_scans.scan_range",
        "routers.traditional_scans.scan_subnet",
        "routers.traditional_scans.scan_subnets",
        "routers.phase_scans.scan_host_discovery",
        "routers.phase_scans.scan_asset_discovery",
        "routers.phase_scans.scan_vulnerability_audit",
        "routers.phase_scans.scan_phases",
        "routers.credentialed.scan_credentialed",
        "routers.web_scans.start_web_scan",
        "routers.compliance.trigger_compliance_scan",
    }
    by_key = {r["key"]: r for r in inventory}
    missing = sorted(k for k in dispatch if not by_key.get(k, {}).get("limited"))
    assert not missing, f"scan-dispatch routes with no limit: {missing}"


def test_allowlists_do_not_name_routes_that_no_longer_exist(inventory):
    """
    A stale allowlist entry is worse than none: it reads as a decision somebody
    made about a live route, and it silently stops covering anything.
    """
    keys = {r["key"] for r in inventory}
    stale = sorted((UNAUTHENTICATED_WITHOUT_LIMIT | SENSITIVE_WITHOUT_LIMIT) - keys)
    assert not stale, f"allowlist names handlers that no longer exist: {stale}"

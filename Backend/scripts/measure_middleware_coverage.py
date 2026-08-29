"""
scripts/measure_middleware_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-09 coverage — authenticated application and middleware
configuration assessment.

    python -m scripts.measure_middleware_coverage

Run before and after a change to get a comparable number.

What this denominator covers, and what it deliberately does not
──────────────────────────────────────────────────────────────
**Reading a middleware product's own configuration on a host we hold a
credential for**, and judging it against an expected state. nginx, Apache
httpd, Tomcat and the Docker daemon.

It does **not** cover the *unauthenticated web surface* — missing security
headers, dangerous HTTP methods, directory listing observed over the wire,
server version disclosure in a banner, insecure cookie flags, sensitive paths,
TLS protocol and cipher assessment. Every one of those is already implemented
and already counted in **GAP-06**, which promoted them from the network probes
and validated them against real targets. Counting them again here would be
double-counting, and double-counting is how a coverage figure stops meaning
anything.

That boundary is narrower than it first looks, and it is worth stating exactly
where it falls. GAP-06 answers "what does this server *show* an anonymous
client". GAP-09 answers "what does this server's configuration *say*". The two
diverge in one direction that matters — a setting the network cannot observe
because nothing links to the path it governs, or because the behaviour only
appears under conditions a scanner does not create — and they agree in the
other. Where they would agree, GAP-06 owns it and this denominator excludes it.

So the honest before-figure is **~3%**, not the matrix's "5% [estimated]": the
only thing here that existed before this phase is the ability to *detect that
the middleware is installed at all*, through the Phase 3 ``package`` and
``service`` collectors.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Twelve of the thirty-six areas below are real Nessus middleware-audit checks
this build does **not** perform. Six of them are IIS, which needs a Windows
Server target that is not available in this environment; this programme does
not ship an engine it has not validated against, so IIS is declared and left
unimplemented rather than written blind. The rest each carry their own reason.

A coverage figure is only worth reading if it can go down.

Three things are counted separately and must never be conflated
──────────────────────────────────────────────────────────────
``implemented``   a check exists and the engine can execute it
``tested``        an automated test names the area and exercises it
``validated``     it has produced a correct result against a real service

**The headline coverage figure is implemented *and* tested.** Product breadth —
how many of the four middleware products answer a given area — is reported
separately and is never folded into the headline: an area answered on one
product is implemented, and answering it on three does not make it three areas.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: The middleware products this phase set out to support.
SUPPORTED_PRODUCTS: Tuple[str, ...] = ("nginx", "apache", "tomcat", "docker")

RESERVED_PRODUCTS: Tuple[Tuple[str, str]] = (
    (
        "iis",
        "needs a Windows Server target to validate against; none available here",
    ),
)

#: (area id, theme, description). Frozen at the start of Phase 8 and not to be
#: edited to match what was built.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Information disclosure ───────────────────────────────────────────────
    ("mw.disclosure.version_tokens", "disclosure", "Product version in responses"),
    ("mw.disclosure.error_detail", "disclosure", "Stack traces / detailed errors"),
    ("mw.disclosure.status_endpoint", "disclosure", "Status/info handler exposed"),
    ("mw.disclosure.default_content", "disclosure", "Default or example content"),
    # ── Access control & authorisation ───────────────────────────────────────
    ("mw.access.override_files", "access", "Per-directory override files honoured"),
    ("mw.access.default_accounts", "access", "Default or weak built-in accounts"),
    ("mw.access.admin_interface", "access", "Management interface enabled"),
    ("mw.access.path_restrictions", "access", "Default deny on the filesystem root"),
    # ── Process & privilege ──────────────────────────────────────────────────
    ("mw.process.run_as_user", "process", "Runs as an unprivileged account"),
    ("mw.process.file_ownership", "process", "Config owned by the right account"),
    ("mw.process.file_permissions", "process", "Config not world-readable"),
    ("mw.process.privilege_flags", "process", "No-new-privileges / capability drop"),
    # ── Transport security ───────────────────────────────────────────────────
    ("mw.tls.protocols_configured", "tls", "Configured TLS protocol floor"),
    ("mw.tls.ciphers_configured", "tls", "Configured cipher policy"),
    ("mw.tls.server_preference", "tls", "Server cipher preference honoured"),
    ("mw.tls.session_tickets", "tls", "Session ticket / resumption policy"),
    ("mw.tls.daemon_socket", "tls", "Management socket requires TLS"),
    # ── Logging & audit ──────────────────────────────────────────────────────
    ("mw.log.access_log", "logging", "Access logging enabled"),
    ("mw.log.error_log", "logging", "Error logging enabled"),
    ("mw.log.log_level", "logging", "Error log verbosity adequate"),
    ("mw.log.driver_configured", "logging", "Container log driver configured"),
    # ── Resource & denial-of-service hardening ───────────────────────────────
    ("mw.limits.request_body", "limits", "Request body size bounded"),
    ("mw.limits.timeouts", "limits", "Request and keep-alive timeouts set"),
    ("mw.limits.connection_limits", "limits", "Worker / connection limits set"),
    ("mw.limits.ulimits", "limits", "Default resource limits set"),
    # ── Network exposure ─────────────────────────────────────────────────────
    ("mw.exposure.management_port", "exposure", "Management port bound narrowly"),
    ("mw.exposure.daemon_socket_tcp", "exposure", "Daemon socket over TCP"),
    ("mw.exposure.inter_container", "exposure", "Unrestricted inter-container traffic"),
    ("mw.exposure.insecure_registry", "exposure", "Insecure registries configured"),
    # ── Currency ─────────────────────────────────────────────────────────────
    ("mw.version.supported_release", "currency", "Running a supported release"),
    # ── IIS — declared, not implemented ──────────────────────────────────────
    ("mw.iis.request_filtering", "iis", "IIS request filtering configured"),
    ("mw.iis.directory_browsing", "iis", "IIS directory browsing disabled"),
    ("mw.iis.app_pool_identity", "iis", "IIS application pool identity"),
    ("mw.iis.tls_configuration", "iis", "IIS TLS/schannel configuration"),
    ("mw.iis.logging", "iis", "IIS logging configured"),
    ("mw.iis.default_documents", "iis", "IIS default site and documents removed"),
)

#: Areas inside the denominator that this phase did not set out to implement,
#: each with the reason. Declared so the gap between "in scope" and "built" is a
#: recorded decision rather than something a reader has to infer.
NOT_PLANNED: Dict[str, str] = {
    "mw.iis.request_filtering": "IIS needs a Windows Server target; none available",
    "mw.iis.directory_browsing": "IIS needs a Windows Server target; none available",
    "mw.iis.app_pool_identity": "IIS needs a Windows Server target; none available",
    "mw.iis.tls_configuration": "IIS needs a Windows Server target; none available",
    "mw.iis.logging": "IIS needs a Windows Server target; none available",
    "mw.iis.default_documents": "IIS needs a Windows Server target; none available",
    "mw.disclosure.error_detail": (
        "the observable is what an anonymous client is shown, which is a "
        "network probe and belongs to GAP-06; the configuration side differs "
        "per application framework rather than per middleware product"
    ),
    "mw.tls.session_tickets": (
        "the security argument depends on key rotation the configuration does "
        "not express, so a verdict from the setting alone would be an opinion "
        "rather than a finding"
    ),
    "mw.limits.connection_limits": (
        "worker and connection counts are sizing decisions with no defensible "
        "expected value; a rule asserting one would fail on correctly tuned "
        "servers"
    ),
    "mw.process.file_ownership": (
        "answered already by the Phase 3 permission collector and the Phase 5 "
        "privilege probes; a middleware-specific rule would report one "
        "condition twice"
    ),
    "mw.version.supported_release": (
        "no middleware here publishes its version through the configuration "
        "file; reading it needs the package collector, which is GAP-03's path, "
        "and the network banner, which is GAP-06's"
    ),
    "mw.access.path_restrictions": (
        "Apache expresses this as a <Directory /> container with Require "
        "all denied, which needs container-aware evaluation rather than a "
        "directive read; deferred with the nested-scope work"
    ),
}

#: Named so the exclusion is visible rather than silent.
OUT_OF_SCOPE = (
    "missing security headers observed over the wire — GAP-06",
    "dangerous HTTP methods observed over the wire — GAP-06",
    "directory listing observed over the wire — GAP-06",
    "server version disclosure in a live banner — GAP-06",
    "insecure cookie flags — GAP-06",
    "TLS protocol, cipher and certificate assessment of a live endpoint — GAP-06",
    "web application testing (/web-scans: ffuf, sqlmap, nuclei)",
    "the host operating system underneath the middleware — GAP-03",
    "container image vulnerability scanning — GAP-17",
)


def _implemented() -> Dict[str, object]:
    """Areas with a built-in check the engine can execute."""
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception as exc:  # pragma: no cover - import guard
        print(f"could not import the built-in checks: {exc}")
        return {}
    found: Dict[str, object] = {}
    for check in BUILTIN_CHECKS:
        area = str(check.metadata.get("gap09_area") or "")
        if area:
            found.setdefault(area, check)
    return found


def _products_per_area() -> Dict[str, Set[str]]:
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS
    except Exception:  # pragma: no cover - import guard
        return {}
    by_area: Dict[str, Set[str]] = {}
    for check in BUILTIN_CHECKS:
        area = str(check.metadata.get("gap09_area") or "")
        product = str(check.metadata.get("middleware") or "")
        if area and product:
            by_area.setdefault(area, set()).add(product)
    return by_area


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources rather than from a hand-maintained list — a list
    would keep saying "tested" for as long as nobody updated it, which is
    precisely the failure a coverage figure must not have.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for path in root.rglob("test_middleware*.py"):
        corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    products = _products_per_area()

    print("=" * 78)
    print("GAP-09 — APPLICATION / MIDDLEWARE CONFIGURATION COVERAGE")
    print("=" * 78)
    print(f"\n{'area':34} {'theme':11} {'impl':5} {'test':5} {'products':22}")
    print("-" * 78)

    by_theme: Dict[str, List[bool]] = {}
    for area, theme, _description in SCOPE:
        has = area in implemented
        has_test = area in tested
        by_theme.setdefault(theme, []).append(has and has_test)
        covered = sorted(products.get(area, set()))
        marker = "" if has else ("  (not planned)" if area in NOT_PLANNED else "")
        print(
            f"{area:34} {theme:11} {'yes' if has else 'NO':5} "
            f"{'yes' if has_test else 'NO':5} "
            f"{','.join(covered) if covered else '-':22}{marker}"
        )

    total = len(SCOPE)
    done = sum(1 for area, _t, _d in SCOPE if area in implemented)
    proven = sum(1 for area, _t, _d in SCOPE if area in implemented and area in tested)

    print("-" * 78)
    for theme, flags in by_theme.items():
        print(
            f"  {theme:11} proven: {sum(flags)}/{len(flags)} "
            f"({round(100.0 * sum(flags) / len(flags), 1)}%)"
        )

    print(
        f"\n  implemented          : {done}/{total} = "
        f"{round(100.0 * done / total, 1)}%"
    )
    print(
        f"  implemented + tested : {proven}/{total} = "
        f"**{round(100.0 * proven / total, 1)}%**   <- GAP-09 coverage"
    )
    print("  real-target validated: reported separately, never folded in")

    if done != proven:
        print(
            f"\n  {done - proven} area(s) have a check no automated test names. "
            f"Implemented is not proven, and only proven counts."
        )

    unplanned_but_built = sorted(set(implemented) & set(NOT_PLANNED))
    if unplanned_but_built:
        print(
            f"\n  NOTE: {len(unplanned_but_built)} area(s) marked not-planned "
            f"were built after all: {unplanned_but_built}"
        )
        print("  Update NOT_PLANNED — a stale reason is worse than none.")

    orphans = sorted(set(implemented) - {a for a, _t, _d in SCOPE})
    if orphans:
        print(
            f"\n  WARNING: {len(orphans)} check(s) claim a gap09_area outside "
            f"the scope: {orphans}"
        )
        print("  The denominator is fixed; an area outside it counts for nothing.")

    print("\n  Not implemented, with the reason recorded:")
    for area in sorted(NOT_PLANNED):
        if area not in implemented:
            print(f"    - {area}: {NOT_PLANNED[area]}")

    print("\n  Deliberately out of scope (not in the denominator):")
    for item in OUT_OF_SCOPE:
        print(f"    - {item}")

    print("\n" + "-" * 78)
    print("PRODUCT BREADTH — reported separately, never folded into the headline")
    per_product: Dict[str, int] = {}
    try:
        from core.config_audit.builtin import BUILTIN_CHECKS

        for check in BUILTIN_CHECKS:
            product = str(check.metadata.get("middleware") or "")
            if product:
                per_product[product] = per_product.get(product, 0) + 1
    except Exception as exc:  # pragma: no cover
        print(f"  (could not measure product breadth: {exc})")

    for product in SUPPORTED_PRODUCTS:
        areas_here = sum(1 for _a, p in products.items() if product in p)
        print(
            f"  {product:10} checks: {per_product.get(product, 0):3}   "
            f"areas answered: {areas_here}/{len(SCOPE)}"
        )
    for product, reason in RESERVED_PRODUCTS:
        print(f"  {product:10} not implemented — {reason}")

    print("\n" + "-" * 78)
    print("SUPPORTING MEASUREMENTS")
    try:
        from core.config_audit.collectors import collector_registry

        for platform in ("linux", "windows"):
            types = collector_registry.supported_check_types(platform)
            print(f"  check types on {platform:8}: {len(types)}  {types}")
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the collector registry: {exc})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

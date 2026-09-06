"""
scripts/measure_export_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-15 coverage — reporting and export expansion.

    python -m scripts.measure_export_coverage

Run before and after a change to get a comparable number.

What this denominator covers
────────────────────────────
**Getting assessment results out of the product in a form somebody else can
use.** The product now holds 955 benchmark rules, a finding lifecycle, an
immutable policy snapshot per scan and a remediation workflow; almost none of
that was reachable except by reading a PDF.

It deliberately does not cover:

* **What is assessed.** Every capability gap that produces the data — the
  benchmarks, the SCAP reader, the credentialed transports — is measured by its
  own phase's denominator. An export cannot improve the assessment.
* **The compliance framework reports.** Thirteen `/compliance/reports/*`
  endpoints already render PDF and DOCX per framework, and they are a
  governance deliverable rather than a data export. They are counted here only
  as "already exists", never as new capability.
* **Dashboards and the UI.** Rendering a number on a screen is not an export.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Several of the forty-four areas below are real export capability this build
does **not** have, each with its reason recorded before the work started. A
coverage figure is only worth reading if it can go down, and a denominator
edited afterwards to match what was built measures nothing at all.

Three things counted separately and never conflated
───────────────────────────────────────────────────
``implemented``   the capability exists and something in the product reads it
``tested``        an automated test names the area and exercises it
``validated``     it has been driven end to end against a real target

**The headline coverage figure is implemented *and* tested.**

The starting figure, and why it is 50%
──────────────────────────────────────
The gap matrix carried "50% [measured]", which is roughly right and worth
saying precisely. What already existed: an executive PDF, a technical PDF, a
findings CSV with full provenance columns, a suppressed-candidate sidecar CSV,
a host-inventory CSV, thirteen compliance framework PDFs, a DOCX Statement of
Applicability, an audit-log export, RBAC on every one of them, tenant scoping,
a rate limit and an audit entry per download. That is a great deal, and it is
why this gap was never Critical.

What none of it had was a *machine-readable* form of the thing the last five
phases produced. 955 benchmark verdicts existed only as prose inside a PDF, or
as `compliance_findings` rows whose status vocabulary cannot express ERROR at
all. There was no XLSX generator anywhere in the tree, and `?fmt=XLSX` was a
400. The findings CSV predates GAP-12, GAP-13 and GAP-14 and carries none of
their columns.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: (area id, theme, description). Frozen at the start of Phase 19 and not to be
#: edited to match what was built.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Formats the product can emit ─────────────────────────────────────────
    ("exp.fmt.pdf_exec", "format", "Executive PDF"),
    ("exp.fmt.pdf_tech", "format", "Technical PDF"),
    ("exp.fmt.csv_findings", "format", "Findings CSV"),
    ("exp.fmt.csv_hosts", "format", "Host-inventory CSV"),
    ("exp.fmt.csv_suppressed", "format", "Suppressed-candidate CSV sidecar"),
    ("exp.fmt.compliance_docs", "format", "Compliance framework PDF/DOCX"),
    ("exp.fmt.xlsx", "format", "Real XLSX workbook"),
    ("exp.fmt.json", "format", "Structured JSON export"),
    ("exp.fmt.sarif", "format", "SARIF for code-scanning pipelines"),
    ("exp.fmt.stix", "format", "STIX / TAXII threat-intel exchange"),
    # ── Compliance and benchmark verdict export ──────────────────────────────
    ("exp.comp.verdicts", "compliance", "Per-check benchmark verdicts exported"),
    ("exp.comp.states", "compliance", "PASS/FAIL/NA/ERROR/MANUAL kept distinct"),
    ("exp.comp.not_assessed", "compliance", "Selected-but-unassessed reported"),
    ("exp.comp.control_map", "compliance", "Framework and control id per row"),
    ("exp.comp.profile", "compliance", "Benchmark profile recorded"),
    ("exp.comp.evidence", "compliance", "Expected / observed / raw evidence"),
    ("exp.comp.remediation", "compliance", "Remediation text per verdict"),
    ("exp.comp.applicability", "compliance", "Why a check did not apply"),
    ("exp.comp.scan_context", "compliance", "Scan, asset, organisation, time"),
    ("exp.comp.attestation", "compliance", "Manual attestation state per control"),
    # ── Findings export ──────────────────────────────────────────────────────
    ("exp.find.core", "findings", "Identity, severity, status, evidence"),
    ("exp.find.definition_type", "findings", "CVE vs config vs privilege check"),
    ("exp.find.lifecycle", "findings", "First found, last found, fixed"),
    ("exp.find.compat", "findings", "Existing CSV consumers unbroken"),
    ("exp.find.remediation_state", "findings", "GAP-14 remediation state"),
    ("exp.find.owner", "findings", "Remediation owner"),
    ("exp.find.sla", "findings", "SLA due date and overdue state"),
    ("exp.find.verification", "findings", "Verified-fixed provenance"),
    ("exp.find.risk_acceptance", "findings", "Accepted risk and expiry"),
    ("exp.find.policy_context", "findings", "GAP-12 policy the scan ran under"),
    # ── Scan comparison export ───────────────────────────────────────────────
    ("exp.cmp.classes", "comparison", "NEW/STILL_OPEN/FIXED/REAPPEARED/NOT_ASSESSED"),
    ("exp.cmp.baseline", "comparison", "Baseline scan named in the export"),
    ("exp.cmp.reuse", "comparison", "Reuses GAP-13, no second comparison"),
    # ── API surface ──────────────────────────────────────────────────────────
    ("exp.api.format_param", "api", "Format selected by parameter"),
    ("exp.api.no_silent_fallback", "api", "Unsupported format refused, not swapped"),
    ("exp.api.filters", "api", "Scan / asset / framework / severity / verdict"),
    ("exp.api.rbac", "api", "Permission enforced on every export"),
    ("exp.api.tenant_isolation", "api", "No cross-organisation export"),
    ("exp.api.rate_limit", "api", "Export routes are bounded"),
    ("exp.api.audit", "api", "An export leaving the platform is audited"),
    ("exp.api.async_jobs", "api", "Asynchronous export job queue"),
    ("exp.api.delivery", "api", "Scheduled delivery by email or webhook"),
    # ── Spreadsheet and file quality ─────────────────────────────────────────
    ("exp.xl.formula_injection", "quality", "Untrusted text cannot become a formula"),
    ("exp.xl.large", "quality", "Large result sets stream rather than accumulate"),
)

#: Areas inside the denominator this phase did not set out to implement, each
#: with the reason. Written before implementation, alongside the scope.
NOT_PLANNED: Dict[str, str] = {
    "exp.fmt.sarif": (
        "SARIF describes findings against source code locations — a file, a "
        "line, a region. This product assesses hosts, services and "
        "configuration, and has no source location to put in the one field "
        "SARIF is built around. Emitting it would mean inventing artifact URIs "
        "that point at nothing"
    ),
    "exp.fmt.stix": (
        "STIX exchanges threat intelligence — indicators, actors, campaigns. "
        "A host's benchmark verdict is not intelligence about an adversary, "
        "and the CVE enrichment this product consumes is already published as "
        "STIX by the feeds it comes from. Exporting it back adds a hop"
    ),
    "exp.comp.attestation": (
        "manual attestation lives in `compliance_findings` with its own "
        "reviewer, justification and next-review date, and is exported by the "
        "Statement of Applicability that ISO clause 6.1.3(d) requires. Folding "
        "it into a scan-scoped verdict export would put a governance decision "
        "beside a machine reading and imply the scan established it"
    ),
    "exp.api.async_jobs": (
        "a job queue, a status endpoint and an artefact store are a feature in "
        "their own right, and the measured cost of the largest export "
        "available here does not need one. Building it speculatively would add "
        "an asynchronous failure mode to a path that currently has none"
    ),
    "exp.api.delivery": (
        "scheduled delivery is a connector surface — SMTP or a webhook, with "
        "its own credentials, retry policy and audit questions. It belongs "
        "with whatever adds integrations, not with the exporter"
    ),
}

#: Named so nobody counts them, in either direction.
OUT_OF_SCOPE: Tuple[str, ...] = (
    "What is assessed — every capability that produces the data is measured by "
    "its own phase's denominator; an export cannot improve an assessment",
    "The thirteen compliance framework report endpoints — a governance "
    "deliverable that already exists, counted as existing and never as new",
    "Dashboards and the frontend — rendering a number on a screen is not an " "export",
    "The audit-log export (reporting/audit_export.py) — tamper-evidence "
    "artefacts with their own retention and approval rules",
)


def _implemented() -> Set[str]:
    """
    Areas the product actually answers, derived from the code rather than
    declared in a list here.

    A hand-maintained list would keep saying "implemented" for as long as
    nobody updated it, which is the one thing a coverage figure must not do.
    """
    found: Set[str] = set()

    # 1. Format emitters, probed as real callables.
    emitters = {
        "exp.fmt.pdf_exec": ("reporting.pdf_generator", "ScanReportGenerator"),
        "exp.fmt.pdf_tech": ("reporting.pdf_generator", "ScanReportGenerator"),
        "exp.fmt.csv_findings": ("reporting.csv_generator", "generate_scan_csv"),
        "exp.fmt.csv_hosts": (
            "reporting.csv_generator",
            "generate_host_inventory_csv",
        ),
        "exp.fmt.csv_suppressed": ("reporting.csv_generator", "suppressed_csv_path"),
        "exp.fmt.xlsx": ("reporting.xlsx_generator", "write_workbook"),
        "exp.fmt.json": ("reporting.exports", "export_payload"),
        "exp.xl.formula_injection": ("reporting.xlsx_generator", "sanitize_cell"),
        "exp.xl.large": ("reporting.xlsx_generator", "WRITE_ONLY"),
        "exp.comp.verdicts": ("reporting.exports", "compliance_verdict_rows"),
        "exp.comp.not_assessed": ("reporting.exports", "compliance_verdict_rows"),
        "exp.comp.control_map": ("reporting.exports", "control_map_for_checks"),
        "exp.find.core": ("reporting.exports", "finding_export_rows"),
        "exp.find.compat": ("reporting.csv_generator", "NETWORK_HEADERS"),
        "exp.cmp.reuse": ("reporting.exports", "comparison_export_rows"),
        "exp.api.audit": ("routers.reports", "_audit_report_download"),
    }
    for area, (module_name, attr) in emitters.items():
        try:
            module = __import__(module_name, fromlist=[attr])
            if getattr(module, attr, None) is not None:
                found.add(area)
        except Exception:
            continue

    # The compliance framework reports are a router surface rather than a
    # module: count them from the routes that actually exist.
    try:
        from routers.compliance import router as compliance_router

        if any(
            "/reports/" in str(getattr(r, "path", "")) for r in compliance_router.routes
        ):
            found.add("exp.fmt.compliance_docs")
    except Exception:
        pass

    # 2. Column surfaces. An export area is implemented when the column that
    #    carries it is actually emitted, read from the header lists themselves
    #    so a removed column loses its credit.
    try:
        from reporting import exports as _exports

        columns = set()
        for name in dir(_exports):
            if name.endswith("_COLUMNS") or name.endswith("_HEADERS"):
                value = getattr(_exports, name)
                if isinstance(value, (list, tuple)):
                    columns |= {str(c).strip().lower() for c in value}

        column_areas = {
            "exp.comp.states": "verdict",
            "exp.comp.profile": "profile",
            "exp.comp.evidence": "observed",
            "exp.comp.remediation": "remediation",
            "exp.comp.applicability": "applicability",
            "exp.comp.scan_context": "scan id",
            "exp.find.definition_type": "definition type",
            "exp.find.lifecycle": "first found",
            "exp.find.remediation_state": "remediation state",
            "exp.find.owner": "remediation owner",
            "exp.find.sla": "sla due",
            "exp.find.verification": "verified at",
            "exp.find.risk_acceptance": "risk accepted at",
            "exp.find.policy_context": "policy name",
            "exp.cmp.classes": "change",
            "exp.cmp.baseline": "baseline scan id",
        }
        for area, column in column_areas.items():
            if any(column in c for c in columns):
                found.add(area)
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the export column surfaces: {exc})")

    # 3. Routes and the guarantees the route layer owns.
    try:
        from routers.reports import ROUTE_AREAS, router as reports_router

        paths = {
            (r.path, frozenset(getattr(r, "methods", ()) or ()))
            for r in reports_router.routes
        }
        for (path, method), area in ROUTE_AREAS.items():
            if any(path == p and method in m for p, m in paths):
                found.add(area)
    except Exception:
        pass

    try:
        from routers.reports import (  # noqa: F401
            EXPORT_FORMATS,
            _require_reports_read,
            download_report,
            export_scan_dataset,
        )

        found.add("exp.api.format_param")
        found.add("exp.api.no_silent_fallback")
        found.add("exp.api.rbac")
        found.add("exp.api.tenant_isolation")
    except Exception:
        # The pre-phase state: the download route exists and refuses an
        # unknown format, but there is no export route and no format table.
        try:
            from routers.reports import _require_reports_read  # noqa: F401

            found.add("exp.api.rbac")
            found.add("exp.api.tenant_isolation")
            found.add("exp.api.format_param")
            found.add("exp.api.no_silent_fallback")
        except Exception:
            pass

    try:
        from routers.reports import router as reports_router
        from scan_helpers import limiter

        limited = set(getattr(limiter, "_route_limits", {}) or {})
        if any(
            str(getattr(r, "endpoint", None).__name__ if r.endpoint else "") in limited
            or getattr(r, "endpoint", None) is not None
            and f"{r.endpoint.__module__}.{r.endpoint.__qualname__}" in limited
            for r in reports_router.routes
            if getattr(r, "endpoint", None) is not None
        ):
            found.add("exp.api.rate_limit")
        elif limited:
            # slowapi keys by the decorated function's qualified name; fall back
            # to the decorator marker the limiter leaves behind.
            for route in reports_router.routes:
                endpoint = getattr(route, "endpoint", None)
                if endpoint is not None and hasattr(endpoint, "__wrapped__"):
                    found.add("exp.api.rate_limit")
                    break
    except Exception:
        pass

    # 4. Filters: an export that takes them declares them.
    try:
        import inspect

        from routers.reports import export_scan_dataset

        params = set(inspect.signature(export_scan_dataset).parameters)
        if {"asset_id", "severity"} <= params and (
            "framework_id" in params or "verdict" in params
        ):
            found.add("exp.api.filters")
    except Exception:
        pass

    return found


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources, so an area whose test is deleted loses its
    coverage credit.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for pattern in (
        "test_export*.py",
        "test_report*.py",
        "test_csv*.py",
        "test_xlsx*.py",
    ):
        for path in root.rglob(pattern):
            corpus += path.read_text(encoding="utf-8", errors="replace")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    total = len(SCOPE)
    in_scope = {a for a, _t, _d in SCOPE}

    print("=" * 78)
    print("GAP-15 — REPORTING & EXPORT EXPANSION: COVERAGE")
    print("=" * 78)

    theme = None
    for area, area_theme, description in SCOPE:
        if area_theme != theme:
            theme = area_theme
            print(f"\n  [{theme}]")
        impl = "yes" if area in implemented else " - "
        test = "yes" if area in tested else " - "
        print(f"    {area:30} impl={impl}  test={test}  {description}")

    proven = sum(1 for a, _t, _d in SCOPE if a in implemented and a in tested)
    print("\n" + "-" * 78)
    print(f"  implemented          : {len(implemented & in_scope)}/{total}")
    print(f"  tested               : {len(tested)}/{total}")
    print(
        f"  implemented + tested : {proven}/{total} = "
        f"{100.0 * proven / total:.1f}%   <-- headline"
    )
    print("-" * 78)

    unplanned_but_built = sorted(a for a in NOT_PLANNED if a in implemented)
    if unplanned_but_built:
        print(
            f"\n  NOTE: {len(unplanned_but_built)} area(s) recorded as not "
            f"planned were built after all: {unplanned_but_built}"
        )
        print("  Update NOT_PLANNED — a stale reason is worse than none.")

    orphans = sorted(implemented - in_scope)
    if orphans:
        print(
            f"\n  WARNING: {len(orphans)} area(s) outside the frozen scope: {orphans}"
        )
        print("  The denominator is fixed; an area outside it counts for nothing.")

    missing = [a for a, _t, _d in SCOPE if a not in implemented]
    print("\n  Not implemented:")
    for area in missing:
        reason = NOT_PLANNED.get(area, "NO REASON RECORDED — record one")
        print(f"    - {area}: {reason}")

    print("\n  Deliberately out of scope (not in the denominator):")
    for item in OUT_OF_SCOPE:
        print(f"    - {item}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

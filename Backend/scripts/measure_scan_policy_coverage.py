"""
scripts/measure_scan_policy_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-12 coverage — the configurable scan policy engine.

    python -m scripts.measure_scan_policy_coverage

Run before and after a change to get a comparable number.

What this denominator covers
────────────────────────────
**A reusable, named, versioned assessment configuration that decides what a
scan actually assesses, survives into the historical record of the scan it
drove, and is visible to an auditor reading the report.**

Three things it deliberately does not cover, because they are other gaps:

* **Remediation and SLA policy** — how long a finding may stay open, who is
  accountable, what the escalation is. That is GAP-14 and has its own model.
* **Notification and alerting policy.** Follows the finding, not the scan.
* **Agent / distributed scanner policy.** GAP-18. A policy that names a
  scanner pool is meaningless until there is a pool.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Several of the thirty-nine areas below are real scan-policy capability this
build does **not** have. Each carries its reason. A coverage figure is only
worth reading if it can go down, and a denominator edited afterwards to match
what was built measures nothing at all.

Three things counted separately and never conflated
───────────────────────────────────────────────────
``implemented``   the capability exists and something in the product reads it
``tested``        an automated test names the area and exercises it
``validated``     it has changed a real scan's behaviour against a real target

**The headline coverage figure is implemented *and* tested.**

The starting figure, and why it is 20%
──────────────────────────────────────
The gap matrix carried "20% [measured]" before this phase, and re-measuring
against this denominator agrees to within a point: seven of the thirty-nine
areas were already answered by request parameters on the manual scan routes —
port selection, both intensities, target exclusion, sections, concurrency and
the deployment-wide intrusive switch. What none of them were was *reusable*,
*named*, *validated*, *versioned* or *recorded*, which is the whole of the gap.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import Dict, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: (area id, theme, description). Frozen at the start of Phase 17 and not to be
#: edited to match what was built.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── The policy object itself ─────────────────────────────────────────────
    ("pol.crud.create", "lifecycle", "Create a reusable named policy"),
    ("pol.crud.read", "lifecycle", "List and fetch policies"),
    ("pol.crud.update", "lifecycle", "Edit a policy"),
    ("pol.crud.archive", "lifecycle", "Archive or delete a policy safely"),
    ("pol.crud.enable", "lifecycle", "Enable / disable without deleting"),
    ("pol.lifecycle.version", "lifecycle", "Versioned policy family"),
    ("pol.lifecycle.default", "lifecycle", "A per-tenant default policy"),
    ("pol.lifecycle.template", "lifecycle", "Built-in starting templates"),
    ("pol.lifecycle.clone", "lifecycle", "Clone an existing policy"),
    ("pol.lifecycle.import_export", "lifecycle", "Import / export a policy"),
    # ── Authorisation and isolation ──────────────────────────────────────────
    ("pol.authz.rbac", "authz", "RBAC atoms distinct from scans:*"),
    ("pol.authz.tenant", "authz", "Tenant isolation on every lookup"),
    ("pol.authz.audit", "authz", "Policy changes reach the audit trail"),
    # ── What the policy selects ──────────────────────────────────────────────
    ("pol.select.frameworks", "selection", "Benchmark / framework selection"),
    ("pol.select.profile", "selection", "Benchmark profile selection"),
    ("pol.select.families", "selection", "Check family / domain selection"),
    ("pol.select.platforms", "selection", "OS / platform scope"),
    ("pol.select.sections", "selection", "Credentialed assessment sections"),
    ("pol.select.builtin", "selection", "Built-in pack on or off"),
    ("pol.select.network_plugins", "selection", "Network plugin selection"),
    ("pol.select.individual_checks", "selection", "Individual check enable/disable"),
    # ── What the policy filters out ──────────────────────────────────────────
    ("pol.filter.severity", "filter", "Severity threshold on checks"),
    ("pol.filter.check_exclusions", "filter", "Named check exclusions"),
    ("pol.filter.tag_exclusions", "filter", "Tag-based check exclusions"),
    ("pol.filter.target_exclusions", "filter", "Target / address exclusions"),
    # ── How hard the scan works ──────────────────────────────────────────────
    ("pol.depth.ports", "depth", "Port selection and exclusion"),
    ("pol.depth.discovery", "depth", "Host-discovery intensity"),
    ("pol.depth.port_scan", "depth", "Port-scan intensity"),
    ("pol.depth.concurrency", "depth", "Rate limit and concurrency"),
    ("pol.safety.intrusive", "depth", "Intrusive probes per policy"),
    # ── Binding a policy to work ─────────────────────────────────────────────
    ("pol.bind.scan", "binding", "Assign a policy to a direct scan"),
    ("pol.bind.schedule", "binding", "Assign a policy to a schedule"),
    ("pol.bind.credential", "binding", "Credential requirement enforced"),
    ("pol.bind.validation", "binding", "Invalid combinations refused up front"),
    # ── The historical record ────────────────────────────────────────────────
    ("pol.record.snapshot", "record", "Immutable per-scan configuration snapshot"),
    ("pol.record.fingerprint", "record", "Stable identifier for a configuration"),
    ("pol.record.api", "record", "Read a historical scan's effective policy"),
    ("pol.record.report", "record", "Policy visible in the generated report"),
    ("pol.record.comparison", "record", "GAP-13 comparison carries both policies"),
)

#: Areas inside the denominator this phase did not set out to implement, each
#: with the reason. Written before implementation, alongside the scope.
NOT_PLANNED: Dict[str, str] = {
    "pol.lifecycle.template": (
        "a starting template is a seeded policy row, which needs a decision "
        "about whether shipped rows are a tenant's to edit — the same question "
        "the parked compliance catalogues answer differently. Not worth "
        "guessing at inside this phase"
    ),
    "pol.lifecycle.clone": (
        "clone is create-with-a-body the caller already has; it buys a round "
        "trip and needs a rule for what happens to the family code. Deferred "
        "rather than half-answered"
    ),
    "pol.lifecycle.import_export": (
        "a portable policy has to name frameworks and checks that exist in the "
        "importing installation, so it needs a resolution and failure "
        "vocabulary of its own. That is a phase, not a field"
    ),
    "pol.select.individual_checks": (
        "the engine selects by platform, domain, framework, profile and "
        "severity, and excludes by id and by tag. A positive per-check "
        "allow-list over 955 benchmark rules is a UI problem before it is a "
        "backend one, and an allow-list that silently drops a control from a "
        "benchmark score is the failure this programme keeps correcting"
    ),
    "pol.lifecycle.default": (
        "a per-tenant default changes what an existing scan does when nobody "
        "chose anything, which this phase's backward-compatibility rule "
        "forbids. It needs an explicit opt-in that is its own decision"
    ),
    "pol.depth.concurrency": (
        "rate_limit and max_concurrency already reach run_host_discovery_task "
        "from the request. Carrying them on a policy is a real capability, but "
        "they bound the *scanner*, not what is assessed, so they cannot change "
        "a finding — and this phase's rule is that a policy field must change "
        "assessment behaviour or say plainly that it does not"
    ),
    "pol.select.network_plugins": (
        "select_plugins() maps ports to modules and VulnerabilityEngine "
        "dispatches them at a pinned arity. Filtering the module list is "
        "possible; deciding what a 'family' is when one plugin emits findings "
        "for three of them is not, and a wrong answer silently removes checks "
        "from a scan that still reports success"
    ),
}

#: Named so nobody counts them, in either direction.
OUT_OF_SCOPE: Tuple[str, ...] = (
    "Remediation and SLA policy — GAP-14 owns it and has its own model",
    "Notification / alerting policy — follows the finding, not the scan",
    "Agent and distributed-scanner policy — GAP-18; meaningless with no pool",
    "Web-application scan policy — /web-scans has its own configuration surface",
    "Compliance framework scan policy — CompliancePolicy already exists for it",
)


def _implemented() -> Set[str]:
    """
    Areas the product actually answers, derived from the code rather than
    declared in a list here.

    A hand-maintained list would keep saying "implemented" for as long as
    nobody updated it, which is the one thing a coverage figure must not do.
    """
    found: Set[str] = set()

    # 1. Policy fields that reach the scan. Declared beside the field itself.
    try:
        from core.scan_policy.spec import FIELD_AREAS, EffectivePolicy

        live = {f.name for f in dataclasses.fields(EffectivePolicy)}
        for field_name, area in FIELD_AREAS.items():
            if field_name in live:
                found.add(area)
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the policy spec: {exc})")

    # 2. Lifecycle and API areas, from the routes that exist.
    try:
        from routers.scan_policies import ROUTE_AREAS, router

        paths = {
            (r.path, frozenset(getattr(r, "methods", ()) or ())) for r in router.routes
        }
        for (path, method), area in ROUTE_AREAS.items():
            if any(path == p and method in m for p, m in paths):
                found.add(area)
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the policy router: {exc})")

    # 3. Capabilities that are functions rather than fields or routes.
    probes = {
        "pol.record.snapshot": ("core.scan_policy.snapshot", "record_policy_snapshot"),
        "pol.record.fingerprint": ("core.scan_policy.spec", "policy_fingerprint"),
        "pol.bind.validation": ("core.scan_policy.validation", "validate_policy"),
        "pol.record.report": ("reporting.pdf_generator", "_policy_section"),
        "pol.record.comparison": ("core.findings.comparison", "policy_context"),
        "pol.bind.schedule": ("core.scheduling.dispatcher", "_schedule_policy_options"),
        "pol.lifecycle.version": ("core.scan_policy.spec", "next_version_number"),
        "pol.authz.tenant": ("routers.scan_policies", "_get_policy"),
        "pol.authz.audit": ("routers.scan_policies", "_audit_policy_change"),
        "pol.bind.credential": ("core.scan_policy.validation", "assert_credential_ok"),
        "pol.record.api": ("routers.scan_history", "scan_policy_record"),
        "pol.bind.scan": ("scans.policy_binding", "resolve_scan_policy"),
    }
    for area, (module_name, attr) in probes.items():
        try:
            module = __import__(module_name, fromlist=[attr])
            if getattr(module, attr, None) is not None:
                found.add(area)
        except Exception:
            continue

    return found


def _tested() -> Set[str]:
    """
    Areas an automated test names.

    Read from the test sources, so an area whose test is deleted loses its
    coverage credit.
    """
    root = Path(__file__).resolve().parents[1] / "tests"
    corpus = ""
    for pattern in ("test_scan_policy*.py", "test_policy_*.py"):
        for path in root.rglob(pattern):
            corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    total = len(SCOPE)
    in_scope = {a for a, _t, _d in SCOPE}

    print("=" * 78)
    print("GAP-12 — CONFIGURABLE SCAN POLICY ENGINE: COVERAGE")
    print("=" * 78)

    theme = None
    for area, area_theme, description in SCOPE:
        if area_theme != theme:
            theme = area_theme
            print(f"\n  [{theme}]")
        impl = "yes" if area in implemented else " - "
        test = "yes" if area in tested else " - "
        print(f"    {area:32} impl={impl}  test={test}  {description}")

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

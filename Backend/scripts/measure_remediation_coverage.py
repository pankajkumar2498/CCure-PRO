"""
scripts/measure_remediation_coverage.py
─────────────────────────────────────────────────────────────────────────────
Measures GAP-14 coverage — remediation and SLA management.

    python -m scripts.measure_remediation_coverage

Run before and after a change to get a comparable number.

What this denominator covers
────────────────────────────
**The workflow around a finding that already exists**: who owns it, when it is
due, what state its remediation is in, and — the part that makes the rest worth
anything — whether a *subsequent assessment* actually confirmed the fix.

It deliberately does not cover:

* **Automated remediation execution.** Pushing a fix to a host over a
  credential is `ComplianceRemediationRequest`'s maker–checker workflow, which
  already exists. This gap tracks remediation; it does not perform it.
* **Remediation content.** What the fix *is* — the recommendation text, the
  command, the vendor advisory — lives in `ComplianceRemediation` and in
  `AssetVulnerability.vendor_remediation`. Building a second store for it is
  explicitly out of scope.
* **Ticketing integration.** Jira, ServiceNow and email are a connector
  surface, not a lifecycle.

Why the denominator includes things we did not build
────────────────────────────────────────────────────
Several of the thirty-seven areas below are real remediation capability this
build does **not** have, each with its reason. A coverage figure is only worth
reading if it can go down, and a denominator edited afterwards to match what
was built measures nothing at all.

Three things counted separately and never conflated
───────────────────────────────────────────────────
``implemented``   the capability exists and something in the product reads it
``tested``        an automated test names the area and exercises it
``validated``     it has been driven end to end against a real target

**The headline coverage figure is implemented *and* tested.**

The starting figure, and why it is 30%
──────────────────────────────────────
The gap matrix carried "30% [measured]", and re-measuring against this
denominator broadly agrees. What already existed on the security-finding side:
a three-value ``status`` (open/accepted/fixed), ``remediation_notes``,
``fixed_at``, ``accepted_risk_reason`` and ``accepted_by``, an endpoint to set
them, and CISA KEV's externally-mandated ``kev_due_date``. On the compliance
side rather more: ``owner``, ``next_review_at``, ``remediation_applied_by/at``,
a ``pending_reverify`` status and a ``ComplianceFindingHistory`` timeline.

Eleven of thirty-seven is 30%. What none of it had was an SLA, an owner on a
security finding, or any verification that a fix actually happened — the
existing endpoint stamped ``fixed_at`` from a user's click, which is the column
GAP-13 reconstructs its baseline from.
"""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path
from typing import Dict, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

#: (area id, theme, description). Frozen at the start of Phase 18 and not to be
#: edited to match what was built.
SCOPE: Tuple[Tuple[str, str, str], ...] = (
    # ── Ownership ────────────────────────────────────────────────────────────
    ("rem.own.assign", "ownership", "Assign a remediation owner"),
    ("rem.own.reassign", "ownership", "Reassign, with the previous owner kept"),
    ("rem.own.unassign", "ownership", "Clear an owner without losing history"),
    ("rem.own.bulk", "ownership", "Assign many findings in one call"),
    ("rem.own.team", "ownership", "Assign to a team rather than a person"),
    # ── Remediation state ────────────────────────────────────────────────────
    ("rem.state.open", "state", "Open — nothing started"),
    ("rem.state.assigned", "state", "Assigned to an owner"),
    ("rem.state.in_progress", "state", "In remediation"),
    ("rem.state.pending_verification", "state", "Fix claimed, awaiting a scan"),
    ("rem.state.verified", "state", "Verified fixed by an assessment"),
    ("rem.state.reopened", "state", "Reopened after a regression"),
    ("rem.state.risk_accepted", "state", "Accepted risk / exception"),
    ("rem.state.transitions", "state", "Illegal transitions refused"),
    # ── SLA ──────────────────────────────────────────────────────────────────
    ("rem.sla.by_severity", "sla", "Due date derived from severity"),
    ("rem.sla.from_discovery", "sla", "Clock starts at first_found_at"),
    ("rem.sla.no_reset", "sla", "Rediscovery does not reset the clock"),
    ("rem.sla.kev", "sla", "CISA KEV mandated date respected"),
    ("rem.sla.per_tenant", "sla", "Per-organisation SLA configuration"),
    ("rem.sla.within", "sla", "Within-SLA state"),
    ("rem.sla.due_soon", "sla", "Due-soon state"),
    ("rem.sla.overdue", "sla", "Overdue state"),
    ("rem.sla.paused", "sla", "Clock paused while risk is accepted"),
    ("rem.sla.business_days", "sla", "Business-day / calendar-aware SLA"),
    # ── Verification — the part that makes the rest mean anything ────────────
    ("rem.verify.fixed", "verify", "FIXED verdict verifies the remediation"),
    ("rem.verify.not_assessed", "verify", "NOT_ASSESSED must never verify"),
    ("rem.verify.error", "verify", "ERROR / unavailable must never verify"),
    ("rem.verify.reappeared", "verify", "REAPPEARED reopens the remediation"),
    ("rem.verify.scope_mismatch", "verify", "Out-of-scope scan cannot verify"),
    ("rem.verify.no_self_attest", "verify", "A user claim alone cannot verify"),
    # ── Exceptions ───────────────────────────────────────────────────────────
    ("rem.exc.grant", "exception", "Accept risk with reason and approver"),
    ("rem.exc.expiry", "exception", "Expiry returns the finding to remediation"),
    ("rem.exc.audit", "exception", "Exception changes reach the audit trail"),
    # ── Record and reporting ─────────────────────────────────────────────────
    ("rem.rec.history", "record", "Immutable remediation event history"),
    ("rem.rec.notes", "record", "Remediation notes and actions"),
    ("rem.rec.summary_api", "record", "Summary / overdue / pending-verification API"),
    ("rem.rec.report_exec", "record", "Executive report remediation summary"),
    ("rem.rec.report_tech", "record", "Technical report per-finding remediation"),
)

#: Areas inside the denominator this phase did not set out to implement, each
#: with the reason. Written before implementation, alongside the scope.
NOT_PLANNED: Dict[str, str] = {
    "rem.own.team": (
        "there is no team or group entity in this product — RBAC is "
        "organisation plus role, and a finding's owner is a user id. "
        "Inventing a team model here would be a second identity system, which "
        "the brief forbids and which belongs with whatever eventually adds "
        "groups to RBAC"
    ),
    "rem.sla.business_days": (
        "a business-day clock needs a working calendar and a holiday table per "
        "organisation, and getting it wrong makes every due date subtly wrong "
        "rather than visibly absent. Calendar days are stated plainly instead, "
        "so nobody can mistake one for the other"
    ),
    "rem.sla.paused": (
        "pausing the clock during an accepted risk is defensible and so is "
        "letting it run — the second keeps the original due date visible when "
        "the exception expires, which is what an auditor asks for. Recorded as "
        "a deliberate choice rather than implemented both ways"
    ),
}

#: Named so nobody counts them, in either direction.
OUT_OF_SCOPE: Tuple[str, ...] = (
    "Automated remediation execution — ComplianceRemediationRequest already "
    "owns the maker-checker workflow for pushing a fix over a credential",
    "Remediation content — ComplianceRemediation and "
    "AssetVulnerability.vendor_remediation already hold what the fix is",
    "Ticketing integration (Jira, ServiceNow, email) — a connector surface",
    "Compliance control attestation — the ISMS review cycle, already built",
)


def _implemented() -> Set[str]:
    """
    Areas the product actually answers, derived from the code rather than
    declared in a list here.

    A hand-maintained list would keep saying "implemented" for as long as
    nobody updated it, which is the one thing a coverage figure must not do.
    """
    found: Set[str] = set()

    # 1. Remediation states, from the vocabulary the model enforces.
    try:
        from core.remediation.states import STATE_AREAS, REMEDIATION_STATES

        for state, area in STATE_AREAS.items():
            if state in REMEDIATION_STATES:
                found.add(area)
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the remediation states: {exc})")

    # 2. Finding columns that carry the workflow.
    try:
        from db.models.findings import AssetVulnerability
        from core.remediation.states import COLUMN_AREAS

        columns = set(AssetVulnerability.__table__.columns.keys())
        for column, area in COLUMN_AREAS.items():
            if column in columns:
                found.add(area)
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the finding columns: {exc})")

    # 3. Routes.
    try:
        from routers.remediation import ROUTE_AREAS, router

        paths = {
            (r.path, frozenset(getattr(r, "methods", ()) or ())) for r in router.routes
        }
        for (path, method), area in ROUTE_AREAS.items():
            if any(path == p and method in m for p, m in paths):
                found.add(area)
    except Exception as exc:  # pragma: no cover
        print(f"  (could not read the remediation router: {exc})")

    # 4. Capabilities that are functions rather than columns or routes.
    probes = {
        "rem.sla.by_severity": ("core.remediation.sla", "due_at_for"),
        "rem.sla.from_discovery": ("core.remediation.sla", "due_at_for"),
        "rem.sla.no_reset": ("core.remediation.sla", "sla_anchor"),
        "rem.sla.kev": ("core.remediation.sla", "due_at_for"),
        "rem.sla.per_tenant": ("core.remediation.sla", "sla_policy_for_org"),
        "rem.sla.within": ("core.remediation.sla", "sla_state"),
        "rem.sla.due_soon": ("core.remediation.sla", "sla_state"),
        "rem.sla.overdue": ("core.remediation.sla", "sla_state"),
        "rem.verify.fixed": ("core.remediation.verification", "verify_from_comparison"),
        "rem.verify.not_assessed": (
            "core.remediation.verification",
            "verify_from_comparison",
        ),
        "rem.verify.error": ("core.remediation.verification", "verify_from_comparison"),
        "rem.verify.reappeared": (
            "core.remediation.verification",
            "verify_from_comparison",
        ),
        "rem.verify.scope_mismatch": (
            "core.remediation.verification",
            "verify_from_comparison",
        ),
        "rem.verify.no_self_attest": ("core.remediation.workflow", "claim_fixed"),
        "rem.state.transitions": ("core.remediation.states", "assert_transition"),
        "rem.exc.grant": ("core.remediation.workflow", "accept_risk"),
        "rem.exc.expiry": ("core.remediation.workflow", "expire_due_exceptions"),
        "rem.rec.history": ("db.models.findings", "FindingRemediationEvent"),
        "rem.rec.report_exec": ("reporting.pdf_generator", "_remediation_summary_line"),
        "rem.rec.report_tech": ("reporting.pdf_generator", "_remediation_section"),
        "rem.own.assign": ("core.remediation.workflow", "assign_owner"),
        "rem.own.reassign": ("core.remediation.workflow", "assign_owner"),
        "rem.own.unassign": ("core.remediation.workflow", "assign_owner"),
        "rem.exc.audit": ("core.remediation.workflow", "record_event"),
        "rem.rec.notes": ("core.remediation.workflow", "add_note"),
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
    for pattern in ("test_remediation*.py", "test_sla*.py"):
        for path in root.rglob(pattern):
            corpus += path.read_text(encoding="utf-8")
    return {area for area, _t, _d in SCOPE if area in corpus}


def main() -> int:
    implemented = _implemented()
    tested = _tested()
    total = len(SCOPE)
    in_scope = {a for a, _t, _d in SCOPE}

    print("=" * 78)
    print("GAP-14 — REMEDIATION & SLA MANAGEMENT: COVERAGE")
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

"""
core/compliance_catalogue/benchmark_selection.py
─────────────────────────────────────────────────────────────────────────────
Which benchmark checks apply to a scan, resolved from the database.

Compliance's since G4, which moved it unchanged from
``core/benchmarks/selection.py``; that path is an alias of this module.

The Phase 3 engine runs whatever ``ConfigCheck`` list it is handed. Phase 3
handed it the twenty built-in rules. Phase 4 adds the rules a loaded benchmark
wrote into ``compliance_rules``, which is the link that makes
"CIS Benchmark → Control → Rule Engine" real rather than diagrammatic.

Resolved before the scan, not during it
───────────────────────────────────────
``audit_credentialed_host`` opens no database session today and should not
start: it runs on the host worker, against a live target, and adding a session
to it would put a database round trip inside the window a WinRM connection is
held open. So the caller resolves the checks while it has a session and passes
them in.

That also means the checks for *both* platforms are resolved together — the
target's OS is not known until the audit has connected — and the engine's own
platform targeting narrows them. That is the same filter it already applies to
the built-ins, so nothing new decides applicability.

Profile scope
─────────────
``profile=None`` assesses every control the benchmark defines, which is the
honest default: assuming Level 1 would silently drop every Level 2 control
from the score without saying so.

Phase 17 supplies the setting this was written for. ``core/scan_policy``
resolves a scan's ``EffectivePolicy`` and passes ``framework_ids``,
``profile``, ``platforms``, ``min_severity`` and the exclusions here. Nothing
in this module changed shape to accommodate it — the profile and platform
filters were already here and tested.

Every narrowing argument means "no restriction" when empty
──────────────────────────────────────────────────────────
``framework_ids=None`` and ``framework_ids=()`` both resolve **every**
framework the tenant has installed, which is the pre-policy behaviour and
therefore what a policy that says nothing about frameworks must do. Reading an
empty selection as "select nothing" would let an under-specified policy reduce
a scan to zero checks while still reporting success — a clean report on a host
nobody assessed. The same reading applies to ``platforms`` and to the two
exclusion sets.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Sequence

from sqlalchemy.orm import Session

from core.checks.contract import severity_at_least
from core.config_audit.spec import ConfigCheck, SpecError
from db.models.compliance import (
    ComplianceControl,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)

log = logging.getLogger("ccure.benchmarks.selection")

__all__ = ["benchmark_checks_for_org", "benchmark_frameworks_for_org"]


def benchmark_frameworks_for_org(db: Session, org_id: str) -> List[str]:
    """
    Framework ids this tenant has installed and this installation offers.

    Both gates, in the order ``compliance_sync`` applies them and for the same
    reasons — a parked catalogue must not be scored, and a tenant must not
    acquire a score for a benchmark they never installed.
    """
    from core.compliance_frameworks import is_active as is_active_framework

    rows = (
        db.query(ComplianceTenantFramework.framework_id)
        .filter(
            ComplianceTenantFramework.tenant_id == org_id,
            ComplianceTenantFramework.is_enabled.is_(True),
        )
        .all()
    )
    return [r[0] for r in rows if is_active_framework(r[0])]


def benchmark_checks_for_org(
    db: Session,
    org_id: str,
    *,
    profile: Optional[str] = None,
    platforms: Optional[Sequence[str]] = None,
    framework_ids: Optional[Sequence[str]] = None,
    min_severity: Optional[str] = None,
    excluded_check_ids: Optional[Sequence[str]] = None,
    excluded_tags: Optional[Sequence[str]] = None,
) -> List[ConfigCheck]:
    """
    Every executable benchmark check in scope for *org_id*.

    A rule that will not parse back into a ``ConfigCheck`` is **skipped with a
    warning, not raised**: one malformed row in a six-hundred-control benchmark
    must not abort the audit of every other control on the host. The warning
    names the rule so it is fixable, and the control it belongs to then reports
    as unassessed rather than as passing — which is the direction that
    under-claims rather than over-claims.
    """
    installed = benchmark_frameworks_for_org(db, org_id)
    if not installed:
        return []

    # A policy's selection narrows what is installed; it never adds to it. A
    # framework the tenant has not installed cannot be scored by naming it in a
    # policy, and `validate_for_dispatch` has already refused such a policy
    # with a message saying so — this intersection is the second line of that
    # defence, so a caller reaching here directly cannot bypass it.
    if framework_ids:
        wanted = {str(f) for f in framework_ids if f}
        selected = [f for f in installed if f in wanted]
        if not selected:
            log.warning(
                "Policy for org %s selected framework(s) %s, none of which are "
                "installed and active here; no benchmark check resolved",
                org_id,
                sorted(wanted),
            )
            return []
    else:
        selected = installed
    framework_ids = selected

    excluded_ids = {str(c).strip() for c in (excluded_check_ids or []) if c}
    excluded_tag_set = {str(t).strip().lower() for t in (excluded_tags or []) if t}

    query = (
        db.query(ComplianceRule, ComplianceControl)
        .join(ComplianceRuleControl, ComplianceRuleControl.rule_id == ComplianceRule.id)
        .join(
            ComplianceControl,
            ComplianceControl.id == ComplianceRuleControl.control_id,
        )
        .filter(
            ComplianceControl.framework_id.in_(framework_ids),
            ComplianceRule.status == "active",
        )
    )
    if platforms:
        query = query.filter(ComplianceRule.target_platform.in_(list(platforms)))

    checks: List[ConfigCheck] = []
    seen: set[str] = set()
    for rule, control in query.all():
        if rule.id in seen:
            # A rule covering several controls appears once per link. It is one
            # check and must run once, or the host is probed N times and the
            # result counted N times in the score.
            continue
        if not ConfigCheck.is_config_rule(rule):
            continue
        if rule.id in excluded_ids:
            # An exclusion is a decision on the record, not a silent drop: the
            # control it answers for will report as unassessed rather than as
            # passing, which is the direction that under-claims.
            log.debug("Rule %s excluded by policy", rule.id)
            continue
        if profile:
            control_profiles = list(control.profiles or [])
            # An empty profile list means "in scope whatever profile you
            # selected" — the same reading migration c5d6e7f8a9b0 gives the
            # column, so the two cannot disagree.
            if control_profiles and profile not in control_profiles:
                continue
        try:
            check = ConfigCheck.from_rule(rule)
            # Severity and tags are properties of the *check*, not of the rule
            # row, so both filters run after the parse rather than in the query.
            # An unrecognised severity clears every floor — see
            # `core.checks.contract.severity_at_least`: a check whose severity
            # this build does not know has not been established to be below the
            # threshold, and dropping it would remove a check on the strength
            # of a string nobody defined.
            if min_severity and not severity_at_least(check.severity, min_severity):
                continue
            if excluded_tag_set and excluded_tag_set & {t.lower() for t in check.tags}:
                continue
            checks.append(check)
        except (SpecError, ValueError) as exc:
            log.warning(
                "Benchmark rule %s could not be executed and was skipped: %s",
                rule.id,
                exc,
            )
            continue
        seen.add(rule.id)

    log.info(
        "Resolved %d benchmark check(s) for org %s across %d framework(s)",
        len(checks),
        org_id,
        len(framework_ids),
    )
    return checks

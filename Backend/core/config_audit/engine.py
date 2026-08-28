"""
core/config_audit/engine.py
─────────────────────────────────────────────────────────────────────────────
The engine: one pipeline, run once per check per target.

    platform targeting → credential precondition → collector resolution →
    collection → comparison → CheckResult

Everything benchmark-specific lives in the ``ConfigCheck`` records the engine
is handed. There is no CIS, no STIG and no vendor name in this file, and none
should ever appear here: the moment the engine knows what benchmark it is
running, adding the next one means editing it.

The outcome map, and why each arrow points where it does
────────────────────────────────────────────────────────
================================  ==================  ========================
Situation                         Outcome             Why not something else
================================  ==================  ========================
Rule targets another platform     NOT_APPLICABLE      Nothing was assessed and
                                                      nothing needs to be.
Host platform unknown             ERROR               A rule that could not be
                                                      *placed* is not a rule
                                                      that does not apply.
Check needs an account, none      ERROR               The historical bug: ISO
                                                      A.8.2 reported *failed*
                                                      on hosts nobody could
                                                      authenticate to.
No collector for the pair         ERROR               "We cannot do that check"
                                                      is a product gap, not a
                                                      property of the host.
Collector raised                  ERROR               A bug in our code must
                                                      never invent a finding.
Collection UNAVAILABLE            ERROR               The single most important
                                                      arrow in the table.
Collection UNSUPPORTED            NOT_APPLICABLE      Established out of scope.
Collection ABSENT                 rule's policy       Only the rule knows.
Comparison true / false           PASS / FAIL         The verdicts.
Operator unknown                  ERROR               A typo in a rule must not
                                                      manufacture a finding.
================================  ==================  ========================

Note what has no arrow into it: nothing reaches PASS except a comparison that
came out true, or a rule that explicitly declares absence to be compliant.
There is no path from a failure of any kind to PASS, which is the property the
Phase 3 tests are written to hold the engine to.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.checks.contract import CheckOutcome, CheckResult, Evidence
from core.config_audit.collection import (
    CollectedState,
    CollectionContext,
    CollectionStatus,
)
from core.config_audit.collectors.base import CollectorRegistry, collector_registry
from core.config_audit.operators import ComparisonOutcome, evaluate_detailed
from core.config_audit.spec import ConfigCheck

log = logging.getLogger("ccure.config_audit.engine")

__all__ = ["ConfigAuditEngine", "ConfigAuditReport"]


@dataclass
class ConfigAuditReport:
    """The results of one configuration audit of one target, plus its shape."""

    target: str
    platform: str
    results: List[CheckResult] = field(default_factory=list)

    @property
    def counts(self) -> Dict[str, int]:
        tally = {outcome.value: 0 for outcome in CheckOutcome}
        for result in self.results:
            tally[result.outcome.value] += 1
        return tally

    @property
    def failures(self) -> List[CheckResult]:
        return [r for r in self.results if r.outcome is CheckOutcome.FAIL]

    @property
    def assessed(self) -> List[CheckResult]:
        """Checks that produced a verdict — the denominator of any score."""
        return [r for r in self.results if r.is_verdict]

    def compliance_score(self) -> Optional[float]:
        """
        Percentage of *verdicts* that passed, or None where nothing was
        assessed.

        None rather than 0.0 or 100.0: a target on which no check produced a
        verdict has no score, and both numeric answers are assertions nobody
        established. NOT_APPLICABLE, MANUAL_REVIEW and ERROR are excluded from
        both halves of the fraction — counting an unreachable host's errors as
        failures invents findings, and counting them as passes inflates the
        score.
        """
        verdicts = self.assessed
        if not verdicts:
            return None
        passed = sum(1 for r in verdicts if r.outcome is CheckOutcome.PASS)
        return round(100.0 * passed / len(verdicts), 2)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "platform": self.platform,
            "counts": self.counts,
            "assessed": len(self.assessed),
            "compliance_score": self.compliance_score(),
            "results": [r.as_dict() for r in self.results],
        }


class ConfigAuditEngine:
    """
    Executes configuration checks against one target at a time.

    Stateless apart from the collector registry, so a worker may hold one and
    reuse it across hosts. Per-host state (the executor, the memo cache) lives
    on :class:`CollectionContext`, which is what makes the engine safe to share
    between the threads a parallel host sweep runs in.
    """

    def __init__(self, registry: Optional[CollectorRegistry] = None) -> None:
        self._registry = registry or collector_registry

    # ── Public API ───────────────────────────────────────────────────────────

    def run(
        self, checks: Sequence[ConfigCheck], ctx: CollectionContext
    ) -> ConfigAuditReport:
        report = ConfigAuditReport(target=ctx.target, platform=ctx.platform)
        for check in checks:
            report.results.append(self.run_check(check, ctx))
        return report

    def run_check(self, check: ConfigCheck, ctx: CollectionContext) -> CheckResult:
        """Evaluate one check. Never raises for a target-side problem."""
        gate = self._precondition(check, ctx)
        if gate is not None:
            return gate

        collector = self._registry.resolve(check.check_type, ctx.platform)
        if collector is None:
            return self._error(
                check,
                ctx,
                f"no collector implements check_type {check.check_type!r} on "
                f"platform {ctx.platform!r}, so this check could not be "
                f"performed",
            )

        try:
            state = collector.collect(check, ctx)
        except Exception as exc:
            # A defect in our own collector must not become a finding about the
            # customer's host. Logged with the traceback so it is fixable, and
            # reported as an error so it is visible rather than swallowed.
            log.exception(
                "Collector %s raised on check %s against %s",
                type(collector).__name__,
                check.check_id,
                ctx.target,
            )
            return self._error(
                check,
                ctx,
                f"collector {type(collector).__name__} raised "
                f"{type(exc).__name__}: {exc}",
            )

        if not isinstance(state, CollectedState):
            return self._error(
                check,
                ctx,
                f"collector {type(collector).__name__} returned "
                f"{type(state).__name__}, not a CollectedState",
            )

        return self._interpret(check, ctx, state)

    # ── Pipeline stages ──────────────────────────────────────────────────────

    def _precondition(
        self, check: ConfigCheck, ctx: CollectionContext
    ) -> Optional[CheckResult]:
        """Platform targeting and the credential requirement."""
        platform = (ctx.platform or "").strip().lower()

        if not platform:
            return self._error(
                check,
                ctx,
                "the target's platform has not been determined, so platform "
                "targeting could not be applied. A check evaluated against an "
                "unidentified host would be asserting something about a "
                "machine of unknown kind.",
            )

        if not check.applies_to_platform(platform):
            return CheckResult.not_applicable(
                check_id=check.check_id,
                target=ctx.target,
                reason=(
                    f"check targets {', '.join(check.platforms)}; this host is "
                    f"{platform}"
                ),
                title=check.title,
                severity=check.severity,
                references=list(check.references),
            )

        os_reason = check.os_applicability(ctx.os_name, ctx.os_version_id)
        if os_reason:
            if "not identified" in os_reason:
                # "We could not tell what this host runs" is not "this host is
                # not what the benchmark is for". Only the second is a reason
                # for a control to leave the score; the first is a gap in
                # fingerprinting and must be visible as one.
                return self._error(
                    check,
                    ctx,
                    f"{os_reason}, so the benchmark's operating-system "
                    f"targeting could not be applied",
                )
            return CheckResult.not_applicable(
                check_id=check.check_id,
                target=ctx.target,
                reason=os_reason,
                title=check.title,
                severity=check.severity,
                references=list(check.references),
            )

        if check.requires_credentials and not ctx.has_credentials:
            return self._error(
                check,
                ctx,
                "this check requires an authenticated session and none was "
                "established for the host",
            )

        return None

    def _interpret(
        self, check: ConfigCheck, ctx: CollectionContext, state: CollectedState
    ) -> CheckResult:
        """Turn a collected state into an outcome. The table in the module docstring."""
        if state.status is CollectionStatus.UNAVAILABLE:
            return self._error(
                check, ctx, state.detail, evidence=self._evidence(check, state)
            )

        if state.status is CollectionStatus.UNSUPPORTED:
            return CheckResult.not_applicable(
                check_id=check.check_id,
                target=ctx.target,
                reason=state.detail or "not supported on this target",
                title=check.title,
                severity=check.severity,
                evidence=[self._evidence(check, state)],
                references=list(check.references),
            )

        if state.status is CollectionStatus.ABSENT:
            outcome = check.absent.to_outcome()
            return self._result(check, ctx, outcome, state)

        comparison = evaluate_detailed(
            check.expect.operator, state.value, check.expect.value
        )
        if comparison is ComparisonOutcome.UNKNOWN_OPERATOR:
            return self._error(
                check,
                ctx,
                f"the rule's comparison could not be performed "
                f"(operator {check.expect.operator!r}); the check was not "
                f"evaluated",
                evidence=self._evidence(check, state),
            )

        outcome = (
            CheckOutcome.PASS
            if comparison is ComparisonOutcome.TRUE
            else CheckOutcome.FAIL
        )
        return self._result(check, ctx, outcome, state)

    # ── Result construction ──────────────────────────────────────────────────

    def _evidence(self, check: ConfigCheck, state: CollectedState) -> Evidence:
        return Evidence(
            collector=state.collector or f"config_audit:{check.check_type}",
            description=check.title,
            expected=check.expect.render(),
            observed=state.observed_text(),
            raw=state.raw,
        )

    def _result(
        self,
        check: ConfigCheck,
        ctx: CollectionContext,
        outcome: CheckOutcome,
        state: CollectedState,
    ) -> CheckResult:
        return CheckResult(
            check_id=check.check_id,
            outcome=outcome,
            title=check.title,
            severity=check.severity,
            target=ctx.target,
            evidence=[self._evidence(check, state)],
            remediation=check.remediation or None,
            references=list(check.references),
            detection_method="config_check",
            confidence="Confirmed",
            qod=check.qod,
            metadata={
                "check_type": check.check_type,
                "domain": check.domain,
                "collection_status": state.status.value,
                "asset_id": ctx.asset_id,
                **(
                    {"absent_policy": check.absent.value}
                    if state.status is CollectionStatus.ABSENT
                    else {}
                ),
            },
        )

    def _error(
        self,
        check: ConfigCheck,
        ctx: CollectionContext,
        reason: str,
        *,
        evidence: Optional[Evidence] = None,
    ) -> CheckResult:
        return CheckResult.error_result(
            check_id=check.check_id,
            target=ctx.target,
            reason=reason,
            title=check.title,
            severity=check.severity,
            evidence=[evidence] if evidence else [],
            references=list(check.references),
            metadata={
                "check_type": check.check_type,
                "domain": check.domain,
                "asset_id": ctx.asset_id,
            },
        )


def select_checks(
    checks: Iterable[ConfigCheck],
    *,
    platform: Optional[str] = None,
    domains: Optional[Sequence[str]] = None,
    include_intrusive: bool = False,
    tags: Optional[Sequence[str]] = None,
) -> List[ConfigCheck]:
    """
    Narrow a check set before running it.

    ``include_intrusive`` defaults to False and must be turned on deliberately.
    This product scans production and OT hosts, where an audit that causes an
    outage is worse than the finding it would have produced — the same trade
    ``nuclei_probe`` makes with ``-exclude-tags dos,fuzz,intrusive``.
    """
    wanted_domains = {d.strip().lower() for d in (domains or [])}
    wanted_tags = {t.strip().lower() for t in (tags or [])}
    selected: List[ConfigCheck] = []
    for check in checks:
        if platform and not check.applies_to_platform(platform):
            continue
        if wanted_domains and check.domain.lower() not in wanted_domains:
            continue
        if wanted_tags and not wanted_tags & {t.lower() for t in check.tags}:
            continue
        if check.intrusive and not include_intrusive:
            continue
        selected.append(check)
    return selected

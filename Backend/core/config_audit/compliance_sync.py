"""
core/config_audit/compliance_sync.py
─────────────────────────────────────────────────────────────────────────────
The link Phase 3 built and did not connect: a configuration verdict becoming a
compliance finding.

    ConfigAuditEngine result ──> compliance_findings row on every control the
                                 rule covers, in every framework the tenant has
                                 enabled and this installation has active

Phase 3 wrote ``compliance_verdict()`` and tested it, and nothing called it —
because configuration rules were not yet linked to framework controls and there
was nothing to link them to. Phase 4's benchmark loader creates those links, so
this is the piece that makes a benchmark result reach the compliance score, the
register and the report.

What is reused rather than rebuilt
──────────────────────────────────
Everything that writes. ``_save_finding_for_control`` owns the finding row, its
history transition, the exception-waiver check and the scope columns;
``resolve_controls_for_rule`` owns control resolution and is framework-scoped
for the reason CLAUDE.md records — 57 of 114 ISO rules once resolved to a
control in a *different* standard, so an ISO scan wrote half its findings onto
GDPR. Neither is reimplemented here.

Three gates, and why each is in this order
──────────────────────────────────────────
1. **The rule must exist.** A result whose ``check_id`` matches no
   ``compliance_rules`` row is a built-in check, not benchmark content. It
   still becomes a security finding through the Phase 3 path; it just has no
   control to answer for, and inventing one would attach a verdict to a
   framework nobody mapped it to.
2. **The framework must be active in this installation.** Eleven catalogues
   ship parked. Writing findings for one would put a score on a framework the
   workspace cannot open.
3. **The tenant must have it enabled.** ``ComplianceTenantFramework`` is the
   marketplace installation. A tenant who never installed a benchmark should
   not acquire a score for it because a host happened to be scanned.

Errors are not verdicts, here either
────────────────────────────────────
``compliance_verdict()`` maps ERROR to ``manual_review`` and records the reason
in the evidence payload, because ``compliance_findings.status`` has no ``error``
member and must not gain one — it would be a claim about a host that nothing
established. The reason travels with it so an operator can see *why* a control
is unassessed rather than only that it is.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from sqlalchemy.orm import Session

from core.checks.contract import CheckOutcome
from core.config_audit.findings import compliance_verdict
from db.models.compliance import (
    ComplianceControl,
    ComplianceRule,
    ComplianceRuleControl,
    ComplianceTenantFramework,
)

log = logging.getLogger("ccure.config_audit.compliance_sync")

__all__ = ["ConfigComplianceSyncResult", "sync_config_audit_findings"]


@dataclass
class ConfigComplianceSyncResult:
    """What one sync wrote, and what it deliberately did not."""

    findings_written: int = 0
    controls_covered: int = 0
    #: Results whose check_id matched no rule — built-in checks, not benchmark
    #: content. Counted rather than logged per item so a host running twenty
    #: built-ins does not produce twenty log lines.
    unmapped_results: int = 0
    #: Rules that resolved to no control in any enabled framework.
    rules_without_controls: int = 0
    #: Per-outcome tally of what was written, for the caller's summary.
    by_status: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "findings_written": self.findings_written,
            "controls_covered": self.controls_covered,
            "unmapped_results": self.unmapped_results,
            "rules_without_controls": self.rules_without_controls,
            "by_status": dict(self.by_status),
        }


def _enabled_framework_ids(db: Session, org_id: str) -> List[str]:
    """
    Frameworks this tenant has installed *and* this installation offers.

    Both halves are needed and CLAUDE.md records why: the tenant flag already
    gated the register and the scans but not the report endpoints, and the
    active list is what stops a parked catalogue being scored at all.
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


def _as_result_rows(results: Iterable[Any]) -> List[Mapping[str, Any]]:
    """
    Accept either ``CheckResult`` objects or the dicts ``as_dict()`` produced.

    The scan path stores the dict form on the asset and hands it back here, so
    both shapes reach this function and neither should need the caller to
    remember which.
    """
    rows: List[Mapping[str, Any]] = []
    for entry in results or []:
        if isinstance(entry, Mapping):
            rows.append(entry)
        elif hasattr(entry, "as_dict"):
            rows.append(entry.as_dict())
    return rows


def sync_config_audit_findings(
    db: Session,
    *,
    org_id: str,
    asset_id: str,
    results: Iterable[Any],
    scan_run_id: Optional[str] = None,
) -> ConfigComplianceSyncResult:
    """
    Write one compliance finding per (control, rule) for every configuration
    result that belongs to a loaded benchmark.

    Does not commit — the caller owns the transaction, so the findings land in
    the same commit as the asset sync that produced them. A finding committed
    separately from the asset it describes can outlive a rolled-back scan.
    """
    from core.compliance_tasks import (
        _save_finding_for_control,
        resolve_controls_for_rule,
    )

    summary = ConfigComplianceSyncResult()
    rows = _as_result_rows(results)
    if not rows:
        return summary

    framework_ids = _enabled_framework_ids(db, org_id)
    if not framework_ids:
        # Nothing installed and active: the results are still security
        # findings, they simply answer to no framework here.
        summary.unmapped_results = len(rows)
        return summary

    # One query for every rule the results name, rather than one per result.
    check_ids = [str(r.get("check_id") or "") for r in rows if r.get("check_id")]
    rules = {
        rule.id: rule
        for rule in db.query(ComplianceRule)
        .filter(ComplianceRule.id.in_(check_ids))
        .all()
    }

    covered: set[str] = set()
    for row in rows:
        check_id = str(row.get("check_id") or "")
        rule = rules.get(check_id)
        if rule is None:
            summary.unmapped_results += 1
            continue

        control_ids: List[str] = []
        for framework_id in framework_ids:
            control_ids.extend(resolve_controls_for_rule(db, rule.id, framework_id))
        if not control_ids:
            summary.rules_without_controls += 1
            continue

        try:
            outcome = CheckOutcome(str(row.get("outcome")))
        except ValueError:
            # A stored result carrying an outcome this build does not know is
            # not evidence of anything. Skipping is the only safe reading:
            # guessing would write a verdict from a string nobody defined.
            log.warning(
                "Configuration result for %s carries unknown outcome %r; skipped",
                check_id,
                row.get("outcome"),
            )
            summary.unmapped_results += 1
            continue

        verdict = compliance_verdict(_rehydrate(row, outcome))

        for control_id in control_ids:
            _save_finding_for_control(
                db,
                org_id,
                asset_id,
                rule,
                control_id,
                scan_run_id,
                verdict["status"],
                verdict["evidence"],
            )
            summary.findings_written += 1
            covered.add(control_id)
        summary.by_status[verdict["status"]] = (
            summary.by_status.get(verdict["status"], 0) + 1
        )

    summary.controls_covered = len(covered)
    log.info(
        "Configuration verdicts synced for asset %s: %d finding(s) across %d "
        "control(s); %d result(s) mapped to no rule, %d rule(s) to no control",
        asset_id,
        summary.findings_written,
        summary.controls_covered,
        summary.unmapped_results,
        summary.rules_without_controls,
    )
    return summary


def _rehydrate(row: Mapping[str, Any], outcome: CheckOutcome):
    """
    Rebuild the minimum ``CheckResult`` ``compliance_verdict`` needs.

    A full reconstruction is deliberately avoided: ``CheckResult`` refuses a
    FAIL with no evidence, and a stored row that lost its evidence would raise
    here rather than at the point the evidence went missing. This carries the
    stored fields through as they are, so the verdict describes what was
    actually recorded.
    """
    from core.checks.contract import CheckResult, Evidence

    evidence: List[Evidence] = []
    for item in row.get("evidence") or []:
        if not isinstance(item, Mapping):
            continue
        evidence.append(
            Evidence(
                collector=str(item.get("collector") or "config_audit"),
                description=str(item.get("description") or row.get("title") or "check"),
                expected=item.get("expected"),
                observed=item.get("observed"),
                raw=item.get("raw"),
            )
        )

    if outcome is CheckOutcome.FAIL and not evidence:
        # The stored row lost its evidence. Reporting the failure without it
        # would produce a finding nobody can defend, so it degrades to
        # "not assessed" with the reason recorded.
        return CheckResult(
            check_id=str(row.get("check_id")),
            outcome=CheckOutcome.ERROR,
            title=str(row.get("title") or ""),
            severity=str(row.get("severity") or "medium"),
            target=str(row.get("target") or ""),
            error=(
                "the stored configuration result recorded a failure with no "
                "evidence, so the verdict could not be reconstructed"
            ),
            metadata=dict(row.get("metadata") or {}),
        )

    return CheckResult(
        check_id=str(row.get("check_id")),
        outcome=outcome,
        title=str(row.get("title") or ""),
        severity=str(row.get("severity") or "medium"),
        target=str(row.get("target") or ""),
        evidence=evidence,
        remediation=row.get("remediation"),
        references=list(row.get("references") or []),
        detection_method=str(row.get("detection_method") or "config_check"),
        confidence=str(row.get("confidence") or "Confirmed"),
        qod=int(row.get("qod") or 95),
        error=row.get("error"),
        metadata=dict(row.get("metadata") or {}),
    )

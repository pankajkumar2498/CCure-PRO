"""
core/remediation/verification.py
─────────────────────────────────────────────────────────────────────────────
The only path by which a remediation becomes *verified fixed*.

    scan → findings sync → GAP-13 comparison → FIXED / REAPPEARED / NOT_ASSESSED
                                             → verify_from_comparison
                                             → verified_fixed | reopened | nothing

Why this consumes GAP-13 rather than deciding for itself
────────────────────────────────────────────────────────
GAP-13 already answers the hard question — *was this finding open at the
baseline, is it open now, and did this scan actually assess the check it
belongs to?* — and answers it with the assessment scope the scan recorded. That
work is done, tested and real-target validated. Reimplementing the judgement
here would give the product two answers to one question, and the day they
disagree is the day a customer is told a control was remediated when it was
not.

So this module contains no lifecycle logic. It reads a
:class:`~core.findings.comparison.ScanComparison` and maps its classifications
onto remediation states. The mapping is the whole module and it is deliberately
tiny.

The three refusals
──────────────────
**NOT_ASSESSED never verifies.** It is GAP-13's word for "this finding was open
and this scan did not look" — the single most dangerous thing to mistake for a
fix, and the reason GAP-13 introduced the class. 126 Windows STIG findings are
absent from ``cve_list`` when the audit passes *and* when the credential
expired; only the scan's recorded assessment scope tells them apart.

**A scan with no recorded scope never verifies.** ``AssessmentScope.recorded``
is False for a scan that predates GAP-13 or that failed before it could record
anything. That is "we do not know what was assessed", and unknown reach is not
"assessed everything" — the comparison already degrades to NOT_ASSESSED for it,
and this module inherits that rather than second-guessing it.

**A comparison that is not comparable never verifies.** Two scans run under
materially different policies (GAP-12) are not equivalent assessments, and a
finding absent from the narrower one may simply be outside its scope. The
comparison reports ``policies_match``; where it is False and the scopes differ,
verification is withheld and says so.

Nothing here commits
────────────────────
The caller owns the transaction, so a verification and the event recording it
land together — and so a scan whose sync is rolled back does not leave findings
marked verified against results that no longer exist.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from core.findings.comparison import (
    CLASS_FIXED,
    CLASS_NOT_ASSESSED,
    CLASS_REAPPEARED,
)
from core.remediation.states import (
    STATE_ASSIGNED,
    STATE_OPEN,
    STATE_REOPENED,
    STATE_RISK_ACCEPTED,
    STATE_VERIFIED_FIXED,
    assert_transition,
    can_transition,
)
from core.remediation.workflow import (
    ACTOR_VERIFICATION,
    EVENT_REOPENED,
    EVENT_VERIFIED,
    record_event,
)

log = logging.getLogger("ccure.remediation.verification")

__all__ = [
    "VerificationOutcome",
    "verify_from_comparison",
    "verify_scan",
]


@dataclass
class VerificationOutcome:
    """What one verification pass did, and what it deliberately did not do."""

    verified: List[str] = field(default_factory=list)
    reopened: List[str] = field(default_factory=list)
    #: Findings the comparison classified FIXED that were **not** verified,
    #: each with the reason. Counted and named rather than dropped: a reader
    #: told "8 verified" and not told "40 could not be" has been handed a
    #: number that implies progress the scan did not establish — the same
    #: position GAP-13 takes on its own NOT_ASSESSED class.
    withheld: Dict[str, str] = field(default_factory=dict)
    #: True when the comparison itself could not be trusted, in which case
    #: nothing was verified at all.
    comparison_usable: bool = True
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verified": list(self.verified),
            "reopened": list(self.reopened),
            "withheld": dict(self.withheld),
            "verified_count": len(self.verified),
            "reopened_count": len(self.reopened),
            "withheld_count": len(self.withheld),
            "comparison_usable": self.comparison_usable,
            "reason": self.reason,
        }

    def summary_line(self) -> str:
        if not self.comparison_usable:
            return f"No remediation verified: {self.reason}"
        parts = [
            f"{len(self.verified)} verified fixed",
            f"{len(self.reopened)} reopened",
        ]
        if self.withheld:
            parts.append(f"{len(self.withheld)} not verified (not assessed)")
        return ", ".join(parts)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def verify_from_comparison(
    db,
    comparison: Any,
    *,
    scan_id: Optional[str] = None,
    org_id: Optional[str] = None,
) -> VerificationOutcome:
    """
    Apply a GAP-13 comparison to the remediation states it justifies.

    Returns a :class:`VerificationOutcome`. Does not commit.

    Only two classifications move anything:

    * ``FIXED`` → ``verified_fixed``, because GAP-13 has already established
      that the finding was open at the baseline, is absent now, **and** that
      this scan assessed the relevant check.
    * ``REAPPEARED`` → ``reopened``, and the SLA clock restarts from the
      regression rather than from the original discovery.

    ``NEW`` and ``STILL_OPEN`` deliberately move nothing. A finding that is
    still open is still open; its remediation state belongs to whoever is
    working on it, and a scan has no business resetting that.
    """
    outcome = VerificationOutcome()

    if comparison is None:
        outcome.comparison_usable = False
        outcome.reason = "no comparison was available for this scan"
        return outcome

    if not getattr(comparison, "comparable", False):
        outcome.comparison_usable = False
        outcome.reason = (
            getattr(comparison, "reason", "") or "the two scans are not comparable"
        )
        log.info(
            "Remediation verification skipped for scan %s: %s",
            scan_id,
            outcome.reason,
        )
        return outcome

    # GAP-12 supplies this. Two scans run under materially different
    # configurations are not equivalent assessments, and a finding absent from
    # the narrower one may simply be outside its scope rather than fixed.
    # Withheld rather than refused outright when only one side is unrecorded —
    # that is the common case for scans predating GAP-12 and refusing it would
    # make verification impossible on any existing installation.
    current_policy = getattr(comparison, "current_policy", None) or {}
    baseline_policy = getattr(comparison, "baseline_policy", None) or {}
    policies_known = bool(current_policy.get("recorded")) and bool(
        baseline_policy.get("recorded")
    )
    if policies_known and not getattr(comparison, "policies_match", False):
        outcome.comparison_usable = False
        outcome.reason = (
            "the two scans ran under different assessment configurations, so a "
            "finding absent from this one may be out of its scope rather than "
            "fixed"
        )
        log.info(
            "Remediation verification skipped for scan %s: %s", scan_id, outcome.reason
        )
        return outcome

    from db.models.findings import AssetVulnerability

    deltas = list(getattr(comparison, "findings", None) or [])
    interesting = {
        d.finding_id: d
        for d in deltas
        if getattr(d, "classification", None)
        in (CLASS_FIXED, CLASS_REAPPEARED, CLASS_NOT_ASSESSED)
    }
    if not interesting:
        return outcome

    # One query for every finding the comparison named, rather than one per
    # finding. At the scale this product reaches — 4,633 findings on one Linux
    # host — a per-finding lookup here would be the N+1 that makes verification
    # cost more than the scan.
    rows = (
        db.query(AssetVulnerability)
        .filter(AssetVulnerability.id.in_(list(interesting)))
        .all()
    )
    by_id = {row.id: row for row in rows}

    for finding_id, delta in interesting.items():
        finding = by_id.get(finding_id)
        if finding is None:
            # The comparison named a row that no longer exists. Recorded rather
            # than ignored: it means something deleted a finding between the
            # comparison and this pass.
            outcome.withheld[finding_id] = "the finding row no longer exists"
            continue

        if org_id and str(finding.org_id) != str(org_id):
            # Defence in depth. `compare_scans` already filters on org_id; this
            # is the second line, because a verification writing across a
            # tenant boundary would be the worst defect available here.
            outcome.withheld[finding_id] = "belongs to another organisation"
            continue

        classification = getattr(delta, "classification", None)

        if classification == CLASS_NOT_ASSESSED:
            # The whole point. GAP-13 says this finding was open and this scan
            # did not look at it; nothing may be concluded from its absence.
            outcome.withheld[finding_id] = (
                "this scan did not assess the relevant check, so its absence "
                "establishes nothing"
            )
            continue

        if classification == CLASS_FIXED:
            _verify_one(db, finding, scan_id=scan_id, outcome=outcome, delta=delta)
        elif classification == CLASS_REAPPEARED:
            _reopen_one(db, finding, scan_id=scan_id, outcome=outcome, delta=delta)

    return outcome


def _verify_one(db, finding, *, scan_id, outcome: VerificationOutcome, delta) -> None:
    current = str(getattr(finding, "remediation_state", None) or STATE_OPEN)

    if current == STATE_VERIFIED_FIXED:
        return  # already settled; re-verifying writes noise, not information

    if current == STATE_RISK_ACCEPTED:
        # An organisation decided to carry this risk. A scan no longer seeing
        # it does not retract that decision, and silently converting an
        # acceptance into a verification would erase a record somebody is
        # accountable for. Left alone, and said out loud.
        outcome.withheld[finding.id] = (
            "the risk is accepted; a scan does not retract that decision"
        )
        return

    if not can_transition(current, STATE_VERIFIED_FIXED, by_assessment=True):
        outcome.withheld[finding.id] = (
            f"a finding in state {current!r} is not verifiable from an assessment"
        )
        return

    assert_transition(current, STATE_VERIFIED_FIXED, by_assessment=True)
    finding.remediation_state = STATE_VERIFIED_FIXED
    finding.verified_at = _utcnow()
    finding.verified_scan_id = scan_id

    record_event(
        db,
        finding,
        event_type=EVENT_VERIFIED,
        actor_id=None,
        actor_label=ACTOR_VERIFICATION,
        from_state=current,
        to_state=STATE_VERIFIED_FIXED,
        scan_id=scan_id,
        note="Confirmed fixed by a subsequent assessment",
        details={
            "classification": CLASS_FIXED,
            "baseline_scan_id": getattr(delta, "baseline_scan_id", None),
            "severity": getattr(finding, "severity", None),
        },
    )
    outcome.verified.append(finding.id)


def _reopen_one(db, finding, *, scan_id, outcome: VerificationOutcome, delta) -> None:
    current = str(getattr(finding, "remediation_state", None) or STATE_OPEN)

    if current == STATE_RISK_ACCEPTED:
        # Same reasoning as above: an accepted risk reappearing is not new
        # information, and reopening it would override a decision on its own.
        outcome.withheld[finding.id] = (
            "the risk is accepted; a reappearance does not withdraw that"
        )
        return

    if current not in (STATE_VERIFIED_FIXED,):
        # Only a finding that had been verified can *regress*. One that was
        # never verified and is present again was simply never fixed, and
        # calling that a regression would inflate the figure that matters most.
        return

    now = _utcnow()
    assert_transition(current, STATE_REOPENED, by_assessment=True)
    finding.remediation_state = STATE_REOPENED
    finding.reopened_at = now
    finding.reopened_count = int(getattr(finding, "reopened_count", 0) or 0) + 1
    finding.verified_at = None
    finding.verified_scan_id = None

    # The SLA clock restarts from the regression. Dating a returned finding
    # from its original discovery would report an instant, unfixable breach —
    # `sla_anchor` reads `reopened_at` first for exactly this.
    try:
        from core.remediation.workflow import apply_sla

        apply_sla(db, finding)
    except Exception:  # noqa: BLE001
        log.warning(
            "Could not recompute the SLA for reopened finding %s",
            finding.id,
            exc_info=True,
        )

    record_event(
        db,
        finding,
        event_type=EVENT_REOPENED,
        actor_id=None,
        actor_label=ACTOR_VERIFICATION,
        from_state=current,
        to_state=STATE_REOPENED,
        scan_id=scan_id,
        note="Found again by a subsequent assessment after being verified fixed",
        details={
            "classification": CLASS_REAPPEARED,
            "reopened_count": finding.reopened_count,
        },
    )
    outcome.reopened.append(finding.id)


def verify_scan(db, scan, *, baseline=None) -> VerificationOutcome:
    """
    Compute a comparison for *scan* and apply it. Convenience for the sync path.

    Uses GAP-13's own baseline selection when none is given, so the remediation
    layer never decides what a scan should be compared against — that judgement
    stays in one place.
    """
    from core.findings.comparison import compare_scans, previous_scan_for

    if baseline is None:
        baseline = previous_scan_for(db, scan)
    if baseline is None:
        outcome = VerificationOutcome()
        outcome.comparison_usable = False
        outcome.reason = "this is the first scan; there is nothing to compare against"
        return outcome

    comparison = compare_scans(db, current=scan, baseline=baseline, limit_findings=None)
    return verify_from_comparison(
        db, comparison, scan_id=str(scan.id), org_id=str(scan.org_id)
    )

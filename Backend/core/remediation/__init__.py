"""
core/remediation/
─────────────────────────────────────────────────────────────────────────────
Remediation and SLA management. GAP-14; tracker §9Q.

    finding → assign → in remediation → claim fixed → scan → VERIFIED
                     ↘ accept risk → expiry → back to the queue
                                              scan finds it again → REOPENED

**No parallel finding engine and no parallel lifecycle.** Everything here
operates on the `AssetVulnerability` rows the scan pipeline already writes,
consumes GAP-13's comparison for its verdicts, and reuses the columns that
already existed — `status`, `remediation_notes`, `fixed_at`,
`accepted_risk_reason`, `accepted_by`.

Four modules, four jobs
───────────────────────
``states``        the workflow vocabulary and which transitions are legal
``sla``           when a finding is due, and whether it is late
``workflow``      what a person may do, and the event trail it writes
``verification``  the only path to *verified fixed*, driven by GAP-13

Read ``states`` first. It carries the two decisions the rest depends on: why
the workflow is a second column rather than more values in ``status``, and why
no human action can reach ``verified_fixed``.
"""

from core.remediation.reporting import remediation_report_payload  # noqa: F401
from core.remediation.sla import (  # noqa: F401
    DEFAULT_SLA_DAYS,
    SLA_DUE_SOON,
    SLA_NOT_APPLICABLE,
    SLA_OVERDUE,
    SLA_PENDING_VERIFICATION,
    SLA_RESOLVED,
    SLA_STATES,
    SLA_WITHIN,
    SlaPolicy,
    days_remaining,
    due_at_for,
    sla_anchor,
    sla_policy_for_org,
    sla_state,
)
from core.remediation.states import (  # noqa: F401
    ACTIVE_STATES,
    REMEDIATION_STATES,
    STATE_ASSIGNED,
    STATE_IN_REMEDIATION,
    STATE_OPEN,
    STATE_PENDING_VERIFICATION,
    STATE_REOPENED,
    STATE_RISK_ACCEPTED,
    STATE_VERIFIED_FIXED,
    TERMINAL_STATES,
    TransitionError,
    assert_transition,
    can_transition,
    is_active,
)
from core.remediation.verification import (  # noqa: F401
    VerificationOutcome,
    verify_from_comparison,
    verify_scan,
)
from core.remediation.workflow import (  # noqa: F401
    accept_risk,
    add_note,
    apply_sla,
    assign_owner,
    change_state,
    claim_fixed,
    expire_due_exceptions,
    record_event,
    withdraw_acceptance,
)

__all__ = [
    "ACTIVE_STATES",
    "DEFAULT_SLA_DAYS",
    "REMEDIATION_STATES",
    "SLA_DUE_SOON",
    "SLA_NOT_APPLICABLE",
    "SLA_OVERDUE",
    "SLA_PENDING_VERIFICATION",
    "SLA_RESOLVED",
    "SLA_STATES",
    "SLA_WITHIN",
    "STATE_ASSIGNED",
    "STATE_IN_REMEDIATION",
    "STATE_OPEN",
    "STATE_PENDING_VERIFICATION",
    "STATE_REOPENED",
    "STATE_RISK_ACCEPTED",
    "STATE_VERIFIED_FIXED",
    "TERMINAL_STATES",
    "SlaPolicy",
    "TransitionError",
    "VerificationOutcome",
    "accept_risk",
    "add_note",
    "apply_sla",
    "assert_transition",
    "assign_owner",
    "can_transition",
    "change_state",
    "claim_fixed",
    "days_remaining",
    "due_at_for",
    "expire_due_exceptions",
    "is_active",
    "record_event",
    "remediation_report_payload",
    "sla_anchor",
    "sla_policy_for_org",
    "sla_state",
    "verify_from_comparison",
    "verify_scan",
    "withdraw_acceptance",
]

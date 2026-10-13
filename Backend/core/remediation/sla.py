"""
core/remediation/sla.py
─────────────────────────────────────────────────────────────────────────────
When a finding is due, and whether it is late.

    first_found_at + days(severity)  ──>  sla_due_at  ──>  within | due_soon | overdue

Four rules, each of which is a decision rather than an implementation detail.

**The clock starts at discovery, not at assignment.** ``first_found_at`` is
the moment the organisation *could* have known, and it is the field GAP-13
already treats as trustworthy. Anchoring on assignment would mean a finding
nobody looked at for six months was never late, which inverts what an SLA is
for.

**Rediscovery does not reset the clock.** ``last_found_at`` moves on every
scan; if the due date were derived from it, a finding present for a year would
be perpetually two weeks from due and could never go overdue. This is the
single most important line in the module and :func:`sla_anchor` exists so
there is exactly one place that decides it.

**A regression starts a new clock, from the regression.** A finding that was
verified fixed and came back is not six months late — it is new work, and
dating it from the original discovery would report an instant, unfixable
breach. ``reopened_at`` becomes the anchor, and the original ``first_found_at``
stays on the row so the history is not lost.

**CISA KEV wins where it applies.** ``kev_due_date`` is a date the US
government has mandated under BOD 22-01. Where it is earlier than the
severity-derived date it is used, because an internal policy cannot extend an
external legal deadline. Where it is later it is *not* used — an organisation
may be stricter than the mandate, and silently relaxing to the federal date
would be the product loosening a customer's own policy.

Calendar days, said out loud
────────────────────────────
Durations are calendar days, not business days. A business-day clock needs a
working calendar and a holiday table per organisation, and getting it wrong
makes every due date subtly wrong rather than visibly absent. The API and the
report both say "calendar days" so nobody has to guess.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Optional

log = logging.getLogger("ccure.remediation.sla")

__all__ = [
    "DEFAULT_SLA_DAYS",
    "DUE_SOON_WINDOW_DAYS",
    "SLA_NOT_APPLICABLE",
    "SLA_OVERDUE",
    "SLA_DUE_SOON",
    "SLA_PENDING_VERIFICATION",
    "SLA_RESOLVED",
    "SLA_WITHIN",
    "SLA_STATES",
    "SlaPolicy",
    "due_at_for",
    "sla_anchor",
    "org_sla_setting",
    "sla_policy_for_org",
    "sla_policy_for_org_id",
    "sla_state",
    "store_sla_setting",
    "stored_sla_setting",
]

# ─────────────────────────────────────────────────────────────────────────────
# The policy
# ─────────────────────────────────────────────────────────────────────────────

#: Calendar days from discovery to due, by canonical severity. The vocabulary
#: is ``scans.cvss.CANONICAL_SEVERITIES`` — the same six values the finding
#: column is constrained to — so a severity the product can store always has an
#: answer here.
#:
#: The numbers follow the shape of CISA BOD 22-01 (15 days for the most urgent)
#: and of common commercial policy, and they are a **default**, not a claim
#: about anybody's obligations. An organisation sets its own; that is what
#: ``sla_policy_for_org`` is for.
DEFAULT_SLA_DAYS: Dict[str, int] = {
    "critical": 15,
    "high": 30,
    "medium": 90,
    "low": 180,
    # A finding with no published rating and one rated zero are different
    # facts, and neither carries a remediation obligation on its own — so both
    # get no due date rather than an invented one. `due_at_for` returns None.
    "none": 0,
    "unscored": 0,
}

#: How long before the due date a finding starts reporting ``due_soon``.
#: Seven days is a week of notice, which is the point of the state — it exists
#: so somebody can act *before* the breach rather than being told about it
#: afterwards.
DUE_SOON_WINDOW_DAYS = 7

# An organisation's own deadlines are platform-owned: they are read and
# written through ccure_platform.api, by the seam
# functions below and nowhere else in Audit
# (tests/repo/test_organisation_settings_containment.py). Where they are stored is the
# platform's business. What they *mean* — the severity vocabulary, the
# defaults above, the KEV rule and the lenient reading below — is Audit's.

SLA_WITHIN = "within_sla"
SLA_DUE_SOON = "due_soon"
SLA_OVERDUE = "overdue"
SLA_RESOLVED = "resolved"
SLA_PENDING_VERIFICATION = "pending_verification"
#: No due date applies — an unrated finding, or one whose severity carries no
#: obligation. Deliberately **not** folded into ``within_sla``: "comfortably
#: inside its deadline" and "has no deadline" are different, and reporting the
#: second as the first would inflate every compliance figure built on this.
SLA_NOT_APPLICABLE = "not_applicable"

SLA_STATES = (
    SLA_WITHIN,
    SLA_DUE_SOON,
    SLA_OVERDUE,
    SLA_RESOLVED,
    SLA_PENDING_VERIFICATION,
    SLA_NOT_APPLICABLE,
)


@dataclass(frozen=True)
class SlaPolicy:
    """
    One organisation's remediation deadlines.

    Frozen because it is read while computing due dates for thousands of
    findings in a loop, and a value that could change halfway through would
    give two findings of the same severity different deadlines in one pass.
    """

    days_by_severity: Mapping[str, int]
    due_soon_window_days: int = DUE_SOON_WINDOW_DAYS
    #: Whether CISA KEV's mandated date overrides a later internal one.
    #: On by default, and turning it off is a decision an organisation has to
    #: make deliberately — it means choosing to miss a federal deadline.
    honour_kev_due_date: bool = True

    def days_for(self, severity: Optional[str]) -> int:
        key = str(severity or "unscored").strip().lower()
        # An unrecognised severity gets no deadline rather than the strictest
        # or the most lenient one. Guessing would either manufacture a breach
        # or hide one, and both are worse than saying "not applicable".
        return int(self.days_by_severity.get(key, 0))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "days_by_severity": dict(self.days_by_severity),
            "due_soon_window_days": self.due_soon_window_days,
            "honour_kev_due_date": self.honour_kev_due_date,
        }


DEFAULT_POLICY = SlaPolicy(days_by_severity=DEFAULT_SLA_DAYS)


def org_sla_setting(db, org_id: Optional[str]):
    """
    The organisation's stored SLA setting, asked of the platform: a
    ``RemediationSlaSettingView``, or None if the organisation does not exist.

    **The Audit seam of the remediation-SLA setting.** This
    module is the only Audit code that asks the platform for it, so removing
    the setting means this seam and ``ccure_platform.organisation_settings.remediation_sla``.
    """
    from ccure_platform import api as platform_api

    return platform_api.remediation_sla_setting(db, org_id)


def sla_policy_for_org_id(db, org_id: Optional[str]) -> SlaPolicy:
    """The policy in force for the organisation — the default if it set none."""
    return sla_policy_for_org(org_sla_setting(db, org_id))


def stored_sla_setting(db, org_id: str) -> Optional[Dict[str, Any]]:
    """
    The organisation's stored setting as a dict to merge an update into, or
    None if the organisation does not exist.
    """
    setting = org_sla_setting(db, org_id)
    if setting is None:
        return None
    raw = json.loads(setting.stored) if setting.stored is not None else None
    return dict(raw or {})


def store_sla_setting(db, org_id: str, value: Mapping[str, Any]) -> None:
    """Store the organisation's setting. The caller commits, with its audit event."""
    from ccure_platform import api as platform_api

    platform_api.store_remediation_sla_setting(db, org_id, value)


def sla_policy_for_org(setting: Any) -> SlaPolicy:
    """
    The SLA policy in force for an organisation, from its stored setting (a
    ``RemediationSlaSettingView``, or None), falling back to the shipped default.

    A malformed or partial setting **merges over** the default rather than
    replacing it, so an organisation that configured only ``critical`` still
    has a deadline for ``high`` — a partial override that silently removed the
    other five deadlines would report thousands of findings as having no
    obligation.
    """
    org_id = getattr(setting, "org_id", "?")
    stored = getattr(setting, "stored", None) if setting is not None else None
    raw = (json.loads(stored) if stored is not None else None) or {}
    if not isinstance(raw, Mapping):
        log.warning(
            "Organisation %s has a malformed remediation_sla setting (%s); "
            "using the default SLA policy",
            org_id,
            type(raw).__name__,
        )
        return DEFAULT_POLICY

    days = dict(DEFAULT_SLA_DAYS)
    configured = raw.get("days_by_severity")
    if isinstance(configured, Mapping):
        for severity, value in configured.items():
            key = str(severity).strip().lower()
            if key not in DEFAULT_SLA_DAYS:
                log.warning(
                    "Organisation %s configures an SLA for unknown severity "
                    "%r; ignored",
                    org_id,
                    severity,
                )
                continue
            try:
                parsed = int(value)
            except (TypeError, ValueError):
                log.warning(
                    "Organisation %s configures a non-numeric SLA for %r; "
                    "keeping the default of %s days",
                    org_id,
                    severity,
                    days[key],
                )
                continue
            if parsed < 0:
                log.warning(
                    "Organisation %s configures a negative SLA for %r; "
                    "keeping the default",
                    org_id,
                    severity,
                )
                continue
            days[key] = parsed

    window = raw.get("due_soon_window_days", DUE_SOON_WINDOW_DAYS)
    try:
        window = max(0, int(window))
    except (TypeError, ValueError):
        window = DUE_SOON_WINDOW_DAYS

    honour_kev = raw.get("honour_kev_due_date", True)
    return SlaPolicy(
        days_by_severity=days,
        due_soon_window_days=window,
        honour_kev_due_date=bool(honour_kev),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Computing the due date
# ─────────────────────────────────────────────────────────────────────────────


def _aware(value: Any) -> Optional[datetime]:
    """Coerce to a timezone-aware UTC datetime, or None."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        # A KEV due date is a date, not a datetime. End of that day in UTC is
        # the reading that does not make a finding overdue on the morning of
        # the day it is actually due.
        return datetime(
            value.year, value.month, value.day, 23, 59, 59, tzinfo=timezone.utc
        )
    return None


def sla_anchor(finding: Any) -> Optional[datetime]:
    """
    The moment this finding's clock started.

    ``reopened_at`` where the finding is a regression, ``first_found_at``
    otherwise. **Never ``last_found_at``**: that moves on every scan, so a due
    date derived from it would slide forward for as long as the finding
    persisted and the finding could never go overdue. This function exists so
    that decision has exactly one home.
    """
    reopened = _aware(getattr(finding, "reopened_at", None))
    if reopened is not None:
        return reopened
    return _aware(getattr(finding, "first_found_at", None))


def due_at_for(
    finding: Any,
    policy: Optional[SlaPolicy] = None,
) -> Optional[datetime]:
    """
    When this finding must be remediated by, or None if no deadline applies.

    None is a real answer — an unrated finding carries no obligation — and it
    must not be rendered as "due now" or as "within SLA". :func:`sla_state`
    returns ``not_applicable`` for it.
    """
    policy = policy or DEFAULT_POLICY
    anchor = sla_anchor(finding)
    if anchor is None:
        return None

    days = policy.days_for(getattr(finding, "severity", None))
    internal = anchor + timedelta(days=days) if days > 0 else None

    kev = _aware(getattr(finding, "kev_due_date", None))
    if not policy.honour_kev_due_date:
        kev = None

    if kev is None:
        return internal
    if internal is None:
        # No internal deadline but a mandated one: the mandate applies. An
        # unrated CVE that CISA has listed as exploited is exactly the case
        # where the external date is the only one that matters.
        return kev
    # The earlier of the two. An internal policy may be stricter than BOD
    # 22-01 and that is honoured; it may not be more lenient, because an
    # organisation cannot extend a federal deadline by writing a setting.
    return min(internal, kev)


# ─────────────────────────────────────────────────────────────────────────────
# Reading the state
# ─────────────────────────────────────────────────────────────────────────────


def sla_state(
    finding: Any,
    *,
    policy: Optional[SlaPolicy] = None,
    now: Optional[datetime] = None,
) -> str:
    """
    Where this finding stands against its deadline.

    Order matters and is deliberate:

    1. A **verified** or **risk-accepted** finding is ``resolved``. Nothing
       further is owed on it and reporting it as overdue would be noise.
    2. A finding **pending verification** reports as such rather than as
       overdue *only while it is inside its deadline*. Past the deadline it is
       overdue: "I applied the fix three months ago and no scan has confirmed
       it" is a breach, and letting the claim suppress the state would make
       ``pending_verification`` a way to hide from the SLA.
    3. No deadline → ``not_applicable``.
    4. Otherwise the deadline decides.

    ``status`` is deliberately **not** consulted. A finding absent from the
    latest scan (``status = fixed``) is not resolved for SLA purposes until the
    verification path has confirmed the scan actually assessed it — which is
    the whole point of GAP-14, and reading ``status`` here would reintroduce
    exactly the shortcut this gap exists to remove.
    """
    from core.remediation.states import (
        STATE_PENDING_VERIFICATION,
        STATE_RISK_ACCEPTED,
        STATE_VERIFIED_FIXED,
    )

    policy = policy or DEFAULT_POLICY
    now = now or datetime.now(timezone.utc)
    state = str(getattr(finding, "remediation_state", None) or "open")

    if state in (STATE_VERIFIED_FIXED, STATE_RISK_ACCEPTED):
        return SLA_RESOLVED

    due = _aware(getattr(finding, "sla_due_at", None)) or due_at_for(finding, policy)
    if due is None:
        return SLA_NOT_APPLICABLE

    if now > due:
        return SLA_OVERDUE

    if state == STATE_PENDING_VERIFICATION:
        return SLA_PENDING_VERIFICATION

    if now >= due - timedelta(days=policy.due_soon_window_days):
        return SLA_DUE_SOON

    return SLA_WITHIN


def days_remaining(
    finding: Any,
    *,
    policy: Optional[SlaPolicy] = None,
    now: Optional[datetime] = None,
) -> Optional[int]:
    """
    Whole days until due; negative when overdue, None when no deadline applies.

    Truncated toward zero rather than rounded, so "due in 14 hours" reports 0
    and not 1 — a report that says a day remains when it does not is the kind
    of small dishonesty that makes an operator stop trusting the figure.
    """
    policy = policy or DEFAULT_POLICY
    now = now or datetime.now(timezone.utc)
    due = _aware(getattr(finding, "sla_due_at", None)) or due_at_for(finding, policy)
    if due is None:
        return None
    return int((due - now).total_seconds() // 86400)

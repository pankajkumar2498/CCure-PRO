"""
tests/scans/test_remediation_sla.py
─────────────────────────────────────────────────────────────────────────────
GAP-14 — SLA computation and the workflow state machine.

No database and no HTTP. These pin the rules the rest of the phase depends on:

* the clock starts at discovery and rediscovery does not restart it
* a regression starts a new clock, from the regression
* CISA KEV's mandated date wins where it is earlier and never where it is later
* no human transition reaches ``verified_fixed``

Coverage areas exercised: rem.sla.by_severity, rem.sla.from_discovery,
rem.sla.no_reset, rem.sla.kev, rem.sla.within, rem.sla.due_soon,
rem.sla.overdue, rem.state.transitions, rem.verify.no_self_attest,
rem.state.open, rem.state.assigned, rem.state.in_progress,
rem.state.pending_verification, rem.state.verified, rem.state.reopened,
rem.state.risk_accepted.
"""

from datetime import date, datetime, timedelta, timezone

import pytest
from core.remediation import (
    DEFAULT_SLA_DAYS,
    SLA_DUE_SOON,
    SLA_NOT_APPLICABLE,
    SLA_OVERDUE,
    SLA_PENDING_VERIFICATION,
    SLA_RESOLVED,
    SLA_WITHIN,
    STATE_ASSIGNED,
    STATE_IN_REMEDIATION,
    STATE_OPEN,
    STATE_PENDING_VERIFICATION,
    STATE_REOPENED,
    STATE_RISK_ACCEPTED,
    STATE_VERIFIED_FIXED,
    SlaPolicy,
    TransitionError,
    assert_transition,
    can_transition,
    days_remaining,
    due_at_for,
    is_active,
    sla_anchor,
    sla_policy_for_org,
    sla_state,
)

UTC = timezone.utc
NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)


class _Finding:
    """A finding's SLA-relevant surface. The real model behaves identically."""

    def __init__(self, **kwargs):
        self.severity = kwargs.get("severity", "high")
        self.first_found_at = kwargs.get("first_found_at", NOW - timedelta(days=1))
        self.last_found_at = kwargs.get("last_found_at", NOW)
        self.reopened_at = kwargs.get("reopened_at")
        self.kev_due_date = kwargs.get("kev_due_date")
        self.sla_due_at = kwargs.get("sla_due_at")
        self.remediation_state = kwargs.get("remediation_state", STATE_OPEN)


def _Org(settings=None):
    """
    An organisation's SLA setting as the platform reports it (Phase 8.4): the
    stored value as JSON text, or None when the organisation never set one.
    """
    import json

    from ccure_platform.api import RemediationSlaSettingView

    settings = settings or {}
    stored = (
        json.dumps(settings["remediation_sla"])
        if "remediation_sla" in settings
        else None
    )
    return RemediationSlaSettingView(org_id="org_test", stored=stored)


# ─────────────────────────────────────────────────────────────────────────────
# rem.sla.by_severity / rem.sla.from_discovery
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "severity,days", [("critical", 15), ("high", 30), ("medium", 90), ("low", 180)]
)
def test_the_due_date_is_severity_days_from_discovery(severity, days):
    """rem.sla.by_severity, rem.sla.from_discovery."""
    found = datetime(2026, 1, 1, tzinfo=UTC)
    finding = _Finding(severity=severity, first_found_at=found)
    assert due_at_for(finding) == found + timedelta(days=days)


def test_an_unrated_finding_carries_no_deadline():
    """
    None is a real answer. Rendering it as "due now" would manufacture a
    breach; rendering it as "within SLA" would claim an obligation was met
    that never existed.
    """
    for severity in ("none", "unscored", None, "not-a-severity"):
        assert due_at_for(_Finding(severity=severity)) is None
    assert sla_state(_Finding(severity="unscored"), now=NOW) == SLA_NOT_APPLICABLE


def test_the_anchor_is_discovery_not_the_last_sighting():
    """rem.sla.from_discovery — the clock starts when we could have known."""
    found = datetime(2026, 1, 1, tzinfo=UTC)
    finding = _Finding(first_found_at=found, last_found_at=NOW)
    assert sla_anchor(finding) == found


def test_a_naive_timestamp_is_read_as_utc():
    """
    The scan pipeline writes timezone-aware UTC, but a row written by an older
    release or a fixture may not be. Comparing a naive datetime against an
    aware one raises, which would take out the whole overdue query.
    """
    finding = _Finding(first_found_at=datetime(2026, 1, 1))
    assert due_at_for(finding).tzinfo is not None


# ─────────────────────────────────────────────────────────────────────────────
# rem.sla.no_reset — the most important rule in the module
# ─────────────────────────────────────────────────────────────────────────────


def test_rediscovery_does_not_restart_the_clock():
    """
    rem.sla.no_reset. If the due date came from ``last_found_at`` a finding
    present for a year would be perpetually two weeks from due and could never
    go overdue — the SLA would be unenforceable by construction.
    """
    found = datetime(2026, 1, 1, tzinfo=UTC)
    early = _Finding(first_found_at=found, last_found_at=found)
    still_there = _Finding(first_found_at=found, last_found_at=NOW)
    assert due_at_for(early) == due_at_for(still_there)
    assert sla_state(still_there, now=NOW) == SLA_OVERDUE


def test_a_regression_starts_a_new_clock_from_the_regression():
    """
    A returned finding is new work. Dating it from the original discovery
    would report an instant, unfixable breach the moment it came back.
    """
    found = datetime(2026, 1, 1, tzinfo=UTC)
    reopened = datetime(2026, 8, 30, tzinfo=UTC)
    finding = _Finding(
        severity="high",
        first_found_at=found,
        reopened_at=reopened,
        remediation_state=STATE_REOPENED,
    )
    assert sla_anchor(finding) == reopened
    assert due_at_for(finding) == reopened + timedelta(days=30)
    assert sla_state(finding, now=NOW) == SLA_WITHIN


# ─────────────────────────────────────────────────────────────────────────────
# rem.sla.kev
# ─────────────────────────────────────────────────────────────────────────────


def test_an_earlier_kev_date_wins_over_the_internal_policy():
    """An internal policy cannot extend a federally mandated deadline."""
    found = datetime(2026, 1, 1, tzinfo=UTC)
    finding = _Finding(
        severity="medium",  # 90 days internally
        first_found_at=found,
        kev_due_date=date(2026, 1, 15),
    )
    due = due_at_for(finding)
    assert due.date() == date(2026, 1, 15)


def test_a_later_kev_date_does_not_relax_a_stricter_internal_policy():
    """
    An organisation may be stricter than BOD 22-01. Silently relaxing to the
    federal date would be the product loosening a customer's own policy.
    """
    found = datetime(2026, 1, 1, tzinfo=UTC)
    finding = _Finding(
        severity="critical",  # 15 days
        first_found_at=found,
        kev_due_date=date(2026, 6, 1),
    )
    assert due_at_for(finding) == found + timedelta(days=15)


def test_a_kev_date_applies_even_when_the_severity_carries_no_deadline():
    """An unrated CVE that CISA lists as exploited still has a real deadline."""
    finding = _Finding(severity="unscored", kev_due_date=date(2026, 2, 1))
    due = due_at_for(finding)
    assert due is not None and due.date() == date(2026, 2, 1)


def test_a_kev_due_date_is_end_of_day():
    """
    A date, not a datetime. Reading it as midnight makes a finding overdue on
    the morning of the day it is actually due.
    """
    finding = _Finding(severity="unscored", kev_due_date=date(2026, 2, 1))
    due = due_at_for(finding)
    assert due.hour == 23 and due.minute == 59


def test_kev_can_be_switched_off_deliberately():
    policy = SlaPolicy(days_by_severity=DEFAULT_SLA_DAYS, honour_kev_due_date=False)
    found = datetime(2026, 1, 1, tzinfo=UTC)
    finding = _Finding(
        severity="medium", first_found_at=found, kev_due_date=date(2026, 1, 15)
    )
    assert due_at_for(finding, policy) == found + timedelta(days=90)


# ─────────────────────────────────────────────────────────────────────────────
# rem.sla.within / rem.sla.due_soon / rem.sla.overdue
# ─────────────────────────────────────────────────────────────────────────────


def test_the_three_sla_states():
    """rem.sla.within, rem.sla.due_soon, rem.sla.overdue."""
    assert (
        sla_state(_Finding(sla_due_at=NOW + timedelta(days=30)), now=NOW) == SLA_WITHIN
    )
    assert (
        sla_state(_Finding(sla_due_at=NOW + timedelta(days=3)), now=NOW) == SLA_DUE_SOON
    )
    assert (
        sla_state(_Finding(sla_due_at=NOW - timedelta(days=1)), now=NOW) == SLA_OVERDUE
    )


def test_a_verified_or_accepted_finding_reports_resolved_not_overdue():
    """Nothing further is owed, so reporting it late would be noise."""
    for state in (STATE_VERIFIED_FIXED, STATE_RISK_ACCEPTED):
        finding = _Finding(
            sla_due_at=NOW - timedelta(days=100), remediation_state=state
        )
        assert sla_state(finding, now=NOW) == SLA_RESOLVED


def test_pending_verification_shows_as_such_only_while_inside_the_deadline():
    """
    Past the deadline it is overdue. "I applied the fix three months ago and
    no scan has confirmed it" is a breach — letting the claim suppress the
    state would make pending_verification a way to hide from the SLA.
    """
    inside = _Finding(
        sla_due_at=NOW + timedelta(days=10),
        remediation_state=STATE_PENDING_VERIFICATION,
    )
    assert sla_state(inside, now=NOW) == SLA_PENDING_VERIFICATION

    late = _Finding(
        sla_due_at=NOW - timedelta(days=10),
        remediation_state=STATE_PENDING_VERIFICATION,
    )
    assert sla_state(late, now=NOW) == SLA_OVERDUE


def test_status_fixed_alone_does_not_resolve_the_sla():
    """
    The shortcut this whole gap exists to remove. A finding absent from the
    latest scan is not resolved until the verification path has confirmed the
    scan actually assessed it.
    """
    finding = _Finding(sla_due_at=NOW - timedelta(days=5), remediation_state=STATE_OPEN)
    finding.status = "fixed"
    assert sla_state(finding, now=NOW) == SLA_OVERDUE


def test_days_remaining_truncates_rather_than_rounding():
    """A report that says a day remains when it does not is a small dishonesty."""
    finding = _Finding(sla_due_at=NOW + timedelta(hours=14))
    assert days_remaining(finding, now=NOW) == 0
    late = _Finding(sla_due_at=NOW - timedelta(days=2, hours=1))
    assert days_remaining(late, now=NOW) < 0
    assert days_remaining(_Finding(severity="unscored"), now=NOW) is None


# ─────────────────────────────────────────────────────────────────────────────
# rem.sla.per_tenant
# ─────────────────────────────────────────────────────────────────────────────


def test_an_organisation_sets_its_own_deadlines():
    org = _Org({"remediation_sla": {"days_by_severity": {"critical": 3}}})
    policy = sla_policy_for_org(org)
    assert policy.days_for("critical") == 3


def test_a_partial_override_merges_rather_than_replacing():
    """
    An organisation configuring only `critical` must keep its other five
    deadlines. A replace would silently report thousands of findings as
    carrying no obligation.
    """
    org = _Org({"remediation_sla": {"days_by_severity": {"critical": 3}}})
    policy = sla_policy_for_org(org)
    assert policy.days_for("high") == DEFAULT_SLA_DAYS["high"]
    assert policy.days_for("medium") == DEFAULT_SLA_DAYS["medium"]


def test_a_malformed_policy_falls_back_to_the_default_rather_than_failing():
    for settings in (
        {"remediation_sla": "not a mapping"},
        {"remediation_sla": {"days_by_severity": {"critical": "soon"}}},
        {"remediation_sla": {"days_by_severity": {"nonsense": 5}}},
        {"remediation_sla": {"days_by_severity": {"critical": -1}}},
        {},
        None,
    ):
        policy = sla_policy_for_org(_Org(settings))
        assert policy.days_for("critical") in (DEFAULT_SLA_DAYS["critical"], 3)
        assert policy.days_for("high") == DEFAULT_SLA_DAYS["high"]


def test_no_org_at_all_yields_the_default_policy():
    assert sla_policy_for_org(None).days_for("critical") == DEFAULT_SLA_DAYS["critical"]


# ─────────────────────────────────────────────────────────────────────────────
# rem.state.transitions and rem.verify.no_self_attest
# ─────────────────────────────────────────────────────────────────────────────


def test_no_human_transition_reaches_verified_fixed():
    """
    rem.verify.no_self_attest — the control the phase exists for. Asserted
    over *every* state rather than a sample, so a table edit that opened one
    of them fails here.
    """
    from core.remediation import REMEDIATION_STATES

    for state in REMEDIATION_STATES:
        assert not can_transition(
            state, STATE_VERIFIED_FIXED
        ), f"a person must not be able to move {state!r} to verified_fixed"


def test_the_refusal_explains_itself_and_points_at_the_alternative():
    with pytest.raises(TransitionError) as exc:
        assert_transition(STATE_IN_REMEDIATION, STATE_VERIFIED_FIXED)
    message = str(exc.value)
    assert "cannot be marked verified fixed by hand" in message
    assert STATE_PENDING_VERIFICATION in message


def test_only_the_assessment_path_may_verify():
    for state in (
        STATE_OPEN,
        STATE_ASSIGNED,
        STATE_IN_REMEDIATION,
        STATE_PENDING_VERIFICATION,
        STATE_REOPENED,
    ):
        assert can_transition(state, STATE_VERIFIED_FIXED, by_assessment=True)


def test_an_assessment_may_reopen_a_verified_finding_and_a_person_may_not():
    assert can_transition(STATE_VERIFIED_FIXED, STATE_REOPENED, by_assessment=True)
    assert not can_transition(STATE_VERIFIED_FIXED, STATE_REOPENED)


def test_an_assessment_never_overrides_an_accepted_risk():
    """
    The organisation made a decision somebody is accountable for. A scan not
    seeing the finding does not retract it, and a scan seeing it again is not
    new information.
    """
    assert not can_transition(
        STATE_RISK_ACCEPTED, STATE_VERIFIED_FIXED, by_assessment=True
    )
    assert not can_transition(STATE_RISK_ACCEPTED, STATE_REOPENED, by_assessment=True)


def test_the_ordinary_workflow_transitions_are_permitted():
    """rem.state.open, .assigned, .in_progress, .pending_verification."""
    assert can_transition(STATE_OPEN, STATE_ASSIGNED)
    assert can_transition(STATE_ASSIGNED, STATE_IN_REMEDIATION)
    assert can_transition(STATE_IN_REMEDIATION, STATE_PENDING_VERIFICATION)
    # And back, because a person may realise the fix was incomplete before a
    # scan runs.
    assert can_transition(STATE_PENDING_VERIFICATION, STATE_IN_REMEDIATION)


def test_a_verified_finding_is_not_editable_by_hand():
    """rem.state.verified — settled by evidence, not reopened by opinion."""
    for target in (STATE_OPEN, STATE_ASSIGNED, STATE_RISK_ACCEPTED):
        with pytest.raises(TransitionError):
            assert_transition(STATE_VERIFIED_FIXED, target)


def test_a_reopened_finding_re_enters_the_workflow():
    """rem.state.reopened."""
    assert can_transition(STATE_REOPENED, STATE_ASSIGNED)
    assert can_transition(STATE_REOPENED, STATE_IN_REMEDIATION)


def test_an_acceptance_can_be_withdrawn():
    """rem.state.risk_accepted."""
    assert can_transition(STATE_RISK_ACCEPTED, STATE_OPEN)
    assert can_transition(STATE_RISK_ACCEPTED, STATE_ASSIGNED)


def test_an_unknown_state_is_refused_by_name():
    with pytest.raises(TransitionError, match="not a remediation state"):
        assert_transition(STATE_OPEN, "almost_done")


def test_active_states_exclude_the_two_settled_ones():
    assert is_active(STATE_OPEN)
    assert is_active(STATE_PENDING_VERIFICATION)
    assert is_active(STATE_REOPENED)
    assert not is_active(STATE_VERIFIED_FIXED)
    assert not is_active(STATE_RISK_ACCEPTED)


def test_the_state_vocabulary_has_one_home():
    """
    The model declares it and ``core.remediation.states`` imports it. Two
    copies is how the CHECK constraint and the code come to disagree — the
    defect CLAUDE.md records against CONTROL_THEMES.
    """
    from core.remediation.states import REMEDIATION_STATES as core_states
    from db.models.findings import REMEDIATION_STATES as model_states

    assert core_states is model_states

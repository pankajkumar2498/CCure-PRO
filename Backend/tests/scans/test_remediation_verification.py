"""
tests/scans/test_remediation_verification.py
─────────────────────────────────────────────────────────────────────────────
GAP-14 — the lifecycle: workflow, verification, exceptions and history.

**The file the phase is really about.** A remediation must not be considered
verified fixed because a user said so, and it must not be considered verified
fixed because a finding vanished from a scan that never looked for it. Both
refusals are exercised here against real rows.

These call the workflow and verification functions directly with a real
session rather than driving them through ``TestClient``, for the reason
CLAUDE.md records against ``test_finding_comparison.py``.

Coverage areas exercised: rem.own.assign, rem.own.reassign, rem.own.unassign,
rem.verify.fixed, rem.verify.not_assessed, rem.verify.error,
rem.verify.reappeared, rem.verify.scope_mismatch, rem.verify.no_self_attest,
rem.exc.grant, rem.exc.expiry, rem.exc.audit, rem.rec.history, rem.rec.notes.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from core.findings.comparison import (
    CLASS_FIXED,
    CLASS_NEW,
    CLASS_NOT_ASSESSED,
    CLASS_REAPPEARED,
    CLASS_STILL_OPEN,
    FindingDelta,
    ScanComparison,
)
from core.remediation import (
    STATE_ASSIGNED,
    STATE_IN_REMEDIATION,
    STATE_OPEN,
    STATE_PENDING_VERIFICATION,
    STATE_REOPENED,
    STATE_RISK_ACCEPTED,
    STATE_VERIFIED_FIXED,
    TransitionError,
    accept_risk,
    add_note,
    apply_sla,
    assign_owner,
    change_state,
    claim_fixed,
    expire_due_exceptions,
    verify_from_comparison,
    withdraw_acceptance,
)
from db.models import Organization, User
from db.models.assets import Asset
from db.models.findings import (
    AssetVulnerability,
    FindingRemediationEvent,
    VulnerabilityDefinition,
)
from db.models.scans import Scan
from sqlalchemy.orm import Session

UTC = timezone.utc


def _now(**kw):
    return datetime.now(UTC) + timedelta(**kw)


@pytest.fixture
def asset(db_session: Session, test_org: Organization) -> Asset:
    row = Asset(
        id=f"ast_{uuid.uuid4().hex[:12]}",
        org_id=test_org.id,
        ip_address="192.0.2.50",
        hostname="target.test",
        last_seen_at=_now(),
    )
    db_session.add(row)
    db_session.commit()
    return row


@pytest.fixture
def other_user(db_session: Session, test_org: Organization) -> User:
    """
    A second real user to reassign to.

    Not a made-up id: ``fk_asset_vuln_remediation_owner`` refuses one, which is
    the constraint doing its job — an owner who does not exist cannot be
    notified, cannot be chased and cannot be held accountable.
    """
    from auth.jwt_handler import hash_password
    from db.base import gen_user_id, utcnow
    from db.models import Role

    role = db_session.query(Role).filter(Role.name == "analyst").first()
    row = User(
        id=gen_user_id(test_org.slug, "remowner"),
        username=f"remowner-{uuid.uuid4().hex[:6]}",
        email=f"remowner-{uuid.uuid4().hex[:6]}@test.com",
        full_name="Remediation Owner",
        password_hash=hash_password("remediationpassword123"),
        org_id=test_org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(row)
    db_session.commit()
    return row


@pytest.fixture
def scan(db_session: Session, test_org: Organization, test_user: User) -> Scan:
    row = Scan(
        id=f"scn_{uuid.uuid4().hex[:12]}",
        org_id=test_org.id,
        created_by=str(test_user.id),
        target_str="192.0.2.50",
        target_hosts=["192.0.2.50"],
        scan_type="credentialed",
        pipeline_mode="credentialed",
        status="complete",
        started_at=_now(minutes=-10),
        completed_at=_now(minutes=-5),
        options={},
    )
    db_session.add(row)
    db_session.commit()
    return row


def _finding(
    db_session: Session,
    org: Organization,
    asset: Asset,
    scan: Scan,
    *,
    severity="high",
    vuln_id=None,
    state=STATE_OPEN,
    first_found_at=None,
) -> AssetVulnerability:
    vuln_id = vuln_id or f"CCURE-CFG-TEST-{uuid.uuid4().hex[:8].upper()}"
    # The catalogue row the finding's FK needs. `ck_vuln_def_cve_id_matches_type`
    # requires a check row to carry a NULL cve_id — a minted CCURE- identifier
    # in that column is how a configuration finding acquires an NVD link that
    # resolves to nothing.
    if not db_session.get(VulnerabilityDefinition, vuln_id):
        db_session.add(
            VulnerabilityDefinition(
                id=vuln_id,
                cve_id=None,
                definition_type="config_check",
                title=f"Fixture {vuln_id}",
                description="fixture",
                severity=severity,
            )
        )
        db_session.flush()
    row = AssetVulnerability(
        id=f"fnd_{asset.id}_{vuln_id}"[:340],
        org_id=org.id,
        scan_id=scan.id,
        asset_id=asset.id,
        vuln_id=vuln_id,
        severity=severity,
        status="open",
        source_family="credentialed_config",
        remediation_state=state,
        first_found_at=first_found_at or _now(days=-40),
        last_found_at=_now(),
    )
    db_session.add(row)
    db_session.commit()
    return row


def _comparison(
    deltas,
    *,
    comparable=True,
    policies_match=True,
    current_recorded=True,
    baseline_recorded=True,
    reason="",
):
    """A GAP-13 comparison shaped exactly as `compare_scans` returns one."""
    return ScanComparison(
        current_scan_id="scn_current",
        baseline_scan_id="scn_baseline",
        comparable=comparable,
        reason=reason,
        findings=list(deltas),
        current_policy={"recorded": current_recorded, "fingerprint": "aaaa"},
        baseline_policy={
            "recorded": baseline_recorded,
            "fingerprint": "aaaa" if policies_match else "bbbb",
        },
        policies_match=policies_match,
    )


def _delta(finding, classification):
    return FindingDelta(
        finding_id=finding.id,
        vuln_id=finding.vuln_id,
        asset_id=finding.asset_id,
        classification=classification,
        severity=finding.severity or "",
    )


def _events(db_session, finding, event_type=None):
    query = db_session.query(FindingRemediationEvent).filter(
        FindingRemediationEvent.finding_id == finding.id
    )
    if event_type:
        query = query.filter(FindingRemediationEvent.event_type == event_type)
    return query.order_by(FindingRemediationEvent.occurred_at).all()


# ─────────────────────────────────────────────────────────────────────────────
# rem.verify.fixed — the happy path, and it is the only path
# ─────────────────────────────────────────────────────────────────────────────


def test_a_fixed_verdict_verifies_the_remediation(
    db_session, test_org, test_user, asset, scan
):
    """rem.verify.fixed."""
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_FIXED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.verified == [finding.id]
    assert finding.remediation_state == STATE_VERIFIED_FIXED
    assert finding.verified_at is not None
    # The citation. Without the scan id, "verified" is an assertion with no
    # evidence behind it and an auditor cannot check it.
    assert finding.verified_scan_id == scan.id

    events = _events(db_session, finding, "verified")
    assert len(events) == 1
    assert events[0].scan_id == scan.id
    # A system action carries a label, not an identity.
    assert events[0].actor_id is None
    assert events[0].actor_label == "system:verification"


def test_a_claimed_fix_becomes_verified_only_after_a_scan_agrees(
    db_session, test_org, test_user, asset, scan
):
    """
    rem.verify.no_self_attest — the whole phase in one test.

    A person claims the fix; the finding sits in pending_verification and is
    *not* verified. Only when an assessment classifies it FIXED does it move.
    """
    finding = _finding(db_session, test_org, asset, scan)

    claim_fixed(db_session, finding, actor_id=str(test_user.id), note="patched")
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_state == STATE_PENDING_VERIFICATION
    assert finding.verified_at is None
    # And the detection timeline GAP-13 reads is untouched by the claim.
    assert finding.fixed_at is None

    verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_FIXED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)
    assert finding.remediation_state == STATE_VERIFIED_FIXED


def test_a_person_cannot_move_a_finding_to_verified_fixed(
    db_session, test_org, test_user, asset, scan
):
    finding = _finding(db_session, test_org, asset, scan)
    with pytest.raises(TransitionError, match="verified fixed by hand"):
        change_state(
            db_session, finding, target=STATE_VERIFIED_FIXED, actor_id=str(test_user.id)
        )


# ─────────────────────────────────────────────────────────────────────────────
# rem.verify.not_assessed / rem.verify.error — the refusals
# ─────────────────────────────────────────────────────────────────────────────


def test_not_assessed_never_verifies(db_session, test_org, test_user, asset, scan):
    """
    rem.verify.not_assessed. GAP-13's word for "this finding was open and this
    scan did not look" — the single most dangerous thing to mistake for a fix.
    """
    finding = _finding(
        db_session, test_org, asset, scan, state=STATE_PENDING_VERIFICATION
    )
    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_NOT_ASSESSED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.verified == []
    assert finding.id in outcome.withheld
    assert "did not assess" in outcome.withheld[finding.id]
    assert finding.remediation_state == STATE_PENDING_VERIFICATION
    assert finding.verified_at is None


def test_a_scan_that_could_not_be_compared_verifies_nothing(
    db_session, test_org, test_user, asset, scan
):
    """
    rem.verify.error. A comparison that is not comparable — a failed scan, a
    first scan, an unusable baseline — establishes nothing about any finding.
    """
    finding = _finding(
        db_session, test_org, asset, scan, state=STATE_PENDING_VERIFICATION
    )
    outcome = verify_from_comparison(
        db_session,
        _comparison(
            [_delta(finding, CLASS_FIXED)],
            comparable=False,
            reason="the baseline scan did not complete",
        ),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.comparison_usable is False
    assert outcome.verified == []
    assert finding.remediation_state == STATE_PENDING_VERIFICATION


def test_no_comparison_at_all_verifies_nothing(db_session):
    outcome = verify_from_comparison(db_session, None)
    assert outcome.comparison_usable is False
    assert outcome.verified == []
    assert "no comparison" in outcome.reason


def test_a_policy_mismatch_verifies_nothing(
    db_session, test_org, test_user, asset, scan
):
    """
    rem.verify.scope_mismatch. GAP-12 supplies this: two scans under different
    configurations are not equivalent assessments, so a finding absent from
    the narrower one may be out of its scope rather than fixed.
    """
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_FIXED)], policies_match=False),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.comparison_usable is False
    assert "different assessment configurations" in outcome.reason
    assert finding.remediation_state == STATE_IN_REMEDIATION


def test_two_unrecorded_policies_do_not_block_verification(
    db_session, test_org, test_user, asset, scan
):
    """
    The common case for scans predating GAP-12. Refusing it would make
    verification impossible on any existing installation, so an unknown
    configuration on either side is not treated as a mismatch.
    """
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    outcome = verify_from_comparison(
        db_session,
        _comparison(
            [_delta(finding, CLASS_FIXED)],
            policies_match=False,
            current_recorded=False,
            baseline_recorded=False,
        ),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    assert outcome.verified == [finding.id]


def test_new_and_still_open_move_nothing(db_session, test_org, test_user, asset, scan):
    """
    A finding that is still open is still open; its remediation state belongs
    to whoever is working on it, and a scan has no business resetting that.
    """
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    for classification in (CLASS_NEW, CLASS_STILL_OPEN):
        verify_from_comparison(
            db_session,
            _comparison([_delta(finding, classification)]),
            scan_id=scan.id,
            org_id=test_org.id,
        )
        db_session.commit()
        db_session.refresh(finding)
        assert finding.remediation_state == STATE_IN_REMEDIATION


def test_verification_never_crosses_a_tenant_boundary(
    db_session, test_org, test_user, asset, scan
):
    """
    Defence in depth. `compare_scans` already filters on org_id; a
    verification writing across a boundary would be the worst defect here.
    """
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_FIXED)]),
        scan_id=scan.id,
        org_id="org_someone_else",
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.verified == []
    assert "another organisation" in outcome.withheld[finding.id]
    assert finding.remediation_state == STATE_IN_REMEDIATION


# ─────────────────────────────────────────────────────────────────────────────
# rem.verify.reappeared
# ─────────────────────────────────────────────────────────────────────────────


def test_a_reappearance_reopens_a_verified_finding_and_restarts_its_clock(
    db_session, test_org, test_user, asset, scan
):
    """rem.verify.reappeared."""
    finding = _finding(
        db_session,
        test_org,
        asset,
        scan,
        state=STATE_VERIFIED_FIXED,
        first_found_at=_now(days=-200),
    )
    finding.verified_at = _now(days=-30)
    finding.verified_scan_id = scan.id
    db_session.commit()

    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_REAPPEARED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.reopened == [finding.id]
    assert finding.remediation_state == STATE_REOPENED
    assert finding.reopened_count == 1
    assert finding.reopened_at is not None
    # The verification is withdrawn: it is no longer true.
    assert finding.verified_at is None
    assert finding.verified_scan_id is None
    # And the clock restarts from the regression, not from 200 days ago —
    # otherwise it would be reported as an instant, unfixable breach.
    assert finding.sla_due_at > datetime.now(UTC)

    events = _events(db_session, finding, "reopened")
    assert len(events) == 1
    assert events[0].details.get("reopened_count") == 1


def test_a_finding_that_was_never_verified_is_not_a_regression(
    db_session, test_org, test_user, asset, scan
):
    """
    Only a finding that had been verified can *regress*. One that was never
    fixed and is present again was simply never fixed, and calling that a
    regression inflates the figure that matters most.
    """
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_REAPPEARED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.reopened == []
    assert finding.remediation_state == STATE_IN_REMEDIATION
    assert finding.reopened_count == 0


def test_reopening_twice_counts_twice(db_session, test_org, test_user, asset, scan):
    finding = _finding(db_session, test_org, asset, scan, state=STATE_VERIFIED_FIXED)
    for _ in range(2):
        verify_from_comparison(
            db_session,
            _comparison([_delta(finding, CLASS_REAPPEARED)]),
            scan_id=scan.id,
            org_id=test_org.id,
        )
        db_session.commit()
        db_session.refresh(finding)
        # Re-verify so the second reappearance has something to regress from.
        finding.remediation_state = STATE_VERIFIED_FIXED
        db_session.commit()
    assert finding.reopened_count == 2


# ─────────────────────────────────────────────────────────────────────────────
# rem.own.* — ownership
# ─────────────────────────────────────────────────────────────────────────────


def test_assigning_an_owner_moves_an_open_finding_to_assigned(
    db_session, test_org, test_user, asset, scan
):
    """rem.own.assign."""
    finding = _finding(db_session, test_org, asset, scan)
    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_owner == str(test_user.id)
    assert finding.remediation_state == STATE_ASSIGNED
    assert finding.assigned_at is not None
    assert _events(db_session, finding, "assigned")


def test_reassigning_keeps_the_previous_owner_in_the_trail(
    db_session, test_org, test_user, other_user, asset, scan
):
    """
    rem.own.reassign. "Who was this assigned to in March" has to survive a
    reassignment — which is the whole reason ownership does not live only on
    the finding row.
    """
    finding = _finding(db_session, test_org, asset, scan)
    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    db_session.commit()
    assign_owner(
        db_session, finding, owner_id=str(other_user.id), actor_id=str(test_user.id)
    )
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_owner == str(other_user.id)
    events = _events(db_session, finding, "assigned")
    assert len(events) == 2
    assert events[1].details["previous_owner"] == str(test_user.id)


def test_unassigning_returns_it_to_the_queue_without_losing_history(
    db_session, test_org, test_user, asset, scan
):
    """rem.own.unassign."""
    finding = _finding(db_session, test_org, asset, scan)
    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    db_session.commit()
    assign_owner(db_session, finding, owner_id=None, actor_id=str(test_user.id))
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_owner is None
    assert finding.remediation_state == STATE_OPEN
    events = _events(db_session, finding, "unassigned")
    assert events and events[0].details["previous_owner"] == str(test_user.id)


def test_reassigning_does_not_un_start_work_in_progress(
    db_session, test_org, test_user, asset, scan
):
    finding = _finding(db_session, test_org, asset, scan, state=STATE_IN_REMEDIATION)
    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    db_session.commit()
    db_session.refresh(finding)
    assert finding.remediation_state == STATE_IN_REMEDIATION


# ─────────────────────────────────────────────────────────────────────────────
# rem.exc.* — risk acceptance
# ─────────────────────────────────────────────────────────────────────────────


def test_accepting_a_risk_records_reason_approver_and_expiry(
    db_session, test_org, test_user, asset, scan
):
    """rem.exc.grant."""
    finding = _finding(db_session, test_org, asset, scan)
    expires = _now(days=30)
    accept_risk(
        db_session,
        finding,
        reason="Compensating control: segment is air-gapped",
        actor_id=str(test_user.id),
        expires_at=expires,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_state == STATE_RISK_ACCEPTED
    assert finding.accepted_by == str(test_user.id)
    assert finding.accepted_at is not None
    assert finding.exception_expires_at == expires
    # The detection status too, so the dashboard and the asset risk score stop
    # treating it as outstanding.
    assert finding.status == "accepted"
    assert _events(db_session, finding, "risk_accepted")


def test_an_acceptance_without_a_reason_is_refused(
    db_session, test_org, test_user, asset, scan
):
    """
    An acceptance with no justification is indistinguishable from somebody
    clearing their queue, and it is the first thing an auditor asks for.
    """
    finding = _finding(db_session, test_org, asset, scan)
    for reason in ("", "   ", None):
        with pytest.raises(ValueError, match="requires a reason"):
            accept_risk(db_session, finding, reason=reason, actor_id=str(test_user.id))


def test_an_acceptance_cannot_expire_in_the_past(
    db_session, test_org, test_user, asset, scan
):
    finding = _finding(db_session, test_org, asset, scan)
    with pytest.raises(ValueError, match="cannot expire in the past"):
        accept_risk(
            db_session,
            finding,
            reason="x",
            actor_id=str(test_user.id),
            expires_at=_now(days=-1),
        )


def test_an_expired_acceptance_returns_to_the_remediation_queue(
    db_session, test_org, test_user, asset, scan
):
    """rem.exc.expiry."""
    finding = _finding(db_session, test_org, asset, scan)
    accept_risk(
        db_session,
        finding,
        reason="temporary waiver",
        actor_id=str(test_user.id),
        expires_at=_now(days=1),
    )
    db_session.commit()

    # Move the expiry into the past, as the passage of time would.
    finding.exception_expires_at = _now(hours=-1)
    db_session.commit()

    expired = expire_due_exceptions(db_session, org_id=test_org.id)
    db_session.commit()
    db_session.refresh(finding)

    assert expired == 1
    assert finding.remediation_state == STATE_OPEN
    assert finding.status == "open"
    assert finding.exception_expires_at is None

    events = _events(db_session, finding, "exception_expired")
    assert len(events) == 1
    assert events[0].actor_label == "system:exception-expiry"
    # The original reason survives into the event, so the trail says what the
    # acceptance was for and that it ended on its own.
    assert events[0].details["reason"] == "temporary waiver"


def test_an_expired_acceptance_returns_to_assigned_when_it_has_an_owner(
    db_session, test_org, test_user, asset, scan
):
    finding = _finding(db_session, test_org, asset, scan)
    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    accept_risk(
        db_session,
        finding,
        reason="waiver",
        actor_id=str(test_user.id),
        expires_at=_now(days=1),
    )
    db_session.commit()
    finding.exception_expires_at = _now(hours=-1)
    db_session.commit()

    expire_due_exceptions(db_session, org_id=test_org.id)
    db_session.commit()
    db_session.refresh(finding)
    assert finding.remediation_state == STATE_ASSIGNED


def test_an_indefinite_acceptance_is_never_expired(
    db_session, test_org, test_user, asset, scan
):
    """
    A permanent compensating control is a legitimate decision. Expiring it
    because nobody set a date would silently overrule somebody's judgement.
    """
    finding = _finding(db_session, test_org, asset, scan)
    accept_risk(
        db_session,
        finding,
        reason="permanent compensating control",
        actor_id=str(test_user.id),
        expires_at=None,
    )
    db_session.commit()

    assert expire_due_exceptions(db_session, org_id=test_org.id) == 0
    db_session.refresh(finding)
    assert finding.remediation_state == STATE_RISK_ACCEPTED


def test_an_acceptance_can_be_withdrawn_by_hand(
    db_session, test_org, test_user, asset, scan
):
    finding = _finding(db_session, test_org, asset, scan)
    accept_risk(db_session, finding, reason="waiver", actor_id=str(test_user.id))
    db_session.commit()
    withdraw_acceptance(db_session, finding, actor_id=str(test_user.id))
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_state == STATE_OPEN
    assert finding.status == "open"
    assert finding.exception_expires_at is None


def test_an_accepted_risk_is_not_verified_by_a_scan(
    db_session, test_org, test_user, asset, scan
):
    """
    The organisation made a decision somebody is accountable for. A scan no
    longer seeing the finding does not retract it.
    """
    finding = _finding(db_session, test_org, asset, scan)
    accept_risk(db_session, finding, reason="waiver", actor_id=str(test_user.id))
    db_session.commit()

    outcome = verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_FIXED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()
    db_session.refresh(finding)

    assert outcome.verified == []
    assert "risk is accepted" in outcome.withheld[finding.id]
    assert finding.remediation_state == STATE_RISK_ACCEPTED


# ─────────────────────────────────────────────────────────────────────────────
# rem.rec.history / rem.rec.notes
# ─────────────────────────────────────────────────────────────────────────────


def test_the_event_trail_is_append_only_across_a_whole_lifecycle(
    db_session, test_org, test_user, asset, scan
):
    """
    rem.rec.history. The finding row carries the current state; the trail
    carries how it got there, so an owner change or a withdrawn acceptance is
    answerable months later.
    """
    finding = _finding(db_session, test_org, asset, scan)

    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    change_state(
        db_session, finding, target=STATE_IN_REMEDIATION, actor_id=str(test_user.id)
    )
    add_note(db_session, finding, note="patch staged", actor_id=str(test_user.id))
    claim_fixed(db_session, finding, actor_id=str(test_user.id))
    db_session.commit()

    verify_from_comparison(
        db_session,
        _comparison([_delta(finding, CLASS_FIXED)]),
        scan_id=scan.id,
        org_id=test_org.id,
    )
    db_session.commit()

    kinds = [e.event_type for e in _events(db_session, finding)]
    assert kinds == [
        "assigned",
        "state_changed",
        "note_added",
        "state_changed",
        "verified",
    ]
    # And the states either side are recorded, so a timeline reads without
    # replaying every prior row.
    verified = _events(db_session, finding, "verified")[0]
    assert verified.from_state == STATE_PENDING_VERIFICATION
    assert verified.to_state == STATE_VERIFIED_FIXED


def test_a_note_is_kept_in_full_even_when_the_column_is_replaced(
    db_session, test_org, test_user, asset, scan
):
    """rem.rec.notes."""
    finding = _finding(db_session, test_org, asset, scan)
    add_note(db_session, finding, note="first", actor_id=str(test_user.id))
    add_note(db_session, finding, note="second", actor_id=str(test_user.id))
    db_session.commit()
    db_session.refresh(finding)

    assert finding.remediation_notes == "second"
    notes = [e.note for e in _events(db_session, finding, "note_added")]
    assert notes == ["first", "second"]


def test_changing_the_owner_does_not_rewrite_the_scan_result(
    db_session, test_org, test_user, asset, scan
):
    """
    Historical integrity. The finding's detection facts — when it was first
    seen, when it was last seen, whether a scan reported it fixed — belong to
    the assessment and must survive every workflow action.
    """
    finding = _finding(db_session, test_org, asset, scan)
    before = (
        finding.first_found_at,
        finding.last_found_at,
        finding.fixed_at,
        finding.scan_id,
    )

    assign_owner(
        db_session, finding, owner_id=str(test_user.id), actor_id=str(test_user.id)
    )
    change_state(
        db_session, finding, target=STATE_IN_REMEDIATION, actor_id=str(test_user.id)
    )
    add_note(db_session, finding, note="x", actor_id=str(test_user.id))
    accept_risk(db_session, finding, reason="y", actor_id=str(test_user.id))
    db_session.commit()
    db_session.refresh(finding)

    assert (
        finding.first_found_at,
        finding.last_found_at,
        finding.fixed_at,
        finding.scan_id,
    ) == before


# ─────────────────────────────────────────────────────────────────────────────
# SLA materialisation
# ─────────────────────────────────────────────────────────────────────────────


def test_apply_sla_is_idempotent_and_records_only_real_changes(
    db_session, test_org, test_user, asset, scan
):
    """
    This runs over every finding on every scan. An event per finding per scan
    would make the history unreadable — it would record that nothing happened,
    several thousand times a day.
    """
    finding = _finding(db_session, test_org, asset, scan, severity="high")
    apply_sla(db_session, finding, org=test_org)
    db_session.commit()
    first_due = finding.sla_due_at
    assert first_due is not None
    assert len(_events(db_session, finding)) == 1

    apply_sla(db_session, finding, org=test_org)
    db_session.commit()
    assert finding.sla_due_at == first_due
    assert (
        len(_events(db_session, finding)) == 1
    ), "an unchanged deadline writes nothing"


def test_a_re_rated_finding_gets_a_new_deadline_and_an_event(
    db_session, test_org, test_user, asset, scan
):
    finding = _finding(db_session, test_org, asset, scan, severity="low")
    apply_sla(db_session, finding, org=test_org)
    db_session.commit()
    low_due = finding.sla_due_at

    finding.severity = "critical"
    apply_sla(db_session, finding, org=test_org)
    db_session.commit()

    assert finding.sla_due_at < low_due
    assert finding.sla_basis == "critical"
    changed = _events(db_session, finding, "sla_changed")
    assert changed and changed[0].details["basis"] == "critical"

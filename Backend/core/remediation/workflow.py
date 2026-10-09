"""
core/remediation/workflow.py
─────────────────────────────────────────────────────────────────────────────
The operations a person may perform on a finding's remediation.

    assign → in remediation → claim fixed → (scan) → verified
                            ↘ accept risk → (expiry) → back to remediation

Every operation here writes a :class:`FindingRemediationEvent`, and that is not
bookkeeping — it is the auditability requirement. The finding row carries only
the *current* owner and state; the event table carries how it got there, so
changing an owner or a due date cannot erase what the previous one was.

The one thing this module cannot do
───────────────────────────────────
**Nothing here marks a finding verified fixed.** :func:`claim_fixed` moves a
finding to ``pending_verification``, which says "the fix has been applied and
is ready to be checked" — a much weaker statement than "it is fixed", and the
only one a person is in a position to make. The transition table in
:mod:`core.remediation.states` refuses the stronger one by omission, and
:mod:`core.remediation.verification` is the only caller allowed to pass
``by_assessment=True``.

This is the defect the phase exists to fix. Before it,
``PATCH /findings/{id}/status`` accepted ``status="fixed"`` from any user with
``findings:update`` and stamped ``fixed_at = utcnow()`` — and ``fixed_at`` is
the column GAP-13 reconstructs its baseline from. A person clicking a button
was writing into the lifecycle timeline that the comparison, the reports and
the remediation figures all trust.

Transactions
────────────
Nothing here commits. Every function mutates and records, and the caller owns
the transaction — so a finding's new state and the event describing it land in
one commit, and a failure leaves neither. A state change without its event
would be exactly the untraceable mutation this table exists to prevent.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional

from core.remediation.states import (
    STATE_ASSIGNED,
    STATE_IN_REMEDIATION,
    STATE_OPEN,
    STATE_PENDING_VERIFICATION,
    STATE_REOPENED,
    STATE_RISK_ACCEPTED,
    STATE_VERIFIED_FIXED,
    TransitionError,
    assert_transition,
)

log = logging.getLogger("ccure.remediation.workflow")

__all__ = [
    "EVENT_TYPES",
    "accept_risk",
    "add_note",
    "apply_sla",
    "assign_owner",
    "change_state",
    "claim_fixed",
    "expire_due_exceptions",
    "record_event",
    "withdraw_acceptance",
]

EVENT_ASSIGNED = "assigned"
EVENT_UNASSIGNED = "unassigned"
EVENT_STATE_CHANGED = "state_changed"
EVENT_NOTE_ADDED = "note_added"
EVENT_RISK_ACCEPTED = "risk_accepted"
EVENT_EXCEPTION_EXPIRED = "exception_expired"
EVENT_VERIFIED = "verified"
EVENT_REOPENED = "reopened"
EVENT_SLA_SET = "sla_set"
EVENT_SLA_CHANGED = "sla_changed"

EVENT_TYPES = (
    EVENT_ASSIGNED,
    EVENT_UNASSIGNED,
    EVENT_STATE_CHANGED,
    EVENT_NOTE_ADDED,
    EVENT_RISK_ACCEPTED,
    EVENT_EXCEPTION_EXPIRED,
    EVENT_VERIFIED,
    EVENT_REOPENED,
    EVENT_SLA_SET,
    EVENT_SLA_CHANGED,
)

#: Labels for events with no human actor. Deliberately *labels*, not
#: identities — no account exists that could be confused with one, which is the
#: reading `core.audit.log_audit_event`'s `system_actor` already takes.
ACTOR_VERIFICATION = "system:verification"
ACTOR_EXPIRY = "system:exception-expiry"
#: The SLA engine. A separate label from the verification one because they are
#: separate things: real-target validation showed an `sla_set` event reading
#: "system:verification", which invites a reader of the timeline to think an
#: assessment moved a due date.
ACTOR_SLA = "system:sla"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _event_id(finding_id: str, event_type: str, when: datetime) -> str:
    """
    A readable, unique event id.

    The finding id is up to 350 characters and the event id column is 120, so
    the finding is hashed rather than embedded. The prefix keeps it greppable
    and the timestamp keeps a finding's events roughly ordered by eye.

    **The random tail is not decoration.** The first version was
    ``fre_<digest>_<type>_<timestamp>`` and collided: two events of the same
    type on the same finding written in the same microsecond produced the same
    primary key, and because every workflow call shares one transaction the
    duplicate took the *whole lifecycle* down — assignment, note and state
    change all rolled back together. That is not a rare race; a scripted
    remediation, a bulk assignment or the two state changes a claim-then-verify
    performs all run inside one flush. Found by the lifecycle test, not by
    reasoning about it.

    Ordering does not depend on the tail: `occurred_at` is the sort key and the
    id is only the tiebreak, so simultaneous events sort deterministically
    without the id having to encode their sequence.
    """
    digest = hashlib.sha256(str(finding_id).encode("utf-8")).hexdigest()[:16]
    stamp = when.strftime("%Y%m%d%H%M%S%f")
    return f"fre_{digest}_{event_type[:12]}_{stamp}_{secrets.token_hex(3)}"


def record_event(
    db,
    finding: Any,
    *,
    event_type: str,
    actor_id: Optional[str] = None,
    actor_label: Optional[str] = None,
    from_state: Optional[str] = None,
    to_state: Optional[str] = None,
    note: Optional[str] = None,
    scan_id: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
):
    """
    Append one remediation event. Never updates, never deletes.

    Returns the row without committing. An event whose ``actor_id`` is NULL and
    whose ``actor_label`` is set is a system action; one with neither is a
    defect and is logged as such rather than silently written, because an event
    nobody can attribute is worth less than no event at all — the same position
    ``log_audit_event`` takes on an actorless call.
    """
    from db.models.findings import FindingRemediationEvent

    if event_type not in EVENT_TYPES:
        raise ValueError(f"{event_type!r} is not a remediation event type")

    if actor_id is None and not actor_label:
        log.warning(
            "Remediation event %s on finding %s has no actor and no label; "
            "recording it anyway, but it cannot be attributed.",
            event_type,
            getattr(finding, "id", "?"),
        )

    when = _utcnow()
    event = FindingRemediationEvent(
        id=_event_id(str(finding.id), event_type, when),
        finding_id=str(finding.id),
        org_id=str(finding.org_id),
        event_type=event_type,
        from_state=from_state,
        to_state=to_state,
        actor_id=actor_id,
        actor_label=actor_label,
        note=note,
        scan_id=scan_id,
        details=dict(details or {}),
        occurred_at=when,
    )
    db.add(event)
    return event


# ─────────────────────────────────────────────────────────────────────────────
# SLA
# ─────────────────────────────────────────────────────────────────────────────


def apply_sla(db, finding: Any, *, policy: Any = None, actor_id: Optional[str] = None):
    """
    Compute and store this finding's due date.

    Idempotent: recomputing an unchanged deadline writes no event. That matters
    because this runs on every scan sync over thousands of findings, and an
    event per finding per scan would make the history unreadable — the table
    would record that nothing happened, several thousand times a day.

    A *changed* deadline does write one, with both values, because a due date
    moving is exactly the kind of thing an auditor asks about.
    """
    from core.remediation.sla import due_at_for, sla_policy_for_org_id

    # A caller working through many findings of one organisation passes the
    # policy once rather than having it looked up per finding.
    if policy is None:
        policy = sla_policy_for_org_id(db, finding.org_id)
    new_due = due_at_for(finding, policy)
    basis = str(getattr(finding, "severity", None) or "unscored").lower()

    old_due = getattr(finding, "sla_due_at", None)
    if old_due is not None and old_due.tzinfo is None:
        old_due = old_due.replace(tzinfo=timezone.utc)

    if old_due == new_due and getattr(finding, "sla_basis", None) == basis:
        return finding

    finding.sla_due_at = new_due
    finding.sla_basis = basis

    record_event(
        db,
        finding,
        event_type=EVENT_SLA_SET if old_due is None else EVENT_SLA_CHANGED,
        actor_id=actor_id,
        actor_label=None if actor_id else ACTOR_SLA,
        details={
            "from": old_due.isoformat() if old_due else None,
            "to": new_due.isoformat() if new_due else None,
            "basis": basis,
            "days": policy.days_for(basis),
        },
    )
    return finding


# ─────────────────────────────────────────────────────────────────────────────
# Ownership
# ─────────────────────────────────────────────────────────────────────────────


def assign_owner(
    db,
    finding: Any,
    *,
    owner_id: Optional[str],
    actor_id: str,
    note: Optional[str] = None,
):
    """
    Assign, reassign or clear a finding's remediation owner.

    ``owner_id=None`` unassigns. The previous owner is kept in the event's
    details, so "who was this assigned to in March" survives a reassignment —
    which is the whole reason ownership does not live only on the finding row.

    Assigning moves an ``open`` finding to ``assigned``. It does **not** move a
    finding already ``in_remediation`` backwards, because reassigning work that
    is under way does not un-start it.
    """
    previous_owner = getattr(finding, "remediation_owner", None)
    if previous_owner == owner_id:
        return finding

    current_state = str(getattr(finding, "remediation_state", None) or STATE_OPEN)
    finding.remediation_owner = owner_id
    finding.assigned_at = _utcnow() if owner_id else None
    finding.assigned_by = actor_id if owner_id else None

    target_state = current_state
    if owner_id and current_state == STATE_OPEN:
        target_state = STATE_ASSIGNED
    elif not owner_id and current_state == STATE_ASSIGNED:
        # Unassigning work that had not started returns it to the queue.
        target_state = STATE_OPEN

    if target_state != current_state:
        assert_transition(current_state, target_state)
        finding.remediation_state = target_state

    record_event(
        db,
        finding,
        event_type=EVENT_ASSIGNED if owner_id else EVENT_UNASSIGNED,
        actor_id=actor_id,
        from_state=current_state,
        to_state=target_state,
        note=note,
        details={"previous_owner": previous_owner, "owner": owner_id},
    )
    return finding


# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────


def change_state(
    db,
    finding: Any,
    *,
    target: str,
    actor_id: str,
    note: Optional[str] = None,
):
    """
    Move a finding to *target*, refusing anything the transition table forbids.

    ``by_assessment`` is deliberately not a parameter. A caller who could pass
    it would be able to write ``verified_fixed`` from a request handler, which
    is the exact defect this phase removes — so the capability lives in
    :mod:`core.remediation.verification` and nowhere a route can reach.
    """
    current = str(getattr(finding, "remediation_state", None) or STATE_OPEN)
    if current == target:
        return finding

    assert_transition(current, target)
    finding.remediation_state = target

    if target == STATE_IN_REMEDIATION and not getattr(finding, "assigned_at", None):
        # Starting work without an explicit assignment still records when it
        # started; otherwise a finding worked on by its reporter has no
        # timestamp at all.
        finding.assigned_at = _utcnow()

    record_event(
        db,
        finding,
        event_type=EVENT_STATE_CHANGED,
        actor_id=actor_id,
        from_state=current,
        to_state=target,
        note=note,
    )
    return finding


def claim_fixed(db, finding: Any, *, actor_id: str, note: Optional[str] = None):
    """
    Record that somebody has applied the fix. **This does not verify it.**

    The finding moves to ``pending_verification`` and waits for a scan. It is
    named ``claim_fixed`` rather than ``mark_fixed`` on purpose: the caller is
    making a claim, and the product's position is that a claim is not evidence.

    ``status`` and ``fixed_at`` are **not** touched. Those belong to the
    detection lifecycle and are written by the scan sweeps; a person writing
    them is how the previous implementation put an unverified assertion into
    the timeline GAP-13 reads.
    """
    return change_state(
        db,
        finding,
        target=STATE_PENDING_VERIFICATION,
        actor_id=actor_id,
        note=note,
    )


def add_note(db, finding: Any, *, note: str, actor_id: str):
    """
    Append a remediation note.

    The finding's ``remediation_notes`` column keeps the latest note, because
    that is what the existing findings API and the reports already read. The
    event table keeps every one of them, so replacing the note does not destroy
    what it said before — which is the property the column alone cannot offer.
    """
    finding.remediation_notes = note
    record_event(db, finding, event_type=EVENT_NOTE_ADDED, actor_id=actor_id, note=note)
    return finding


# ─────────────────────────────────────────────────────────────────────────────
# Risk acceptance
# ─────────────────────────────────────────────────────────────────────────────


def accept_risk(
    db,
    finding: Any,
    *,
    reason: str,
    actor_id: str,
    expires_at: Optional[datetime] = None,
):
    """
    Record a decision to carry the risk rather than fix it.

    Reuses the columns that already existed — ``accepted_risk_reason`` and
    ``accepted_by`` — and adds the two things they lacked: when it was taken,
    and when it stops applying. A reason is **required**: an acceptance with no
    stated justification is indistinguishable from somebody clearing their
    queue, and it is the first thing an auditor asks for.

    ``expires_at=None`` means the acceptance does not expire. That is a
    legitimate decision for a compensating control that is itself permanent,
    and it is different from "nobody set a date" — ``accepted_at`` records when
    the decision was taken either way, so an indefinite acceptance can still be
    found and reviewed.
    """
    if not str(reason or "").strip():
        raise ValueError(
            "Accepting a risk requires a reason. An acceptance with no stated "
            "justification cannot be reviewed and cannot be defended."
        )
    if expires_at is not None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= _utcnow():
            raise ValueError(
                "An acceptance cannot expire in the past. Set a future date, "
                "or omit it for an acceptance that does not expire."
            )

    current = str(getattr(finding, "remediation_state", None) or STATE_OPEN)
    assert_transition(current, STATE_RISK_ACCEPTED)

    finding.remediation_state = STATE_RISK_ACCEPTED
    finding.accepted_risk_reason = reason
    finding.accepted_by = actor_id
    finding.accepted_at = _utcnow()
    finding.exception_expires_at = expires_at
    # The detection-side status too: `accepted` already exists there and the
    # dashboard and asset risk recompute both read it, so leaving it `open`
    # would show an accepted finding as outstanding on every other screen.
    finding.status = "accepted"

    record_event(
        db,
        finding,
        event_type=EVENT_RISK_ACCEPTED,
        actor_id=actor_id,
        from_state=current,
        to_state=STATE_RISK_ACCEPTED,
        note=reason,
        details={
            "expires_at": expires_at.isoformat() if expires_at else None,
            "indefinite": expires_at is None,
        },
    )
    return finding


def withdraw_acceptance(db, finding: Any, *, actor_id: str, note: Optional[str] = None):
    """Return an accepted finding to the remediation queue by hand."""
    current = str(getattr(finding, "remediation_state", None) or STATE_OPEN)
    if current != STATE_RISK_ACCEPTED:
        raise TransitionError("This finding does not have an accepted risk.")

    target = (
        STATE_ASSIGNED if getattr(finding, "remediation_owner", None) else STATE_OPEN
    )
    assert_transition(current, target)
    finding.remediation_state = target
    finding.exception_expires_at = None
    finding.status = "open"

    record_event(
        db,
        finding,
        event_type=EVENT_STATE_CHANGED,
        actor_id=actor_id,
        from_state=current,
        to_state=target,
        note=note or "Risk acceptance withdrawn",
    )
    return finding


def expire_due_exceptions(db, *, org_id: Optional[str] = None, limit: int = 5000):
    """
    Return findings whose risk acceptance has run out to the remediation queue.

    Run on beat. Returns the number expired.

    An expired acceptance goes back to ``assigned`` when it still has an owner
    and ``open`` when it does not — not to ``verified_fixed`` and not to some
    "expired" state of its own, because the finding is simply outstanding again
    and the remediation queue is where outstanding findings belong.

    ``status`` returns to ``open`` alongside, so the dashboard and the asset
    risk score stop treating it as dealt with. Those two columns disagreeing is
    exactly the confusion this phase is meant to avoid.
    """
    from db.models.findings import AssetVulnerability

    now = _utcnow()
    query = db.query(AssetVulnerability).filter(
        AssetVulnerability.remediation_state == STATE_RISK_ACCEPTED,
        AssetVulnerability.exception_expires_at.isnot(None),
        AssetVulnerability.exception_expires_at <= now,
    )
    if org_id:
        query = query.filter(AssetVulnerability.org_id == org_id)

    expired = 0
    for finding in query.limit(limit).all():
        target = STATE_ASSIGNED if finding.remediation_owner else STATE_OPEN
        finding.remediation_state = target
        finding.status = "open"
        previous_expiry = finding.exception_expires_at
        finding.exception_expires_at = None
        record_event(
            db,
            finding,
            event_type=EVENT_EXCEPTION_EXPIRED,
            actor_id=None,
            actor_label=ACTOR_EXPIRY,
            from_state=STATE_RISK_ACCEPTED,
            to_state=target,
            note="Risk acceptance expired",
            details={
                "expired_at": previous_expiry.isoformat() if previous_expiry else None,
                "reason": finding.accepted_risk_reason,
            },
        )
        expired += 1

    if expired:
        log.info("Expired %d risk acceptance(s)", expired)
    return expired

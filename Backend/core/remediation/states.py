"""
core/remediation/states.py
─────────────────────────────────────────────────────────────────────────────
The remediation workflow vocabulary, and which transitions are legal.

Why this is a second column and not more values in ``status``
─────────────────────────────────────────────────────────────
``asset_vulnerabilities.status`` already exists with three values —
``open``, ``fixed``, ``accepted`` — and it answers a **detection** question:
*is this finding present on the host?* It is written by the scan sweeps, read
by the dashboard, the asset risk recompute, the findings list and GAP-13's
comparison, and something like a dozen places test ``status == "open"``.

``remediation_state`` answers a **workflow** question: *what is anybody doing
about it?* The two are genuinely independent — a finding can be present on the
host (``status = open``) while its fix is half-built (``in_remediation``), and
a finding can be absent from the latest scan (``status = fixed``) while nobody
has yet confirmed that the absence was a real fix rather than a scan that did
not look.

Adding ``in_remediation`` to ``status`` would have been smaller to write and
much worse: every ``status == "open"`` query in the product would silently stop
counting those findings, so putting a finding into remediation would remove it
from the dashboard, from the asset's risk score and from the overdue list. A
workflow column that makes findings disappear when you start working on them is
the opposite of what this gap is for.

The one place they must agree
─────────────────────────────
``VERIFIED_FIXED`` requires **both**: the assessment says the finding is gone
(``status = fixed``, set by a scan sweep) *and* the verification path confirmed
that the scan actually assessed the relevant check. Neither alone is enough,
and :mod:`core.remediation.verification` is the only thing that may set it.

Transitions are checked, and refusing them matters
──────────────────────────────────────────────────
:func:`assert_transition` refuses a move that would let a person write an
outcome only an assessment may establish. In particular there is **no**
transition from any state to ``VERIFIED_FIXED`` that a human action can take;
the only route in is :func:`core.remediation.verification.verify_from_comparison`
and the table says so by omission rather than by a comment somebody has to
remember to read.
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Tuple

__all__ = [
    "ACTIVE_STATES",
    "COLUMN_AREAS",
    "REMEDIATION_STATES",
    "STATE_AREAS",
    "STATE_ASSIGNED",
    "STATE_IN_REMEDIATION",
    "STATE_OPEN",
    "STATE_PENDING_VERIFICATION",
    "STATE_REOPENED",
    "STATE_RISK_ACCEPTED",
    "STATE_VERIFIED_FIXED",
    "TERMINAL_STATES",
    "TransitionError",
    "assert_transition",
    "can_transition",
    "is_active",
]

# ─────────────────────────────────────────────────────────────────────────────
# The vocabulary
# ─────────────────────────────────────────────────────────────────────────────

# The vocabulary itself lives in ``db.models.findings``, beside the column it
# constrains, and is imported here rather than declared. The models are the
# lower layer — this package reads ``core.findings.comparison``, which reads
# the models — so declaring the states here and importing them there is a
# circular import, which is exactly how the first version of this module
# failed. Same shape as ``db.models.compliance.CONTROL_THEMES``.
#
# What lives *here* is everything the model layer has no business knowing:
# which transitions are legal, and which of them only an assessment may make.
from db.models.findings import (  # noqa: E402
    REMEDIATION_STATE_ASSIGNED as STATE_ASSIGNED,
    REMEDIATION_STATE_IN_REMEDIATION as STATE_IN_REMEDIATION,
    REMEDIATION_STATE_OPEN as STATE_OPEN,
    REMEDIATION_STATE_PENDING_VERIFICATION as STATE_PENDING_VERIFICATION,
    REMEDIATION_STATE_REOPENED as STATE_REOPENED,
    REMEDIATION_STATE_RISK_ACCEPTED as STATE_RISK_ACCEPTED,
    REMEDIATION_STATE_VERIFIED_FIXED as STATE_VERIFIED_FIXED,
    REMEDIATION_STATES,
    REMEDIATION_STATE_SQL,
)

#: States where the clock is still running and the finding still needs work.
#: This is the set every SLA and overdue query filters on, so it lives here
#: rather than being spelled out at each call site.
ACTIVE_STATES: FrozenSet[str] = frozenset(
    {
        STATE_OPEN,
        STATE_ASSIGNED,
        STATE_IN_REMEDIATION,
        STATE_PENDING_VERIFICATION,
        STATE_REOPENED,
    }
)

#: States where no further remediation work is expected. ``risk_accepted`` is
#: here **and** can expire back out of it, which is the point of the expiry.
TERMINAL_STATES: FrozenSet[str] = frozenset({STATE_VERIFIED_FIXED, STATE_RISK_ACCEPTED})


def is_active(state: str) -> bool:
    """Whether a finding in *state* still needs remediation work."""
    return str(state or STATE_OPEN) in ACTIVE_STATES


# ─────────────────────────────────────────────────────────────────────────────
# Transitions
# ─────────────────────────────────────────────────────────────────────────────


class TransitionError(ValueError):
    """A remediation state change that is not allowed, with the reason."""


#: What a **human action** may do. Read this table for what it does *not*
#: contain: nothing reaches ``verified_fixed``. A person can say "I have
#: applied the fix" (``pending_verification``); only an assessment can say "it
#: is fixed", and that path does not go through here.
_HUMAN_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    STATE_OPEN: frozenset(
        {
            STATE_ASSIGNED,
            STATE_IN_REMEDIATION,
            STATE_PENDING_VERIFICATION,
            STATE_RISK_ACCEPTED,
        }
    ),
    STATE_ASSIGNED: frozenset(
        {
            STATE_OPEN,
            STATE_ASSIGNED,
            STATE_IN_REMEDIATION,
            STATE_PENDING_VERIFICATION,
            STATE_RISK_ACCEPTED,
        }
    ),
    STATE_IN_REMEDIATION: frozenset(
        {
            STATE_ASSIGNED,
            STATE_IN_REMEDIATION,
            STATE_PENDING_VERIFICATION,
            STATE_RISK_ACCEPTED,
            STATE_OPEN,
        }
    ),
    STATE_PENDING_VERIFICATION: frozenset(
        # Back to in_remediation is legitimate: the person realised the fix was
        # not complete before a scan ran. Forward to verified_fixed is not, and
        # its absence here is the control.
        {STATE_IN_REMEDIATION, STATE_ASSIGNED, STATE_RISK_ACCEPTED, STATE_OPEN}
    ),
    STATE_REOPENED: frozenset(
        {
            STATE_ASSIGNED,
            STATE_IN_REMEDIATION,
            STATE_PENDING_VERIFICATION,
            STATE_RISK_ACCEPTED,
            STATE_OPEN,
        }
    ),
    STATE_RISK_ACCEPTED: frozenset(
        # Withdrawing an acceptance returns the finding to the queue.
        {STATE_OPEN, STATE_ASSIGNED, STATE_IN_REMEDIATION}
    ),
    STATE_VERIFIED_FIXED: frozenset(
        # A verified-fixed finding that somebody wants to work on again is
        # reopened by an *assessment* finding it, not by a person deciding so.
        # Accepting the risk on one is meaningless — there is no risk left.
        set()
    ),
}

#: What the **verification path** may do, which is deliberately different.
#: Reached only from :mod:`core.remediation.verification`, which is the only
#: caller permitted to pass ``by_assessment=True``.
_ASSESSMENT_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    STATE_OPEN: frozenset({STATE_VERIFIED_FIXED}),
    STATE_ASSIGNED: frozenset({STATE_VERIFIED_FIXED}),
    STATE_IN_REMEDIATION: frozenset({STATE_VERIFIED_FIXED}),
    STATE_PENDING_VERIFICATION: frozenset({STATE_VERIFIED_FIXED}),
    STATE_REOPENED: frozenset({STATE_VERIFIED_FIXED}),
    STATE_VERIFIED_FIXED: frozenset({STATE_REOPENED}),
    # An accepted risk is not silently re-verified or reopened by a scan. The
    # organisation made a decision; an assessment noticing the finding again is
    # not new information, and quietly overriding it would erase a decision
    # somebody is accountable for. Expiry is what ends an acceptance.
    STATE_RISK_ACCEPTED: frozenset(),
}


def can_transition(current: str, target: str, *, by_assessment: bool = False) -> bool:
    """Whether *current* → *target* is permitted for this kind of actor."""
    table = _ASSESSMENT_TRANSITIONS if by_assessment else _HUMAN_TRANSITIONS
    return target in table.get(str(current or STATE_OPEN), frozenset())


def assert_transition(
    current: str, target: str, *, by_assessment: bool = False
) -> None:
    """
    Raise :class:`TransitionError` unless the transition is permitted.

    The message names both states and, for the one case that matters most,
    says explicitly why a person cannot make it — so the refusal reads as a
    designed control rather than as a missing feature.
    """
    current = str(current or STATE_OPEN)
    target = str(target or "")

    if target not in REMEDIATION_STATES:
        raise TransitionError(
            f"{target!r} is not a remediation state. Known states: "
            + ", ".join(REMEDIATION_STATES)
        )

    if can_transition(current, target, by_assessment=by_assessment):
        return

    if target == STATE_VERIFIED_FIXED and not by_assessment:
        raise TransitionError(
            "A finding cannot be marked verified fixed by hand. It becomes "
            "verified when a subsequent scan actually assesses the relevant "
            "check and reports it gone. Move it to "
            f"{STATE_PENDING_VERIFICATION!r} to say the fix has been applied."
        )

    if current == STATE_VERIFIED_FIXED:
        raise TransitionError(
            f"This finding was verified fixed by an assessment; it cannot be "
            f"moved to {target!r} by hand. If it has returned, a scan will "
            f"reopen it."
        )

    raise TransitionError(f"Cannot move a finding from {current!r} to {target!r}.")


# ─────────────────────────────────────────────────────────────────────────────
# Coverage wiring
# ─────────────────────────────────────────────────────────────────────────────

#: Which coverage area each state answers, read by
#: ``scripts/measure_remediation_coverage.py``. Declared beside the states so
#: an area cannot claim coverage from a state that was removed.
STATE_AREAS: Dict[str, str] = {
    STATE_OPEN: "rem.state.open",
    STATE_ASSIGNED: "rem.state.assigned",
    STATE_IN_REMEDIATION: "rem.state.in_progress",
    STATE_PENDING_VERIFICATION: "rem.state.pending_verification",
    STATE_VERIFIED_FIXED: "rem.state.verified",
    STATE_REOPENED: "rem.state.reopened",
    STATE_RISK_ACCEPTED: "rem.state.risk_accepted",
}

#: Which coverage area each finding column answers.
COLUMN_AREAS: Dict[str, str] = {
    "remediation_owner": "rem.own.assign",
    "sla_due_at": "rem.sla.by_severity",
    "remediation_state": "rem.state.open",
    "exception_expires_at": "rem.exc.expiry",
}

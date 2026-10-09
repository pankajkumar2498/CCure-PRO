"""
:class:`AssessmentVerdictsView` → ``ControlResult`` items, and a page of them.

The roll-up is the contract's: per asset, then per rule and per control, with
the precedence ``FAIL > ERROR > NOT_ASSESSED > MANUAL_REVIEW > PASS >
NOT_APPLICABLE`` — a confirmed failure is reported whatever else is unknown,
and anything unknown outranks a pass.

Which assets count towards a rule, and this is the decision that keeps a PASS
earned:

* an **assessed** host counts towards a rule only if it stored a result for
  it. A host the scan's policy did not select a check for (a Linux host and a
  Windows rule) has no result, and counting it as NOT_ASSESSED would make every
  control in a mixed estate unpassable;
* a host whose configuration audit **did not run** counts as NOT_ASSESSED
  towards *every* rule and control in the result, with the engine's own
  reason. Nobody can say which checks would have applied to it, and leaving it
  out would let a control pass on the hosts that were reached while the rest
  were never looked at.

What this mapper cannot say, and does not pretend to:

* A control appears only if some host stored a verdict record for a check
  mapped to it. An assessment whose audit ran nowhere produces **no** control
  results; that is a statement about coverage, which belongs to
  ``AssessmentResult.assets`` (not mapped in Phase 5), not a clean result.
* ``basis`` is always ``automated`` and ``disposition`` always ``none``:
  scan verdicts are automated by construction, and attestations and
  dispositions live in the compliance register, which this view does not read.
* ``finding_refs`` and ``evidence_refs`` are null — the contract's "not
  implemented". A FAIL's finding id is minted by ``core`` and the evidence
  store has no identifiers yet; an empty list would claim there are none.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ccure_audit.integration import vocabulary as vocab
from ccure_audit.integration.envelope import EnvelopeContext, envelope
from ccure_audit.integration.errors import MappingError
from ccure_audit.integration.mappers._common import build, control_ref
from ccure_audit.services.assessment_read import (
    AssessmentVerdictsView,
    CheckVerdictView,
    ControlRefView,
)
from ccure_contracts.assessment_result.v1.models import CcureAssessmentControlsPageV1
from ccure_contracts.common.v1.assessment import CcureControlResultV1

CONTROLS_PAGE_CONTRACT = "ccure.audit.assessment_controls_page"

#: Highest first.
PRECEDENCE: Tuple[str, ...] = (
    "FAIL",
    "ERROR",
    "NOT_ASSESSED",
    "MANUAL_REVIEW",
    "PASS",
    "NOT_APPLICABLE",
)
_RANK = {state: i for i, state in enumerate(PRECEDENCE)}
_COUNT_KEYS = {
    "PASS": "PASS",
    "FAIL": "FAIL",
    "NOT_ASSESSED": "NOT_ASSESSED",
    "NOT_APPLICABLE": "NOT_APPLICABLE",
    "MANUAL_REVIEW": "MANUAL_REVIEW",
    "ERROR": "ERROR",
}
_VERDICTS = ("PASS", "FAIL")


def roll_up(states: Iterable[str]) -> str:
    """The highest-precedence state; there must be at least one."""
    ranked = sorted(states, key=_RANK.__getitem__)
    if not ranked:
        raise ValueError("nothing to roll up")
    return ranked[0]


@dataclass
class _Reading:
    """One host's state for one rule, and why."""

    state: str
    reason: str = ""
    result: Optional[CheckVerdictView] = None


@dataclass
class _Rule:
    rule_id: str
    title: str
    severity: str
    by_host: Dict[str, List[_Reading]] = field(
        default_factory=lambda: defaultdict(list)
    )


@dataclass
class _Control:
    ref: ControlRefView
    rules: Dict[str, _Rule] = field(default_factory=dict)


def _reading(result: CheckVerdictView) -> _Reading:
    state = vocab.assessment_state(result.outcome)
    if not vocab.is_known_outcome(result.outcome):
        reason = f"Stored outcome {result.outcome!r} is not one this build defines."
    elif state == "ERROR":
        reason = result.error or "The check could not be evaluated."
    elif state == "NOT_APPLICABLE":
        reason = result.not_applicable_reason or "Not applicable to this asset."
    elif state == "MANUAL_REVIEW":
        reason = result.error or "Needs a human decision."
    elif state == "NOT_ASSESSED":
        reason = "The stored verdict record carries no outcome."
    else:
        reason = ""
    return _Reading(state=state, reason=reason, result=result)


def _counts(states: Iterable[str]) -> Dict[str, int]:
    tally = Counter(states)
    return {key: tally.get(state, 0) for state, key in _COUNT_KEYS.items()}


def _explain(state: str, per_host: Dict[str, _Reading], total: int) -> Optional[str]:
    """Why a non-verdict state, from the hosts that carried it."""
    if state in _VERDICTS:
        return None
    hosts = sorted(h for h, r in per_host.items() if r.state == state)
    first = next((per_host[h].reason for h in hosts if per_host[h].reason), "")
    text = f"{state} on {len(hosts)} of {total} asset(s)"
    return vocab.short_text(f"{text}: {first}" if first else f"{text}.")


def _host_reading(readings: Sequence[_Reading]) -> _Reading:
    state = roll_up(r.state for r in readings)
    return next(r for r in readings if r.state == state)


def _gap_description(control: _Control) -> Optional[str]:
    lines: List[str] = []
    for rule in sorted(control.rules.values(), key=lambda r: r.rule_id):
        failing = sorted(
            (host, r)
            for host, readings in rule.by_host.items()
            for r in readings
            if r.state == "FAIL"
        )
        if not failing:
            continue
        host, reading = failing[0]
        detail = ""
        if reading.result is not None:
            expected, observed = reading.result.expected, reading.result.observed
            if expected or observed:
                detail = f" — expected {expected or 'unstated'}, observed {observed or 'unstated'}"
        lines.append(
            f"{rule.title}: failed on {len({h for h, _ in failing})} asset(s), "
            f"e.g. {host}{detail}"
        )
    return vocab.long_text("\n".join(lines)) if lines else None


def _collect(view: AssessmentVerdictsView) -> Dict[str, _Control]:
    controls: Dict[str, _Control] = {}
    for host in view.hosts:
        if not host.assessed:
            continue
        name = host.host or ""
        for result in host.results:
            reading = _reading(result)
            target = name or result.target
            for ref in result.controls:
                control = controls.setdefault(ref.control_id, _Control(ref=ref))
                rule = control.rules.get(result.check_id)
                if rule is None:
                    rule = control.rules[result.check_id] = _Rule(
                        rule_id=result.check_id,
                        title=vocab.short_text(result.title, fallback=result.check_id),
                        severity=vocab.severity(result.severity),
                    )
                rule.by_host[target].append(reading)
    unassessed = [h for h in view.hosts if not h.assessed]
    for control in controls.values():
        for rule in control.rules.values():
            for host in unassessed:
                rule.by_host[host.host].append(
                    _Reading(
                        state="NOT_ASSESSED",
                        reason=host.reason
                        or "The configuration audit did not run on this asset.",
                    )
                )
    return controls


def _control_result(control: _Control) -> dict:
    ref = control.ref
    where = f"control {ref.control_id} ({ref.framework_id})"
    rules: List[dict] = []
    per_host_rules: Dict[str, List[_Reading]] = defaultdict(list)
    for rule in sorted(control.rules.values(), key=lambda r: r.rule_id):
        per_host = {h: _host_reading(rs) for h, rs in rule.by_host.items()}
        for h, r in per_host.items():
            per_host_rules[h].append(r)
        state = roll_up(r.state for r in per_host.values())
        rules.append(
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "state": state,
                "asset_counts": _counts(r.state for r in per_host.values()),
                "reason": _explain(state, per_host, len(per_host)),
            }
        )
    per_host = {h: _host_reading(rs) for h, rs in per_host_rules.items()}
    state = roll_up(r.state for r in per_host.values())
    return {
        "control": control_ref(
            ref.framework_code, ref.framework_version, ref.control_number, where
        ),
        "requirement_id": None,
        "state": state,
        "state_reason": _explain(state, per_host, len(per_host)),
        "basis": "automated",
        "disposition": "none",
        "asset_counts": _counts(r.state for r in per_host.values()),
        "rules": rules,
        "gap_description": _gap_description(control) if state == "FAIL" else None,
        "finding_refs": None,
        "evidence_refs": None,
    }


def control_results(view: AssessmentVerdictsView) -> Tuple[CcureControlResultV1, ...]:
    """
    One result per framework control the assessment stored a verdict for,
    ordered by framework and published control identifier.
    """
    controls = _collect(view)
    seen: Dict[Tuple[str, str, str], str] = {}
    for cid, control in controls.items():
        key = (
            control.ref.framework_code,
            control.ref.framework_version,
            control.ref.control_number,
        )
        if key in seen:
            raise MappingError(
                f"controls {seen[key]} and {cid} publish the same identifier {key}; "
                "a consumer could not tell their results apart"
            )
        seen[key] = cid
    ordered = sorted(
        controls.items(),
        key=lambda kv: (
            kv[1].ref.framework_code,
            kv[1].ref.framework_version,
            kv[1].ref.control_number,
            kv[0],
        ),
    )
    return tuple(
        build(
            CcureControlResultV1,
            _control_result(control),
            f"control {cid} of assessment {view.scan_id}",
        )
        for cid, control in ordered
    )


def controls_page(
    items: Sequence[CcureControlResultV1],
    *,
    result_id: str,
    ctx: EnvelopeContext,
    next_cursor: Optional[str] = None,
) -> CcureAssessmentControlsPageV1:
    return build(
        CcureAssessmentControlsPageV1,
        {
            **envelope(CONTROLS_PAGE_CONTRACT, ctx),
            "result_id": result_id,
            "items": list(items),
            "position": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
        f"controls page of {result_id}",
    )

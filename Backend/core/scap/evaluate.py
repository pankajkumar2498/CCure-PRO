"""
core/scap/evaluate.py
─────────────────────────────────────────────────────────────────────────────
Evaluating a compiled OVAL definition against a live target.

Three-valued, deliberately
──────────────────────────
:class:`Outcome` is TRUE, FALSE or **UNKNOWN**, and the third is the whole
point. OVAL itself defines six result values; the distinction that matters to
this product is between a result and the absence of one. A test whose object
could not be collected has established nothing, and folding that into FALSE
invents a finding while folding it into TRUE hides one. UNKNOWN propagates
through the criteria tree and surfaces as an ERROR result — the Phase 3 rule,
one layer down.

The truth tables below are the ones OVAL 5.11 §5.3 specifies, restricted to
three values. Where a combination could still be decided despite an unknown —
``OR`` with a TRUE in it, ``AND`` with a FALSE — it *is* decided, because the
unknown cannot change the answer. Returning UNKNOWN there would lose real
verdicts on hosts where one unrelated file happened to be unreadable.

What a definition means
───────────────────────
Benchmark OVAL is written so that **TRUE means the host is in the state the
rule describes** — the state the benchmark wants. So TRUE is a pass and FALSE
is a fail. That is the ``@class="compliance"`` convention SSG and DISA both
use, and it is asserted rather than assumed: a definition whose class is
``vulnerability`` or ``patch`` inverts, and is refused by the converter rather
than scored backwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from core.config_audit.collection import CollectionContext
from core.scap.probes import ProbeResult, collect_object

__all__ = [
    "DefinitionResult",
    "Outcome",
    "evaluate_applicability",
    "evaluate_definition",
]

#: ``compare(left, right)`` → negative, zero or positive, or None when the two
#: cannot be ordered: ``CollectionContext.version_compare``.
VersionCompare = Callable[[str, str], Optional[int]]


class Outcome(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DefinitionResult:
    """The verdict, plus enough detail for a finding to be actionable."""

    outcome: Outcome
    #: Why, in one sentence. For a FALSE this names the test that decided it;
    #: for an UNKNOWN it names what could not be read.
    detail: str = ""
    #: Per-test notes, in evaluation order, for the evidence payload.
    notes: Tuple[str, ...] = ()

    @property
    def is_verdict(self) -> bool:
        return self.outcome in (Outcome.TRUE, Outcome.FALSE)


# ─────────────────────────────────────────────────────────────────────────────
# Value coercion and comparison
# ─────────────────────────────────────────────────────────────────────────────

_TRUE_TOKENS = ("true", "1", "yes", "on")
_FALSE_TOKENS = ("false", "0", "no", "off")


def _as_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE_TOKENS:
        return True
    if text in _FALSE_TOKENS:
        return False
    return None


def _as_number(value: Any) -> Optional[float]:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _version_compare(
    left: Any, right: Any, compare: Optional[VersionCompare]
) -> Optional[int]:
    """
    Order two version strings with the comparator the context was given.

    That is the package matcher's rpmvercmp implementation
    (``compare_distro_versions``), passed in by whoever built the context
    rather than imported (B10), and not a second implementation. Epoch handling
    and ``~`` ordering are what make an EVR comparison correct, and CLAUDE.md
    records what a naive comparison cost the last time: a backported fix
    compared equal to the vulnerable version it fixed, on the distributions
    that backport nearly everything.

    No comparator means the comparison cannot be made: None, which the caller
    reads as unknown. Falling back to a naive order would be the defect above.
    """
    if compare is None:
        return None
    return compare(str(left), str(right))


def _compare(
    actual: Any,
    operation: str,
    expected: Any,
    datatype: str,
    version_compare: Optional[VersionCompare] = None,
) -> Optional[bool]:
    """
    One OVAL comparison. ``None`` means it could not be performed.

    None is never turned into False by a caller. A comparison that could not
    run has established nothing about the host, and reporting that as a failed
    condition is the defect this whole module is arranged to avoid.
    """
    if operation == "pattern match":
        try:
            return re.search(str(expected), str(actual)) is not None
        except re.error:
            return None

    if operation in ("case insensitive equals", "case insensitive not equal"):
        equal = str(actual).strip().lower() == str(expected).strip().lower()
        return equal if operation == "case insensitive equals" else not equal

    if datatype == "record":
        # A WMI row against the fields the content names. Every field the state
        # declares must be present on the row and equal; a field the row does
        # not carry is UNKNOWN, never False, because "this build did not
        # collect that column" is not "the host disagrees".
        if not isinstance(expected, Mapping):
            return None
        if not isinstance(actual, Mapping):
            return None
        if operation not in ("equals", "case insensitive equals"):
            return None
        lowered = {str(k).strip().lower(): v for k, v in actual.items()}
        for field, want in expected.items():
            key = str(field).strip().lower()
            if key not in lowered:
                return None
            got = str(lowered[key]).strip()
            wanted = str(want).strip()
            if operation == "case insensitive equals":
                if got.lower() != wanted.lower():
                    return False
            elif got != wanted:
                return False
        return True

    if datatype == "boolean":
        left, right = _as_bool(actual), _as_bool(expected)
        if left is None or right is None:
            return None
        if operation == "equals":
            return left == right
        if operation == "not equal":
            return left != right
        return None

    if datatype in ("version", "evr_string", "debian_evr_string", "ios_version"):
        order = _version_compare(actual, expected, version_compare)
        if order is None:
            return None
        return _from_order(order, operation)

    if datatype in ("int", "float"):
        left_num, right_num = _as_number(actual), _as_number(expected)
        if left_num is None or right_num is None:
            return None
        order = (left_num > right_num) - (left_num < right_num)
        return _from_order(order, operation)

    left_text, right_text = str(actual), str(expected)
    if operation == "equals":
        return left_text == right_text
    if operation == "not equal":
        return left_text != right_text
    order = (left_text > right_text) - (left_text < right_text)
    return _from_order(order, operation)


def _from_order(order: int, operation: str) -> Optional[bool]:
    return {
        "equals": order == 0,
        "not equal": order != 0,
        "greater than": order > 0,
        "greater than or equal": order >= 0,
        "less than": order < 0,
        "less than or equal": order <= 0,
    }.get(operation)


def _entity_check(results: Sequence[Optional[bool]], mode: str) -> Optional[bool]:
    """Fold one entity's per-value results according to ``entity_check``."""
    if not results:
        return None
    if any(value is None for value in results):
        # One uncomparable value can still leave the answer decided: "at least
        # one" is satisfied by a value that already matched, and "none satisfy"
        # is refuted by one.
        decided = [value for value in results if value is not None]
        if mode == "at least one" and any(decided):
            return True
        if mode == "none satisfy" and any(decided):
            return False
        return None
    if mode == "all":
        return all(results)
    if mode == "at least one":
        return any(results)
    if mode == "none satisfy":
        return not any(results)
    if mode == "only one":
        return sum(1 for value in results if value) == 1
    return None


def _fold_three_valued(
    outcomes: Sequence[Optional[bool]], operator: str
) -> Optional[bool]:
    """Combine tri-state results under an OVAL operator.

    ``None`` is "not established", and it is absorbing only where it could
    still change the answer: an OR already holding a True is True whatever the
    rest turned out to be, and an AND already holding a False is False.
    """
    if not outcomes:
        return None
    if str(operator).upper() == "OR":
        if any(value is True for value in outcomes):
            return True
        return None if any(value is None for value in outcomes) else False
    if any(value is False for value in outcomes):
        return False
    return None if any(value is None for value in outcomes) else True


def _item_satisfies(
    item: Mapping[str, Any],
    state: Mapping[str, Any],
    version_compare: Optional[VersionCompare] = None,
) -> Optional[bool]:
    """Whether one collected item is in the state the rule describes."""
    operator = str(state.get("operator") or "AND").upper()
    outcomes: List[Optional[bool]] = []
    for spec in state.get("fields") or []:
        name = str(spec.get("name") or "")
        if name not in item:
            # The probe does not produce this entity at all. That is a gap in
            # this build, not a property of the host, so it must not decide
            # the check.
            outcomes.append(None)
            continue
        actual = item[name]
        actuals = actual if isinstance(actual, (list, tuple)) else [actual]
        expected_values = (spec.get("value") or {}).get("values") or []
        operation = str(spec.get("operation") or "equals")
        datatype = str(spec.get("datatype") or "string")
        mode = str(spec.get("entity_check") or "all")

        per_value: List[Optional[bool]] = []
        for one in actuals:
            # A state entity carrying several values (from a variable) is
            # satisfied when any of them matches; that is what a variable
            # holding a set of acceptable answers means.
            matched = [
                _compare(one, operation, expected, datatype, version_compare)
                for expected in expected_values
            ]
            if not matched:
                per_value.append(None)
            elif any(value is True for value in matched):
                per_value.append(True)
            elif any(value is None for value in matched):
                per_value.append(None)
            else:
                per_value.append(False)
        outcomes.append(_entity_check(per_value, mode))

    return _fold_three_valued(outcomes, operator)


# ─────────────────────────────────────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────────────────────────────────────


def _existence_holds(count: int, mode: str) -> bool:
    return {
        "all_exist": count > 0,
        "any_exist": True,
        "at_least_one_exists": count >= 1,
        "none_exist": count == 0,
        "only_one_exists": count == 1,
    }.get(mode, count >= 1)


def _apply_filters(
    items: Sequence[Mapping[str, Any]],
    obj: Mapping[str, Any],
    compiled: Mapping[str, Any],
    version_compare: Optional[VersionCompare] = None,
) -> Tuple[Tuple[Mapping[str, Any], ...], str]:
    """
    Narrow a collected item set by the object's ``<filter>`` elements.

    A filter is a state plus an action, applied **after** collection — so it is
    the same comparison machinery the tests use, pointed at the item set rather
    than at the verdict. ``exclude`` drops the items that satisfy the state,
    ``include`` keeps only those that do.

    An item whose filter state cannot be compared makes the whole test unknown
    rather than being silently kept or dropped. Keeping it would inflate every
    ``none_exist`` check; dropping it would satisfy them. Neither is a reading,
    and existence checks are decided entirely by how many items survive here.
    """
    filters = obj.get("filters") or []
    if not filters:
        return tuple(items), ""
    states = compiled.get("states") or {}
    surviving = list(items)
    for spec in filters:
        state_id = str(spec.get("state") or "")
        state = states.get(state_id)
        if not state:
            return (), f"filter references state {state_id}, which is missing"
        action = str(spec.get("action") or "exclude")
        kept: List[Mapping[str, Any]] = []
        for item in surviving:
            satisfied = _item_satisfies(item, state, version_compare)
            if satisfied is None:
                return (), (
                    "an item could not be compared against the object's "
                    "filter, so how many items the object selects was never "
                    "established"
                )
            if (action == "exclude" and not satisfied) or (
                action == "include" and satisfied
            ):
                kept.append(item)
        surviving = kept
    return tuple(surviving), ""


def _evaluate_test(
    ctx: CollectionContext,
    test: Mapping[str, Any],
    compiled: Mapping[str, Any],
    notes: List[Tuple[Outcome, str]],
) -> Outcome:
    object_id = str(test.get("object") or "")
    obj = (compiled.get("objects") or {}).get(object_id)
    if not obj:
        notes.append(
            (Outcome.UNKNOWN, f"object {object_id} is missing from the compiled rule")
        )
        return Outcome.UNKNOWN

    probe: ProbeResult = collect_object(ctx, obj)
    if not probe.ok:
        notes.append((Outcome.UNKNOWN, f"{obj.get('type')}: {probe.detail}"))
        return Outcome.UNKNOWN

    items, filter_failure = _apply_filters(
        probe.items, obj, compiled, ctx.version_compare
    )
    if filter_failure:
        notes.append((Outcome.UNKNOWN, f"{obj.get('type')}: {filter_failure}"))
        return Outcome.UNKNOWN
    probe = ProbeResult.collected(items, raw=probe.raw)

    existence = str(test.get("check_existence") or "at_least_one_exists")
    if not _existence_holds(len(probe.items), existence):
        notes.append(
            (
                Outcome.FALSE,
                f"{obj.get('type')}: {len(probe.items)} item(s) collected, "
                f"which does not satisfy {existence}",
            )
        )
        return Outcome.FALSE

    state_ids = [s for s in (test.get("states") or []) if s]
    if not state_ids or not probe.items:
        # Existence was the whole question, or there is nothing to compare
        # against because the existence rule permitted zero items.
        return Outcome.TRUE

    states = compiled.get("states") or {}
    per_item: List[Optional[bool]] = []
    for item in probe.items:
        item_results = [
            _item_satisfies(item, states[state_id], ctx.version_compare)
            for state_id in state_ids
            if state_id in states
        ]
        if len(item_results) != len(state_ids):
            notes.append(
                (
                    Outcome.UNKNOWN,
                    "a referenced state is missing from the compiled rule",
                )
            )
            return Outcome.UNKNOWN
        # `state_operator`, not a hard AND. See the note in oval.py: the DISA
        # content writes OR wherever a setting has more than one acceptable
        # answer, and ANDing alternatives is unsatisfiable rather than merely
        # strict. Rules compiled before this was carried have no such key and
        # default to AND, which is OVAL's own default -- those packs must be
        # re-loaded to pick the operator up.
        per_item.append(
            _fold_three_valued(item_results, str(test.get("state_operator") or "AND"))
        )

    check = str(test.get("check") or "all")
    folded = _entity_check(per_item, check)
    if folded is None:
        notes.append(
            (
                Outcome.UNKNOWN,
                f"{obj.get('type')}: the state comparison could not be "
                f"performed on {len(probe.items)} collected item(s)",
            )
        )
        return Outcome.UNKNOWN
    if not folded:
        offending = next(
            (item for item, value in zip(probe.items, per_item) if value is False),
            None,
        )
        notes.append(
            (
                Outcome.FALSE,
                (
                    f"{obj.get('type')}: {_describe(offending)} does not satisfy "
                    f"the required state"
                    if offending
                    else f"{obj.get('type')}: no collected item satisfies the "
                    f"required state"
                ),
            )
        )
        return Outcome.FALSE
    return Outcome.TRUE


def _describe(item: Optional[Mapping[str, Any]]) -> str:
    """A short, readable rendering of the item that decided a failure."""
    if not item:
        return "the collected item"
    for key in ("filepath", "name", "unit", "value"):
        if item.get(key):
            value = item[key]
            if key == "filepath" and item.get("text"):
                return f"{value}: {str(item['text']).strip()[:160]}"
            return str(value)[:160]
    return str(dict(item))[:160]


# ─────────────────────────────────────────────────────────────────────────────
# Criteria
# ─────────────────────────────────────────────────────────────────────────────


def _negate(outcome: Outcome) -> Outcome:
    if outcome is Outcome.TRUE:
        return Outcome.FALSE
    if outcome is Outcome.FALSE:
        return Outcome.TRUE
    return Outcome.UNKNOWN


def _combine(operator: str, outcomes: Sequence[Outcome]) -> Outcome:
    if operator == "AND":
        if any(o is Outcome.FALSE for o in outcomes):
            return Outcome.FALSE
        return (
            Outcome.UNKNOWN
            if any(o is Outcome.UNKNOWN for o in outcomes)
            else Outcome.TRUE
        )
    if operator == "OR":
        if any(o is Outcome.TRUE for o in outcomes):
            return Outcome.TRUE
        return (
            Outcome.UNKNOWN
            if any(o is Outcome.UNKNOWN for o in outcomes)
            else Outcome.FALSE
        )
    if operator == "ONE":
        trues = sum(1 for o in outcomes if o is Outcome.TRUE)
        if trues > 1:
            return Outcome.FALSE
        if any(o is Outcome.UNKNOWN for o in outcomes):
            return Outcome.UNKNOWN
        return Outcome.TRUE if trues == 1 else Outcome.FALSE
    if operator == "XOR":
        if any(o is Outcome.UNKNOWN for o in outcomes):
            return Outcome.UNKNOWN
        return (
            Outcome.TRUE
            if sum(1 for o in outcomes if o is Outcome.TRUE) % 2 == 1
            else Outcome.FALSE
        )
    return Outcome.UNKNOWN


def _evaluate_node(
    ctx: CollectionContext,
    node: Mapping[str, Any],
    compiled: Mapping[str, Any],
    notes: List[Tuple[Outcome, str]],
) -> Outcome:
    kind = str(node.get("kind") or "")
    if kind == "test":
        test_id = str(node.get("test") or "")
        test = (compiled.get("tests") or {}).get(test_id)
        if not test:
            notes.append(
                (Outcome.UNKNOWN, f"test {test_id} is missing from the compiled rule")
            )
            outcome = Outcome.UNKNOWN
        else:
            outcome = _evaluate_test(ctx, test, compiled, notes)
        return _negate(outcome) if node.get("negate") else outcome

    if kind == "criteria":
        outcomes = [
            _evaluate_node(ctx, child, compiled, notes)
            for child in node.get("children") or []
        ]
        if not outcomes:
            return Outcome.UNKNOWN
        combined = _combine(str(node.get("operator") or "AND").upper(), outcomes)
        return _negate(combined) if node.get("negate") else combined

    notes.append((Outcome.UNKNOWN, f"criteria node of kind {kind!r} is not evaluable"))
    return Outcome.UNKNOWN


def evaluate_applicability(
    ctx: CollectionContext, payload: Mapping[str, Any]
) -> Outcome:
    """
    Whether the host satisfies a rule's CPE platform applicability.

    TRUE means the rule applies, FALSE that it does not, UNKNOWN that this
    could not be established — and the third is why this returns an
    :class:`Outcome` rather than a bool. Reading "we could not tell whether
    this applies" as "it applies" puts the rule's verdict back into the
    false-positive class applicability exists to remove; reading it as "it does
    not" silently drops a control from the score.

    Results are memoised per host: a platform such as "is this a real system
    with a kernel" is asked by a hundred rules and its answer cannot differ
    between them.
    """
    definitions = payload.get("definitions") or {}
    cache = ctx.cache.setdefault("__scap_applicability__", {})

    def fact(definition_id: str) -> Outcome:
        if definition_id not in cache:
            compiled = definitions.get(definition_id)
            if not compiled:
                cache[definition_id] = Outcome.UNKNOWN
            else:
                cache[definition_id] = evaluate_definition(ctx, compiled).outcome
        return cache[definition_id]

    def walk(node: Mapping[str, Any]) -> Outcome:
        kind = str(node.get("kind") or "")
        if kind == "fact":
            return fact(str(node.get("definition") or ""))
        if kind != "logical":
            return Outcome.UNKNOWN
        children = [walk(child) for child in node.get("children") or []]
        if not children:
            return Outcome.UNKNOWN
        combined = _combine(str(node.get("operator") or "AND").upper(), children)
        return _negate(combined) if node.get("negate") else combined

    trees = payload.get("platforms") or []
    if not trees:
        return Outcome.TRUE
    return _combine(
        str(payload.get("operator") or "OR").upper(), [walk(tree) for tree in trees]
    )


def evaluate_definition(
    ctx: CollectionContext, compiled: Mapping[str, Any]
) -> DefinitionResult:
    """
    Evaluate one compiled definition against the target described by *ctx*.

    Never raises for a target-side problem: an unreadable file, an absent tool
    or a probe defect all become UNKNOWN with the reason recorded, which the
    collector renders as ERROR.
    """
    notes: List[Tuple[Outcome, str]] = []
    criteria = compiled.get("criteria") or {}
    if not criteria:
        return DefinitionResult(
            Outcome.UNKNOWN,
            "the compiled rule carries no criteria, so nothing could be " "evaluated",
        )
    outcome = _evaluate_node(ctx, criteria, compiled, notes)

    # **The first note is not necessarily the reason.** A definition whose
    # criteria are `A OR B` records A's ordinary failure before B's unknown, so
    # reporting note zero for an ERROR tells the reader the rule failed on
    # something that was in fact measured — and reporting it for a FAIL can
    # name a read that never happened. Each note therefore carries the outcome
    # it explains, and only a matching one is quoted.
    matching = [text for kind, text in notes if kind is outcome]
    if outcome is Outcome.UNKNOWN:
        fallback = "the rule could not be evaluated"
    elif outcome is Outcome.FALSE:
        fallback = "the host is not in the required state"
    else:
        return DefinitionResult(
            outcome,
            "the host is in the state the rule requires",
            tuple(text for _kind, text in notes[:12]),
        )
    detail = matching[0] if matching else fallback
    return DefinitionResult(outcome, detail, tuple(text for _kind, text in notes[:12]))

"""
core/config_audit/operators.py
─────────────────────────────────────────────────────────────────────────────
The single comparison vocabulary shared by the compliance rule engine and the
configuration audit engine.

Why this module exists at all
─────────────────────────────
``core/compliance_tasks._evaluate_operator`` already owned this vocabulary and
already drove every seeded compliance rule. Phase 3 needs the same comparisons
plus a handful more (regex, set membership, ranges, boolean coercion), and the
obvious way to get them — write a second evaluator inside the new engine — is
how a product ends up with two spellings of "greater than or equal" that
disagree on the string ``"07"``. CLAUDE.md records what two vocabularies for
one idea already cost this codebase in ``GROUP BY`` and in severity.

So the implementation moved here and ``_evaluate_operator`` became a thin
delegate. The shared operators keep their exact previous semantics, quirks
included, because the seeded rules already depend on them:

* comparison is case-insensitive and whitespace-stripped on both sides;
* a list *actual* with ``contains`` tests membership, but with any other
  operator falls through to comparing ``str(actual)`` — which is a strange
  thing to do and is nonetheless what the shipped rules were written against;
* a non-numeric operand under ``gte``/``lte``/``gt``/``lt`` yields False rather
  than raising.

``UNKNOWN_OPERATOR`` and the not-assessed direction
───────────────────────────────────────────────────
The previous implementation ended in a bare ``return False``, so a rule
carrying a misspelled operator evaluated to False, and the caller recorded
False as **fail**. A typo in a rule definition therefore manufactured a finding
against every host it was evaluated on — the same class of defect as evidence
that could not be collected being read as non-compliance.

:func:`evaluate` still returns a bool so the pre-Phase-3 contract is unchanged,
but :func:`evaluate_detailed` returns a tri-state so a caller that can express
"not assessed" is able to. The configuration engine uses the latter.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional, Sequence, Tuple

__all__ = [
    "COMPARISON_OPERATORS",
    "SHARED_OPERATORS",
    "ComparisonOutcome",
    "evaluate",
    "evaluate_detailed",
    "is_known_operator",
]


class ComparisonOutcome(str, Enum):
    """The three things a comparison can conclude."""

    TRUE = "true"
    FALSE = "false"
    #: The comparison could not be performed — an operator this module does not
    #: implement, or a rule-supplied pattern that will not compile.
    #: Deliberately not False: a rule nobody can evaluate has not established
    #: that the host is non-compliant.
    UNKNOWN_OPERATOR = "unknown_operator"


#: Operators that existed before Phase 3 and whose semantics are frozen by the
#: seeded rule catalogue. ``tests/scans/test_config_audit_operators.py`` pins
#: every one of them against a truth table evaluated through both entry points.
SHARED_OPERATORS: Tuple[str, ...] = (
    "equals",
    "==",
    "not_equals",
    "contains",
    "not_contains",
    "gte",
    "lte",
    "gt",
    "lt",
    "version_gte",
    "version_lte",
    "is_empty",
    "not_empty",
)

#: Operators added by the configuration audit engine. New ones may be added
#: here; none of the above may change meaning.
_CONFIG_OPERATORS: Tuple[str, ...] = (
    "matches",
    "not_matches",
    "in",
    "not_in",
    "between",
    "starts_with",
    "ends_with",
    "is_true",
    "is_false",
)

COMPARISON_OPERATORS: Tuple[str, ...] = SHARED_OPERATORS + _CONFIG_OPERATORS

#: Spellings a configuration source uses for a boolean. Registry DWORDs arrive
#: as 1/0, PowerShell as True/False, INI and sshd_config as yes/no or on/off,
#: and a rule author should not have to know which of the three a given
#: collector emits.
_TRUE_TOKENS = frozenset({"1", "true", "yes", "on", "enabled", "enable"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "off", "disabled", "disable"})


def is_known_operator(operator: str) -> bool:
    return str(operator or "").strip().lower() in COMPARISON_OPERATORS


def _as_str_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip().lower() for x in value]
    return [str(value).strip().lower()]


def _coerce_bool(value: Any) -> Optional[bool]:
    """
    Interpret a collected value as a boolean, or None where it plainly is not
    one. None rather than False: a value nobody can read as a boolean has not
    established that the setting is off.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    token = str(value).strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    return None


def _parse_version(value: Any) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", str(value))]


def _b(value: bool) -> ComparisonOutcome:
    return ComparisonOutcome.TRUE if value else ComparisonOutcome.FALSE


def evaluate_detailed(
    operator: str, actual: Any, expected: Any = None
) -> ComparisonOutcome:
    """
    Compare *actual* against *expected*, reporting an unimplemented operator
    distinctly from a comparison that came out false.
    """
    op = str(operator or "").strip().lower()

    # Emptiness is a verdict in its own right and has to be decided before the
    # None guard: "this host lists no NTP server" and "this host was never
    # asked about NTP" are different findings, and only the caller's
    # missing-value check can tell them apart. By the time a value reaches
    # here, an empty list is an observation.
    if op in ("not_empty", "is_empty"):
        empty = actual is None or (
            len(actual) == 0
            if isinstance(actual, (list, tuple, set, dict, str))
            else False
        )
        return _b(empty if op == "is_empty" else not empty)

    if op in ("is_true", "is_false"):
        coerced = _coerce_bool(actual)
        if coerced is None:
            return ComparisonOutcome.FALSE
        return _b(coerced is (op == "is_true"))

    if not is_known_operator(op):
        return ComparisonOutcome.UNKNOWN_OPERATOR

    if actual is None:
        return ComparisonOutcome.FALSE

    expected_str_list = _as_str_list(expected)
    expected_str = expected_str_list[0] if expected_str_list else ""

    # 1. Actual value is list-like (open ports, NTP servers, group members).
    if isinstance(actual, (list, tuple, set)):
        actual_str_list = [str(x).strip().lower() for x in actual]
        if op == "contains":
            return _b(any(exp in actual_str_list for exp in expected_str_list))
        if op == "not_contains":
            return _b(not any(exp in actual_str_list for exp in expected_str_list))
        if op == "in":
            return _b(all(act in expected_str_list for act in actual_str_list))
        if op == "not_in":
            return _b(not any(act in expected_str_list for act in actual_str_list))

    # 2. Actual value is a scalar.
    actual_str = str(actual).strip().lower()

    if op in ("equals", "=="):
        return _b(actual_str == expected_str)
    if op == "not_equals":
        return _b(actual_str != expected_str)
    if op == "contains":
        return _b(any(exp in actual_str for exp in expected_str_list))
    if op == "not_contains":
        return _b(not any(exp in actual_str for exp in expected_str_list))
    if op == "in":
        return _b(actual_str in expected_str_list)
    if op == "not_in":
        return _b(actual_str not in expected_str_list)
    if op == "starts_with":
        return _b(any(actual_str.startswith(exp) for exp in expected_str_list))
    if op == "ends_with":
        return _b(any(actual_str.endswith(exp) for exp in expected_str_list))

    if op in ("matches", "not_matches"):
        # An unparseable pattern is a defect in the rule, not a property of the
        # host, so it reports as unknown rather than as a passing or failing
        # comparison.
        try:
            hit = re.search(str(expected), str(actual), re.IGNORECASE) is not None
        except re.error:
            return ComparisonOutcome.UNKNOWN_OPERATOR
        return _b(hit if op == "matches" else not hit)

    if op in ("gte", "lte", "gt", "lt"):
        try:
            act_num = float(actual)
            exp_num = float(expected)
        except (ValueError, TypeError):
            return ComparisonOutcome.FALSE
        if op == "gte":
            return _b(act_num >= exp_num)
        if op == "lte":
            return _b(act_num <= exp_num)
        if op == "gt":
            return _b(act_num > exp_num)
        return _b(act_num < exp_num)

    if op == "between":
        bounds: Sequence[Any] = (
            expected if isinstance(expected, (list, tuple)) else (expected,)
        )
        if len(bounds) != 2:
            return ComparisonOutcome.UNKNOWN_OPERATOR
        try:
            act_num = float(actual)
            low = float(bounds[0])
            high = float(bounds[1])
        except (ValueError, TypeError):
            return ComparisonOutcome.FALSE
        return _b(low <= act_num <= high)

    if op in ("version_gte", "version_lte"):
        try:
            act_v = _parse_version(actual)
            exp_v = _parse_version(expected)
        except Exception:
            return ComparisonOutcome.FALSE
        return _b(act_v >= exp_v if op == "version_gte" else act_v <= exp_v)

    # Reached only if an operator is named in COMPARISON_OPERATORS and not
    # handled above — a programming error in this module rather than in a rule.
    return ComparisonOutcome.UNKNOWN_OPERATOR


def evaluate(operator: str, actual: Any, expected: Any = None) -> bool:
    """
    Boolean form, preserving the pre-Phase-3 contract exactly: anything that is
    not definitely true is False, including an operator this module does not
    implement.

    New code should prefer :func:`evaluate_detailed`, which can distinguish
    "false" from "could not be compared".
    """
    return evaluate_detailed(operator, actual, expected) is ComparisonOutcome.TRUE

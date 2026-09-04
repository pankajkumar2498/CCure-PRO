"""
tests/scans/test_config_audit_operators.py
─────────────────────────────────────────────────────────────────────────────
The comparison vocabulary, and the guard against it forking.

Phase 3 moved ``core/compliance_tasks._evaluate_operator`` into
``core/config_audit/operators.py`` and left the original behind as
``_evaluate_operator_legacy``. That is not dead code — it is the reference
these tests compare against. Asserting the new implementation's behaviour
directly would pass just as happily if the move had changed the meaning of
``gte`` for the 72 seeded compliance rules that depend on it; comparing the two
over a truth table is what actually holds the move to being a move.
"""

import pytest

from core.compliance_tasks import _evaluate_operator, _evaluate_operator_legacy
from core.config_audit.operators import (
    COMPARISON_OPERATORS,
    SHARED_OPERATORS,
    ComparisonOutcome,
    evaluate,
    evaluate_detailed,
    is_known_operator,
)

#: Values chosen to cover every branch the two implementations contain:
#: list-like and scalar actuals, numeric and non-numeric strings, empty
#: containers, None, booleans, and an expected side that is itself a list.
_ACTUALS = [
    None,
    "",
    "0",
    "1",
    "yes",
    "Enabled",
    " Running ",
    "14",
    "07",
    7,
    14,
    0,
    True,
    False,
    [],
    ["22", "80"],
    ["telnet"],
    ("a",),
    {},
    {"k": "v"},
    "1.2.3",
    "10.0.26200.9168",
]

_EXPECTEDS = [
    None,
    "",
    "0",
    "1",
    "14",
    14,
    7,
    "running",
    "telnet",
    ["22", "443"],
    ["no", "prohibit-password"],
    "1.2.4",
    True,
]


@pytest.mark.parametrize("operator", SHARED_OPERATORS)
def test_shared_operators_agree_with_the_pre_phase3_implementation(operator):
    """
    The move must not have changed a single verdict for the operators the
    seeded rule catalogue already uses.

    A disagreement here means a compliance rule that passed yesterday fails
    today, or the reverse, with no rule having been edited.
    """
    disagreements = []
    for actual in _ACTUALS:
        for expected in _EXPECTEDS:
            legacy = _evaluate_operator_legacy(operator, actual, expected)
            shared = evaluate(operator, actual, expected)
            if legacy != shared:
                disagreements.append(
                    f"{operator}(actual={actual!r}, expected={expected!r}): "
                    f"legacy={legacy} shared={shared}"
                )
    assert not disagreements, "\n".join(disagreements)


def test_compliance_entry_point_delegates_rather_than_duplicating():
    """
    ``_evaluate_operator`` must be the delegate, not a second copy that
    happens to agree today.
    """
    for operator in SHARED_OPERATORS:
        for actual in _ACTUALS[:8]:
            assert _evaluate_operator(operator, actual, "1") == evaluate(
                operator, actual, "1"
            )


class TestSharedSemanticsAreExactlyPreserved:
    """Specific quirks the seeded rules were written against."""

    def test_comparison_is_case_insensitive_and_stripped(self):
        assert evaluate("equals", " Running ", "running") is True

    def test_missing_value_is_false_not_an_error(self):
        assert evaluate("equals", None, "1") is False

    def test_emptiness_is_decided_before_the_none_guard(self):
        # "this host lists no NTP server" is an observation; it must not be
        # collapsed into "this host was never asked".
        assert evaluate("is_empty", [], None) is True
        assert evaluate("is_empty", None, None) is True
        assert evaluate("not_empty", ["ntp1"], None) is True

    def test_list_actual_with_contains_tests_membership(self):
        assert evaluate("contains", ["22", "80"], "80") is True
        assert evaluate("not_contains", ["22", "80"], "23") is True

    def test_non_numeric_operand_under_gte_is_false_not_a_crash(self):
        assert evaluate("gte", "abc", 14) is False
        assert evaluate("gte", ["a"], 14) is False

    def test_numeric_comparison_is_numeric_not_lexical(self):
        # "07" < "1" lexically, 7 > 1 numerically. The rules mean the latter.
        assert evaluate("gt", "07", "1") is True

    def test_version_comparison_ignores_non_numeric_separators(self):
        assert evaluate("version_gte", "10.0.26200.9168", "10.0.26100.0") is True
        assert evaluate("version_lte", "1.2.3", "1.2.4") is True


class TestOperatorsAddedByPhase3:
    def test_in_and_not_in_test_set_membership(self):
        assert evaluate("in", "prohibit-password", ["no", "prohibit-password"]) is True
        assert evaluate("in", "yes", ["no", "prohibit-password"]) is False
        assert evaluate("not_in", "yes", ["no"]) is True

    def test_in_over_a_list_actual_requires_every_member(self):
        assert evaluate("in", ["22", "443"], ["22", "443", "80"]) is True
        assert evaluate("in", ["22", "23"], ["22", "443"]) is False

    def test_between_is_inclusive_at_both_bounds(self):
        assert evaluate("between", 1, [1, 10]) is True
        assert evaluate("between", 10, [1, 10]) is True
        assert evaluate("between", 0, [1, 10]) is False
        assert evaluate("between", 11, [1, 10]) is False

    def test_between_with_malformed_bounds_is_unknown_not_false(self):
        # A rule that names one bound cannot be evaluated. Reporting False
        # would record a failure against every host it ran on.
        assert (
            evaluate_detailed("between", 5, [1]) is ComparisonOutcome.UNKNOWN_OPERATOR
        )

    def test_boolean_coercion_accepts_the_spellings_collectors_emit(self):
        for truthy in (1, "1", "true", "True", "yes", "on", "enabled", True):
            assert evaluate("is_true", truthy) is True, truthy
        for falsy in (0, "0", "false", "no", "off", "disabled", False):
            assert evaluate("is_false", falsy) is True, falsy

    def test_a_value_that_is_not_a_boolean_satisfies_neither(self):
        # "sometimes" is not False. Coercing it to False would let an
        # unreadable setting satisfy `is_false`.
        assert evaluate("is_true", "sometimes") is False
        assert evaluate("is_false", "sometimes") is False

    def test_matches_is_a_regex_and_is_case_insensitive(self):
        assert evaluate("matches", "PermitRootLogin no", r"^permitrootlogin\s+no$")
        assert evaluate("not_matches", "yes", r"^no$") is True

    def test_starts_and_ends_with(self):
        assert evaluate("starts_with", "Windows 11 Pro", "windows") is True
        assert evaluate("ends_with", "/etc/shadow", "shadow") is True


class TestUnknownOperatorsDoNotManufactureFindings:
    """
    The defect the tri-state exists for: the pre-Phase-3 implementation ended
    in a bare ``return False``, and the caller recorded False as *fail*. A
    typo in a rule therefore invented a finding on every host it touched.
    """

    def test_an_unknown_operator_reports_unknown_not_false(self):
        assert (
            evaluate_detailed("grater_than", 14, 8)
            is ComparisonOutcome.UNKNOWN_OPERATOR
        )

    def test_an_uncompilable_pattern_reports_unknown_not_false(self):
        # A broken pattern is a defect in the rule, not a property of the host.
        assert (
            evaluate_detailed("matches", "anything", "(unclosed")
            is ComparisonOutcome.UNKNOWN_OPERATOR
        )

    def test_the_boolean_entry_point_still_collapses_unknown_to_false(self):
        # Compatibility: no existing compliance rule may change verdict
        # because of the new third state.
        assert evaluate("grater_than", 14, 8) is False

    def test_is_known_operator_covers_the_published_vocabulary(self):
        for operator in COMPARISON_OPERATORS:
            assert is_known_operator(operator), operator
        assert not is_known_operator("definitely_not_an_operator")

    def test_every_published_operator_is_actually_implemented(self):
        """
        A name in ``COMPARISON_OPERATORS`` with no branch behind it falls
        through to UNKNOWN_OPERATOR, which would make it look like a typo to
        every rule author who used it.
        """
        # The expected side has to be well-formed for the operator under test.
        # `between` legitimately reports UNKNOWN_OPERATOR for a scalar bound —
        # that is the malformed-rule path asserted above, not a missing branch.
        well_formed = {"between": [0, 2]}
        unimplemented = [
            operator
            for operator in COMPARISON_OPERATORS
            if evaluate_detailed(operator, "1", well_formed.get(operator, "1"))
            is ComparisonOutcome.UNKNOWN_OPERATOR
        ]
        assert not unimplemented, unimplemented

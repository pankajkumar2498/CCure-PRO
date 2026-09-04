"""
tests/scans/test_database_areas.py
─────────────────────────────────────────────────────────────────────────────
Every GAP-10 area this build claims, exercised in both directions. Phase 7.

The area names below are literals on purpose.
``scripts/measure_database_coverage.py`` reads these test sources to decide
which areas count as *tested*, so an area whose test is deleted loses its
coverage credit rather than keeping it until somebody remembers to update a
hand-maintained list. That is the same construction Phase 5 used, and for the
same reason: a coverage figure that cannot go down is not a measurement.

What sits behind the names is not decoration
────────────────────────────────────────────
A check that can never fail is indistinguishable from a clean estate, and a
check that fails on everything reaches a customer as a false positive. Both
have shipped in this product before — Phase 6 found ``ssh_probe`` promoting a
list nothing ever appended to, and the ROBOT substring test reporting every
server sslyze had positively cleared.

So each area is driven through the real :class:`ConfigAuditEngine` twice: once
with a reading that violates its expectation, which must produce a FAIL
carrying evidence, and once with a compliant reading, which must produce a
PASS. The violating and compliant values are derived from the rule's own
operator rather than written out per rule, so a rule added later is covered
without anybody extending a table — and an operator this file does not know
how to violate fails loudly rather than being skipped.
"""

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit.builtin import DATABASE_CHECKS
from core.config_audit.collection import CollectionContext
from core.config_audit.engine import ConfigAuditEngine
from engines.credentialed.database_executor import QueryResult
from scripts.measure_database_coverage import SCOPE

#: Areas this build implements. Every entry must exist in the frozen
#: denominator, which ``test_database_content.py`` asserts from the other side.
IMPLEMENTED_AREAS = [
    "db.auth.empty_password",
    "db.auth.weak_auth_method",
    "db.auth.default_accounts",
    "db.auth.password_policy",
    "db.auth.login_auditing",
    "db.auth.superuser_remote",
    "db.priv.superusers",
    "db.priv.public_grants",
    "db.priv.dangerous_features",
    "db.priv.schema_create",
    "db.priv.filesystem_access",
    "db.tls.enabled",
    "db.tls.enforced",
    "db.tls.min_version",
    "db.audit.enabled",
    "db.audit.connections",
    "db.audit.ddl_privilege",
    "db.audit.retention",
    "db.conf.listen_exposure",
    "db.conf.version_supported",
    "db.conf.dangerous_options",
    "db.conf.connection_limits",
    "db.conf.sample_databases",
]


class _Session:
    """A database session returning one prescribed result."""

    def __init__(self, engine, rows):
        self.engine = engine
        self._rows = rows

    def query(self, statement, params=None, timeout=None):
        return QueryResult(statement, rows=self._rows, ok=True)


def _engine_of(check):
    declared = check.collect["engine"]
    return declared[0] if isinstance(declared, (list, tuple)) else declared


def _run(check, rows):
    return ConfigAuditEngine().run_check(
        check,
        CollectionContext(
            target="10.0.0.1:5432",
            platform="database",
            os_name=check.os_match["os_name_contains"][0],
            os_version_id="1.0",
            executor=_Session(_engine_of(check), rows),
        ),
    )


def _violating_rows(check):
    """Rows that must fail this check."""
    shape = check.collect.get("result")
    operator = check.expect.operator
    expected = check.expect.value

    if shape == "rows":
        return [("ccure-offending-item",)]
    if shape == "count":
        return [] if operator in ("gte", "gt") else [("x",)] * 99

    if operator == "is_true":
        return [("off",)]
    if operator == "is_false":
        return [("on",)]
    if operator in ("equals", "=="):
        return [("ccure-not-the-expected-value",)]
    if operator == "not_equals":
        return [(expected,)]
    if operator == "in":
        return [("ccure-not-in-the-list",)]
    if operator == "not_in":
        first = list(expected)[0] if isinstance(expected, (list, tuple)) else expected
        return [(first,)]
    if operator in ("gte", "gt"):
        return [(float(expected) - 1,)]
    if operator in ("lte", "lt"):
        return [(float(expected) + 1,)]
    if operator == "version_gte":
        return [("0.0.1",)]
    if operator == "not_empty":
        return [("",)]
    if operator == "is_empty":
        return [("ccure-something",)]
    if operator == "not_matches":
        return [("TLSv1,TLSv1.1,TLSv1.2",)]
    if operator == "matches":
        return [("ccure-does-not-match",)]
    raise AssertionError(
        f"{check.check_id} uses operator {operator!r}, which this file does "
        f"not know how to violate. Teach it rather than skipping the check — "
        f"an unexercised rule is one nobody has seen work."
    )


def _compliant_rows(check):
    """Rows that must pass this check."""
    shape = check.collect.get("result")
    operator = check.expect.operator
    expected = check.expect.value

    if shape == "rows":
        return []
    if shape == "count":
        return [("x",)] if operator in ("gte", "gt") else []

    if operator == "is_true":
        return [("on",)]
    if operator == "is_false":
        return [("off",)]
    if operator in ("equals", "=="):
        return [(expected,)]
    if operator == "not_equals":
        return [("ccure-a-different-value",)]
    if operator == "in":
        first = list(expected)[0] if isinstance(expected, (list, tuple)) else expected
        return [(first,)]
    if operator == "not_in":
        return [("10.0.0.5",)]
    if operator in ("gte", "gt"):
        return [(float(expected) + 1,)]
    if operator in ("lte", "lt"):
        return [(float(expected) - 1,)]
    if operator == "version_gte":
        return [("99.0",)]
    if operator == "not_empty":
        return [("/var/lib/mysql-files/",)]
    if operator == "is_empty":
        return [("",)]
    if operator == "not_matches":
        return [("TLSv1.2,TLSv1.3",)]
    if operator == "matches":
        return [(str(expected),)]
    raise AssertionError(f"{check.check_id}: unhandled operator {operator!r}")


def _checks_for(area):
    return [c for c in DATABASE_CHECKS if c.metadata.get("gap10_area") == area]


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_is_in_the_frozen_denominator(area):
    assert area in {a for a, _theme, _description in SCOPE}


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_has_at_least_one_shipped_rule(area):
    assert _checks_for(area), f"no shipped rule claims area {area!r}"


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_can_produce_a_finding(area):
    """
    A check that never fires is indistinguishable from a clean estate.
    """
    for check in _checks_for(area):
        result = _run(check, _violating_rows(check))
        assert result.outcome is CheckOutcome.FAIL, (
            f"{check.check_id} did not fail on a violating reading; it "
            f"produced {result.outcome.value}"
        )
        assert result.evidence, f"{check.check_id} failed with no evidence"
        assert result.evidence[0].observed, (
            f"{check.check_id} produced no observed value, so the finding "
            f"cannot say what is wrong"
        )
        assert (
            result.remediation
        ), f"{check.check_id} produced a finding with no remediation"


@pytest.mark.parametrize("area", IMPLEMENTED_AREAS)
def test_area_passes_on_a_compliant_reading(area):
    """
    The direction that reaches a customer as a false positive.
    """
    for check in _checks_for(area):
        result = _run(check, _compliant_rows(check))
        assert result.outcome is CheckOutcome.PASS, (
            f"{check.check_id} did not pass on a compliant reading; it "
            f"produced {result.outcome.value}"
        )


def test_every_shipped_rule_belongs_to_a_claimed_area():
    """
    The reverse of the per-area tests: a rule whose area is not listed above is
    a rule nothing exercises, and it would still count as *implemented* in the
    coverage harness.
    """
    claimed = set(IMPLEMENTED_AREAS)
    for check in DATABASE_CHECKS:
        area = check.metadata.get("gap10_area")
        assert area in claimed, (
            f"{check.check_id} claims area {area!r}, which no test in this "
            f"file exercises"
        )

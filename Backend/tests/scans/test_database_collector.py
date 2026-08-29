"""
tests/scans/test_database_collector.py
─────────────────────────────────────────────────────────────────────────────
The ``database_query`` collector and its four collection states. Phase 7
(GAP-10).

The whole point of this collector is that an empty result set is ambiguous
────────────────────────────────────────────────────────────────────────────
A hardened database answers "which accounts have an empty password" with no
rows. So does a database that refused the query, and so does one whose
catalogue view does not exist in this version. Reading any of the last two as
the first is how a scanner reports a clean bill of health for an instance it
was never allowed to inspect — and unlike anywhere else in the configuration
engine, here the *correct* answer and the *failed* answer are byte-identical.

So every test below is really one test asked four ways: does this path produce
a verdict, and is it entitled to?
"""

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit.collection import CollectionContext, CollectionStatus
from core.config_audit.collectors import collector_registry, register_builtin_collectors
from core.config_audit.collectors.database import DatabaseQueryCollector
from core.config_audit.engine import ConfigAuditEngine
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation
from engines.credentialed.database_executor import QueryResult

register_builtin_collectors()


class FakeSession:
    """A database session that returns whatever the test prescribes."""

    def __init__(self, result=None, engine="postgresql", raises=None):
        self.engine = engine
        self._result = result
        self._raises = raises
        self.statements = []

    def query(self, statement, params=None, timeout=None):
        self.statements.append((statement, params))
        if self._raises is not None:
            raise self._raises
        return self._result


def _check(**overrides):
    params = {
        "check_id": "ccure.db.test.example",
        "title": "Example database check",
        "check_type": "database_query",
        "platforms": ("database",),
        "collect": {"sql": "SELECT setting FROM pg_settings WHERE name = 'ssl'"},
        "expect": Expectation("is_true"),
        "absent": AbsencePolicy.MANUAL_REVIEW,
    }
    collect_override = overrides.pop("collect", None)
    if collect_override is not None:
        params["collect"] = collect_override
    params.update(overrides)
    return ConfigCheck(**params)


def _ctx(session, **overrides):
    params = {
        "target": "10.0.0.1:5432",
        "platform": "database",
        "os_name": "PostgreSQL 16.15",
        "os_version_id": "16.15",
        "executor": session,
    }
    params.update(overrides)
    return CollectionContext(**params)


COLLECTOR = DatabaseQueryCollector()


# ── Registration ─────────────────────────────────────────────────────────────


def test_the_collector_is_registered_for_the_reserved_pair():
    """
    Phase 3 declared ``database_query`` and ``database`` with nothing behind
    them, so a rule using them reported ERROR. This is the collector that
    closes that.
    """
    resolved = collector_registry.resolve("database_query", "database")
    assert isinstance(resolved, DatabaseQueryCollector)


def test_database_platform_reports_its_check_type_as_supported():
    assert "database_query" in collector_registry.supported_check_types("database")


def test_registering_the_collector_did_not_disturb_the_host_platforms():
    for platform in ("windows", "linux"):
        assert collector_registry.supported_check_types(platform)
        assert "database_query" not in collector_registry.supported_check_types(
            platform
        )


# ── The four collection states ───────────────────────────────────────────────


def test_a_value_is_collected():
    session = FakeSession(
        QueryResult("s", rows=[("on",)], columns=("setting",), ok=True)
    )
    state = COLLECTOR.collect(_check(), _ctx(session))
    assert state.status is CollectionStatus.COLLECTED
    assert state.value == "on"


def test_no_session_is_unavailable_never_a_verdict():
    state = COLLECTOR.collect(_check(), _ctx(None))
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "no authenticated database session" in state.detail


def test_a_refused_query_is_unavailable_not_absent():
    """
    The defining test. A privilege refusal returns zero rows exactly as a
    compliant instance does; only ``ok`` separates them, and reading the rows
    instead is the bug this whole vocabulary exists to prevent.
    """
    refused = QueryResult(
        "s", rows=[], ok=False, error="permission denied for pg_authid"
    )
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT rolname FROM pg_authid", "result": "rows"}),
        _ctx(FakeSession(refused)),
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    assert state.status is not CollectionStatus.ABSENT
    assert "permission denied" in state.detail


def test_a_dropped_connection_is_unavailable():
    dropped = QueryResult("s", transport_error="server closed the connection")
    state = COLLECTOR.collect(_check(), _ctx(FakeSession(dropped)))
    assert state.status is CollectionStatus.UNAVAILABLE


def test_a_driver_that_raises_is_unavailable_not_an_escape():
    """
    The session is not supposed to raise, but a driver can. It must not
    propagate — one unlucky statement would abort the audit of every remaining
    check on the instance.
    """
    session = FakeSession(raises=RuntimeError("driver exploded"))
    state = COLLECTOR.collect(_check(), _ctx(session))
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "RuntimeError" in state.detail


def test_a_scalar_with_no_row_is_absent():
    """
    A setting this engine version does not have. The *rule* decides what that
    means, which is what AbsencePolicy is for — the collector must not guess.
    """
    state = COLLECTOR.collect(
        _check(), _ctx(FakeSession(QueryResult("s", rows=[], ok=True)))
    )
    assert state.status is CollectionStatus.ABSENT


def test_an_engine_mismatch_is_unsupported_not_an_error():
    """
    A PostgreSQL catalogue read dispatched at MySQL was never in scope for that
    instance. NOT_APPLICABLE is right; reporting a product gap would fill the
    report with targeting decisions.
    """
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1", "engine": "postgresql"}),
        _ctx(FakeSession(QueryResult("s", rows=[("x",)], ok=True), engine="mysql")),
    )
    assert state.status is CollectionStatus.UNSUPPORTED
    assert "postgresql" in state.detail and "mysql" in state.detail


def test_a_matching_engine_is_collected():
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1", "engine": ["postgresql", "mysql"]}),
        _ctx(FakeSession(QueryResult("s", rows=[("on",)], ok=True), engine="mysql")),
    )
    assert state.status is CollectionStatus.COLLECTED


# ── Result shapes ────────────────────────────────────────────────────────────


def test_rows_shape_with_no_rows_is_absent_so_a_clean_instance_can_pass():
    """
    The Phase 5 offender-list shape. A search that returned nothing is a real
    result, so ``absent = PASS`` makes a clean instance pass — unlike a missing
    registry value, which establishes nothing.
    """
    check = _check(
        collect={"sql": "SELECT rolname FROM pg_authid", "result": "rows"},
        expect=Expectation("is_empty"),
        absent=AbsencePolicy.PASS,
    )
    result = ConfigAuditEngine().run_check(
        check, _ctx(FakeSession(QueryResult("s", rows=[], ok=True)))
    )
    assert result.outcome is CheckOutcome.PASS


def test_rows_shape_names_the_offenders_as_evidence():
    rows = [("ccure_nopass",), ("guest",)]
    check = _check(
        collect={"sql": "SELECT rolname FROM pg_authid", "result": "rows"},
        expect=Expectation("is_empty"),
        absent=AbsencePolicy.PASS,
    )
    result = ConfigAuditEngine().run_check(
        check, _ctx(FakeSession(QueryResult("s", rows=rows, ok=True)))
    )
    assert result.outcome is CheckOutcome.FAIL
    observed = result.evidence[0].observed
    assert "ccure_nopass" in observed and "guest" in observed


def test_count_shape_never_reports_absent():
    """
    Zero is a reading. A rule saying "at most two sysadmins" has to be able to
    pass on an instance with none, which an ABSENT would deny it.
    """
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1", "result": "count"}),
        _ctx(FakeSession(QueryResult("s", rows=[], ok=True))),
    )
    assert state.status is CollectionStatus.COLLECTED
    assert state.value == 0


def test_an_unknown_result_shape_is_unavailable():
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1", "result": "histogram"}),
        _ctx(FakeSession(QueryResult("s", rows=[("x",)], ok=True))),
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_value_index_selects_the_right_column():
    """
    ``SHOW VARIABLES LIKE 'x'`` answers ``(name, value)``. Reading column 0
    compares the setting's *name* against the expected value and fails on
    every host.
    """
    two_col = QueryResult("s", rows=[("local_infile", "ON")], ok=True)
    state = COLLECTOR.collect(
        _check(collect={"sql": "SHOW VARIABLES LIKE 'x'", "value_index": 1}),
        _ctx(FakeSession(two_col)),
    )
    assert state.value == "ON"


def test_value_column_selects_by_name():
    result = QueryResult(
        "s", rows=[("local_infile", "ON")], columns=("Variable_name", "Value"), ok=True
    )
    state = COLLECTOR.collect(
        _check(collect={"sql": "SHOW VARIABLES", "value_column": "Value"}),
        _ctx(FakeSession(result)),
    )
    assert state.value == "ON"


def test_a_value_column_the_query_did_not_return_is_unavailable():
    """
    A defect in the rule. Comparing against None instead would evaluate and
    record a verdict about the instance.
    """
    result = QueryResult("s", rows=[("x",)], columns=("setting",), ok=True)
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1", "value_column": "nope"}),
        _ctx(FakeSession(result)),
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "nope" in state.detail


def test_a_rule_with_no_sql_is_unavailable():
    state = COLLECTOR.collect(
        _check(collect={"result": "rows"}), _ctx(FakeSession(None))
    )
    assert state.status is CollectionStatus.UNAVAILABLE


def test_interpolated_params_are_refused():
    """
    Rule parameters are data. A rule handing over anything but a bound sequence
    is refused rather than concatenated into the statement.
    """
    state = COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1 WHERE x = %s", "params": "'; DROP TABLE t--"}),
        _ctx(FakeSession(QueryResult("s", rows=[("x",)], ok=True))),
    )
    assert state.status is CollectionStatus.UNAVAILABLE
    assert "bound values" in state.detail


def test_bound_params_are_passed_through_separately():
    session = FakeSession(QueryResult("s", rows=[("x",)], ok=True))
    COLLECTOR.collect(
        _check(collect={"sql": "SELECT 1 WHERE name = %s", "params": ["ssl"]}),
        _ctx(session),
    )
    _statement, params = session.statements[0]
    assert params == ["ssl"]


# ── Evidence ─────────────────────────────────────────────────────────────────


def test_evidence_records_the_statement_that_produced_the_verdict():
    """
    An auditor reading a database finding is entitled to see what was asked as
    well as what came back — a verdict is only as good as its query.
    """
    session = FakeSession(
        QueryResult("s", rows=[("bad_account",)], columns=("rolname",), ok=True)
    )
    check = _check(
        collect={"sql": "SELECT rolname FROM pg_authid", "result": "rows"},
        expect=Expectation("is_empty"),
        absent=AbsencePolicy.PASS,
    )
    result = ConfigAuditEngine().run_check(check, _ctx(session))
    raw = result.evidence[0].raw
    assert "SQL: SELECT rolname FROM pg_authid" in raw
    assert "bad_account" in raw


# ── Engine outcomes: nothing reaches a verdict it has not earned ─────────────


@pytest.mark.parametrize(
    "result,expected",
    [
        (QueryResult("s", rows=[], ok=False, error="denied"), CheckOutcome.ERROR),
        (QueryResult("s", transport_error="gone"), CheckOutcome.ERROR),
    ],
)
def test_a_failed_read_becomes_an_error_never_a_pass_or_a_fail(result, expected):
    outcome = ConfigAuditEngine().run_check(_check(), _ctx(FakeSession(result))).outcome
    assert outcome is expected
    assert outcome not in (CheckOutcome.PASS, CheckOutcome.FAIL)


def test_an_unreachable_instance_produces_no_findings_at_all():
    """
    An instance nobody could read must not acquire a compliance score. Errors
    are excluded from both halves of the fraction.
    """
    checks = [_check(check_id=f"ccure.db.test.c{i}") for i in range(5)]
    report = ConfigAuditEngine().run(checks, _ctx(None))
    assert report.counts["error"] == 5
    assert report.assessed == []
    assert report.compliance_score() is None

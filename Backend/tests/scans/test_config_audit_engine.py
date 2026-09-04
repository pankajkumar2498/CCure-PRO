"""
tests/scans/test_config_audit_engine.py
─────────────────────────────────────────────────────────────────────────────
The engine pipeline, and the three ways a configuration scanner lies.

Phase 3's stated acceptance criteria are that the engine must never turn

  * unavailable evidence into PASS,
  * unsupported controls into FAIL,
  * failed collection into PASS,

and that PASS / FAIL / MANUAL_REVIEW / NOT_APPLICABLE / not-assessed stay
distinguishable. Those are not incidental properties — every one of them is a
way a scanner produces a confidently wrong report, and each has a class below
written to hold the engine to it from several directions rather than one.

``TestNoPathReachesPassExceptATrueComparison`` is the strongest of them: it
enumerates every failure mode the engine models and asserts none of them
produces PASS, so a future collector state or precondition added without
thought cannot quietly land on the flattering answer.
"""

from dataclasses import dataclass
from typing import Optional

import pytest

from core.checks.contract import CheckOutcome
from core.config_audit import (
    AbsencePolicy,
    CollectedState,
    CollectionContext,
    CollectionStatus,
    ConfigAuditEngine,
    ConfigCheck,
    Expectation,
    select_checks,
)
from core.config_audit.collectors.base import Collector, CollectorRegistry


# ─────────────────────────────────────────────────────────────────────────────
# Doubles
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class FakeResult:
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    success: bool = True


class FakeExecutor:
    """A ``BaseExecutor`` that answers from a table, used with no real host."""

    def __init__(self, table=None, raises: Optional[Exception] = None):
        self.table = table or {}
        self.raises = raises
        self.commands = []

    def connect(self):
        pass

    def disconnect(self):
        pass

    def run(self, command, timeout=None):
        self.commands.append(command)
        if self.raises:
            raise self.raises
        if "PSVersionTable" in command:
            return FakeResult(stdout="5")
        for needle, response in self.table.items():
            if needle in command:
                return response
        return FakeResult(stderr="no stub for this command", exit_code=1, success=False)


class StubCollector(Collector):
    """Returns a fixed :class:`CollectedState`, or raises."""

    check_type = "command"
    platforms = ("windows", "linux")
    name = "stub"

    def __init__(self, state=None, raises=None):
        self.state = state
        self.raises = raises

    def collect(self, check, ctx):
        if self.raises:
            raise self.raises
        return self.state


def make_check(**overrides) -> ConfigCheck:
    params = dict(
        check_id="test.check",
        title="A test check",
        check_type="command",
        platforms=("windows",),
        collect={"command": "whoami"},
        expect=Expectation("equals", "expected-value"),
        absent=AbsencePolicy.MANUAL_REVIEW,
        severity="high",
    )
    params.update(overrides)
    return ConfigCheck(**params)


def engine_with(collector) -> ConfigAuditEngine:
    registry = CollectorRegistry()
    registry.register(collector)
    return ConfigAuditEngine(registry)


def ctx(platform="windows", executor="default", **kwargs) -> CollectionContext:
    return CollectionContext(
        target="10.0.0.1",
        platform=platform,
        executor=FakeExecutor() if executor == "default" else executor,
        **kwargs,
    )


# ─────────────────────────────────────────────────────────────────────────────
# The verdicts
# ─────────────────────────────────────────────────────────────────────────────


class TestTheTwoVerdicts:
    def test_a_matching_value_passes(self):
        engine = engine_with(StubCollector(CollectedState.collected("expected-value")))
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.PASS
        assert result.is_verdict

    def test_a_differing_value_fails(self):
        engine = engine_with(StubCollector(CollectedState.collected("something-else")))
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.FAIL
        assert result.is_verdict
        assert result.is_finding

    def test_a_failure_carries_the_expected_and_observed_states(self):
        """
        A reviewer challenging a finding needs the value the rule required
        beside the value the host held. A finding that can say only
        "non-compliant" cannot be defended in an audit.
        """
        engine = engine_with(StubCollector(CollectedState.collected("0")))
        result = engine.run_check(
            make_check(expect=Expectation("equals", 1, description="EnableLUA = 1")),
            ctx(),
        )
        assert result.outcome is CheckOutcome.FAIL
        evidence = result.evidence[0]
        assert evidence.expected == "EnableLUA = 1"
        assert evidence.observed == "0"

    def test_a_pass_is_not_a_finding(self):
        engine = engine_with(StubCollector(CollectedState.collected("expected-value")))
        assert not engine.run_check(make_check(), ctx()).is_finding


# ─────────────────────────────────────────────────────────────────────────────
# Acceptance criterion 1 & 3 — nothing that failed may become PASS
# ─────────────────────────────────────────────────────────────────────────────


class TestFailedCollectionNeverBecomesPassOrFail:
    def test_unavailable_collection_is_an_error(self):
        engine = engine_with(
            StubCollector(CollectedState.unavailable("the command exited 5"))
        )
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.ERROR
        assert not result.is_verdict
        assert "exited 5" in result.error

    def test_a_missing_credential_is_an_error_not_a_failure(self):
        """
        The historical bug this mirrors: ISO A.8.2 was reported as *failed* on
        hosts the scanner could not authenticate to.
        """
        engine = engine_with(StubCollector(CollectedState.collected("x")))
        result = engine.run_check(make_check(), ctx(executor=None))
        assert result.outcome is CheckOutcome.ERROR
        assert "authenticated session" in result.error

    def test_a_collector_that_raises_yields_an_error_not_a_finding(self):
        """A defect in our code must not invent a finding about a host."""
        engine = engine_with(StubCollector(raises=RuntimeError("boom")))
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.ERROR
        assert "RuntimeError" in result.error

    def test_a_collector_returning_the_wrong_type_is_an_error(self):
        engine = engine_with(StubCollector(state="not a CollectedState"))
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.ERROR
        assert "CollectedState" in result.error

    def test_no_collector_for_the_check_type_is_an_error_not_applicable(self):
        """
        "This product cannot perform that check" and "that check does not
        apply to this host" are different facts. Only the second is a
        legitimate reason for a control to leave the compliance score.
        """
        engine = ConfigAuditEngine(CollectorRegistry())
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.ERROR
        assert "no collector" in result.error

    def test_an_unknown_platform_is_an_error_not_a_skip(self):
        engine = engine_with(StubCollector(CollectedState.collected("x")))
        result = engine.run_check(make_check(platforms=("any",)), ctx(platform=""))
        assert result.outcome is CheckOutcome.ERROR
        assert "platform" in result.error

    def test_an_unevaluable_operator_is_an_error_not_a_failure(self):
        """
        A rule whose comparison cannot be performed has established nothing.
        Recording it as FAIL manufactures a finding out of a typo.
        """
        check = make_check()
        # Bypass Expectation's own validation to simulate a stored rule that
        # predates the operator vocabulary, which is how this reaches the
        # engine in practice.
        object.__setattr__(check.expect, "operator", "grater_than")
        engine = engine_with(StubCollector(CollectedState.collected("5")))
        result = engine.run_check(check, ctx())
        assert result.outcome is CheckOutcome.ERROR
        assert "comparison could not be performed" in result.error


class TestNoPathReachesPassExceptATrueComparison:
    """
    Enumerate every modelled failure and assert none of them is a PASS.

    Written as one sweep rather than one assertion per case so that a state
    added to :class:`CollectionStatus`, or a precondition added to the engine,
    cannot land on the flattering answer without this failing.
    """

    @pytest.mark.parametrize(
        "state,label",
        [
            (CollectedState.unavailable("no session"), "unavailable"),
            (CollectedState.unavailable("command exited 1"), "command failed"),
            (CollectedState.unsupported("not on this platform"), "unsupported"),
        ],
    )
    def test_non_observation_states_never_pass(self, state, label):
        engine = engine_with(StubCollector(state))
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is not CheckOutcome.PASS, label

    def test_every_collection_status_is_handled_explicitly(self):
        """
        A status with no branch would fall through to the comparison and be
        compared against ``value=None`` — which for most operators is False,
        i.e. a FAIL invented from an unhandled state.
        """
        seen = {}
        for status in CollectionStatus:
            state = CollectedState(
                status=status,
                value=(
                    "expected-value" if status is CollectionStatus.COLLECTED else None
                ),
                detail="reason" if status is CollectionStatus.UNAVAILABLE else "",
            )
            engine = engine_with(StubCollector(state))
            seen[status] = engine.run_check(make_check(), ctx()).outcome
        assert seen[CollectionStatus.COLLECTED] is CheckOutcome.PASS
        assert seen[CollectionStatus.ABSENT] is CheckOutcome.MANUAL_REVIEW
        assert seen[CollectionStatus.UNSUPPORTED] is CheckOutcome.NOT_APPLICABLE
        assert seen[CollectionStatus.UNAVAILABLE] is CheckOutcome.ERROR

    def test_an_empty_reading_is_not_silently_a_pass(self):
        """
        An empty string is a real reading only if the collector says so. It
        must be compared, not waved through.
        """
        engine = engine_with(StubCollector(CollectedState.collected("")))
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.FAIL


# ─────────────────────────────────────────────────────────────────────────────
# Acceptance criterion 2 — an out-of-scope control is not a failure
# ─────────────────────────────────────────────────────────────────────────────


class TestUnsupportedControlsAreNeverFailures:
    def test_a_windows_rule_on_a_linux_host_is_not_applicable(self):
        engine = engine_with(StubCollector(CollectedState.collected("x")))
        result = engine.run_check(
            make_check(platforms=("windows",)), ctx(platform="linux")
        )
        assert result.outcome is CheckOutcome.NOT_APPLICABLE
        assert not result.is_verdict
        assert "windows" in result.metadata["not_applicable_reason"]

    def test_an_any_platform_rule_runs_everywhere(self):
        engine = engine_with(StubCollector(CollectedState.collected("expected-value")))
        for platform in ("windows", "linux"):
            result = engine.run_check(
                make_check(platforms=("any",)), ctx(platform=platform)
            )
            assert result.outcome is CheckOutcome.PASS, platform

    def test_a_collector_reporting_unsupported_is_not_applicable(self):
        engine = engine_with(
            StubCollector(CollectedState.unsupported("no registry on this host"))
        )
        result = engine.run_check(make_check(), ctx())
        assert result.outcome is CheckOutcome.NOT_APPLICABLE


# ─────────────────────────────────────────────────────────────────────────────
# Absence — the state whose meaning only the rule knows
# ─────────────────────────────────────────────────────────────────────────────


class TestAbsenceIsResolvedByTheRuleNotTheEngine:
    @pytest.mark.parametrize(
        "policy,expected",
        [
            (AbsencePolicy.PASS, CheckOutcome.PASS),
            (AbsencePolicy.FAIL, CheckOutcome.FAIL),
            (AbsencePolicy.NOT_APPLICABLE, CheckOutcome.NOT_APPLICABLE),
            (AbsencePolicy.MANUAL_REVIEW, CheckOutcome.MANUAL_REVIEW),
        ],
    )
    def test_each_policy_maps_to_its_outcome(self, policy, expected):
        engine = engine_with(
            StubCollector(CollectedState.absent("the service is not installed"))
        )
        result = engine.run_check(make_check(absent=policy), ctx())
        assert result.outcome is expected

    def test_absence_that_fails_still_carries_evidence(self):
        """
        ``CheckResult`` refuses a FAIL with no evidence. An absence-driven
        failure is the case most likely to be built without any, because
        nothing was read.
        """
        engine = engine_with(
            StubCollector(CollectedState.absent("auditd is not installed"))
        )
        result = engine.run_check(make_check(absent=AbsencePolicy.FAIL), ctx())
        assert result.outcome is CheckOutcome.FAIL
        assert result.evidence
        assert "not present" in result.evidence[0].observed

    def test_the_result_records_which_policy_decided_it(self):
        engine = engine_with(StubCollector(CollectedState.absent("gone")))
        result = engine.run_check(make_check(absent=AbsencePolicy.PASS), ctx())
        assert result.metadata["absent_policy"] == "pass"
        assert result.metadata["collection_status"] == "absent"

    def test_absence_and_an_empty_value_are_not_the_same_thing(self):
        """
        "The registry value does not exist" and "the registry value is empty"
        routinely mean opposite things for a hardening rule.
        """
        check = make_check(absent=AbsencePolicy.PASS, expect=Expectation("equals", ""))
        absent = engine_with(StubCollector(CollectedState.absent("no such value")))
        empty = engine_with(StubCollector(CollectedState.collected("")))
        assert absent.run_check(check, ctx()).outcome is CheckOutcome.PASS
        assert empty.run_check(check, ctx()).outcome is CheckOutcome.PASS
        # …and with the opposite expectation they diverge, which is the point.
        check2 = make_check(absent=AbsencePolicy.FAIL, expect=Expectation("equals", ""))
        assert absent.run_check(check2, ctx()).outcome is CheckOutcome.FAIL
        assert empty.run_check(check2, ctx()).outcome is CheckOutcome.PASS


# ─────────────────────────────────────────────────────────────────────────────
# Scoring
# ─────────────────────────────────────────────────────────────────────────────


class TestScoringCountsVerdictsOnly:
    def _report(self, states):
        results = []
        engine_stub = ConfigAuditEngine(CollectorRegistry())
        for index, state in enumerate(states):
            registry = CollectorRegistry()
            registry.register(StubCollector(state))
            engine = ConfigAuditEngine(registry)
            results.append(engine.run_check(make_check(check_id=f"c{index}"), ctx()))
        report = engine_stub.run([], ctx())
        report.results = results
        return report

    def test_errors_are_excluded_from_both_halves_of_the_score(self):
        """
        Counting an unreachable host's errors as failures invents findings;
        counting them as passes inflates the score. Neither may happen.
        """
        report = self._report(
            [
                CollectedState.collected("expected-value"),  # pass
                CollectedState.collected("other"),  # fail
                CollectedState.unavailable("no session"),  # error
                CollectedState.unavailable("no session"),  # error
            ]
        )
        assert report.compliance_score() == 50.0
        assert len(report.assessed) == 2

    def test_not_applicable_does_not_enter_the_score(self):
        report = self._report(
            [
                CollectedState.collected("expected-value"),
                CollectedState.unsupported("out of scope"),
            ]
        )
        assert report.compliance_score() == 100.0

    def test_a_host_with_no_verdicts_has_no_score_rather_than_zero_or_full(self):
        """
        None, not 0.0 and not 100.0. Both numbers are assertions nobody
        established about a host where nothing could be assessed.
        """
        report = self._report(
            [
                CollectedState.unavailable("no session"),
                CollectedState.unsupported("out of scope"),
            ]
        )
        assert report.compliance_score() is None

    def test_counts_cover_every_outcome_member(self):
        report = self._report([CollectedState.collected("expected-value")])
        assert set(report.counts) == {o.value for o in CheckOutcome}

    def test_failures_are_reported_separately_from_results(self):
        report = self._report(
            [
                CollectedState.collected("expected-value"),
                CollectedState.collected("other"),
            ]
        )
        assert len(report.results) == 2
        assert len(report.failures) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Selection
# ─────────────────────────────────────────────────────────────────────────────


class TestSelection:
    def test_intrusive_checks_are_excluded_unless_asked_for(self):
        """
        This product scans production and OT hosts. An audit that causes an
        outage is worse than the finding it would have produced.
        """
        safe = make_check(check_id="safe")
        risky = make_check(check_id="risky", intrusive=True)
        assert select_checks([safe, risky]) == [safe]
        assert len(select_checks([safe, risky], include_intrusive=True)) == 2

    def test_platform_filtering_uses_the_checks_own_rule(self):
        win = make_check(check_id="w", platforms=("windows",))
        anywhere = make_check(check_id="a", platforms=("any",))
        selected = select_checks([win, anywhere], platform="linux")
        assert [c.check_id for c in selected] == ["a"]

    def test_domain_and_tag_filters(self):
        a = make_check(check_id="a", domain="host_configuration", tags=("cis",))
        b = make_check(check_id="b", domain="tls", tags=("tls",))
        assert [c.check_id for c in select_checks([a, b], domains=["tls"])] == ["b"]
        assert [c.check_id for c in select_checks([a, b], tags=["cis"])] == ["a"]


# ─────────────────────────────────────────────────────────────────────────────
# Live-ish path, through the real Windows collector and a stub transport
# ─────────────────────────────────────────────────────────────────────────────


class TestThroughARealCollector:
    """
    Exercises the registry, the sentinel protocol and the shell wrapper — the
    parts a stub collector skips over.
    """

    def _engine(self):
        return ConfigAuditEngine()

    def _check(self):
        return ConfigCheck(
            check_id="test.registry",
            title="A registry value",
            check_type="registry",
            platforms=("windows",),
            collect={
                "path": r"HKLM\SOFTWARE\Test",
                "value": "Setting",
            },
            expect=Expectation("equals", 1),
            absent=AbsencePolicy.MANUAL_REVIEW,
        )

    def test_a_sentinel_value_becomes_a_verdict(self):
        executor = FakeExecutor({"Setting": FakeResult(stdout="CCURE::VALUE::1")})
        result = self._engine().run_check(self._check(), ctx(executor=executor))
        assert result.outcome is CheckOutcome.PASS

    def test_a_sentinel_absent_becomes_the_absence_policy(self):
        executor = FakeExecutor(
            {"Setting": FakeResult(stdout="CCURE::ABSENT::key does not exist")}
        )
        result = self._engine().run_check(self._check(), ctx(executor=executor))
        assert result.outcome is CheckOutcome.MANUAL_REVIEW

    def test_a_nonzero_exit_becomes_an_error(self):
        executor = FakeExecutor(
            {
                "Setting": FakeResult(
                    stderr="Access is denied.", exit_code=5, success=False
                )
            }
        )
        result = self._engine().run_check(self._check(), ctx(executor=executor))
        assert result.outcome is CheckOutcome.ERROR
        assert "Access is denied" in result.error

    def test_output_with_no_sentinel_is_an_error_not_an_empty_reading(self):
        """
        The failure this protocol exists for. A command that succeeded but
        printed something unexpected has not produced a value, and reading its
        output as one would compare the banner text against the rule.
        """
        executor = FakeExecutor({"Setting": FakeResult(stdout="unexpected banner")})
        result = self._engine().run_check(self._check(), ctx(executor=executor))
        assert result.outcome is CheckOutcome.ERROR
        assert "result marker" in result.error

    def test_a_transport_exception_is_an_error_not_a_verdict(self):
        executor = FakeExecutor(raises=ConnectionResetError("connection dropped"))
        result = self._engine().run_check(self._check(), ctx(executor=executor))
        assert result.outcome is CheckOutcome.ERROR

    def test_a_rule_missing_a_required_parameter_errors_without_aborting(self):
        check = ConfigCheck(
            check_id="test.malformed",
            title="Missing the value name",
            check_type="registry",
            platforms=("windows",),
            collect={"unrelated": "x"},
            expect=Expectation("equals", 1),
            absent=AbsencePolicy.MANUAL_REVIEW,
        )
        result = self._engine().run_check(check, ctx())
        assert result.outcome is CheckOutcome.ERROR
        assert "required parameter" in result.error

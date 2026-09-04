"""
tests/compliance/test_benchmark_pack.py
─────────────────────────────────────────────────────────────────────────────
The benchmark content format, and everything it refuses.

Most of this file is about refusals, because the failure mode of benchmark
content is not a crash — it is a pack that loads cleanly and quietly claims
more than it does. A control that says it is automated with no check behind it,
a profile spelled ``"L!"``, a duplicate recommendation number: each of those
produces a benchmark that scores better than it should and gives no sign of it.

The three assessment states are the centre of it. ``automated`` / ``manual`` /
``unimplemented`` are not interchangeable, and the pack format refuses to infer
one from the presence of a check — CLAUDE.md records what inference cost the
last time, when eighteen ISO controls claimed ``semi_auto`` with no automated
rule behind them and the register, the coverage figures and the SoA all read
that as partial automation.
"""

import json

import pytest

from core.benchmarks.pack import (
    ASSESSMENT_STATES,
    BenchmarkControl,
    BenchmarkPack,
    BenchmarkProfile,
    PackError,
    load_pack,
    parse_pack,
)
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation


def a_check(**overrides) -> ConfigCheck:
    params = dict(
        check_id="x.1",
        title="A check",
        check_type="registry",
        platforms=("windows",),
        collect={"path": r"HKLM\SOFTWARE\X", "value": "V"},
        expect=Expectation("equals", 1),
        absent=AbsencePolicy.MANUAL_REVIEW,
    )
    params.update(overrides)
    return ConfigCheck(**params)


def a_control(**overrides) -> BenchmarkControl:
    params = dict(
        control_id="1.1",
        title="A recommendation",
        assessment="automated",
        severity="medium",
        profiles=("L1",),
        check=a_check(),
    )
    params.update(overrides)
    return BenchmarkControl(**params)


def a_pack(**overrides) -> BenchmarkPack:
    params = dict(
        code="TEST_BM",
        name="Test Benchmark",
        version="1.0.0",
        platform="windows",
        publisher="Test Publisher",
        licence="Test licence",
        profiles=(BenchmarkProfile("L1"), BenchmarkProfile("L2")),
        controls=(a_control(),),
    )
    params.update(overrides)
    return BenchmarkPack(**params)


class TestAssessmentIsDeclaredNotInferred:
    def test_automated_without_a_check_is_refused(self):
        """
        The defect this exists for: claiming automation that does not run. A
        coverage figure built on it overstates what a scan does.
        """
        with pytest.raises(PackError, match="carries no check"):
            a_control(assessment="automated", check=None)

    def test_manual_with_a_check_is_refused(self):
        with pytest.raises(PackError, match="carries a check"):
            a_control(assessment="manual", check=a_check())

    def test_unimplemented_with_a_check_is_refused(self):
        with pytest.raises(PackError, match="carries a check"):
            a_control(assessment="unimplemented", check=a_check())

    def test_an_undeclared_assessment_is_refused(self):
        with pytest.raises(PackError, match="assessment must be one of"):
            a_control(assessment="", check=None)

    def test_unimplemented_must_say_why(self):
        """
        A counted gap nobody can explain is a number, not information.
        """
        with pytest.raises(PackError, match="must say"):
            a_control(assessment="unimplemented", check=None)
        # …and with a reason it constructs.
        control = a_control(
            assessment="unimplemented",
            check=None,
            unimplemented_reason="the collector returns unparsed text",
        )
        assert not control.is_automated

    def test_manual_and_unimplemented_both_map_to_manual_scannability(self):
        """
        Nothing automated runs for either, and the register must not claim it
        does. The difference between them is kept in tags, not lost here.
        """
        manual = a_control(assessment="manual", check=None)
        unimplemented = a_control(
            assessment="unimplemented", check=None, unimplemented_reason="not built"
        )
        assert manual.scannability == "manual"
        assert unimplemented.scannability == "manual"
        assert a_control().scannability == "auto"

    def test_the_three_states_are_the_whole_vocabulary(self):
        assert ASSESSMENT_STATES == ("automated", "manual", "unimplemented")


class TestPackLevelRefusals:
    def test_a_duplicate_control_id_is_refused(self):
        """Two rows for one recommendation would be scored twice."""
        with pytest.raises(PackError, match="duplicate control_id"):
            a_pack(controls=(a_control(), a_control()))

    def test_an_undeclared_profile_is_refused(self):
        """
        A misspelled profile would otherwise create a profile of one member and
        silently remove the control from the real one.
        """
        with pytest.raises(PackError, match="does not declare"):
            a_pack(controls=(a_control(profiles=("L3",)),))

    def test_an_empty_pack_is_refused(self):
        with pytest.raises(PackError, match="no controls"):
            a_pack(controls=())

    def test_a_licence_is_required(self):
        """
        Content whose licence nobody recorded is content nobody can safely
        redistribute, and the report attributes it.
        """
        with pytest.raises(PackError, match="licence is required"):
            a_pack(licence="")

    def test_a_publisher_is_required(self):
        with pytest.raises(PackError, match="publisher is required"):
            a_pack(publisher="")

    def test_an_unknown_platform_is_refused(self):
        with pytest.raises(PackError, match="platform"):
            a_pack(platform="solaris")

    def test_a_check_targeting_another_platform_is_refused(self):
        """
        It would report not-applicable on every host the benchmark is run
        against — a control that can never produce a verdict, loaded silently.
        """
        with pytest.raises(PackError, match="benchmark"):
            a_pack(controls=(a_control(check=a_check(platforms=("linux",))),))

    def test_an_unknown_severity_is_refused(self):
        with pytest.raises(PackError, match="severity"):
            a_control(severity="catastrophic")


class TestProfileScoping:
    def test_a_control_with_no_profile_is_in_every_profile(self):
        """
        The same reading migration c5d6e7f8a9b0 gives an empty `profiles`
        column, so the two cannot disagree.
        """
        pack = a_pack(
            controls=(
                a_control(control_id="1.1", profiles=()),
                a_control(control_id="1.2", profiles=("L2",)),
            )
        )
        assert len(pack.controls_in_profile("L1")) == 1
        assert len(pack.controls_in_profile("L2")) == 2
        assert len(pack.controls_in_profile(None)) == 2

    def test_counts_report_every_assessment_state(self):
        pack = a_pack(
            controls=(
                a_control(control_id="1.1"),
                a_control(control_id="1.2", assessment="manual", check=None),
                a_control(
                    control_id="1.3",
                    assessment="unimplemented",
                    check=None,
                    unimplemented_reason="not built",
                ),
            )
        )
        assert pack.counts() == {
            "automated": 1,
            "manual": 1,
            "unimplemented": 1,
            "total": 3,
        }
        assert pack.automation_pct() == 33.3

    def test_the_framework_id_carries_the_benchmark_prefix(self):
        """
        Load-bearing: it is how `is_active` tells loaded content from a
        catalogue that ships parked, and therefore how a benchmark avoids
        scoring nothing.
        """
        assert a_pack().framework_id == "cfw_bm_test_bm"


class TestParsing:
    def _payload(self, **control_overrides):
        control = {
            "control_id": "1.1",
            "title": "A recommendation",
            "assessment": "automated",
            "severity": "medium",
            "profiles": ["L1"],
            "check": {
                "check_type": "registry",
                "collect": {"path": "HKLM\\SOFTWARE\\X", "value": "V"},
                "operator": "equals",
                "expected": 1,
                "absent": "manual_review",
                "platforms": ["windows"],
            },
        }
        control.update(control_overrides)
        return {
            "benchmark": {
                "code": "TEST_BM",
                "name": "Test Benchmark",
                "version": "1.0.0",
                "platform": "windows",
                "publisher": "Test Publisher",
                "licence": "Test licence",
                "profiles": [{"id": "L1"}],
            },
            "controls": [control],
        }

    def test_a_well_formed_pack_parses(self):
        pack = parse_pack(self._payload())
        assert pack.code == "TEST_BM"
        assert len(pack.controls) == 1
        assert pack.controls[0].check is not None

    def test_the_control_narrative_reaches_the_check(self):
        """
        The check carries the remediation into the security finding, so it must
        inherit the control's text rather than being written twice.
        """
        pack = parse_pack(
            self._payload(remediation="Set it to 1.", rationale="Because.")
        )
        assert pack.controls[0].check.remediation == "Set it to 1."
        assert pack.controls[0].check.rationale == "Because."

    def test_a_check_that_will_not_execute_names_its_control(self):
        """
        A six-hundred-control pack reporting a spec error with no control id is
        an error nobody can locate.
        """
        with pytest.raises(PackError, match="1.1"):
            parse_pack(self._payload(check={"check_type": "registry"}))

    def test_a_check_with_no_absence_policy_is_refused(self):
        payload = self._payload()
        del payload["controls"][0]["check"]["absent"]
        with pytest.raises(PackError, match="absent"):
            parse_pack(payload)

    def test_a_pack_with_no_controls_array_is_refused(self):
        with pytest.raises(PackError, match="controls"):
            parse_pack({"benchmark": {"code": "X"}})

    def test_a_pack_that_is_not_an_object_is_refused(self):
        with pytest.raises(PackError, match="not an object"):
            parse_pack([1, 2, 3])

    def test_load_reports_the_file_it_could_not_read(self, tmp_path):
        missing = tmp_path / "nope.benchmark.json"
        with pytest.raises(PackError, match="not found"):
            load_pack(missing)

    def test_invalid_json_names_the_file(self, tmp_path):
        broken = tmp_path / "broken.benchmark.json"
        broken.write_text("{not json", encoding="utf-8")
        with pytest.raises(PackError, match="not valid JSON"):
            load_pack(broken)

    def test_a_parse_error_names_the_file(self, tmp_path):
        path = tmp_path / "bad.benchmark.json"
        payload = self._payload()
        payload["controls"][0]["assessment"] = "guesswork"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(PackError, match="bad.benchmark.json"):
            load_pack(path)

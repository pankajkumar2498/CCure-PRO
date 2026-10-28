"""
tests/compliance/test_benchmark_loader.py
─────────────────────────────────────────────────────────────────────────────
Writing a benchmark into the tables the compliance engine already has.

The loader creates no table of its own — a benchmark is a framework, its
recommendations are controls, and its automated recommendations are rules. That
is what lets a benchmark's results reach the register, the score, the findings
queue and the report without any of them learning what a benchmark is.

Two properties get most of the attention here:

**Convergence.** Loading the same pack twice must update, not duplicate. A
benchmark that doubled its control count on the second load would halve its own
score and give no sign why.

**The two engines must not fight.** ``run_scan_task`` evaluates every active
rule linked to a control in the framework it is scanning. A benchmark rule has
no evidence *key* — it is evaluated against a live host by the configuration
audit — so the compliance scan would read that as missing evidence and write
``manual_review`` over the real verdict. The skip that prevents it is asserted
below, because the symptom would be a compliance scan silently blanking every
benchmark result.
"""

import pytest

from core.compliance_catalogue.benchmark_loader import (
    BENCHMARK_EVIDENCE_SOURCE,
    BENCHMARK_THEME,
    control_row_id,
    load_pack_into_db,
    rule_row_id,
)
from core.benchmarks.pack import BenchmarkControl, BenchmarkPack, BenchmarkProfile
from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation
from db.models.compliance import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceRule,
    ComplianceRuleControl,
)


def a_check(check_id="x.1", **overrides) -> ConfigCheck:
    params = dict(
        check_id=check_id,
        title="A check",
        check_type="registry",
        platforms=("windows",),
        collect={"path": r"HKLM\SOFTWARE\X", "value": "V"},
        expect=Expectation("equals", 1),
        absent=AbsencePolicy.MANUAL_REVIEW,
    )
    params.update(overrides)
    return ConfigCheck(**params)


def a_pack(code="LOADER_TEST", controls=None) -> BenchmarkPack:
    return BenchmarkPack(
        code=code,
        name="Loader Test Benchmark",
        version="1.0.0",
        platform="windows",
        publisher="Test Publisher",
        licence="Test licence",
        profiles=(BenchmarkProfile("L1"), BenchmarkProfile("L2")),
        controls=controls
        or (
            BenchmarkControl(
                control_id="1.1",
                title="An automated recommendation",
                assessment="automated",
                severity="high",
                profiles=("L1",),
                section="1 Account Policies",
                remediation="Set it to 1.",
                crosswalk=("CIS_V8_1:5.2",),
                check=a_check(),
            ),
            BenchmarkControl(
                control_id="1.2",
                title="A manual recommendation",
                assessment="manual",
                severity="medium",
                profiles=("L2",),
            ),
            BenchmarkControl(
                control_id="1.3",
                title="An unimplemented recommendation",
                assessment="unimplemented",
                severity="low",
                unimplemented_reason="the collector returns unparsed text",
            ),
        ),
    )


@pytest.fixture
def loaded(db_session):
    """Load a pack, and remove it afterwards so the shared database is clean."""
    pack = a_pack()
    load_pack_into_db(db_session, pack, commit=False)
    db_session.flush()
    yield pack
    db_session.query(ComplianceFramework).filter(
        ComplianceFramework.id == pack.framework_id
    ).delete()
    db_session.query(ComplianceRule).filter(
        ComplianceRule.id.like(f"rule_{pack.code.lower()}%")
    ).delete(synchronize_session=False)
    db_session.commit()


class TestWhatTheLoaderWrites:
    def test_the_benchmark_becomes_a_framework(self, db_session, loaded):
        framework = (
            db_session.query(ComplianceFramework)
            .filter(ComplianceFramework.id == loaded.framework_id)
            .first()
        )
        assert framework is not None
        assert framework.code == "LOADER_TEST"
        assert framework.version == "1.0.0"
        # Global, like every other catalogue: a benchmark is a standard, not a
        # tenant's private data.
        assert framework.tenant_id is None

    def test_every_recommendation_becomes_a_control(self, db_session, loaded):
        controls = (
            db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == loaded.framework_id)
            .all()
        )
        assert len(controls) == 3
        assert {c.control_number for c in controls} == {"1.1", "1.2", "1.3"}
        assert all(c.theme == BENCHMARK_THEME for c in controls)

    def test_only_automated_recommendations_become_rules(self, db_session, loaded):
        rules = (
            db_session.query(ComplianceRule)
            .filter(ComplianceRule.id.like("rule_loader_test%"))
            .all()
        )
        assert len(rules) == 1
        assert rules[0].id == rule_row_id(loaded, "1.1")
        assert rules[0].status == "active"
        assert rules[0].evidence_source == BENCHMARK_EVIDENCE_SOURCE

    def test_the_rule_is_linked_to_its_control(self, db_session, loaded):
        link = (
            db_session.query(ComplianceRuleControl)
            .filter(
                ComplianceRuleControl.rule_id == rule_row_id(loaded, "1.1"),
                ComplianceRuleControl.control_id == control_row_id(loaded, "1.1"),
            )
            .first()
        )
        assert link is not None

    def test_profiles_land_on_the_control(self, db_session, loaded):
        by_number = {
            c.control_number: c
            for c in db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == loaded.framework_id)
            .all()
        }
        assert by_number["1.1"].profiles == ["L1"]
        assert by_number["1.2"].profiles == ["L2"]
        # No profile means in scope whatever profile was selected.
        assert by_number["1.3"].profiles == []

    def test_scannability_never_claims_absent_automation(self, db_session, loaded):
        by_number = {
            c.control_number: c
            for c in db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == loaded.framework_id)
            .all()
        }
        assert by_number["1.1"].scannability == "auto"
        assert by_number["1.2"].scannability == "manual"
        # Unimplemented is manual too: nothing automated runs for it.
        assert by_number["1.3"].scannability == "manual"

    def test_the_assessment_state_survives_in_tags(self, db_session, loaded):
        """
        `scannability` cannot distinguish "a human must judge this" from "we
        have not built it yet", and the coverage figures need that difference.
        """
        by_number = {
            c.control_number: c
            for c in db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == loaded.framework_id)
            .all()
        }
        assert "assessment:manual" in by_number["1.2"].tags
        assert "assessment:unimplemented" in by_number["1.3"].tags

    def test_the_crosswalk_is_written(self, db_session, loaded):
        control = (
            db_session.query(ComplianceControl)
            .filter(ComplianceControl.id == control_row_id(loaded, "1.1"))
            .first()
        )
        assert control.crosswalk == ["CIS_V8_1:5.2"]

    def test_severity_weight_matches_the_hand_seeded_convention(
        self, db_session, loaded
    ):
        rule = (
            db_session.query(ComplianceRule)
            .filter(ComplianceRule.id == rule_row_id(loaded, "1.1"))
            .first()
        )
        assert rule.severity == "high"
        assert rule.severity_weight == 8


class TestConvergence:
    def test_loading_twice_updates_rather_than_duplicating(self, db_session, loaded):
        """
        A benchmark that doubled its control count on reload would halve its own
        score with no sign of why.
        """
        second = load_pack_into_db(db_session, a_pack(), commit=False)
        db_session.flush()
        assert second.controls_created == 0
        assert second.controls_updated == 3
        assert second.links_created == 0
        assert (
            db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == loaded.framework_id)
            .count()
            == 3
        )

    def test_a_withdrawn_check_archives_its_rule_rather_than_deleting_it(
        self, db_session, loaded
    ):
        """
        `run_scan_task` evaluates active rules only, so archiving switches the
        check off. The row survives as the record that it once existed.
        """
        withdrawn = a_pack(
            controls=(
                BenchmarkControl(
                    control_id="1.1",
                    title="An automated recommendation",
                    assessment="unimplemented",
                    severity="high",
                    unimplemented_reason="withdrawn pending a parser",
                ),
            )
        )
        result = load_pack_into_db(db_session, withdrawn, commit=False)
        db_session.flush()
        assert result.rules_archived == 1
        rule = (
            db_session.query(ComplianceRule)
            .filter(ComplianceRule.id == rule_row_id(loaded, "1.1"))
            .first()
        )
        assert rule is not None
        assert rule.status == "archived"

    def test_two_spellings_of_one_control_number_produce_one_row(self):
        """
        Same rule `definition_id_for_check` applies to catalogue identifiers,
        and for the same reason: two rows for one recommendation get scored
        twice.
        """
        pack = a_pack()
        assert control_row_id(pack, "2.3.1.1") == control_row_id(pack, "2_3_1_1")
        assert rule_row_id(pack, "2.3.1.1") == rule_row_id(pack, "2-3-1-1")


class TestTheTwoEnginesDoNotFight:
    def test_a_benchmark_rule_is_recognised_as_a_configuration_rule(
        self, db_session, loaded
    ):
        rule = (
            db_session.query(ComplianceRule)
            .filter(ComplianceRule.id == rule_row_id(loaded, "1.1"))
            .first()
        )
        assert ConfigCheck.is_config_rule(rule)

    def test_the_compliance_scan_skips_configuration_rules(self):
        """
        Regression guard, asserted against the source because the symptom is
        silent: without the skip, a compliance scan finds no evidence key,
        reads that as missing evidence and writes `manual_review` over the real
        verdict a credentialed scan established.
        """
        import inspect

        from core import compliance_tasks

        source = inspect.getsource(compliance_tasks.run_scan_task)
        assert "ConfigCheck.is_config_rule(rule)" in source
        assert "continue" in source

    def test_a_benchmark_rule_round_trips_back_into_a_check(self, db_session, loaded):
        rule = (
            db_session.query(ComplianceRule)
            .filter(ComplianceRule.id == rule_row_id(loaded, "1.1"))
            .first()
        )
        check = ConfigCheck.from_rule(rule)
        assert check.check_id == rule.id
        assert check.check_type == "registry"
        assert check.expect.operator == "equals"
        assert check.absent is AbsencePolicy.MANUAL_REVIEW
        assert check.remediation == "Set it to 1."


class TestProfileColumnDirection:
    def test_new_frameworks_do_not_use_saq_profiles(self, db_session, loaded):
        """
        `saq_profiles` is PCI-DSS's, and is left alone because the PCI scoping
        queries read it. `profiles` is the generic one. Two conventions for one
        idea is how they quietly diverge, so the direction is pinned.
        """
        controls = (
            db_session.query(ComplianceControl)
            .filter(ComplianceControl.framework_id == loaded.framework_id)
            .all()
        )
        assert all(not c.saq_profiles for c in controls)
        assert any(c.profiles for c in controls)

"""
tests/scans/test_config_audit_spec.py
─────────────────────────────────────────────────────────────────────────────
The declarative rule: what it refuses at construction, and whether it survives
a round trip through the database.

The round-trip test is the one that earns its place. ``ConfigCheck`` is a
dataclass and ``compliance_rules.check_definition`` is JSONB, and a field added
to the first without a home in the second stops being persisted with no error
anywhere — the rule simply comes back from the database with a default, and the
check quietly evaluates something other than what its author wrote.
"""

import dataclasses

import pytest

from core.config_audit.builtin import BUILTIN_CHECKS, builtin_checks_by_id
from core.config_audit.spec import (
    CHECK_TYPES,
    PLATFORMS,
    AbsencePolicy,
    ConfigCheck,
    Expectation,
    SpecError,
)
from db.models.compliance import RULE_CHECK_TYPES, RULE_TARGET_PLATFORMS


def minimal(**overrides) -> dict:
    params = dict(
        check_id="x.y",
        title="A check",
        check_type="registry",
        collect={"path": "HKLM\\SOFTWARE\\X"},
        expect=Expectation("equals", 1),
        absent=AbsencePolicy.MANUAL_REVIEW,
    )
    params.update(overrides)
    return params


class TestConstructionRefusesUnexecutableRules:
    def test_an_unknown_check_type_is_refused(self):
        with pytest.raises(SpecError, match="check_type"):
            ConfigCheck(**minimal(check_type="telepathy"))

    def test_an_unknown_platform_is_refused(self):
        with pytest.raises(SpecError, match="platform"):
            ConfigCheck(**minimal(platforms=("solaris",)))

    def test_an_unknown_operator_is_refused_at_the_expectation(self):
        """
        Caught here rather than at scan time, because the pre-Phase-3
        behaviour for a misspelled operator was to evaluate False and record a
        failure against every host.
        """
        with pytest.raises(SpecError, match="operator"):
            Expectation("grater_than", 5)

    def test_a_rule_with_no_collection_parameters_is_refused(self):
        with pytest.raises(SpecError, match="collect"):
            ConfigCheck(**minimal(collect={}))

    def test_an_empty_check_id_or_title_is_refused(self):
        with pytest.raises(SpecError):
            ConfigCheck(**minimal(check_id=""))
        with pytest.raises(SpecError):
            ConfigCheck(**minimal(title=""))

    def test_qod_outside_the_range_is_refused(self):
        with pytest.raises(SpecError, match="qod"):
            ConfigCheck(**minimal(qod=140))

    def test_severity_is_normalised_to_the_canonical_vocabulary(self):
        assert ConfigCheck(**minimal(severity="INFO")).severity == "none"
        assert ConfigCheck(**minimal(severity="nonsense")).severity == "unscored"


class TestAbsencePolicyHasNoDefault:
    """
    Every value of :class:`AbsencePolicy` is right for some real rule and wrong
    for others, so the rule author has to choose. A default would silently pick
    whichever answer flatters the score.
    """

    def test_absent_is_a_required_field(self):
        fields = {f.name: f for f in dataclasses.fields(ConfigCheck)}
        absent = fields["absent"]
        assert absent.default is dataclasses.MISSING
        assert absent.default_factory is dataclasses.MISSING

    def test_a_stored_definition_without_an_absent_policy_is_refused(self):
        with pytest.raises(SpecError, match="absent"):
            ConfigCheck.from_check_definition(
                {
                    "check_id": "x",
                    "check_type": "registry",
                    "collect": {"path": "p"},
                    "operator": "equals",
                    "expected": 1,
                }
            )

    def test_every_policy_maps_to_a_distinct_outcome(self):
        outcomes = {p: p.to_outcome() for p in AbsencePolicy}
        assert len(set(outcomes.values())) == len(AbsencePolicy)


class TestPlatformTargeting:
    def test_any_matches_every_platform(self):
        check = ConfigCheck(**minimal(platforms=("any",)))
        assert check.applies_to_platform("windows")
        assert check.applies_to_platform("linux")

    def test_an_unknown_platform_does_not_match_a_targeted_rule(self):
        """
        Guessing here is how a Windows registry rule comes to be evaluated
        against a switch. The engine reports it unresolved instead.
        """
        check = ConfigCheck(**minimal(platforms=("windows",)))
        assert not check.applies_to_platform("")
        assert not check.applies_to_platform(None)

    def test_matching_is_case_insensitive(self):
        check = ConfigCheck(**minimal(platforms=("windows",)))
        assert check.applies_to_platform("Windows")


class TestRoundTripThroughTheDatabaseShape:
    @pytest.mark.parametrize("check", BUILTIN_CHECKS, ids=lambda c: c.check_id)
    def test_every_builtin_check_survives_a_round_trip(self, check):
        definition = check.to_check_definition()
        restored = ConfigCheck.from_check_definition(
            definition, severity=check.severity
        )
        assert restored.check_id == check.check_id
        assert restored.title == check.title
        assert restored.check_type == check.check_type
        assert restored.collect == dict(check.collect)
        assert restored.expect.operator == check.expect.operator
        assert restored.expect.value == check.expect.value
        assert restored.absent is check.absent
        assert restored.platforms == check.platforms
        assert restored.domain == check.domain
        assert restored.severity == check.severity
        assert restored.remediation == check.remediation
        assert restored.references == check.references
        assert restored.qod == check.qod
        assert restored.requires_credentials == check.requires_credentials
        assert restored.intrusive == check.intrusive

    def test_the_marker_distinguishes_config_rules_from_evidence_key_rules(self):
        """
        The two rule kinds share several ``check_type`` names on purpose, so
        the marker in the definition is what tells them apart.
        """

        class Row:
            def __init__(self, definition):
                self.check_definition = definition

        assert ConfigCheck.is_config_rule(Row(BUILTIN_CHECKS[0].to_check_definition()))
        assert not ConfigCheck.is_config_rule(
            Row({"key": "uac_enabled", "operator": "equals", "expected": True})
        )
        assert not ConfigCheck.is_config_rule(Row(None))

    def test_the_column_wins_over_the_payload_for_identity_fields(self):
        """
        ``check_type``, ``severity`` and ``target_platform`` are real columns
        the database constrains and indexes. Where the JSONB disagrees with
        them, the column is what the constraints actually enforce.
        """

        class Row:
            id = "rule_from_column"
            check_type = "service"
            severity = "critical"
            target_platform = "linux"
            check_definition = {
                "config_check": True,
                "check_id": "stale_id_in_payload",
                "check_type": "registry",
                "collect": {"name": "auditd"},
                "operator": "equals",
                "expected": "active",
                "absent": "fail",
                "platforms": ["windows"],
            }

        check = ConfigCheck.from_rule(Row())
        assert check.check_id == "rule_from_column"
        assert check.check_type == "service"
        assert check.severity == "critical"
        assert check.platforms == ("linux",)


class TestVocabulariesStayAlignedWithTheDatabase:
    def test_every_spec_check_type_is_admitted_by_the_column_constraint(self):
        """
        A check type the spec allows but the CHECK constraint rejects makes the
        rule unsaveable — and the failure surfaces as an IntegrityError during
        seeding, far from the vocabulary that caused it.
        """
        assert set(CHECK_TYPES) <= set(RULE_CHECK_TYPES)

    def test_every_spec_platform_is_admitted_by_the_column_constraint(self):
        assert set(PLATFORMS) <= set(RULE_TARGET_PLATFORMS)


class TestTheBuiltinRulePack:
    def test_check_ids_are_unique(self):
        ids = [c.check_id for c in BUILTIN_CHECKS]
        assert len(ids) == len(set(ids))

    def test_every_check_has_remediation_and_a_rationale(self):
        """
        A finding a reader cannot act on is a finding they will ignore. Both
        fields reach the report.
        """
        missing = [
            c.check_id
            for c in BUILTIN_CHECKS
            if not c.remediation.strip() or not c.rationale.strip()
        ]
        assert not missing, missing

    def test_no_builtin_check_is_intrusive(self):
        """
        These run on every credentialed scan, including against OT hosts.
        Nothing in the default set may disrupt a target.
        """
        assert not [c.check_id for c in BUILTIN_CHECKS if c.intrusive]

    def test_every_check_targets_exactly_one_named_platform(self):
        """
        A host rule declared ``any`` would be dispatched at a switch or a
        database once those platforms exist.
        """
        loose = [c.check_id for c in BUILTIN_CHECKS if "any" in c.platforms]
        assert not loose, loose

    def test_lookup_by_id_covers_the_whole_pack(self):
        assert len(builtin_checks_by_id()) == len(BUILTIN_CHECKS)

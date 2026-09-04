"""
tests/scans/test_scap_content.py
─────────────────────────────────────────────────────────────────────────────
Converting SCAP content into a benchmark pack, and the coverage claim.
Phase 10, GAP-05.

The converter is where GAP-05 joins everything that already exists, so these
tests are mostly about *not* inventing a second way to do something Phase 3 and
Phase 4 already do — and about the three assessment states, which are what keep
the coverage figures honest.

No STIG content is committed here. The fixtures are CCURE-authored and shaped
like published content; the real datastreams are fetched by an operator, and
the tests that need one are skipped when it is absent rather than carrying a
copy.
"""

import json

import pytest

from core.benchmarks import dump_pack, parse_pack
from core.benchmarks.pack import (
    ASSESSMENT_AUTOMATED,
    ASSESSMENT_MANUAL,
    ASSESSMENT_UNIMPLEMENTED,
    PackError,
)
from core.checks.definitions import (
    DEFINITION_TYPE_CONFIG_CHECK,
    definition_id_for_check,
    definition_type_for_id,
)
from core.config_audit.spec import CHECK_TYPES, AbsencePolicy
from core.scap import applies_to_from_platforms, parse_content, supported_areas, to_pack
from db.models.compliance import RULE_CHECK_TYPES
from scripts.measure_scap_coverage import (
    DISCOVERED_AFTER_FREEZE,
    NOT_PLANNED,
    SCOPE,
    WINDOWS_NOT_IMPLEMENTED,
    WINDOWS_SCOPE,
)

from test_scap_parsers import BENCHMARK, SIMPLE_OVAL, datastream, oval  # noqa: F401

SCOPE_AREAS = {area for area, _t, _d in SCOPE}
#: Windows has its own frozen denominator. `SCOPE` was frozen at the start
#: of Phase 10 with the Windows OVAL schema deliberately excluded, and it
#: says it must not be edited to match what was built — so the Windows
#: areas are declared separately rather than appended to it.
WINDOWS_AREAS = {area for area, _t, _d in WINDOWS_SCOPE}


@pytest.fixture()
def pack_and_report():
    content = parse_content(datastream(BENCHMARK), origin="fixture")
    return to_pack(
        content,
        code="fixture_stig",
        publisher="CCURE (synthetic fixture)",
        licence="synthetic test fixture, not benchmark content",
        profile_id="stig",
    )


# ── Conversion ───────────────────────────────────────────────────────────────


def test_a_benchmark_becomes_a_pack_with_no_new_table(pack_and_report):
    """``scap.run.pack_conversion``. A benchmark *is* a framework — Phase 4."""
    pack, _report = pack_and_report
    assert pack.code == "FIXTURE_STIG"
    assert pack.framework_id == "cfw_bm_fixture_stig"
    assert pack.platform == "linux"
    assert {c.control_id for c in pack.controls} == {"one", "two"}


def test_an_ocil_rule_is_manual_not_a_gap(pack_and_report):
    """
    The benchmark is asking a human. That is a real state, and recording it as
    ``unimplemented`` would claim a gap in this build that does not exist.
    """
    pack, report = pack_and_report
    two = next(c for c in pack.controls if c.control_id == "two")
    assert two.assessment == ASSESSMENT_MANUAL
    assert two.check is None
    assert report.manual == 1


def test_an_automated_rule_carries_a_runnable_check(pack_and_report):
    pack, report = pack_and_report
    one = next(c for c in pack.controls if c.control_id == "one")
    assert one.assessment == ASSESSMENT_AUTOMATED
    assert one.check is not None
    assert one.check.check_type == "scap_rule"
    assert one.check.platforms == ("linux",)
    assert one.check.requires_credentials is True
    assert report.automated == 1


def test_an_unsupported_construct_becomes_unimplemented_with_a_reason():
    """
    ``scap.run.unsupported_not_assessed``, at load time. This is the phase's
    central rule and the reason the coverage figures can be read: a benchmark
    that silently drops what it cannot do reports better coverage than it has.
    """
    broken = SIMPLE_OVAL.replace("textfilecontent54_test", "partition_test").replace(
        "ind:partition_test", "linux:partition_test"
    )
    content = parse_content(datastream(BENCHMARK, broken))
    pack, report = to_pack(
        content,
        code="fixture_stig",
        publisher="CCURE (synthetic fixture)",
        licence="synthetic test fixture",
        profile_id="stig",
    )
    one = next(c for c in pack.controls if c.control_id == "one")
    assert one.assessment == ASSESSMENT_UNIMPLEMENTED
    assert one.check is None
    assert "partition_test" in one.unimplemented_reason
    assert report.unimplemented == 1
    assert report.total == len(pack.controls)


def test_a_vulnerability_class_definition_is_refused_not_inverted():
    """
    A ``compliance`` definition is TRUE when the host is hardened; a
    ``vulnerability`` one is TRUE when it is *affected*. Scoring the second
    with the first's polarity reports every vulnerable host as compliant —
    the worst direction available — so the class is read rather than assumed.
    """
    inverted = SIMPLE_OVAL.replace('class="compliance"', 'class="vulnerability"')
    content = parse_content(datastream(BENCHMARK, inverted))
    pack, _report = to_pack(
        content,
        code="fixture_stig",
        publisher="CCURE (synthetic fixture)",
        licence="synthetic test fixture",
        profile_id="stig",
    )
    one = next(c for c in pack.controls if c.control_id == "one")
    assert one.assessment == ASSESSMENT_UNIMPLEMENTED
    assert "invert" in one.unimplemented_reason


def test_the_profile_decides_which_rules_convert():
    """``scap.run.profile_selection``."""
    content = parse_content(datastream(BENCHMARK))
    pack, _ = to_pack(
        content,
        code="f",
        publisher="CCURE",
        licence="fixture",
        profile_id="base",
    )
    assert {c.control_id for c in pack.controls} == {"one"}


def test_an_unknown_profile_is_refused_with_the_ones_that_exist():
    content = parse_content(datastream(BENCHMARK))
    with pytest.raises(PackError, match="no profile"):
        to_pack(
            content,
            code="f",
            publisher="CCURE",
            licence="fixture",
            profile_id="nonexistent",
        )


def test_the_variable_bound_from_the_profile_reaches_the_check():
    """
    ``check-export`` maps an OVAL variable to an XCCDF Value, and
    ``refine-value`` picks which of that Value's options a profile wants. This
    is how "the STIG wants 15" reaches the comparison; without it the rule is
    evaluated against nothing.
    """
    oval_body = SIMPLE_OVAL.replace(
        '<ind:subexpression datatype="string" operation="equals">on</ind:subexpression>',
        '<ind:subexpression datatype="int" operation="greater than or equal"'
        ' var_ref="oval:t:var:1"/>',
    ).replace(
        "</states>",
        '</states><variables><external_variable id="oval:t:var:1" version="1"'
        ' datatype="int" comment="c"/></variables>',
    )
    benchmark = BENCHMARK.replace(
        '<check-content-ref href="t-oval.xml" name="oval:t:def:1"/>',
        '<check-export export-name="oval:t:var:1" value-id="xccdf_t_value_v"/>'
        '<check-content-ref href="t-oval.xml" name="oval:t:def:1"/>',
    )
    content = parse_content(datastream(benchmark, oval_body))
    pack, _ = to_pack(
        content,
        code="f",
        publisher="CCURE",
        licence="fixture",
        profile_id="stig",
    )
    one = next(c for c in pack.controls if c.control_id == "one")
    state = next(iter(one.check.collect["definition"]["states"].values()))
    assert state["fields"][0]["value"]["values"] == ["15"]


# ── Targeting ────────────────────────────────────────────────────────────────


def test_targeting_is_derived_from_the_benchmarks_own_platform(pack_and_report):
    """``scap.run.os_targeting``."""
    pack, _ = pack_and_report
    assert pack.applies_to == {
        "os_name_contains": ["red hat"],
        "os_version_prefix": ["9"],
    }


def test_a_rebuild_is_an_operator_decision_not_an_inference():
    """
    Nothing here decides that Rocky is close enough to Red Hat. That judgement
    has an audit consequence and belongs to the person signing the report, so
    it is supplied explicitly.
    """
    assert applies_to_from_platforms(["cpe:/o:redhat:enterprise_linux:9"]) == {
        "os_name_contains": ["red hat"],
        "os_version_prefix": ["9"],
    }
    assert "rocky" not in json.dumps(
        applies_to_from_platforms(["cpe:/o:redhat:enterprise_linux:9"])
    )
    content = parse_content(datastream(BENCHMARK))
    pack, _ = to_pack(
        content,
        code="f",
        publisher="CCURE",
        licence="fixture",
        profile_id="stig",
        applies_to={"os_name_contains": ["rocky"], "os_version_prefix": ["9"]},
    )
    assert pack.applies_to["os_name_contains"] == ["rocky"]


def test_an_unrecognised_platform_yields_no_targeting_rather_than_all_hosts():
    """
    ``{}`` means "the operator has to say", and the loader warns. A benchmark
    with no targeting runs its RHEL package names against Ubuntu and reads
    their absence as a verdict.
    """
    assert applies_to_from_platforms(["cpe:/a:example:thing:1"]) == {}
    assert applies_to_from_platforms([]) == {}


def test_targeting_reaches_every_converted_check(pack_and_report):
    pack, _ = pack_and_report
    for control in pack.controls:
        if control.check is not None:
            assert control.check.os_match == pack.applies_to


# ── Findings and identity ────────────────────────────────────────────────────


def test_a_converted_check_mints_a_usable_catalogue_key(pack_and_report):
    """``scap.report.finding`` — the existing path, with no new identifier kind."""
    pack, _ = pack_and_report
    one = next(c for c in pack.controls if c.control_id == "one")
    minted = definition_id_for_check(one.check.check_id, one.check.finding_type)
    assert minted.startswith("CCURE-CFG-")
    assert len(minted) <= 120
    assert definition_type_for_id(minted) == DEFINITION_TYPE_CONFIG_CHECK


def test_a_rule_whose_identifier_is_too_long_is_declined_not_truncated():
    """A truncated key silently merges two sibling rules into one catalogue row."""
    long_id = "x" * 120
    benchmark = BENCHMARK.replace("xccdf_t_rule_one", f"xccdf_t_rule_{long_id}")
    content = parse_content(datastream(benchmark))
    pack, _ = to_pack(
        content,
        code="f",
        publisher="CCURE",
        licence="fixture",
        profile_id="base",
    )
    control = pack.controls[0]
    assert control.assessment == ASSESSMENT_UNIMPLEMENTED
    assert "characters" in control.unimplemented_reason


def test_the_check_defers_on_an_absence_it_can_never_reach(pack_and_report):
    """
    The collector reports COLLECTED for both verdicts and UNAVAILABLE for
    everything else, so there is no absence to have a policy about. The spec
    still demands a deliberate choice, and MANUAL_REVIEW is the one value that
    could not flatter a score if the collector ever changed.
    """
    pack, _ = pack_and_report
    one = next(c for c in pack.controls if c.control_id == "one")
    assert one.check.absent is AbsencePolicy.MANUAL_REVIEW


def test_the_narrative_reaches_the_check(pack_and_report):
    """A finding that does not say what to do is not an audit finding."""
    pack, _ = pack_and_report
    one = next(c for c in pack.controls if c.control_id == "one")
    assert one.check.description and one.check.rationale and one.check.remediation
    assert one.check.metadata["stig_id"] == "one"
    assert one.check.metadata["oval_definition"] == "oval:t:def:1"


def test_the_crosswalk_reaches_the_control(pack_and_report):
    pack, _ = pack_and_report
    one = next(c for c in pack.controls if c.control_id == "one")
    assert "NIST_800_53_R5:AC-17" in one.crosswalk


# ── Provenance ───────────────────────────────────────────────────────────────


def test_publisher_and_licence_are_required(pack_and_report):
    """
    ``scap.run.provenance``. A result from SSG's STIG profile is SSG's
    rendering of the STIG's requirements, not a DISA certification, and a
    report has to be able to say which one it ran.
    """
    pack, _ = pack_and_report
    assert pack.publisher and pack.licence
    content = parse_content(datastream(BENCHMARK))
    with pytest.raises(PackError, match="licence"):
        to_pack(content, code="f", publisher="CCURE", licence="", profile_id="stig")
    with pytest.raises(PackError, match="publisher"):
        to_pack(content, code="f", publisher="", licence="fixture", profile_id="stig")


def test_a_pack_round_trips_through_json(pack_and_report):
    """
    ``dump_pack`` is the inverse of ``parse_pack``, and it exists because this
    phase produces packs in memory. Without it the content an operator
    reviewed and committed would be a different artefact from the one that ran.
    """
    pack, _ = pack_and_report
    restored = parse_pack(json.loads(json.dumps(dump_pack(pack))))
    assert restored.code == pack.code
    assert restored.framework_id == pack.framework_id
    assert restored.counts() == pack.counts()
    assert restored.applies_to == pack.applies_to
    original = next(c for c in pack.controls if c.check is not None)
    copy = next(c for c in restored.controls if c.control_id == original.control_id)
    assert copy.check.collect == original.check.collect
    assert copy.check.severity == original.check.severity
    assert copy.crosswalk == original.crosswalk


# ── Vocabulary and migration ─────────────────────────────────────────────────


def test_the_spec_and_the_model_agree_on_the_check_type():
    assert "scap_rule" in CHECK_TYPES
    assert "scap_rule" in RULE_CHECK_TYPES


def test_the_migration_renders_the_current_vocabulary_exactly():
    """
    The *newest* migration carries the exact-equality assertion; older ones
    assert only the subset relation, because a migration renders the vocabulary
    as of itself. When a later phase adds a check type, that assertion moves to
    the new migration and this one relaxes — see
    ``test_middleware_content.test_the_check_type_matches_the_migration``.
    """
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "c1d2e3f4a5b6_scap_rule_check_type.py"
    )
    spec = importlib.util.spec_from_file_location("_gap05_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert tuple(module.CHECK_TYPES) == tuple(RULE_CHECK_TYPES)
    assert "scap_rule" in module.CHECK_TYPES
    assert "scap_rule" not in module.OLD_CHECK_TYPES


def test_scap_rules_do_not_collide_with_the_builtin_pack():
    """
    GAP-05 ships no built-in rules. The engine's own pack is Phase 3's twenty,
    and a STIG is loaded content — keeping them apart is what lets the
    built-in pack stay a fixture rather than becoming a benchmark.
    """
    from core.config_audit.builtin import BUILTIN_CHECKS

    assert not [c for c in BUILTIN_CHECKS if c.check_type == "scap_rule"]


# ── The coverage claim ───────────────────────────────────────────────────────


def test_every_claimed_area_is_in_the_frozen_denominator():
    """
    The one failure this whole harness exists to prevent: a denominator that
    quietly grew to match the implementation.
    """
    unknown = supported_areas() - SCOPE_AREAS - WINDOWS_AREAS
    assert not unknown, f"code claims area(s) outside the frozen denominator: {unknown}"


def test_no_windows_area_is_both_claimed_and_excused():
    """
    The Windows half of the same guard. An area cannot be implemented and also
    carry a reason for not being implemented.
    """
    overlap = supported_areas() & set(WINDOWS_NOT_IMPLEMENTED)
    assert not overlap, f"{sorted(overlap)} are claimed and also excused"


def test_every_windows_area_is_either_implemented_or_has_a_reason():
    """
    No silent gaps: each of the ten Windows OVAL test types the DISA Windows 11
    STIG uses is either supported or listed with what it costs.
    """
    for area in WINDOWS_AREAS:
        assert area in supported_areas() or area in WINDOWS_NOT_IMPLEMENTED, (
            f"{area} is in the Windows denominator but is neither implemented "
            f"nor recorded as unimplemented"
        )


def test_no_area_recorded_as_not_planned_is_claimed_as_implemented():
    overlap = supported_areas() & set(NOT_PLANNED)
    assert not overlap, f"{sorted(overlap)} are claimed and also excused"


def test_areas_found_after_the_freeze_are_not_implemented():
    assert not (supported_areas() & set(DISCOVERED_AFTER_FREEZE))


def test_the_capability_claim_is_read_from_the_dispatch_tables():
    """
    Removing a probe must remove its coverage credit. A list kept beside the
    code keeps saying "implemented" after the code is gone, which is exactly
    the failure a coverage figure must not have.
    """
    from core.scap import probes as probes_module

    before = supported_areas()
    assert "scap.oval.rpminfo" in before
    saved = probes_module.PROBES.pop("linux:rpminfo_object")
    try:
        assert "scap.oval.rpminfo" not in supported_areas()
    finally:
        probes_module.PROBES["linux:rpminfo_object"] = saved
    assert supported_areas() == before

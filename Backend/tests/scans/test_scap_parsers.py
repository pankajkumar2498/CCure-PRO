"""
tests/scans/test_scap_parsers.py
─────────────────────────────────────────────────────────────────────────────
XCCDF and OVAL reading, and the compiler that refuses what it cannot evaluate.
Phase 10, GAP-05.

These are pure-function tests over hand-built content. They exist because every
defect this phase found on real content was a *parser* defect that produced a
plausible-looking result: values collected from the wrong level of the tree,
reference text discarded in favour of its href, a rule id too long to mint a
key from. None of them raised. All of them reduced the benchmark quietly.

The fixtures below are CCURE-authored and shaped like published content. They
carry **no real STIG rule text, no real CCI-to-800-53 mapping and no real
benchmark values** — inventing any of those would put a false compliance claim
into a test that then asserts it, which is the failure mode this programme has
refused since Phase 4.
"""

import pytest

from core.scap.cci import (
    base_control,
    crosswalk_entries,
    known_controls,
    parse_cci_list,
)
from core.scap.oval import (
    CRITERIA_OPERATORS,
    OvalError,
    UnsupportedConstruct,
    literal_prefix,
    parse_oval,
    schema_of,
)
from core.scap.xccdf import XccdfError, parse_content
from scripts.measure_scap_coverage import DISCOVERED_AFTER_FREEZE, NOT_PLANNED, SCOPE

# ── Fixtures ─────────────────────────────────────────────────────────────────

OVAL_HEAD = (
    '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"'
    ' xmlns:ind="http://oval.mitre.org/XMLSchema/oval-definitions-5#independent"'
    ' xmlns:unix="http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"'
    ' xmlns:linux="http://oval.mitre.org/XMLSchema/oval-definitions-5#linux">'
)


def oval(body: str) -> str:
    return f"{OVAL_HEAD}{body}</oval_definitions>"


SIMPLE_OVAL = oval(
    """
  <definitions>
    <definition id="oval:t:def:1" version="1" class="compliance">
      <metadata><title>a directive</title></metadata>
      <criteria operator="AND">
        <criterion test_ref="oval:t:tst:1"/>
      </criteria>
    </definition>
  </definitions>
  <tests>
    <ind:textfilecontent54_test id="oval:t:tst:1" version="1"
        check="all" check_existence="all_exist">
      <ind:object object_ref="oval:t:obj:1"/>
      <ind:state state_ref="oval:t:ste:1"/>
    </ind:textfilecontent54_test>
  </tests>
  <objects>
    <ind:textfilecontent54_object id="oval:t:obj:1" version="1">
      <ind:filepath>/etc/example.conf</ind:filepath>
      <ind:pattern operation="pattern match">^Setting\\s+(\\S+)$</ind:pattern>
    </ind:textfilecontent54_object>
  </objects>
  <states>
    <ind:textfilecontent54_state id="oval:t:ste:1" version="1">
      <ind:subexpression datatype="string" operation="equals">on</ind:subexpression>
    </ind:textfilecontent54_state>
  </states>
"""
)


def datastream(xccdf_body: str, oval_body: str = SIMPLE_OVAL) -> str:
    return f"""<?xml version="1.0"?>
<ds:data-stream-collection xmlns:ds="http://scap.nist.gov/schema/scap/source/1.2"
    xmlns:xlink="http://www.w3.org/1999/xlink"
    xmlns:cat="urn:oasis:names:tc:entity:xmlns:xml:catalog" id="c">
  <ds:data-stream id="ds" scap-version="1.3">
    <ds:checklists>
      <ds:component-ref id="cref_x" xlink:href="#comp_x">
        <cat:catalog><cat:uri name="t-oval.xml" uri="#cref_o"/></cat:catalog>
      </ds:component-ref>
    </ds:checklists>
    <ds:checks><ds:component-ref id="cref_o" xlink:href="#comp_o"/></ds:checks>
  </ds:data-stream>
  <ds:component id="comp_x">{xccdf_body}</ds:component>
  <ds:component id="comp_o">{oval_body}</ds:component>
</ds:data-stream-collection>"""


BENCHMARK = """
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2" id="xccdf_t_benchmark_b">
  <title>Fixture Benchmark</title>
  <version>V1R1</version>
  <platform idref="cpe:/o:redhat:enterprise_linux:9"/>
  <Profile id="xccdf_t_profile_base">
    <title>base</title>
    <select idref="xccdf_t_rule_one" selected="true"/>
  </Profile>
  <Profile id="xccdf_t_profile_stig" extends="xccdf_t_profile_base">
    <title>stig</title>
    <select idref="xccdf_t_rule_two" selected="true"/>
    <refine-value idref="xccdf_t_value_v" selector="strict"/>
  </Profile>
  <Group id="xccdf_t_group_g">
    <title>Group One</title>
    <Value id="xccdf_t_value_v" type="number">
      <title>a parameter</title>
      <value selector="strict">15</value>
      <value>8</value>
    </Value>
    <Rule id="xccdf_t_rule_one" severity="high" selected="false">
      <title>Rule One</title>
      <description>First fixture rule.</description>
      <rationale>Because.</rationale>
      <fixtext>Set it.</fixtext>
      <ident system="https://public.cyber.mil/stigs/cci/">CCI-999001</ident>
      <reference href="https://nvd.nist.gov/800-53/Rev5">AC-17 (1)</reference>
      <reference href="https://www.cisecurity.org/controls/">11</reference>
      <check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
        <check-content-ref href="t-oval.xml" name="oval:t:def:1"/>
      </check>
    </Rule>
    <Rule id="xccdf_t_rule_two" severity="low" selected="false">
      <title>Rule Two</title>
      <description>Second fixture rule.</description>
      <check system="http://scap.nist.gov/schema/ocil/2">
        <check-content-ref href="t-ocil.xml" name="ocil:t:questionnaire:1"/>
      </check>
    </Rule>
  </Group>
</Benchmark>
"""


@pytest.fixture()
def content():
    return parse_content(datastream(BENCHMARK), origin="fixture")


# ── Datastream and XCCDF ─────────────────────────────────────────────────────


def test_a_datastream_resolves_its_oval_through_the_catalogue(content):
    """
    ``scap.ingest.datastream``.

    The XCCDF names ``t-oval.xml``; only the catalogue knows that means the
    embedded component. Skipping that indirection leaves every rule unable to
    find its check, which presents as a benchmark where nothing is automated
    rather than as a parse failure.
    """
    assert content.oval_for("t-oval.xml") is not None
    assert content.oval_for("t-oval.xml").definitions


def test_the_benchmark_tree_is_walked_for_rules(content):
    """``scap.ingest.xccdf_benchmark``."""
    assert {r.rule_id for r in content.benchmark.rules} == {
        "xccdf_t_rule_one",
        "xccdf_t_rule_two",
    }
    assert content.benchmark.rules[0].group_path == ("Group One",)


def test_values_are_collected_from_inside_groups(content):
    """
    ``scap.ingest.xccdf_value``, and the defect that motivated it.

    XCCDF permits ``<Value>`` inside a ``<Group>`` and SCAP Security Guide puts
    nearly all of them there. Reading only the Benchmark's direct children
    found **zero** values in the real RHEL 9 datastream, which made every
    parameterised rule fail to compile for want of a variable binding — and
    those rules then loaded as ``unimplemented`` with a plausible reason, so
    nothing looked broken.
    """
    assert "xccdf_t_value_v" in content.benchmark.values


def test_profile_inheritance_selects_the_parents_rules_too(content):
    """``scap.ingest.xccdf_profile``."""
    profile = content.benchmark.resolved_profile("xccdf_t_profile_stig")
    assert profile.selections == {
        "xccdf_t_rule_one": True,
        "xccdf_t_rule_two": True,
    }
    selected = {
        r.rule_id for r in content.benchmark.rules_in_profile("xccdf_t_profile_stig")
    }
    assert selected == {"xccdf_t_rule_one", "xccdf_t_rule_two"}


def test_refine_value_picks_the_profiles_selector(content):
    """The mechanism by which one rule carries different numbers per profile."""
    assert content.benchmark.values_for_profile("xccdf_t_profile_stig") == {
        "xccdf_t_value_v": "15"
    }
    assert content.benchmark.values_for_profile(None) == {"xccdf_t_value_v": "8"}


def test_rule_metadata_survives_the_parse(content):
    """``scap.ingest.xccdf_metadata`` — a verdict with no fix text is unusable."""
    rule = next(r for r in content.benchmark.rules if r.rule_id == "xccdf_t_rule_one")
    assert rule.title == "Rule One"
    assert rule.description
    assert rule.rationale
    assert rule.fixtext
    assert rule.severity == "high"


def test_reference_text_is_kept_beside_its_href(content):
    """
    ``scap.ingest.stig_identity``.

    SSG writes ``<reference href="…/cci/">CCI-000366</reference>``: the href
    names the catalogue, the *text* is the identifier. Keeping only the href —
    which the first implementation did — discards every CCI and every NIST
    control in the benchmark and leaves a list of URLs repeated across hundreds
    of rules.
    """
    rule = next(r for r in content.benchmark.rules if r.rule_id == "xccdf_t_rule_one")
    assert ("https://nvd.nist.gov/800-53/Rev5", "AC-17 (1)") in rule.references
    assert rule.cci_ids == ("CCI-999001",)


def test_a_rule_with_no_version_still_yields_a_short_identifier(content):
    """
    No SSG rule carries ``<version>``, so the id falls back to the rule id —
    and the raw XCCDF form is long enough that dozens of rules exceeded the
    catalogue-key ceiling and were dropped as unconvertible. Stripping the
    XCCDF 1.2 scaffolding is defined by the specification, not by a
    publisher's convention.
    """
    rule = next(r for r in content.benchmark.rules if r.rule_id == "xccdf_t_rule_one")
    assert rule.version == ""
    assert rule.short_name == "one"
    assert rule.stig_id == "one"


def test_a_second_benchmark_is_refused_rather_than_guessed_at():
    doubled = (
        datastream(BENCHMARK).replace("</ds:component>", "</ds:component>", 1) + ""
    )
    payload = doubled.replace(
        '<ds:component id="comp_o">',
        f'<ds:component id="comp_x2">{BENCHMARK}</ds:component><ds:component id="comp_o">',
        1,
    )
    with pytest.raises(XccdfError, match="benchmarks"):
        parse_content(payload)


def test_a_doctype_is_refused_before_the_parser_sees_it():
    """
    Same ban as Phase 8's, one format over. ElementTree expands internal
    entities, and this content is downloaded from outside the product.
    """
    with pytest.raises(XccdfError, match="DOCTYPE"):
        parse_content('<!DOCTYPE x [<!ENTITY a "b">]>' + datastream(BENCHMARK))


def test_content_larger_than_the_ceiling_is_refused(monkeypatch):
    from core.scap import xccdf as module

    monkeypatch.setattr(module, "MAX_CONTENT_BYTES", 10)
    with pytest.raises(XccdfError, match="ceiling"):
        parse_content(datastream(BENCHMARK))


def test_the_digest_is_recorded_and_a_mismatch_refused(tmp_path, content):
    """``scap.ingest.integrity``."""
    from core.scap import load_content

    path = tmp_path / "ds.xml"
    path.write_text(datastream(BENCHMARK), encoding="utf-8")
    good = load_content(path)
    assert len(good.digest) == 64
    load_content(path, expected_digest=good.digest.upper())
    with pytest.raises(XccdfError, match="SHA-256"):
        load_content(path, expected_digest="0" * 64)


# ── OVAL ─────────────────────────────────────────────────────────────────────


def test_schemas_are_read_not_stripped():
    """
    ``file_test`` exists in the unix schema *and* the windows schema. Phase 8
    strips namespaces because Tomcat's made every selection empty; here
    stripping would merge two different tests and hand a Windows registry rule
    to a Unix probe.
    """
    assert (
        schema_of("{http://oval.mitre.org/XMLSchema/oval-definitions-5#unix}file_test")
        == "unix"
    )
    assert (
        schema_of(
            "{http://oval.mitre.org/XMLSchema/oval-definitions-5#windows}file_test"
        )
        == "windows"
    )


def test_a_definition_compiles_to_a_self_contained_payload():
    """``scap.ingest.oval_document`` — the rule must not need its datastream."""
    import json

    document = parse_oval(SIMPLE_OVAL)
    compiled = document.compile_definition("oval:t:def:1")
    payload = compiled.as_dict()
    json.dumps(payload)  # must survive the JSONB round trip
    assert payload["tests"] and payload["objects"] and payload["states"]
    assert payload["test_types"] == ["independent:textfilecontent54_test"]


def test_all_four_criteria_operators_are_supported():
    """``scap.oval.criteria_logic``."""
    assert set(CRITERIA_OPERATORS) == {"AND", "OR", "ONE", "XOR"}


def test_an_unimplemented_test_type_is_refused_not_ignored():
    """
    ``scap.run.unsupported_not_assessed``. The whole phase turns on this: a
    construct this build cannot evaluate must stop the rule from becoming a
    check, so it is recorded as unimplemented rather than silently evaluated
    on a subset of its criteria.
    """
    body = SIMPLE_OVAL.replace("textfilecontent54_test", "partition_test").replace(
        "ind:partition_test", "linux:partition_test"
    )
    document = parse_oval(body)
    with pytest.raises(UnsupportedConstruct, match="not implemented"):
        document.compile_definition("oval:t:def:1")


def test_a_local_variable_is_named_as_the_reason():
    """
    Reporting "could not resolve a variable" for both a local_variable and an
    unbound external one hides which of the two a benchmark is losing rules to,
    and therefore what to build next. 107 rules in the RHEL 9 STIG profile fall
    into the first.
    """
    body = SIMPLE_OVAL.replace(
        '<ind:subexpression datatype="string" operation="equals">on</ind:subexpression>',
        '<ind:subexpression datatype="int" operation="equals" var_ref="oval:t:var:1"/>',
    ).replace(
        "</states>",
        '</states><variables><local_variable id="oval:t:var:1" version="1"'
        ' datatype="int" comment="c"><count><object_component'
        ' object_ref="oval:t:obj:1" item_field="instance"/></count>'
        "</local_variable></variables>",
    )
    document = parse_oval(body)
    with pytest.raises(UnsupportedConstruct, match="local_variable"):
        document.compile_definition("oval:t:def:1")


def test_an_extend_definition_cycle_is_refused():
    body = oval(
        """
  <definitions>
    <definition id="oval:t:def:1" version="1" class="compliance">
      <criteria><extend_definition definition_ref="oval:t:def:2"/></criteria>
    </definition>
    <definition id="oval:t:def:2" version="1" class="compliance">
      <criteria><extend_definition definition_ref="oval:t:def:1"/></criteria>
    </definition>
  </definitions>
"""
    )
    with pytest.raises(UnsupportedConstruct, match="cycle"):
        parse_oval(body).compile_definition("oval:t:def:1")


def test_an_object_selecting_a_path_by_an_unresolvable_operation_is_refused():
    """
    An entity selects **which items to collect**, so an operation this build
    cannot resolve is not a comparison it gets wrong — it is a set of items it
    never gathers, and every ``check_existence`` value is decided by how many
    items there are. Refused at compile time so it lands in the load tally
    rather than erroring on every host the benchmark runs against.
    """
    body = SIMPLE_OVAL.replace(
        "<ind:filepath>/etc/example.conf</ind:filepath>",
        '<ind:filepath operation="not equal">/etc/example.conf</ind:filepath>',
    )
    with pytest.raises(UnsupportedConstruct, match="selects filepath"):
        parse_oval(body).compile_definition("oval:t:def:1")


def test_a_path_pattern_with_no_literal_root_is_refused():
    body = SIMPLE_OVAL.replace(
        "<ind:filepath>/etc/example.conf</ind:filepath>",
        '<ind:filepath operation="pattern match">^(/etc/a|/etc/b)$</ind:filepath>',
    )
    with pytest.raises(UnsupportedConstruct, match="literal directory"):
        parse_oval(body).compile_definition("oval:t:def:1")


def test_a_document_with_no_definitions_is_an_error_not_an_empty_result():
    with pytest.raises(OvalError, match="no definitions"):
        parse_oval(oval("<definitions></definitions>"))


@pytest.mark.parametrize(
    "pattern,expected",
    [
        (r"^\/etc\/(sudoers|sudoers\.d\/.*)$", "/etc"),
        (r"^/etc/sudoers(\.d/.*)?$", "/etc"),
        (r"^/etc/ssh/sshd_config$", "/etc/ssh"),
        (r".*\.conf", ""),
        (r"^(/etc/a|/etc/b)$", ""),
    ],
)
def test_literal_prefix_bounds_a_path_search(pattern, expected):
    """
    ``\\/`` is PCRE's escaped separator and SSG writes paths that way. Reading
    it as a character class yields no prefix at all, and every rule written in
    that style is then declined — 32 of them in the RHEL 9 STIG profile.
    """
    assert literal_prefix(pattern) == expected


# ── CCI crosswalk ────────────────────────────────────────────────────────────


def test_cci_list_parses_to_base_controls():
    """
    ``scap.ingest.cci_map``. The identifiers below are deliberately synthetic:
    no real CCI-to-800-53 mapping is written into this repository, because
    inventing one puts a false compliance claim into a customer's report.
    """
    document = """<?xml version="1.0"?>
<cci_list xmlns="http://iase.disa.mil/cci">
  <cci_items>
    <cci_item id="CCI-999001">
      <references>
        <reference creator="NIST" title="NIST SP 800-53 Revision 5" index="AC-17 (1)"/>
      </references>
    </cci_item>
  </cci_items>
</cci_list>"""
    assert parse_cci_list(document) == {"CCI-999001": ("AC-17",)}


def test_an_unreadable_cci_list_raises_rather_than_yielding_nothing():
    with pytest.raises(ValueError):
        parse_cci_list("<cci_list></cci_list>")


@pytest.mark.parametrize(
    "reference,expected",
    [("AC-17 (1)", "AC-17"), ("ac-17", "AC-17"), ("AC-3", "AC-3"), ("nonsense", "")],
)
def test_enhancements_collapse_to_the_base_control(reference, expected):
    """
    The seeded catalogue holds the 252 base controls, so a crosswalk naming
    ``AC-17 (1)`` resolves to nothing — silently — in gap analysis and in
    cross-framework inheritance. That is the dangling-crosswalk defect
    CLAUDE.md records against thirteen ISO entries.
    """
    assert base_control(reference) == expected


def test_a_csf_identifier_is_not_read_as_an_800_53_control():
    """
    ``PR.DS-01`` yielded ``DS-1`` on the first real run, and ``DS-1`` is not a
    NIST SP 800-53 control. The reference's href says "nist", so the source
    filter alone let it through.
    """
    assert (
        crosswalk_entries((), (("https://csrc.nist.gov/cyberframework", "PR.DS-01"),))
        == ()
    )


def test_a_crosswalk_entry_must_name_a_control_the_catalogue_has():
    assert known_controls(), "the seeded NIST SP 800-53 catalogue should be readable"
    assert crosswalk_entries(
        (), (("https://nvd.nist.gov/800-53/Rev5", "AC-17 (1)"),)
    ) == ("NIST_800_53_R5:AC-17",)
    assert crosswalk_entries((), (("https://nvd.nist.gov/800-53/Rev5", "ZZ-99"),)) == ()


def test_a_reference_that_is_not_about_800_53_is_ignored():
    assert (
        crosswalk_entries((), (("https://www.cisecurity.org/controls/", "11"),)) == ()
    )


# ── The denominator itself ───────────────────────────────────────────────────


def test_the_frozen_denominator_has_no_duplicates():
    areas = [area for area, _t, _d in SCOPE]
    assert len(areas) == len(set(areas))


def test_every_not_planned_area_is_in_the_denominator_and_carries_a_reason():
    areas = {area for area, _t, _d in SCOPE}
    assert set(NOT_PLANNED) <= areas
    for area, reason in NOT_PLANNED.items():
        assert len(reason) > 40, f"{area} does not say why"


def test_areas_found_after_the_freeze_are_recorded_outside_the_frozen_list():
    """
    ``systemdunitdependency`` and the OpenSCAP Script Check Engine were both
    used by real content and neither was named when the denominator was frozen.
    They are reported separately and against a corrected total rather than
    added to ``SCOPE``: the frozen list is what was predicted before
    implementation, and editing it after the fact destroys the only thing it
    was for.
    """
    areas = {area for area, _t, _d in SCOPE}
    assert DISCOVERED_AFTER_FREEZE
    assert not (set(DISCOVERED_AFTER_FREEZE) & areas)
    for area, reason in DISCOVERED_AFTER_FREEZE.items():
        assert len(reason) > 40, f"{area} does not say why"

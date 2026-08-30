"""
tests/scans/test_scap_applicability.py
─────────────────────────────────────────────────────────────────────────────
CPE platform applicability, and the remaining OVAL probes. Phase 10, GAP-05.

Applicability earns its own file because it was the phase's largest measured
defect and it is not obvious. A STIG rule is frequently conditional: "if PAM is
installed", "if this is a real system with a kernel rather than a container",
"unless the architecture is aarch64". Ignoring those conditions does not make
the scan stricter — it makes it wrong. Measured against ``oscap`` on the same
host with the same content, ignoring them produced **128 verdicts on rules it
correctly skipped, 102 of them findings** about software the target does not
have.

The nesting is the part that is easy to get wrong twice. Platforms declared
side by side are alternatives; platforms inherited from different levels are
cumulative. Reading the second as the first left 17 rules applicable that
``oscap`` skipped — every one a Group saying "a system with a kernel" and a
Rule saying "and PAM is installed", which in a container are false and true
respectively.
"""

import pytest

from core.config_audit.collection import CollectionContext
from core.scap.evaluate import Outcome, evaluate_applicability
from core.scap.probes import collect_object
from core.scap.xccdf import parse_content, parse_cpe_platforms

from test_scap_evaluation import FakeResult, FakeShell, ctx, found, one_test_definition
from test_scap_parsers import BENCHMARK, SIMPLE_OVAL, datastream, oval


# ── The CPE platform tree ────────────────────────────────────────────────────


def platform_payload(*levels, definitions=None):
    """A compiled applicability payload: AND across levels, OR within one."""
    return {
        "operator": "AND",
        "platforms": [
            {
                "kind": "logical",
                "operator": "OR",
                "negate": False,
                "children": [
                    {
                        "kind": "logical",
                        "operator": "AND",
                        "negate": False,
                        "children": [{"kind": "fact", "definition": ref}],
                    }
                    for ref in level
                ],
            }
            for level in levels
        ],
        "definitions": definitions or {},
    }


def fact_definition(present):
    """A compiled definition that is TRUE when the fixture file has the line."""
    compiled = one_test_definition(states=["s1"])
    compiled["objects"]["o1"]["entities"]["filepath"]["values"] = [
        f"/etc/{'present' if present else 'absent'}.conf"
    ]
    return compiled


def test_a_rule_whose_platform_is_absent_is_not_applicable():
    """
    ``scap.ingest.cpe_applicability``. Not a failure — the benchmark itself
    says the rule is conditional, and a host without the software has not
    breached a control about it.
    """
    shell = FakeShell(
        [
            ("present.conf", found("Setting on\n")),
            ("absent.conf", FakeResult("CCURE::MISSING::")),
        ]
    )
    definitions = {"yes": fact_definition(True), "no": fact_definition(False)}
    assert (
        evaluate_applicability(
            ctx(shell), platform_payload(["yes"], definitions=definitions)
        )
        is Outcome.TRUE
    )
    assert (
        evaluate_applicability(
            ctx(shell), platform_payload(["no"], definitions=definitions)
        )
        is Outcome.FALSE
    )


def test_platforms_from_different_levels_are_cumulative():
    """
    A Group that applies only to a system with a kernel does not stop applying
    because a Rule inside it also names a package that happens to be installed.
    OR-ing the two left 17 rules applicable that ``oscap`` skipped.
    """
    shell = FakeShell(
        [
            ("present.conf", found("Setting on\n")),
            ("absent.conf", FakeResult("CCURE::MISSING::")),
        ]
    )
    definitions = {"yes": fact_definition(True), "no": fact_definition(False)}
    assert (
        evaluate_applicability(
            ctx(shell), platform_payload(["no"], ["yes"], definitions=definitions)
        )
        is Outcome.FALSE
    )


def test_platforms_at_one_level_are_alternatives():
    shell = FakeShell(
        [
            ("present.conf", found("Setting on\n")),
            ("absent.conf", FakeResult("CCURE::MISSING::")),
        ]
    )
    definitions = {"yes": fact_definition(True), "no": fact_definition(False)}
    assert (
        evaluate_applicability(
            ctx(shell), platform_payload(["no", "yes"], definitions=definitions)
        )
        is Outcome.TRUE
    )


def test_an_unestablished_platform_is_unknown_not_applicable():
    """
    Reading "we could not tell whether this applies" as "it applies" puts the
    verdict back into the false-positive class applicability exists to remove;
    reading it as "it does not" silently drops a control from the score.
    """
    shell = FakeShell([("present.conf", FakeResult("", 1, "denied"))])
    definitions = {"yes": fact_definition(True)}
    assert (
        evaluate_applicability(
            ctx(shell), platform_payload(["yes"], definitions=definitions)
        )
        is Outcome.UNKNOWN
    )


def test_a_platform_with_no_compiled_definition_is_unknown():
    assert (
        evaluate_applicability(ctx(FakeShell()), platform_payload(["missing"]))
        is Outcome.UNKNOWN
    )


def test_no_platforms_means_the_rule_applies():
    assert evaluate_applicability(ctx(FakeShell()), {"platforms": []}) is Outcome.TRUE


def test_applicability_is_measured_once_per_host():
    """
    "Is this a real system with a kernel" is asked by a hundred rules and its
    answer cannot differ between them.
    """
    shell = FakeShell([("present.conf", found("Setting on\n"))])
    context = ctx(shell)
    payload = platform_payload(["yes"], definitions={"yes": fact_definition(True)})
    for _ in range(6):
        evaluate_applicability(context, payload)
    assert len(shell.commands) == 1


def test_platform_inheritance_is_read_from_the_group_tree():
    """
    103 of the Ubuntu STIG profile's rules inherit ``system_with_kernel`` from
    an enclosing Group rather than declaring it. Reading only rule-level
    platforms finds a third of what is there.
    """
    benchmark = BENCHMARK.replace(
        '<Group id="xccdf_t_group_g">\n    <title>Group One</title>',
        '<Group id="xccdf_t_group_g">\n    <title>Group One</title>\n'
        '    <platform idref="#system_with_kernel"/>',
    ).replace(
        '<Rule id="xccdf_t_rule_one" severity="high" selected="false">',
        '<Rule id="xccdf_t_rule_one" severity="high" selected="false">\n'
        '      <platform idref="#package_pam"/>',
    )
    content = parse_content(datastream(benchmark))
    rule = next(r for r in content.benchmark.rules if r.rule_id == "xccdf_t_rule_one")
    assert "system_with_kernel" in rule.platforms
    assert "package_pam" in rule.platforms
    # Benchmark CPE, then the Group's, then the Rule's — three distinct levels.
    assert rule.platform_levels == (
        ("cpe:/o:redhat:enterprise_linux:9",),
        ("system_with_kernel",),
        ("package_pam",),
    )


def test_cpe_platform_definitions_are_parsed_from_the_content():
    from xml.etree import ElementTree as ET

    document = ET.fromstring(
        '<x xmlns:cpe="http://cpe.mitre.org/language/2.0">'
        '<cpe:platform id="system_with_kernel">'
        '<cpe:logical-test operator="AND" negate="false">'
        '<cpe:check-fact-ref system="http://oval.mitre.org/XMLSchema/oval-definitions-5"'
        ' href="cpe-oval.xml" id-ref="oval:x:def:1"/>'
        "</cpe:logical-test></cpe:platform></x>"
    )
    platforms = parse_cpe_platforms(document)
    assert set(platforms) == {"system_with_kernel"}
    tree = platforms["system_with_kernel"]
    assert tree["operator"] == "AND"
    assert tree["children"][0]["definition"] == "oval:x:def:1"


def test_a_platform_whose_check_cannot_be_compiled_makes_the_rule_unimplemented():
    """
    Consistent with every other unsupported construct: recorded at load time
    with a reason, never evaluated as though the condition held.
    """
    from core.scap import to_pack

    cpe_oval = oval(
        """
  <definitions>
    <definition id="oval:cpe:def:1" version="1" class="inventory">
      <criteria><criterion test_ref="oval:cpe:tst:1"/></criteria>
    </definition>
  </definitions>
  <tests>
    <linux:partition_test id="oval:cpe:tst:1" version="1" check="all">
      <linux:object object_ref="oval:cpe:obj:1"/>
    </linux:partition_test>
  </tests>
  <objects>
    <linux:partition_object id="oval:cpe:obj:1" version="1">
      <linux:mount_point>/</linux:mount_point>
    </linux:partition_object>
  </objects>
"""
    )
    benchmark = BENCHMARK.replace(
        '<Rule id="xccdf_t_rule_one" severity="high" selected="false">',
        '<Rule id="xccdf_t_rule_one" severity="high" selected="false">\n'
        '      <platform idref="#needs_partition"/>',
    )
    payload = datastream(benchmark).replace(
        '<ds:component id="comp_o">',
        '<ds:component id="comp_cpe">'
        '<cpe:platform xmlns:cpe="http://cpe.mitre.org/language/2.0"'
        ' id="needs_partition">'
        '<cpe:logical-test operator="AND" negate="false">'
        '<cpe:check-fact-ref system="http://oval.mitre.org/XMLSchema/oval-definitions-5"'
        ' href="cpe-oval.xml" id-ref="oval:cpe:def:1"/>'
        "</cpe:logical-test></cpe:platform>"
        f"{cpe_oval}"
        '</ds:component><ds:component id="comp_o">',
        1,
    )
    content = parse_content(payload)
    pack, report = to_pack(
        content,
        code="f",
        publisher="CCURE",
        licence="fixture",
        profile_id="base",
    )
    control = next(c for c in pack.controls if c.control_id == "one")
    assert control.assessment == "unimplemented"
    assert "applicability" in control.unimplemented_reason


# ── The remaining probes ─────────────────────────────────────────────────────


def test_xmlfilecontent_selects_by_xpath():
    """``scap.oval.xmlfilecontent`` — reuses Phase 8's XML reader."""
    shell = FakeShell([("server.xml", found("<Server port='8005'><a/></Server>"))])
    obj = {
        "type": "independent:xmlfilecontent_object",
        "entities": {
            "filepath": {"values": ["/etc/server.xml"], "operation": "equals"},
            "xpath": {"values": ["/Server/@port"], "operation": "equals"},
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert result.ok
    assert result.items[0]["value_of"] == "8005"


def test_yamlfilecontent_selects_by_a_dotted_path():
    """``scap.oval.yamlfilecontent`` — reuses Phase 9's YAML reader."""
    shell = FakeShell(
        [("config.yaml", found("authentication:\n  anonymous:\n    enabled: false\n"))]
    )
    obj = {
        "type": "independent:yamlfilecontent_object",
        "entities": {
            "filepath": {"values": ["/etc/config.yaml"], "operation": "equals"},
            "yamlpath": {
                "values": [".authentication.anonymous.enabled"],
                "operation": "equals",
            },
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert result.ok
    assert result.items[0]["value"] is False


def test_a_yamlpath_beyond_the_supported_subset_is_declined():
    """
    A yamlpath silently read as something else produces a confident verdict
    about the wrong key.
    """
    shell = FakeShell([("config.yaml", found("a: 1\n"))])
    obj = {
        "type": "independent:yamlfilecontent_object",
        "entities": {
            "filepath": {"values": ["/etc/config.yaml"], "operation": "equals"},
            "yamlpath": {"values": [".items[*].name"], "operation": "equals"},
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert not result.ok
    assert "subset" in result.detail


def test_uname_reports_the_kernel_and_release():
    """``scap.oval.uname``."""
    shell = FakeShell(
        [("uname", FakeResult("CCURE::REC::Linux|host|6.8.0-40-generic|#1 SMP|x86_64"))]
    )
    result = collect_object(ctx(shell), {"type": "unix:uname_object"})
    assert result.ok
    item = result.items[0]
    assert item["os_name"] == "Linux"
    assert item["os_release"] == "6.8.0-40-generic"
    assert item["machine_class"] == "x86_64"


def test_a_variable_object_yields_the_resolved_value():
    """
    ``scap.oval.variable_external``. The compiled entity holds the variable's
    *value*, not its id — storing the id and comparing that would be a verdict
    about a machine derived from an identifier.
    """
    obj = {
        "type": "independent:variable_object",
        "entities": {
            "var_ref": {
                "values": ["15"],
                "operation": "equals",
                "from_variable": "oval:t:var:1",
            }
        },
        "behaviors": {},
    }
    result = collect_object(ctx(FakeShell()), obj)
    assert result.ok
    assert result.items[0]["value"] == "15"


def test_a_variable_object_with_no_resolved_value_is_a_failed_read():
    obj = {
        "type": "independent:variable_object",
        "entities": {"var_ref": {"values": [], "operation": "equals"}},
        "behaviors": {},
    }
    assert not collect_object(ctx(FakeShell()), obj).ok

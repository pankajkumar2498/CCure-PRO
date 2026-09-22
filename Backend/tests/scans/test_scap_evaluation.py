"""
tests/scans/test_scap_evaluation.py
─────────────────────────────────────────────────────────────────────────────
OVAL evaluation against a target: probes, three-valued logic, and the rule
that an unknown is never a verdict. Phase 10, GAP-05.

Everything here runs against a fake shell rather than a container, so the
truth tables are exercised exhaustively and deterministically. The real
targets prove the commands work; these prove the *semantics*, which is where a
silent wrong answer comes from — ``check_existence`` alone has five values, and
picking the wrong one turns "this bad line is absent" into "this good line is
present" without anything raising.
"""

import pytest

from core.config_audit.collection import CollectedState, CollectionContext
from core.config_audit.collectors.scap import (
    COMPLIANT,
    NON_COMPLIANT,
    ScapRuleCollector,
)
from core.scap.evaluate import Outcome, evaluate_definition
from core.scap.probes import PROBES, ProbeResult, collect_object, supported_object_types


# ── A shell that answers exactly what it is told to ──────────────────────────


class FakeResult:
    def __init__(self, stdout="", exit_code=0, stderr=""):
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.success = exit_code == 0


class FakeShell:
    """Matches commands by substring and returns canned output."""

    def __init__(self, answers=None, default=None):
        self.answers = answers or []
        self.default = default or FakeResult("", 1, "no answer configured")
        self.commands = []

    def run(self, command, timeout=None):
        self.commands.append(command)
        for needle, result in self.answers:
            if needle in command:
                return result
        return self.default


def ctx(shell=None, **kwargs):
    params = {
        "target": "fixture",
        "platform": "linux",
        "os_name": "Rocky Linux",
        "os_version_id": "9.6",
        "executor": shell,
    }
    params.update(kwargs)
    return CollectionContext(**params)


def found(text):
    return FakeResult(f"CCURE::FOUND::{text}")


MISSING = FakeResult("CCURE::MISSING::")


# ── Probes ───────────────────────────────────────────────────────────────────


def test_every_supported_test_type_has_a_probe():
    """
    ``core.scap.oval.SUPPORTED_TESTS`` is read by the coverage script as the
    capability claim. A test type named there with no probe behind it is the
    "registered but never runs" failure CLAUDE.md records for the plugin
    arity bug, one layer up.
    """
    from core.scap.oval import SUPPORTED_TESTS

    for test_type in SUPPORTED_TESTS:
        assert test_type.replace("_test", "_object") in PROBES, test_type
    assert set(supported_object_types()) == set(PROBES)


def test_textfilecontent_captures_groups_as_the_subexpression():
    """``scap.oval.textfilecontent54``."""
    shell = FakeShell([("example.conf", found("Setting on\nOther off\n"))])
    obj = {
        "type": "independent:textfilecontent54_object",
        "entities": {
            "filepath": {"values": ["/etc/example.conf"], "operation": "equals"},
            "pattern": {
                "values": [r"^Setting\s+(\S+)$"],
                "operation": "pattern match",
            },
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert result.ok
    assert len(result.items) == 1
    assert result.items[0]["subexpression"] == ["on"]


def test_a_missing_file_collects_nothing_and_is_still_a_reading():
    """
    Zero items with ``ok`` True is what every ``none_exist`` check in the
    corpus depends on. Reporting a missing file as a failed *read* would turn
    "the bad directive is not there" into "we could not tell".
    """
    shell = FakeShell([("example.conf", MISSING)])
    obj = {
        "type": "independent:textfilecontent54_object",
        "entities": {
            "filepath": {"values": ["/etc/example.conf"], "operation": "equals"},
            "pattern": {"values": ["x"], "operation": "pattern match"},
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert result.ok and result.items == ()


def test_an_unreadable_file_is_a_failed_read_not_an_empty_one():
    shell = FakeShell([("example.conf", FakeResult("", 1, "Permission denied"))])
    obj = {
        "type": "independent:textfilecontent54_object",
        "entities": {
            "filepath": {"values": ["/etc/example.conf"], "operation": "equals"},
            "pattern": {"values": ["x"], "operation": "pattern match"},
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert not result.ok
    assert "Permission denied" in result.detail


def test_file_mode_bits_are_decomposed_the_way_oval_addresses_them():
    """``scap.oval.file`` — OVAL states name the individual bits, not the octal."""
    shell = FakeShell([("stat", FakeResult("CCURE::REC::/etc/shadow|81a4|0|0\n"))])
    obj = {
        "type": "unix:file_object",
        "entities": {"filepath": {"values": ["/etc/shadow"], "operation": "equals"}},
        "behaviors": {},
    }
    item = collect_object(ctx(shell), obj).items[0]
    assert item["type"] == "regular"
    assert item["user_id"] == "0" and item["group_id"] == "0"
    assert item["uread"] is True and item["uwrite"] is True
    assert item["gread"] is True and item["gwrite"] is False
    assert item["oread"] is True and item["owrite"] is False
    assert item["suid"] is False and item["sgid"] is False


def test_a_symlink_is_reported_as_a_symlink():
    """
    ``stat`` is deliberately used without ``-L``: OVAL's ``file_state/type``
    distinguishes a link from its target, and dereferencing would report the
    target's mode for the link. That is the inverse of the Phase 5 defect and
    wrong for the same reason.
    """
    shell = FakeShell([("stat", FakeResult("CCURE::REC::/bin|a1ff|0|0\n"))])
    obj = {
        "type": "unix:file_object",
        "entities": {"filepath": {"values": ["/bin"], "operation": "equals"}},
        "behaviors": {},
    }
    assert collect_object(ctx(shell), obj).items[0]["type"] == "symbolic link"


def test_a_removed_but_not_purged_package_is_not_installed():
    """
    ``scap.oval.dpkginfo``. dpkg keeps a row for a package that was removed
    without purging. Reading that as installed inverts every "must not be
    installed" rule.
    """
    shell = FakeShell(
        [
            (
                "dpkg-query",
                FakeResult(
                    "CCURE::REC::telnetd|0.17|amd64|deinstall ok config-files\n"
                    "CCURE::REC::aide|0.18|amd64|install ok installed\n"
                ),
            )
        ]
    )
    obj = {
        "type": "linux:dpkginfo_object",
        "entities": {"name": {"values": ["telnetd", "aide"], "operation": "equals"}},
        "behaviors": {},
    }
    items = collect_object(ctx(shell), obj).items
    assert [i["name"] for i in items] == ["aide"]


def test_an_empty_filename_selects_the_directory_itself():
    """
    OVAL's ``<filename/>`` empty means *this directory*, not "no file". The
    first implementation dropped it, so a rule addressing ``/var/log/journal``
    collected nothing and ``check_existence="none_exist"`` read "no offending
    directory" off an empty set.

    That is a vacuous truth and a false **negative** — the direction that
    reaches a customer as a missed finding rather than a wrong one. It was the
    only rule ``oscap`` and this build ever disagreed on, and ``oscap`` was
    right.
    """
    shell = FakeShell(
        [
            ("find", FakeResult("/var/log/journal\n/var/log/journal/abc\n")),
            ("stat", FakeResult("CCURE::REC::/var/log/journal|41ed|0|0\n")),
        ]
    )
    obj = {
        "type": "unix:file_object",
        "entities": {
            "path": {"values": ["/var/log/journal"], "operation": "equals"},
            "filename": {"values": [""], "operation": "equals"},
        },
        "behaviors": {
            "recurse": "directories",
            "recurse_direction": "down",
            "max_depth": "-1",
        },
    }
    result = collect_object(ctx(shell), obj)
    assert result.ok
    assert result.items, "the directory itself must be collected"
    assert result.items[0]["filepath"] == "/var/log/journal"
    # The root is part of the walk, not excluded by -mindepth.
    assert any("-mindepth" not in c for c in shell.commands if "find" in c)


def test_a_missing_package_manager_is_a_failed_read_not_an_absent_package():
    shell = FakeShell([("rpm", FakeResult("", 97))])
    obj = {
        "type": "linux:rpminfo_object",
        "entities": {"name": {"values": ["aide"], "operation": "equals"}},
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert not result.ok
    assert "not the same as it being absent" in result.detail


def test_systemd_answers_an_unknown_property_with_no_item():
    """``scap.oval.systemdunitproperty``."""
    shell = FakeShell([("systemctl", FakeResult("CCURE::REC::\n"))])
    obj = {
        "type": "linux:systemdunitproperty_object",
        "entities": {
            "unit": {"values": ["sshd.service"], "operation": "equals"},
            "property": {"values": ["ActiveState"], "operation": "equals"},
        },
        "behaviors": {},
    }
    result = collect_object(ctx(shell), obj)
    assert result.ok and result.items == ()


def test_the_family_probe_answers_from_the_audit_context():
    """
    ``scap.oval.family``. Asking the host again could only disagree with the
    decision that chose the collector set in the first place.
    """
    result = collect_object(ctx(FakeShell()), {"type": "independent:family_object"})
    assert result.ok and result.items[0]["family"] == "unix"


def test_a_probe_that_raises_becomes_a_failed_result(monkeypatch):
    """A defect in our own probe must never read as "the host has none of these"."""

    def explode(_ctx, _obj):
        raise RuntimeError("boom")

    monkeypatch.setitem(PROBES, "independent:family_object", explode)
    result = collect_object(ctx(FakeShell()), {"type": "independent:family_object"})
    assert not result.ok and "RuntimeError" in result.detail


def test_reads_are_memoised_across_checks():
    """``scap.run.read_memoisation`` — a STIG reads sshd_config dozens of times."""
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    context = ctx(shell)
    obj = {
        "type": "independent:textfilecontent54_object",
        "entities": {
            "filepath": {"values": ["/etc/example.conf"], "operation": "equals"},
            "pattern": {"values": [r"^Setting\s+(\S+)$"], "operation": "pattern match"},
        },
        "behaviors": {},
    }
    for _ in range(5):
        collect_object(context, obj)
    assert len(shell.commands) == 1


# ── Compiled-definition helpers ──────────────────────────────────────────────


def definition(criteria, tests, objects, states):
    return {
        "definition_id": "oval:t:def:1",
        "criteria": criteria,
        "tests": tests,
        "objects": objects,
        "states": states,
    }


def one_test_definition(
    check_existence="at_least_one_exists", check="all", states=None
):
    return definition(
        {
            "kind": "criteria",
            "operator": "AND",
            "negate": False,
            "children": [{"kind": "test", "test": "t1", "negate": False}],
        },
        {
            "t1": {
                "type": "independent:textfilecontent54_test",
                "object": "o1",
                "states": list(states or []),
                "check": check,
                "check_existence": check_existence,
            }
        },
        {
            "o1": {
                "type": "independent:textfilecontent54_object",
                "entities": {
                    "filepath": {
                        "values": ["/etc/example.conf"],
                        "operation": "equals",
                    },
                    "pattern": {
                        "values": [r"^Setting\s+(\S+)$"],
                        "operation": "pattern match",
                    },
                },
                "behaviors": {},
                "filters": [],
            }
        },
        {
            "s1": {
                "operator": "AND",
                "fields": [
                    {
                        "name": "subexpression",
                        "operation": "equals",
                        "datatype": "string",
                        "entity_check": "all",
                        "value": {"values": ["on"]},
                    }
                ],
            }
        },
    )


# ── check_existence ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "existence,present,expected",
    [
        ("all_exist", True, Outcome.TRUE),
        ("all_exist", False, Outcome.FALSE),
        ("any_exist", True, Outcome.TRUE),
        ("any_exist", False, Outcome.TRUE),
        ("at_least_one_exists", True, Outcome.TRUE),
        ("at_least_one_exists", False, Outcome.FALSE),
        ("none_exist", True, Outcome.FALSE),
        ("none_exist", False, Outcome.TRUE),
        ("only_one_exists", True, Outcome.TRUE),
        ("only_one_exists", False, Outcome.FALSE),
    ],
)
def test_check_existence_truth_table(existence, present, expected):
    """
    ``scap.oval.check_existence``. Five values, 472 ``all_exist`` and 220
    ``none_exist`` uses in the measured content, and getting one wrong turns
    "the bad line is absent" into "the good line is present".
    """
    text = "Setting on\n" if present else ""
    shell = FakeShell([("example.conf", found(text))])
    result = evaluate_definition(ctx(shell), one_test_definition(existence))
    assert result.outcome is expected


@pytest.mark.parametrize(
    "check,expected",
    [
        ("all", Outcome.FALSE),
        ("at least one", Outcome.TRUE),
        ("none satisfy", Outcome.FALSE),
        ("only one", Outcome.TRUE),
    ],
)
def test_check_attribute_folds_over_items(check, expected):
    """``scap.oval.check_attribute`` — one matching item, one not."""
    shell = FakeShell([("example.conf", found("Setting on\nSetting off\n"))])
    compiled = one_test_definition(check=check, states=["s1"])
    assert evaluate_definition(ctx(shell), compiled).outcome is expected


# ── Criteria logic ───────────────────────────────────────────────────────────


def two_test_definition(operator, negate=False):
    compiled = one_test_definition(states=["s1"])
    compiled["tests"]["t2"] = dict(compiled["tests"]["t1"], object="o2")
    compiled["objects"]["o2"] = dict(
        compiled["objects"]["o1"],
        entities={
            "filepath": {"values": ["/etc/second.conf"], "operation": "equals"},
            "pattern": {"values": [r"^Setting\s+(\S+)$"], "operation": "pattern match"},
        },
    )
    compiled["criteria"] = {
        "kind": "criteria",
        "operator": operator,
        "negate": negate,
        "children": [
            {"kind": "test", "test": "t1", "negate": False},
            {"kind": "test", "test": "t2", "negate": False},
        ],
    }
    return compiled


@pytest.mark.parametrize(
    "operator,first,second,expected",
    [
        ("AND", "on", "on", Outcome.TRUE),
        ("AND", "on", "off", Outcome.FALSE),
        ("OR", "on", "off", Outcome.TRUE),
        ("OR", "off", "off", Outcome.FALSE),
        ("ONE", "on", "off", Outcome.TRUE),
        ("ONE", "on", "on", Outcome.FALSE),
        ("XOR", "on", "off", Outcome.TRUE),
        ("XOR", "on", "on", Outcome.FALSE),
    ],
)
def test_criteria_operators(operator, first, second, expected):
    """``scap.oval.criteria_logic``."""
    shell = FakeShell(
        [
            ("example.conf", found(f"Setting {first}\n")),
            ("second.conf", found(f"Setting {second}\n")),
        ]
    )
    result = evaluate_definition(ctx(shell), two_test_definition(operator))
    assert result.outcome is expected


def test_negation_flips_a_verdict_but_not_an_unknown():
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    compiled = one_test_definition(states=["s1"])
    compiled["criteria"]["negate"] = True
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.FALSE

    broken = FakeShell([("example.conf", FakeResult("", 1, "denied"))])
    assert evaluate_definition(ctx(broken), compiled).outcome is Outcome.UNKNOWN


def test_an_unknown_that_cannot_change_the_answer_does_not_hide_a_verdict():
    """
    ``AND`` with a FALSE in it is FALSE whatever the unknown turns out to be.
    Returning UNKNOWN there loses real findings on hosts where one unrelated
    file happened to be unreadable.
    """
    shell = FakeShell(
        [
            ("example.conf", found("Setting off\n")),
            ("second.conf", FakeResult("", 1, "denied")),
        ]
    )
    assert evaluate_definition(ctx(shell), two_test_definition("AND")).outcome is (
        Outcome.FALSE
    )
    shell = FakeShell(
        [
            ("example.conf", found("Setting on\n")),
            ("second.conf", FakeResult("", 1, "denied")),
        ]
    )
    assert evaluate_definition(ctx(shell), two_test_definition("OR")).outcome is (
        Outcome.TRUE
    )


def test_an_unknown_that_could_change_the_answer_stays_unknown():
    shell = FakeShell(
        [
            ("example.conf", found("Setting on\n")),
            ("second.conf", FakeResult("", 1, "denied")),
        ]
    )
    assert evaluate_definition(ctx(shell), two_test_definition("AND")).outcome is (
        Outcome.UNKNOWN
    )


def test_an_error_detail_names_what_was_unknown_not_the_first_note():
    """
    A definition whose criteria are ``A OR B`` records A's ordinary failure
    before B's unknown. Quoting note zero tells a reader the rule failed on
    something that was in fact measured.
    """
    shell = FakeShell(
        [
            ("example.conf", found("Setting off\n")),
            ("second.conf", FakeResult("", 1, "Permission denied")),
        ]
    )
    result = evaluate_definition(ctx(shell), two_test_definition("OR"))
    assert result.outcome is Outcome.UNKNOWN
    assert "Permission denied" in result.detail


# ── State comparison ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "operation,datatype,actual,expected_value,expected",
    [
        ("equals", "string", "on", "on", Outcome.TRUE),
        ("not equal", "string", "on", "off", Outcome.TRUE),
        ("case insensitive equals", "string", "ON", "on", Outcome.TRUE),
        ("pattern match", "string", "abcdef", "^abc", Outcome.TRUE),
        ("greater than or equal", "int", "15", "15", Outcome.TRUE),
        ("greater than or equal", "int", "8", "15", Outcome.FALSE),
        ("less than", "int", "8", "15", Outcome.TRUE),
        ("greater than", "version", "1.10", "1.9", Outcome.TRUE),
        ("greater than or equal", "evr_string", "0:2.4-3", "0:2.4-2", Outcome.TRUE),
    ],
)
def test_state_operations(operation, datatype, actual, expected_value, expected):
    """``scap.oval.state_operations`` and ``scap.oval.datatypes``."""
    shell = FakeShell([("example.conf", found(f"Setting {actual}\n"))])
    compiled = one_test_definition(states=["s1"])
    compiled["states"]["s1"]["fields"][0].update(
        operation=operation, datatype=datatype, value={"values": [expected_value]}
    )
    assert evaluate_definition(ctx(shell), compiled).outcome is expected


# ── state_operator ───────────────────────────────────────────────────────────


def _two_state_definition(state_operator=None):
    """One test, two mutually exclusive states — the DISA alternatives shape."""
    compiled = one_test_definition(states=["s1", "s2"])
    compiled["states"]["s2"] = {
        "operator": "AND",
        "fields": [
            {
                "name": "subexpression",
                "operation": "equals",
                "datatype": "string",
                "entity_check": "all",
                "value": {"values": ["off"]},
            }
        ],
    }
    if state_operator is not None:
        compiled["tests"]["t1"]["state_operator"] = state_operator
    return compiled


def test_alternative_states_are_ored_when_the_content_says_so():
    """The defect this exists for: ANDing alternatives is unsatisfiable.

    A test naming two states that cannot both hold -- "unassigned OR held only
    by Administrators", "the value is on OR off" -- is written by DISA with
    ``state_operator="OR"``. That attribute was not read, so every such rule
    was ANDed and could not pass on any host in any configuration.

    Measured against the DISA Windows 11 STIG on a real host, 22 Sep 2026: 44
    of 198 rules carry a multi-state test, and they passed at 2/42 where the
    single-state rules passed at 61/147.
    """
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    assert (
        evaluate_definition(ctx(shell), _two_state_definition("OR")).outcome
        is Outcome.TRUE
    )


def test_or_is_false_only_when_no_state_holds():
    shell = FakeShell([("example.conf", found("Setting maybe\n"))])
    assert (
        evaluate_definition(ctx(shell), _two_state_definition("OR")).outcome
        is Outcome.FALSE
    )


def test_and_remains_the_default_for_content_that_names_no_operator():
    """OVAL's own default, and what a pack compiled before this was carried has.

    Defaulting to OR instead would silently loosen every rule that genuinely
    means "all of these must hold".
    """
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    assert (
        evaluate_definition(ctx(shell), _two_state_definition(None)).outcome
        is Outcome.FALSE
    )
    assert (
        evaluate_definition(ctx(shell), _two_state_definition("AND")).outcome
        is Outcome.FALSE
    )


def test_an_unknown_state_cannot_decide_an_or_that_already_holds():
    """Tri-state, not boolean: a True short-circuits an OR.

    Reading the uncomparable one as False would be asserting something about
    the host; reading the whole fold as UNKNOWN would discard an answer the
    content already gave.
    """
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    compiled = _two_state_definition("OR")
    # A state naming an entity the probe does not produce is UNKNOWN.
    compiled["states"]["s2"]["fields"][0]["name"] = "no_such_entity"
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.TRUE


def test_the_compiler_refuses_an_operator_it_does_not_implement():
    """ONE and XOR are recorded as unimplemented, never approximated.

    OVAL defines four operators. A wrong fold is indistinguishable from a right
    one once it reaches the report, which is what UnsupportedConstruct exists
    to prevent -- so the two that are not implemented must fail to compile
    rather than fall through to AND.
    """
    import inspect

    from core.scap import oval

    assert set(oval._STATE_OPERATORS) == {"AND", "OR"}

    source = inspect.getsource(oval.OvalDocument._compile_test)
    assert "state_operator" in source, "the compiler no longer reads state_operator"
    assert "_STATE_OPERATORS" in source, (
        "the compiler no longer validates state_operator against the vocabulary, "
        "so ONE and XOR would silently be treated as AND"
    )


def test_an_uncomparable_value_is_unknown_not_false():
    """
    A comparison that could not run has established nothing about the host.
    Reporting it as a failed condition is the defect this module is arranged
    to avoid.
    """
    shell = FakeShell([("example.conf", found("Setting yes\n"))])
    compiled = one_test_definition(states=["s1"])
    compiled["states"]["s1"]["fields"][0].update(
        operation="greater than", datatype="int", value={"values": ["15"]}
    )
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.UNKNOWN


def test_a_state_field_the_probe_does_not_produce_is_unknown_not_false():
    """That is a gap in this build, not a property of the host."""
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    compiled = one_test_definition(states=["s1"])
    compiled["states"]["s1"]["fields"][0]["name"] = "no_such_entity"
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.UNKNOWN


# ── Object filters ───────────────────────────────────────────────────────────


def test_an_exclude_filter_drops_the_items_that_satisfy_it():
    """
    613 objects in the RHEL 9 datastream carry a filter, 547 of them
    ``exclude``. Refusing them would put a fifth of the benchmark out of reach.
    """
    shell = FakeShell([("example.conf", found("Setting on\nSetting off\n"))])
    compiled = one_test_definition(check_existence="none_exist")
    compiled["objects"]["o1"]["filters"] = [{"state": "s1", "action": "exclude"}]
    # Only "off" survives the exclusion of "on", so `none_exist` is False.
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.FALSE

    compiled["objects"]["o1"]["filters"] = [{"state": "s1", "action": "include"}]
    compiled["tests"]["t1"]["check_existence"] = "only_one_exists"
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.TRUE


def test_an_uncomparable_filter_makes_the_test_unknown():
    """
    Keeping the item would inflate every ``none_exist`` check and dropping it
    would satisfy them. Neither is a reading, and existence is decided entirely
    by how many items survive.
    """
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    compiled = one_test_definition(check_existence="none_exist")
    compiled["objects"]["o1"]["filters"] = [{"state": "s1", "action": "exclude"}]
    compiled["states"]["s1"]["fields"][0].update(
        operation="greater than", datatype="int"
    )
    assert evaluate_definition(ctx(shell), compiled).outcome is Outcome.UNKNOWN


# ── The collector ────────────────────────────────────────────────────────────


def collector_state(shell, compiled):
    from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

    check = ConfigCheck(
        check_id="stig.fixture.rule",
        title="fixture",
        check_type="scap_rule",
        collect={"definition": compiled},
        expect=Expectation("equals", COMPLIANT),
        absent=AbsencePolicy.MANUAL_REVIEW,
        platforms=("linux",),
    )
    return ScapRuleCollector().collect(check, ctx(shell))


def test_the_collector_reports_two_values_and_an_unavailable():
    shell = FakeShell([("example.conf", found("Setting on\n"))])
    state = collector_state(shell, one_test_definition(states=["s1"]))
    assert state.status.name == "COLLECTED" and state.value == COMPLIANT

    shell = FakeShell([("example.conf", found("Setting off\n"))])
    state = collector_state(shell, one_test_definition(states=["s1"]))
    assert state.status.name == "COLLECTED" and state.value == NON_COMPLIANT


def test_an_unknown_becomes_unavailable_which_the_engine_renders_as_error():
    """
    ``scap.run.unsupported_not_assessed``, at run time. This is the phase's
    central rule: a definition that could not be evaluated must never reach a
    verdict, in either direction.
    """
    shell = FakeShell([("example.conf", FakeResult("", 1, "denied"))])
    state = collector_state(shell, one_test_definition(states=["s1"]))
    assert state.status.name == "UNAVAILABLE"
    assert state.detail

    from core.config_audit.engine import ConfigAuditEngine
    from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

    check = ConfigCheck(
        check_id="stig.fixture.rule",
        title="fixture",
        check_type="scap_rule",
        collect={"definition": one_test_definition(states=["s1"])},
        expect=Expectation("equals", COMPLIANT),
        absent=AbsencePolicy.MANUAL_REVIEW,
        platforms=("linux",),
    )
    result = ConfigAuditEngine().run_check(check, ctx(shell))
    assert result.outcome.value == "error"
    assert not result.outcome.is_verdict


def test_a_rule_with_no_definition_is_unavailable_not_a_verdict():
    from core.config_audit.spec import AbsencePolicy, ConfigCheck, Expectation

    check = ConfigCheck(
        check_id="stig.fixture.rule",
        title="fixture",
        check_type="scap_rule",
        collect={"definition": "not a mapping"},
        expect=Expectation("equals", COMPLIANT),
        absent=AbsencePolicy.MANUAL_REVIEW,
        platforms=("linux",),
    )
    state = ScapRuleCollector().collect(check, ctx(FakeShell()))
    assert state.status.name == "UNAVAILABLE"


def test_the_collector_is_registered_for_linux_only():
    """``scap.run.credentialed_execution``."""
    from core.config_audit.collectors import (
        collector_registry,
        register_builtin_collectors,
    )

    register_builtin_collectors()
    assert collector_registry.resolve("scap_rule", "linux") is not None
    assert collector_registry.resolve("scap_rule", "database") is None

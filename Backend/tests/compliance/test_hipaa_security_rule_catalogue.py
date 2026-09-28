"""
The HIPAA Security Rule catalogue (45 CFR Part 164, Subpart C).

Added 28 Sep 2026 so a Policy Pro baseline naming a HIPAA requirement can be
answered. The catalogue is the regulation's own structure: each standard and
implementation specification of 164.308, 164.310, 164.312, 164.314 and 164.316
under its CFR citation, with the regulation's text as its description. It is
parked.

What is pinned here is agreement with the regulation, not with ourselves: the
Required/Addressable tags against the regulation's own markers and the totals
of the published Security Standards Matrix (Appendix A to Subpart C), every
specification's parent standard, and the citation format another module will
name a control by.
"""

from __future__ import annotations

import json
import re
from collections import Counter

import pytest

from core import compliance_frameworks
from core.compliance_seeds import seed_path

FRAMEWORK_ID = "cfw_hipaa_security_rule"
SEED = seed_path("hipaa_security_rule_controls_seed.json")
THEME_BY_SECTION = {
    "164.308": "HIPAA_ADM",
    "164.310": "HIPAA_PHY",
    "164.312": "HIPAA_TEC",
    "164.314": "HIPAA_ORG",
    "164.316": "HIPAA_DOC",
}
CITATION = re.compile(r"^(164\.3(?:08|10|12|14|16))((?:\([a-zA-Z0-9]+\))+)$")


@pytest.fixture(scope="module")
def seed() -> dict:
    with open(SEED, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(scope="module")
def controls(seed) -> list:
    return seed["controls"]


def _kind(c) -> str:
    return "standard" if "standard" in c["tags"] else "specification"


def test_the_framework_is_the_security_rule(seed):
    fw = seed["framework"]
    assert fw["code"] == "HIPAA_SECURITY_RULE"
    assert f"cfw_{fw['code'].lower()}" == FRAMEWORK_ID


def test_every_section_is_present_in_full(controls):
    by_theme = Counter(c["theme"] for c in controls)
    assert by_theme == {
        "HIPAA_ADM": 30,
        "HIPAA_PHY": 12,
        "HIPAA_TEC": 12,
        "HIPAA_ORG": 6,
        "HIPAA_DOC": 5,
    }


def test_each_control_is_named_by_its_cfr_citation(controls):
    numbers = [c["control_number"] for c in controls]
    assert len(numbers) == len(set(numbers))
    for c in controls:
        match = CITATION.match(c["control_number"])
        assert match, f"not a CFR citation: {c['control_number']}"
        assert c["theme"] == THEME_BY_SECTION[match.group(1)]
        # The description is the regulation's own text, opened by its citation.
        assert c["description"].startswith(f"45 CFR {c['control_number']} ")


def test_required_and_addressable_follow_the_regulation(controls):
    """
    Each tag agrees with the marker the regulation writes. The totals are the
    published Security Standards Matrix's: 22 addressable specifications, 21
    required ones, and 7 standards with no specification, which are required in
    themselves.
    """
    for c in controls:
        text = c["description"]
        tags = set(c["tags"])
        assert len(tags & {"required", "addressable"}) <= 1, c["control_number"]
        if "(Addressable)" in text:
            assert "addressable" in tags, c["control_number"]
        if "(Required)" in text:
            assert "required" in tags, c["control_number"]
        if _kind(c) == "specification":
            assert tags & {
                "required",
                "addressable",
            }, f"{c['control_number']} is untagged"

    specs = [c for c in controls if _kind(c) == "specification"]
    standards = [c for c in controls if _kind(c) == "standard"]
    assert (len(standards), len(specs)) == (22, 43)
    assert sum("addressable" in c["tags"] for c in specs) == 22
    assert sum("required" in c["tags"] for c in specs) == 21
    assert sum("required" in c["tags"] for c in standards) == 7


def _parent_key(number: str) -> str:
    """The standard a paragraph belongs to: 164.308(a)(N) for the numbered
    administrative standards, otherwise the section plus its lettered paragraph."""
    section, groups = CITATION.match(number).groups()
    parts = re.findall(r"\(([a-zA-Z0-9]+)\)", groups)
    if section == "164.308" and parts[0] == "a":
        return f"{section}(a)({parts[1]})"
    return f"{section}({parts[0]})"


def test_every_specification_has_its_standard(controls):
    standards = {
        _parent_key(c["control_number"]) for c in controls if _kind(c) == "standard"
    }
    orphans = [
        c["control_number"]
        for c in controls
        if _kind(c) == "specification"
        and _parent_key(c["control_number"]) not in standards
    ]
    assert not orphans, f"specifications without their standard: {orphans}"


def test_nothing_is_claimed_that_nobody_reviewed(controls):
    for c in controls:
        assert c["scannability"] == "manual" and not c.get("scan_module_hint")
        assert not c.get("crosswalk")


def test_the_catalogue_ships_parked():
    assert FRAMEWORK_ID in compliance_frameworks.ALL_FRAMEWORK_IDS
    assert FRAMEWORK_ID not in compliance_frameworks.DEFAULT_ACTIVE_FRAMEWORK_IDS


def test_the_seeder_publishes_the_cfr_citation():
    from scripts.seed_compliance import _control_number

    ctrl = {"id": "164_312_a_2_iii", "control_number": "164.312(a)(2)(iii)"}
    assert _control_number(FRAMEWORK_ID, ctrl) == "164.312(a)(2)(iii)"

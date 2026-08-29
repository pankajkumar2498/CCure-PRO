"""
tests/scans/test_middleware_content.py
─────────────────────────────────────────────────────────────────────────────
The shipped middleware rules and the GAP-09 denominator. Phase 8.

Invariants over the *content*. A middleware rule is three things at once — an
address into a configuration document, a targeting declaration and a coverage
claim — and each can be wrong independently while the other two look right. The
engine catches none of them: a rule addressing a file that no distribution uses
runs nowhere and reports nothing, which is indistinguishable from a clean
estate.
"""

import pytest

from core.checks.definitions import (
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_CVE,
    definition_id_for_check,
    definition_type_for_id,
)
from core.config_audit.builtin import BUILTIN_CHECKS, MIDDLEWARE_CHECKS
from core.config_audit.engine import select_checks
from core.config_audit.spec import AbsencePolicy
from scripts.measure_middleware_coverage import (
    NOT_PLANNED,
    SCOPE,
    SUPPORTED_PRODUCTS,
)

SCOPE_AREAS = {area for area, _t, _d in SCOPE}

_STRUCTURED = [c for c in MIDDLEWARE_CHECKS if c.check_type == "structured_config"]


# ── Shape ────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("check", MIDDLEWARE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_runs_on_a_host_platform(check):
    """
    Middleware configuration lives on a host and is read over the host's own
    credentialed session. A rule targeting the `database` platform would never
    be selected by the host audit.
    """
    assert set(check.platforms) <= {"linux", "windows"}
    assert check.requires_credentials is True


@pytest.mark.parametrize("check", MIDDLEWARE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_names_its_product_and_area(check):
    assert check.metadata.get("middleware") in SUPPORTED_PRODUCTS
    area = check.metadata.get("gap09_area")
    assert area, f"{check.check_id} claims no gap09_area"
    assert area in SCOPE_AREAS, (
        f"{check.check_id} claims area {area!r}, which is not in the frozen "
        f"GAP-09 denominator. The denominator is fixed; adding an area to it "
        f"to match what was built is inflating coverage."
    )


@pytest.mark.parametrize("check", _STRUCTURED, ids=lambda c: c.check_id)
def test_every_structured_rule_declares_a_format_and_an_address(check):
    fmt = check.collect.get("format")
    assert fmt in ("nginx", "apache", "xml", "json")
    address = {
        "nginx": "directive",
        "apache": "directive",
        "xml": "xpath",
        "json": "pointer",
    }[fmt]
    assert check.collect.get(
        address
    ), f"{check.check_id} declares format {fmt!r} but names no {address}"


@pytest.mark.parametrize("check", _STRUCTURED, ids=lambda c: c.check_id)
def test_every_structured_rule_offers_more_than_one_candidate_path(check):
    """
    Distributions put the same product in different places. A rule pinned to a
    single path reports "not configured" on every host packaged differently —
    except for the Docker daemon, which has exactly one canonical location.
    """
    paths = check.collect["path"]
    assert isinstance(paths, list) and paths
    if check.metadata.get("middleware") != "docker":
        assert len(paths) > 1, (
            f"{check.check_id} names one path only; it will miss every host "
            f"that packages the product elsewhere"
        )
    assert all(str(p).startswith("/") for p in paths)


@pytest.mark.parametrize("check", MIDDLEWARE_CHECKS, ids=lambda c: c.check_id)
def test_no_middleware_rule_is_filed_as_a_cve(check):
    assert check.finding_type == DEFINITION_TYPE_CONFIG_CHECK
    assert check.finding_type != DEFINITION_TYPE_CVE


@pytest.mark.parametrize("check", MIDDLEWARE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_mints_a_usable_identifier(check):
    minted = definition_id_for_check(check.check_id, check.finding_type)
    assert minted.startswith("CCURE-CFG-")
    assert len(minted) <= 120
    assert definition_type_for_id(minted) == DEFINITION_TYPE_CONFIG_CHECK


@pytest.mark.parametrize("check", MIDDLEWARE_CHECKS, ids=lambda c: c.check_id)
def test_every_rule_is_actionable(check):
    assert check.remediation.strip(), f"{check.check_id} has no remediation"
    assert check.rationale.strip(), f"{check.check_id} has no rationale"
    assert check.description.strip(), f"{check.check_id} has no description"


@pytest.mark.parametrize("check", MIDDLEWARE_CHECKS, ids=lambda c: c.check_id)
def test_a_rule_that_defers_on_absence_says_what_the_default_is(check):
    """
    MANUAL_REVIEW is the honest answer for a directive at its compiled-in
    default, but only if the reviewer is told what that default is. Otherwise
    the finding is "we do not know" with no route to knowing, which is where
    manual verdicts go to be ignored.

    ``result: count`` rules are exempt and asserted separately: a count is
    always a reading, so their absence policy can never be reached and there is
    no default for them to document.
    """
    if check.absent is not AbsencePolicy.MANUAL_REVIEW:
        return
    text = check.description.lower()
    if check.collect.get("result") == "count":
        assert "unreachable" in text, (
            f"{check.check_id} counts matches, so its absence policy cannot be "
            f"reached; the description should say so rather than leaving a "
            f"reader to work out why it is declared"
        )
        return
    assert "unset" in text or "default" in text or "not apply" in text, (
        f"{check.check_id} defers when the setting is absent but its "
        f"description does not say what the product does by default"
    )


def test_ids_and_minted_identifiers_are_unique_across_every_builtin():
    ids = [c.check_id for c in BUILTIN_CHECKS]
    assert len(ids) == len(set(ids))
    minted = [
        definition_id_for_check(c.check_id, c.finding_type) for c in BUILTIN_CHECKS
    ]
    assert len(minted) == len(set(minted))


# ── Boundary with GAP-06 ─────────────────────────────────────────────────────


_GAP06_TERRITORY = (
    "autoindex",
    "traceenable",
    "add_header",
    "header",
    "ssl_stapling",
)


@pytest.mark.parametrize("check", _STRUCTURED, ids=lambda c: c.check_id)
def test_no_rule_duplicates_a_check_gap06_already_makes(check):
    """
    Directory listing, dangerous methods and security headers are observed over
    the wire by GAP-06 and validated there. A configuration-side twin would
    report one condition twice and make the remediation look twice as large —
    the mistake Phase 7 caught in its own pg_hba rules.
    """
    address = str(
        check.collect.get("directive") or check.collect.get("xpath") or ""
    ).lower()
    assert not any(term in address for term in _GAP06_TERRITORY), (
        f"{check.check_id} reads {address!r}, which GAP-06 already assesses "
        f"over the network"
    )


# ── Coverage claims ──────────────────────────────────────────────────────────


def test_areas_recorded_as_not_planned_have_no_implementation():
    implemented = {c.metadata.get("gap09_area") for c in MIDDLEWARE_CHECKS}
    overlap = implemented & set(NOT_PLANNED)
    assert not overlap, (
        f"areas {sorted(overlap)} are implemented but still listed in "
        f"NOT_PLANNED with a reason for not implementing them"
    )


def test_iis_is_declared_and_unimplemented():
    """
    IIS is in the denominator so the figure reflects what a Nessus user would
    expect, and unimplemented because there is no Windows Server target here to
    validate against. Shipping it unvalidated is what this records as refused.
    """
    iis_areas = {a for a, theme, _d in SCOPE if theme == "iis"}
    assert iis_areas
    assert iis_areas <= set(NOT_PLANNED)
    assert not [
        c for c in MIDDLEWARE_CHECKS if c.metadata.get("gap09_area") in iis_areas
    ]


def test_every_supported_product_ships_rules():
    covered = {c.metadata.get("middleware") for c in MIDDLEWARE_CHECKS}
    assert covered == set(SUPPORTED_PRODUCTS)


# ── Selection ────────────────────────────────────────────────────────────────


def test_middleware_rules_are_selected_for_a_host_audit():
    selected = select_checks(BUILTIN_CHECKS, platform="linux")
    ids = {c.check_id for c in selected}
    assert {c.check_id for c in MIDDLEWARE_CHECKS if "linux" in c.platforms} <= ids


def test_middleware_rules_are_never_selected_for_a_database_audit():
    selected = select_checks(BUILTIN_CHECKS, platform="database")
    assert selected
    assert all(c.check_type == "database_query" for c in selected)


def test_the_check_type_matches_the_migration():
    """
    Migration a9b0c1d2e3f4 renders the vocabulary by hand. A model that gains a
    value the migration does not have produces a schema an upgraded database
    rejects and a bootstrapped one accepts.
    """
    import importlib.util
    from pathlib import Path

    from db.models.compliance import RULE_CHECK_TYPES

    path = (
        Path(__file__).resolve().parents[2]
        / "alembic"
        / "versions"
        / "a9b0c1d2e3f4_structured_config_check_type.py"
    )
    spec = importlib.util.spec_from_file_location("_gap09_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert tuple(module.CHECK_TYPES) == tuple(RULE_CHECK_TYPES)
    assert "structured_config" not in module.OLD_CHECK_TYPES


def test_the_spec_and_the_model_agree_on_the_check_type():
    from core.config_audit.spec import CHECK_TYPES
    from db.models.compliance import RULE_CHECK_TYPES

    assert "structured_config" in CHECK_TYPES
    assert "structured_config" in RULE_CHECK_TYPES

"""
tests/scans/test_check_framework.py
─────────────────────────────────────────────────────────────────────────────
The common assessment contract in ``core/checks/``.

Every assertion here corresponds to a defect this codebase has already shipped
at least once, in one engine or another. The contract exists to make those
states unrepresentable rather than merely discouraged, so these tests are
written against the *invariants*, not against the implementation that happens
to enforce them today.
"""

import pytest
from core.checks import (
    CheckOutcome,
    CheckResult,
    CheckSpec,
    Evidence,
    RegistrationError,
    definition_id_for_check,
    is_cve_id,
    normalize_severity,
)
from core.checks.contract import roll_up_outcomes
from core.checks.definitions import (
    DEFINITION_ID_MAX_LENGTH,
    DEFINITION_TYPE_CONFIG_CHECK,
    DEFINITION_TYPE_CVE,
    DEFINITION_TYPE_PLUGIN_CHECK,
    definition_type_for_id,
)
from core.checks.registry import CheckRegistry


def _evidence(**overrides) -> Evidence:
    payload = {
        "collector": "windows_registry",
        "description": "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel",
        "expected": "5",
        "observed": "1",
    }
    payload.update(overrides)
    return Evidence(**payload)


# ─────────────────────────────────────────────────────────────────────────────
# Outcome semantics
# ─────────────────────────────────────────────────────────────────────────────


def test_only_pass_and_fail_are_verdicts():
    """
    A host the collector could not authenticate to, a control that does not
    apply to this SKU, and one awaiting a human are all *not assessed*. Every
    counter and roll-up in the product gates on ``is_verdict``; if any of the
    three ever became a verdict, an unreachable host would start scoring as
    compliant or as failing. ISO A.8.2 was reported as *failed* on hosts the
    scanner could not reach for exactly this reason.
    """
    assert CheckOutcome.PASS.is_verdict is True
    assert CheckOutcome.FAIL.is_verdict is True
    for outcome in (
        CheckOutcome.NOT_APPLICABLE,
        CheckOutcome.MANUAL_REVIEW,
        CheckOutcome.ERROR,
    ):
        assert outcome.is_verdict is False, outcome


def test_not_applicable_is_assessed_but_error_is_not():
    """
    "This control does not apply here" is a completed assessment. "I could not
    look" is not. Collapsing the two hides which checks never ran.
    """
    assert CheckOutcome.NOT_APPLICABLE.is_assessed is True
    assert CheckOutcome.PASS.is_assessed is True
    assert CheckOutcome.ERROR.is_assessed is False


def test_outcome_strings_match_the_compliance_status_vocabulary():
    """
    ``compliance_findings.status`` is CHECK-constrained to a fixed set. The
    four non-error outcomes must be spelled identically or a check result
    cannot be stored as a compliance verdict without a translation table —
    and a translation table is how two vocabularies for one idea start.
    """
    stored_by_compliance = {
        "pass",
        "fail",
        "not_applicable",
        "manual_review",
        "exception",
        "remediation_applied",
        "pending_reverify",
    }
    for outcome in CheckOutcome:
        if outcome is CheckOutcome.ERROR:
            assert outcome.value not in stored_by_compliance
        else:
            assert outcome.value in stored_by_compliance, outcome


def test_roll_up_ranks_error_above_pass_and_fail_above_error():
    """
    A control with nine passes and one check that could not run has *not* been
    established as compliant, so ERROR must outrank PASS. But one check that
    positively found a problem is a finding regardless of how many siblings
    were unreachable, so FAIL must outrank ERROR.
    """
    assert roll_up_outcomes([CheckOutcome.PASS] * 9 + [CheckOutcome.ERROR]) is (
        CheckOutcome.ERROR
    )
    assert (
        roll_up_outcomes([CheckOutcome.ERROR, CheckOutcome.FAIL]) is CheckOutcome.FAIL
    )
    assert roll_up_outcomes([CheckOutcome.PASS, CheckOutcome.NOT_APPLICABLE]) is (
        CheckOutcome.PASS
    )
    assert roll_up_outcomes([]) is CheckOutcome.NOT_APPLICABLE


# ─────────────────────────────────────────────────────────────────────────────
# CheckResult invariants
# ─────────────────────────────────────────────────────────────────────────────


def test_a_fail_without_evidence_is_refused():
    """
    The single most important invariant here. A FAIL with nothing collected
    behind it cannot be defended when the customer challenges it, and it is
    indistinguishable from the synthesised-evidence defect that once made every
    password-policy rule pass unconditionally on every host — the same error
    pointed the other way.
    """
    with pytest.raises(ValueError, match="must carry at least one Evidence"):
        CheckResult(check_id="cis_1_1_1", outcome=CheckOutcome.FAIL)


def test_a_pass_needs_no_evidence_but_may_carry_it():
    CheckResult(check_id="cis_1_1_1", outcome=CheckOutcome.PASS)
    result = CheckResult(
        check_id="cis_1_1_1", outcome=CheckOutcome.PASS, evidence=[_evidence()]
    )
    assert len(result.evidence) == 1


def test_an_error_must_say_why():
    """An error with no reason reads in a log exactly like a check that did
    nothing — which is how a plugin that never executed looked registered."""
    with pytest.raises(ValueError, match="must set `error`"):
        CheckResult(check_id="cis_1_1_1", outcome=CheckOutcome.ERROR)

    result = CheckResult.error_result(
        check_id="cis_1_1_1", target="10.0.0.5", reason="WinRM refused: 401"
    )
    assert result.outcome is CheckOutcome.ERROR
    assert "401" in result.error
    assert result.is_finding is False


def test_only_a_fail_becomes_a_finding():
    """A pass is a compliance verdict, not a vulnerability. If a pass ever
    became a finding the register would fill with rows saying nothing is
    wrong."""
    evidence = [_evidence()]
    assert (
        CheckResult(
            check_id="c", outcome=CheckOutcome.FAIL, evidence=evidence
        ).is_finding
        is True
    )
    for outcome in (
        CheckOutcome.PASS,
        CheckOutcome.NOT_APPLICABLE,
        CheckOutcome.MANUAL_REVIEW,
    ):
        assert (
            CheckResult(check_id="c", outcome=outcome, evidence=evidence).is_finding
            is False
        ), outcome


def test_qod_outside_zero_to_one_hundred_is_refused():
    with pytest.raises(ValueError, match="qod must be 0-100"):
        CheckResult(check_id="c", outcome=CheckOutcome.PASS, qod=101)


def test_not_applicable_records_its_reason():
    result = CheckResult.not_applicable(
        "cis_win_only", "10.0.0.5", reason="target is Linux"
    )
    assert result.outcome is CheckOutcome.NOT_APPLICABLE
    assert result.metadata["not_applicable_reason"] == "target is Linux"


# ─────────────────────────────────────────────────────────────────────────────
# Severity — one vocabulary, not three
# ─────────────────────────────────────────────────────────────────────────────


def test_compliance_info_severity_maps_onto_the_finding_vocabulary():
    """
    ``compliance_rules.severity`` permits ``info``; the finding tables permit
    ``none`` and reject ``info`` outright. Two spellings of one severity split
    every GROUP BY in the product, which this codebase has already paid for
    once.
    """
    assert normalize_severity("info") == "none"
    assert normalize_severity("INFO") == "none"
    assert normalize_severity("Critical") == "critical"


def test_unrecognised_severity_becomes_unscored_not_none():
    """``unscored`` means no rating was published; ``none`` means a published
    rating of zero. Collapsing them hides which checks were never rated."""
    assert normalize_severity("banana") == "unscored"
    assert normalize_severity(None) == "unscored"
    assert normalize_severity("") == "unscored"


def test_check_result_normalises_severity_on_construction():
    result = CheckResult(check_id="c", outcome=CheckOutcome.PASS, severity="info")
    assert result.severity == "none"


# ─────────────────────────────────────────────────────────────────────────────
# Evidence
# ─────────────────────────────────────────────────────────────────────────────


def test_raw_evidence_is_redacted_on_construction():
    """
    Collected configuration is exactly where secrets turn up — a connection
    string in a config file, a password in an answer file — and this object is
    written to the database and rendered into reports. Redaction has to happen
    at construction, not at render time, or one code path that forgets it
    publishes the secret.
    """
    evidence = _evidence(raw="db_password=hunter2\nAuthorization: Bearer abcdef123456")
    assert "hunter2" not in evidence.raw
    assert "abcdef123456" not in evidence.raw
    assert "[REDACTED]" in evidence.raw


def test_evidence_distinguishes_nothing_captured_from_empty_output():
    assert _evidence(raw=None).raw is None
    assert _evidence(raw="").raw == ""


def test_evidence_requires_a_collector_and_a_description():
    with pytest.raises(ValueError, match="collector is required"):
        Evidence(collector="", description="x")
    with pytest.raises(ValueError, match="description is required"):
        Evidence(collector="x", description="  ")


def test_evidence_refuses_a_naive_timestamp():
    """Timestamps in scan payloads are timezone-aware UTC. A naive one renders
    as local time beside UTC siblings."""
    from datetime import datetime

    with pytest.raises(ValueError, match="timezone-aware"):
        Evidence(collector="x", description="y", collected_at=datetime(2026, 8, 27))


# ─────────────────────────────────────────────────────────────────────────────
# Catalogue identifiers for non-CVE findings
# ─────────────────────────────────────────────────────────────────────────────


def test_check_identifiers_are_vendor_prefixed_and_never_cve_shaped():
    """
    A reader who meets ``CCURE-CFG-…`` in a report knows the identifier is ours
    and that searching NVD for it will return nothing. That is the whole point:
    the live catalogue already contains 23 rows keyed ``CVE-9999-…`` (test
    residue), and every one of those reads to a human as a published CVE.
    """
    minted = definition_id_for_check("cis_win2022_2.3.1.1")
    assert minted == "CCURE-CFG-CIS-WIN2022-2-3-1-1"
    assert not is_cve_id(minted)
    assert definition_type_for_id(minted) == DEFINITION_TYPE_CONFIG_CHECK


def test_two_spellings_of_one_control_mint_one_identifier():
    """Dots and underscores are the same control. If they minted two catalogue
    rows, one control would carry two independent finding histories."""
    assert definition_id_for_check("cis_win2022_2.3.1.1") == definition_id_for_check(
        "CIS.WIN2022.2_3_1_1"
    )


def test_minting_refuses_a_cve_identifier():
    """A finding for a published CVE belongs under its real identifier, written
    by the feeds — not minted as a check."""
    with pytest.raises(ValueError, match="is a CVE identifier"):
        definition_id_for_check("CVE-2024-4577")


def test_minting_refuses_rather_than_truncating_an_over_long_identifier():
    """
    Truncating the tail would silently merge two long sibling controls onto one
    catalogue row — the exact collision the slug rules exist to prevent.
    """
    with pytest.raises(ValueError, match="over the .* column limit"):
        definition_id_for_check("x" * (DEFINITION_ID_MAX_LENGTH + 5))


def test_an_unrecognised_identifier_is_not_assumed_to_be_a_cve():
    """Mislabelling an in-house identifier as a CVE puts it in front of a
    customer as a published vulnerability — the worse direction to be wrong."""
    assert definition_type_for_id("something-odd") == DEFINITION_TYPE_PLUGIN_CHECK
    assert definition_type_for_id("CVE-2024-4577") == DEFINITION_TYPE_CVE


def test_minted_identifiers_fit_the_catalogue_column():
    """The column is varchar(120) as of migration e1f2a3b4c5d6."""
    from db.models.findings import VulnerabilityDefinition

    assert VulnerabilityDefinition.__table__.c.id.type.length == (
        DEFINITION_ID_MAX_LENGTH
    )
    from db.models.findings import AssetVulnerability

    assert AssetVulnerability.__table__.c.vuln_id.type.length == (
        DEFINITION_ID_MAX_LENGTH
    )


def test_the_model_and_the_definitions_module_agree_on_the_type_vocabulary():
    """
    The CHECK constraint and the minting code must not drift. If they do, a
    value the code produces becomes a value the database refuses — at scan
    time, on a customer's network.
    """
    from core.checks.definitions import DEFINITION_TYPES
    from db.models.findings import DEFINITION_TYPE_VALUES

    assert set(DEFINITION_TYPES) == set(DEFINITION_TYPE_VALUES)


# ─────────────────────────────────────────────────────────────────────────────
# Registry
# ─────────────────────────────────────────────────────────────────────────────


def _spec(check_id="demo_check", **overrides) -> CheckSpec:
    payload = {
        "check_id": check_id,
        "title": "Demo",
        "domain": "host_configuration",
    }
    payload.update(overrides)
    return CheckSpec(**payload)


def test_registration_refuses_a_check_the_executor_could_never_call():
    """
    The defect this whole module exists for: a check whose ``run`` takes the
    wrong number of arguments raises TypeError on every target, is caught and
    logged at DEBUG, and is counted as registered while never executing. It
    must be impossible to register, not merely discouraged.
    """
    reg = CheckRegistry(required_arity=1)
    with pytest.raises(RegistrationError, match="cannot be called with 1"):
        reg.register(_spec(), lambda: None)
    with pytest.raises(RegistrationError, match="cannot be called with 1"):
        reg.register(_spec(), lambda ctx, extra: None)
    assert len(reg) == 0


def test_registration_accepts_the_shapes_the_executor_can_call():
    reg = CheckRegistry(required_arity=1)
    reg.register(_spec("a"), lambda ctx: None)
    reg.register(_spec("b"), lambda ctx, extra=None: None)
    reg.register(_spec("c"), lambda *args: None)
    assert len(reg) == 3


def test_duplicate_check_ids_are_refused_unless_replacement_is_explicit():
    """Two checks sharing an id collapse to one catalogue row and one finding,
    so the second silently erases the first."""
    reg = CheckRegistry()
    reg.register(_spec("dup"), lambda ctx: None)
    with pytest.raises(RegistrationError, match="already registered"):
        reg.register(_spec("dup"), lambda ctx: None)
    reg.register(_spec("dup"), lambda ctx: None, replace=True)
    assert len(reg) == 1


def test_a_raising_check_yields_an_error_result_not_a_fail_and_not_silence():
    """
    Both alternatives are wrong and both have shipped here: swallowing makes a
    broken check indistinguishable from a clean host, and returning FAIL
    invents a finding out of a bug in our own code.
    """
    reg = CheckRegistry()

    def _boom(ctx):
        raise RuntimeError("collector exploded")

    reg.register(_spec("boom"), _boom)

    class _Ctx:
        target = "10.0.0.5"

    result = reg.run_check("boom", _Ctx())
    assert result.outcome is CheckOutcome.ERROR
    assert "collector exploded" in result.error
    assert result.target == "10.0.0.5"


def test_a_check_returning_the_wrong_type_yields_an_error_result():
    reg = CheckRegistry()
    reg.register(_spec("wrong"), lambda ctx: {"legacy": "dict"})

    class _Ctx:
        target = "10.0.0.5"

    result = reg.run_check("wrong", _Ctx())
    assert result.outcome is CheckOutcome.ERROR
    assert "expected CheckResult" in result.error


def test_intrusive_checks_are_excluded_unless_explicitly_allowed():
    """
    This product scans production and OT hosts. An intrusive check must be
    something an operator turned on, never something they forgot to turn off.
    """
    reg = CheckRegistry()
    reg.register(_spec("safe"), lambda ctx: None)
    reg.register(_spec("rough", intrusive=True), lambda ctx: None)

    assert [e.check_id for e in reg.select()] == ["safe"]
    assert sorted(e.check_id for e in reg.select(allow_intrusive=True)) == [
        "rough",
        "safe",
    ]


def test_select_filters_by_domain_platform_and_credential_requirement():
    reg = CheckRegistry()
    reg.register(_spec("win", platforms=("windows",)), lambda ctx: None)
    reg.register(_spec("nix", platforms=("linux",)), lambda ctx: None)
    reg.register(_spec("any", platforms=("any",)), lambda ctx: None)
    reg.register(
        _spec("cred", platforms=("windows",), requires_credentials=True),
        lambda ctx: None,
    )

    windows = {e.check_id for e in reg.select(platform="windows")}
    assert windows == {"win", "any", "cred"}, (
        "'any' must apply to every platform, and a credentialed check is still "
        "a windows check"
    )
    assert {e.check_id for e in reg.select(platform="windows", credentialed=False)} == {
        "win",
        "any",
    }
    assert reg.select(domain="database") == []


def test_a_spec_with_an_unknown_domain_is_refused():
    with pytest.raises(ValueError, match="is not one of"):
        _spec("x", domain="wishful_thinking")

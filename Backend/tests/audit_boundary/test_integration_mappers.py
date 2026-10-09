"""
Integration mappers — Phase 5 step 5.6.

Pure Audit view → Phase 4 contract mapping, tested without a database: every
view here is built by hand, so each test states exactly the stored data it is
about. The DB-backed path (service → view → mapper) is covered beside each
service's own fixture, in ``test_assessment_read_service`` and
``test_finding_read_service``.

What is pinned:

* **the adapter's vocabulary tables agree with Audit's own definitions** and
  with the contract enums, so neither side can drift silently;
* every mapped message **validates against its contract model** and survives
  a JSON round trip;
* **unknown is never reported as a known state** — absent values are stated
  ``not_implemented`` / ``not_applicable`` / ``not_collected`` with a reason,
  unassessed hosts count as NOT_ASSESSED, a withdrawn acceptance is not an
  acceptance, and inconsistent stored data is refused with ``MappingError``;
* mappers are **pure**: the same input gives an equal message.
"""

from __future__ import annotations

import inspect
import json
import uuid
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from ccure_audit.integration import vocabulary as vocab
from ccure_audit.integration.envelope import EnvelopeContext, envelope
from ccure_audit.integration.errors import MappingError
from ccure_audit.integration.mappers.baseline_coverage import baseline_coverage
from ccure_audit.integration.mappers.capabilities import (
    ContractSupport,
    MethodSupport,
    capabilities,
)
from ccure_audit.integration.mappers.control_results import (
    PRECEDENCE,
    control_results,
    controls_page,
    roll_up,
)
from ccure_audit.integration.mappers.findings import (
    exploit_availability,
    finding,
    findings_page,
)
from ccure_audit.integration.mappers.policy_baseline import baseline_input
from ccure_audit.services.assessment_read import (
    AssessmentVerdictsView,
    CheckVerdictView,
    ControlRefView,
    HostVerdictsView,
)
from ccure_audit.services.baseline_mapping import (
    PARAMETER_HANDLINGS,
    ControlCoverageView,
    CoverageCountsView,
    CoverageView,
    ParameterDefinition,
    ParameterOutcomeView,
    ScopeOutcomeView,
    ScopeRejectionView,
)
from ccure_audit.services.compliance_catalogue import (
    MAPPING_STATES,
    CatalogueFrameworkView,
    CatalogueRuleView,
    ControlKey,
    ControlMappingView,
    FrameworkCapabilityView,
)
from ccure_audit.services.finding_read import FindingPageView, FindingView
from ccure_contracts.common.v1 import vocabulary as cv
from ccure_contracts.policy_baseline.v1.models import CcurePolicyBaselineV1
from ccure_contracts.registry import SCHEMA_VERSION
from testpaths import BACKEND_ROOT

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)
CTX = EnvelopeContext(
    message_id=uuid.UUID("00000000-0000-4000-8000-000000000001"),
    tenant_id="org_mapper",
    module_version="test",
    produced_at=NOW,
    correlation_id="corr-mapper",
)


def _values(enum) -> set:
    return {member.value for member in enum}


def _round_trips(message) -> None:
    again = type(message).model_validate_json(message.model_dump_json(by_alias=True))
    assert again == message


# ─────────────────────────────────────────────────────────────────────────────
# Vocabulary: pinned to Audit's definitions and to the contract
# ─────────────────────────────────────────────────────────────────────────────


def test_outcomes_are_audits_check_outcomes():
    from core.checks.contract import CheckOutcome

    assert set(vocab._OUTCOME_TO_STATE) == _values(CheckOutcome)
    assert set(vocab._OUTCOME_TO_STATE.values()) | {"NOT_ASSESSED"} == _values(
        cv.AssessmentState
    )


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "  ",
        "Critical",
        "HIGH",
        "medium",
        "low",
        "none",
        "info",
        "Informational",
        "unknown",
        "unscored",
        "bogus",
        7.5,
    ],
)
def test_severity_follows_audits_normaliser(value):
    from core.checks.contract import normalize_severity

    assert vocab.severity(value) == normalize_severity(value)


def test_severity_vocabularies_agree():
    from core.checks.contract import _RULE_SEVERITY_ALIASES
    from core.checks.cvss import CANONICAL_SEVERITIES

    assert vocab.CANONICAL_SEVERITIES == tuple(CANONICAL_SEVERITIES)
    assert set(vocab.CANONICAL_SEVERITIES) == _values(cv.Severity)
    assert vocab._SEVERITY_ALIASES == _RULE_SEVERITY_ALIASES


def test_detection_vocabularies_agree():
    from core.checks.finding_normalizer import Confidence, DetectionMethod

    assert set(vocab.CANONICAL_DETECTION_METHODS) == _values(DetectionMethod)
    assert set(vocab.CANONICAL_DETECTION_METHODS) == _values(cv.DetectionMethod)
    assert set(vocab._CONFIDENCES) == {c.lower() for c in _values(Confidence)}
    assert set(vocab._CONFIDENCES) == _values(cv.DetectionConfidence)


def test_detection_aliases_are_the_normalisers():
    """The raw plugin spellings map where ``classify_detection`` maps them."""
    from core.checks import finding_normalizer

    source = inspect.getsource(finding_normalizer.classify_detection)
    for raw, method in vocab._DETECTION_ALIASES.items():
        assert f'"{raw}": DetectionMethod.{method.upper()}' in source


def test_closed_vocabularies_agree():
    from core.checks.definitions import DEFINITION_TYPES
    from core.remediation.sla import SLA_STATES
    from db.models.findings import REMEDIATION_STATES

    assert vocab.REMEDIATION_STATES == tuple(REMEDIATION_STATES)
    assert set(vocab.REMEDIATION_STATES) == _values(cv.RemediationState)
    assert vocab.SLA_STATES == tuple(SLA_STATES)
    assert set(vocab.SLA_STATES) == _values(cv.SlaState)
    assert vocab.DEFINITION_TYPES == tuple(DEFINITION_TYPES)
    assert set(vocab.DEFINITION_TYPES) == _values(cv.DefinitionType)
    assert set(vocab.DETECTION_STATUSES) == _values(cv.DetectionStatus)


def test_mapping_and_parameter_vocabularies_agree():
    assert set(vocab._MAPPING_STATES) == set(MAPPING_STATES)
    assert set(vocab._MAPPING_STATES.values()) == _values(cv.BaselineMappingState)
    assert set(vocab._PARAMETER_HANDLINGS) == set(PARAMETER_HANDLINGS)
    assert set(vocab._PARAMETER_HANDLINGS.values()) == _values(cv.ParameterHandling)


def test_the_precedence_is_the_contracts_and_covers_every_state():
    assert set(PRECEDENCE) == _values(cv.AssessmentState)
    for i, higher in enumerate(PRECEDENCE):
        for lower in PRECEDENCE[i:]:
            assert roll_up([lower, higher]) == higher


def test_a_truncated_text_says_so():
    long = "x" * 2000
    cut = vocab.short_text(long)
    assert len(cut) == vocab.SHORT_TEXT_MAX and cut.endswith("[…]")
    assert vocab.short_text("  ") is None
    assert vocab.short_text("", fallback="id") == "id"


def test_the_envelope_is_the_callers():
    fields = envelope("ccure.audit.capabilities", CTX)
    assert fields["schema_version"] == SCHEMA_VERSION
    assert fields["message_id"] == CTX.message_id
    assert fields["source"] == {"module": "audit", "module_version": "test"}
    assert "causation_id" not in fields


# ─────────────────────────────────────────────────────────────────────────────
# Findings
# ─────────────────────────────────────────────────────────────────────────────


def _finding(**kw) -> FindingView:
    base = dict(
        finding_id="fnd_ast_org_mapper_10_0_0_1_CVE-9999-60001",
        scan_id="scn_mapper",
        first_scan_id="scn_mapper",
        asset_id="ast_org_mapper_10_0_0_1",
        ip_address="10.0.0.1",
        hostname=None,
        mac_address=None,
        definition_id="CVE-9999-60001",
        definition_type="cve",
        title="A fixture vulnerability",
        severity="high",
        cvss_score=Decimal("7.5"),
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_version="3.1",
        status="open",
        source_family="credentialed_package",
        detection_method="credentialed_package",
        confidence="Confirmed",
        qod=97,
        detected_version="1.2.3",
        in_kev=False,
        kev_due_date=None,
        epss_score=Decimal("0.12345"),
        epss_percentile=Decimal("0.9"),
        has_exploit=False,
        verified_exploit=False,
        canary_confirmed=False,
        ransomware_linked=False,
        exploit_sources=(),
        evidence="installed 1.2.3",
        vendor_remediation="Upgrade to 1.2.4.",
        first_found_at=NOW - timedelta(days=10),
        last_found_at=NOW,
        fixed_at=None,
        remediation_state="open",
        remediation_owner_id=None,
        assigned_at=None,
        sla_due_at=NOW + timedelta(days=20),
        sla_basis="high",
        sla_state="within_sla",
        verified_at=None,
        verified_scan_id=None,
        reopened_at=None,
        reopened_count=0,
        accepted_at=None,
        accepted_by_id=None,
        exception_expires_at=None,
        accepted_risk_reason=None,
    )
    base.update(kw)
    return FindingView(**base)


def test_a_cve_finding_maps_and_round_trips():
    message = finding(_finding())
    _round_trips(message)
    assert message.definition.cve_id == "CVE-9999-60001"
    assert message.detection.method is cv.DetectionMethod.CREDENTIALED_PACKAGE
    assert message.detection.confidence is cv.DetectionConfidence.CONFIRMED
    assert message.exploit.availability is cv.ExploitAvailability.NONE_KNOWN
    assert message.exploit.in_cisa_kev is False
    assert message.exploit.epss_score == pytest.approx(0.12345)
    assert message.risk.cvss_component.status is cv.ValueStatus.AVAILABLE
    assert message.risk.cvss_component.value == 7.5
    assert message.remediation.guidance == "Upgrade to 1.2.4."
    assert message.last_assessment.assessment_id == "scn_mapper"
    # Not implemented is null, never an empty list claiming there is none.
    assert message.evidence_refs is None


def test_what_audit_does_not_implement_is_stated_never_zero():
    risk = finding(_finding()).risk
    for component in (
        risk.asset_criticality_component,
        risk.exposure_component,
        risk.srs_risk_score,
        risk.residual_risk_score,
    ):
        assert component.status is cv.ValueStatus.NOT_IMPLEMENTED
        assert component.value is None and component.reason
    assert risk.risk_category is None and risk.audit_priority is None


def test_a_configuration_check_carries_no_exploit_intel_and_no_cvss():
    view = _finding(
        definition_id="CCURE-CFG-TEST-MAPPER",
        definition_type="config_check",
        cvss_score=None,
        cvss_vector=None,
        cvss_version=None,
        epss_score=None,
        detection_method="active_check",
    )
    message = finding(view)
    assert message.definition.cve_id is None
    assert message.cvss is None
    assert message.exploit.availability is cv.ExploitAvailability.NOT_APPLICABLE
    assert message.exploit.in_cisa_kev is None  # not False: KEV is about CVEs
    assert message.exploit.ransomware_linked is None
    assert message.risk.cvss_component.status is cv.ValueStatus.NOT_APPLICABLE
    assert message.detection.method is cv.DetectionMethod.CONFIG_CHECK


@pytest.mark.parametrize("definition_type", ["config_check", "privilege_check"])
def test_a_stored_zero_on_a_check_is_not_reported_as_its_cvss(definition_type):
    """Audit stores cvss_score 0.0, no vector, on every non-CVE finding —
    critical ones included. That is a placeholder, not a published score."""
    view = _finding(
        definition_id="CCURE-PRV-CCURE-PRIV-WIN-SERVICE-BINARY-ACL",
        definition_type=definition_type,
        severity="critical",
        cvss_score=Decimal("0.0"),
        cvss_vector=None,
        cvss_version=None,
    )
    message = finding(view)
    assert message.cvss is None
    assert message.risk.cvss_component.status is cv.ValueStatus.NOT_APPLICABLE
    assert message.risk.cvss_component.value is None
    assert message.severity is cv.Severity.CRITICAL


def test_a_cve_without_a_score_is_not_collected_rather_than_zero():
    message = finding(_finding(cvss_score=None, cvss_vector=None, cvss_version=None))
    assert message.cvss is None
    assert message.risk.cvss_component.status is cv.ValueStatus.NOT_COLLECTED
    assert message.risk.cvss_component.value is None


@pytest.mark.parametrize(
    "flags, expected",
    [
        ({}, "none_known"),
        ({"has_exploit": True}, "public_exploit"),
        ({"has_exploit": True, "verified_exploit": True}, "verified_exploit"),
        ({"verified_exploit": True, "in_kev": True}, "actively_exploited"),
        ({"canary_confirmed": True}, "actively_exploited"),
        ({"ransomware_linked": True}, "actively_exploited"),
    ],
)
def test_exploit_availability_is_the_strongest_evidence(flags, expected):
    assert exploit_availability(_finding(**flags)) == expected


def test_a_kev_due_date_travels_only_with_kev():
    due = date(2026, 10, 1)
    assert finding(_finding(in_kev=True, kev_due_date=due)).exploit.kev_due_date == due
    assert (
        finding(_finding(in_kev=False, kev_due_date=due)).exploit.kev_due_date is None
    )


@pytest.mark.parametrize(
    "raw, method",
    [
        ("active_check", "config_check"),
        ("nessus", "imported"),
        ("VERSION_MATCH", "version_match"),
        (None, "unverified"),
        ("something_new", "unverified"),
    ],
)
def test_detection_methods_never_claim_more_than_stored(raw, method):
    assert finding(_finding(detection_method=raw)).detection.method.value == method


@pytest.mark.parametrize(
    "raw, level",
    [
        ("Confirmed", "confirmed"),
        ("potential", "potential"),
        (None, "unverified"),
        ("certain", "unverified"),
    ],
)
def test_confidence_is_normalised(raw, level):
    assert finding(_finding(confidence=raw)).detection.confidence.value == level


@pytest.mark.parametrize(
    "raw, severity",
    [
        ("info", "none"),
        (None, "unscored"),
        ("bogus", "unscored"),
        ("CRITICAL", "critical"),
    ],
)
def test_finding_severity_never_invents_a_rating(raw, severity):
    assert finding(_finding(severity=raw)).severity.value == severity


def test_verified_fixed_names_the_verifying_scan():
    view = _finding(
        status="fixed",
        remediation_state="verified_fixed",
        fixed_at=NOW,
        verified_at=NOW,
        verified_scan_id="scn_verifier",
        sla_state="resolved",
    )
    remediation = finding(view).remediation
    assert remediation.verified_by.assessment_id == "scn_verifier"
    with pytest.raises(MappingError, match="verifying scan"):
        finding(replace(view, verified_scan_id=None))


def test_a_risk_acceptance_is_emitted_only_in_state_risk_accepted():
    accepted = _finding(
        status="accepted",
        remediation_state="risk_accepted",
        sla_state="resolved",
        accepted_at=NOW,
        accepted_by_id="usr_approver",
        exception_expires_at=NOW + timedelta(days=90),
        accepted_risk_reason="Compensating control in place.",
    )
    acceptance = finding(accepted).remediation.risk_acceptance
    assert acceptance.reason == "Compensating control in place."
    assert acceptance.accepted_by_ref == "usr_approver"
    assert acceptance.compensating_controls is None

    # Withdrawn: the state moved on and the residue stayed. The state decides.
    withdrawn = replace(
        accepted,
        status="open",
        remediation_state="open",
        sla_state="within_sla",
        exception_expires_at=None,
    )
    assert finding(withdrawn).remediation.risk_acceptance is None


@pytest.mark.parametrize("missing", ["accepted_at", "accepted_risk_reason"])
def test_an_acceptance_missing_its_record_is_refused(missing):
    view = _finding(
        remediation_state="risk_accepted",
        status="accepted",
        sla_state="resolved",
        accepted_at=NOW,
        accepted_risk_reason="Reason.",
    )
    with pytest.raises(MappingError, match="risk_accepted"):
        finding(replace(view, **{missing: None}))


@pytest.mark.parametrize(
    "field_name, value",
    [
        ("remediation_state", "parked"),
        ("sla_state", "fine"),
        ("status", "gone"),
        ("definition_type", "nasl"),
    ],
)
def test_a_closed_vocabulary_value_audit_does_not_define_is_refused(field_name, value):
    with pytest.raises(MappingError, match="not in the contract vocabulary"):
        finding(_finding(**{field_name: value}))


def test_no_deadline_is_not_within_sla():
    remediation = finding(
        _finding(sla_state="not_applicable", sla_due_at=None)
    ).remediation
    assert (
        remediation.sla_state is cv.SlaState.NOT_APPLICABLE
        and remediation.sla_due_at is None
    )


def test_an_untitled_definition_is_shown_by_its_identifier():
    assert finding(_finding(title="")).definition.title == "CVE-9999-60001"


def test_an_identifier_the_contract_cannot_carry_is_a_mapping_error():
    with pytest.raises(MappingError, match="finding"):
        finding(_finding(asset_id="has a space"))


def test_the_findings_page_carries_the_cursor():
    items = (
        _finding(),
        _finding(finding_id="fnd_second", definition_id="CVE-9999-60002"),
    )
    more = findings_page(
        FindingPageView(scan_id="scn_mapper", items=items, next_after="fnd_second"),
        result_id="res_mapper",
        ctx=CTX,
    )
    _round_trips(more)
    assert more.position.has_more and more.position.next_cursor == "fnd_second"
    assert len(more.items) == 2
    last = findings_page(
        FindingPageView(scan_id="scn_mapper", items=(), next_after=None),
        result_id="res_mapper",
        ctx=CTX,
    )
    assert not last.position.has_more and last.position.next_cursor is None


def test_mapping_is_pure():
    view = _finding()
    assert finding(view) == finding(view)


# ─────────────────────────────────────────────────────────────────────────────
# Control results
# ─────────────────────────────────────────────────────────────────────────────


def _ref(number="5.2.8", code="BM_MAPPER", control_id=None) -> ControlRefView:
    return ControlRefView(
        framework_id="cfw_bm_mapper",
        framework_name="Mapper benchmark",
        control_id=control_id or f"cct_cfw_bm_mapper_{number.replace('.', '_')}",
        control_title=f"Control {number}",
        profiles=(),
        framework_code=code,
        framework_version="1.0",
        control_number=number,
    )


def _check(check_id, outcome, controls=(), **kw) -> CheckVerdictView:
    base = dict(
        check_id=check_id,
        title=f"Check {check_id}",
        target="",
        outcome=outcome,
        severity="high",
        check_type="config_file",
        domain="host_configuration",
        description="",
        expected="no",
        observed="yes" if outcome == "fail" else "no",
        evidence_lines=(),
        error="",
        remediation="",
        references="",
        not_applicable_reason="",
        controls=tuple(controls),
    )
    base.update(kw)
    return CheckVerdictView(**base)


def _host(host, *results, assessed=True, reason="") -> HostVerdictsView:
    return HostVerdictsView(
        host=host,
        asset_id=None,
        platform="linux",
        assessed=assessed,
        reason=reason,
        results=tuple(results),
    )


def _verdicts(*hosts) -> AssessmentVerdictsView:
    return AssessmentVerdictsView(
        scan_id="scn_mapper",
        org_id="org_mapper",
        policy_framework_ids=None,
        hosts=hosts,
    )


def _one(view):
    (result,) = control_results(view)
    _round_trips(result)
    return result


def test_a_control_passes_only_where_every_asset_that_ran_it_passed():
    ref = _ref()
    result = _one(_verdicts(_host("10.0.0.1", _check("r1", "pass", [ref]))))
    assert result.state is cv.AssessmentState.PASS
    assert result.control.control_id == "5.2.8"
    assert result.control.framework.code == "BM_MAPPER"
    assert result.asset_counts.pass_ == 1 and result.state_reason is None
    assert result.basis == "automated"
    assert result.disposition is cv.ComplianceDisposition.NONE
    assert result.finding_refs is None and result.evidence_refs is None


def test_an_unassessed_host_keeps_the_control_from_passing():
    ref = _ref()
    result = _one(
        _verdicts(
            _host("10.0.0.1", _check("r1", "pass", [ref])),
            _host("10.0.0.2", assessed=False, reason="Authentication was rejected."),
        )
    )
    assert result.state is cv.AssessmentState.NOT_ASSESSED
    assert result.asset_counts.pass_ == 1 and result.asset_counts.not_assessed == 1
    assert "Authentication was rejected." in result.state_reason
    (rule,) = result.rules
    assert rule.state is cv.AssessmentState.NOT_ASSESSED and rule.reason


def test_a_host_the_policy_did_not_select_a_rule_for_does_not_count():
    linux, windows = _ref("1.1"), _ref("2.2")
    results = control_results(
        _verdicts(
            _host("10.0.0.1", _check("linux_rule", "pass", [linux])),
            _host("10.0.0.2", _check("windows_rule", "pass", [windows])),
        )
    )
    assert [r.state for r in results] == [cv.AssessmentState.PASS] * 2
    assert all(r.asset_counts.pass_ == 1 for r in results)


def test_a_failure_outranks_everything_and_is_described():
    ref = _ref()
    result = _one(
        _verdicts(
            _host("10.0.0.1", _check("r1", "fail", [ref], title="Root login")),
            _host(
                "10.0.0.2", _check("r1", "error", [ref], error="sshd_config unreadable")
            ),
            _host("10.0.0.3", assessed=False, reason="No credential."),
        )
    )
    assert result.state is cv.AssessmentState.FAIL
    assert result.asset_counts.fail == 1
    assert result.asset_counts.error == 1
    assert result.asset_counts.not_assessed == 1
    assert (
        "Root login" in result.gap_description and "10.0.0.1" in result.gap_description
    )
    assert "expected no, observed yes" in result.gap_description


@pytest.mark.parametrize(
    "outcome, extra, state, reason_fragment",
    [
        ("error", {"error": "getcap missing"}, "ERROR", "getcap missing"),
        (
            "not_applicable",
            {"not_applicable_reason": "windows only"},
            "NOT_APPLICABLE",
            "windows only",
        ),
        ("manual_review", {}, "MANUAL_REVIEW", "human decision"),
        ("", {}, "NOT_ASSESSED", "no outcome"),
        ("flaky", {}, "ERROR", "'flaky'"),
    ],
)
def test_every_non_verdict_says_why(outcome, extra, state, reason_fragment):
    result = _one(
        _verdicts(_host("10.0.0.1", _check("r1", outcome, [_ref()], **extra)))
    )
    assert result.state.value == state
    assert reason_fragment in result.state_reason
    assert result.gap_description is None


def test_an_asset_rolls_up_across_the_controls_rules():
    ref = _ref()
    result = _one(
        _verdicts(
            _host(
                "10.0.0.1",
                _check("r1", "pass", [ref]),
                _check("r2", "manual_review", [ref]),
            ),
            _host("10.0.0.2", _check("r1", "pass", [ref]), _check("r2", "pass", [ref])),
        )
    )
    assert result.state is cv.AssessmentState.MANUAL_REVIEW
    assert result.asset_counts.manual_review == 1 and result.asset_counts.pass_ == 1
    assert [r.rule_id for r in result.rules] == ["r1", "r2"]
    assert [r.state.value for r in result.rules] == ["PASS", "MANUAL_REVIEW"]


def test_nothing_assessed_produces_no_control_results_rather_than_passes():
    assert (
        control_results(_verdicts(_host("10.0.0.1", assessed=False, reason="x"))) == ()
    )


def test_a_control_without_its_published_identifier_is_refused():
    ref = replace(_ref(), control_number="")
    with pytest.raises(MappingError, match="published control identifier"):
        control_results(_verdicts(_host("10.0.0.1", _check("r1", "pass", [ref]))))


def test_two_controls_publishing_one_identifier_are_refused():
    a, b = _ref(control_id="cct_a"), _ref(control_id="cct_b")
    with pytest.raises(MappingError, match="same identifier"):
        control_results(
            _verdicts(
                _host("10.0.0.1", _check("r1", "pass", [a]), _check("r2", "pass", [b]))
            )
        )


def test_the_controls_page():
    items = control_results(
        _verdicts(_host("10.0.0.1", _check("r1", "fail", [_ref()])))
    )
    page = controls_page(items, result_id="res_mapper", ctx=CTX)
    _round_trips(page)
    assert page.contract == "ccure.audit.assessment_controls_page"
    assert not page.position.has_more


# ─────────────────────────────────────────────────────────────────────────────
# Policy baseline and baseline coverage
# ─────────────────────────────────────────────────────────────────────────────

EXAMPLES = (
    Path(BACKEND_ROOT) / "ccure_contracts" / "policy_baseline" / "v1" / "examples"
)


def test_a_received_baseline_becomes_the_services_input():
    message = CcurePolicyBaselineV1.model_validate(
        json.loads((EXAMPLES / "policy_baseline.request.json").read_text())
    )
    view = baseline_input(message)
    assert view.baseline_id == message.data.baseline_id
    assert view.baseline_version == message.data.baseline_version
    assert len(view.controls) == len(message.data.controls)
    for got, sent in zip(view.controls, message.data.controls):
        assert got.requirement_id == sent.requirement_id
        assert got.control.framework_code == sent.control.framework.code
        assert got.control.framework_version == sent.control.framework.version
        assert got.control.control_id == sent.control.control_id
        assert got.applicable is (sent.applicability is cv.Applicability.APPLICABLE)
        assert [p.name for p in got.parameters] == [p.name for p in sent.parameters]
    assert (view.scope is None) is (message.data.scope is None)


def _fw(active=True, installed=True, version="2022") -> CatalogueFrameworkView:
    return CatalogueFrameworkView(
        framework_id="cfw_iso27001",
        code="ISO27001_2022",
        version=version,
        name="ISO/IEC 27001:2022",
        active_in_installation=active,
        installed_for_tenant=installed,
    )


def _rule(rule_id="crl_a_8_9", source="scan") -> CatalogueRuleView:
    return CatalogueRuleView(
        rule_id=rule_id,
        title="Configuration management",
        check_type="config_file",
        evidence_source=source,
        target_platform="linux",
        severity="medium",
        status="active",
    )


def _coverage_control(
    requirement_id, number, state, reason=None, rules=(), notes=(), applicable=True
) -> ControlCoverageView:
    key = ControlKey(
        framework_code="ISO27001_2022", framework_version="2022", control_id=number
    )
    return ControlCoverageView(
        requirement_id=requirement_id,
        applicable=applicable,
        mapping=ControlMappingView(
            key=key,
            state=state,
            reason=reason,
            framework=_fw(),
            control_ref=f"cct_{number}",
            control_title=f"Control {number}",
            scannability="auto",
            rules=tuple(rules),
        ),
        assessing_rules=tuple(rules),
        notes=tuple(notes),
    )


def _coverage(*controls, parameters=(), scope=None) -> CoverageView:
    counts = {s: 0 for s in MAPPING_STATES}
    for c in controls:
        if c.mapping.state in counts:
            counts[c.mapping.state] += 1
    return CoverageView(
        baseline_id="bl_mapper",
        baseline_version=3,
        counts=CoverageCountsView(controls_total=len(controls), **counts),
        controls=tuple(controls),
        parameters=tuple(parameters),
        scope=scope
        or ScopeOutcomeView(
            requested=False,
            org_scope_configured=True,
            accepted_cidrs=(),
            rejected_cidrs=(),
            asset_tags=(),
            unmatched_tags=(),
        ),
    )


def _map_coverage(view, **kw):
    kw.setdefault("activation", "pending_review")
    return baseline_coverage(
        view, ctx=CTX, received_at=NOW, mapped_at=NOW, mapping_revision=1, **kw
    )


def test_every_mapping_state_maps_and_the_summary_adds_up():
    view = _coverage(
        _coverage_control("req-1", "A.8.9", "automated", rules=[_rule()]),
        _coverage_control(
            "req-2",
            "A.8.8",
            "partially_automated",
            "Part manual.",
            rules=[_rule("crl_a_8_8")],
        ),
        _coverage_control("req-3", "A.5.1", "attestation_required", "Policy document."),
        _coverage_control("req-4", "Z.9.9", "unknown_control", "Not in the catalogue."),
        _coverage_control("req-5", "A.7.4", "unsupported", "Physical control."),
        parameters=[
            ParameterOutcomeView(
                requirement_id="req-1",
                name="min_len",
                handling="unknown_parameter",
                reason="Audit has no parameter vocabulary yet.",
            )
        ],
        scope=ScopeOutcomeView(
            requested=True,
            org_scope_configured=True,
            accepted_cidrs=("10.0.0.0/24",),
            rejected_cidrs=(
                ScopeRejectionView(
                    entry="192.168.0.0/16", reason="outside the authorised scope"
                ),
            ),
            asset_tags=("finance",),
            unmatched_tags=("finance",),
        ),
    )
    message = _map_coverage(view)
    _round_trips(message)
    data = message.data
    assert [c.mapping_state.value for c in data.controls] == [
        "AUTOMATED",
        "PARTIALLY_AUTOMATED",
        "ATTESTATION_REQUIRED",
        "UNKNOWN_CONTROL",
        "UNSUPPORTED",
    ]
    assert data.summary.controls_total == 5 and data.summary.unsupported == 1
    assert data.controls[0].audit_rules[0].rule_id == "crl_a_8_9"
    assert data.controls[0].audit_rules[0].platforms == ["linux"]
    assert data.controls[0].reason is None
    assert data.parameters[0].handling is cv.ParameterHandling.UNKNOWN_PARAMETER
    scope = data.scope
    assert scope.applied and scope.organisation_scope_configured
    (rejected,) = scope.rejected_entries
    assert rejected.entry == "192.168.0.0/16"
    assert rejected.reason == "outside the authorised scope"
    # Inside the scope but matching nothing: reported, never refused.
    assert scope.unmatched_asset_tags == ["finance"]
    assert data.activation == "pending_review"


def test_notes_and_applicability_have_their_own_fields():
    control = _coverage_control(
        "req-1",
        "A.8.9",
        "automated",
        rules=[_rule()],
        applicable=False,
        notes=("Declared not applicable by the baseline.",),
    )
    (mapped,) = _map_coverage(_coverage(control)).data.controls
    assert mapped.applicability is cv.Applicability.NOT_APPLICABLE
    assert mapped.notes == ["Declared not applicable by the baseline."]
    # reason keeps its contract meaning: why the control is not automated.
    assert mapped.reason is None


def test_an_unconfigured_organisation_scope_is_said_out_loud():
    view = _coverage(
        _coverage_control("req-1", "A.8.9", "automated", rules=[_rule()]),
        scope=ScopeOutcomeView(
            requested=True,
            org_scope_configured=False,
            accepted_cidrs=("10.0.0.0/24",),
            rejected_cidrs=(),
            asset_tags=(),
            unmatched_tags=(),
        ),
    )
    scope = _map_coverage(view).data.scope
    assert scope.applied and scope.organisation_scope_configured is False


def test_an_automated_control_with_no_assessing_rule_is_refused():
    with pytest.raises(MappingError, match="no assessing rule"):
        _map_coverage(_coverage(_coverage_control("req-1", "A.8.9", "automated")))


def test_an_unknown_mapping_state_is_refused():
    with pytest.raises(MappingError, match="mapping state"):
        _map_coverage(_coverage(_coverage_control("req-1", "A.8.9", "probably")))


def test_activation_is_the_callers_to_state():
    control = _coverage_control("req-1", "A.8.9", "automated", rules=[_rule()])
    with pytest.raises(TypeError):
        baseline_coverage(  # no activation: the mapper never decides it
            _coverage(control),
            ctx=CTX,
            received_at=NOW,
            mapped_at=NOW,
            mapping_revision=1,
        )
    with pytest.raises(MappingError):
        _map_coverage(_coverage(control), activation="probably_active")


# ─────────────────────────────────────────────────────────────────────────────
# Capabilities
# ─────────────────────────────────────────────────────────────────────────────

_METHODS = (MethodSupport(method="configuration_audit", implemented=True),)


def _capability(active=True, version="2022") -> FrameworkCapabilityView:
    return FrameworkCapabilityView(
        framework=_fw(active=active, version=version),
        controls_total=93,
        controls_automated=20,
        controls_partially_automated=5,
        controls_attestation_required=60,
        controls_unsupported=8,
    )


def test_capabilities_offer_only_active_frameworks():
    parked = replace(
        _capability(active=False),
        framework=replace(_fw(active=False), code="NIS2", framework_id="cfw_nis2"),
    )
    message = capabilities(
        [_capability(), parked],
        [
            ParameterDefinition(
                name="min_len",
                datatype="integer",
                unit="characters",
                description="Minimum password length.",
                honoured=False,
            )
        ],
        contracts=[
            ContractSupport(
                contract="ccure.audit.capabilities",
                schema_versions=("1.0",),
                direction="outbound",
                status="draft",
            )
        ],
        methods=_METHODS,
        ctx=CTX,
    )
    _round_trips(message)
    (fw,) = message.data.frameworks
    assert fw.framework.code == "ISO27001_2022"
    assert fw.controls_automated == 25  # automated + partially automated
    assert message.data.baseline_parameters[0].honoured is False


def test_an_empty_parameter_vocabulary_is_an_empty_list():
    from ccure_audit.services.baseline_mapping import PARAMETER_VOCABULARY

    message = capabilities(
        [], PARAMETER_VOCABULARY, contracts=[], methods=_METHODS, ctx=CTX
    )
    assert message.data.baseline_parameters == []


def test_capabilities_refuse_to_report_no_methods():
    with pytest.raises(MappingError, match="no method support"):
        capabilities([], (), contracts=[], methods=(), ctx=CTX)


def test_a_framework_without_a_version_is_refused():
    with pytest.raises(MappingError, match="framework version"):
        capabilities(
            [_capability(version="")], (), contracts=[], methods=_METHODS, ctx=CTX
        )


# ─────────────────────────────────────────────────────────────────────────────
# Boundary
# ─────────────────────────────────────────────────────────────────────────────


def test_the_mappers_import_only_contracts_services_and_the_adapter():
    import ast

    root = Path(BACKEND_ROOT) / "ccure_audit" / "integration"
    allowed = ("ccure_contracts", "ccure_audit.services", "ccure_audit.integration")
    stdlib_ok = {
        "__future__",
        "typing",
        "dataclasses",
        "datetime",
        "uuid",
        "collections",
        "pydantic",
    }
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                assert (
                    name.startswith(allowed) or name.split(".")[0] in stdlib_ok
                ), f"{path.relative_to(BACKEND_ROOT)} imports {name}"

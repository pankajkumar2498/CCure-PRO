"""
ComplianceCatalogueService — Phase 5 step 5.2.

Two layers of tests:

* ``classify_control`` on its own, with hand-built rules: every state, the
  approved rule exactly, and the two properties that matter most — only active
  rules count, and no rule never means automated.
* The service against the shipped catalogue in the test database: known ISO,
  CIS and GDPR controls classified as the catalogue says they should be, and
  tenant scoping. Rows a test needs that the catalogue does not have (a
  rule-less control, a tenant-private framework, a tenant installation) are
  flushed inside a transaction that is rolled back, never committed.
"""

from __future__ import annotations

import pytest

from ccure_audit.services.compliance_catalogue import (
    MAPPING_ATTESTATION_REQUIRED,
    MAPPING_AUTOMATED,
    MAPPING_PARTIALLY_AUTOMATED,
    MAPPING_STATES,
    MAPPING_UNKNOWN_CONTROL,
    MAPPING_UNSUPPORTED,
    CatalogueRuleView,
    ComplianceCatalogueService,
    ControlKey,
    classify_control,
)
from ccure_audit.services.views import impurities
from core.compliance_frameworks import is_active

ISO = ("ISO27001_2022", "2022")
CIS = ("CIS_V8_1", "8.1")
GDPR = ("GDPR", "2016/679")


def _rule(rule_id, *, source="offline_configuration", status="active"):
    return CatalogueRuleView(
        rule_id=rule_id,
        title=rule_id,
        check_type="registry",
        evidence_source=source,
        target_platform="any",
        severity="high",
        status=status,
    )


AUTO = _rule("r_auto")
AUTO_ARCHIVED = _rule("r_auto_old", status="archived")
MANUAL = _rule("r_manual", source="manual")
MANUAL_ARCHIVED = _rule("r_manual_old", source="manual", status="archived")


# ── classify_control ──────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "rules, expected",
    [
        ([AUTO], MAPPING_AUTOMATED),
        ([AUTO, _rule("r_auto_2")], MAPPING_AUTOMATED),
        ([AUTO, MANUAL], MAPPING_PARTIALLY_AUTOMATED),
        ([MANUAL], MAPPING_ATTESTATION_REQUIRED),
        ([MANUAL, _rule("r_manual_2", source="manual")], MAPPING_ATTESTATION_REQUIRED),
        ([], MAPPING_UNSUPPORTED),
    ],
    ids=["one-auto", "two-auto", "auto+manual", "manual", "two-manual", "none"],
)
def test_the_approved_rule(rules, expected):
    assert (
        classify_control(known=True, framework_active=True, rules=rules).state
        == expected
    )


def test_only_active_rules_count():
    # An archived automated rule does not make a control automated …
    assert (
        classify_control(known=True, framework_active=True, rules=[AUTO_ARCHIVED]).state
        == MAPPING_UNSUPPORTED
    )
    # … an archived placeholder does not make it partial …
    assert (
        classify_control(
            known=True, framework_active=True, rules=[AUTO, MANUAL_ARCHIVED]
        ).state
        == MAPPING_AUTOMATED
    )
    # … and archived rules alone leave a control with nothing.
    assert (
        classify_control(
            known=True, framework_active=True, rules=[AUTO_ARCHIVED, MANUAL_ARCHIVED]
        ).state
        == MAPPING_UNSUPPORTED
    )


def test_no_rule_is_never_automated_and_never_a_verdict():
    decided = classify_control(known=True, framework_active=True, rules=[])
    assert decided.state == MAPPING_UNSUPPORTED
    assert decided.reason
    for state in MAPPING_STATES:
        assert state not in ("pass", "fail", "PASS", "FAIL")


def test_unknown_and_unsupported_stay_distinct():
    unknown = classify_control(known=False, framework_active=True, rules=[AUTO])
    parked = classify_control(known=True, framework_active=False, rules=[AUTO])
    ruleless = classify_control(known=True, framework_active=True, rules=[])
    assert unknown.state == MAPPING_UNKNOWN_CONTROL
    assert parked.state == MAPPING_UNSUPPORTED
    assert ruleless.state == MAPPING_UNSUPPORTED
    assert len({unknown.reason, parked.reason, ruleless.reason}) == 3


def test_an_unknown_control_ignores_any_rules_passed_with_it():
    decided = classify_control(known=False, framework_active=True, rules=[AUTO, MANUAL])
    assert decided.state == MAPPING_UNKNOWN_CONTROL


def test_a_parked_framework_is_unsupported_even_with_automated_rules():
    decided = classify_control(known=True, framework_active=False, rules=[AUTO])
    assert decided.state == MAPPING_UNSUPPORTED
    assert "parked" in decided.reason


def test_every_state_but_automated_says_why():
    cases = [
        classify_control(known=True, framework_active=True, rules=[AUTO, MANUAL]),
        classify_control(known=True, framework_active=True, rules=[MANUAL]),
        classify_control(known=False, framework_active=True, rules=[]),
        classify_control(known=True, framework_active=True, rules=[]),
    ]
    assert all(c.reason for c in cases)
    assert (
        classify_control(known=True, framework_active=True, rules=[AUTO]).reason is None
    )


# ── The service against the real catalogue ────────────────────────────────────


@pytest.fixture
def catalogue(db_session):
    """
    The service over a session whose writes are never committed. Two tenants,
    neither of which has installed anything.
    """
    from db.models import Organization

    for org_id in ("org_cat_a", "org_cat_b"):
        db_session.add(
            Organization(
                id=org_id, name=f"Catalogue {org_id}", slug=org_id.replace("_", "-")
            )
        )
    db_session.flush()
    try:
        yield ComplianceCatalogueService(db_session), db_session
    finally:
        db_session.rollback()


def _one(service, org_id, code_version, control_id):
    (result,) = service.resolve_controls(
        org_id=org_id,
        keys=[
            ControlKey(
                framework_code=code_version[0],
                framework_version=code_version[1],
                control_id=control_id,
            )
        ],
    )
    assert impurities(result) == [], impurities(result)
    return result


@pytest.mark.parametrize("control_id", ["A.8.8", "A.8.9", "A.5.18"])
def test_real_automated_iso_controls(catalogue, control_id):
    service, _ = catalogue
    result = _one(service, "org_cat_a", ISO, control_id)
    assert result.state == MAPPING_AUTOMATED
    assert result.reason is None
    assert result.rules and all(not r.is_attestation_placeholder for r in result.rules)
    assert result.framework.framework_id == "cfw_iso27001_2022"


def test_a_8_8_names_its_vulnerability_rules(catalogue):
    service, _ = catalogue
    result = _one(service, "org_cat_a", ISO, "A.8.8")
    assert {r.rule_id for r in result.rules} >= {
        "crl_vuln_critical_v1",
        "crl_vuln_high_v1",
    }


@pytest.mark.parametrize("control_id", ["A.5.1", "A.5.17", "A.7.4"])
def test_real_attestation_iso_controls(catalogue, control_id):
    service, _ = catalogue
    result = _one(service, "org_cat_a", ISO, control_id)
    assert result.state == MAPPING_ATTESTATION_REQUIRED
    assert all(r.is_attestation_placeholder for r in result.rules)


def test_a_real_partially_automated_control(catalogue):
    """CIS v8.1 11.1 carries automated rules and a manual placeholder."""
    service, _ = catalogue
    assert is_active("cfw_cis_v8_1"), "precondition: CIS v8.1 is active (Phase 4)"
    result = _one(service, "org_cat_a", CIS, "11.1")
    assert result.state == MAPPING_PARTIALLY_AUTOMATED
    sources = {r.is_attestation_placeholder for r in result.rules}
    assert sources == {True, False}


def test_a_real_control_in_a_parked_framework_is_unsupported(catalogue):
    """GDPR_3_2 has automated rules, but GDPR is parked here."""
    service, _ = catalogue
    assert not is_active("cfw_gdpr"), "precondition: GDPR is parked"
    result = _one(service, "org_cat_a", GDPR, "GDPR_3_2")
    assert result.state == MAPPING_UNSUPPORTED
    assert "parked" in result.reason
    assert result.framework.active_in_installation is False


@pytest.mark.parametrize(
    "code_version, control_id, reason_part",
    [
        (ISO, "A.9.99", "Control A.9.99 is not in"),
        (("ISO27001_2022", "2013"), "A.8.8", "catalogue has: 2022"),
        (("ORG_INTERNAL", "3"), "PWD-01", "Framework ORG_INTERNAL is not in"),
        (ISO, "a.8.8", "Control a.8.8 is not in"),  # D3: no guessing at spellings
    ],
)
def test_unknown_controls_are_reported_as_unknown(
    catalogue, code_version, control_id, reason_part
):
    service, _ = catalogue
    result = _one(service, "org_cat_a", code_version, control_id)
    assert result.state == MAPPING_UNKNOWN_CONTROL
    assert reason_part in result.reason
    assert result.rules == ()


def test_results_come_back_in_the_order_asked(catalogue):
    service, _ = catalogue
    keys = [
        ControlKey(
            framework_code="ORG_INTERNAL", framework_version="3", control_id="X"
        ),
        ControlKey(framework_code=ISO[0], framework_version=ISO[1], control_id="A.5.1"),
        ControlKey(framework_code=ISO[0], framework_version=ISO[1], control_id="A.8.8"),
    ]
    results = service.resolve_controls(org_id="org_cat_a", keys=keys)
    assert [r.key for r in results] == keys
    assert [r.state for r in results] == [
        MAPPING_UNKNOWN_CONTROL,
        MAPPING_ATTESTATION_REQUIRED,
        MAPPING_AUTOMATED,
    ]


def test_a_known_control_with_no_active_rule_is_unsupported(catalogue):
    """No such control ships, so one is added (and rolled back) with only an
    archived automated rule linked to it."""
    from db.models.compliance import (
        ComplianceControl,
        ComplianceRule,
        ComplianceRuleControl,
    )

    service, db = catalogue
    theme = (
        db.query(ComplianceControl.theme)
        .filter(ComplianceControl.framework_id == "cfw_iso27001_2022")
        .limit(1)
        .scalar()
    )
    db.add(
        ComplianceControl(
            id="cct_test_catalogue_ruleless",
            framework_id="cfw_iso27001_2022",
            control_number="A.99.1",
            theme=theme,
            title="Synthetic rule-less control",
            scannability="auto",  # a claim of automation the rules do not back
        )
    )
    db.add(
        ComplianceRule(
            id="crl_test_catalogue_archived",
            rule_family_code="RULE-TEST-ARCHIVED",
            version_number=1,
            check_type="service_status",
            evidence_source="offline_configuration",
            target_platform="any",
            check_definition={
                "key": "telnet_disabled",
                "expected": True,
                "operator": "equals",
            },
            severity="high",
            status="archived",
        )
    )
    db.flush()
    db.add(
        ComplianceRuleControl(
            rule_id="crl_test_catalogue_archived",
            control_id="cct_test_catalogue_ruleless",
        )
    )
    db.flush()

    result = _one(service, "org_cat_a", ISO, "A.99.1")
    assert result.state == MAPPING_UNSUPPORTED
    assert "no active rule" in result.reason
    assert result.rules == ()
    # The catalogue's own scannability claim is reported, never believed.
    assert result.scannability == "auto"


def test_another_tenants_private_framework_is_unknown(catalogue):
    from db.models.compliance import ComplianceFramework

    service, db = catalogue
    db.add(
        ComplianceFramework(
            id="cfw_test_private_to_a",
            tenant_id="org_cat_a",
            code="PRIVATE_A",
            name="Tenant A's own framework",
            version="1",
        )
    )
    db.flush()

    seen_by_a = _one(service, "org_cat_a", ("PRIVATE_A", "1"), "P-1")
    seen_by_b = _one(service, "org_cat_b", ("PRIVATE_A", "1"), "P-1")
    # A sees its framework (the control itself does not exist);
    # B is told the framework does not exist at all.
    assert seen_by_a.state == MAPPING_UNKNOWN_CONTROL
    assert seen_by_a.framework is not None
    assert seen_by_b.state == MAPPING_UNKNOWN_CONTROL
    assert seen_by_b.framework is None
    assert "Framework PRIVATE_A is not in" in seen_by_b.reason

    visible_to_b = {
        c.framework.code for c in service.framework_capabilities(org_id="org_cat_b")
    }
    assert "PRIVATE_A" not in visible_to_b


def test_installation_is_per_tenant(catalogue):
    from db.models.compliance import ComplianceTenantFramework

    service, db = catalogue
    db.add(
        ComplianceTenantFramework(
            id="ctf_test_catalogue_a_iso",
            tenant_id="org_cat_a",
            framework_id="cfw_iso27001_2022",
            is_enabled=True,
        )
    )
    db.flush()
    a = _one(service, "org_cat_a", ISO, "A.8.8")
    b = _one(service, "org_cat_b", ISO, "A.8.8")
    assert a.framework.installed_for_tenant is True
    assert b.framework.installed_for_tenant is False
    # Installation is reported beside the state, not folded into it.
    assert a.state == b.state == MAPPING_AUTOMATED


def test_capabilities_agree_with_per_control_resolution(catalogue):
    from db.models.compliance import ComplianceControl

    service, db = catalogue
    capabilities = service.framework_capabilities(org_id="org_cat_a")
    assert impurities(capabilities) == []
    iso = next(
        c for c in capabilities if c.framework.framework_id == "cfw_iso27001_2022"
    )

    assert iso.controls_total == (
        iso.controls_automated
        + iso.controls_partially_automated
        + iso.controls_attestation_required
        + iso.controls_unsupported
    )
    numbers = [
        n
        for (n,) in db.query(ComplianceControl.control_number)
        .filter(ComplianceControl.framework_id == "cfw_iso27001_2022")
        .all()
    ]
    assert iso.controls_total == len(numbers)
    states = [
        r.state
        for r in service.resolve_controls(
            org_id="org_cat_a",
            keys=[
                ControlKey(
                    framework_code=ISO[0], framework_version=ISO[1], control_id=n
                )
                for n in numbers
            ],
        )
    ]
    assert states.count(MAPPING_AUTOMATED) == iso.controls_automated
    assert states.count(MAPPING_PARTIALLY_AUTOMATED) == iso.controls_partially_automated
    assert (
        states.count(MAPPING_ATTESTATION_REQUIRED) == iso.controls_attestation_required
    )
    assert states.count(MAPPING_UNSUPPORTED) == iso.controls_unsupported
    assert MAPPING_UNKNOWN_CONTROL not in states


def test_a_parked_framework_counts_nothing_as_assessable(catalogue):
    service, _ = catalogue
    gdpr = next(
        c
        for c in service.framework_capabilities(org_id="org_cat_a")
        if c.framework.code == "GDPR"
    )
    assert gdpr.controls_total > 0
    assert gdpr.controls_unsupported == gdpr.controls_total
    assert gdpr.controls_automated == gdpr.controls_partially_automated == 0


def test_the_service_refuses_to_answer_without_a_tenant(catalogue):
    service, _ = catalogue
    with pytest.raises(ValueError, match="org_id is required"):
        service.resolve_controls(org_id="", keys=[])
    with pytest.raises(ValueError, match="org_id is required"):
        service.framework_capabilities(org_id="")


def test_query_count_does_not_grow_with_the_number_of_controls(catalogue):
    from sqlalchemy import event

    service, db = catalogue
    statements = []

    def count(*_args, **_kwargs):
        statements.append(1)

    engine = db.get_bind()
    event.listen(engine, "before_cursor_execute", count)
    try:
        few = [
            ControlKey(
                framework_code=ISO[0], framework_version=ISO[1], control_id="A.8.8"
            )
        ]
        service.resolve_controls(org_id="org_cat_a", keys=few)
        n_few = len(statements)
        statements.clear()
        many = [
            ControlKey(
                framework_code=ISO[0], framework_version=ISO[1], control_id=f"A.8.{i}"
            )
            for i in range(1, 35)
        ]
        service.resolve_controls(org_id="org_cat_a", keys=many)
        n_many = len(statements)
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert n_many == n_few <= 4

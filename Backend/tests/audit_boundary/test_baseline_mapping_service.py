"""
BaselineMappingService — Phase 5 step 5.3.

* ``parameter_handling`` and ``evaluate_scope_cidrs`` on their own: every
  outcome, including the honest empty-vocabulary case and a scope entry that
  only overlaps the authorised range.
* The service against the real catalogue: the Phase 4 example baseline mapped
  control by control, notes kept beside states, parameters, scope, tags and
  tenant scoping. Every row a test needs is flushed and rolled back.
"""

from __future__ import annotations

import ipaddress

import pytest

from ccure_audit.services.baseline_mapping import (
    PARAM_HONOURED,
    PARAM_INVALID_VALUE,
    PARAM_RECORDED_NOT_HONOURED,
    PARAM_UNKNOWN,
    PARAMETER_VOCABULARY,
    BaselineControlInput,
    BaselineInput,
    BaselineMappingService,
    BaselineParameterInput,
    BaselineScopeInput,
    ParameterDefinition,
    evaluate_scope_cidrs,
    parameter_handling,
)
from ccure_audit.services.compliance_catalogue import (
    MAPPING_ATTESTATION_REQUIRED,
    MAPPING_AUTOMATED,
    MAPPING_PARTIALLY_AUTOMATED,
    MAPPING_UNKNOWN_CONTROL,
    MAPPING_UNSUPPORTED,
    ControlKey,
)
from ccure_audit.services.views import impurities

ISO = ("ISO27001_2022", "2022")


def _nets(*cidrs):
    return [ipaddress.ip_network(c) for c in cidrs]


# ── parameter_handling ────────────────────────────────────────────────────────

LENGTH = ParameterDefinition(
    name="password_min_length",
    datatype="integer",
    unit="characters",
    description="Minimum password length.",
    honoured=False,
)
LENGTH_USED = ParameterDefinition(
    name="password_min_length",
    datatype="integer",
    unit="characters",
    description="Minimum password length.",
    honoured=True,
)


def test_audit_has_no_parameter_vocabulary_yet():
    """No rule takes a parameter until plan Phase 17; nothing may claim otherwise."""
    assert PARAMETER_VOCABULARY == ()


def test_with_no_vocabulary_every_parameter_is_unknown_and_recorded():
    handling, reason = parameter_handling(
        "password_min_length", 12, PARAMETER_VOCABULARY
    )
    assert handling == PARAM_UNKNOWN
    assert "no parameter vocabulary" in reason and "recorded" in reason


@pytest.mark.parametrize(
    "vocabulary, name, value, expected",
    [
        ([LENGTH], "password_min_length", 12, PARAM_RECORDED_NOT_HONOURED),
        ([LENGTH_USED], "password_min_length", 12, PARAM_HONOURED),
        ([LENGTH], "password_min_length", "12", PARAM_INVALID_VALUE),
        (
            [LENGTH],
            "password_min_length",
            True,
            PARAM_INVALID_VALUE,
        ),  # bool is not an int here
        ([LENGTH], "lockout_threshold", 5, PARAM_UNKNOWN),
    ],
)
def test_parameter_handling(vocabulary, name, value, expected):
    handling, reason = parameter_handling(name, value, vocabulary)
    assert handling == expected
    assert (reason is None) == (expected == PARAM_HONOURED)


# ── evaluate_scope_cidrs ──────────────────────────────────────────────────────


def test_scope_entries_must_lie_inside_the_authorised_scope():
    accepted, rejected = evaluate_scope_cidrs(
        [
            "192.0.2.0/25",
            "192.0.2.128/26",
            "192.0.2.0/23",
            "198.51.100.0/24",
            "garbage",
            "2001:db8::/64",
        ],
        _nets("192.0.2.0/24"),
    )
    assert accepted == ("192.0.2.0/25", "192.0.2.128/26")
    reasons = {r.entry: r.reason for r in rejected}
    assert "Outside" in reasons["192.0.2.0/23"]  # overlaps, but wider: would widen
    assert "Outside" in reasons["198.51.100.0/24"]
    assert "Not a valid CIDR" in reasons["garbage"]
    assert "Outside" in reasons["2001:db8::/64"]  # a v6 entry never fits a v4 scope


def test_an_unrestricted_scope_accepts_every_valid_entry():
    accepted, rejected = evaluate_scope_cidrs(["10.0.0.0/8", "bad"], None)
    assert accepted == ("10.0.0.0/8",)
    assert [r.entry for r in rejected] == ["bad"]


def test_a_deny_all_scope_rejects_everything():
    accepted, rejected = evaluate_scope_cidrs(["192.0.2.0/25"], [])
    assert accepted == ()
    assert "denies all scanning" in rejected[0].reason


def test_accepted_entries_are_canonical_and_deduplicated():
    accepted, _ = evaluate_scope_cidrs(
        ["192.0.2.5/25", "192.0.2.0/25"], _nets("192.0.2.0/24")
    )
    assert accepted == ("192.0.2.0/25",)


# ── The service ───────────────────────────────────────────────────────────────


def _control(req, code_version, control_id, *, applicable=True, parameters=()):
    return BaselineControlInput(
        requirement_id=req,
        control=ControlKey(
            framework_code=code_version[0],
            framework_version=code_version[1],
            control_id=control_id,
        ),
        applicable=applicable,
        parameters=tuple(parameters),
    )


#: The Phase 4 worked example, as the adapter will hand it over.
EXAMPLE = BaselineInput(
    baseline_id="pp-baseline-infosec-core",
    baseline_version=4,
    controls=(
        _control(
            "REQ-ACC-01",
            ISO,
            "A.5.17",
            parameters=[
                BaselineParameterInput(
                    name="password_min_length", value=12, unit="characters"
                )
            ],
        ),
        _control("REQ-VUL-01", ISO, "A.8.8"),
        _control("REQ-CFG-01", ISO, "A.8.9"),
        _control("REQ-GOV-01", ISO, "A.5.1"),
        _control("REQ-PHY-01", ISO, "A.7.4", applicable=False),
        _control("REQ-ORG-07", ("ORG_INTERNAL", "3"), "PWD-01"),
    ),
    scope=BaselineScopeInput(cidrs=("192.0.2.0/24", "198.51.100.0/24"), asset_tags=()),
)


@pytest.fixture
def tenant(db_session):
    """Two organisations; the first authorised to scan 192.0.2.0/24 only."""
    from db.models import Organization

    db_session.add(
        Organization(
            id="org_map_a",
            name="Mapping A",
            slug="org-map-a",
            scan_scope_cidrs=["192.0.2.0/24"],
        )
    )
    db_session.add(Organization(id="org_map_b", name="Mapping B", slug="org-map-b"))
    db_session.flush()
    try:
        yield BaselineMappingService(db_session), db_session
    finally:
        db_session.rollback()


def test_the_example_baseline_maps_control_by_control(tenant):
    service, _ = tenant
    coverage = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE)
    assert impurities(coverage) == [], impurities(coverage)

    states = {c.requirement_id: c.mapping.state for c in coverage.controls}
    assert states == {
        "REQ-ACC-01": MAPPING_ATTESTATION_REQUIRED,
        "REQ-VUL-01": MAPPING_AUTOMATED,
        "REQ-CFG-01": MAPPING_AUTOMATED,
        "REQ-GOV-01": MAPPING_ATTESTATION_REQUIRED,
        "REQ-PHY-01": MAPPING_ATTESTATION_REQUIRED,
        "REQ-ORG-07": MAPPING_UNKNOWN_CONTROL,
    }
    assert [c.requirement_id for c in coverage.controls] == [
        c.requirement_id for c in EXAMPLE.controls
    ]
    counts = coverage.counts
    assert (
        counts.controls_total,
        counts.automated,
        counts.attestation_required,
        counts.unknown_control,
    ) == (6, 2, 3, 1)
    assert counts.partially_automated == counts.unsupported == 0


def test_automated_controls_name_their_assessing_rules_and_nothing_else_does(tenant):
    service, _ = tenant
    coverage = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE)
    by_req = {c.requirement_id: c for c in coverage.controls}
    assert {r.rule_id for r in by_req["REQ-VUL-01"].assessing_rules} >= {
        "crl_vuln_critical_v1",
        "crl_vuln_high_v1",
    }
    assert all(
        not r.is_attestation_placeholder for r in by_req["REQ-CFG-01"].assessing_rules
    )
    for req in ("REQ-ACC-01", "REQ-GOV-01", "REQ-PHY-01", "REQ-ORG-07"):
        assert by_req[req].assessing_rules == ()


def test_a_partially_automated_control_names_only_its_automated_rules(tenant):
    service, _ = tenant
    baseline = BaselineInput(
        baseline_id="b",
        baseline_version=1,
        controls=(_control("R1", ("CIS_V8_1", "8.1"), "11.1"),),
        scope=None,
    )
    (control,) = service.map_baseline(org_id="org_map_a", baseline=baseline).controls
    assert control.mapping.state == MAPPING_PARTIALLY_AUTOMATED
    assert control.assessing_rules
    assert all(not r.is_attestation_placeholder for r in control.assessing_rules)
    assert len(control.assessing_rules) < len(control.mapping.rules)


def test_notes_are_kept_beside_the_state(tenant):
    service, _ = tenant
    coverage = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE)
    by_req = {c.requirement_id: c for c in coverage.controls}

    physical = by_req["REQ-PHY-01"]
    assert physical.applicable is False
    assert (
        physical.mapping.state == MAPPING_ATTESTATION_REQUIRED
    )  # capability unchanged
    assert any("not applicable" in n for n in physical.notes)

    vulnerability = by_req["REQ-VUL-01"]
    assert vulnerability.mapping.state == MAPPING_AUTOMATED  # not downgraded …
    assert any(
        "not installed for this tenant" in n for n in vulnerability.notes
    )  # … but said
    assert by_req["REQ-ORG-07"].notes == ()  # nothing to say about an unknown control


def test_installing_the_framework_removes_the_note(tenant):
    from db.models.compliance import ComplianceTenantFramework

    service, db = tenant
    db.add(
        ComplianceTenantFramework(
            id="ctf_test_mapping_a_iso",
            tenant_id="org_map_a",
            framework_id="cfw_iso27001_2022",
            is_enabled=True,
        )
    )
    db.flush()
    a = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE)
    b = service.map_baseline(org_id="org_map_b", baseline=EXAMPLE)
    note = "not installed for this tenant"
    assert not any(note in n for c in a.controls for n in c.notes)
    assert any(note in n for c in b.controls for n in c.notes)


def test_a_parked_framework_gets_no_installation_note(tenant):
    """Unsupported because parked: installing it would not change that."""
    service, _ = tenant
    baseline = BaselineInput(
        baseline_id="b",
        baseline_version=1,
        controls=(_control("R1", ("GDPR", "2016/679"), "GDPR_3_2"),),
        scope=None,
    )
    (control,) = service.map_baseline(org_id="org_map_a", baseline=baseline).controls
    assert control.mapping.state == MAPPING_UNSUPPORTED
    assert control.notes == ()


def test_parameters_are_recorded_never_ignored(tenant):
    service, _ = tenant
    coverage = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE)
    (param,) = coverage.parameters
    assert (param.requirement_id, param.name, param.handling) == (
        "REQ-ACC-01",
        "password_min_length",
        PARAM_UNKNOWN,
    )
    assert param.reason


def test_a_supplied_vocabulary_is_honoured_by_the_service(db_session, tenant):
    _, db = tenant
    service = BaselineMappingService(db, parameter_vocabulary=[LENGTH])
    (param,) = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE).parameters
    assert param.handling == PARAM_RECORDED_NOT_HONOURED


def test_scope_narrows_the_authorised_scope(tenant):
    service, _ = tenant
    scope = service.map_baseline(org_id="org_map_a", baseline=EXAMPLE).scope
    assert scope.requested and scope.org_scope_configured
    assert scope.accepted_cidrs == ("192.0.2.0/24",)
    assert [r.entry for r in scope.rejected_cidrs] == ["198.51.100.0/24"]
    assert scope.applied


def test_an_unconfigured_org_scope_is_reported_as_such(tenant, monkeypatch):
    from config import AppConfig

    service, _ = tenant
    monkeypatch.setattr(AppConfig, "REQUIRE_SCAN_SCOPE", False)
    scope = service.map_baseline(org_id="org_map_b", baseline=EXAMPLE).scope
    assert scope.org_scope_configured is False
    assert scope.accepted_cidrs == ("192.0.2.0/24", "198.51.100.0/24")

    # With REQUIRE_SCAN_SCOPE on, an unconfigured org scans nothing — the same
    # answer scan admission gives, because the same function decides it.
    monkeypatch.setattr(AppConfig, "REQUIRE_SCAN_SCOPE", True)
    scope = service.map_baseline(org_id="org_map_b", baseline=EXAMPLE).scope
    assert scope.accepted_cidrs == ()
    assert all("denies all" in r.reason for r in scope.rejected_cidrs)


def test_no_scope_means_nothing_was_requested(tenant):
    service, _ = tenant
    baseline = BaselineInput(
        baseline_id="b",
        baseline_version=1,
        controls=(_control("R1", ISO, "A.8.8"),),
        scope=None,
    )
    scope = service.map_baseline(org_id="org_map_a", baseline=baseline).scope
    assert not scope.requested and not scope.applied


def test_tags_that_match_no_asset_of_this_tenant_are_reported(tenant):
    from db.models.assets import Asset, AssetTag

    service, db = tenant
    db.add(
        Asset(id="ast_test_mapping_a_1", org_id="org_map_a", ip_address="192.0.2.10")
    )
    db.add(
        Asset(id="ast_test_mapping_b_1", org_id="org_map_b", ip_address="192.0.2.20")
    )
    db.flush()
    db.add(AssetTag(asset_id="ast_test_mapping_a_1", tag="finance"))
    db.add(
        AssetTag(asset_id="ast_test_mapping_b_1", tag="payroll")
    )  # another tenant's tag
    db.flush()
    baseline = BaselineInput(
        baseline_id="b",
        baseline_version=1,
        controls=(_control("R1", ISO, "A.8.8"),),
        scope=BaselineScopeInput(cidrs=(), asset_tags=("finance", "payroll", " ")),
    )
    scope = service.map_baseline(org_id="org_map_a", baseline=baseline).scope
    assert scope.asset_tags == ("finance", "payroll")
    assert scope.unmatched_tags == ("payroll",)  # B's asset does not count for A
    assert scope.applied


def test_the_service_needs_a_known_tenant_and_unique_requirements(tenant):
    service, _ = tenant
    with pytest.raises(ValueError, match="org_id is required"):
        service.map_baseline(org_id="", baseline=EXAMPLE)
    with pytest.raises(ValueError, match="unknown organisation"):
        service.map_baseline(org_id="org_does_not_exist", baseline=EXAMPLE)
    duplicate = BaselineInput(
        baseline_id="b",
        baseline_version=1,
        controls=(_control("R1", ISO, "A.8.8"), _control("R1", ISO, "A.8.9")),
        scope=None,
    )
    with pytest.raises(ValueError, match="duplicate requirement_id"):
        service.map_baseline(org_id="org_map_a", baseline=duplicate)


def test_mapping_writes_nothing(tenant):
    service, db = tenant
    before = {len(db.new), len(db.dirty), len(db.deleted)}
    service.map_baseline(org_id="org_map_a", baseline=EXAMPLE)
    assert {len(db.new), len(db.dirty), len(db.deleted)} == before == {0}


def test_query_count_does_not_grow_with_the_baseline(tenant):
    from sqlalchemy import event

    service, db = tenant
    statements = []

    def count(*_a, **_k):
        statements.append(1)

    def run(n):
        statements.clear()
        baseline = BaselineInput(
            baseline_id="b",
            baseline_version=1,
            controls=tuple(_control(f"R{i}", ISO, f"A.8.{i}") for i in range(1, n + 1)),
            scope=BaselineScopeInput(cidrs=("192.0.2.0/25",), asset_tags=("finance",)),
        )
        service.map_baseline(org_id="org_map_a", baseline=baseline)
        return len(statements)

    # The session's own connection, not the engine: the suite's TestClient runs
    # the app lifespan, whose background loops query the same engine from
    # another thread, and an engine-wide listener counted them intermittently.
    connection = db.connection()
    event.listen(connection, "before_cursor_execute", count)
    try:
        few, many = run(1), run(30)
    finally:
        event.remove(connection, "before_cursor_execute", count)
    assert 0 < few == many <= 6

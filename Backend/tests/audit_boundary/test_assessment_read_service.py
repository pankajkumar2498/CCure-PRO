"""
AssessmentReadService — Phase 5 step 5.4.

The export's read logic now lives in ``ccure_audit.services.assessment_read``.
These tests pin three things:

* the export resolves every moved name to the service — one implementation;
* the service's ``_text``/``_iso`` copies agree with the export's, which the
  walker's host and deduplication keys depend on;
* the views reproduce the export's compliance rows cell for cell, on the
  export's own fixture, and stay tenant-scoped and pure.

Byte-identity of the export itself was proven separately, against a restored
copy of the live database plus synthetic scans covering every walker path
(see the 5.4 commit message); the 88 export tests run unchanged.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from ccure_audit.services import assessment_read
from ccure_audit.services.assessment_read import AssessmentReadService
from ccure_audit.services.views import impurities
from reporting import exports

HOST = "10.20.30.41"
SCAN_START = datetime(2026, 9, 1, 10, 0, tzinfo=timezone.utc)
SCAN_END = SCAN_START + timedelta(minutes=10)
MAPPED_CHECK = "ccure.test.read.permit_root_login"


def _result(check_id, outcome, **kw):
    evidence = kw.pop("evidence", None)
    if evidence is None and outcome in ("pass", "fail"):
        evidence = [
            {
                "description": kw.get("title", check_id),
                "expected": "PermitRootLogin no",
                "observed": "yes",
                "raw": "CCURE::VALUE::yes",
            },
            {"raw": "CCURE::VALUE::yes"},  # a duplicate raw line: shown once
        ]
    return {
        "check_id": check_id,
        "outcome": outcome,
        "title": kw.get("title", f"Check {check_id}"),
        "severity": kw.get("severity", "high"),
        "target": HOST,
        "evidence": evidence or [],
        "remediation": "Set the directive and restart.",
        "references": ["https://example.invalid/doc", ""],
        "error": kw.get("error"),
        "metadata": kw.get(
            "metadata", {"domain": "host_configuration", "check_type": "config_file"}
        ),
    }


@pytest.fixture()
def world(db_session):
    """
    The same shape the export tests use: one organisation, one asset, one
    completed scan whose vulnerability-audit phase payload carries a
    configuration audit covering all five stored outcomes, and one installed
    benchmark control (with a profile) that one of the checks answers for.
    """
    from db.models.assets import Asset
    from db.models.compliance import (
        ComplianceControl,
        ComplianceFramework,
        ComplianceRule,
        ComplianceRuleControl,
        ComplianceTenantFramework,
    )
    from db.models.rbac import Organization
    from db.models.scans import Scan, ScanPhase

    suffix = uuid.uuid4().hex[:8]
    org_id = f"org_read_{suffix}"
    db_session.add(
        Organization(id=org_id, name=f"Read {suffix}", slug=f"read-{suffix}")
    )
    db_session.flush()
    asset_id = f"ast_{org_id}_10_20_30_41"
    db_session.add(Asset(id=asset_id, org_id=org_id, ip_address=HOST))
    scan = Scan(
        id=f"scn_read_{suffix}",
        org_id=org_id,
        scan_no=7,
        target_str=HOST,
        scan_type="credentialed",
        pipeline_mode="vulnerability_audit",
        status="complete",
        created_at=SCAN_START,
        started_at=SCAN_START,
        completed_at=SCAN_END,
        options={},
    )
    db_session.add(scan)
    db_session.flush()

    results = [
        _result(MAPPED_CHECK, "fail"),
        _result("ccure.test.read.protocol", "pass"),
        _result(
            "ccure.test.read.uac",
            "not_applicable",
            metadata={
                "domain": "host_configuration",
                "check_type": "registry",
                "not_applicable_reason": "check targets windows; this host is linux",
            },
        ),
        _result("ccure.test.read.audit_rules", "manual_review"),
        _result(
            "ccure.test.read.file_caps",
            "error",
            error="getcap is not installed, so nothing was established",
        ),
    ]
    db_session.add(
        ScanPhase(
            id=f"sph_{scan.id}_credentialed",
            scan_id=scan.id,
            phase_key="credentialed",
            phase_order=3,
            status="complete",
            started_at=SCAN_START,
            completed_at=SCAN_END,
            summary={
                "_phase_data": [
                    {
                        "ip_address": HOST,
                        "credentialed_report": {
                            "target": HOST,
                            "config_audit": {
                                "assessed": True,
                                "platform": "linux",
                                "results": results,
                            },
                        },
                    }
                ]
            },
        )
    )

    framework_id = f"cfw_bm_read_{suffix}"
    db_session.add(
        ComplianceFramework(
            id=framework_id,
            code=f"BM_READ_{suffix.upper()}",
            name="Read baseline (test)",
            version="1.0",
        )
    )
    db_session.flush()
    control_id = f"cct_{framework_id}_5_2_8"
    db_session.add(
        ComplianceControl(
            id=control_id,
            framework_id=framework_id,
            control_number="5.2.8",
            theme="BENCHMARK",
            title="Ensure SSH root login is disabled",
            scannability="auto",
            tags=[],
            profiles=["L1"],
        )
    )
    db_session.add(
        ComplianceRule(
            id=MAPPED_CHECK,
            rule_family_code=f"fam_{suffix}",
            version_number=1,
            check_type="config_file",
            target_platform="linux",
            check_definition={"config_check": True},
            severity="high",
            status="active",
            tags=[],
        )
    )
    db_session.flush()
    db_session.add(ComplianceRuleControl(rule_id=MAPPED_CHECK, control_id=control_id))
    db_session.add(
        ComplianceTenantFramework(
            id=f"ctf_read_{suffix}",
            tenant_id=org_id,
            framework_id=framework_id,
            is_enabled=True,
        )
    )
    db_session.flush()
    db_session.refresh(scan)
    try:
        yield {"org_id": org_id, "asset_id": asset_id, "scan": scan}
    finally:
        db_session.rollback()


MOVED = (
    "_HostAudit",
    "_collect_host_audits",
    "_dedupe_host_audits",
    "_scan_host_audits",
    "_asset_ids_for_hosts",
    "control_map_for_checks",
    "ControlRef",
    "organisation_name",
    "policy_framework_ids",
)


@pytest.mark.parametrize("name", MOVED)
def test_the_export_uses_the_service_implementation(name):
    assert getattr(exports, name).__module__ == "ccure_audit.services.assessment_read"


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "10.0.0.1",
        True,
        False,
        0,
        3.5,
        ["a", "", None, "b"],
        ("x",),
        {"k": "v"},
        datetime(2026, 9, 26, 10, 0),
        datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc),
    ],
)
def test_the_services_text_rendering_matches_the_exports(value):
    assert assessment_read._text(value) == exports._text(value)
    assert assessment_read._iso(value) == exports._iso(value)


def test_views_reproduce_the_export_rows_cell_for_cell(db_session, world):
    scan = world["scan"]
    view = AssessmentReadService(db_session).verdicts(
        org_id=world["org_id"], scan_id=scan.id
    )
    assert impurities(view) == [], impurities(view)

    rows = exports.compliance_verdict_rows(db_session, scan)
    col = {name: i for i, name in enumerate(exports.CONFIG_VERDICT_COLUMNS)}

    expected = []
    for host in view.hosts:
        for result in host.results:
            for control in result.controls or (None,):
                expected.append(
                    {
                        "Asset ID": host.asset_id or "",
                        "Host": host.host or result.target,
                        "Platform": host.platform,
                        "Framework ID": control.framework_id if control else "",
                        "Framework Name": control.framework_name if control else "",
                        "Control ID": control.control_id if control else "",
                        "Control Title": control.control_title if control else "",
                        "Check ID": result.check_id,
                        "Check Type": result.check_type,
                        "Check Domain": result.domain,
                        "Title": result.title,
                        "Description": result.description,
                        "Verdict": exports._verdict_label(result.outcome),
                        "Severity": result.severity,
                        "Expected": result.expected,
                        "Observed": result.observed,
                        "Evidence": "\n".join(result.evidence_lines),
                        "Applicability": result.not_applicable_reason,
                        "Error": result.error,
                        "Remediation": result.remediation,
                        "References": result.references,
                    }
                )
    actual = [{name: row[col[name]] for name in expected[0]} for row in rows]
    assert actual == expected
    # The fixture exercises a mapped check: the crosswalk reached a control.
    assert any(r["Control ID"] for r in actual)


def test_every_stored_outcome_is_carried_untranslated(db_session, world):
    view = AssessmentReadService(db_session).verdicts(
        org_id=world["org_id"], scan_id=world["scan"].id
    )
    (host,) = view.hosts
    assert host.assessed and host.host == HOST and host.asset_id == world["asset_id"]
    assert sorted(r.outcome for r in host.results) == [
        "error",
        "fail",
        "manual_review",
        "not_applicable",
        "pass",
    ]
    errored = next(r for r in host.results if r.outcome == "error")
    assert "getcap is not installed" in errored.error


def test_an_unassessed_host_carries_the_engines_reason_and_no_results(
    db_session, world
):
    from sqlalchemy.orm.attributes import flag_modified

    scan = world["scan"]
    phase = scan.phases[0]
    summary = dict(phase.summary)
    summary["_phase_data"] = [
        {
            "ip_address": HOST,
            "credentialed_report": {
                "target": HOST,
                "config_audit": {
                    "assessed": False,
                    "reason": "Authentication was rejected; the audit did not run.",
                    "results": [],
                },
            },
        }
    ]
    phase.summary = summary
    flag_modified(phase, "summary")
    db_session.flush()

    view = AssessmentReadService(db_session).verdicts(
        org_id=world["org_id"], scan_id=scan.id
    )
    (host,) = view.hosts
    assert host.assessed is False
    assert "Authentication was rejected" in host.reason
    assert host.results == ()


def test_another_tenants_assessment_is_not_found(db_session, world):
    service = AssessmentReadService(db_session)
    with pytest.raises(LookupError, match="for this tenant"):
        service.verdicts(org_id="org_somebody_else", scan_id=world["scan"].id)
    with pytest.raises(ValueError, match="org_id is required"):
        service.verdicts(org_id="", scan_id=world["scan"].id)


def test_reading_writes_nothing(db_session, world):
    AssessmentReadService(db_session).verdicts(
        org_id=world["org_id"], scan_id=world["scan"].id
    )
    assert not db_session.new and not db_session.dirty and not db_session.deleted


def test_a_control_ref_carries_the_published_identifiers(db_session, world):
    view = AssessmentReadService(db_session).verdicts(
        org_id=world["org_id"], scan_id=world["scan"].id
    )
    (host,) = view.hosts
    mapped = next(r for r in host.results if r.check_id == MAPPED_CHECK)
    (ref,) = mapped.controls
    assert ref.framework_code.startswith("BM_READ_")
    assert ref.framework_version == "1.0"
    assert ref.control_number == "5.2.8"
    # The internal row id is unchanged — it is what the export prints.
    assert ref.control_id.startswith("cct_cfw_bm_read_")


def test_the_view_maps_to_contract_control_results(db_session, world):
    """Service → view → Phase 5.6 mapper, on real rows."""
    from ccure_audit.integration.mappers.control_results import control_results

    view = AssessmentReadService(db_session).verdicts(
        org_id=world["org_id"], scan_id=world["scan"].id
    )
    (result,) = control_results(view)
    assert result.control.control_id == "5.2.8"
    assert result.control.framework.version == "1.0"
    assert result.state.value == "FAIL"
    assert result.asset_counts.fail == 1
    assert [r.rule_id for r in result.rules] == [MAPPED_CHECK]

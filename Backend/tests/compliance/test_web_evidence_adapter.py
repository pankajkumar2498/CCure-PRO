"""
Compliance web-application evidence — Phase 1, finding F3.

`_adapt_web_vulnerability_audit` is handed a network `Asset.id` (`ast_…`) and
filtered `WebFinding.web_asset_id` with it, which holds web-scan asset ids
(`was_…`). The query could never match, so every web rule read "0 critical
findings, no SQL injection" and a rule expecting `sqli_detected == False` passed
on every host — whether or not a web scan had ever run against it.

The adapter now links a network asset to the latest completed web scan in the
same organisation whose target host is the asset's IP or hostname, and answers
"not assessed" when there is none.
"""

import uuid

import pytest

from core.compliance_evidence import ComplianceEvidenceProvider
from db.base import gen_asset_id, utcnow
from db.models.assets import Asset
from db.models.rbac import Organization
from db.models.web_scans import WebFinding, WebScan

_PREFIX = "wsc_f3_"
adapt = ComplianceEvidenceProvider._adapt_web_vulnerability_audit


@pytest.fixture
def rows(db_session):
    made = {"assets": [], "scans": []}
    yield made
    db_session.rollback()
    db_session.query(WebFinding).filter(
        WebFinding.web_scan_id.like(f"{_PREFIX}%")
    ).delete(synchronize_session=False)
    db_session.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
        synchronize_session=False
    )
    if made["assets"]:
        db_session.query(Asset).filter(Asset.id.in_(made["assets"])).delete(
            synchronize_session=False
        )
    db_session.commit()


def _asset(db, org, rows, ip, hostname=None) -> Asset:
    asset = Asset(
        id=gen_asset_id(org.slug, ip),
        org_id=org.id,
        ip_address=ip,
        hostname=hostname,
    )
    db.add(asset)
    db.commit()
    rows["assets"].append(asset.id)
    return asset


def _web_scan(db, org_id, target_domain, status="complete") -> WebScan:
    scan = WebScan(
        id=f"{_PREFIX}{uuid.uuid4().hex[:12]}",
        org_id=org_id,
        target_url=f"http://{target_domain}/",
        target_domain=target_domain,
        authorization_confirmed=True,
        scan_name="f3",
        status=status,
        created_at=utcnow(),
        started_at=utcnow(),
        completed_at=utcnow(),
    )
    db.add(scan)
    db.commit()
    return scan


def _finding(db, scan, finding_type, severity, status="open") -> None:
    db.add(
        WebFinding(
            id=f"{scan.id}_{uuid.uuid4().hex[:6]}",
            web_scan_id=scan.id,
            org_id=scan.org_id,
            finding_type=finding_type,
            title=finding_type,
            severity=severity,
            status=status,
        )
    )
    db.commit()


def _other_org(db) -> Organization:
    uid = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_{uid}",
        name=f"F3 Other {uid}",
        slug=f"f3-other-{uid}",
        max_assets=10,
        max_users=10,
        is_active=True,
    )
    db.add(org)
    db.commit()
    return org


def test_a_host_no_web_scan_ran_against_is_not_assessed(db_session, test_org, rows):
    asset = _asset(db_session, test_org, rows, "10.91.0.5")

    evidence = adapt(db_session, asset.id)

    assert evidence["_evidence_available"] is False
    assert "No completed web application scan" in evidence["_reason"]
    # The defect: these used to come back as False / 0, which reads as clean.
    assert "sqli_detected" not in evidence
    assert "critical_web_vuln_count" not in evidence


def test_findings_of_a_completed_scan_of_the_host_are_evidence(
    db_session, test_org, rows
):
    asset = _asset(db_session, test_org, rows, "10.91.0.6")
    scan = _web_scan(db_session, test_org.id, "10.91.0.6:8080")
    _finding(db_session, scan, "sqli", "critical")
    _finding(db_session, scan, "xss", "high", status="confirmed")
    _finding(db_session, scan, "tls_issue", "high", status="false_positive")

    evidence = adapt(db_session, asset.id)

    assert evidence.get("_evidence_available") is not False
    assert evidence["sqli_detected"] is True
    assert evidence["xss_detected"] is True
    assert evidence["tls_issue_detected"] is False  # false positive excluded
    assert evidence["critical_web_vuln_count"] == 1
    assert evidence["high_web_vuln_count"] == 1


def test_a_completed_scan_that_found_nothing_is_a_real_clean_result(
    db_session, test_org, rows
):
    asset = _asset(db_session, test_org, rows, "10.91.0.7", hostname="App.Example.Test")
    _web_scan(db_session, test_org.id, "app.example.test")

    evidence = adapt(db_session, asset.id)

    assert evidence.get("_evidence_available") is not False
    assert evidence["sqli_detected"] is False
    assert evidence["critical_web_vuln_count"] == 0


def test_only_completed_scans_count(db_session, test_org, rows):
    asset = _asset(db_session, test_org, rows, "10.91.0.8")
    failed = _web_scan(db_session, test_org.id, "10.91.0.8", status="failed")
    _finding(db_session, failed, "sqli", "critical")

    assert adapt(db_session, asset.id)["_evidence_available"] is False


def test_another_organisations_web_scan_is_never_evidence(db_session, test_org, rows):
    asset = _asset(db_session, test_org, rows, "10.91.0.9")
    foreign = _web_scan(db_session, _other_org(db_session).id, "10.91.0.9")
    _finding(db_session, foreign, "sqli", "critical")

    assert adapt(db_session, asset.id)["_evidence_available"] is False

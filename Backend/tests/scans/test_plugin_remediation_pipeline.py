"""Execution/evidence survive the existing DB, scan API and report boundaries."""

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from auth.jwt_handler import create_access_token
from core.checks.plugin_outcomes import (
    coverage_summary,
    outcome_for_result,
    result_with_outcome,
)
from db.models.assets import Asset
from db.models.findings import AssetVulnerability
from db.models.rbac import Organization
from db.models.scans import Scan, ScanPhase
from engines.vulnerability.network_checks import network_finding
from engines.vulnerability.vulnerability_engine import VulnerabilityEngine
from native_rbac import create_user, fixture_role, grant_permissions
from reporting.exports import export_payload, scan_context_rows
from reporting.pdf_generator import ScanReportGenerator
from scans.db_helpers import _phase_summary_payload

IP = "192.0.2.15"


@pytest.fixture()
def pipeline(db_session, monkeypatch):
    from scans import asset_syncer

    monkeypatch.setattr(asset_syncer, "_enrich_findings_with_intel", lambda hosts: None)
    suffix = uuid.uuid4().hex[:8]
    org = Organization(
        id=f"org_pr_{suffix}", name="Plugin remediation", slug=f"pr-{suffix}"
    )
    role = fixture_role(db_session, f"pr_reader_{suffix}")
    db_session.add_all([org, role])
    db_session.flush()
    grant_permissions(
        db_session,
        role,
        "audit.scan.read",
        "audit.scan.read_all",
        "audit.report.read",
        "audit.finding.read",
        "audit.scan.run",
    )
    user = create_user(
        db_session,
        username=f"pr-{suffix}",
        email=f"pr-{suffix}@test.com",
        password_hash="hash",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.add(
        Asset(id=f"ast_pr_{suffix}", org_id=org.id, ip_address=IP, custom_attributes={})
    )
    db_session.commit()

    def store(host):
        scan = Scan(
            id=f"scn_pr_{uuid.uuid4().hex[:8]}",
            org_id=org.id,
            created_by=user.id,
            target_str=IP,
            pipeline_mode="vulnerability_audit",
            status="complete",
        )
        db_session.add(scan)
        db_session.commit()
        # The normal pipeline records these services in phase two.
        for endpoint in host.get("open_ports") or []:
            asset_syncer._upsert_network_service(
                db_session, f"ast_pr_{suffix}", scan.id, endpoint
            )
        db_session.commit()
        asset_syncer.sync_vulnerability_audit(
            db_session, scan.id, org.id, user.id, [host]
        )
        coverage = coverage_summary([host])
        db_session.add(
            ScanPhase(
                id=f"sph_pr_{uuid.uuid4().hex[:8]}",
                scan_id=scan.id,
                phase_key="vulnerability_assessment",
                phase_order=3,
                status="complete",
                summary=_phase_summary_payload(
                    {"network_plugin_coverage": coverage}, [host]
                ),
            )
        )
        db_session.commit()
        return scan

    token = create_access_token(user.id, user.username, org_id=org.id)
    return store, {"Authorization": f"Bearer {token}"}, org


def host_with_outcome(result):
    from orchestrator.scan_orchestrator import ScanOrchestrator

    host = {
        "ip_address": IP,
        "hostname": "fixture",
        "is_active": True,
        "open_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
        "cves": result.get("cves", []),
        "plugin_outcomes": [outcome_for_result("tls_scanner", result)],
    }
    host["plugin_coverage"] = coverage_summary([host])
    orchestrator = ScanOrchestrator.__new__(ScanOrchestrator)
    formatted = orchestrator._format_host(IP, host).to_phase3_dict()
    # The established phase-three format omits the redundant port inventory.
    return {**formatted, "open_ports": host["open_ports"]}


def test_d09_failed_outcome_survives_persistence_scan_api_and_exports(
    pipeline, db_session, client, tmp_path, monkeypatch
):
    store, headers, _ = pipeline
    host = host_with_outcome(
        result_with_outcome(status="timed_out", detail="TLS fixture timed out")
    )
    scan = store(host)
    response = client.get(f"/scans/{scan.id}", headers=headers)
    assert response.status_code == 200, response.text
    detail = response.json()
    outcome = detail["results"]["phase3"]["data"][0]["plugin_outcomes"][0]
    assert outcome["status"] == "timed_out"
    assert detail["summary"]["network_plugin_coverage"]["complete"] is False
    payload = export_payload(db_session, scan, datasets=("hosts",))
    coverage = payload["scan"]["network_plugin_coverage"]
    assert coverage["counts"]["timed_out"] == 1
    assert any("timed_out" in row[1] for row in scan_context_rows(payload["scan"]))
    generator = ScanReportGenerator(str(tmp_path))
    doc = MagicMock()
    monkeypatch.setattr(generator, "_doc", lambda *a: doc)
    result = {"data": [host], "summary": {"network_plugin_coverage": coverage}}
    for generate in (
        generator.generate_executive_pdf,
        generator.generate_technical_pdf,
    ):
        generate(result, "vulnerability_audit")
        story = doc.build.call_args.args[0]
        text = " ".join(f.getPlainText() for f in story if hasattr(f, "getPlainText"))
        # The technical report carries the coverage in its methodology table.
        tables = " ".join(str(getattr(f, "_cellvalues", "")) for f in story)
        assert "timed_out" in text + tables
        assert "Incomplete" in text + tables or "incomplete" in text + tables


@pytest.mark.parametrize("status", ["failed", "timed_out", "unsupported", "skipped"])
def test_d09_incomplete_scan_does_not_retire_existing_findings(
    pipeline, db_session, status
):
    store, _, org = pipeline
    finding = network_finding(
        "tls.certificate_expired",
        "Fixture expired certificate",
        target=f"{IP}:443",
        port=443,
    )
    store(host_with_outcome(result_with_outcome({"cves": [finding]})))
    store(host_with_outcome(result_with_outcome(status=status)))
    row = (
        db_session.query(AssetVulnerability)
        .filter(AssetVulnerability.org_id == org.id)
        .one()
    )
    assert row.status == "open"
    assert row.fixed_at is None


def test_d09_completed_negative_can_retire_previous_finding(pipeline, db_session):
    store, _, org = pipeline
    finding = network_finding(
        "tls.certificate_expired",
        "Fixture expired certificate",
        target=f"{IP}:443",
        port=443,
    )
    store(host_with_outcome(result_with_outcome({"cves": [finding]})))
    store(host_with_outcome(result_with_outcome()))
    row = (
        db_session.query(AssetVulnerability)
        .filter(AssetVulnerability.org_id == org.id)
        .one()
    )
    assert row.status == "fixed"


def test_d13_invalid_scope_is_rejected_by_api_before_dispatch(
    pipeline, client, monkeypatch
):
    _, headers, _ = pipeline
    from routers import phase_scans

    task = MagicMock()
    monkeypatch.setattr(phase_scans.run_host_discovery_task, "delay", task)
    response = client.post(
        "/scan/host-discovery",
        headers=headers,
        json={
            "targets": [IP],
            "options": {
                "credentials": [{"credential_id": "fixture", "targets": ["invalid"]}]
            },
        },
    )
    assert response.status_code == 422, response.text
    task.assert_not_called()


def test_d10_endpoint_evidence_survives_verification_db_api_and_export(
    pipeline, db_session, client
):
    store, headers, org = pipeline
    records = [
        network_finding(
            "tls.certificate_expired",
            f"fixture-certificate-{port} " + "proof " * 400,
            target=f"{IP}:{port}",
            port=port,
        )
        for port in (443, 8443)
    ]
    host = {
        "ip_address": IP,
        "is_active": True,
        "hostname": "fixture",
        "open_ports": [
            {"port": port, "protocol": "tcp", "service": "https"}
            for port in (443, 8443)
        ],
        "cves": records,
    }
    VulnerabilityEngine._verify_host(host)
    assert len(host["cves"]) == 1
    observations = host["cves"][0]["endpoint_observations"]
    assert {o["port"] for o in observations} == {443, 8443}
    scan = store(host)
    row = (
        db_session.query(AssetVulnerability)
        .filter(AssetVulnerability.org_id == org.id)
        .one()
    )
    assert (
        "fixture-certificate-443" in row.evidence
        and "fixture-certificate-8443" in row.evidence
    )
    from db.models.findings import Service

    service = db_session.query(Service).filter(Service.id == row.service_id).one()
    assert service.port in {443, 8443}
    detail = client.get(f"/findings/{row.id}", headers=headers)
    assert detail.status_code == 200, detail.text
    assert "fixture-certificate-8443" in detail.json()["evidence"]
    phase = client.get(f"/scans/{scan.id}", headers=headers).json()["results"]["phase3"]
    assert {
        o["port"] for o in phase["data"][0]["cves"][0]["endpoint_observations"]
    } == {443, 8443}
    payload = export_payload(db_session, scan, datasets=("findings",))
    dataset = payload["datasets"]["findings"]
    index = dataset["columns"].index("Evidence")
    assert "fixture-certificate-443" in dataset["rows"][0][index]
    assert "fixture-certificate-8443" in dataset["rows"][0][index]

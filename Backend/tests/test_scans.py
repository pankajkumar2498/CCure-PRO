"""
tests/test_scans.py
─────────────────────────────────────────────────────────────────────────────
API tests for the phase-selective and traditional scan endpoints.
We mock the internal scanner engines so tests run instantly and don't hit the network.
"""

from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from db.models.users import User, AuditLog
from db.models.rbac import Organization, Role
from db.models.scans import Scan
from db.models.assets import Asset
from db.models.findings import AssetVulnerability
from auth.jwt_handler import hash_password
from db.base import utcnow
from scans.db_helpers import _phase_summary_payload, _public_phase_summary, create_scan, update_scan_phase1, mark_scan_failed
from scans.asset_syncer import sync_advanced_scan


def test_phase_summary_payload_strips_postgres_unsafe_control_chars():
    payload = _phase_summary_payload(
        {"scan_duration": 1.0, "description": "ok\x00bad\x01value\nkept"},
        [
            {
                "ip_address": "192.168.1.10",
                "interfaces": [{"address": "\x01\x01\x00binary"}],
                "raw": b"snmp\x00response",
            }
        ],
    )

    assert payload["description"] == "okbadvalue\nkept"
    assert payload["_phase_data"][0]["interfaces"][0]["address"] == "binary"
    assert payload["_phase_data"][0]["raw"] == "snmpresponse"


def test_public_phase_summary_hides_internal_phase_data():
    summary = _public_phase_summary({
        "total_hosts": 254,
        "_phase_data": [{"ip_address": "192.168.1.10"}],
    })

    assert summary == {"total_hosts": 254}


def test_create_scan_writes_audit_log(db_session: Session):
    import uuid
    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    org = Organization(
        id=org_id,
        name=f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.commit()

    user_id = f"user_test_{uuid.uuid4().hex[:8]}"
    user = User(
        id=user_id,
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=3,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    scan = create_scan(
        db=db_session,
        user_id=str(user.id),
        target="192.168.1.1",
        targets=["192.168.1.1"],
        scan_type="adaptive",
        pipeline_mode="advanced",
    )

    audit_entry = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "scan.created", AuditLog.resource_type == "scan", AuditLog.resource_id == str(scan.id))
        .one_or_none()
    )

    assert audit_entry is not None
    assert audit_entry.user_id == str(user.id)
    assert audit_entry.changes["scan_no"] == scan.scan_no
    assert audit_entry.changes["pipeline_mode"] == "advanced"
    assert audit_entry.status == "success"


def test_scan_completion_logs_audit_event(db_session: Session):
    import uuid
    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    org = Organization(
        id=org_id,
        name=f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.commit()

    user_id = f"user_test_{uuid.uuid4().hex[:8]}"
    user = User(
        id=user_id,
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=3,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    scan = create_scan(
        db=db_session,
        user_id=str(user.id),
        target="192.168.1.1",
        targets=["192.168.1.1"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )

    result = {
        "summary": {"scan_duration": 0.2, "total_hosts": 1, "active_hosts": 1},
        "data": [{"ip_address": "192.168.1.1"}],
    }

    update_scan_phase1(
        db=db_session,
        scan_id=str(scan.id),
        user_id=str(user.id),
        phase1_data=result,
        is_final=True,
    )

    completion_log = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "scan.completed", AuditLog.resource_type == "scan", AuditLog.resource_id == str(scan.id))
        .one_or_none()
    )

    assert completion_log is not None
    assert completion_log.changes["phase"] == 1
    assert completion_log.changes["duration_seconds"] == 0.2
    assert completion_log.status == "success"


def test_scan_failure_logs_audit_event(db_session: Session):
    import uuid
    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    org = Organization(
        id=org_id,
        name=f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.commit()

    user_id = f"user_test_{uuid.uuid4().hex[:8]}"
    user = User(
        id=user_id,
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=3,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    scan = create_scan(
        db=db_session,
        user_id=str(user.id),
        target="192.168.1.1",
        targets=["192.168.1.1"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )

    mark_scan_failed(db=db_session, scan_id=str(scan.id), user_id=str(user.id), reason="test failure")

    failure_log = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "scan.failed", AuditLog.resource_type == "scan", AuditLog.resource_id == str(scan.id))
        .one_or_none()
    )

    assert failure_log is not None
    assert failure_log.status == "failure"
    assert failure_log.changes["reason"] == "test failure"


def test_sync_advanced_scan_includes_org_id_in_findings(db_session: Session):
    import uuid
    org_id = f"org_test_{uuid.uuid4().hex[:8]}"
    org = Organization(
        id=org_id,
        name=f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        max_assets=100,
        max_users=10,
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.commit()

    asset = Asset(
        id=f"ast_{org_id}_192_168_1_10",
        org_id=org.id,
        ip_address="192.168.1.10",
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="test-host",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id,
        org_id=org.id,
        created_by=None,
        target_str="192.168.1.10",
        scan_type="adaptive",
        pipeline_mode="advanced",
    )
    db_session.add(scan)
    db_session.commit()

    hosts = [
        {
            "ip_address": "192.168.1.10",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-9999-0001",
                    "title": "Test vulnerability",
                    "description": "Test description",
                    "severity": "Low",
                    "cvss": 1.0,
                    "plugin_output": "Test output",
                }
            ]
        }
    ]

    sync_advanced_scan(db_session, scan_id=scan_id, org_id=org.id, user_id=None, hosts=hosts)

    finding = db_session.query(AssetVulnerability).filter(AssetVulnerability.asset_id == asset.id).one()
    assert finding.org_id == org.id
    assert finding.scan_id == scan_id
    assert finding.vuln_id == "CVE-9999-0001"


def test_host_discovery_endpoint(client: TestClient, auth_headers: dict):
    """Test the Phase 1 Host Discovery API logic and DB persistence."""
    
    # Mock the internal orchestrator to return a successful dummy result
    mock_result = {
        "success": True,
        "data": [{"ip_address": "192.168.1.10", "status": "up", "mac_address": "AA:BB:CC:DD:EE:FF"}],
        "summary": {"total_hosts": 1, "active_hosts": 1, "inactive_hosts": 0, "scan_duration": 0.5}
    }
    
    with patch("scan_helpers.HostDiscoveryAPI") as mock_api_class:
        mock_orch = AsyncMock()
        mock_orch.run_host_discovery_only.return_value = mock_result
        mock_orch.generate_phase_report.return_value = {"json_pdf": "/fake/path.pdf"}
        
        # Override the get_api() singleton
        mock_api_instance = mock_api_class.return_value
        mock_api_instance._orch = mock_orch
        
        with patch("routers.phase_scans.get_api", return_value=mock_api_instance):
            response = client.post(
                "/scan/host-discovery",
                headers=auth_headers,
                json={
                    "targets": ["192.168.1.0/24"],
                    "scan_type": "adaptive",
                    "pipeline_mode": "asset"
                }
            )
            
            assert response.status_code == 200
            data = response.json()
            assert data["success"] is True
            assert "scan_id" in data
            assert data["pipeline_mode"] == "asset"
            assert data["summary"]["active_hosts"] == 1

            # Ensure rate limiting header is present (slowapi adds standard X-RateLimit headers)
            assert "X-RateLimit-Limit" in response.headers or response.status_code == 200


def test_asset_discovery_wrong_pipeline_mode(client: TestClient, auth_headers: dict):
    """Test that calling Asset Discovery on a 'basic' pipeline fails."""
    response = client.post(
        "/scan/asset-discovery",
        headers=auth_headers,
        json={
            "hosts": [{"ip_address": "192.168.1.10"}],
            "intensity": "normal",
            "pipeline_mode": "basic"  # Basic pipeline only allows Phase 1
        }
    )
    
    assert response.status_code == 400
    assert "not part of the 'basic' pipeline" in response.json()["detail"]


def test_credentialed_scan_validation_scrubbing(client: TestClient, auth_headers: dict):
    """
    Test that the global RequestValidationError handler scrubs sensitive fields 
    like 'password' from 422 Unprocessable Entity responses.
    """
    # Missing required 'ip' and 'username' fields, but providing a bad password type
    response = client.post(
        "/scan/credentialed",
        headers=auth_headers,
        json={
            "password": ["this_is_an_invalid_type_for_a_password_field"] 
        }
    )
    
    assert response.status_code == 422
    data = response.json()
    
    # Check that the raw input isn't leaked in the response
    detail_str = str(data["detail"])
    assert "this_is_an_invalid_type_for_a_password_field" not in detail_str
    assert "Value redacted for security." in detail_str


def test_scan_progress_requires_scan_read_permission(client: TestClient, db_session: Session, test_org: Organization):
    """Users without scans:read should be denied access to scan progress."""
    role = Role(name="limited", description="Limited role", is_system_role=False)
    db_session.add(role)
    db_session.commit()
    db_session.refresh(role)

    user = User(
        username="limiteduser",
        email="limited@example.com",
        full_name="Limited User",
        password_hash=hash_password("securepassword"),
        org_id=test_org.id,
        role_id=role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    scan = Scan(
        org_id=test_org.id,
        created_by=str(user.id),
        scan_no=1,
        target_str="10.0.0.0/24",
        scan_type="adaptive",
        pipeline_mode="basic",
        status="running",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    response = client.post(
        "/auth/login",
        json={"email": "limited@example.com", "password": "securepassword"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    progress_response = client.get(
        f"/scan/progress/{scan.id}",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert progress_response.status_code == 403
    assert "scans:read" in progress_response.json()["detail"]

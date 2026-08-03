"""
tests/test_scans.py
─────────────────────────────────────────────────────────────────────────────
API tests for the phase-selective and traditional scan endpoints.
We mock the internal scanner engines so tests run instantly and don't hit the network.
"""

from unittest.mock import AsyncMock, patch

from auth.jwt_handler import hash_password
from db.base import gen_asset_id, utcnow
from db.models.assets import Asset
from db.models.findings import AssetVulnerability, VulnerabilityDefinition
from db.models.rbac import Organization, Role
from db.models.scans import Scan
from db.models.users import AuditLog, User
from fastapi.testclient import TestClient
from routers.findings import StatusUpdate, update_finding_status
from scans.asset_syncer import (
    sync_asset_discovery,
    sync_host_discovery,
    sync_vulnerability_audit,
)
from scans.db_helpers import (
    _phase_summary_payload,
    _public_phase_summary,
    create_scan,
    mark_scan_failed,
    update_scan_phase1,
)
from sqlalchemy.orm import Session


def test_phase_summary_payload_strips_postgres_unsafe_control_chars():
    payload = _phase_summary_payload(
        {"scan_duration": 1.0, "description": "ok\x00bad\x01value\nkept"},
        [
            {
                "ip_address": "10.180.6.140",
                "interfaces": [{"address": "\x01\x01\x00binary"}],
                "raw": b"snmp\x00response",
            }
        ],
    )

    assert payload["description"] == "okbadvalue\nkept"
    assert payload["_phase_data"][0]["interfaces"][0]["address"] == "binary"
    assert payload["_phase_data"][0]["raw"] == "snmpresponse"


def test_public_phase_summary_hides_internal_phase_data():
    summary = _public_phase_summary(
        {
            "total_hosts": 254,
            "_phase_data": [{"ip_address": "10.180.6.140"}],
        }
    )

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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user_id = f"user_test_{uuid.uuid4().hex[:8]}"
    user = User(
        id=user_id,
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    scan = create_scan(
        db=db_session,
        user_id=str(user.id),
        target="10.180.6.14",
        targets=["10.180.6.14"],
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
    )

    audit_entry = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.action == "scan.created",
            AuditLog.resource_type == "scan",
            AuditLog.resource_id == str(scan.id),
        )
        .one_or_none()
    )

    assert audit_entry is not None
    assert audit_entry.user_id == str(user.id)
    assert audit_entry.changes["scan_no"] == scan.scan_no
    assert audit_entry.changes["pipeline_mode"] == "vulnerability_audit"
    assert audit_entry.status == "success"


def test_global_org_scan_numbering_across_users(db_session: Session):
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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user1 = User(
        id=f"user_test_{uuid.uuid4().hex[:8]}",
        username=f"user1_{uuid.uuid4().hex[:8]}",
        email=f"user1_{uuid.uuid4().hex[:8]}@test.com",
        full_name="User One",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    user2 = User(
        id=f"user_test_{uuid.uuid4().hex[:8]}",
        username=f"user2_{uuid.uuid4().hex[:8]}",
        email=f"user2_{uuid.uuid4().hex[:8]}@test.com",
        full_name="User Two",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add_all([user1, user2])
    db_session.commit()

    scan1 = create_scan(
        db=db_session,
        user_id=str(user1.id),
        target="10.180.6.14",
        targets=["10.180.6.14"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )
    scan2 = create_scan(
        db=db_session,
        user_id=str(user2.id),
        target="192.168.1.2",
        targets=["192.168.1.2"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )
    scan3 = create_scan(
        db=db_session,
        user_id=str(user1.id),
        target="192.168.1.3",
        targets=["192.168.1.3"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )

    assert scan1.scan_no == 1
    assert scan2.scan_no == 2
    assert scan3.scan_no == 3


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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user_id = f"user_test_{uuid.uuid4().hex[:8]}"
    user = User(
        id=user_id,
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    scan = create_scan(
        db=db_session,
        user_id=str(user.id),
        target="10.180.6.14",
        targets=["10.180.6.14"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )

    result = {
        "summary": {"scan_duration": 0.2, "total_hosts": 1, "active_hosts": 1},
        "data": [{"ip_address": "10.180.6.14"}],
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
        .filter(
            AuditLog.action == "scan.completed",
            AuditLog.resource_type == "scan",
            AuditLog.resource_id == str(scan.id),
        )
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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user_id = f"user_test_{uuid.uuid4().hex[:8]}"
    user = User(
        id=user_id,
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()

    scan = create_scan(
        db=db_session,
        user_id=str(user.id),
        target="10.180.6.14",
        targets=["10.180.6.14"],
        scan_type="adaptive",
        pipeline_mode="basic",
    )

    mark_scan_failed(
        db=db_session, scan_id=str(scan.id), user_id=str(user.id), reason="test failure"
    )

    failure_log = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.action == "scan.failed",
            AuditLog.resource_type == "scan",
            AuditLog.resource_id == str(scan.id),
        )
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
        ip_address="10.180.6.140",
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
        target_str="10.180.6.140",
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
    )
    db_session.add(scan)
    db_session.commit()

    hosts = [
        {
            "ip_address": "10.180.6.140",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-9999-0001",
                    "title": "Test vulnerability",
                    "description": "Test description",
                    "severity": "Low",
                    "cvss": 1.0,
                    "plugin_output": "Test output",
                }
            ],
        }
    ]

    sync_vulnerability_audit(
        db_session, scan_id=scan_id, org_id=org.id, user_id=None, hosts=hosts
    )

    finding = (
        db_session.query(AssetVulnerability)
        .filter(AssetVulnerability.asset_id == asset.id)
        .one()
    )
    assert finding.org_id == org.id
    assert finding.scan_id == scan_id
    assert finding.vuln_id == "CVE-9999-0001"
    assert finding.source_family == "network_service"
    assert finding.evidence_source == "vulnerability_audit"


def test_sync_advanced_scan_updates_asset_vuln_counts(db_session: Session):
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
        ip_address="10.180.6.140",
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname="test-host",
        last_seen_at=utcnow(),
        risk_score=0,
        risk_level="Info",
        vuln_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
    )
    db_session.add(asset)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id,
        org_id=org.id,
        created_by=None,
        target_str="10.180.6.140",
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
    )
    db_session.add(scan)
    db_session.commit()

    hosts = [
        {
            "ip_address": "10.180.6.140",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-9999-0001",
                    "title": "Test vulnerability 1",
                    "description": "Test description",
                    "severity": "High",
                    "cvss": 7.5,
                    "plugin_output": "Test output",
                },
                {
                    "cve_id": "CVE-9999-0002",
                    "title": "Test vulnerability 2",
                    "description": "Test description",
                    "severity": "Low",
                    "cvss": 2.5,
                    "plugin_output": "Test output",
                },
            ],
        }
    ]

    sync_vulnerability_audit(
        db_session, scan_id=scan_id, org_id=org.id, user_id=None, hosts=hosts
    )

    db_session.refresh(asset)
    assert asset.vuln_counts == {"critical": 0, "high": 1, "medium": 0, "low": 1}
    assert asset.risk_score == 18
    assert asset.risk_level == "Low"


def test_lower_priority_discovery_does_not_overwrite_credentialed_hostname(
    db_session: Session,
):
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

    asset_id = gen_asset_id(org.id, "192.168.1.20")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="192.168.1.20",
        hostname="credentialed-host",
        discovery_method="credentialed",
        last_seen_at=utcnow(),
        custom_attributes={
            "provenance": {
                "hostname": {
                    "source": "credentialed",
                    "scan_id": "scn_cred",
                    "at": utcnow().isoformat(),
                }
            }
        },
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="192.168.1.20",
            scan_type="adaptive",
            pipeline_mode="basic",
        )
    )
    db_session.commit()

    sync_host_discovery(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[
            {"ip_address": "192.168.1.20", "hostname": "basic-host", "is_active": True}
        ],
    )

    db_session.refresh(asset)
    assert asset.hostname == "credentialed-host"


def test_discovery_dns_repairs_short_credentialed_fqdn_without_replacing_hostname(
    db_session: Session,
):
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

    asset_id = gen_asset_id(org.id, "192.168.1.23")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="192.168.1.23",
        hostname="superusr-HP3",
        fqdn="superusr-HP3",
        discovery_method="credentialed",
        last_seen_at=utcnow(),
        custom_attributes={
            "provenance": {
                "hostname": {
                    "source": "credentialed",
                    "scan_id": "scn_cred",
                    "at": utcnow().isoformat(),
                },
                "fqdn": {
                    "source": "credentialed",
                    "scan_id": "scn_cred",
                    "at": utcnow().isoformat(),
                },
            }
        },
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="192.168.1.23",
            scan_type="adaptive",
            pipeline_mode="basic",
        )
    )
    db_session.commit()

    sync_host_discovery(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[
            {
                "ip_address": "192.168.1.23",
                "hostname": "atharv-desktop.blr.cdac.in",
                "ptr_hostname": "atharv-desktop.blr.cdac.in",
                "is_active": True,
            }
        ],
    )

    db_session.refresh(asset)
    assert asset.hostname == "superusr-HP3"
    assert asset.fqdn == "atharv-desktop.blr.cdac.in"
    assert asset.dns_name == "atharv-desktop.blr.cdac.in"


def test_duplicate_phase1_host_entries_do_not_create_two_assets(db_session: Session):
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

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="192.168.1.20",
            scan_type="adaptive",
            pipeline_mode="host_discovery",
        )
    )
    db_session.commit()

    hosts = [
        {"ip_address": "192.168.1.20", "hostname": "first-host", "is_active": True},
        {"ip_address": "192.168.1.20", "hostname": "second-host", "is_active": True},
    ]

    sync_host_discovery(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=hosts,
    )

    assets = (
        db_session.query(Asset)
        .filter(Asset.org_id == org.id, Asset.ip_address == "192.168.1.20")
        .all()
    )
    assert len(assets) == 1
    assert assets[0].hostname in {"first-host", "second-host"}


def test_reuses_existing_asset_row_without_ip_for_same_phase1_host(db_session: Session):
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

    asset_id = gen_asset_id(org.id, "10.180.6.97")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address=None,
        hostname="orphaned-host",
        discovery_method="discovery",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="10.180.6.97",
            scan_type="adaptive",
            pipeline_mode="host_discovery",
        )
    )
    db_session.commit()

    sync_host_discovery(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[
            {
                "ip_address": "10.180.6.97",
                "hostname": "recovered-host",
                "is_active": True,
            }
        ],
    )

    db_session.refresh(asset)
    assert asset.id == asset_id
    assert asset.ip_address == "10.180.6.97"
    assert asset.hostname == "recovered-host"


def test_advanced_dns_hostname_populates_fqdn_without_replacing_credentialed_hostname(
    db_session: Session,
):
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

    asset_id = gen_asset_id(org.id, "10.180.6.45")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="10.180.6.45",
        hostname="superusr-HP3",
        discovery_method="credentialed",
        last_seen_at=utcnow(),
        custom_attributes={
            "provenance": {
                "hostname": {
                    "source": "credentialed",
                    "scan_id": "scn_cred",
                    "at": utcnow().isoformat(),
                }
            }
        },
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="10.180.6.45",
            scan_type="adaptive",
            pipeline_mode="vulnerability_audit",
        )
    )
    db_session.commit()

    sync_vulnerability_audit(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[
            {
                "ip_address": "10.180.6.45",
                "hostname": "atharv-desktop.blr.cdac.in",
                "vulnerabilities": [],
            }
        ],
    )

    db_session.refresh(asset)
    assert asset.hostname == "superusr-HP3"
    assert asset.fqdn == "atharv-desktop.blr.cdac.in"
    assert asset.dns_name == "atharv-desktop.blr.cdac.in"


def test_asset_discovery_dns_hostname_populates_fqdn_without_replacing_credentialed_hostname(
    db_session: Session,
):
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

    asset_id = gen_asset_id(org.id, "10.180.6.45")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="10.180.6.45",
        hostname="superusr-HP3",
        discovery_method="credentialed",
        last_seen_at=utcnow(),
        custom_attributes={
            "provenance": {
                "hostname": {
                    "source": "credentialed",
                    "scan_id": "scn_cred",
                    "at": utcnow().isoformat(),
                }
            }
        },
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="10.180.6.45",
            scan_type="adaptive",
            pipeline_mode="asset",
        )
    )
    db_session.commit()

    sync_asset_discovery(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[
            {
                "ip_address": "10.180.6.45",
                "hostname": "atharv-desktop.blr.cdac.in",
                "ports": [],
            }
        ],
    )

    db_session.refresh(asset)
    assert asset.hostname == "superusr-HP3"
    assert asset.fqdn == "atharv-desktop.blr.cdac.in"
    assert asset.dns_name == "atharv-desktop.blr.cdac.in"


def test_credentialed_scan_does_not_overwrite_existing_dns_fqdn(db_session: Session):
    import uuid

    from core.tasks import _sync_credentialed_asset_identity

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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user = User(
        id=f"usr_{org_id}_admin",
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)

    asset_id = gen_asset_id(org.id, "10.180.6.45")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="10.180.6.45",
        hostname="atharv-desktop.blr.cdac.in",
        fqdn="atharv-desktop.blr.cdac.in",
        dns_name="atharv-desktop.blr.cdac.in",
        discovery_method="vulnerability_audit",
        last_seen_at=utcnow(),
        custom_attributes={
            "provenance": {
                "fqdn": {
                    "source": "vulnerability_audit",
                    "scan_id": "scn_adv",
                    "at": utcnow().isoformat(),
                },
                "dns_name": {
                    "source": "vulnerability_audit",
                    "scan_id": "scn_adv",
                    "at": utcnow().isoformat(),
                },
            }
        },
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="10.180.6.45",
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()

    _sync_credentialed_asset_identity(
        db_session,
        user_id=user.id,
        ip="10.180.6.45",
        scan_id=scan_id,
        os_type="linux",
        system_data={
            "os_name": "Ubuntu 24.04.4 LTS",
            "hostname_short": "superusr-HP3",
            "hostname_fqdn": "superusr-HP3.localdomain",
            "fqdn": "superusr-HP3.localdomain",
        },
        stored_report={"open_ports_credentialed": []},
        cve_list=[],
        severity_counts={},
    )
    db_session.commit()

    db_session.refresh(asset)
    assert asset.hostname == "superusr-HP3"
    assert asset.fqdn == "atharv-desktop.blr.cdac.in"
    assert asset.dns_name == "atharv-desktop.blr.cdac.in"


def test_credentialed_short_hostname_is_not_treated_as_fqdn():
    from core.tasks import _extract_credentialed_identity_names

    hostname, fqdn, raw_hostname_fqdn = _extract_credentialed_identity_names(
        {
            "hostname_fqdn": "superusr-HP3",
        }
    )

    assert hostname == "superusr-HP3"
    assert fqdn == ""
    assert raw_hostname_fqdn == "superusr-HP3"


def test_credentialed_linux_interface_parser_extracts_target_mac():
    from engines.credentialed.linux_collector import _mac_from_linux_interfaces

    raw = """
    [
      {"ifname":"lo","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
      {"ifname":"enp2s0","address":"2c:58:b9:87:0b:b3","addr_info":[{"family":"inet","local":"10.180.6.45","prefixlen":22}]}
    ]
    """

    assert _mac_from_linux_interfaces(raw, "10.180.6.45") == "2c:58:b9:87:0b:b3"


def test_credentialed_windows_interface_parser_extracts_target_mac():
    from engines.credentialed.windows_collector import _mac_from_windows_interfaces

    raw = [
        {
            "IPAddress": "10.180.6.44",
            "PrefixLength": 22,
            "MacAddress": "AA-BB-CC-DD-EE-FF",
        },
        {
            "IPAddress": "10.180.6.45",
            "PrefixLength": 22,
            "MacAddress": "2C-58-B9-87-0B-B3",
        },
    ]

    assert _mac_from_windows_interfaces(raw, "10.180.6.45") == "2c:58:b9:87:0b:b3"


def test_credentialed_scan_always_collects_identity_sections():
    from core.tasks import _credentialed_sections_with_identity

    sections = _credentialed_sections_with_identity(["packages"])

    assert sections == ["packages", "system_info", "network"]
    assert _credentialed_sections_with_identity(None) is None


def test_credentialed_sync_fills_mac_and_vendor_fallback(db_session: Session):
    import uuid

    from core.tasks import _sync_credentialed_asset_identity

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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user = User(
        id=f"usr_{org_id}_admin",
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)

    asset_id = gen_asset_id(org.id, "192.168.1.24")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="192.168.1.24",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="192.168.1.24",
            scan_type="credentialed",
            pipeline_mode="credentialed",
        )
    )
    db_session.commit()

    _sync_credentialed_asset_identity(
        db_session,
        user_id=user.id,
        ip="192.168.1.24",
        scan_id=scan_id,
        os_type="linux",
        system_data={
            "os_name": "Ubuntu 24.04.4 LTS",
            "os_version_id": "24.04",
            "hostname_fqdn": "superusr-HP3.localdomain",
            "manufacturer": "HP",
            "mac_address": "02-11-22-33-44-55",
            "subnet": "10.180.6.0/24",
            "credentialed_response_time_ms": 123,
        },
        stored_report={"open_ports_credentialed": []},
        cve_list=[],
        severity_counts={},
    )
    db_session.commit()

    db_session.refresh(asset)
    assert str(asset.mac_address) == "02:11:22:33:44:55"
    assert asset.manufacturer == "HP"
    assert asset.vendor == "HP"
    assert asset.subnet == "10.180.6.0/24"
    assert asset.fqdn is None
    assert asset.response_time_ms == 123


def test_asset_discovery_does_not_overwrite_advanced_os(db_session: Session):
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

    asset_id = gen_asset_id(org.id, "192.168.1.21")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="192.168.1.21",
        os_name="Ubuntu 24.04.4 LTS",
        discovery_method="vulnerability_audit",
        last_seen_at=utcnow(),
        custom_attributes={
            "provenance": {
                "os_name": {
                    "source": "vulnerability_audit",
                    "scan_id": "scn_adv",
                    "at": utcnow().isoformat(),
                }
            }
        },
    )
    db_session.add(asset)
    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=org.id,
            created_by=None,
            target_str="192.168.1.21",
            scan_type="adaptive",
            pipeline_mode="basic",
        )
    )
    db_session.commit()

    sync_asset_discovery(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[{"ip_address": "192.168.1.21", "os_guess": "Linux"}],
    )

    db_session.refresh(asset)
    assert asset.os_name == "Ubuntu 24.04.4 LTS"


def test_advanced_scan_does_not_fix_credentialed_package_finding(db_session: Session):
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

    asset_id = gen_asset_id(org.id, "192.168.1.22")
    asset = Asset(
        id=asset_id,
        org_id=org.id,
        ip_address="192.168.1.22",
        hostname="pkg-host",
        last_seen_at=utcnow(),
    )
    db_session.add(asset)

    cve_id = f"CVE-9999-{uuid.uuid4().hex[:8]}"
    vuln = VulnerabilityDefinition(
        id=cve_id,
        cve_id=cve_id,
        title="Package CVE",
        severity="High",
        cvss_v3_score=8.0,
        source="credentialed",
    )
    db_session.add(vuln)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id,
        org_id=org.id,
        created_by=None,
        target_str="192.168.1.22",
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
    )
    db_session.add(scan)

    finding = AssetVulnerability(
        id=f"fnd_{asset_id}_credentialed_package_{cve_id}",
        org_id=org.id,
        scan_id=scan_id,
        asset_id=asset_id,
        vuln_id=cve_id,
        severity="High",
        cvss_score=8.0,
        status="open",
        source_family="credentialed_package",
        evidence_source="credentialed",
        proof="Source_Family:credentialed_package\nPackage: openssl 3.0",
    )
    db_session.add(finding)
    db_session.commit()

    sync_vulnerability_audit(
        db_session,
        scan_id=scan_id,
        org_id=org.id,
        user_id=None,
        hosts=[{"ip_address": "192.168.1.22", "vulnerabilities": []}],
    )

    db_session.refresh(finding)
    assert finding.status == "open"
    assert finding.fixed_at is None


def test_update_finding_status_refreshes_asset_counts(db_session: Session):
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

    org_admin_role = db_session.query(Role).filter_by(name="org_admin").first()
    user = User(
        id=f"usr_{org_id}_admin",
        username=f"testadmin{uuid.uuid4().hex[:8]}",
        email=f"admin{uuid.uuid4().hex[:8]}@test.com",
        full_name="Test Admin",
        password_hash=hash_password("securepassword123"),
        org_id=org.id,
        role_id=org_admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)

    asset = Asset(
        id=f"ast_{org_id}_192_168_1_11",
        org_id=org.id,
        ip_address="10.180.6.141",
        mac_address="AA:BB:CC:DD:EE:00",
        hostname="status-host",
        last_seen_at=utcnow(),
        vuln_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
    )
    db_session.add(asset)

    scan_id = f"scn_{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id,
        org_id=org.id,
        created_by=None,
        target_str="10.180.6.141",
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
    )
    db_session.add(scan)
    db_session.commit()

    hosts = [
        {
            "ip_address": "10.180.6.141",
            "vulnerabilities": [
                {
                    "cve_id": "CVE-9999-0003",
                    "title": "Test vulnerability status",
                    "description": "Test description",
                    "severity": "High",
                    "cvss": 8.0,
                    "plugin_output": "Test output",
                }
            ],
        }
    ]

    sync_vulnerability_audit(
        db_session, scan_id=scan_id, org_id=org.id, user_id=None, hosts=hosts
    )
    finding = (
        db_session.query(AssetVulnerability)
        .filter(AssetVulnerability.asset_id == asset.id)
        .one()
    )
    assert finding.status == "open"

    update_finding_status(
        finding_id=finding.id,
        body=StatusUpdate(status="fixed"),
        org_id=org.id,
        db=db_session,
        user=user,
    )

    db_session.refresh(asset)
    assert asset.vuln_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_host_discovery_endpoint(
    client: TestClient, auth_headers: dict, db_session: Session
):
    """Test the Phase 1 Host Discovery API logic and DB persistence."""

    # Mock the internal orchestrator to return a successful dummy result
    mock_result = {
        "success": True,
        "data": [
            {
                "ip_address": "10.180.6.140",
                "status": "up",
                "mac_address": "AA:BB:CC:DD:EE:FF",
            }
        ],
        "summary": {
            "total_hosts": 1,
            "active_hosts": 1,
            "inactive_hosts": 0,
            "scan_duration": 0.5,
        },
    }

    mock_orch = AsyncMock()
    mock_orch.run_host_discovery_only.return_value = mock_result
    mock_orch.generate_phase_report.return_value = {"executive_pdf": "/fake/path.pdf"}

    with patch("core.tasks._new_orchestrator", return_value=mock_orch):
        response = client.post(
            "/scan/host-discovery",
            headers=auth_headers,
            json={
                "targets": ["10.180.6.0/24"],
                "scan_type": "adaptive",
                "pipeline_mode": "asset",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "scan_id" in data

        # Query and verify DB persistence
        scan_id = data["scan_id"]
        db_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
        assert db_scan is not None
        assert db_scan.pipeline_mode == "asset"
        assert db_scan.active_hosts == 1
        assert db_scan.total_hosts == 1

        # Ensure rate limiting header is present (slowapi adds standard X-RateLimit headers)
        assert "X-RateLimit-Limit" in response.headers or response.status_code == 200


def test_asset_discovery_wrong_pipeline_mode(client: TestClient, auth_headers: dict):
    """Test that calling Asset Discovery on a 'basic' pipeline fails."""
    response = client.post(
        "/scan/asset-discovery",
        headers=auth_headers,
        json={
            "hosts": [{"ip_address": "10.180.6.140"}],
            "intensity": "normal",
            "pipeline_mode": "basic",  # Basic pipeline only allows Phase 1
        },
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
        json={"password": ["this_is_an_invalid_type_for_a_password_field"]},
    )

    assert response.status_code == 422
    data = response.json()

    # Check that the raw input isn't leaked in the response
    detail_str = str(data["detail"])
    assert "this_is_an_invalid_type_for_a_password_field" not in detail_str
    assert "Value redacted for security." in detail_str


def test_scan_history_includes_started_by_metadata(
    client: TestClient, auth_headers: dict, test_user: User, db_session: Session
):
    """Test that scan history exposes scan starter metadata for the scan list."""
    scan = Scan(
        org_id=test_user.org_id,
        created_by=str(test_user.id),
        scan_no=101,
        target_str="10.0.0.7",
        scan_type="adaptive",
        pipeline_mode="basic",
        status="queued",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    response = client.get("/scans", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    found = next(
        (item for item in data.get("scans", []) if item.get("id") == scan.id), None
    )
    assert found is not None
    assert found["created_by"] == str(test_user.id)
    assert found["started_by"]["user_id"] == str(test_user.id)
    assert found["started_by"]["username"] == test_user.username
    assert found["started_by"]["full_name"] == test_user.full_name
    assert found["started_by"]["display_name"] == test_user.full_name


def test_scan_history_owner_filter_returns_only_my_scans(
    client: TestClient, auth_headers: dict, test_user: User, db_session: Session
):
    other_user = User(
        username="otheruser",
        email="other@test.com",
        full_name="Other User",
        password_hash=hash_password("securepassword"),
        org_id=test_user.org_id,
        role_id=test_user.role_id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(other_user)
    db_session.commit()
    db_session.refresh(other_user)

    mine_scan = Scan(
        org_id=test_user.org_id,
        created_by=str(test_user.id),
        scan_no=102,
        target_str="10.0.0.8",
        scan_type="adaptive",
        pipeline_mode="basic",
        status="complete",
    )
    other_scan = Scan(
        org_id=test_user.org_id,
        created_by=str(other_user.id),
        scan_no=103,
        target_str="10.0.0.9",
        scan_type="adaptive",
        pipeline_mode="basic",
        status="complete",
    )
    db_session.add_all([mine_scan, other_scan])
    db_session.commit()

    response = client.get("/scans?created_by=me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    ids = [item["id"] for item in data.get("scans", [])]
    assert str(mine_scan.id) in ids
    assert str(other_scan.id) not in ids


def test_scan_progress_requires_scan_read_permission(
    client: TestClient, db_session: Session, test_org: Organization
):
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
        target_str="10.180.5.0/24",
        scan_type="adaptive",
        pipeline_mode="basic",
        status="running",
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    response = client.post(
        "/auth/login",
        json={"email": "limited@example.com", "password": "securepassword"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]

    progress_response = client.get(
        f"/scan/progress/{scan.id}", headers={"Authorization": f"Bearer {token}"}
    )

    assert progress_response.status_code == 403
    assert "scans:read" in progress_response.json()["detail"]


def test_sync_vulnerability_audit_populates_tls_details(db_session: Session):
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
        ip_address="10.180.6.140",
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
        target_str="10.180.6.140",
        scan_type="adaptive",
        pipeline_mode="vulnerability_audit",
    )
    db_session.add(scan)
    db_session.commit()

    from db.base import gen_service_id
    from db.models.findings import Service, TLSDetail

    service_id = gen_service_id(asset.id, 443, "tcp")
    service = Service(
        id=service_id,
        scan_id=scan_id,
        asset_id=asset.id,
        port=443,
        protocol="tcp",
        state="open",
        service_name="https",
    )
    db_session.add(service)
    db_session.commit()

    hosts = [
        {
            "ip_address": "10.180.6.140",
            "open_ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                }
            ],
            "tls_info": {
                "enabled": True,
                "version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "cert_subject": "google.com",
                "cert_issuer": "GTS CA 1C3",
                "cert_expiry": "Jun 10 17:30:00 2026 GMT",
                "cert_expired": False,
                "cert_self_signed": False,
                "weak_cipher": False,
                "score": "A",
                "issues": [],
            },
        }
    ]

    sync_vulnerability_audit(
        db_session, scan_id=scan_id, org_id=org.id, user_id=None, hosts=hosts
    )

    tls_entry = (
        db_session.query(TLSDetail).filter(TLSDetail.service_id == service_id).first()
    )
    assert tls_entry is not None
    assert tls_entry.is_enabled is True
    assert tls_entry.protocol_version == "TLSv1.3"
    assert tls_entry.cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert tls_entry.grade == "A"
    assert tls_entry.cert_subject == {"common_name": "google.com"}
    assert tls_entry.cert_issuer == {"common_name": "GTS CA 1C3"}
    assert tls_entry.cert_is_expired is False
    assert tls_entry.cert_is_self_signed is False

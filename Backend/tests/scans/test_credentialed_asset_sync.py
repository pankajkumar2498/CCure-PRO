"""
A standalone credentialed audit's asset writes are the asset registry's
(``core.asset_credentialed``, 1 Nov 2026).

``scans.tasks.credentialed_sync._sync_credentialed_asset_identity`` keeps its
signature and its order: it resolves the scan's organisation, asks the
registry for the asset and its identity, calls the findings writer, records
the scan's assessment scope, then asks the registry to finish the asset. These
pin what a sync writes for a new asset, an asset found by MAC that moved
address, and one found by address, and that a failure either writes nothing
(an unknown user) or does not stop the sync (the scan's own bookkeeping).
"""

import ast
import uuid

import pytest
from db.base import utcnow
from db.models import Asset, AssetChangeLog, Organization, Scan, User
from sqlalchemy.orm import Session
from testpaths import BACKEND_ROOT

from scans.tasks.credentialed_sync import _sync_credentialed_asset_identity

SYSTEM = {
    "os_name": "Ubuntu 24.04.4 LTS",
    "os_version_id": "24.04",
    "hostname_fqdn": "audit-host.example.internal",
    "manufacturer": "HP",
    "subnet": "192.0.2.0/24",
    "credentialed_response_time_ms": 40,
    "running_services": [{"name": "auditd"}, {"name": "ufw"}],
    "password_policy": {"min_length": 14, "history_length": 5},
    "smbv1_disabled": True,
}


@pytest.fixture
def scan(db_session: Session, test_org: Organization) -> Scan:
    row = Scan(
        id=f"scn_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        created_by=None,
        target_str="192.0.2.40",
        scan_type="credentialed",
        pipeline_mode="credentialed",
        options={},
    )
    db_session.add(row)
    db_session.flush()
    return row


def _sync(db, user, scan, ip, **system):
    _sync_credentialed_asset_identity(
        db,
        user_id=user.id,
        ip=ip,
        scan_id=scan.id,
        os_type="linux",
        system_data={**SYSTEM, **system},
        stored_report={"open_ports_credentialed": []},
        cve_list=[],
        severity_counts={},
    )
    db.flush()


def _asset(db, org, ip, **fields) -> Asset:
    row = Asset(
        id=f"ast_{uuid.uuid4().hex[:10]}",
        org_id=org.id,
        ip_address=ip,
        last_seen_at=utcnow(),
        **fields,
    )
    db.add(row)
    db.flush()
    return row


def _changes(db, asset_id) -> list:
    return (
        db.query(AssetChangeLog.field_name, AssetChangeLog.new_value)
        .filter(AssetChangeLog.asset_id == asset_id)
        .all()
    )


def test_a_new_host_is_bootstrapped_with_its_identity_and_evidence(
    db_session: Session, test_user: User, test_org: Organization, scan: Scan
):
    _sync(db_session, test_user, scan, "192.0.2.40")

    asset = (
        db_session.query(Asset)
        .filter(Asset.org_id == test_org.id, Asset.ip_address == "192.0.2.40")
        .one()
    )
    assert asset.discovery_method == "credentialed"
    assert asset.is_active is True
    assert asset.os_name == "Ubuntu 24.04.4 LTS"
    assert asset.hostname == "audit-host"
    # A credentialed name is not a DNS identity (scans.asset_syncer refuses
    # it for fqdn); it is kept in the system information instead.
    assert asset.fqdn is None
    assert asset.last_scan_id == scan.id
    assert asset.vuln_counts is not None and asset.risk_level is not None
    attrs = asset.custom_attributes
    assert attrs["credentialed_status"] == "success"
    assert attrs["password_policy"] == {"min_length": 14, "history_length": 5}
    assert attrs["registry_hardening"]["audit_configured"] is True
    assert attrs["registry_hardening"]["firewall_active"] is True
    assert attrs["registry_hardening"]["smbv1_disabled"] is True
    assert attrs["registry_hardening"]["telnet_disabled"] is None  # not read
    assert attrs["credentialed_system_info"]["source_scan_id"] == scan.id
    assert attrs["credentialed_system_info"]["fqdn"] == "audit-host.example.internal"
    assert attrs["provenance"]["device_category"]["signal"] == "credentialed"
    assert ("lifecycle", {"val": "bootstrapped_via_credentialed"}) in _changes(
        db_session, asset.id
    )
    # The scan's own record, written by the task, not the registry.
    db_session.refresh(scan)
    assert scan.options["assessment_scope"]["assets"] == [asset.id]


def test_a_host_found_by_mac_moves_address_and_releases_the_old_holder(
    db_session: Session, test_user: User, test_org: Organization, scan: Scan
):
    moved = _asset(db_session, test_org, "192.0.2.41", mac_address="02:11:22:33:44:55")
    holder = _asset(db_session, test_org, "192.0.2.42")

    _sync(db_session, test_user, scan, "192.0.2.42", mac_address="02-11-22-33-44-55")

    db_session.refresh(moved)
    db_session.refresh(holder)
    assert moved.ip_address == "192.0.2.42"
    assert (holder.ip_address, holder.is_active) == (None, False)
    assert ("ip_address", {"val": "192.0.2.42"}) in _changes(db_session, moved.id)
    assert ("ip_address", {"val": None}) in _changes(db_session, holder.id)


def test_a_host_found_by_address_is_updated_in_place(
    db_session: Session, test_user: User, test_org: Organization, scan: Scan
):
    existing = _asset(
        db_session,
        test_org,
        "192.0.2.43",
        custom_attributes={"tags": ["cde"], "password_policy": {"min_length": 8}},
    )

    _sync(db_session, test_user, scan, "192.0.2.43", password_policy={})

    db_session.refresh(existing)
    assert existing.os_name == "Ubuntu 24.04.4 LTS"
    assert existing.last_scan_id == scan.id
    attrs = existing.custom_attributes
    assert attrs["tags"] == ["cde"]  # what the sync does not own is kept
    # Collected, never assumed: no policy read this time, so none is reported.
    assert "password_policy" not in attrs
    assert ("os_name", {"val": "Ubuntu 24.04.4 LTS"}) in _changes(
        db_session, existing.id
    )
    assert (
        db_session.query(Asset)
        .filter(Asset.org_id == test_org.id, Asset.ip_address == "192.0.2.43")
        .count()
        == 1
    )


def test_an_unknown_user_writes_nothing(
    db_session: Session, test_org: Organization, scan: Scan
):
    _sync(db_session, User(id="usr_gone"), scan, "192.0.2.44")
    assert (
        db_session.query(Asset)
        .filter(Asset.org_id == test_org.id, Asset.ip_address == "192.0.2.44")
        .count()
        == 0
    )


def test_a_failed_scope_record_does_not_stop_the_asset_sync(
    db_session: Session,
    test_user: User,
    test_org: Organization,
    scan: Scan,
    monkeypatch,
):
    import core.findings

    def refuse(*a, **kw):
        raise RuntimeError("bookkeeping failed")

    monkeypatch.setattr(core.findings, "record_assessment_scope", refuse)

    _sync(db_session, test_user, scan, "192.0.2.45")

    asset = (
        db_session.query(Asset)
        .filter(Asset.org_id == test_org.id, Asset.ip_address == "192.0.2.45")
        .one()
    )
    assert asset.custom_attributes["credentialed_status"] == "success"
    assert asset.last_scan_id == scan.id


def test_the_task_imports_no_asset_model():
    tree = ast.parse(
        (BACKEND_ROOT / "scans" / "tasks" / "credentialed_sync.py").read_text()
    )
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module in ("db.models", "db.models.assets")
        for alias in node.names
    }
    assert imported == {"Scan"}, imported

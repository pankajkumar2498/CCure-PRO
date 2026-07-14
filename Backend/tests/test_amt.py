"""
tests/test_amt.py
─────────────────────────────────────────────────────────────────────────────
Unit and integration tests for the AMT Inventory Import and Reconciliation.
"""

import json
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from db.models.users import User
from db.models.assets import Asset, AssetChangeLog
from db.models.amt import AMTInventoryRecord
from core.utils import normalize_mac
from core.amt_reconciliation import reconcile_amt_inventory


def test_normalize_mac():
    """Verify MAC address normalization conforms to canonical format."""
    # Canonical colons
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"
    # Hyphens
    assert normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"
    # Plain hex string
    assert normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"
    # Mixed formatting
    assert normalize_mac("Aa-Bb:Cc-Dd:Ee-Ff") == "AA:BB:CC:DD:EE:FF"

    # Invalid lengths or formats
    assert normalize_mac("aabbccddeef") is None
    assert normalize_mac("aabbccddeeffgg") is None
    assert normalize_mac("") is None
    assert normalize_mac(None) is None


def test_import_amt_inventory_endpoint(
    client: TestClient, auth_headers: dict, db_session: Session, test_user: User
):
    """Test upload of assets.json to import AMT inventory."""
    mock_assets_data = {
        "data": [
            {
                "mac_address_1": "11:22:33:44:55:66",
                "mac_address_2": "66:55:44:33:22:11",
                "asset_tag": "TAG-001",
                "asset_name": "Laptop-Alice",
                "serial": "SN12345",
                "vendor": "Dell",
                "asset_type": "Laptop",
                "asset_user": "Alice Smith",
                "emp_id": "EMP001",
                "status": "Active",
                "location": "Boston Office",
                "location_id": 10,
                "company_name": "Acme Corp",
            },
            {
                "mac_address_1": "aa:bb:cc:dd:ee:ff",
                "mac_address_2": None,
                "asset_tag": "TAG-002",
                "asset_name": "Server-Bob",
                "serial": "SN67890",
                "vendor": "HP",
                "asset_type": "Server",
                "asset_user": "Bob Jones",
                "emp_id": "EMP002",
                "status": "Active",
                "location": "New York Data Center",
                "location_id": 12,
                "company_name": "Acme Corp",
            },
        ]
    }

    # Upload mock assets.json
    file_payload = (
        "assets.json",
        json.dumps(mock_assets_data).encode("utf-8"),
        "application/json",
    )
    response = client.post(
        "/assets/import-amt", headers=auth_headers, files={"file": file_payload}
    )

    assert response.status_code == 200
    res_data = response.json()
    assert res_data["success"] is True
    assert res_data["records_imported"] == 2

    # Check database records
    records = (
        db_session.query(AMTInventoryRecord)
        .filter(AMTInventoryRecord.org_id == test_user.org_id)
        .all()
    )
    assert len(records) == 2

    alice_rec = next(r for r in records if r.mac_address_1 == "11:22:33:44:55:66")
    assert alice_rec.asset_user == "Alice Smith"
    assert alice_rec.serial == "SN12345"
    assert alice_rec.emp_id == "EMP001"
    assert alice_rec.mac_address_2 == "66:55:44:33:22:11"

    # Verify that a second upload clears the old records and populates new ones
    mock_assets_data_2 = {
        "data": [
            {
                "mac_address_1": "11:22:33:44:55:66",
                "asset_tag": "TAG-001-NEW",
                "asset_name": "Laptop-Alice-New",
                "serial": "SN12345",
                "vendor": "Dell",
                "asset_type": "Laptop",
                "asset_user": "Alice Jones",
                "emp_id": "EMP001",
                "status": "Active",
                "location": "Boston Office",
                "location_id": 10,
                "company_name": "Acme Corp",
            }
        ]
    }
    file_payload_2 = (
        "assets.json",
        json.dumps(mock_assets_data_2).encode("utf-8"),
        "application/json",
    )
    response_2 = client.post(
        "/assets/import-amt", headers=auth_headers, files={"file": file_payload_2}
    )

    assert response_2.status_code == 200
    assert response_2.json()["records_imported"] == 1

    records_2 = (
        db_session.query(AMTInventoryRecord)
        .filter(AMTInventoryRecord.org_id == test_user.org_id)
        .all()
    )
    assert len(records_2) == 1
    assert records_2[0].asset_user == "Alice Jones"
    assert records_2[0].asset_tag == "TAG-001-NEW"


def test_import_amt_inventory_duplicate_macs(
    client: TestClient, auth_headers: dict, db_session: Session, test_user: User
):
    """Verify that uploading files with duplicate MACs is handled by programmatically selecting the best/newest record."""
    mock_assets_data = {
        "data": [
            {
                "mac_address_1": "aa:bb:cc:dd:ee:ff",
                "asset_tag": "TAG-001",
                "asset_user": "User One",
                "status": "In Use",  # Active status
            },
            {
                "mac_address_1": "aa:bb:cc:dd:ee:ff",
                "asset_tag": "TAG-002",
                "asset_user": "User Two",
                "status": "Ready to Deploy",  # Less active status
            },
            {
                "mac_address_1": "AA:BB:CC:DD:EE:FF",  # Case variation of same MAC
                "asset_tag": "TAG-003",
                "asset_user": "User Three",
                "status": "Undeployable",  # Inactive status
            },
        ]
    }

    # Upload file with duplicate MAC entries
    file_payload = (
        "assets.json",
        json.dumps(mock_assets_data).encode("utf-8"),
        "application/json",
    )
    response = client.post(
        "/assets/import-amt", headers=auth_headers, files={"file": file_payload}
    )

    assert response.status_code == 200
    res_data = response.json()
    assert res_data["success"] is True
    # Only one record should be imported for this MAC address
    assert res_data["records_imported"] == 1

    records = (
        db_session.query(AMTInventoryRecord)
        .filter(AMTInventoryRecord.org_id == test_user.org_id)
        .all()
    )
    assert len(records) == 1
    # TAG-001 should win because status "In Use" is prioritized over "Ready to Deploy" and "Undeployable"
    assert records[0].asset_user == "User One"
    assert records[0].asset_tag == "TAG-001"

    # Now verify sequential tag priority when status is equal
    db_session.query(AMTInventoryRecord).filter(
        AMTInventoryRecord.org_id == test_user.org_id
    ).delete()
    db_session.commit()

    mock_assets_data_equal_status = {
        "data": [
            {
                "mac_address_1": "aa:bb:cc:dd:ee:ff",
                "asset_tag": "TAG-001",
                "asset_user": "User One",
                "status": "In Use",
            },
            {
                "mac_address_1": "aa:bb:cc:dd:ee:ff",
                "asset_tag": "TAG-005",  # Newer sequence
                "asset_user": "User Five",
                "status": "In Use",
            },
        ]
    }

    file_payload_equal = (
        "assets.json",
        json.dumps(mock_assets_data_equal_status).encode("utf-8"),
        "application/json",
    )
    response_equal = client.post(
        "/assets/import-amt", headers=auth_headers, files={"file": file_payload_equal}
    )
    assert response_equal.status_code == 200
    assert response_equal.json()["records_imported"] == 1

    records_equal = (
        db_session.query(AMTInventoryRecord)
        .filter(AMTInventoryRecord.org_id == test_user.org_id)
        .all()
    )
    assert len(records_equal) == 1
    # TAG-005 should win because status is equal, but tag sequence is higher
    assert records_equal[0].asset_user == "User Five"
    assert records_equal[0].asset_tag == "TAG-005"


def test_reconciliation_logic(db_session: Session, test_user: User):
    """Test that reconciliation matches scanned assets with AMT records and logs modifications."""
    org_id = test_user.org_id

    # 1. Create a scanned asset in the database
    asset = Asset(
        id=f"ast_test_{org_id}_10_0_0_5",
        org_id=org_id,
        ip_address="10.0.0.5",
        mac_address="11:22:33:44:55:66",
        hostname="scanned-host-alice",
        device_category="unknown",
        vendor="unknown",
        owner=None,
        provenance={},
    )
    db_session.add(asset)

    # 2. Add matching AMT record
    amt_record = AMTInventoryRecord(
        org_id=org_id,
        mac_address_1="11:22:33:44:55:66",
        asset_tag="TAG-001",
        asset_name="Laptop-Alice",
        serial="SN12345",
        vendor="Dell Inc",
        asset_type="Laptop Computer",
        asset_user="Alice Smith",
        emp_id="EMP001",
        status="Active",
        location="Boston Office",
        company_name="Acme Corp",
    )
    db_session.add(amt_record)
    db_session.commit()

    # 3. Perform reconciliation
    stats = reconcile_amt_inventory(db_session, org_id)
    assert stats["matched"] == 1
    assert stats["updated"] == 1

    # Reload asset
    db_session.refresh(asset)
    assert asset.owner == "Alice Smith"
    assert asset.device_category == "laptop"
    assert asset.vendor == "Dell Inc"
    assert asset.custom_attributes.get("serial_number") == "SN12345"
    assert asset.custom_attributes.get("owner_employee_id") == "EMP001"
    assert asset.custom_attributes.get("amt_asset_tag") == "TAG-001"
    assert asset.provenance.get("owner", {}).get("source") == "amt_import"

    # Check change log
    changelogs = (
        db_session.query(AssetChangeLog)
        .filter(AssetChangeLog.asset_id == asset.id)
        .all()
    )
    assert len(changelogs) >= 1
    assert any(
        cl.change_type == "owner_reassigned" and cl.new_value == "Alice Smith"
        for cl in changelogs
    )


def test_reconciliation_analyst_override(db_session: Session, test_user: User):
    """Verify reconciliation respects analyst manual overrides."""
    org_id = test_user.org_id

    # 1. Scanned asset with analyst-defined owner
    asset = Asset(
        id=f"ast_test_{org_id}_10_0_0_5",
        org_id=org_id,
        ip_address="10.0.0.5",
        mac_address="11:22:33:44:55:66",
        owner="Manual Charlie",
        provenance={
            "owner": {
                "source": "analyst",
                "user_id": "usr_test",
                "updated_at": "2026-06-09T00:00:00Z",
            }
        },
    )
    db_session.add(asset)

    # 2. Add matching AMT record pointing to different owner
    amt_record = AMTInventoryRecord(
        org_id=org_id,
        mac_address_1="11:22:33:44:55:66",
        asset_user="Alice Smith",
        serial="SN12345",
    )
    db_session.add(amt_record)
    db_session.commit()

    # 3. Perform reconciliation
    reconcile_amt_inventory(db_session, org_id)

    db_session.refresh(asset)
    # The owner must remain the manually specified one
    assert asset.owner == "Manual Charlie"
    assert asset.provenance["owner"]["source"] == "analyst"
    # Serial should still be enriched since it wasn't overridden
    assert asset.custom_attributes.get("serial_number") == "SN12345"


def test_coverage_stats_endpoint(
    client: TestClient, auth_headers: dict, db_session: Session, test_user: User
):
    """Test retrieving coverage metrics dashboard statistics."""
    org_id = test_user.org_id

    # Reset table data for predictable test outcome
    db_session.query(Asset).filter(Asset.org_id == org_id).delete()
    db_session.query(AMTInventoryRecord).filter(
        AMTInventoryRecord.org_id == org_id
    ).delete()
    db_session.commit()

    # 1. Scanned asset matching inventory (Fully Audited)
    asset_audited = Asset(
        id=f"ast_test_{org_id}_10_0_0_10",
        org_id=org_id,
        ip_address="10.0.0.10",
        mac_address="11:11:11:11:11:11",
    )
    # 2. Scanned asset NOT in inventory (Shadow IT / Rogue)
    asset_rogue = Asset(
        id=f"ast_test_{org_id}_10_0_0_11",
        org_id=org_id,
        ip_address="10.0.0.11",
        mac_address="22:22:22:22:22:22",
    )
    db_session.add_all([asset_audited, asset_rogue])

    # 3. AMT Record matching scanned asset (Fully Audited)
    amt_audited = AMTInventoryRecord(org_id=org_id, mac_address_1="11:11:11:11:11:11")
    # 4. AMT Record never scanned (Coverage Gap)
    amt_gap = AMTInventoryRecord(org_id=org_id, mac_address_1="33:33:33:33:33:33")
    db_session.add_all([amt_audited, amt_gap])
    db_session.commit()

    response = client.get("/assets/coverage-stats", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()

    assert data["configured"] is True
    assert data["total_scanned"] == 2
    assert data["total_inventory"] == 2
    assert data["fully_audited"] == 1
    assert data["shadow_it"] == 1
    assert data["coverage_gap"] == 1
    assert data["coverage_percentage"] == 50.0


def test_sync_asset_discovery_reconcile(db_session: Session, test_user: User):
    """Verify that sync_asset_discovery_task automatically triggers AMT reconciliation when terminal."""
    org_id = test_user.org_id

    # 1. Create scan row with pipeline_mode="asset"
    scan = Scan(
        id="scn_test_asset_reconcile",
        org_id=org_id,
        created_by=str(test_user.id),
        scan_no=999,
        status="running",
        pipeline_mode="asset",
        scan_type="adaptive",
        target_str="10.0.0.5",
        target_hosts=["10.0.0.5"],
    )
    db_session.add(scan)

    # 2. Create the scanned asset
    asset = Asset(
        id=f"ast_test_{org_id}_10_0_0_5",
        org_id=org_id,
        ip_address="10.0.0.5",
        mac_address="11:22:33:44:55:66",
        hostname="scanned-host-alice",
        device_category="unknown",
        vendor="unknown",
        owner=None,
        provenance={},
    )
    db_session.add(asset)

    # 3. Add matching AMT record
    amt_record = AMTInventoryRecord(
        org_id=org_id,
        mac_address_1="11:22:33:44:55:66",
        asset_tag="TAG-001",
        asset_user="Alice Smith",
        status="Active",
    )
    db_session.add(amt_record)
    db_session.commit()

    # 4. Trigger sync_asset_discovery_task
    from core.tasks import sync_asset_discovery_task

    sync_asset_discovery_task(
        scan_id=scan.id,
        org_id=org_id,
        user_id=str(test_user.id),
        hosts=[
            {
                "ip_address": "10.0.0.5",
                "mac_address": "11:22:33:44:55:66",
                "is_active": True,
            }
        ],
    )

    # 5. Check if reconciliation successfully ran and enriched the asset
    db_session.refresh(asset)
    assert asset.owner == "Alice Smith"
    assert asset.custom_attributes.get("amt_asset_tag") == "TAG-001"


def test_sync_vulnerability_audit_reconcile(db_session: Session, test_user: User):
    """Verify that sync_vulnerability_audit_task automatically triggers AMT reconciliation when terminal."""
    org_id = test_user.org_id

    # 1. Create scan row with pipeline_mode="vulnerability_audit"
    scan = Scan(
        id="scn_test_vuln_reconcile",
        org_id=org_id,
        created_by=str(test_user.id),
        scan_no=1000,
        status="running",
        pipeline_mode="vulnerability_audit",
        scan_type="adaptive",
        target_str="10.0.0.5",
        target_hosts=["10.0.0.5"],
    )
    db_session.add(scan)

    # 2. Create the scanned asset
    asset = Asset(
        id=f"ast_test_{org_id}_10_0_0_5",
        org_id=org_id,
        ip_address="10.0.0.5",
        mac_address="11:22:33:44:55:66",
        hostname="scanned-host-alice",
        device_category="unknown",
        vendor="unknown",
        owner=None,
        provenance={},
    )
    db_session.add(asset)

    # 3. Add matching AMT record
    amt_record = AMTInventoryRecord(
        org_id=org_id,
        mac_address_1="11:22:33:44:55:66",
        asset_tag="TAG-002",
        asset_user="Bob Smith",
        status="Active",
    )
    db_session.add(amt_record)
    db_session.commit()

    # 4. Trigger sync_vulnerability_audit_task
    from core.tasks import sync_vulnerability_audit_task

    sync_vulnerability_audit_task(
        scan_id=scan.id,
        org_id=org_id,
        user_id=str(test_user.id),
        hosts=[
            {
                "ip_address": "10.0.0.5",
                "mac_address": "11:22:33:44:55:66",
                "is_active": True,
            }
        ],
    )

    # 5. Check if reconciliation successfully ran and enriched the asset
    db_session.refresh(asset)
    assert asset.owner == "Bob Smith"
    assert asset.custom_attributes.get("amt_asset_tag") == "TAG-002"


def test_credentialed_scan_reconcile(db_session: Session, test_user: User):
    """Verify that _sync_credentialed_asset_identity followed by reconciliation correctly matches and enriches the asset."""
    org_id = test_user.org_id

    # 1. Create scan row with pipeline_mode="vulnerability_audit" and scan_type="credentialed"
    scan = Scan(
        id="scn_test_cred_reconcile",
        org_id=org_id,
        created_by=str(test_user.id),
        scan_no=1001,
        status="running",
        pipeline_mode="vulnerability_audit",
        scan_type="credentialed",
        target_str="10.0.0.5",
        target_hosts=["10.0.0.5"],
    )
    db_session.add(scan)

    # 2. Add matching AMT record
    amt_record = AMTInventoryRecord(
        org_id=org_id,
        mac_address_1="11:22:33:44:55:66",
        asset_tag="TAG-003",
        asset_user="Charlie Smith",
        status="Active",
    )
    db_session.add(amt_record)
    db_session.commit()

    # 3. Trigger _sync_credentialed_asset_identity to sync the asset
    from core.tasks import _sync_credentialed_asset_identity

    _sync_credentialed_asset_identity(
        db_session,
        user_id=str(test_user.id),
        ip="10.0.0.5",
        scan_id=scan.id,
        os_type="linux",
        system_data={
            "os_name": "Ubuntu 24.04.4 LTS",
            "os_version_id": "24.04",
            "mac_address": "11-22-33-44-55-66",
            "subnet": "10.0.0.0/24",
        },
        stored_report={"open_ports_credentialed": []},
        cve_list=[],
        severity_counts={},
    )

    # 4. Trigger reconciliation (replicates run_credentialed_scan_task logic)
    reconcile_amt_inventory(db_session, org_id)
    db_session.commit()

    # 5. Check if reconciliation successfully ran and enriched the asset
    asset = (
        db_session.query(Asset)
        .filter(Asset.org_id == org_id, Asset.ip_address == "10.0.0.5")
        .first()
    )
    assert asset is not None
    assert asset.owner == "Charlie Smith"
    assert asset.custom_attributes.get("amt_asset_tag") == "TAG-003"

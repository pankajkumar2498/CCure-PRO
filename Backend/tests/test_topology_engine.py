from unittest.mock import patch

from core.topology.engine import run_topology_mapping
from db.models import Asset, Scan
from core.topology.client import SNMPWalkResult, LLDPNeighbor, InterfaceInfo


@patch("core.topology.engine._resolve_gateway_ip")
@patch("core.topology.client.walk_target")
def test_run_topology_mapping_enrichment(mock_walk, mock_gw, db_session, test_org):
    mock_gw.return_value = "10.180.4.1"

    # 1. Setup mock SNMPWalkResult
    # Walks: target IP 10.180.4.10
    # sys_services: 6 (layer 2 + layer 3 = switch/router) -> should classify target as router
    # Neighbors: LLDP neighbor 00:11:22:33:44:55 (sysName: core-switch)
    result = SNMPWalkResult(target_ip="10.180.4.10")
    result.sys_name = "NOC-Router"
    result.sys_services = 6
    result.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="00:11:22:33:44:ff",
            port_id="Gi1/0/24",
            system_name="core-switch",
            local_port_index="24",
        )
    ]
    result.interface_table = {
        "24": InterfaceInfo(
            if_index="24",
            descr="GigabitEthernet1/0/24",
            speed_bps=1000000000,
            vlan_id=100,
        )
    }
    result.bridge_port_map = {"24": "24"}

    mock_walk.return_value = result

    # 2. Add source target device to the DB (pre-exist)
    target_asset = Asset(
        id=f"ast_{test_org.slug}_10_180_4_10",
        org_id=test_org.id,
        ip_address="10.180.4.10",
        mac_address="00:11:22:33:44:aa",
        device_category="host",  # generic/host -> should be updated to router
        discovery_method="discovery",
    )
    db_session.add(target_asset)

    # Add a scan record
    import uuid

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id,
        org_id=test_org.id,
        status="completed",
        target_hosts=["10.180.4.10"],
        target_str="10.180.4.10",
    )
    db_session.add(scan)
    db_session.commit()

    # Execute run_topology_mapping
    snmp_config = {"version": "v2c", "community": "public"}
    run_result = run_topology_mapping(
        db=db_session,
        scan_id=scan_id,
        org_id=test_org.id,
        snmp_config=snmp_config,
        target_ips=["10.180.4.10"],
    )

    assert run_result["success"] is True

    # 3. Assert target device was classified correctly based on sysServices
    db_session.refresh(target_asset)
    assert target_asset.device_category == "router"

    # 4. Assert placeholder asset was enrolled for LLDP neighbor
    # MAC: 00:11:22:33:44:ff, hostname: core-switch, category: switch (default category)
    placeholder = (
        db_session.query(Asset).filter(Asset.mac_address == "00:11:22:33:44:ff").first()
    )
    assert placeholder is not None
    assert placeholder.hostname == "core-switch"
    assert placeholder.device_category == "switch"
    assert placeholder.discovery_method == "topology"

    # 5. Assert strict VLAN sentinel validation
    # VLAN ID 100 is valid (not 0/4095), so it should be synced to target_asset or placeholder
    assert placeholder.vlan_id == 100


def test_run_topology_mapping_mac_first_and_ip_fallback(db_session, test_org):
    from core.topology.engine import _reconcile_target_asset

    # Setup test assets
    # Asset A: has MAC 00:11:22:33:44:55 and old IP 10.180.6.140
    asset_a = Asset(
        id=f"ast_{test_org.slug}_192_168_1_10",
        org_id=test_org.id,
        ip_address="10.180.6.140",
        mac_address="00:11:22:33:44:55",
        hostname="Laptop-A",
        discovery_method="discovery",
    )
    # Asset B: has MAC 00:11:22:33:44:66 and IP 192.168.1.20, hostname Phone-B
    asset_b = Asset(
        id=f"ast_{test_org.slug}_192_168_1_20",
        org_id=test_org.id,
        ip_address="192.168.1.20",
        mac_address="00:11:22:33:44:66",
        hostname="Phone-B",
        discovery_method="discovery",
    )
    db_session.add(asset_a)
    db_session.add(asset_b)
    db_session.commit()

    # Case 1: Match by MAC first (new IP 192.168.1.30, but matching MAC of Asset A)
    matched = _reconcile_target_asset(
        db_session,
        test_org.id,
        ip="192.168.1.30",
        mac="00:11:22:33:44:55",
        hostname="NewName",
    )
    assert matched is not None
    assert matched.id == asset_a.id

    # Case 2: Match by IP + Hostname correlation (MAC is missing, but IP and hostname match Asset B)
    matched = _reconcile_target_asset(
        db_session,
        test_org.id,
        ip="192.168.1.20",
        mac="sw:192:168:1:20",
        hostname="Phone-B",
    )
    assert matched is not None
    assert matched.id == asset_b.id

    # Case 3: Recycled IP Protection (IP matches Asset B, but hostname is different and MAC is different/placeholder)
    matched = _reconcile_target_asset(
        db_session,
        test_org.id,
        ip="192.168.1.20",
        mac="sw:192:168:1:20",
        hostname="Laptop-C",
    )
    # Should fall back to matching by IP only
    assert matched is not None
    assert matched.id == asset_b.id


def test_sync_host_discovery_mac_first_and_ip_hijack(db_session, test_org):
    from scans.asset_syncer import sync_host_discovery

    # Setup test assets
    # Asset A: laptop with MAC 00:11:22:33:44:55 at IP 192.168.1.5
    asset_a = Asset(
        id=f"ast_{test_org.slug}_192_168_1_5",
        org_id=test_org.id,
        ip_address="192.168.1.5",
        mac_address="00:11:22:33:44:55",
        hostname="Laptop-A",
        discovery_method="discovery",
    )
    # Asset B: phone with MAC 00:11:22:33:44:66 at IP 192.168.1.6
    asset_b = Asset(
        id=f"ast_{test_org.slug}_192_168_1_6",
        org_id=test_org.id,
        ip_address="192.168.1.6",
        mac_address="00:11:22:33:44:66",
        hostname="Phone-B",
        discovery_method="discovery",
    )
    db_session.add(asset_a)
    db_session.add(asset_b)
    db_session.commit()

    # Scene: Laptop-A moves to IP 192.168.1.6 (which was previously leased to Phone-B).
    # Phone-B is currently offline or inactive.
    # The scan discovers Laptop-A (MAC 00:11:22:33:44:55) at the new IP 192.168.1.6.
    import uuid

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id, org_id=test_org.id, status="completed", target_str="10.180.6.0/24"
    )
    db_session.add(scan)
    db_session.commit()

    hosts_payload = [
        {
            "ip_address": "192.168.1.6",
            "mac_address": "00:11:22:33:44:55",
            "hostname": "Laptop-A",
            "state": "up",
            "is_active": True,
        }
    ]

    sync_host_discovery(
        db_session, scan_id, test_org.id, user_id=None, hosts=hosts_payload
    )

    db_session.refresh(asset_a)
    db_session.refresh(asset_b)

    # Asset A (Laptop-A) should now have IP 192.168.1.6 (updated due to MAC-first match)
    assert asset_a.ip_address == "192.168.1.6"

    # Asset B (Phone-B) should have its IP address set to None/NULL to prevent UNIQUE constraint collisions,
    # and marked as inactive since Laptop-A has taken over the IP address.
    assert asset_b.ip_address is None
    assert asset_b.is_active is False


def test_sync_credentialed_asset_identity_mac_first_and_ip_hijack(db_session, test_org):
    from core.tasks import _sync_credentialed_asset_identity
    from db.models import User, Role

    # Setup test assets
    # Asset A: laptop with MAC 00:11:22:33:44:55 at IP 192.168.1.5
    asset_a = Asset(
        id=f"ast_{test_org.slug}_192_168_1_5",
        org_id=test_org.id,
        ip_address="192.168.1.5",
        mac_address="00:11:22:33:44:55",
        hostname="Laptop-A",
        discovery_method="credentialed",
    )
    # Asset B: phone with MAC 00:11:22:33:44:66 at IP 192.168.1.6
    asset_b = Asset(
        id=f"ast_{test_org.slug}_192_168_1_6",
        org_id=test_org.id,
        ip_address="192.168.1.6",
        mac_address="00:11:22:33:44:66",
        hostname="Phone-B",
        discovery_method="credentialed",
    )
    # Add a User record to act as the scanner runner
    import uuid

    uid = uuid.uuid4().hex[:8]
    _role = db_session.query(Role).filter_by(name="org_admin").first()
    user = User(
        id=f"scanner-user-{uid}",
        org_id=test_org.id,
        email=f"scanner-{uid}@ccurepro.com",
        username=f"scanner-{uid}",
        password_hash="...",
        role_id=_role.id,
    )
    db_session.add(asset_a)
    db_session.add(asset_b)
    db_session.add(user)
    db_session.commit()

    # Scene: Laptop-A moves to IP 192.168.1.6 (which was previously leased to Phone-B).
    # The credentialed scan discovers Laptop-A (MAC 00:11:22:33:44:55) at the new IP 192.168.1.6.
    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    scan = Scan(
        id=scan_id, org_id=test_org.id, status="completed", target_str="10.180.6.0/24"
    )
    db_session.add(scan)
    db_session.commit()

    system_data = {
        "mac_address": "00:11:22:33:44:55",
        "os_name": "Ubuntu 22.04",
        "hostname": "Laptop-A",
    }

    _sync_credentialed_asset_identity(
        db_session,
        user_id=user.id,
        ip="192.168.1.6",
        scan_id=scan_id,
        os_type="linux",
        system_data=system_data,
        stored_report={},
        cve_list=[],
        severity_counts={},
    )

    db_session.refresh(asset_a)
    db_session.refresh(asset_b)

    # Asset A (Laptop-A) should now have IP 192.168.1.6 (updated due to MAC-first match)
    assert asset_a.ip_address == "192.168.1.6"

    # Asset B (Phone-B) should have its IP address set to None/NULL to prevent UNIQUE constraint collisions,
    # and marked as inactive since Laptop-A has taken over the IP address.
    assert asset_b.ip_address is None
    assert asset_b.is_active is False

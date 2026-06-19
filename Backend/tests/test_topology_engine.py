import pytest
from unittest.mock import MagicMock, patch

from core.topology.engine import run_topology_mapping
from db.models import Asset, NetworkLink, Scan
from core.topology.client import SNMPWalkResult, LLDPNeighbor, InterfaceInfo


@patch("core.topology.engine._resolve_gateway_ip")
@patch("core.topology.engine.walk_target")
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
            chassis_id="00:11:22:33:44:55",
            port_id="Gi1/0/24",
            system_name="core-switch",
            local_port_index="24"
        )
    ]
    result.interface_table = {
        "24": InterfaceInfo(if_index="24", descr="GigabitEthernet1/0/24", speed_bps=1000000000, vlan_id=100)
    }
    result.bridge_port_map = {"24": "24"}
    
    mock_walk.return_value = result

    # 2. Add source target device to the DB (pre-exist)
    target_asset = Asset(
        id=f"ast_{test_org.slug}_10_180_4_10",
        org_id=test_org.id,
        ip_address="10.180.4.10",
        mac_address="00:11:22:33:44:aa",
        device_category="host", # generic/host -> should be updated to router
        discovery_method="discovery"
    )
    db_session.add(target_asset)
    
    # Add a scan record
    scan = Scan(
        id="scan-123",
        org_id=test_org.id,
        status="completed",
        target_hosts=["10.180.4.10"]
    )
    db_session.add(scan)
    db_session.commit()

    # Execute run_topology_mapping
    snmp_config = {"version": "v2c", "community": "public"}
    run_result = run_topology_mapping(
        db=db_session,
        scan_id="scan-123",
        org_id=test_org.id,
        snmp_config=snmp_config,
        target_ips=["10.180.4.10"]
    )

    assert run_result["success"] is True

    # 3. Assert target device was classified correctly based on sysServices
    db_session.refresh(target_asset)
    assert target_asset.device_category == "router"

    # 4. Assert placeholder asset was enrolled for LLDP neighbor
    # MAC: 00:11:22:33:44:55, hostname: core-switch, category: switch (default category)
    placeholder = db_session.query(Asset).filter(Asset.mac_address == "00:11:22:33:44:55").first()
    assert placeholder is not None
    assert placeholder.hostname == "core-switch"
    assert placeholder.device_category == "switch"
    assert placeholder.discovery_method == "topology"

    # 5. Assert strict VLAN sentinel validation
    # VLAN ID 100 is valid (not 0/4095), so it should be synced to target_asset or placeholder
    assert placeholder.vlan_id == 100

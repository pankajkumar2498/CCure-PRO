import os
os.environ["DATABASE_URL"] = "postgresql://ccure_user:ccure_admin_2026@127.0.0.1:5432/ccure_test"

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from core.topology.client import (
    _format_mac,
    _format_ip_from_bytes,
    _get_oid_suffix,
    walk_target,
    SNMPCredentials,
    OID_LLDP_REM_CHASSIS_ID,
    OID_LLDP_REM_PORT_ID,
    OID_LLDP_REM_SYS_NAME,
    OID_CDP_CACHE_ADDRESS,
    OID_CDP_CACHE_DEVICE_ID,
    OID_CDP_CACHE_DEVICE_PORT,
    OID_CDP_CACHE_PLATFORM,
)


class MockOctetString:
    """Mock PyASN1 OctetString class returning raw bytes."""
    def __init__(self, val_bytes: bytes):
        self.val_bytes = val_bytes

    def asOctets(self) -> bytes:
        return self.val_bytes

    def __str__(self) -> str:
        return self.val_bytes.decode("utf-8", errors="ignore")


def test_format_mac():
    # Native bytes 6-byte MAC
    assert _format_mac(b"\x00\x1a\x2b\x3c\x4d\x5e") == "00:1a:2b:3c:4d:5e"
    
    # Mock PyASN1 6-byte binary MAC
    mock_val = MockOctetString(b"\x00\x1a\x2b\x3c\x4d\x5e")
    assert _format_mac(mock_val) == "00:1a:2b:3c:4d:5e"
    
    # Mock PyASN1 text-based OctetString
    mock_text = MockOctetString(b"NOC-Router-A")
    assert _format_mac(mock_text) == "NOC-Router-A"
    
    # Pre-formatted strings
    assert _format_mac("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert _format_mac("00-11-22-33-44-55") == "00:11:22:33:44:55"
    assert _format_mac("001122334455") == "00:11:22:33:44:55"
    
    # Invalid fallback
    assert _format_mac("INVALID") == "INVALID"


def test_format_ip_from_bytes():
    # Native bytes 4-byte IP
    assert _format_ip_from_bytes(b"\xc0\xa8\x01\x01") == "192.168.1.1"
    
    # Mock PyASN1 4-byte IP
    mock_ip = MockOctetString(b"\x0a\xb4\x06\x0e")
    assert _format_ip_from_bytes(mock_ip) == "10.180.6.14"
    
    # Text fallback
    assert _format_ip_from_bytes("192.168.1.2") == "192.168.1.2"


def test_get_oid_suffix():
    base = "1.3.6.1.2.1.17.4.3.1.2"
    
    # Normal case
    assert _get_oid_suffix("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85", base) == "0.17.34.51.68.85"
    
    # Leading dots
    assert _get_oid_suffix(".1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.85", base) == "0.17.34.51.68.85"
    
    # Suffix not matching base (different branch)
    assert _get_oid_suffix("1.3.6.1.2.1.17.4.3.1.3.0.17.34", base) == ""
    
    # Suffix matching base prefix but sibling (e.g. base ending in 2, OID having 20)
    assert _get_oid_suffix("1.3.6.1.2.1.17.4.3.1.20.17.34", base) == ""


@patch("core.topology.client._build_snmp_engine")
@patch("core.topology.client._snmp_get_async")
@patch("core.topology.client._snmp_walk_async")
def test_walk_target_neighbor_collisions(mock_walk, mock_get, mock_engine):
    """
    Test that LLDP and CDP neighbor details are parsed correctly and do not collide
    when they share the same final suffix component but differ in full suffixes.
    """
    # Setup engine mock
    mock_engine.return_value = (MagicMock(), MagicMock(), MagicMock(), MagicMock())
    
    # Setup system identity gets
    async def mock_get_side_effect(*args):
        return None
    mock_get.side_effect = mock_get_side_effect

    # Mock walks
    async def side_effect_walk(engine, auth, transport, context, oid: str, max_rows: int = 0):
        if oid == OID_LLDP_REM_CHASSIS_ID:
            return [
                ("1.0.8802.1.1.2.1.4.1.1.5.0.10.1", MockOctetString(b"\x00\x1a\x2b\x3c\x4d\xaa")),
                ("1.0.8802.1.1.2.1.4.1.1.5.0.20.1", MockOctetString(b"\x00\x1a\x2b\x3c\x4d\xbb")),
            ]
        elif oid == OID_LLDP_REM_PORT_ID:
            return [
                ("1.0.8802.1.1.2.1.4.1.1.7.0.10.1", MockOctetString(b"port-ten")),
                ("1.0.8802.1.1.2.1.4.1.1.7.0.20.1", MockOctetString(b"port-twenty")),
            ]
        elif oid == OID_LLDP_REM_SYS_NAME:
            return [
                ("1.0.8802.1.1.2.1.4.1.1.9.0.10.1", MockOctetString(b"sys-ten")),
                ("1.0.8802.1.1.2.1.4.1.1.9.0.20.1", MockOctetString(b"sys-twenty")),
            ]
        elif oid == OID_CDP_CACHE_ADDRESS:
            return [
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.4.5.1", MockOctetString(b"\x0a\xb4\x06\x01")),
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.4.7.1", MockOctetString(b"\x0a\xb4\x06\x02")),
            ]
        elif oid == OID_CDP_CACHE_DEVICE_ID:
            return [
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.6.5.1", MockOctetString(b"cdp-device-five")),
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.6.7.1", MockOctetString(b"cdp-device-seven")),
            ]
        elif oid == OID_CDP_CACHE_DEVICE_PORT:
            return [
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.7.5.1", MockOctetString(b"Gig0/5")),
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.7.7.1", MockOctetString(b"Gig0/7")),
            ]
        elif oid == OID_CDP_CACHE_PLATFORM:
            return [
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.8.5.1", MockOctetString(b"Cisco-2960")),
                ("1.3.6.1.4.1.9.9.23.1.2.1.1.8.7.1", MockOctetString(b"Cisco-3750")),
            ]
        return []

    mock_walk.side_effect = side_effect_walk

    # Execute
    creds = SNMPCredentials(version="v2c")
    result = walk_target("127.0.0.1", creds)

    # Assert LLDP parsed successfully without collision
    assert len(result.lldp_neighbors) == 2
    n1, n2 = result.lldp_neighbors
    
    assert n1.chassis_id == "00:1a:2b:3c:4d:aa"
    assert n1.port_id == "port-ten"
    assert n1.system_name == "sys-ten"
    assert n1.local_port_index == "10"
    
    assert n2.chassis_id == "00:1a:2b:3c:4d:bb"
    assert n2.port_id == "port-twenty"
    assert n2.system_name == "sys-twenty"
    assert n2.local_port_index == "20"

    # Assert CDP parsed successfully without collision
    assert len(result.cdp_neighbors) == 2
    c1, c2 = result.cdp_neighbors
    
    assert c1.device_id == "cdp-device-five"
    assert c1.ip_address == "10.180.6.1"
    assert c1.device_port == "Gig0/5"
    assert c1.platform == "Cisco-2960"
    assert c1.local_port_index == "5"

    assert c2.device_id == "cdp-device-seven"
    assert c2.ip_address == "10.180.6.2"
    assert c2.device_port == "Gig0/7"
    assert c2.platform == "Cisco-3750"
    assert c2.local_port_index == "7"


@patch("core.topology.client._build_snmp_engine")
@patch("core.topology.client._snmp_get_async")
@patch("core.topology.client._snmp_walk_async")
def test_walk_target_interface_enrichment(mock_walk, mock_get, mock_engine):
    """
    Test that walk_target correctly populates interface details (descr, name, alias, speed, vlan)
    and resolves bridge ports, using the normalized speed logic and multi-VLAN FDB walks.
    """
    from core.topology.client import (
        OID_IF_DESCR, OID_IF_NAME, OID_IF_ALIAS, OID_IF_SPEED, OID_IF_HIGH_SPEED,
        OID_BRIDGE_PORT_IF_INDEX, OID_DOT1Q_PVID, OID_CISCO_VM_VLAN,
        OID_FDB_ADDRESS, OID_FDB_PORT
    )

    mock_engine.return_value = (MagicMock(), MagicMock(), MagicMock(), MagicMock())
    
    # Setup system identity gets
    async def mock_get_side_effect(*args):
        return None
    mock_get.side_effect = mock_get_side_effect

    # Mock walks
    async def side_effect_walk(engine, auth, transport, context, oid: str, max_rows: int = 0):
        comm = str(auth.communityName) if hasattr(auth, "communityName") else ""

        if oid == OID_IF_DESCR:
            return [
                (f"{OID_IF_DESCR}.10", MockOctetString(b"GigabitEthernet1/0/10")),
                (f"{OID_IF_DESCR}.20", MockOctetString(b"TenGigabitEthernet1/0/20")),
            ]
        elif oid == OID_IF_NAME:
            return [
                (f"{OID_IF_NAME}.10", MockOctetString(b"Gi1/0/10")),
                (f"{OID_IF_NAME}.20", MockOctetString(b"Te1/0/20")),
            ]
        elif oid == OID_IF_ALIAS:
            return [
                (f"{OID_IF_ALIAS}.10", MockOctetString(b"Uplink to Core")),
            ]
        elif oid == OID_IF_SPEED:
            return [
                (f"{OID_IF_SPEED}.10", 1000000000),
                (f"{OID_IF_SPEED}.20", 4294967295),
            ]
        elif oid == OID_IF_HIGH_SPEED:
            return [
                (f"{OID_IF_HIGH_SPEED}.20", 10000),
            ]
        elif oid == OID_BRIDGE_PORT_IF_INDEX:
            # Map bridge port 1 to ifIndex 10, bridge port 2 to ifIndex 20
            return [
                (f"{OID_BRIDGE_PORT_IF_INDEX}.1", "10"),
                (f"{OID_BRIDGE_PORT_IF_INDEX}.2", "20"),
            ]
        elif oid == OID_DOT1Q_PVID:
            # Port 10 is on VLAN 100
            return [
                (f"{OID_DOT1Q_PVID}.10", 100),
            ]
        elif oid == OID_CISCO_VM_VLAN:
            # Port 20 is on VLAN 200
            return [
                (f"{OID_CISCO_VM_VLAN}.20", 200),
            ]
        elif oid == OID_FDB_ADDRESS:
            if comm == "public@100":
                return [(f"{OID_FDB_ADDRESS}.0.11.22.33.44.66", MockOctetString(b"\x00\x11\x22\x33\x44\x66"))]
            elif comm == "public@200":
                return [(f"{OID_FDB_ADDRESS}.0.11.22.33.44.77", MockOctetString(b"\x00\x11\x22\x33\x44\x77"))]
            else:
                return [(f"{OID_FDB_ADDRESS}.0.11.22.33.44.55", MockOctetString(b"\x00\x11\x22\x33\x44\x55"))]
        elif oid == OID_FDB_PORT:
            if comm == "public@100":
                return [(f"{OID_FDB_PORT}.0.11.22.33.44.66", "1")]
            elif comm == "public@200":
                return [(f"{OID_FDB_PORT}.0.11.22.33.44.77", "2")]
            else:
                return [(f"{OID_FDB_PORT}.0.11.22.33.44.55", "1")]
        return []

    mock_walk.side_effect = side_effect_walk

    # Execute
    creds = SNMPCredentials(version="v2c")
    result = walk_target("127.0.0.1", creds)

    # Assert interface table was built and enriched correctly
    assert len(result.interface_table) == 2
    
    iface10 = result.interface_table["10"]
    assert iface10.descr == "GigabitEthernet1/0/10"
    assert iface10.name == "Gi1/0/10"
    assert iface10.alias == "Uplink to Core"
    assert iface10.display_name == "Uplink to Core (GigabitEthernet1/0/10)"
    assert iface10.speed_bps == 1000000000
    assert iface10.vlan_id == 100

    iface20 = result.interface_table["20"]
    assert iface20.descr == "TenGigabitEthernet1/0/20"
    assert iface20.name == "Te1/0/20"
    assert iface20.alias == ""
    assert iface20.display_name == "TenGigabitEthernet1/0/20"
    # speed should be resolved from high_speed_map (10000 * 1,000,000)
    assert iface20.speed_bps == 10000000000
    assert iface20.vlan_id == 200

    # Test bridge port translation helper
    assert result.resolve_interface("1") == iface10
    assert result.resolve_interface("2") == iface20

    # Assert FDB table populated with default and multi-VLAN entries
    assert len(result.fdb_table) == 3
    
    # 1. Default walk entry (VLAN 1)
    fdb1 = next(f for f in result.fdb_table if f.mac_address == "00:11:22:33:44:55")
    assert fdb1.vlan_id == 1
    assert fdb1.port_index == "1"

    # 2. VLAN 100 walk entry
    fdb2 = next(f for f in result.fdb_table if f.mac_address == "00:11:22:33:44:66")
    assert fdb2.vlan_id == 100
    assert fdb2.port_index == "1"

    # 3. VLAN 200 walk entry
    fdb3 = next(f for f in result.fdb_table if f.mac_address == "00:11:22:33:44:77")
    assert fdb3.vlan_id == 200
    assert fdb3.port_index == "2"


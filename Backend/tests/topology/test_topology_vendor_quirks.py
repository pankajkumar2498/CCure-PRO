"""
Regression tests for behaviour discovered against real hardware.

Every case here was found by walking a live Extreme X670V-48x (EXOS 15.3.1.4)
with ~900 ARP entries, ~1000 FDB entries and six EDP neighbours. Mocked tests
had passed while the module was blind to that network's entire backbone, so
these encode what the device actually does rather than what the RFCs suggest it
should.
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from core.topology.client import (
    EDPNeighbor,
    InterfaceInfo,
    SNMPCredentials,
    SNMPWalkResult,
    _parse_edp_index,
    walk_target,
)
from core.topology.engine import (
    AssetIndex,
    merge_observations,
    observations_from_walk,
    run_topology_mapping,
)
from core.topology.identity import make_endpoint
from db.models import Asset, NetworkLink, Scan


@pytest.fixture()
def scan(db_session, test_org):
    row = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        status="completed",
        target_hosts=["10.180.4.1"],
        target_str="10.180.4.1",
    )
    db_session.add(row)
    db_session.commit()
    return row


def _run(db_session, org, scan, walks, targets):
    with (
        patch("core.topology.client.probe_snmp", return_value=True),
        patch(
            "core.topology.client.walk_target", side_effect=lambda ip, creds: walks[ip]
        ),
    ):
        return run_topology_mapping(
            db=db_session,
            scan_id=scan.id,
            org_id=org.id,
            org_slug=org.slug,
            snmp_config={"version": "v2c", "community": "public"},
            target_ips=targets,
        )


# ── EDP index parsing ────────────────────────────────────────────────────────


def test_parse_edp_index_extracts_ifindex_and_mac():
    """
    Real index from the device:
      1.3.6.1.4.1.1916.1.13.2.1.3.1034.0.0.0.4.150.131.100.172
    ifIndex 1034 is "X670V-48x Port 34"; 00:04:96:83:64:ac appears in that
    switch's FDB on bridge port 34, which dot1dBasePortIfIndex maps to 1034.
    """
    assert _parse_edp_index("1034.0.0.0.4.150.131.100.172") == (
        "1034",
        "00:04:96:83:64:ac",
    )
    assert _parse_edp_index("1031.0.0.0.4.150.131.102.81") == (
        "1031",
        "00:04:96:83:66:51",
    )
    # Malformed indices degrade rather than raising.
    assert _parse_edp_index("") == ("", "")
    assert _parse_edp_index("1034") == ("1034", "")


def test_edp_neighbours_become_infrastructure_links(db_session, test_org, scan):
    """
    EXOS runs EDP, not CDP, and this estate never enabled LLDP. Without EDP the
    six uplinks were invisible and every peer switch collapsed into the MAC-only
    cluster as an anonymous forwarding-table entry.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.1")
    walk.sys_name = "NOC-10G"
    walk.sys_services = 79
    walk.ip_forwarding = 1
    walk.interface_table = {
        "1034": InterfaceInfo(
            if_index="1034", descr="X670V-48x Port 34", speed_bps=10_000_000_000
        )
    }
    walk.edp_neighbors = [
        EDPNeighbor(
            device_name="noc-1g",
            mac_address="00:04:96:83:64:ac",
            local_port_index="1034",
            software_version="15.3.1.4",
        )
    ]

    result = _run(db_session, test_org, scan, {"10.180.4.1": walk}, ["10.180.4.1"])
    assert result["success"] is True

    link = db_session.query(NetworkLink).one()
    assert link.link_type == "edp"
    assert "X670V-48x Port 34" in (link.source_port_desc or link.target_port_desc or "")

    neighbor = db_session.query(Asset).filter(Asset.hostname == "noc-1g").one()
    assert neighbor.device_category == "switch"
    assert neighbor.discovery_method == "topology"


# ── Duplicate default hostnames ──────────────────────────────────────────────


def test_devices_sharing_a_default_hostname_stay_distinct(db_session, test_org, scan):
    """
    Two X460-48t switches on ports 41 and 43 both report sysName "X460-48t" —
    the factory default. Resolving on hostname merged them into one asset,
    losing a switch and inventing adjacency between their neighbours.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.1")
    walk.sys_name = "NOC-10G"
    walk.ip_forwarding = 1
    walk.interface_table = {
        "1041": InterfaceInfo(if_index="1041", descr="X670V-48x Port 41"),
        "1043": InterfaceInfo(if_index="1043", descr="X670V-48x Port 43"),
    }
    walk.edp_neighbors = [
        EDPNeighbor("X460-48t", "00:04:96:83:64:0c", "1041"),
        EDPNeighbor("X460-48t", "00:04:96:83:66:4b", "1043"),
    ]

    result = _run(db_session, test_org, scan, {"10.180.4.1": walk}, ["10.180.4.1"])

    assert result["total_links"] == 2, "two cables, two links"
    peers = db_session.query(Asset).filter(Asset.hostname == "X460-48t").all()
    assert len(peers) == 2, "distinct switches must not merge on a shared name"
    assert {str(a.mac_address) for a in peers} == {
        "00:04:96:83:64:0c",
        "00:04:96:83:66:4b",
    }


def test_ambiguous_hostname_never_resolves(db_session, test_org):
    for mac in ("00:04:96:83:64:0c", "00:04:96:83:66:4b"):
        db_session.add(
            Asset(
                id=f"ast-{uuid.uuid4().hex[:10]}",
                org_id=test_org.id,
                mac_address=mac,
                hostname="X460-48t",
                discovery_method="test",
            )
        )
    db_session.commit()

    index = AssetIndex(db_session, test_org.id)
    # Name alone is now meaningless and must not pick one arbitrarily.
    assert index.resolve(make_endpoint(raw_id="X460-48t")) is None
    # A MAC still resolves precisely.
    assert (
        str(index.resolve(make_endpoint(raw_id="00:04:96:83:64:0c")).mac_address)
        == "00:04:96:83:64:0c"
    )


def test_unmatched_mac_does_not_fall_back_to_hostname(db_session, test_org):
    """
    A MAC is a strong identifier. When it matches nothing, the endpoint is a
    device we have not seen — not a reason to attach it to a similarly named one.
    """
    db_session.add(
        Asset(
            id=f"ast-{uuid.uuid4().hex[:10]}",
            org_id=test_org.id,
            mac_address="00:04:96:83:64:0c",
            hostname="core-sw",
            discovery_method="test",
        )
    )
    db_session.commit()

    index = AssetIndex(db_session, test_org.id)
    endpoint = make_endpoint(raw_id="00:aa:aa:aa:aa:aa", name="core-sw")
    assert index.resolve(endpoint) is None


# ── Port precedence ──────────────────────────────────────────────────────────


def test_neighbour_protocol_port_beats_arp_l3_interface():
    """
    A switch's ARP entry for its neighbour is learned on the routed VLAN
    interface it replied through — "rtif(10.180.4.1/22)" — while EDP names the
    physical port the cable occupies. ARP is walked first, so without ranking by
    evidence the topology link was labelled with a VLAN interface.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.1")
    walk.interface_table = {
        "1000106": InterfaceInfo(if_index="1000106", descr="rtif(10.180.4.1/22)"),
        "1034": InterfaceInfo(if_index="1034", descr="X670V-48x Port 34"),
    }
    from core.topology.client import ARPEntry

    walk.arp_table = [ARPEntry("10.180.4.3", "00:04:96:83:64:ac", "1000106")]
    walk.edp_neighbors = [
        EDPNeighbor("noc-1g", "00:04:96:83:64:ac", "1034"),
    ]

    local = make_endpoint(raw_id=None, ip="10.180.4.1", name="NOC-10G")
    merged = merge_observations(observations_from_walk(walk, local), "acme")

    assert len(merged) == 1
    link = next(iter(merged.values()))
    assert link.link_type == "edp"
    assert link.observed_types == {"arp", "edp"}
    ports = {link.first_port, link.second_port}
    descs = {link.first_port_desc, link.second_port_desc}
    assert "if1034" in ports, "physical port must win over the L3 interface"
    assert "X670V-48x Port 34" in descs
    assert "rtif(10.180.4.1/22)" not in descs


# ── Vendor VLAN inventory must not drive per-VLAN FDB walks ──────────────────


@patch("core.topology.client._build_snmp_engine")
@patch("core.topology.client._snmp_get_async")
@patch("core.topology.client._snmp_walk_async")
def test_vendor_vlan_inventory_does_not_trigger_community_indexed_walks(
    mock_walk, mock_get, mock_engine
):
    """
    EXTREME-VLAN-MIB lists 50 VLANs. Feeding those into the Cisco
    community-indexed FDB walk fired 64 queries at communities EXOS never
    answers, each costing a full timeout — 240s and a truncated walk. Only the
    standard/Cisco port-VLAN tables may seed that walk.
    """
    from core.topology.client import (
        OID_CISCO_VM_VLAN,
        OID_DOT1Q_PVID,
        OID_EXTREME_VLAN_NAME,
        OID_EXTREME_VLAN_TAG,
    )

    mock_engine.return_value = (MagicMock(), MagicMock(), MagicMock(), MagicMock())

    async def _get(*args, **kwargs):
        return None

    mock_get.side_effect = _get

    vlan_communities = []

    async def side_effect_walk(
        engine, auth, transport, context, oid, max_rows=0, use_bulk=True
    ):
        community = str(getattr(auth, "communityName", "") or "")
        if "@" in community:
            vlan_communities.append(community)
        if oid == OID_EXTREME_VLAN_TAG:
            # 50 Extreme VLANs, exactly as the live device reports.
            return [
                (f"{OID_EXTREME_VLAN_TAG}.{1000000 + i}", 10 + i) for i in range(50)
            ]
        if oid == OID_EXTREME_VLAN_NAME:
            return [
                (f"{OID_EXTREME_VLAN_NAME}.{1000000 + i}", f"vlan-{i}")
                for i in range(50)
            ]
        if oid in (OID_DOT1Q_PVID, OID_CISCO_VM_VLAN):
            return []  # Q-BRIDGE unsupported, as on EXOS
        return []

    mock_walk.side_effect = side_effect_walk

    result = walk_target("10.180.4.1", SNMPCredentials(version="v2c"))

    assert vlan_communities == [], (
        "Extreme VLAN inventory must not drive Cisco community-indexed FDB "
        f"walks, but these were attempted: {vlan_communities[:5]}"
    )
    assert result.capabilities["extreme_vlan"] == 50


# ── Per-port VLAN membership ─────────────────────────────────────────────────


def test_decode_port_list_uses_8021q_bit_order():
    """
    First octet covers ports 1-8 with the MSB as port 1. Decoded against the
    live device this put all six inter-switch uplinks in the multi-VLAN set and
    left access ports single-VLAN, which is the expected shape of a real estate.
    """
    from core.topology.client import _decode_port_list

    assert _decode_port_list(b"\x80") == [1]
    assert _decode_port_list(b"\x01") == [8]
    assert _decode_port_list(b"\xa0") == [1, 3]
    assert _decode_port_list(b"\x00\x04") == [14]
    # Real bitmap from VLAN 88 ("un-lan") on the live X670V.
    assert _decode_port_list(bytes.fromhex("a004007774500000")) == [
        1,
        3,
        14,
        26,
        27,
        28,
        30,
        31,
        32,
        34,
        35,
        36,
        38,
        42,
        44,
    ]
    assert _decode_port_list(None) == []
    assert _decode_port_list("not-bytes") == []


@patch("core.topology.client._build_snmp_engine")
@patch("core.topology.client._snmp_get_async")
@patch("core.topology.client._snmp_walk_async")
def test_only_single_vlan_ports_get_a_vlan(mock_walk, mock_get, mock_engine):
    """
    A trunk carrying nine VLANs has no single VLAN. Assigning one would stamp a
    wrong VLAN onto every endpoint reachable through it — and on the live device
    every inter-switch uplink is exactly such a trunk.
    """
    from core.topology.client import (
        OID_BRIDGE_PORT_IF_INDEX,
        OID_EXTREME_VLAN_NAME,
        OID_EXTREME_VLAN_PORTS,
        OID_EXTREME_VLAN_TAG,
        OID_IF_DESCR,
    )

    mock_engine.return_value = (MagicMock(), MagicMock(), MagicMock(), MagicMock())

    async def _get(*a, **k):
        return None

    mock_get.side_effect = _get

    # VLAN 30 on port 2 only; VLAN 88 on ports 2 and 34 -> port 2 is ambiguous,
    # port 34 is a trunk member. Port 4 belongs to VLAN 70 alone.
    vlan_ifindex_30, vlan_ifindex_70, vlan_ifindex_88 = "1000010", "1000020", "1000030"

    def bitmap(*ports):
        raw = bytearray(8)
        for p in ports:
            raw[(p - 1) // 8] |= 0x80 >> ((p - 1) % 8)
        return bytes(raw)

    async def side_effect_walk(
        engine, auth, transport, context, oid, max_rows=0, use_bulk=True
    ):
        if oid == OID_IF_DESCR:
            return [
                (f"{OID_IF_DESCR}.{1000 + p}", MockOctets(f"X670V Port {p}"))
                for p in (2, 4, 34)
            ]
        if oid == OID_BRIDGE_PORT_IF_INDEX:
            return [
                (f"{OID_BRIDGE_PORT_IF_INDEX}.{p}", str(1000 + p)) for p in (2, 4, 34)
            ]
        if oid == OID_EXTREME_VLAN_TAG:
            return [
                (f"{OID_EXTREME_VLAN_TAG}.{vlan_ifindex_30}", 30),
                (f"{OID_EXTREME_VLAN_TAG}.{vlan_ifindex_70}", 70),
                (f"{OID_EXTREME_VLAN_TAG}.{vlan_ifindex_88}", 88),
            ]
        if oid == OID_EXTREME_VLAN_NAME:
            return [
                (f"{OID_EXTREME_VLAN_NAME}.{vlan_ifindex_30}", MockOctets("cmvt")),
                (f"{OID_EXTREME_VLAN_NAME}.{vlan_ifindex_70}", MockOctets("gw")),
                (f"{OID_EXTREME_VLAN_NAME}.{vlan_ifindex_88}", MockOctets("un-lan")),
            ]
        if oid == OID_EXTREME_VLAN_PORTS:
            return [
                (f"{OID_EXTREME_VLAN_PORTS}.1.{vlan_ifindex_30}.1", bitmap(2, 34)),
                (f"{OID_EXTREME_VLAN_PORTS}.1.{vlan_ifindex_70}.1", bitmap(4)),
                (f"{OID_EXTREME_VLAN_PORTS}.1.{vlan_ifindex_88}.1", bitmap(2, 34)),
            ]
        return []

    mock_walk.side_effect = side_effect_walk

    result = walk_target("10.180.4.1", SNMPCredentials(version="v2c"))

    # Port 4 sits in one VLAN and gets it.
    assert result.interface_table["1004"].vlan_id == 70
    # Ports 2 and 34 are in two VLANs each — ambiguous, so no VLAN is invented.
    assert result.interface_table["1002"].vlan_id == 0
    assert result.interface_table["1034"].vlan_id == 0
    assert result.capabilities["extreme_vlan_ports"] == 3


class MockOctets:
    """Minimal stand-in for a pysnmp OctetString."""

    def __init__(self, text):
        self._raw = text.encode()

    def asOctets(self):
        return self._raw

    def __str__(self):
        return self._raw.decode()


# ── Capability reporting ─────────────────────────────────────────────────────


def test_walk_reports_capabilities_so_empty_is_not_mistaken_for_success():
    walk = SNMPWalkResult(target_ip="10.180.4.1")
    assert walk.neighbor_protocols == []

    walk.edp_neighbors = [EDPNeighbor("noc-1g", "00:04:96:83:64:ac", "1034")]
    assert walk.neighbor_protocols == ["edp"]
    assert walk.has_data is True


def test_reciprocal_reports_keep_each_side_its_own_port():
    """
    Live shape: NOC-10G reports noc-1g on its Port 34 while noc-1g reports
    NOC-10G on its Port 54. That is one cable, and the merged row must carry
    both ports on the correct sides rather than one side's view twice.
    """
    core = SNMPWalkResult(target_ip="10.180.4.1")
    core.interface_table = {"1034": InterfaceInfo("1034", descr="X670V-48x Port 34")}
    core.edp_neighbors = [EDPNeighbor("noc-1g", "00:04:96:83:64:ac", "1034")]

    spoke = SNMPWalkResult(target_ip="10.180.4.3")
    spoke.interface_table = {"1054": InterfaceInfo("1054", descr="X460-48t Port 54")}
    spoke.edp_neighbors = [EDPNeighbor("NOC-10G", "00:04:96:82:70:ee", "1054")]

    core_ep = make_endpoint(raw_id="00:04:96:82:70:ee", ip="10.180.4.1", name="NOC-10G")
    spoke_ep = make_endpoint(raw_id="00:04:96:83:64:ac", ip="10.180.4.3", name="noc-1g")

    observations = observations_from_walk(core, core_ep) + observations_from_walk(
        spoke, spoke_ep
    )
    merged = merge_observations(observations, "acme")

    assert len(merged) == 1, "one cable must not produce two rows"
    link = next(iter(merged.values()))
    assert {link.first_port, link.second_port} == {"if1034", "if1054"}
    assert {link.first_port_desc, link.second_port_desc} == {
        "X670V-48x Port 34",
        "X460-48t Port 54",
    }

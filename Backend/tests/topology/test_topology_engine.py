"""
Correlation-engine tests for the topology module.

`run_topology_mapping` is exercised against the real database so that endpoint
identity, asset reconciliation and the upsert path are all covered — several of
the defects these tests pin only appear when a PostgreSQL MACADDR column or a
real unique constraint is involved.
"""

from native_rbac import system_role, create_user

import uuid
from unittest.mock import patch

import pytest
from core.topology.client import (
    ARPEntry,
    CDPNeighbor,
    FDBEntry,
    InterfaceInfo,
    LLDPNeighbor,
    SNMPWalkResult,
)
from core.topology.engine import run_topology_mapping
from db.models import Asset, NetworkLink, Scan


@pytest.fixture()
def scan(db_session, test_org):
    row = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        status="completed",
        target_hosts=["10.180.4.10"],
        target_str="10.180.4.10",
    )
    db_session.add(row)
    db_session.commit()
    return row


def _run(db_session, org, scan, walks: dict, targets: list[str]):
    """Run the pipeline with `walks` standing in for live SNMP responses."""
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


# ── Identity: non-MAC endpoint identifiers ───────────────────────────────────


def test_target_without_known_mac_does_not_break_the_run(db_session, test_org, scan):
    """
    A switch whose MAC inventory has not learned is the normal case for gear
    outside the scanner's own L2 segment. The endpoint used to be given a
    synthetic 'sw:10:180:4:10' identifier that was then compared against
    Asset.mac_address — a MACADDR column — raising InvalidTextRepresentation
    and aborting the whole mapping run.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.arp_table = [
        ARPEntry(
            ip_address="10.180.4.15",
            mac_address="00:11:22:33:44:55",
            interface_index="10",
        )
    ]

    result = _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    assert result["success"] is True
    assert result["links_created"] == 1
    link = db_session.query(NetworkLink).one()

    # The walked device is identified by the asset it resolves to, and the MAC
    # column stays empty rather than holding a synthetic stand-in.
    source = db_session.get(Asset, link.source_asset_id)
    assert source is not None
    assert str(source.ip_address) == "10.180.4.10"
    assert link.source_key == f"asset:{source.id}"
    assert link.source_mac is None
    assert link.source_ip == "10.180.4.10"
    assert link.target_mac == "00:11:22:33:44:55"
    assert link.target_ip == "10.180.4.15"


def test_non_mac_chassis_and_device_ids_are_handled(db_session, test_org, scan):
    """
    LLDP chassis IDs use a subtype: subtype 7 is a locally assigned string and
    subtype 5 a network address, so a chassis ID is frequently not a MAC. CDP
    device IDs are hostnames by design.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="core-sw-01",
            port_id="Gi1/0/1",
            system_name="core-sw-01",
            local_port_index="1",
        )
    ]
    walk.cdp_neighbors = [
        CDPNeighbor(
            device_id="edge-sw-02.corp.local",
            ip_address="10.180.4.3",
            device_port="Gi0/2",
            local_port_index="2",
        )
    ]

    result = _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    assert result["success"] is True
    assert result["links_created"] == 2

    by_type = {link.link_type: link for link in db_session.query(NetworkLink).all()}
    assert by_type["lldp"].target_key == "name:core-sw-01"
    assert by_type["lldp"].target_mac is None
    assert by_type["cdp"].target_key == "ip:10.180.4.3"

    # Both neighbours are enrolled as infrastructure assets.
    lldp_asset = db_session.get(Asset, by_type["lldp"].target_asset_id)
    assert lldp_asset.hostname == "core-sw-01"
    assert lldp_asset.device_category == "switch"
    assert lldp_asset.discovery_method == "topology"


# ── Evidence ranking ─────────────────────────────────────────────────────────


def test_lldp_evidence_survives_an_fdb_entry_for_the_same_neighbour(
    db_session, test_org, scan
):
    """
    A neighbouring switch discovered over LLDP almost always also appears in the
    local FDB. FDB is walked last, and the merge used to keep whichever
    observation arrived last, so the adjacency was downgraded to 'fdb', lost its
    hostname, and was never enrolled as infrastructure.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="00:aa:bb:cc:dd:ee",
            port_id="Gi1/0/1",
            system_name="core-sw-01",
            local_port_index="24",
        )
    ]
    walk.fdb_table = [FDBEntry(mac_address="00:aa:bb:cc:dd:ee", port_index="24")]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    link = db_session.query(NetworkLink).one()
    assert link.link_type == "lldp"
    assert set(link.observed_types.split(",")) == {"fdb", "lldp"}
    assert link.target_port == "Gi1/0/1"

    neighbor = db_session.get(Asset, link.target_asset_id)
    assert neighbor.hostname == "core-sw-01"
    assert neighbor.device_category == "switch"


def test_reciprocal_reports_of_one_wire_collapse_to_one_row(db_session, test_org, scan):
    """
    Two switches each report the other over LLDP. That is one wire. The upsert
    used to leave source_mac from the first report alongside source_port and
    source_asset_id from the second — a row describing neither device.
    """
    a = SNMPWalkResult(target_ip="10.180.4.10")
    a.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="00:bb:bb:bb:bb:bb",
            port_id="Gi1/0/2",
            system_name="sw-b",
            local_port_index="1",
        )
    ]
    b = SNMPWalkResult(target_ip="10.180.4.11")
    b.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="00:aa:aa:aa:aa:aa",
            port_id="Gi1/0/1",
            system_name="sw-a",
            local_port_index="2",
        )
    ]

    for ip, mac, host in (
        ("10.180.4.10", "00:aa:aa:aa:aa:aa", "sw-a"),
        ("10.180.4.11", "00:bb:bb:bb:bb:bb", "sw-b"),
    ):
        db_session.add(
            Asset(
                id=f"ast-{uuid.uuid4().hex[:10]}",
                org_id=test_org.id,
                ip_address=ip,
                mac_address=mac,
                hostname=host,
                device_category="switch",
                discovery_method="test",
            )
        )
    db_session.commit()

    result = _run(
        db_session,
        test_org,
        scan,
        {"10.180.4.10": a, "10.180.4.11": b},
        ["10.180.4.10", "10.180.4.11"],
    )

    assert result["total_links"] == 1
    link = db_session.query(NetworkLink).one()

    # Endpoints are stored in canonical order, and each side's port belongs to
    # the endpoint recorded on that side.
    assert link.source_key < link.target_key
    source = db_session.get(Asset, link.source_asset_id)
    target = db_session.get(Asset, link.target_asset_id)
    assert source.mac_address == link.source_mac
    assert target.mac_address == link.target_mac
    assert {link.source_port, link.target_port} == {"if1", "if2"}


# ── Interface enrichment ─────────────────────────────────────────────────────


def test_arp_port_detail_uses_ifindex_not_bridge_port(db_session, test_org, scan):
    """
    ARP, LLDP and CDP index the ifTable; only FDB uses dot1dBasePort. Routing
    every lookup through the bridge-port map attached a different physical
    port's description, VLAN and speed to ARP/LLDP/CDP links, because bridge
    port numbers and ifIndexes overlap.
    """
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.interface_table = {
        "1": InterfaceInfo(
            if_index="1", descr="GigabitEthernet1/0/1", speed_bps=1_000_000_000
        ),
        "10101": InterfaceInfo(
            if_index="10101", descr="GigabitEthernet2/0/48", speed_bps=10_000_000_000
        ),
    }
    # Bridge port "1" maps to a completely different interface.
    walk.bridge_port_map = {"1": "10101"}
    walk.arp_table = [
        ARPEntry(
            ip_address="10.180.4.15",
            mac_address="00:11:22:33:44:55",
            interface_index="1",
        )
    ]
    walk.fdb_table = [FDBEntry(mac_address="00:11:22:33:44:66", port_index="1")]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    links = {link.link_type: link for link in db_session.query(NetworkLink).all()}
    # ARP ifIndex 1 → the real ifIndex 1
    assert links["arp"].source_port_desc == "GigabitEthernet1/0/1"
    assert links["arp"].speed_bps == 1_000_000_000
    # FDB bridge port 1 → ifIndex 10101
    assert links["fdb"].source_port_desc == "GigabitEthernet2/0/48"
    assert links["fdb"].speed_bps == 10_000_000_000


def test_vlan_enrichment_reaches_the_endpoint_asset(db_session, test_org, scan):
    endpoint = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="10.180.4.15",
        mac_address="00:11:22:33:44:55",
        hostname="ws-1",
        discovery_method="test",
    )
    db_session.add(endpoint)
    db_session.commit()

    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.interface_table = {
        "10": InterfaceInfo(
            if_index="10",
            descr="GigabitEthernet1/0/10",
            speed_bps=1_000_000_000,
            vlan_id=100,
        )
    }
    walk.arp_table = [
        ARPEntry(
            ip_address="10.180.4.15",
            mac_address="00:11:22:33:44:55",
            interface_index="10",
        )
    ]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    db_session.refresh(endpoint)
    assert endpoint.vlan_id == 100
    assert db_session.query(NetworkLink).one().vlan_id == 100


def test_sentinel_vlans_are_not_recorded(db_session, test_org, scan):
    """VLAN 0 and 4095 are 802.1Q sentinels, not memberships."""
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.interface_table = {
        "10": InterfaceInfo(if_index="10", descr="Gi1/0/10", vlan_id=4095)
    }
    walk.fdb_table = [FDBEntry(mac_address="00:11:22:33:44:55", port_index="10")]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])
    assert db_session.query(NetworkLink).one().vlan_id is None


# ── Device classification ────────────────────────────────────────────────────


def test_windows_host_is_not_classified_as_a_router(db_session, test_org, scan):
    """
    Windows' SNMP agent reports sysServices 76/79 — the internet bit is set on
    ordinary workstations and servers. Testing `sysServices & 4` therefore
    labelled every Windows host a router. ipForwarding states the real role.
    """
    host = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="10.180.4.10",
        hostname="file-server",
        device_category="host",
        discovery_method="test",
    )
    db_session.add(host)
    db_session.commit()

    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.sys_services = 76  # application + end-to-end + internet
    walk.ip_forwarding = 2  # not-forwarding
    walk.arp_table = [
        ARPEntry(ip_address="10.180.4.1", mac_address="00:aa:bb:cc:dd:01")
    ]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    db_session.refresh(host)
    assert host.device_category == "host"


def test_forwarding_device_is_classified_as_router(db_session, test_org, scan):
    router = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="10.180.4.10",
        hostname="noc-rtr",
        device_category="host",
        discovery_method="test",
    )
    db_session.add(router)
    db_session.commit()

    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.sys_services = 6
    walk.ip_forwarding = 1
    walk.arp_table = [
        ARPEntry(ip_address="10.180.4.15", mac_address="00:11:22:33:44:55")
    ]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    db_session.refresh(router)
    assert router.device_category == "router"


def test_bridging_device_is_classified_as_switch(db_session, test_org, scan):
    switch = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="10.180.4.10",
        hostname="access-01",
        device_category="unknown",
        discovery_method="test",
    )
    db_session.add(switch)
    db_session.commit()

    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.sys_services = 2
    walk.bridge_port_map = {"1": "10101"}
    walk.fdb_table = [FDBEntry(mac_address="00:11:22:33:44:55", port_index="1")]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    db_session.refresh(switch)
    assert switch.device_category == "switch"


def test_specific_inventory_category_is_never_overwritten(db_session, test_org, scan):
    printer = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="10.180.4.10",
        hostname="hp-lj-3",
        device_category="printer",
        discovery_method="test",
    )
    db_session.add(printer)
    db_session.commit()

    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.sys_services = 2
    walk.fdb_table = [FDBEntry(mac_address="00:11:22:33:44:55", port_index="1")]

    _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])

    db_session.refresh(printer)
    assert printer.device_category == "printer"


# ── Hygiene ──────────────────────────────────────────────────────────────────


def test_broadcast_and_multicast_entries_are_filtered(db_session, test_org, scan):
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.fdb_table = [
        FDBEntry(mac_address="ff:ff:ff:ff:ff:ff", port_index="1"),
        FDBEntry(mac_address="01:00:5e:00:00:fb", port_index="1"),  # IPv4 multicast
        FDBEntry(mac_address="33:33:00:00:00:01", port_index="1"),  # IPv6 multicast
        FDBEntry(mac_address="00:00:00:00:00:00", port_index="1"),
        FDBEntry(mac_address="00:11:22:33:44:55", port_index="1"),
    ]

    result = _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])
    assert result["total_links"] == 1
    assert db_session.query(NetworkLink).one().target_mac == "00:11:22:33:44:55"


def test_device_reporting_itself_creates_no_self_link(db_session, test_org, scan):
    db_session.add(
        Asset(
            id=f"ast-{uuid.uuid4().hex[:10]}",
            org_id=test_org.id,
            ip_address="10.180.4.10",
            mac_address="00:aa:aa:aa:aa:aa",
            hostname="sw-a",
            device_category="switch",
            discovery_method="test",
        )
    )
    db_session.commit()

    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.fdb_table = [FDBEntry(mac_address="00:aa:aa:aa:aa:aa", port_index="1")]

    result = _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])
    assert result["total_links"] == 0


def test_rerunning_updates_rather_than_duplicates(db_session, test_org, scan):
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.arp_table = [
        ARPEntry(ip_address="10.180.4.15", mac_address="00:11:22:33:44:55")
    ]

    first = _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])
    assert (first["links_created"], first["links_updated"]) == (1, 0)
    first_seen = db_session.query(NetworkLink).one().first_seen_at

    second = _run(db_session, test_org, scan, {"10.180.4.10": walk}, ["10.180.4.10"])
    assert (second["links_created"], second["links_updated"]) == (0, 1)
    assert db_session.query(NetworkLink).count() == 1

    db_session.expire_all()
    row = db_session.query(NetworkLink).one()
    assert row.first_seen_at == first_seen  # history is preserved
    assert row.last_seen_at >= first_seen


def test_unresponsive_targets_are_never_walked(db_session, test_org, scan):
    """Probing first is what keeps a /24 of workstations from costing hours."""
    walked = []

    def _walk(ip, creds):
        walked.append(ip)
        return SNMPWalkResult(target_ip=ip)

    with (
        patch(
            "core.topology.client.probe_snmp",
            side_effect=lambda ip, c: ip.endswith(".1"),
        ),
        patch("core.topology.client.walk_target", side_effect=_walk),
    ):
        result = run_topology_mapping(
            db=db_session,
            scan_id=scan.id,
            org_id=test_org.id,
            org_slug=test_org.slug,
            snmp_config={"version": "v2c", "community": "public"},
            target_ips=["10.180.4.1", "10.180.4.2", "10.180.4.3"],
        )

    assert walked == ["10.180.4.1"]
    assert result["targets_walked"] == 0  # responded, but returned no tables


# ── Asset reconciliation ─────────────────────────────────────────────────────


def test_reconcile_prefers_mac_then_ip_and_hostname(db_session, test_org):
    from core.topology.engine import AssetIndex
    from core.topology.identity import make_endpoint

    asset_a = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="10.180.6.140",
        mac_address="00:11:22:33:44:55",
        hostname="Laptop-A",
        discovery_method="discovery",
    )
    asset_b = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=test_org.id,
        ip_address="192.168.1.20",
        mac_address="00:11:22:33:44:66",
        hostname="Phone-B",
        discovery_method="discovery",
    )
    db_session.add_all([asset_a, asset_b])
    db_session.commit()

    index = AssetIndex(db_session, test_org.id)

    def resolve(**kwargs):
        endpoint = make_endpoint(**kwargs)
        return index.resolve(endpoint) if endpoint else None

    # MAC wins even when the IP has moved — L2 identity survives a DHCP lease.
    matched = resolve(raw_id="00:11:22:33:44:55", ip="192.168.1.30", name="NewName")
    assert matched.id == asset_a.id

    # IP + hostname corroborate each other when no MAC is available.
    assert resolve(ip="192.168.1.20", name="Phone-B").id == asset_b.id

    # IP alone still resolves when the hostname disagrees.
    assert resolve(ip="192.168.1.20", name="Laptop-C").id == asset_b.id

    # A device known only by a name nothing matches resolves to nothing rather
    # than being attached to an arbitrary asset.
    assert resolve(raw_id="ghost-switch") is None

    # Hostname alone does resolve when it is unambiguous — this is how a CDP
    # neighbour with no management address finds its inventory record.
    assert resolve(raw_id="Phone-B").id == asset_b.id


def test_sync_host_discovery_mac_first_and_ip_hijack(db_session, test_org):
    from scans.asset_syncer import sync_host_discovery

    asset_a = Asset(
        id=f"ast_{test_org.slug}_192_168_1_5",
        org_id=test_org.id,
        ip_address="192.168.1.5",
        mac_address="00:11:22:33:44:55",
        hostname="Laptop-A",
        discovery_method="discovery",
    )
    asset_b = Asset(
        id=f"ast_{test_org.slug}_192_168_1_6",
        org_id=test_org.id,
        ip_address="192.168.1.6",
        mac_address="00:11:22:33:44:66",
        hostname="Phone-B",
        discovery_method="discovery",
    )
    db_session.add_all([asset_a, asset_b])
    db_session.commit()

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=test_org.id,
            status="completed",
            target_str="10.180.6.0/24",
        )
    )
    db_session.commit()

    # Laptop-A moves onto the IP that Phone-B used to hold.
    sync_host_discovery(
        db_session,
        scan_id,
        test_org.id,
        user_id=None,
        hosts=[
            {
                "ip_address": "192.168.1.6",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "Laptop-A",
                "state": "up",
                "is_active": True,
            }
        ],
    )

    db_session.refresh(asset_a)
    db_session.refresh(asset_b)
    assert asset_a.ip_address == "192.168.1.6"
    assert asset_b.ip_address is None
    assert asset_b.is_active is False


def test_sync_credentialed_asset_identity_mac_first_and_ip_hijack(db_session, test_org):
    from core.tasks import _sync_credentialed_asset_identity

    asset_a = Asset(
        id=f"ast_{test_org.slug}_192_168_1_5",
        org_id=test_org.id,
        ip_address="192.168.1.5",
        mac_address="00:11:22:33:44:55",
        hostname="Laptop-A",
        discovery_method="credentialed",
    )
    asset_b = Asset(
        id=f"ast_{test_org.slug}_192_168_1_6",
        org_id=test_org.id,
        ip_address="192.168.1.6",
        mac_address="00:11:22:33:44:66",
        hostname="Phone-B",
        discovery_method="credentialed",
    )
    uid = uuid.uuid4().hex[:8]
    role = system_role(db_session, "platform.org_admin")
    user = create_user(
        db_session,
        id=f"scanner-user-{uid}",
        org_id=test_org.id,
        email=f"scanner-{uid}@ccurepro.com",
        username=f"scanner-{uid}",
        password_hash="...",
        role=role,
    )
    db_session.add_all([asset_a, asset_b, user])
    db_session.commit()

    scan_id = f"scan-{uuid.uuid4().hex[:8]}"
    db_session.add(
        Scan(
            id=scan_id,
            org_id=test_org.id,
            status="completed",
            target_str="10.180.6.0/24",
        )
    )
    db_session.commit()

    _sync_credentialed_asset_identity(
        db_session,
        user_id=user.id,
        ip="192.168.1.6",
        scan_id=scan_id,
        os_type="linux",
        system_data={
            "mac_address": "00:11:22:33:44:55",
            "os_name": "Ubuntu 22.04",
            "hostname": "Laptop-A",
        },
        stored_report={},
        cve_list=[],
        severity_counts={},
    )

    db_session.refresh(asset_a)
    db_session.refresh(asset_b)
    assert asset_a.ip_address == "192.168.1.6"
    assert asset_b.ip_address is None
    assert asset_b.is_active is False

"""
Graph-rendering tests for the topology module.

These run against the real database session rather than a stub query object:
the graph reads `NetworkLink.source_asset` / `target_asset` relationships and
keys nodes on resolved asset IDs, so a fake that returns bare namespaces cannot
show whether the rendering is actually correct.
"""

import uuid

import pytest
from core.topology.engine import get_topology_graph
from db.base import gen_network_link_id
from db.models import Asset, NetworkLink, Scan


@pytest.fixture()
def scan(db_session, test_org):
    row = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        status="completed",
        target_str="10.180.4.0/24",
    )
    db_session.add(row)
    db_session.commit()
    return row


def _asset(db_session, org, ip=None, mac=None, hostname=None, category=None, **kw):
    asset = Asset(
        id=f"ast-{uuid.uuid4().hex[:10]}",
        org_id=org.id,
        ip_address=ip,
        mac_address=mac,
        hostname=hostname,
        device_category=category,
        discovery_method="test",
        **kw,
    )
    db_session.add(asset)
    db_session.commit()
    return asset


def _link(db_session, org, scan, source_key, target_key, **overrides):
    data = {
        "id": gen_network_link_id(org.slug, source_key, target_key),
        "org_id": org.id,
        "scan_id": scan.id,
        "source_key": source_key,
        "target_key": target_key,
        "source_mac": (
            source_key if ":" in source_key and "ip:" not in source_key else None
        ),
        "target_mac": (
            target_key if ":" in target_key and "ip:" not in target_key else None
        ),
        "link_type": "fdb",
        "observed_types": "fdb",
    }
    data.update(overrides)
    row = NetworkLink(**data)
    db_session.add(row)
    db_session.commit()
    return row


def test_mac_only_cluster_reports_quality_and_evidence(db_session, test_org, scan):
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:55",
        source_ip="10.180.4.1",
        source_port="port:12",
    )
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:66",
        source_ip="10.180.4.1",
        source_port="port:14",
    )

    graph = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)

    cluster = next(n for n in graph["nodes"] if n["id"] == "subnet:MAC-Only / FDB")
    assert graph["graph_version"] == 3
    assert cluster["group"] == "mac_only_cluster"
    assert cluster["host_count"] == 2
    assert cluster["data_quality"]["mac_only"] == 2
    assert cluster["data_quality"]["ip_resolved"] == 0
    assert cluster["data_quality"]["source_count"] == 1
    assert "Run ARP-enabled scan" in cluster["recommended_actions"]

    host = next(n for n in graph["nodes"] if n.get("mac") == "00:11:22:33:44:55")
    assert host["subnet"] == "MAC-Only / FDB"
    assert host["source_port"] == "port:12"
    assert host["asset_match_status"] == "unmatched"

    edge = next(e for e in graph["edges"] if e["to"] == "subnet:MAC-Only / FDB")
    assert edge["host_count"] == 2
    assert edge["link_details"]["type_counts"] == {"fdb": 2}
    assert edge["link_details"]["ports"] == ["port:12", "port:14"]


def test_ip_subnet_counts_resolved_hosts(db_session, test_org, scan):
    asset = _asset(
        db_session,
        test_org,
        ip="10.180.4.15",
        mac="00:11:22:33:44:55",
        hostname="workstation-1",
        category="workstation",
        vendor="Acme",
    )
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:55",
        source_ip="10.180.4.1",
        target_ip="10.180.4.15",
        target_asset_id=asset.id,
        link_type="arp",
        observed_types="arp",
        source_port="if1",
    )

    graph = get_topology_graph(
        db_session, org_id=test_org.id, scan_id=scan.id, subnet_mask=24
    )

    cluster = next(n for n in graph["nodes"] if n["id"] == "subnet:10.180.4.0/24")
    assert cluster["data_quality"]["ip_resolved"] == 1
    assert cluster["data_quality"]["mac_only"] == 0
    assert cluster["data_quality"]["asset_matches"] == 1
    assert cluster["data_quality"]["has_arp"] is True

    host = next(n for n in graph["nodes"] if n.get("mac") == "00:11:22:33:44:55")
    assert host["vendor"] == "Acme"
    assert host["asset_match_status"] == "matched"
    assert host["label"] == "workstation-1"


def test_graph_includes_enriched_snmp_fields(db_session, test_org, scan):
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:55",
        source_ip="10.180.4.1",
        source_port="port:12",
        source_port_desc="GigabitEthernet1/0/12 (Uplink)",
        target_ip="10.180.4.15",
        vlan_id=100,
        speed_bps=1_000_000_000,
    )

    graph = get_topology_graph(
        db_session, org_id=test_org.id, scan_id=scan.id, subnet_mask=24
    )
    host = next(n for n in graph["nodes"] if n.get("mac") == "00:11:22:33:44:55")
    assert host["source_port"] == "port:12"
    assert host["source_port_desc"] == "GigabitEthernet1/0/12 (Uplink)"
    assert host["vlan_id"] == 100
    assert host["speed_bps"] == 1_000_000_000


def test_infra_to_infra_edge_carries_port_detail(db_session, test_org, scan):
    core = _asset(
        db_session, test_org, ip="10.180.4.1", hostname="core-sw", category="switch"
    )
    edge_sw = _asset(
        db_session,
        test_org,
        ip="10.180.4.2",
        mac="00:aa:bb:cc:dd:ee",
        hostname="edge-sw",
        category="switch",
    )
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:aa:bb:cc:dd:ee",
        source_ip="10.180.4.1",
        source_asset_id=core.id,
        target_asset_id=edge_sw.id,
        source_port="if24",
        source_port_desc="GigabitEthernet1/0/24",
        target_port="Gi1/0/1",
        target_port_desc="GigabitEthernet1/0/1",
        link_type="lldp",
        observed_types="lldp",
        vlan_id=200,
        speed_bps=10_000_000_000,
    )

    graph = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)

    edge = next(
        e
        for e in graph["edges"]
        if e["from"] == f"asset:{core.id}" and e["to"] == f"asset:{edge_sw.id}"
    )
    assert edge["source_port"] == "if24"
    assert edge["source_port_desc"] == "GigabitEthernet1/0/24"
    assert edge["target_port"] == "Gi1/0/1"
    assert edge["target_port_desc"] == "GigabitEthernet1/0/1"
    assert edge["vlan_id"] == 200
    assert edge["speed_bps"] == 10_000_000_000

    # Both ends render on the infrastructure tier, and neither is duplicated.
    tiers = {n["id"]: n["tier"] for n in graph["nodes"]}
    assert tiers[f"asset:{core.id}"] == "infra"
    assert tiers[f"asset:{edge_sw.id}"] == "infra"
    assert len(graph["nodes"]) == len({n["id"] for n in graph["nodes"]})


def test_device_appearing_as_source_and_target_yields_one_node(
    db_session, test_org, scan
):
    """
    A switch that is both a walk target and another device's ARP entry used to
    be emitted twice — once as an infra node keyed by its placeholder identity
    and once as a host node keyed by its MAC. Duplicate IDs make vis-network's
    DataSet.add() throw, which takes down the entire map.
    """
    router = _asset(
        db_session, test_org, ip="10.180.4.1", hostname="core-rtr", category="router"
    )
    # Inventory knows this switch by IP; SNMP has not yet learned its MAC, so it
    # is walked under its IP identity but reported by MAC from the router's ARP.
    switch = _asset(
        db_session,
        test_org,
        ip="10.180.4.2",
        mac="00:aa:bb:cc:dd:ee",
        hostname="access-sw",
        category="host",  # deliberately generic
    )

    # Router's ARP table sees the switch.
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:aa:bb:cc:dd:ee",
        source_ip="10.180.4.1",
        source_asset_id=router.id,
        target_ip="10.180.4.2",
        target_asset_id=switch.id,
        link_type="arp",
        observed_types="arp",
    )
    # The switch itself reports an endpoint from its own FDB.
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.2",
        "00:11:22:33:44:99",
        source_ip="10.180.4.2",
        source_asset_id=switch.id,
        link_type="fdb",
        observed_types="fdb",
    )

    graph = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)

    ids = [n["id"] for n in graph["nodes"]]
    assert len(ids) == len(set(ids)), "duplicate node ids would break the renderer"

    switch_nodes = [n for n in graph["nodes"] if n["id"] == f"asset:{switch.id}"]
    assert len(switch_nodes) == 1
    # It reports its own forwarding table, so it belongs on the infra tier.
    assert switch_nodes[0]["tier"] == "infra"


def test_active_within_days_excludes_stale_links(db_session, test_org, scan):
    from datetime import timedelta

    from db.base import utcnow

    fresh = _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:55",
        source_ip="10.180.4.1",
    )
    stale = _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:66",
        source_ip="10.180.4.1",
    )
    fresh.last_seen_at = utcnow()
    stale.last_seen_at = utcnow() - timedelta(days=90)
    db_session.commit()

    full = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)
    assert full["stats"]["hosts"] == 2

    recent = get_topology_graph(
        db_session, org_id=test_org.id, scan_id=scan.id, active_within_days=30
    )
    assert recent["stats"]["hosts"] == 1
    assert {n.get("mac") for n in recent["nodes"] if n["tier"] == "host"} == {
        "00:11:22:33:44:55"
    }


def test_endpoint_shows_its_strongest_evidence(db_session, test_org, scan):
    """
    An endpoint is usually seen by more than one switch. The drill-down should
    show the observation that says the most about where it lives — an ARP entry
    that resolved its IP, not an FDB entry that only saw a frame — rather than
    whichever row the query returned last.
    """
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.9",
        "00:11:22:33:44:55",
        source_ip="10.180.4.9",
        source_port="port:48",
        link_type="fdb",
        observed_types="fdb",
    )
    _link(
        db_session,
        test_org,
        scan,
        "ip:10.180.4.1",
        "00:11:22:33:44:55",
        source_ip="10.180.4.1",
        source_port="if1",
        target_ip="10.180.4.15",
        link_type="arp",
        observed_types="arp",
    )

    graph = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)
    host = next(n for n in graph["nodes"] if n.get("mac") == "00:11:22:33:44:55")
    assert host["link_type"] == "arp"
    assert host["source_port"] == "if1"
    assert host["source_key"] == "ip:10.180.4.1"

    # Both switches still show as sources of the subnet they observed it in.
    subnet_edges = [e for e in graph["edges"] if e["tier"] == "subnet"]
    assert {e["from"] for e in subnet_edges} == {"ip:10.180.4.1", "ip:10.180.4.9"}


def test_self_referential_link_is_dropped(db_session, test_org, scan):
    """A device that lists its own MAC in its own FDB is not adjacent to itself."""
    _link(
        db_session,
        test_org,
        scan,
        "00:11:22:33:44:55",
        "00:11:22:33:44:55",
        source_ip="10.180.4.1",
    )
    graph = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)
    assert graph["nodes"] == []
    assert graph["edges"] == []

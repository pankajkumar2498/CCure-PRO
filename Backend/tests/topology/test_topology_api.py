"""
End-to-end tests for the topology module: SNMP walk → correlation → persistence
→ HTTP payload.

These exercise the whole path a scan actually takes, so a contract break
between the engine and the API surfaces here rather than in the browser.
"""

import uuid
from unittest.mock import patch

import pytest
from core.topology.client import ARPEntry, InterfaceInfo, LLDPNeighbor, SNMPWalkResult
from db.models import Asset, NetworkLink, Organization, Scan


@pytest.fixture()
def scan(db_session, test_org, test_user):
    row = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        created_by=test_user.id,
        status="completed",
        target_hosts=["10.180.4.1", "10.180.4.2"],
        target_str="10.180.4.0/24",
    )
    db_session.add(row)
    db_session.commit()
    return row


def _core_network_walks():
    """
    A small but realistic network:

        core-rtr (10.180.4.1) ──LLDP── access-sw (10.180.4.2)
             │                              │
             └── ARP: ws-1, ws-2            └── FDB: printer
    """
    router = SNMPWalkResult(target_ip="10.180.4.1")
    router.sys_name = "core-rtr"
    router.sys_services = 6
    router.ip_forwarding = 1
    router.interface_table = {
        "1": InterfaceInfo(
            if_index="1", descr="GigabitEthernet0/0", speed_bps=1_000_000_000
        ),
        "24": InterfaceInfo(
            if_index="24",
            descr="GigabitEthernet0/24",
            alias="Uplink to access-sw",
            speed_bps=10_000_000_000,
            vlan_id=10,
        ),
    }
    router.arp_table = [
        ARPEntry("10.180.4.2", "00:aa:bb:cc:dd:02", "24"),
        ARPEntry("10.180.4.50", "00:11:22:33:44:50", "1"),
        ARPEntry("10.180.4.51", "00:11:22:33:44:51", "1"),
    ]
    router.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="00:aa:bb:cc:dd:02",
            port_id="Gi1/0/1",
            system_name="access-sw",
            local_port_index="24",
        )
    ]

    switch = SNMPWalkResult(target_ip="10.180.4.2")
    switch.sys_name = "access-sw"
    switch.sys_services = 2
    switch.interface_table = {
        "10101": InterfaceInfo(
            if_index="10101", descr="GigabitEthernet1/0/5", speed_bps=100_000_000
        )
    }
    switch.bridge_port_map = {"5": "10101"}
    switch.fdb_table = [
        # Bridge port 5 → ifIndex 10101. Also includes the router's own MAC,
        # which must not become a second edge in the wrong direction.
        __import__("core.topology.client", fromlist=["FDBEntry"]).FDBEntry(
            mac_address="00:11:22:33:44:60", port_index="5"
        ),
    ]
    return {"10.180.4.1": router, "10.180.4.2": switch}


def _run_mapping(db_session, org, scan, walks):
    from core.topology.engine import run_topology_mapping

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
            target_ips=list(walks.keys()),
        )


def test_full_pipeline_produces_a_coherent_map(
    db_session, test_org, test_user, scan, client, auth_headers
):
    for ip, mac, hostname in (
        ("10.180.4.1", "00:aa:bb:cc:dd:01", "core-rtr"),
        ("10.180.4.2", None, None),  # inventory has not learned the switch yet
    ):
        db_session.add(
            Asset(
                id=f"ast-{uuid.uuid4().hex[:10]}",
                org_id=test_org.id,
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                device_category="host",
                discovery_method="discovery",
            )
        )
    db_session.commit()

    result = _run_mapping(db_session, test_org, scan, _core_network_walks())
    assert result["success"] is True
    assert result["targets_walked"] == 2
    assert result["errors"] == []

    # ── Persistence ──────────────────────────────────────────────────────
    links = db_session.query(NetworkLink).all()
    # router↔switch (one wire, two protocols), router↔ws-1, router↔ws-2,
    # switch↔printer
    assert len(links) == 4

    uplink = next(link for link in links if link.link_type == "lldp")
    assert set(uplink.observed_types.split(",")) == {"arp", "lldp"}
    assert uplink.speed_bps == 10_000_000_000
    assert "Uplink to access-sw" in (
        uplink.source_port_desc or uplink.target_port_desc or ""
    )

    # Both walked devices were classified from what they reported.
    router_asset = (
        db_session.query(Asset).filter(Asset.ip_address == "10.180.4.1").one()
    )
    switch_asset = (
        db_session.query(Asset).filter(Asset.ip_address == "10.180.4.2").one()
    )
    assert router_asset.device_category == "router"
    assert switch_asset.device_category == "switch"
    assert switch_asset.hostname == "access-sw"

    # ── API payload ──────────────────────────────────────────────────────
    response = client.get(f"/topology/map/{scan.id}", headers=auth_headers)
    assert response.status_code == 200
    payload = response.json()
    assert payload["success"] is True
    assert payload["graph_version"] == 3

    node_ids = [n["id"] for n in payload["nodes"]]
    assert len(node_ids) == len(set(node_ids)), "duplicate ids break the renderer"

    by_id = {n["id"]: n for n in payload["nodes"]}
    router_node = by_id[f"asset:{router_asset.id}"]
    switch_node = by_id[f"asset:{switch_asset.id}"]
    assert router_node["tier"] == "infra" and router_node["group"] == "router"
    assert switch_node["tier"] == "infra" and switch_node["group"] == "switch"

    # The uplink renders as a single infra edge between the two devices.
    infra_edges = [e for e in payload["edges"] if e["tier"] == "infra"]
    assert len(infra_edges) == 1
    assert {infra_edges[0]["from"], infra_edges[0]["to"]} == {
        router_node["id"],
        switch_node["id"],
    }

    # Endpoints are clustered by subnet, and every edge resolves to a real node.
    assert payload["subnets"] == ["10.180.4.0/24", "MAC-Only / FDB"]
    all_ids = set(node_ids)
    for edge in payload["edges"]:
        assert edge["from"] in all_ids and edge["to"] in all_ids

    assert payload["stats"]["hosts"] == 3  # ws-1, ws-2, printer
    assert payload["stats"]["mac_only"] == 1  # printer, learned only from the FDB
    assert payload["stats"]["infrastructure"] == 2


def test_map_is_stable_across_repeated_scans(db_session, test_org, scan):
    """
    Re-running against an unchanged network must not grow the graph. Endpoint
    identity is derived from the same inputs each time, so link IDs have to be
    reproducible rather than drifting as inventory fills in.
    """
    from core.topology.engine import get_topology_graph

    walks = _core_network_walks()
    first = _run_mapping(db_session, test_org, scan, walks)
    graph_one = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)

    second = _run_mapping(db_session, test_org, scan, walks)
    graph_two = get_topology_graph(db_session, org_id=test_org.id, scan_id=scan.id)

    assert first["links_created"] == second["links_updated"]
    assert second["links_created"] == 0
    assert {n["id"] for n in graph_one["nodes"]} == {
        n["id"] for n in graph_two["nodes"]
    }
    assert graph_one["stats"] == graph_two["stats"]


def test_scan_scoped_map_rejects_another_orgs_scan(
    db_session, test_org, scan, client, auth_headers
):
    other_org = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name="Other Org",
        slug=f"other{uuid.uuid4().hex[:4]}",
    )
    db_session.add(other_org)
    db_session.commit()

    foreign_scan = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=other_org.id,
        status="completed",
        target_str="10.1.1.0/24",
    )
    db_session.add(foreign_scan)
    db_session.commit()

    assert (
        client.get(f"/topology/map/{foreign_scan.id}", headers=auth_headers).status_code
        == 403
    )
    assert (
        client.get(
            f"/topology/map?scan_id={foreign_scan.id}", headers=auth_headers
        ).status_code
        == 403
    )
    assert (
        client.get("/topology/map/does-not-exist", headers=auth_headers).status_code
        == 404
    )


def test_map_requires_authentication(client):
    assert client.get("/topology/map").status_code in (401, 403)


def test_subnet_mask_is_validated(client, auth_headers):
    assert (
        client.get("/topology/map?subnet_mask=4", headers=auth_headers).status_code
        == 422
    )
    assert (
        client.get("/topology/map?subnet_mask=31", headers=auth_headers).status_code
        == 422
    )
    assert (
        client.get(
            "/topology/map?active_within_days=0", headers=auth_headers
        ).status_code
        == 422
    )

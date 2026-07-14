from types import SimpleNamespace

from core.topology.engine import get_topology_graph


class FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return self.rows


class FakeDB:
    def __init__(self, links):
        self.links = links

    def query(self, model):
        return FakeQuery(self.links)


def make_link(**overrides):
    data = {
        "org_id": "org-1",
        "scan_id": "scan-1",
        "source_mac": "sw:10:180:4:1",
        "source_port": "port:12",
        "source_port_desc": "",
        "source_asset": None,
        "target_mac": "00:11:22:33:44:55",
        "target_port": "",
        "target_port_desc": "",
        "target_ip": None,
        "target_asset": None,
        "vlan_id": None,
        "speed_bps": None,
        "link_type": "fdb",
    }
    data.update(overrides)
    return SimpleNamespace(**data)


def test_topology_graph_mac_only_cluster_has_quality_and_evidence():
    links = [
        make_link(target_mac="00:11:22:33:44:55", source_port="port:12"),
        make_link(target_mac="00:11:22:33:44:66", source_port="port:14"),
    ]

    graph = get_topology_graph(FakeDB(links), org_id="org-1", scan_id="scan-1")

    cluster = next(
        node for node in graph["nodes"] if node["id"] == "subnet:MAC-Only / FDB"
    )
    assert graph["graph_version"] == 2
    assert cluster["group"] == "mac_only_cluster"
    assert cluster["host_count"] == 2
    assert cluster["data_quality"]["mac_only"] == 2
    assert cluster["data_quality"]["ip_resolved"] == 0
    assert cluster["data_quality"]["source_count"] == 1
    assert "Run ARP-enabled scan" in cluster["recommended_actions"]

    host = next(
        node for node in graph["nodes"] if node.get("mac") == "00:11:22:33:44:55"
    )
    assert host["subnet"] == "MAC-Only / FDB"
    assert host["source_port"] == "port:12"
    assert host["asset_match_status"] == "unmatched"

    edge = next(
        edge for edge in graph["edges"] if edge["to"] == "subnet:MAC-Only / FDB"
    )
    assert edge["host_count"] == 2
    assert edge["link_details"]["type_counts"] == {"fdb": 2}
    assert sorted(edge["link_details"]["ports"]) == ["port:12", "port:14"]


def test_topology_graph_ip_subnet_counts_resolved_hosts():
    asset = SimpleNamespace(
        id="asset-1",
        hostname="workstation-1",
        ip_address="10.180.4.15",
        mac_address="00:11:22:33:44:55",
        device_category="workstation",
        vendor="Acme",
        manufacturer=None,
    )
    links = [
        make_link(
            target_mac="00:11:22:33:44:55",
            target_ip="10.180.4.15",
            target_asset=asset,
            link_type="arp",
            source_port="if1",
        ),
    ]

    graph = get_topology_graph(
        FakeDB(links), org_id="org-1", scan_id="scan-1", subnet_mask=24
    )

    cluster = next(
        node for node in graph["nodes"] if node["id"] == "subnet:10.180.4.0/24"
    )
    assert cluster["data_quality"]["ip_resolved"] == 1
    assert cluster["data_quality"]["mac_only"] == 0
    assert cluster["data_quality"]["asset_matches"] == 1
    assert cluster["data_quality"]["has_arp"] is True

    host = next(
        node for node in graph["nodes"] if node.get("mac") == "00:11:22:33:44:55"
    )
    assert host["vendor"] == "Acme"
    assert host["asset_match_status"] == "matched"


def test_topology_graph_includes_enriched_snmp_fields():
    # 1. Test host node enrichment
    links = [
        make_link(
            source_mac="sw:10:180:4:1",
            source_port="port:12",
            source_port_desc="GigabitEthernet1/0/12 (Uplink)",
            target_mac="00:11:22:33:44:55",
            target_ip="10.180.4.15",
            link_type="fdb",
            vlan_id=100,
            speed_bps=1000000000,
        )
    ]

    graph = get_topology_graph(
        FakeDB(links), org_id="org-1", scan_id="scan-1", subnet_mask=24
    )

    host = next(
        node for node in graph["nodes"] if node.get("mac") == "00:11:22:33:44:55"
    )
    assert host["source_port"] == "port:12"
    assert host["source_port_desc"] == "GigabitEthernet1/0/12 (Uplink)"
    assert host["vlan_id"] == 100
    assert host["speed_bps"] == 1000000000

    # 2. Test infra-to-infra edge enrichment (e.g. LLDP)
    infra_links = [
        make_link(
            source_mac="sw:10:180:4:1",
            source_port="lldp:24",
            source_port_desc="GigabitEthernet1/0/24",
            target_mac="sw:10:180:4:2",
            target_port="lldp:1",
            target_port_desc="GigabitEthernet1/0/1",
            link_type="lldp",
            vlan_id=200,
            speed_bps=10000000000,
        )
    ]

    graph_infra = get_topology_graph(
        FakeDB(infra_links), org_id="org-1", scan_id="scan-1"
    )

    # Locate infra-to-infra edge
    edge = next(
        e
        for e in graph_infra["edges"]
        if e["from"] == "sw:10:180:4:1" and e["to"] == "sw:10:180:4:2"
    )
    assert edge["source_port"] == "lldp:24"
    assert edge["source_port_desc"] == "GigabitEthernet1/0/24"
    assert edge["target_port"] == "lldp:1"
    assert edge["target_port_desc"] == "GigabitEthernet1/0/1"
    assert edge["vlan_id"] == 200
    assert edge["speed_bps"] == 10000000000

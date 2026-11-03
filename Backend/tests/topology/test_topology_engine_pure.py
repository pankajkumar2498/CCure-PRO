"""
The topology engine computes on plain values and writes nothing (2 Nov 2026).

``run_topology_mapping`` and ``get_topology_graph`` run here on a directory
that holds plain records in memory: no database, no session, no model. What a
run decides to write arrives at the directory as one ``TopologyPlan`` — the
assets to enrol, the gaps filled on assets, the link rows — and the graph is
drawn from ``StoredLink`` records. ``test_topology_engine.py`` and
``test_topology_graph.py`` run the same paths against PostgreSQL through
Audit's directory; ``test_topology_store.py`` pins the writers.

This module needs no conftest, so the library isolation harness runs it as
library ``topology``, in a fresh interpreter that refuses SQLAlchemy and the
settings.
"""

import ast
from pathlib import Path

import pytest
from core.topology import client
from core.topology import directory as topology_directory
from core.topology.client import ARPEntry, LLDPNeighbor, SNMPWalkResult
from core.topology.directory import AssetRecord, StoredLink, TopologyPlan
from core.topology.engine import (
    AssetIndex,
    build_topology_graph,
    get_topology_graph,
    run_topology_mapping,
)
from db.ids import gen_asset_id, gen_network_link_id

ORG = "org_pure"
SLUG = "pure-org"
SWITCH = "10.180.4.10"
HOST = "10.180.4.15"
HOST_MAC = "00:11:22:33:44:55"


class MemoryDirectory:
    """A directory over plain records: what a host other than Audit plugs in."""

    def __init__(self, assets=(), links=()):
        self.assets = {record.id: record for record in assets}
        self.links = list(links)
        self.plans: list[TopologyPlan] = []
        self.handles: list = []

    def organisation_assets(self, db, org_id):
        self.handles.append(db)
        return list(self.assets.values())

    def asset(self, db, asset_id):
        return self.assets.get(asset_id)

    def record_topology(self, db, *, org_id, scan_id, plan):
        self.handles.append(db)
        self.plans.append(plan)
        return len(plan.links), 0

    def stored_links(self, db, *, org_id, scan_id, active_within_days):
        self.handles.append(db)
        return [link for link in self.links if not scan_id or link.scan_id == scan_id]

    def scan_targets(self, db, scan_id):
        return [SWITCH]

    def scan(self, db, scan_id):
        return None


@pytest.fixture
def memory(monkeypatch):
    def install(**records):
        found = MemoryDirectory(**records)
        monkeypatch.setattr(topology_directory, "_directory", found)
        return found

    return install


def _walk() -> SNMPWalkResult:
    walk = SNMPWalkResult(target_ip=SWITCH)
    walk.sys_name = "access-sw-01"
    walk.arp_table = [
        ARPEntry(ip_address=HOST, mac_address=HOST_MAC, interface_index="10")
    ]
    walk.lldp_neighbors = [
        LLDPNeighbor(
            chassis_id="core-sw-01",
            port_id="Gi1/0/1",
            system_name="core-sw-01",
            local_port_index="1",
        )
    ]
    return walk


def _run(monkeypatch, handle="opaque-handle", targets=(SWITCH,)):
    monkeypatch.setattr(client, "probe_snmp", lambda ip, creds: True)
    monkeypatch.setattr(client, "walk_target", lambda ip, creds: _walk())
    return run_topology_mapping(
        handle,
        "scan_pure",
        ORG,
        {"version": "v2c", "community": "public"},
        list(targets),
        org_slug=SLUG,
    )


def test_a_run_hands_over_one_plan_and_writes_nothing_itself(memory, monkeypatch):
    host = AssetRecord(id="ast_host", ip_address=HOST, hostname="printer-3")
    core_sw = AssetRecord(id="ast_core", hostname="core-sw-01")
    found = memory(assets=[host, core_sw])

    result = _run(monkeypatch)

    assert len(found.plans) == 1
    plan = found.plans[0]
    # The handle reaches the directory untouched: the engine never uses it.
    assert set(found.handles) == {"opaque-handle"}

    # The walked switch is enrolled under the id the asset registry mints, with
    # no timestamps (the writer stamps them).
    switch_id = gen_asset_id(ORG, SWITCH)
    assert plan.enrolments == [
        {
            "id": switch_id,
            "org_id": ORG,
            "ip_address": SWITCH,
            "mac_address": None,
            "hostname": "access-sw-01",
            "device_category": None,
            "discovery_method": "topology",
        }
    ]

    # The LLDP neighbour resolved to the inventory's core switch by name and
    # filled its generic category — on the record and in the plan, not in any
    # database. The walked switch, enrolled with no category, is that link's
    # other end and gets one the same way. An ARP entry resolves and fills
    # nothing.
    assert core_sw.device_category == "switch"
    assert plan.asset_changes == {
        "ast_core": {"device_category": "switch"},
        switch_id: {"device_category": "switch"},
    }
    assert host.mac_address is None

    rows = {row["link_type"]: row for row in plan.links}
    assert set(rows) == {"arp", "lldp"}
    arp = rows["arp"]
    assert arp["id"] == gen_network_link_id(
        SLUG, f"asset:{switch_id}", "asset:ast_host"
    )
    assert (arp["org_id"], arp["scan_id"]) == (ORG, "scan_pure")
    assert (arp["source_asset_id"], arp["target_asset_id"]) == (switch_id, "ast_host")
    assert (arp["target_mac"], arp["target_ip"]) == (HOST_MAC, HOST)
    assert not {"first_seen_at", "last_seen_at", "created_at"} & set(arp)
    lldp = rows["lldp"]
    assert {lldp["source_asset_id"], lldp["target_asset_id"]} == {
        switch_id,
        "ast_core",
    }

    assert result == {
        "success": True,
        "links_created": 2,
        "links_updated": 0,
        "total_links": 2,
        "targets_walked": 1,
        "assets_enrolled": 1,
        "errors": [],
    }


def test_the_same_walk_plans_the_same_rows(memory, monkeypatch):
    first = memory(assets=[AssetRecord(id="ast_host", ip_address=HOST)])
    _run(monkeypatch)
    second = memory(assets=[AssetRecord(id="ast_host", ip_address=HOST)])
    _run(monkeypatch)
    assert first.plans[0].links == second.plans[0].links
    assert first.plans[0].enrolments == second.plans[0].enrolments


def test_an_asset_found_by_id_is_the_one_the_index_holds(memory):
    """One record per asset, as the session's identity map kept one row: an
    endpoint that misses by address but whose id exists resolves to the held
    record, so a filled gap is seen by every later lookup."""
    moved = AssetRecord(id=gen_asset_id(ORG, "10.0.0.9"), ip_address="10.0.0.200")
    memory(assets=[moved])
    index = AssetIndex("opaque-handle", ORG)
    from core.topology.identity import Endpoint

    found = index.get_or_create(
        Endpoint("ip", "ip:10.0.0.9", ip="10.0.0.9", name="moved-sw"), "switch"
    )
    assert found is moved
    assert moved.hostname == "moved-sw"
    assert index.enrolments == []
    assert index.changes == {
        moved.id: {"hostname": "moved-sw", "device_category": "switch"}
    }
    assert "moved-sw" not in index._ambiguous_hostnames


def test_no_targets_writes_no_plan(memory, monkeypatch):
    found = memory()
    monkeypatch.setattr(found, "scan_targets", lambda db, scan_id: [])
    result = run_topology_mapping(
        "opaque-handle", "scan_pure", ORG, {"version": "v2c"}, None, org_slug=SLUG
    )
    assert result["errors"] == ["No targets"]
    assert found.plans == []


def _stored(link_type="lldp", **fields) -> StoredLink:
    switch = AssetRecord(
        id="ast_sw", ip_address=SWITCH, hostname="access-sw-01", vendor="Extreme"
    )
    core_sw = AssetRecord(
        id="ast_core",
        ip_address="10.180.4.1",
        hostname="core-sw-01",
        device_category="switch",
        vendor="Extreme",
    )
    values = {
        "id": "lnk_one",
        "org_id": ORG,
        "scan_id": "scan_pure",
        "source_key": "asset:ast_sw",
        "source_ip": SWITCH,
        "source_port": "1",
        "source_asset_id": "ast_sw",
        "target_key": "asset:ast_core",
        "target_ip": "10.180.4.1",
        "target_port": "Gi1/0/1",
        "target_asset_id": "ast_core",
        "link_type": link_type,
        "observed_types": link_type,
        "source_asset": switch,
        "target_asset": core_sw,
    }
    values.update(fields)
    return StoredLink(**values)


def test_the_graph_is_drawn_from_plain_records(memory):
    link = _stored()
    found = memory(links=[link])

    graph = get_topology_graph("opaque-handle", ORG, scan_id="scan_pure")

    assert graph == build_topology_graph([link])
    assert set(found.handles) == {"opaque-handle"}
    nodes = {node["id"]: node for node in graph["nodes"] if node.get("asset_id")}
    assert set(nodes) == {"asset:ast_sw", "asset:ast_core"}
    assert nodes["asset:ast_core"]["label"] == "core-sw-01"
    edges = [edge for edge in graph["edges"] if edge.get("link_type") == "lldp"]
    assert len(edges) == 1
    assert {edges[0]["from"], edges[0]["to"]} == set(nodes)
    assert edges[0]["target_port"] == "Gi1/0/1"


def test_the_engine_imports_no_database_model_or_settings():
    tree = ast.parse(
        (Path(__file__).resolve().parents[2] / "core/topology/engine.py").read_text()
    )
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    refused = ("sqlalchemy", "db.base", "db.models", "config", "core.topology.links")
    assert sorted(name for name in imported if name.startswith(refused)) == []

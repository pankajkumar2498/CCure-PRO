"""
The writers behind the topology engine's directory (2 Nov 2026): the asset
registry's half (``core.topology_assets``) and the topology store
(``core.topology.links``), composed by Audit's composition root
(``ccure_audit.topology_directory``) into one ``record_topology``.

What ``_persist_links`` did inside the engine, these do now: the run's assets
are written before the links that reference them, in one transaction that
commits, or rolls back whole and raises; the created/updated count is read
against the stored ids; an empty run still commits its assets. The graph is
drawn from plain records, never rows. The engine end to end, through this
directory, is ``test_topology_engine.py``; the engine without any database is
``test_topology_engine_pure.py``.
"""

import ast
import logging
import uuid

import pytest
from ccure_audit.topology_directory import DIRECTORY
from core import topology_assets
from core.topology import links as topology_links
from core.topology.directory import AssetRecord, StoredLink, TopologyPlan
from db.base import gen_network_link_id, utcnow
from db.models import Asset, NetworkLink, Scan
from scripts.architecture.import_graph import discover_modules
from testpaths import BACKEND_ROOT


@pytest.fixture()
def scan(db_session, test_org):
    row = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        status="completed",
        target_str="10.181.0.0/24",
    )
    db_session.add(row)
    db_session.commit()
    return row


def _enrolment(org, ip):
    return {
        "id": f"ast_store_{uuid.uuid4().hex[:8]}",
        "org_id": org.id,
        "ip_address": ip,
        "mac_address": None,
        "hostname": f"sw-{ip.rsplit('.', 1)[1]}",
        "device_category": "switch",
        "discovery_method": "topology",
    }


def _link(org, scan, source_id, target_id, **fields):
    values = {
        "id": gen_network_link_id(org.slug, f"asset:{source_id}", f"asset:{target_id}"),
        "org_id": org.id,
        "scan_id": scan.id,
        "source_key": f"asset:{source_id}",
        "source_mac": None,
        "source_ip": None,
        "source_port": "1",
        "source_port_desc": None,
        "source_asset_id": source_id,
        "target_key": f"asset:{target_id}",
        "target_mac": None,
        "target_ip": None,
        "target_port": "2",
        "target_port_desc": None,
        "target_asset_id": target_id,
        "vlan_id": None,
        "speed_bps": None,
        "link_type": "lldp",
        "observed_types": "lldp",
    }
    values.update(fields)
    return values


def _record(db, org, scan, plan):
    return DIRECTORY.record_topology(db, org_id=org.id, scan_id=scan.id, plan=plan)


def test_assets_are_written_before_the_links_that_reference_them(
    db_session, test_org, scan
):
    existing = Asset(
        id=f"ast_store_{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        ip_address="10.181.0.1",
        discovery_method="test",
    )
    db_session.add(existing)
    db_session.commit()
    enrolled = _enrolment(test_org, "10.181.0.2")
    plan = TopologyPlan(
        enrolments=[enrolled],
        asset_changes={
            existing.id: {"hostname": "core-sw", "vlan_id": 40},
            enrolled["id"]: {"mac_address": "00:11:22:33:44:66"},
        },
        links=[_link(test_org, scan, existing.id, enrolled["id"])],
    )

    assert _record(db_session, test_org, scan, plan) == (1, 0)

    db_session.expire_all()
    row = db_session.get(Asset, enrolled["id"])
    assert (row.hostname, row.device_category, row.discovery_method) == (
        "sw-2",
        "switch",
        "topology",
    )
    assert str(row.mac_address) == "00:11:22:33:44:66"
    assert row.created_at is not None and row.last_seen_at == row.created_at
    held = db_session.get(Asset, existing.id)
    assert (held.hostname, held.vlan_id) == ("core-sw", 40)
    link = db_session.query(NetworkLink).filter_by(scan_id=scan.id).one()
    assert (link.source_asset_id, link.target_asset_id) == (existing.id, enrolled["id"])
    assert link.first_seen_at == row.created_at

    # The same run again updates the row and keeps its first sighting.
    first_seen = link.first_seen_at
    plan.enrolments = []
    assert _record(db_session, test_org, scan, plan) == (0, 1)
    db_session.expire_all()
    link = db_session.query(NetworkLink).filter_by(scan_id=scan.id).one()
    assert link.first_seen_at == first_seen
    assert link.last_seen_at > first_seen


def test_a_failed_link_write_rolls_the_whole_run_back(
    db_session, test_org, scan, caplog
):
    enrolled = _enrolment(test_org, "10.181.0.3")
    good = _link(test_org, scan, enrolled["id"], enrolled["id"] + "_peer")
    plan = TopologyPlan(
        enrolments=[enrolled],
        links=[{**good, "target_asset_id": None}, {**good, "id": "x" * 201}],
    )

    with caplog.at_level(logging.ERROR, logger="ccure.topology.engine"):
        with pytest.raises(Exception):
            _record(db_session, test_org, scan, plan)

    assert "rolled back" in caplog.text
    assert db_session.get(Asset, enrolled["id"]) is None
    assert db_session.query(NetworkLink).filter_by(scan_id=scan.id).count() == 0


def test_a_run_with_no_links_still_commits_its_assets(db_session, test_org, scan):
    enrolled = _enrolment(test_org, "10.181.0.4")
    plan = TopologyPlan(enrolments=[enrolled])

    assert _record(db_session, test_org, scan, plan) == (0, 0)

    db_session.rollback()  # nothing pending: it was committed
    assert db_session.get(Asset, enrolled["id"]) is not None


def test_the_asset_writer_does_not_commit(db_session, test_org):
    enrolled = _enrolment(test_org, "10.181.0.5")

    topology_assets.write_topology_assets(db_session, [enrolled], {}, now=utcnow())
    assert db_session.get(Asset, enrolled["id"]) is not None  # flushed
    db_session.rollback()
    assert db_session.get(Asset, enrolled["id"]) is None


def test_reads_cross_as_plain_records(db_session, test_org, scan):
    enrolled = _enrolment(test_org, "10.181.0.6")
    plan = TopologyPlan(
        enrolments=[enrolled],
        links=[_link(test_org, scan, enrolled["id"], enrolled["id"] + "_peer")],
    )
    plan.links[0]["target_asset_id"] = None
    _record(db_session, test_org, scan, plan)

    assets = DIRECTORY.organisation_assets(db_session, test_org.id)
    assert all(type(asset) is AssetRecord for asset in assets)
    assert enrolled["id"] in {asset.id for asset in assets}
    assert type(DIRECTORY.asset(db_session, enrolled["id"])) is AssetRecord
    assert DIRECTORY.asset(db_session, "ast_no_such") is None

    (stored,) = DIRECTORY.stored_links(
        db_session, org_id=test_org.id, scan_id=scan.id, active_within_days=None
    )
    assert type(stored) is StoredLink
    assert type(stored.source_asset) is AssetRecord
    assert stored.source_asset.hostname == "sw-6"
    assert stored.target_asset is None
    assert (
        DIRECTORY.stored_links(
            db_session, org_id=test_org.id, scan_id="scan-other", active_within_days=1
        )
        == []
    )


def test_a_stored_link_carries_every_column():
    columns = {column.key for column in NetworkLink.__table__.columns}
    fields = set(StoredLink.__dataclass_fields__) - {"source_asset", "target_asset"}
    assert fields == columns


def test_the_composition_root_registers_the_writers():
    assert DIRECTORY.organisation_assets is topology_assets.organisation_assets
    assert DIRECTORY.asset is topology_assets.asset
    assert DIRECTORY.stored_links is topology_links.stored_links


def test_only_the_topology_store_writes_network_links():
    writers = []
    for module, path in discover_modules().items():
        if module.split(".")[0] in ("tests", "alembic", "scripts"):
            continue
        rel = path.relative_to(BACKEND_ROOT)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and any(
                    isinstance(arg, ast.Name) and arg.id == "NetworkLink"
                    for arg in node.args
                )
                and getattr(node.func, "id", getattr(node.func, "attr", "")) == "insert"
            ) or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "NetworkLink"
            ):
                writers.append(str(rel))
    assert sorted(set(writers)) == ["core/topology/links.py"]

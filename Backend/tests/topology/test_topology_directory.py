"""
The topology engine reads and enrols assets, and reads its scan's targets,
through its directory (Group 3; ``core/topology/directory.py``): the asset
registry answers the assets (``core/topology_assets.py``) and the scans
capability the scan (``scans.reads``), registered together by
``ccure_audit/topology_directory.py``. The engine and the topology API import
neither model.
"""

import ast

import pytest
from core.topology import directory as topology_directory
from testpaths import BACKEND_ROOT


@pytest.mark.parametrize("path", ["core/topology/engine.py", "routers/topology.py"])
def test_the_engine_and_the_api_name_no_asset_or_scan_model(path):
    tree = ast.parse((BACKEND_ROOT / path).read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module and "models" in node.module
        for alias in node.names
    }
    assert not imported & {"Asset", "Scan"}, imported


def test_the_registered_directory_answers():
    from ccure_audit.topology_directory import DIRECTORY
    from core import topology_assets
    from scans import reads

    assert topology_directory.directory() is DIRECTORY
    assert DIRECTORY.enrol is topology_assets.enrol
    assert DIRECTORY.scan_targets is reads.target_hosts
    assert DIRECTORY.scan is reads.scan_by_id


def test_without_a_directory_the_engine_refuses(monkeypatch):
    monkeypatch.setattr(topology_directory, "_directory", None)
    with pytest.raises(topology_directory.TopologyDirectoryMissing):
        topology_directory.directory()


def test_a_second_directory_is_refused(monkeypatch):
    monkeypatch.setattr(topology_directory, "_directory", None)
    first = object()
    topology_directory.register_topology_directory(first)
    topology_directory.register_topology_directory(first)
    with pytest.raises(ValueError):
        topology_directory.register_topology_directory(object())


def test_enrolment_flushes_so_the_link_has_its_key(db_session, test_org):
    from core import topology_assets

    asset = topology_assets.enrol(
        db_session,
        id="ast_g3_topology_enrol",
        org_id=test_org.id,
        ip_address="10.99.0.1",
        discovery_method="topology",
    )
    assert asset.id == "ast_g3_topology_enrol"
    assert topology_assets.asset(db_session, asset.id) is asset
    assert asset in topology_assets.organisation_assets(db_session, test_org.id)

"""
Findings and the asset registry read each other through their own modules (G6,
C7; docs/architecture/MODULAR_REFACTORING_LOG.md §6).

The asset registry depends on findings: its syncer hands a scan's findings to
the findings writer (G3). So the findings capability does not depend on the
asset registry. It reads hosts — a finding's organisation, address and name,
and the risk an asset's open findings give it — through its port,
``core.findings.hosts``, which Audit's composition root fills with the asset
registry's answer (``ccure_audit/host_directory.py``). The assets router reads
the findings tables through ``core.findings.reads``. These pin:

* nothing in the findings capability imports the asset registry or names its
  table;
* the assets router imports no findings model and names no findings table;
* every process that reads hosts registers the directory: the worker through
  Celery's ``imports``, the API through the same loader call;
* the asset registry's projection has exactly the port's columns, from the
  asset table;
* the registry's rules: one directory, a projection with the port's columns,
  and a read with none registered raises.
"""

import ast

import pytest
from sqlalchemy import literal, select

from core import asset_hosts
from core.findings import hosts
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT


def _edges():
    _, edges = collect_edges()
    return edges


def _owned_by(capability):
    return {
        table
        for table, owner in capability_map.table_owners().items()
        if owner == capability
    }


def test_the_findings_capability_imports_nothing_of_the_asset_registry():
    into_assets = sorted(
        (e.src, e.dst)
        for e in _edges()
        if capability_map.capability_of(e.src) == "findings"
        and capability_map.capability_of(e.dst.split(":")[0]) == "assets"
    )
    assert into_assets == []


def test_the_findings_capability_names_no_asset_table():
    references = {
        tuple(r) for r in capability_map.measure()["foreign_table_references"]
    }
    assert {("findings", t) for t in _owned_by("assets")} & references == set()


def test_the_assets_router_reads_findings_through_the_findings_reads():
    into_findings = sorted(
        {
            e.dst
            for e in _edges()
            if e.src == "routers.assets"
            and capability_map.capability_of(e.dst.split(":")[0]) == "findings"
        }
    )
    assert into_findings == ["core.findings", "core.findings.reads"]
    references = {
        tuple(r) for r in capability_map.measure()["foreign_table_references"]
    }
    assert {("assets", t) for t in _owned_by("findings")} & references == set()


def test_the_worker_and_the_api_load_the_host_directory():
    from core.celery_app import celery_app

    assert "ccure_audit.host_directory" in celery_app.conf.imports
    assert "ccure_audit.host_directory" in celery_app.loader.default_modules
    main = ast.parse((BACKEND_ROOT / "main.py").read_text(encoding="utf-8"))
    calls = [
        node.func.attr
        for node in ast.walk(main)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]
    assert "import_default_modules" in calls


def test_the_asset_registry_answers_once_the_registrations_load():
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    assert hosts._directory is asset_hosts.DIRECTORY


def test_the_projection_has_the_ports_columns_from_the_asset_table():
    projection = asset_hosts.DIRECTORY.projection()
    assert tuple(projection.c.keys()) == hosts.HOST_COLUMNS
    assert [t.name for t in projection.element.get_final_froms()] == ["assets"]


def test_a_second_directory_is_refused(monkeypatch):
    monkeypatch.setattr(hosts, "_directory", None)
    hosts.register_host_directory(asset_hosts.DIRECTORY)
    hosts.register_host_directory(asset_hosts.DIRECTORY)  # no-op
    with pytest.raises(ValueError):
        hosts.register_host_directory(asset_hosts.AssetHosts())


def test_a_projection_without_the_ports_columns_is_refused(monkeypatch):
    monkeypatch.setattr(hosts, "_directory", None)

    class Narrow(asset_hosts.AssetHosts):
        def projection(self):
            return select(literal("x").label("id")).subquery("hosts")

    with pytest.raises(ValueError):
        hosts.register_host_directory(Narrow())
    assert hosts._directory is None


def test_reading_hosts_with_no_directory_raises(monkeypatch):
    monkeypatch.setattr(hosts, "_directory", None)
    with pytest.raises(hosts.HostDirectoryMissing):
        hosts.hosts()
    with pytest.raises(hosts.HostDirectoryMissing):
        hosts.record_open_findings(None, "ast_any", {})

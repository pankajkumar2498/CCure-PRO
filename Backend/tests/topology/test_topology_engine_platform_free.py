"""
B6: the topology engine no longer imports the platform API.

``core/topology/engine.py`` imported ``ccure_platform.api`` at module level to
look up one thing, the organisation's slug, from which every network-link id is
derived. That import made the SNMP engine load FastAPI, python-jose, Starlette
and Redis. The task now resolves the slug and passes it in, and the engine
requires it, so a caller cannot leave it out and silently re-key every link.

These pin the purpose (the engine names no platform module and loads no web
stack), the required argument, that links are keyed by the slug passed in, and
that the task passes the organisation's slug, falling back to its id when the
organisation no longer exists, as the engine did before.
"""

import ast
import inspect
import json
import subprocess
import sys
import uuid
from unittest.mock import patch

import pytest

from core.topology.client import ARPEntry, SNMPWalkResult
from core.topology.engine import run_topology_mapping
from db.base import gen_network_link_id
from db.models import NetworkLink, Scan
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

WEB_STACK = ("fastapi", "starlette", "jose", "redis", "ccure_platform.api")


def test_the_engine_names_no_platform_module():
    tree = ast.parse((BACKEND_ROOT / "core" / "topology" / "engine.py").read_text())
    named = [
        node.module if isinstance(node, ast.ImportFrom) else alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (node.names if isinstance(node, ast.Import) else [None])
    ]
    assert not [m for m in named if m and m.startswith("ccure_platform")]


def test_no_topology_module_imports_the_platform():
    """Lazy imports count; they are how the codebase hid its couplings."""
    _, edges = collect_edges()
    into_platform = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src.startswith("core.topology")
        and capability_map.capability_of(e.dst) == "platform"
    )
    assert into_platform == []


_IMPORT = r"""
import json, sys
import core.topology.engine
print(json.dumps(sorted(m for m in %r if m in sys.modules)))
"""


def test_importing_the_engine_loads_no_web_stack():
    done = subprocess.run(
        [sys.executable, "-c", _IMPORT % (WEB_STACK,)],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == []


def test_the_slug_is_required_and_named():
    parameter = inspect.signature(run_topology_mapping).parameters["org_slug"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty
    with pytest.raises(TypeError, match="org_slug"):
        run_topology_mapping(None, "scan", "org", {})


@pytest.fixture()
def scan(db_session, test_org):
    row = Scan(
        id=f"scan-{uuid.uuid4().hex[:8]}",
        org_id=test_org.id,
        status="completed",
        target_hosts=["10.180.4.10"],
        target_str="10.180.4.10",
        options={"snmp": {"version": "v2c", "community": "public"}},
    )
    db_session.add(row)
    db_session.commit()
    return row


def _map(db_session, org, scan, org_slug):
    walk = SNMPWalkResult(target_ip="10.180.4.10")
    walk.arp_table = [
        ARPEntry(
            ip_address="10.180.4.15",
            mac_address="00:11:22:33:44:55",
            interface_index="10",
        )
    ]
    with (
        patch("core.topology.client.probe_snmp", return_value=True),
        patch("core.topology.client.walk_target", return_value=walk),
    ):
        return run_topology_mapping(
            db=db_session,
            scan_id=scan.id,
            org_id=org.id,
            org_slug=org_slug,
            snmp_config={"version": "v2c", "community": "public"},
            target_ips=["10.180.4.10"],
        )


def test_links_are_keyed_by_the_slug_passed_in(db_session, test_org, scan):
    assert _map(db_session, test_org, scan, test_org.slug)["links_created"] == 1
    link = db_session.query(NetworkLink).one()
    assert link.id == gen_network_link_id(
        test_org.slug, link.source_key, link.target_key
    )

    # Another slug is another link: why the engine cannot be left to guess.
    assert _map(db_session, test_org, scan, "another-slug")["links_created"] == 1
    assert db_session.query(NetworkLink).count() == 2


@pytest.mark.parametrize("organisation_found", [True, False])
def test_the_task_passes_the_organisations_slug(
    db_session, test_org, scan, monkeypatch, organisation_found
):
    import core.tasks as tasks

    seen = {}

    def engine(**kwargs):
        seen.update(kwargs)
        return {"success": True, "total_links": 0}

    monkeypatch.setattr("core.topology.engine.run_topology_mapping", engine)
    monkeypatch.setattr("scans.db_helpers.update_scan_phase", lambda **_: None)
    monkeypatch.setattr("core.redis_client.publish_progress_sync", lambda *_: None)
    if not organisation_found:
        monkeypatch.setattr(tasks.platform_api, "organisation", lambda db, org_id: None)

    result = tasks.run_topology_mapping_task.run(scan.id, "no-such-user")

    assert result["success"] is True, result
    assert seen["org_id"] == test_org.id
    assert seen["org_slug"] == (test_org.slug if organisation_found else test_org.id)

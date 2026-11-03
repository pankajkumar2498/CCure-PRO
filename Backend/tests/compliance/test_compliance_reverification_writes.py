"""
Compliance re-verification records a port's reachability through the findings
writer (1 Nov 2026).

After a remediation, ``core.compliance_tasks._run_active_reverification_probes``
connects to the port a ``services_ports`` rule names and records the answer
on the asset's service row. It used to load the ``services`` row and set
``state``, ``network_reachable`` and ``updated_at`` itself, a write to a
findings table outside the findings writer that the capability map counts
only as a reference. ``core.findings.writer.record_port_reachability`` makes
it now; the probe still commits, and only when a row was found, as before.
"""

import ast
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from db.base import utcnow
from db.models import Asset, Organization
from db.models.findings import Service
from sqlalchemy.orm import Session
from testpaths import BACKEND_ROOT

import core.compliance_tasks as compliance_tasks
from core.findings.writer import record_port_reachability

TASKS = BACKEND_ROOT / "core" / "compliance_tasks.py"


class _Socket:
    """A TCP socket whose connect answers *code* (0 is open)."""

    def __init__(self, code):
        self.code = code

    def settimeout(self, _):
        pass

    def connect_ex(self, address):
        self.address = address
        return self.code

    def close(self):
        pass


class _Db:
    commits = 0

    def commit(self):
        self.commits += 1


def _probe(monkeypatch, *, code, found):
    calls = []

    def record(db, asset_id, port, is_open):
        calls.append((asset_id, port, is_open))
        return found

    monkeypatch.setattr(compliance_tasks, "record_port_reachability", record)
    monkeypatch.setattr(
        compliance_tasks.socket, "socket", lambda *a, **kw: _Socket(code)
    )
    db = _Db()
    compliance_tasks._run_active_reverification_probes(
        db,
        SimpleNamespace(asset_id="ast_1"),
        SimpleNamespace(
            evidence_source="services_ports", check_definition={"port": 22}
        ),
        "192.0.2.5",
    )
    return calls, db.commits


@pytest.mark.parametrize("code, is_open", [(0, True), (111, False)])
def test_the_probe_hands_its_observation_to_the_findings_writer(
    monkeypatch, code, is_open
):
    calls, commits = _probe(monkeypatch, code=code, found=True)
    assert calls == [("ast_1", 22, is_open)]
    assert commits == 1


def test_no_service_row_means_no_commit(monkeypatch):
    calls, commits = _probe(monkeypatch, code=0, found=False)
    assert calls == [("ast_1", 22, True)]
    assert commits == 0


def test_compliance_tasks_load_no_findings_row_to_change():
    """The module imports no findings model, and sets neither field."""
    tree = ast.parse(TASKS.read_text(encoding="utf-8"))
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module in ("db.models", "db.models.findings")
        for alias in node.names
    }
    assert not imported & {"Service", "AssetVulnerability", "TLSDetail"}, imported
    assigned = {
        target.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute)
    }
    assert not assigned & {"network_reachable"}, assigned


@pytest.fixture
def asset(db_session: Session) -> Asset:
    org = Organization(
        id=f"org_{uuid.uuid4().hex[:8]}",
        name=f"Reverify {uuid.uuid4().hex[:6]}",
        slug=f"reverify-{uuid.uuid4().hex[:8]}",
        is_active=True,
        settings={},
    )
    db_session.add(org)
    db_session.flush()
    row = Asset(
        id=f"ast_{uuid.uuid4().hex[:10]}",
        org_id=org.id,
        ip_address="192.0.2.5",
        last_seen_at=utcnow(),
    )
    db_session.add(row)
    db_session.flush()
    return row


def test_the_writer_records_both_fields_and_leaves_the_commit_to_the_caller(
    db_session: Session, asset: Asset
):
    service = Service(
        id=f"svc_{uuid.uuid4().hex[:10]}",
        asset_id=asset.id,
        port=22,
        protocol="tcp",
        state="open",
        network_reachable=True,
    )
    db_session.add(service)
    db_session.flush()
    before = datetime.now(timezone.utc)

    assert record_port_reachability(db_session, asset.id, 22, False) is True

    assert service in db_session.dirty  # written, not yet flushed or committed
    assert service.state == "closed"
    assert service.network_reachable is False
    assert service.updated_at >= before

    assert record_port_reachability(db_session, asset.id, 22, True) is True
    assert (service.state, service.network_reachable) == ("open", True)


def test_the_writer_reports_a_port_with_no_service_row(
    db_session: Session, asset: Asset
):
    assert record_port_reachability(db_session, asset.id, 2222, True) is False

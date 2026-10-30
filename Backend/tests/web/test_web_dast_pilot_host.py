"""
The D2 web DAST reuse pilot (Group 4, docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md):
web DAST mounted in a host application that is not Audit's, the
``tests/modules/example`` pattern.

The host is a bare ``FastAPI()`` holding the ``/web-scans`` router and nothing
else. It brings its own identity provider — a stub standing in for the
platform's token verification, which hands the routes whichever account the
test names — and its own web settings, ``PilotWebSettings``. Authorization is
not stubbed: every route still asks the RBAC engine through
``require_authorized``, so a stub account holding no grant is refused.

The engine half — the tool wrappers, the crawler, the nuclei profiles and the
OAST client on the pilot's settings, in a fresh interpreter that refuses
``config`` — is ``test_web_dast_engine_pilot.py``, which the library isolation
harness runs as library ``web_dast``.

Rows are committed and removed by prefix, as in
``test_web_scan_authorization.py``; nothing logs in, because a login commits
the session the app shares with the fixtures.
"""

import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException, status
from fastapi.testclient import TestClient

from config import WebScanConfig
from core.web import settings as web_settings
from core.web.sqlmap.wrapper import SqlmapWrapper
from ccure_platform.identity.dependencies import get_current_user
from db.base import gen_user_id, get_db, utcnow
from db.models.web_scans import WebScan
from native_rbac import create_user, fixture_role
from routers import web_scans as web_scans_router
from scripts.architecture import capability_map as cm
from scripts.architecture.import_graph import collect_edges
from test_web_dast_engine_pilot import PilotWebSettings
from testpaths import BACKEND_ROOT

_PREFIX = "wsc_pilot_"


class StubIdentityProvider:
    """The host's identity: the account it was told is signed in, or none."""

    def __init__(self):
        self.account = None

    def __call__(self):
        if self.account is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "not signed in")
        return self.account


@pytest.fixture
def pilot_settings(monkeypatch):
    monkeypatch.setattr(web_settings, "_settings", None)
    web_settings.configure(PilotWebSettings)
    return PilotWebSettings


@pytest.fixture
def host(db_session, pilot_settings):
    identity = StubIdentityProvider()
    app = FastAPI(title="Web DAST pilot host")
    app.include_router(web_scans_router.router)
    app.dependency_overrides[get_current_user] = identity
    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as client:
        yield client, identity
    db_session.rollback()
    db_session.query(WebScan).filter(WebScan.id.like(f"{_PREFIX}%")).delete(
        synchronize_session=False
    )
    db_session.commit()


def _account(db, org, keys):
    uid = uuid.uuid4().hex[:8]
    role = fixture_role(db, f"pilot_{uid}", keys=keys) if keys else None
    user = create_user(
        db,
        id=gen_user_id(org.slug, f"pilot{uid}"),
        username=f"pilot{uid}",
        email=f"pilot{uid}@test.com",
        full_name="pilot",
        password_hash="x",
        org_id=org.id,
        role=role,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _scan(db, org_id):
    scan = WebScan(
        id=f"{_PREFIX}{uuid.uuid4().hex[:12]}",
        org_id=org_id,
        target_url="http://target.invalid/",
        target_domain="target.invalid",
        authorization_confirmed=True,
        scan_name="pilot",
        status="completed",
        created_at=utcnow(),
        started_at=utcnow(),
    )
    db.add(scan)
    db.commit()
    return scan


def test_audit_registers_its_own_configuration():
    # main.py loads the composition root; the pilot fixtures swap it out.
    assert web_settings.current() is WebScanConfig


def test_the_host_serves_web_dast_to_its_signed_in_account(host, db_session, test_org):
    client, identity = host
    scan = _scan(db_session, test_org.id)
    identity.account = _account(db_session, test_org, ["audit.scan.read"])

    listed = client.get("/web-scans")
    assert listed.status_code == 200
    assert scan.id in [row["id"] for row in listed.json()["data"]]
    detail = client.get(f"/web-scans/{scan.id}")
    assert detail.status_code == 200
    assert detail.json()["data"]["target_url"] == "http://target.invalid/"


def test_authorization_is_still_the_engines(host, db_session, test_org):
    client, identity = host
    scan = _scan(db_session, test_org.id)

    assert client.get(f"/web-scans/{scan.id}").status_code == 401
    identity.account = _account(db_session, test_org, [])
    assert client.get(f"/web-scans/{scan.id}").status_code == 403
    identity.account = _account(db_session, test_org, ["audit.finding.read"])
    assert client.get(f"/web-scans/{scan.id}").status_code == 403
    assert client.get(f"/web-scans/{scan.id}/findings").status_code == 200


def test_the_engine_ignores_the_global_configuration(host, monkeypatch):
    monkeypatch.setattr(WebScanConfig, "SQLMAP_BINARY", "/global/bin/sqlmap")
    monkeypatch.setattr(WebScanConfig, "SQLMAP_TIMEOUT", 1)
    sqlmap = SqlmapWrapper()
    assert (sqlmap.binary, sqlmap.timeout) == ("/pilot/bin/sqlmap", 654)


def test_no_web_dast_module_imports_the_global_configuration():
    _, edges = collect_edges(Path(BACKEND_ROOT))
    importers = sorted(
        {
            edge.src
            for edge in edges
            if cm.capability_of(edge.src) == "web_dast"
            and edge.dst.split(".")[0] == "config"
        }
    )
    assert importers == []

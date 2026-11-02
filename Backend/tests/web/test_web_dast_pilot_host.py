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

Since 2 Nov 2026 the router names no identity, session or limiter of its own:
its progress WebSocket signs in through ``ccure_platform.api.websocket_user``
and reads through the request's session, so the host's stubs serve the socket
too; its two rate limits are declared through ``core.web.rate_limits`` and
enforced by the limiter the host registers (``test_web_dast_rate_limits.py``).

Rows are committed and removed by prefix, as in
``test_web_scan_authorization.py``; nothing logs in, because a login commits
the session the app shares with the fixtures.
"""

import ast
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException, WebSocketDisconnect, status
from fastapi.testclient import TestClient

from config import WebScanConfig
from core.web import settings as web_settings
from core.web.sqlmap.wrapper import SqlmapWrapper
from ccure_platform.identity.dependencies import get_current_user, get_websocket_user
from db.base import SessionLocal, gen_user_id, get_db, utcnow
from db.models import Organization
from db.models.web_scans import WebScan
from native_rbac import create_user, fixture_role
from routers import web_scans as web_scans_router
from scripts.architecture import capability_map as cm
from scripts.architecture.identity_boundary import PLATFORM_API_SURFACE
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


# ── The progress socket, through the host's stubs ─────────────────────────────


class _QuietPubSub:
    """Redis's place: subscribes, then reports the client gone."""

    async def subscribe(self, channel):
        self.channel = channel

    async def get_message(self, **_):
        raise WebSocketDisconnect(1000)

    async def unsubscribe(self, channel):
        pass

    async def close(self):
        pass


class _QuietRedis:
    def pubsub(self):
        return _QuietPubSub()


def _fresh_session():
    # The socket closes its session before subscribing, so it is not handed
    # the fixtures' shared one.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def socket_host(host, monkeypatch):
    client, identity = host
    socket_identity = {"account": None}
    client.app.dependency_overrides[get_websocket_user] = lambda: socket_identity[
        "account"
    ]
    client.app.dependency_overrides[get_db] = _fresh_session
    monkeypatch.setattr(web_scans_router, "redis_client", _QuietRedis())
    return client, socket_identity


def test_the_host_signs_the_progress_socket_in(socket_host, db_session, test_org):
    client, identity = socket_host
    scan = _scan(db_session, test_org.id)
    identity["account"] = _account(db_session, test_org, [])

    with client.websocket_connect(f"/web-scans/{scan.id}/progress") as socket:
        frame = socket.receive_json()
    assert frame["scan_id"] == scan.id
    assert frame["scan_type"] == "web"
    assert frame["scan"]["target_url"] == "http://target.invalid/"
    assert frame["progress"]["percentage"] == 100


def test_the_progress_socket_refuses_no_account(socket_host, db_session, test_org):
    client, _ = socket_host
    scan = _scan(db_session, test_org.id)
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect(f"/web-scans/{scan.id}/progress"):
            pass
    assert refused.value.code == 1008


def test_the_progress_socket_keeps_to_the_accounts_organisation(
    socket_host, db_session, test_org
):
    client, identity = socket_host
    uid = uuid.uuid4().hex[:8]
    other = Organization(
        id=f"org_{uid}", name=f"Other {uid}", slug=f"other-{uid}", is_active=True
    )
    db_session.add(other)
    db_session.commit()
    scan = _scan(db_session, other.id)
    identity["account"] = _account(db_session, test_org, [])

    with client.websocket_connect(f"/web-scans/{scan.id}/progress") as socket:
        frame = socket.receive_json()
        assert frame["phase"] == "not_found"
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_json()
    assert closed.value.code == 1008


# ── What the router imports ───────────────────────────────────────────────────


def test_the_router_names_no_identity_session_or_limiter_of_its_own():
    tree = ast.parse((BACKEND_ROOT / "routers" / "web_scans.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported |= {f"{node.module}.{alias.name}" for alias in node.names}
    refused = (
        "auth.",  # the legacy identity paths, decode_token among them
        "ccure_platform.identity",
        "ccure_platform.models",
        "db.models.User",
        "db.base.SessionLocal",
        "core.rate_limiter",
        "scan_helpers",
        "slowapi",
    )
    assert sorted(n for n in imported if n.startswith(refused)) == []
    platform = {n for n in imported if n.startswith("ccure_platform.")}
    surface = {f"ccure_platform.api.{name}" for name in PLATFORM_API_SURFACE}
    assert platform <= surface | {"ccure_platform.api"}


def test_importing_the_router_loads_no_limiter():
    profile = cm.measure()["load_profiles"]["routers.web_scans"]
    assert "slowapi" not in profile["third_party"]

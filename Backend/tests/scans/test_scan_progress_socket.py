"""
The scan progress WebSocket signs in through the platform (2 Nov 2026).

``/scans/{id}/progress`` used to authenticate its ticket itself, with the
any-kind ``decode_token``, a ``type`` check and its own ``users`` query. It asks
``ccure_platform.api.websocket_user`` now, as web DAST's socket does, and still
requires ``audit.scan.read`` through the RBAC engine. These pin what it
accepts and refuses — every refusal closes with 1008 before accepting — and
that it still shows a member only the scans their reach covers.

One thing is stricter than before, by design: a deleted or inactive account is
refused, as it is on every HTTP route; the socket's own login never checked.
"""

import json
import uuid

import pytest
from auth.jwt_handler import create_access_token, create_download_ticket
from db.base import SessionLocal, gen_user_id, get_db, utcnow
from db.models import Organization, Scan
from fastapi import FastAPI, WebSocketDisconnect
from fastapi.testclient import TestClient
from native_rbac import create_user, fixture_role
from routers import scan_history

import core.redis_client


#: The progress frame the stand-in Redis relays after the state frame, if any.
RELAYED = {"scan_id": "relayed", "phase": 2, "progress": {"status": "running"}}


class _QuietPubSub:
    """Redis's place: relays one progress frame, then reports the client gone."""

    def __init__(self):
        self.relayed = False

    async def subscribe(self, channel):
        pass

    async def get_message(self, **_):
        if not self.relayed:
            self.relayed = True
            return {"data": json.dumps(RELAYED)}
        raise WebSocketDisconnect(1000)

    async def unsubscribe(self, channel):
        pass


class _QuietRedis:
    def pubsub(self):
        return _QuietPubSub()


def _fresh_session():
    # The socket closes its session before subscribing; it gets its own.
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(core.redis_client, "redis_client", _QuietRedis())
    app = FastAPI()
    app.include_router(scan_history.router)
    app.dependency_overrides[get_db] = _fresh_session
    with TestClient(app) as test_client:
        yield test_client


def _account(db, org, keys, **state):
    uid = uuid.uuid4().hex[:8]
    user = create_user(
        db,
        id=gen_user_id(org.slug, f"sock{uid}"),
        username=f"sock{uid}",
        email=f"sock{uid}@test.com",
        full_name="socket",
        password_hash="x",
        org_id=org.id,
        role=fixture_role(db, f"sock_{uid}", keys=keys) if keys else None,
        is_active=state.pop("is_active", True),
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
        **state,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _scan(db, org, owner):
    scan = Scan(
        id=f"scn_sock_{uuid.uuid4().hex[:10]}",
        org_id=org.id,
        created_by=owner.id,
        target_str="192.0.2.10",
        status="completed",
    )
    db.add(scan)
    db.commit()
    return scan


def _ticket(user):
    return create_download_ticket(user.id, user.username)


def _refused(client, path) -> int:
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect(path):
            pass
    return refused.value.code


def test_a_reader_receives_the_scans_state(client, db_session, test_org):
    reader = _account(db_session, test_org, ["audit.scan.read"])
    scan = _scan(db_session, test_org, reader)

    path = f"/scans/{scan.id}/progress?ticket={_ticket(reader)}"
    with client.websocket_connect(path) as socket:
        frame = socket.receive_json()
    assert frame["scan_id"] == scan.id
    assert frame["progress"]["status"] == "completed"
    assert frame["progress"]["scan_status"] == "completed"


@pytest.mark.parametrize("query", ["", "?ticket=", "?ticket=not-a-token"])
def test_no_valid_ticket_closes_with_1008(client, db_session, test_org, query):
    reader = _account(db_session, test_org, ["audit.scan.read"])
    scan = _scan(db_session, test_org, reader)
    assert _refused(client, f"/scans/{scan.id}/progress{query}") == 1008


def test_an_access_token_is_not_a_ticket(client, db_session, test_org):
    reader = _account(db_session, test_org, ["audit.scan.read"])
    scan = _scan(db_session, test_org, reader)
    access = create_access_token(reader.id, reader.username, org_id=test_org.id)
    assert _refused(client, f"/scans/{scan.id}/progress?ticket={access}") == 1008


def test_an_account_without_scan_read_is_refused(client, db_session, test_org):
    owner = _account(db_session, test_org, ["audit.scan.read"])
    scan = _scan(db_session, test_org, owner)
    nobody = _account(db_session, test_org, ["audit.finding.read"])
    path = f"/scans/{scan.id}/progress?ticket={_ticket(nobody)}"
    assert _refused(client, path) == 1008


def test_an_inactive_account_is_refused(client, db_session, test_org):
    reader = _account(db_session, test_org, ["audit.scan.read"], is_active=False)
    scan = _scan(db_session, test_org, reader)
    path = f"/scans/{scan.id}/progress?ticket={_ticket(reader)}"
    assert _refused(client, path) == 1008


def test_a_scan_outside_the_readers_reach_sends_no_state(client, db_session, test_org):
    """Another organisation's scan, and a colleague's without read_all: the
    socket accepts and relays progress frames as before, but sends no state —
    the first frame a reader receives is the relayed one."""
    reader = _account(db_session, test_org, ["audit.scan.read"])
    colleague = _account(db_session, test_org, ["audit.scan.read"])
    uid = uuid.uuid4().hex[:8]
    other = Organization(
        id=f"org_{uid}", name=f"Other {uid}", slug=f"other-{uid}", is_active=True
    )
    db_session.add(other)
    db_session.commit()
    stranger = _account(db_session, other, ["audit.scan.read"])

    for scan in (
        _scan(db_session, other, stranger),
        _scan(db_session, test_org, colleague),
    ):
        path = f"/scans/{scan.id}/progress?ticket={_ticket(reader)}"
        with client.websocket_connect(path) as socket:
            assert socket.receive_json() == RELAYED


def test_the_router_names_no_token_decoder_or_users_model():
    import ast
    from pathlib import Path

    tree = ast.parse(Path(scan_history.__file__).read_text(encoding="utf-8"))
    imported = {
        f"{node.module}.{alias.name}"
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
        for alias in node.names
    }
    assert not {
        n for n in imported if n.startswith(("auth.", "ccure_platform.identity"))
    }
    assert "db.models.User" not in imported

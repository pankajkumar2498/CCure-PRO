"""
``ccure_platform.api.websocket_user`` — a WebSocket's ticket login (D2,
2 Nov 2026).

Web DAST's progress socket used to sign itself in: the any-kind
``decode_token``, a ``type == "ticket"`` check and its own ``users`` query.
The platform answers it now, and these pin that the answer is the one the
socket gave: an account for a valid ticket naming an active account, and None
— the socket then closes with 1008 before accepting — for a missing, empty,
malformed or wrong-kind token, an unknown account, an inactive one and a
deleted one. The account is read in the request's session.
"""

from __future__ import annotations

import uuid

import pytest
from auth.jwt_handler import create_access_token, create_download_ticket
from ccure_platform import api
from db.base import gen_user_id, get_db, utcnow
from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.testclient import TestClient
from native_rbac import create_user


@pytest.fixture
def client(db_session):
    app = FastAPI()

    @app.websocket("/socket")
    async def socket(websocket: WebSocket, account=Depends(api.websocket_user)):
        if account is None:
            await websocket.close(code=1008)
            return
        await websocket.accept()
        await websocket.send_json({"id": account.id})
        await websocket.close()

    app.dependency_overrides[get_db] = lambda: db_session
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def account(db_session, test_org):
    uid = uuid.uuid4().hex[:8]
    user = create_user(
        db_session,
        id=gen_user_id(test_org.slug, f"ws{uid}"),
        username=f"ws{uid}",
        email=f"ws{uid}@test.com",
        full_name="socket",
        password_hash="x",
        org_id=test_org.id,
        role=None,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _signed_in(client, query: str):
    with client.websocket_connect(f"/socket{query}") as socket:
        return socket.receive_json()["id"]


def _refused(client, query: str) -> int:
    with pytest.raises(WebSocketDisconnect) as refused:
        with client.websocket_connect(f"/socket{query}"):
            pass
    return refused.value.code


def test_a_ticket_signs_its_account_in(client, account):
    ticket = create_download_ticket(account.id, account.username)
    assert _signed_in(client, f"?ticket={ticket}") == account.id


@pytest.mark.parametrize("query", ["", "?ticket=", "?ticket=not-a-token"])
def test_no_valid_ticket_is_refused(client, query):
    assert _refused(client, query) == 1008


def test_another_kind_of_token_is_refused(client, account):
    access = create_access_token(account.id, account.username, org_id=account.org_id)
    assert _refused(client, f"?ticket={access}") == 1008


def test_a_ticket_for_no_account_is_refused(client):
    ticket = create_download_ticket("usr_nobody", "nobody")
    assert _refused(client, f"?ticket={ticket}") == 1008


@pytest.mark.parametrize("state", [{"is_active": False}, {"is_deleted": True}])
def test_an_inactive_or_deleted_account_is_refused(client, account, db_session, state):
    ticket = create_download_ticket(account.id, account.username)
    for field, value in state.items():
        setattr(account, field, value)
    db_session.commit()
    assert _refused(client, f"?ticket={ticket}") == 1008


def test_the_platform_api_exports_it():
    assert "websocket_user" in api.__all__

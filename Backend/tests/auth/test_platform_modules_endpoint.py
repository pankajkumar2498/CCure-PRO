"""
Phase 12.1 — ``GET /platform/modules``, CCure Home's product list.

* a signed-out caller is refused exactly as every other signed-in route refuses
  one — the endpoint adds no new authentication behaviour;
* a signed-in caller receives the registry's four products, in order, and the
  vocabulary of availability states — nothing more;
* the least-privileged role receives the same list as an administrator: nothing
  is filtered by user (owner decision D12-4);
* the route is GET only and appears in the OpenAPI document under "Platform".
"""

from __future__ import annotations

import pytest

from ccure_platform.modules import TILE_STATES, products

PRODUCT_FIELDS = {"key", "title", "kind", "description", "entry_path", "tile_state"}


def _expected() -> dict:
    return {
        "tile_states": list(TILE_STATES),
        "modules": [
            {
                "key": p.key,
                "title": p.title,
                "kind": p.kind,
                "description": p.description,
                "entry_path": p.entry_path,
                "tile_state": p.tile_state,
            }
            for p in products()
        ],
    }


def test_a_signed_out_caller_is_refused_like_any_signed_in_route(client):
    # The existing behaviour, kept as it is (D12-8): a request with no
    # credentials is refused by the shared dependency with 403 "Not
    # authenticated", exactly as /auth/me and every Audit route refuse it.
    response = client.get("/platform/modules")
    for reference in ("/auth/me", "/dashboard/summary"):
        other = client.get(reference)
        assert (response.status_code, response.json()["message"]) == (
            other.status_code,
            other.json()["message"],
        ), reference
    assert response.status_code == 403
    assert "entry_path" not in response.text


def test_a_garbage_token_is_refused(client):
    response = client.get(
        "/platform/modules", headers={"Authorization": "Bearer not-a-token"}
    )
    assert response.status_code == 401


def test_a_signed_in_caller_receives_the_registrys_four_products(client, auth_headers):
    response = client.get("/platform/modules", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body == _expected()
    assert set(body) == {"tile_states", "modules"}
    assert [m["key"] for m in body["modules"]] == ["policy_pro", "audit", "rank", "ir"]
    for m in body["modules"]:
        assert set(m) == PRODUCT_FIELDS, m["key"]


@pytest.fixture
def viewer_headers(client, db_session, test_org, test_role_viewer):
    from auth.jwt_handler import hash_password
    from db.base import gen_user_id, utcnow
    from db.models import User

    user = User(
        id=gen_user_id(test_org.slug, "hubviewer"),
        username="hubviewer",
        email="hubviewer@test.com",
        full_name="Hub Viewer",
        password_hash=hash_password("securepassword123"),
        org_id=test_org.id,
        role_id=test_role_viewer.id,
        is_active=True,
        is_verified=True,
        approved_at=utcnow(),
        approved_by="fixture",
    )
    db_session.add(user)
    db_session.commit()
    login = client.post(
        "/auth/login",
        json={"email": "hubviewer@test.com", "password": "securepassword123"},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_the_least_privileged_role_sees_the_same_four_products(
    client, auth_headers, viewer_headers
):
    admin = client.get("/platform/modules", headers=auth_headers)
    viewer = client.get("/platform/modules", headers=viewer_headers)
    assert viewer.status_code == 200
    assert viewer.json() == admin.json() == _expected()


def test_the_route_is_get_only_and_documented_under_platform(client, auth_headers):
    from main import app

    operations = app.openapi()["paths"]["/platform/modules"]
    assert set(operations) == {"get"}
    assert operations["get"]["tags"] == ["Platform"]
    assert (
        client.post("/platform/modules", headers=auth_headers, json={}).status_code
        == 405
    )

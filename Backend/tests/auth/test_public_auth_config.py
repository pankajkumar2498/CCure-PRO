"""The registration UI reads policy directly, without an availability oracle."""

import pytest
from config import AppConfig
from db.models import RegistrationPolicy


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer invalid-session"}])
def test_public_auth_config_is_explicit_and_session_independent(
    client, monkeypatch, enabled, headers
):
    monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", enabled)

    for _ in range(12):
        response = client.get("/auth/config", headers=headers)
        assert response.status_code == 200
        assert response.json() == {"self_registration_enabled": enabled}
        assert response.headers["Cache-Control"] == "no-store"
        assert "set-cookie" not in response.headers


def test_public_auth_config_reads_the_current_setting(client, monkeypatch):
    for enabled in (True, False, True):
        monkeypatch.setattr(AppConfig, "ALLOW_SELF_REGISTRATION", enabled)
        assert client.get("/auth/config").json() == {
            "self_registration_enabled": enabled
        }


def test_public_auth_config_reads_no_accounts(client, db_session):
    from sqlalchemy import event

    statements = []

    def capture(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    engine = db_session.get_bind()
    event.listen(engine, "before_cursor_execute", capture)
    try:
        assert client.get("/auth/config").status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert statements and all(RegistrationPolicy.__tablename__ in s for s in statements)

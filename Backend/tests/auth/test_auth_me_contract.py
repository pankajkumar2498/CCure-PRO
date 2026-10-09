"""
RBAC-8 — ``/auth/me`` and the sign-in profile expose only the Platform RBAC contract: no
legacy role object, role id, role name or permission atom, and nothing a client could
mistake for an authorization input.
"""

from __future__ import annotations

import json

from ccure_platform.identity.router import _user_payload

PROFILE_KEYS = {
    "id",
    "org_id",
    "username",
    "email",
    "full_name",
    "created_at",
    "mfa_enabled",
    "organization",
    "authorization",
}
AUTHORIZATION_KEYS = {
    "contract",
    "home_org_id",
    "active_org_id",
    "permissions",
    "can_switch_organisation",
    "assignments",
}


def test_the_profile_has_exactly_the_contract_fields(db_session, test_user):
    payload = _user_payload(db_session, test_user)
    assert set(payload) == PROFILE_KEYS
    assert set(payload["authorization"]) == AUTHORIZATION_KEYS
    assert payload["authorization"]["contract"] == 1


def test_no_legacy_vocabulary_reaches_the_client(db_session, test_user):
    blob = json.dumps(_user_payload(db_session, test_user), default=str)
    for forbidden in (
        '"role"',
        '"role_id"',
        '"role_name"',
        '"atoms"',
        '"source"',
        "legacy",
    ):
        assert forbidden not in blob, forbidden
    # no permission atom (resource:action) anywhere
    permissions = _user_payload(db_session, test_user)["authorization"]["permissions"]
    assert all(":" not in key for scope in permissions.values() for key in scope)


def test_assignments_are_labels_and_scopes_only(db_session, test_user):
    for row in _user_payload(db_session, test_user)["authorization"]["assignments"]:
        assert set(row) == {"display_name", "scope_type"}

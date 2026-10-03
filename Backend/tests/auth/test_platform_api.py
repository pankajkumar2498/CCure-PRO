"""
``ccure_platform.api`` — the functions modules reach identity through (step 8.3).

Each function replaced one or more direct queries in module code, so each is
tested against the behaviour of the query it replaced: the same rows, the same
answer for a missing id, and no ORM object crossing the boundary.
"""

from __future__ import annotations

from native_rbac import system_role

import dataclasses
from datetime import datetime, timezone

import pytest

from ccure_platform import api
from db.base import gen_user_id
from native_rbac import create_user
from db.models import User


def _add_user(db, org, role, name, **extra):
    row = create_user(
        db,
        id=gen_user_id(org.slug, name),
        username=name,
        email=f"{name}@test.com",
        full_name=name.title(),
        password_hash="x",
        org_id=org.id,
        role=role,
        is_active=extra.pop("is_active", True),
        is_verified=True,
        approved_at=datetime.now(timezone.utc),
        **extra,
    )
    db.add(row)
    db.commit()
    return row


# ── views hold plain values ──────────────────────────────────────────────────


@pytest.mark.parametrize("view", [api.UserView, api.OrganisationView])
def test_views_are_frozen_plain_dataclasses(view):
    params = view.__dataclass_params__
    assert params.frozen
    for f in dataclasses.fields(view):
        assert f.type in ("str", "bool", "str | None"), (view, f.name, f.type)


def test_organisation_view_carries_no_audit_configuration():
    fields = {f.name for f in dataclasses.fields(api.OrganisationView)}
    for audit_setting in (
        "max_assets",
        "max_scans_per_day",
        "max_concurrent_scans",
        "scan_scope_cidrs",
        "settings",
        "plan",
    ):
        assert audit_setting not in fields


# ── accounts ──────────────────────────────────────────────────────────────────


def test_user_returns_a_view_of_the_account(db_session, test_user):
    view = api.user(db_session, test_user.id)
    assert view == api.UserView(
        id=test_user.id,
        org_id=test_user.org_id,
        username=test_user.username,
        email=test_user.email,
        in_app_alerts=True,
    )
    assert not isinstance(view, User)


@pytest.mark.parametrize("missing", [None, "", "usr_does_not_exist"])
def test_user_is_none_for_an_unknown_id(db_session, missing):
    assert api.user(db_session, missing) is None


def test_user_returns_deleted_and_inactive_accounts_as_they_are(
    db_session, test_org, test_role_viewer
):
    """A scan's owner who has since been disabled is still that scan's owner."""
    row = _add_user(db_session, test_org, test_role_viewer, "gone", is_active=False)
    row.is_deleted = True
    db_session.commit()
    assert api.user(db_session, row.id).id == row.id


def test_user_display_names_are_email_addresses_for_known_ids(db_session, test_user):
    names = api.user_display_names(db_session, [test_user.id, "usr_unknown", None])
    assert names == {test_user.id: test_user.email}
    assert api.user_display_names(db_session, []) == {}


@pytest.mark.parametrize(
    "preferences, expected",
    [({}, True), ({"in_app_alerts": True}, True), ({"in_app_alerts": False}, False)],
)
def test_in_app_alerts_is_off_only_when_explicitly_false(
    db_session, test_user, preferences, expected
):
    test_user.preferences = preferences
    db_session.commit()
    assert api.user(db_session, test_user.id).in_app_alerts is expected


def test_users_holding_permission_matches_the_fan_out_query(
    db_session, test_org, test_role_admin, test_role_viewer
):
    """Who is notified is decided by the permission, never a role name (RBAC-8)."""
    admin = _add_user(db_session, test_org, test_role_admin, "admin1")
    viewer = _add_user(db_session, test_org, test_role_viewer, "viewer1")
    inactive = _add_user(
        db_session, test_org, test_role_admin, "admin2", is_active=False
    )
    deleted = _add_user(db_session, test_org, test_role_admin, "admin3")
    deleted.is_deleted = True
    db_session.commit()

    ids = {
        v.id
        for v in api.users_holding_permission(
            db_session, test_org.id, "platform.user.update"
        )
    }
    assert admin.id in ids
    assert viewer.id not in ids
    assert inactive.id not in ids
    assert deleted.id not in ids
    assert api.users_holding_permission(db_session, test_org.id, "no.such.key") == []
    assert (
        api.users_holding_permission(db_session, "org_other", "platform.user.update")
        == []
    )


# ── RBAC ──────────────────────────────────────────────────────────────────────


def test_has_permission_is_the_engines_rule(db_session, test_org, test_role_viewer):
    viewer = _add_user(db_session, test_org, test_role_viewer, "viewer2")
    superadmin_role = system_role(db_session, "platform.superadmin")
    boss = _add_user(db_session, test_org, superadmin_role, "boss")
    nobody = _add_user(db_session, test_org, None, "norole")  # no role at all

    # by ORM user (what a route holds) and by id (what a task holds) agree
    for account in (viewer, viewer.id):
        assert api.has_permission(db_session, account, "audit.scan.read")
        assert not api.has_permission(db_session, account, "platform.user.delete")
    for account in (boss, boss.id):
        assert api.has_permission(db_session, account, "platform.user.delete")
    # an account with no RBAC assignment, no account and an unknown id hold nothing
    assert not api.has_permission(db_session, nobody, "audit.scan.read")
    assert not api.has_permission(db_session, None, "audit.scan.read")
    assert not api.has_permission(db_session, "usr_unknown", "audit.scan.read")
    assert not api.has_permission(db_session, boss, "no.such.key")


def test_request_identity_is_the_existing_dependencies():
    from ccure_platform.identity import dependencies
    from ccure_platform.rbac import dependencies as rbac

    assert api.current_user is dependencies.get_current_user
    assert api.current_user_flexible is dependencies.get_current_user_flexible
    assert api.require_authorized is rbac.require_authorized
    assert api.has_permission is rbac.has_permission
    # the legacy guards are gone
    assert not hasattr(api, "require_permission")
    assert not hasattr(api, "require_role")
    assert not hasattr(api, "user_has_permission")
    # the principal's type is the identity model, named by the platform (8.5)
    assert api.CurrentUser is User


# ── tenancy ───────────────────────────────────────────────────────────────────


def test_organisation_returns_identity_only(db_session, test_org):
    assert api.organisation(db_session, test_org.id) == api.OrganisationView(
        id=test_org.id, name=test_org.name, slug=test_org.slug
    )


@pytest.mark.parametrize("missing", [None, "", "org_does_not_exist"])
def test_organisation_is_none_for_an_unknown_id(db_session, missing):
    assert api.organisation(db_session, missing) is None

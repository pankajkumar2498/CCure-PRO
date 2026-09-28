"""
``ccure_platform.api`` — the functions modules reach identity through (step 8.3).

Each function replaced one or more direct queries in module code, so each is
tested against the behaviour of the query it replaced: the same rows, the same
answer for a missing id, and no ORM object crossing the boundary.
"""

from __future__ import annotations

import dataclasses

import pytest

from ccure_platform import api
from db.base import gen_user_id
from db.models import Role, User


def _add_user(db, org, role, name, **extra):
    row = User(
        id=gen_user_id(org.slug, name),
        username=name,
        email=f"{name}@test.com",
        full_name=name.title(),
        password_hash="x",
        org_id=org.id,
        role_id=role.id if role is not None else None,
        is_active=extra.pop("is_active", True),
        is_verified=True,
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


def test_active_members_with_roles_matches_the_fan_out_query(
    db_session, test_org, test_role_admin, test_role_viewer
):
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
        for v in api.active_members_with_roles(db_session, test_org.id, ["org_admin"])
    }
    assert admin.id in ids
    assert viewer.id not in ids
    assert inactive.id not in ids
    assert deleted.id not in ids
    assert (
        api.active_members_with_roles(db_session, test_org.id, ["no_such_role"]) == []
    )
    assert api.active_members_with_roles(db_session, "org_other", ["org_admin"]) == []


# ── RBAC ──────────────────────────────────────────────────────────────────────


def test_user_has_permission_is_require_permissions_rule(
    db_session, test_org, test_role_viewer
):
    viewer = _add_user(db_session, test_org, test_role_viewer, "viewer2")
    superadmin_role = db_session.query(Role).filter(Role.name == "superadmin").first()
    boss = _add_user(db_session, test_org, superadmin_role, "boss")
    # users.role_id is NOT NULL, so a role-less account exists only in memory —
    # which is the case require_permission guards against.
    nobody = User(id="usr_norole", role_id=None)

    # by ORM user (what a route holds) and by id (what a task holds) agree
    for account in (viewer, viewer.id):
        assert api.user_has_permission(db_session, account, "scans", "read")
        assert not api.user_has_permission(db_session, account, "users", "delete")
    for account in (boss, boss.id):
        assert api.user_has_permission(db_session, account, "anything", "at_all")
    assert not api.user_has_permission(db_session, nobody, "scans", "read")
    assert not api.user_has_permission(db_session, None, "scans", "read")
    assert not api.user_has_permission(db_session, "usr_unknown", "scans", "read")


def test_request_identity_is_the_existing_dependencies():
    from ccure_platform.identity import dependencies
    from ccure_platform.rbac import dependencies as rbac

    assert api.current_user is dependencies.get_current_user
    assert api.current_user_flexible is dependencies.get_current_user_flexible
    assert api.require_permission is rbac.require_permission
    assert api.require_role is rbac.require_role


# ── tenancy ───────────────────────────────────────────────────────────────────


def test_organisation_returns_identity_only(db_session, test_org):
    assert api.organisation(db_session, test_org.id) == api.OrganisationView(
        id=test_org.id, name=test_org.name, slug=test_org.slug
    )


@pytest.mark.parametrize("missing", [None, "", "org_does_not_exist"])
def test_organisation_is_none_for_an_unknown_id(db_session, missing):
    assert api.organisation(db_session, missing) is None

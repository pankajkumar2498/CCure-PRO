"""
RBAC-1 — resolving grants from rows, the stable ``ccure_platform.api`` surface,
and the property that a role's name never matters.

Nothing here touches a live route: the new API is exercised on a throwaway
FastAPI app, with the account supplied by a dependency override.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import ccure_platform.api as api
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import contract as c
from ccure_platform.rbac import resolver
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacRole, RbacUserRole
from db.base import get_db
from rbac_testing import (
    assign,
    custom_org_role,
    decl,
    grant,
    make_org,
    make_user,
    platform_custom_role,
    rbac_db_fixture,  # noqa: F401  (registers the rbac_db fixture)
    role,
    source,
)

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


@pytest.fixture
def world(rbac_db):
    """A catalogue and two organisations with an analyst and a viewer in each."""
    sync(
        rbac_db,
        [
            source(
                "example",
                decl(
                    "example.widget.read",
                    default_grants=("platform.viewer", "platform.analyst"),
                ),
                decl("example.widget.write", default_grants=("platform.analyst",)),
                decl("example.widget.admin", scope_kind="platform"),
                decl("example.widget.audit"),
            ),
            source(
                "platform",
                c.PermissionDecl(
                    key=c.ORG_SWITCH_KEY,
                    description="Enter another organisation",
                    scope_kind="platform",
                    delegable_to_org_roles=False,
                ),
            ),
        ],
    )
    a, b = make_org(rbac_db), make_org(rbac_db)
    w = type("World", (), {})()
    w.db, w.a, w.b = rbac_db, a, b
    w.viewer_a = make_user(rbac_db, a)
    w.analyst_a = make_user(rbac_db, a)
    w.viewer_b = make_user(rbac_db, b)
    assign(rbac_db, w.viewer_a, role(rbac_db, "platform.viewer"))
    assign(rbac_db, w.analyst_a, role(rbac_db, "platform.analyst"))
    assign(rbac_db, w.viewer_b, role(rbac_db, "platform.viewer"))
    return w


def keys(db, user, org=None):
    return set(api.effective_permissions(db, user, org_id=org).permissions)


# ── resolution ───────────────────────────────────────────────────────────────


def test_a_user_holds_what_their_roles_grant_in_their_own_organisation(world):
    assert keys(world.db, world.viewer_a) == {"example.widget.read"}
    assert keys(world.db, world.analyst_a) == {
        "example.widget.read",
        "example.widget.write",
    }


def test_a_user_with_no_assignment_holds_nothing(world):
    stranger = make_user(world.db, world.a)
    assert keys(world.db, stranger) == set()
    assert not api.can(world.db, stranger, "example.widget.read")


def test_permissions_never_cross_organisations(world):
    assert not api.can(
        world.db,
        world.viewer_a,
        "example.widget.read",
        scope=api.ScopeContext(resource_org_id=world.b.id),
    )
    assert api.can(
        world.db,
        world.viewer_b,
        "example.widget.read",
        scope=api.ScopeContext(resource_org_id=world.b.id),
    )


def test_several_roles_union_their_permissions(world):
    extra = custom_org_role(world.db, world.a, "extra", "Extra", "example.widget.audit")
    assign(world.db, world.viewer_a, extra)
    assert keys(world.db, world.viewer_a) == {
        "example.widget.read",
        "example.widget.audit",
    }


def test_a_revoked_assignment_grants_nothing_on_the_very_next_call(world):
    assert api.can(world.db, world.viewer_a, "example.widget.read")
    row = world.db.query(RbacUserRole).filter_by(user_id=world.viewer_a.id).one()
    row.revoked_at, row.revoke_reason = NOW(), "manual"
    world.db.flush()
    assert not api.can(world.db, world.viewer_a, "example.widget.read")


def test_an_expired_assignment_grants_nothing(world):
    user = make_user(world.db, world.a)
    world.db.add(
        RbacUserRole(
            user_id=user.id,
            role_id=role(world.db, "platform.viewer").id,
            scope_type="organization",
            scope_org_id=world.a.id,
            granted_at=NOW() - timedelta(days=2),
            expires_at=NOW() - timedelta(days=1),
        )
    )
    world.db.flush()
    assert keys(world.db, user) == set()
    # and the same row would have granted had it not expired
    world.db.query(RbacUserRole).filter_by(user_id=user.id).delete()
    world.db.flush()
    assign(world.db, user, role(world.db, "platform.viewer"))
    assert keys(world.db, user) == {"example.widget.read"}


def test_a_retiring_role_still_grants_and_a_retired_role_does_not(world):
    custom = custom_org_role(world.db, world.a, "lead", "Lead", "example.widget.read")
    user = make_user(world.db, world.a)
    assignment = assign(world.db, user, custom)
    custom.state = "retiring"
    world.db.flush()
    assert keys(world.db, user) == {
        "example.widget.read"
    }  # no outage during retirement
    assignment.revoked_at, assignment.revoke_reason = NOW(), "role_retired"
    custom.state, custom.retired_at = "retired", NOW()
    world.db.flush()
    assert keys(world.db, user) == set()


def test_a_retired_permission_is_never_granted(world):
    from ccure_platform.rbac.model import RbacPermission

    row = world.db.get(RbacPermission, "example.widget.read")
    row.status, row.retired_at = "retired", NOW()
    world.db.flush()
    assert not api.can(world.db, world.viewer_a, "example.widget.read")
    assert (
        api.authorize(world.db, world.viewer_a, "example.widget.read").reason
        == c.RETIRED_PERMISSION
    )


def test_an_inactive_account_holds_nothing(world):
    world.viewer_a.is_active = False
    world.db.flush()
    assert not api.can(world.db, world.viewer_a, "example.widget.read")
    world.viewer_a.is_active, world.viewer_a.is_deleted = True, True
    assert not api.can(world.db, world.viewer_a, "example.widget.read")


def test_a_platform_role_is_a_materialised_set_with_no_special_case(world):
    boss = make_user(world.db, world.a)
    assign(world.db, boss, role(world.db, "platform.superadmin"))
    granted = keys(world.db, boss)
    assert {"example.widget.read", "example.widget.write"} <= granted
    assert api.can(world.db, boss, "example.widget.admin")  # platform scope
    # the grants are rows; there is no wildcard row
    from ccure_platform.rbac.model import RbacRolePermission

    rows = {
        r.permission_key
        for r in world.db.query(RbacRolePermission).filter_by(
            role_id=role(world.db, "platform.superadmin").id
        )
    }
    assert all(c.PERMISSION_KEY.match(k) for k in rows)


def test_a_platform_holder_reaches_another_organisation_only_through_the_switch(world):
    boss = make_user(world.db, world.a)
    custom = platform_custom_role(world.db, "boss", "Boss", "example.widget.read")
    assign(world.db, boss, custom)
    there = api.ScopeContext(requested_org_id=world.b.id)
    assert api.can(world.db, boss, "example.widget.read")  # home organisation
    assert not api.can(world.db, boss, "example.widget.read", scope=there)
    assert (
        api.authorize(world.db, boss, "example.widget.read", scope=there).reason
        == c.ORG_SWITCH_REQUIRED
    )
    switcher = platform_custom_role(world.db, "switcher", "Switcher", c.ORG_SWITCH_KEY)
    assign(world.db, boss, switcher)
    assert api.can(world.db, boss, "example.widget.read", scope=there)


def test_effective_permissions_for_another_organisation(world):
    assert keys(world.db, world.viewer_a, world.b.id) == set()


# ── the stable surface ───────────────────────────────────────────────────────


def test_authorize_never_raises_for_a_denial_and_explains_it(world):
    out = api.authorize(world.db, world.viewer_a, "example.widget.write")
    assert out.allowed is False and out.reason == c.MISSING_PERMISSION
    assert (
        api.authorize(world.db, world.viewer_a, "example.nothing.here").reason
        == c.UNKNOWN_PERMISSION
    )


def test_the_api_accepts_a_principal_as_well_as_an_account(world):
    principal = resolver.principal_for_user(world.viewer_a)
    assert api.can(world.db, principal, "example.widget.read")


def test_the_new_api_is_exported_through_ccure_platform_api():
    for name in (
        "PermissionDecl",
        "ScopeContext",
        "Principal",
        "AuthorizationDecision",
        "EffectivePermissionSet",
        "authorize",
        "can",
        "effective_permissions",
        "require",
    ):
        assert name in api.__all__, name


def _app(world, user, key):
    app = FastAPI()

    @app.get("/thing")
    def thing(who=Depends(api.require(key))):
        return {"who": who.id}

    app.dependency_overrides[get_current_user] = lambda: user
    app.dependency_overrides[get_db] = lambda: world.db
    return TestClient(app)


def test_require_answers_200_to_a_holder_and_403_to_everyone_else(world):
    assert (
        _app(world, world.viewer_a, "example.widget.read").get("/thing").status_code
        == 200
    )
    denied = _app(world, world.viewer_a, "example.widget.write").get("/thing")
    assert denied.status_code == 403
    assert "example.widget.write" in denied.json()["detail"]


def test_require_never_lets_a_permission_cross_organisations(world):
    scope = api.ScopeContext(resource_org_id=world.b.id)
    app = FastAPI()

    @app.get("/thing")
    def thing(who=Depends(api.require("example.widget.read", scope=scope))):
        return {}

    app.dependency_overrides[get_current_user] = lambda: world.viewer_a
    app.dependency_overrides[get_db] = lambda: world.db
    assert TestClient(app).get("/thing").status_code == 403


# ── a role's name is never an input ──────────────────────────────────────────

LABELS = [
    "Superadmin",
    "superadmin",
    "CISO",
    "platform.superadmin",
    "Viewer",
    "platform.viewer",
    "org_admin",
    "Org Admin",
    "Scanner",
    "admin",
    "root",
    "  ",
    "Ünïcode",
    "x" * 100,
]


def decisions(world):
    probes = [
        (u, k, scope)
        for u in (world.viewer_a, world.analyst_a, world.viewer_b)
        for k in ("example.widget.read", "example.widget.write", "example.widget.admin")
        for scope in (None, api.ScopeContext(resource_org_id=world.b.id))
    ]
    return [(u.id, k, api.authorize(world.db, u, k, scope=s)) for u, k, s in probes]


def test_renaming_any_role_to_anything_changes_no_decision(world):
    """The display-name fuzz: every role renamed to every label, in random
    combinations — including a viewer called "Superadmin" and "platform.superadmin"
    — and every decision is identical to the one before."""
    before = decisions(world)
    rng = random.Random(20261003)
    roles = world.db.query(RbacRole).filter(RbacRole.state == "active").all()
    keys_before = {r.id: r.key for r in roles}
    for round_ in range(25):
        # two phases: display names are unique among live roles, so a bulk rename
        # must not pass through a collision
        for i, r in enumerate(roles):
            r.display_name = f"tmp-{round_}-{i}"
        world.db.flush()
        used = set()
        for r in roles:
            label = rng.choice(LABELS).strip() or f"label{rng.randrange(10**6)}"
            while label.lower() in used:
                label = f"{label[:90]}{rng.randrange(10**6)}"
            used.add(label.lower())
            r.display_name = label[:100]
        world.db.flush()
        assert decisions(world) == before, [r.display_name for r in roles]
    # the roles' keys and ids never moved
    assert {r.id: r.key for r in roles} == keys_before
    assert {"platform.viewer", "platform.superadmin"} <= set(keys_before.values())


def test_a_viewer_named_superadmin_gains_nothing(world):
    # (names are unique among live roles, so the real one is renamed first)
    role(world.db, "platform.superadmin").display_name = "Chief"
    world.db.flush()
    viewer = role(world.db, "platform.viewer")
    viewer.display_name = "Superadmin"
    world.db.flush()
    assert keys(world.db, world.viewer_a) == {"example.widget.read"}
    assert not api.can(world.db, world.viewer_a, "example.widget.admin")


def test_a_superadmin_renamed_to_viewer_loses_nothing(world):
    boss = make_user(world.db, world.a)
    assign(world.db, boss, role(world.db, "platform.superadmin"))
    before = keys(world.db, boss)
    role(world.db, "platform.viewer").display_name = "Reader"
    world.db.flush()
    role(world.db, "platform.superadmin").display_name = "Viewer"
    world.db.flush()
    assert keys(world.db, boss) == before


def test_decisions_and_permission_sets_carry_no_role_identity(world):
    out = api.authorize(world.db, world.viewer_a, "example.widget.read")
    eff = api.effective_permissions(world.db, world.viewer_a)
    for obj in (out, eff):
        text = repr(obj).lower()
        for label in ("viewer", "superadmin", "platform.", "display"):
            assert label not in text, (label, text)
    assert not hasattr(out, "role_id") and not hasattr(eff, "roles")
    grants = resolver.resolve_grants(
        world.db, resolver.principal_for_user(world.viewer_a)
    )
    assert all(
        set(g.__slots__) == {"permission_key", "assignment_scope", "scope_org_id"}
        for g in grants
    )


def test_the_role_repr_never_prints_the_display_name(world):
    row = role(world.db, "platform.viewer")
    row.display_name = "Distinctive Label"
    assert "Distinctive" not in repr(row)

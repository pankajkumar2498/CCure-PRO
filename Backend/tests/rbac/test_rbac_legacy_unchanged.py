"""
RBAC-1 — characterization: the legacy authorization is still the authority.

RBAC-1 is a dark foundation. These tests pin the behaviour it must not change, so
a later edit that quietly reroutes a live check through the new tables fails here
rather than in production:

* ``require_permission`` / ``require_role`` / ``user_has_permission`` are still the
  legacy implementations and still answer from ``users.role_id``, ``roles``,
  ``permissions`` and ``role_permissions``;
* the legacy role and permission tables hold exactly what their seed defines;
* no route in the application is guarded by the new ``require``;
* ``/auth/me`` still returns its legacy shape and nothing from the new model;
* populating the new tables changes no legacy decision.

Each test runs in a rolled-back transaction or reads only.
"""

from __future__ import annotations

import ast
import inspect

import pytest

import ccure_platform.api as api
import ccure_platform.rbac.dependencies as legacy
from ccure_platform.rbac.catalogue import sync
from db.migrate_production_schema import PERMISSIONS, ROLE_PERMISSIONS
from db.models import Permission, Role, RolePermission, User
from rbac_testing import (
    assign,
    decl,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401  (registers the rbac_db fixture)
    role,
    source,
)
from testpaths import BACKEND_ROOT


def with_legacy_role(db, user, name):
    user.role_id = db.query(Role).filter(Role.name == name).one().id
    db.flush()
    db.refresh(user)
    return user


# ── the legacy functions are the live ones ───────────────────────────────────


def test_the_api_still_exports_the_legacy_guards_unchanged():
    assert api.require_permission is legacy.require_permission
    assert api.require_role is legacy.require_role


def test_the_legacy_guards_do_not_mention_the_new_capability():
    for fn in (
        legacy.require_permission,
        legacy.require_role,
        legacy.user_has_permission,
    ):
        source_text = inspect.getsource(fn)
        assert "rbac_" not in source_text and "Rbac" not in source_text
    module_source = inspect.getsource(legacy)
    assert "ccure_platform.rbac.engine" not in module_source
    assert "resolver" not in module_source and "shadow" not in module_source


def test_user_has_permission_still_answers_from_the_legacy_role(rbac_db):
    org = make_org(rbac_db)
    cases = {
        "viewer": (
            ("scans", "read", True),
            ("scans", "execute", False),
            ("users", "create", False),
        ),
        "analyst": (("scans", "execute", True), ("users", "create", False)),
        "scanner": (("scans", "execute", True), ("scans", "read_all", False)),
        "org_admin": (("users", "create", True), ("organizations", "create", False)),
        "superadmin": (("organizations", "create", True), ("anything", "at_all", True)),
    }
    for name, probes in cases.items():
        user = with_legacy_role(rbac_db, make_user(rbac_db, org), name)
        for resource, action, expected in probes:
            assert (
                api.user_has_permission(rbac_db, user, resource, action) is expected
            ), (
                name,
                resource,
                action,
            )


def test_populating_the_new_tables_changes_no_legacy_decision(rbac_db):
    """The new model can hold anything; the legacy decision does not read it."""
    org = make_org(rbac_db)
    viewer = with_legacy_role(rbac_db, make_user(rbac_db, org), "viewer")
    before = api.user_has_permission(rbac_db, viewer, "users", "create")
    sync(
        rbac_db,
        [
            source(
                "example",
                decl("example.users.create", default_grants=("platform.viewer",)),
            )
        ],
    )
    assign(rbac_db, viewer, role(rbac_db, "platform.viewer"))
    assign(rbac_db, viewer, role(rbac_db, "platform.superadmin"))
    assert (
        api.user_has_permission(rbac_db, viewer, "users", "create") is before is False
    )


def test_a_user_with_no_legacy_permission_row_is_still_refused_whatever_the_new_model_says(
    rbac_db,
):
    org = make_org(rbac_db)
    user = with_legacy_role(rbac_db, make_user(rbac_db, org), "viewer")
    assign(rbac_db, user, role(rbac_db, "platform.superadmin"))
    assert api.user_has_permission(rbac_db, user, "organizations", "create") is False


# ── the legacy tables hold exactly what they were seeded with ────────────────


def test_every_seeded_legacy_permission_is_still_there(rbac_db):
    present = {(p.resource, p.action) for p in rbac_db.query(Permission).all()}
    seeded = {(r, a) for r, a, _ in PERMISSIONS}
    assert seeded <= present, sorted(seeded - present)


@pytest.mark.parametrize("name", [n for n in ROLE_PERMISSIONS if n != "superadmin"])
def test_each_legacy_role_holds_exactly_its_seeded_permissions(rbac_db, name):
    row = rbac_db.query(Role).filter(Role.name == name).one()
    held = {
        f"{rp.permission.resource}:{rp.permission.action}"
        for rp in rbac_db.query(RolePermission).filter_by(role_id=row.id)
    }
    assert held == set(ROLE_PERMISSIONS[name]), name


def test_the_five_legacy_roles_still_exist_with_their_names(rbac_db):
    names = {r.name for r in rbac_db.query(Role).all()}
    assert {"superadmin", "org_admin", "analyst", "viewer", "scanner"} <= names


def test_users_role_id_is_still_how_a_user_is_tied_to_a_role():
    column = User.__table__.c.role_id
    assert column.nullable is False
    assert {fk.column.table.name for fk in column.foreign_keys} == {"roles"}
    assert not any(c.name.startswith("rbac") for c in User.__table__.c)


def test_the_legacy_tables_do_not_reference_the_new_ones():
    for table in (
        Role.__table__,
        Permission.__table__,
        RolePermission.__table__,
        User.__table__,
    ):
        for fk in table.foreign_keys:
            assert not fk.column.table.name.startswith("rbac_"), (table.name, fk)


# ── no route was migrated ────────────────────────────────────────────────────


def _dependency_callables(dependant, seen=None):
    seen = seen if seen is not None else set()
    for sub in dependant.dependencies:
        if id(sub) in seen:
            continue
        seen.add(id(sub))
        yield sub.call
        yield from _dependency_callables(sub, seen)


def test_no_route_in_the_application_is_guarded_by_the_new_require():
    from main import app

    new_guards, legacy_guards = 0, 0
    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        for call in _dependency_callables(dependant):
            module = getattr(call, "__module__", "") or ""
            qual = getattr(call, "__qualname__", "")
            if module == "ccure_platform.api" and qual.startswith("require."):
                new_guards += 1
            if qual.startswith(("require_permission.", "require_role.")):
                legacy_guards += 1
    assert new_guards == 0
    assert legacy_guards > 150  # the legacy guards still carry the application


#: The one place outside the platform that may import ``PermissionDecl``: a module's
#: own declaration of its permission catalogue (RBAC-2). It declares data; it makes
#: no decision.
DECLARATION_MODULES = {"ccure_audit/permissions.py"}


def test_no_application_code_imports_the_new_authorization_api_yet():
    offenders = []
    for path in BACKEND_ROOT.rglob("*.py"):
        rel = path.relative_to(BACKEND_ROOT).parts
        if (
            rel[0] in {"tests", ".venv", "venv", "alembic", "__pycache__"}
            or rel[0] == "ccure_platform"
        ):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "ccure_platform.api":
                used = {a.name for a in node.names} & {
                    "authorize",
                    "can",
                    "effective_permissions",
                    "require",
                }
                if "PermissionDecl" in {a.name for a in node.names} and (
                    path.relative_to(BACKEND_ROOT).as_posix() not in DECLARATION_MODULES
                ):
                    used.add("PermissionDecl")
                if used:
                    offenders.append(
                        (str(path.relative_to(BACKEND_ROOT)), sorted(used))
                    )
    assert not offenders, offenders


def test_auth_me_keeps_its_legacy_shape_and_gains_nothing_from_the_new_model(
    client, auth_headers
):
    body = client.get("/auth/me", headers=auth_headers).json()
    assert set(body) == {
        "id",
        "org_id",
        "username",
        "email",
        "full_name",
        "created_at",
        "mfa_enabled",
        "role",
        "organization",
    }
    assert set(body["role"]) == {"name", "permissions"}
    assert all(set(p) == {"resource", "action"} for p in body["role"]["permissions"])
    text = str(body).lower()
    for new_thing in (
        "authorization",
        "effective_permissions",
        "catalogue",
        "display_name",
        "rbac",
    ):
        assert new_thing not in text, new_thing

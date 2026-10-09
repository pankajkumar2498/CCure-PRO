"""
RBAC-8 — the final ratchet. Platform RBAC is the only authorization model, and this file
fails the build if a legacy dependency comes back: a retired mechanism, an authority
switch, a shadow comparison, a read of ``users.role_id`` or a role name as a decision, or
a route guarded by anything but the engine.

Nothing is imported from the application except the route table; everything else is read
from source.
"""

from __future__ import annotations

import ast

import pytest

from testpaths import BACKEND_ROOT, REPO_ROOT

SKIP = {
    ".venv",
    "tests",
    "alembic",
    "__pycache__",
    "node_modules",
    "logs",
    "reports",
    "data",
    "docs",
}

#: Names that were the legacy authorization model. They may exist in history (migrations,
#: docs, the golden mapping, tests) and nowhere else.
RETIRED = {
    "require_permission",
    "require_role",
    "user_has_permission",
    "check_role_assignment",
    "observe_permission",
    "observe_role_check",
    "set_migrated_paths",
    "migrated_paths",
}
RETIRED_SETTINGS = ("RBAC_AUTHORITY_MODE", "RBAC_AUTHORITY_PATHS", "RBAC_SHADOW_MODE")
RETIRED_MODULES = ("authority", "shadow", "shadow_runtime", "legacy_scope")


def runtime_files():
    for path in sorted(BACKEND_ROOT.rglob("*.py")):
        rel = path.relative_to(BACKEND_ROOT).as_posix()
        if SKIP & set(rel.split("/")[:-1]) or rel.startswith("scripts/"):
            continue
        yield rel, path


def test_no_retired_mechanism_is_defined_imported_or_called_in_runtime_code():
    found = []
    for rel, path in runtime_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = [node.name]
            elif isinstance(node, ast.Call):
                f = node.func
                names = [f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")]
            elif isinstance(node, ast.ImportFrom):
                names = [a.name for a in node.names]
            found += [(rel, n) for n in names if n in RETIRED]
    assert not found, found


def test_no_authority_switch_or_shadow_setting_survives():
    haystacks = [BACKEND_ROOT / "config.py", REPO_ROOT / "docker-compose.yml"]
    for env in (BACKEND_ROOT / ".env.example", REPO_ROOT / ".env.example"):
        if env.exists():
            haystacks.append(env)
    for path in haystacks:
        if not path.exists():  # the repository root is not mounted in the API container
            continue
        text = path.read_text(encoding="utf-8")
        for setting in RETIRED_SETTINGS:
            assert setting not in text, (path.name, setting)


def test_the_retired_rbac_modules_are_gone():
    rbac = BACKEND_ROOT / "ccure_platform" / "rbac"
    for name in RETIRED_MODULES:
        assert not (rbac / f"{name}.py").exists(), name
    assert not (BACKEND_ROOT / "auth" / "rbac.py").exists()
    assert not (BACKEND_ROOT / "routers" / "admin_rbac.py").exists()
    for relative in (
        "ccure_platform/rbac/legacy_map.py",
        "ccure_platform/rbac/reconcile.py",
        "scripts/rbac/cutover.py",
        "scripts/rbac/reconcile_assignments.py",
        "data/rbac/golden_legacy_mapping.json",
    ):
        assert not (BACKEND_ROOT / relative).exists(), relative


def test_native_identity_metadata_and_exports_have_no_legacy_rbac():
    from db.base import Base
    import db.models as models
    from db.models.users import User

    assert not {"roles", "permissions", "role_permissions", "rbac_legacy_map"} & set(
        Base.metadata.tables
    )
    assert "role_id" not in User.__table__.columns
    assert not hasattr(User, "role")
    for name in ("Role", "Permission", "RolePermission", "RbacLegacyMap"):
        assert not hasattr(models, name)
    with pytest.raises(TypeError):
        User(role_id=1)


_ACCOUNT_NAMES = {"user", "current_user", "actor", "account", "u"}
#: Runtime code has no exception for the removed legacy account column.
ROLE_COLUMN_ALLOWED = set()


def test_users_role_id_and_the_role_object_are_not_read_by_runtime_code():
    offenders = []
    for rel, path in runtime_files():
        if rel in ROLE_COLUMN_ALLOWED:
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Attribute):
                continue
            base = node.value
            on_account = isinstance(base, ast.Name) and base.id in _ACCOUNT_NAMES
            if node.attr == "role_id" and (
                on_account or (isinstance(base, ast.Name) and base.id == "User")
            ):
                offenders.append(f"{rel}:{node.lineno}: .role_id")
            if (
                node.attr == "name"
                and isinstance(base, ast.Attribute)
                and base.attr == "role"
                and isinstance(base.value, ast.Name)
                and base.value.id in _ACCOUNT_NAMES
            ):
                offenders.append(f"{rel}:{node.lineno}: .role.name")
    assert not offenders, "\n".join(offenders)


def test_the_role_name_ratchet_is_empty():
    from scripts.architecture import rbac_guardrails as rg

    assert rg.KNOWN_LEGACY_ROLE_IDENTITY_SITES == {}
    assert rg.measure_legacy() == {}
    assert rg.measure_new() == []


def test_every_route_is_guarded_by_the_engine_or_by_authentication_alone():
    from main import app

    legacy = []
    for route in app.routes:
        for dep in getattr(getattr(route, "dependant", None), "dependencies", []):
            qual = getattr(dep.call, "__qualname__", "")
            if qual.startswith(("require_permission.", "require_role.")):
                legacy.append((route.path, qual))
    assert legacy == []


def test_the_inventory_has_no_legacy_site():
    from scripts.rbac import build_migration_inventory as bi

    inv = bi.build()
    assert inv["summary"]["legacy"] == 0
    assert bi.INVENTORY.read_text(encoding="utf-8") == bi.render(inv)


@pytest.mark.parametrize("path", ["Frontend/authorization-inventory.json"])
def test_the_frontend_inventory_records_what_was_removed(path):
    import json

    target = REPO_ROOT / path
    if not target.exists():
        pytest.skip("the frontend tree is not reachable from this runtime")
    inv = json.loads(target.read_text(encoding="utf-8"))
    assert inv["summary"]["removed"] >= 5
    assert not [s for s in inv["sites"] if s["kind"] == "role_permissions_read"]

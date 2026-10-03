"""
RBAC-1 — a new module joins RBAC without changing RBAC.

``fixture/ccure_example`` is the test-only proof module (never registered in
production). This test gives it a permission catalogue and shows the whole path
the RBAC-0 design promises:

    manifest → permission declarations (data) → composition root
        → rbac.catalogue.sync → catalogue → grants → decisions → a guarded route

with **no change to any RBAC file**. The module imports only
``ccure_platform.api``; RBAC imports nothing of the module and does not know it
exists. That is the independence claim made concrete.
"""

from __future__ import annotations

import ast
import dataclasses
import sys
from pathlib import Path

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import ccure_platform.api as api
from ccure_platform import composition
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.modules import registry
from ccure_platform.rbac.catalogue import CatalogueError
from db.base import get_db
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401  (registers the rbac_db fixture)
    role,
)
from testpaths import BACKEND_ROOT

FIXTURE = Path(__file__).resolve().parent / "fixture"
PACKAGE = FIXTURE / "ccure_example"

IDENTITY = dict(
    key="example",
    title="Example (test-only proof module)",
    description="A test-only proof module; never registered in production.",
    entry_path="/example-dashboard",
    package="ccure_example",
    db_schema="example",
    route_prefix="/example",
    task_prefix="ccure.example",
    permission_namespace="example",
    tile_state="not_yet_available",
    enabled=True,
)


@pytest.fixture
def example(monkeypatch):
    """The proof module registered beside the real ones for one test, declaring its
    permission catalogue the way a manifest.toml would."""
    monkeypatch.syspath_prepend(str(FIXTURE))
    manifest = registry.build(IDENTITY, root=FIXTURE)
    manifest = dataclasses.replace(
        manifest, permission_modules=("ccure_example.permissions",)
    )
    monkeypatch.setattr(registry, "MODULES", (*registry.MODULES, manifest))
    yield manifest
    for name in [
        n for n in sys.modules if n == "ccure_example" or n.startswith("ccure_example.")
    ]:
        del sys.modules[name]


def test_the_module_declares_data_and_imports_only_the_platforms_api():
    tree = ast.parse((PACKAGE / "permissions.py").read_text())
    imported = {
        (node.module or "")
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported == {"ccure_platform.api"}


def test_the_composition_root_reads_the_declarations_as_data(example):
    (src,) = composition.load_permission_sources()
    assert (src.module_key, src.namespace) == ("example", "example")
    assert [d.key for d in src.permissions] == [
        "example.widget.read",
        "example.widget.write",
        "example.widget.purge",
    ]


def test_a_disabled_module_declares_nothing_to_rbac(example, monkeypatch):
    off = dataclasses.replace(example, enabled=False)
    monkeypatch.setattr(
        registry, "MODULES", (*[m for m in registry.MODULES if m.key != "example"], off)
    )
    assert composition.load_permission_sources() == []


def test_sync_registers_the_catalogue_and_materialises_default_grants(rbac_db, example):
    report = composition.sync_permission_catalogue(rbac_db)
    assert report.registered == (
        "example.widget.purge",
        "example.widget.read",
        "example.widget.write",
    )
    assert report.grants_added["platform.viewer"] == ("example.widget.read",)
    assert report.grants_added["platform.analyst"] == (
        "example.widget.read",
        "example.widget.write",
    )
    # the superadmin role is materialised too, including the privileged permission
    assert "example.widget.purge" in report.grants_added["platform.superadmin"]
    assert not composition.sync_permission_catalogue(rbac_db).changed  # idempotent


def test_the_module_consumes_rbac_through_the_platform_api_only(rbac_db, example):
    composition.sync_permission_catalogue(rbac_db)
    org = make_org(rbac_db)
    viewer, analyst, nobody = (make_user(rbac_db, org) for _ in range(3))
    assign(rbac_db, viewer, role(rbac_db, "platform.viewer"))
    assign(rbac_db, analyst, role(rbac_db, "platform.analyst"))

    assert api.can(rbac_db, viewer, "example.widget.read")
    assert not api.can(rbac_db, viewer, "example.widget.write")
    assert api.can(rbac_db, analyst, "example.widget.write")
    assert not api.can(
        rbac_db, analyst, "example.widget.purge"
    )  # declared, granted to no one
    assert not api.can(rbac_db, nobody, "example.widget.read")
    assert api.effective_permissions(rbac_db, analyst).permissions == {
        "example.widget.read",
        "example.widget.write",
    }


def test_a_route_in_the_module_is_guarded_by_the_platforms_require(rbac_db, example):
    composition.sync_permission_catalogue(rbac_db)
    org = make_org(rbac_db)
    viewer = make_user(rbac_db, org)
    assign(rbac_db, viewer, role(rbac_db, "platform.viewer"))

    app = FastAPI()

    @app.get("/example/widgets")
    def widgets(who=Depends(api.require("example.widget.read"))):
        return {"ok": True}

    @app.post("/example/widgets")
    def create(who=Depends(api.require("example.widget.write"))):
        return {"ok": True}

    app.dependency_overrides[get_current_user] = lambda: viewer
    app.dependency_overrides[get_db] = lambda: rbac_db
    client = TestClient(app)
    assert client.get("/example/widgets").status_code == 200
    assert client.post("/example/widgets").status_code == 403


def test_a_declaration_that_breaks_the_rules_is_refused_with_no_fallback(
    rbac_db, example, monkeypatch
):
    import ccure_example.permissions as declared
    from ccure_platform.api import PermissionDecl

    monkeypatch.setattr(
        declared,
        "PERMISSIONS",
        declared.PERMISSIONS
        + (
            PermissionDecl(
                key="other.thing.read", description="d", scope_kind="organization"
            ),
        ),
    )
    with pytest.raises(
        CatalogueError, match="first segment must be the declaring namespace"
    ):
        composition.sync_permission_catalogue(rbac_db)
    # nothing was applied: not even the declarations that were fine
    from ccure_platform.rbac.model import RbacPermission

    assert (
        rbac_db.query(RbacPermission).filter(RbacPermission.module == "example").count()
        == 0
    )


def test_a_permission_module_that_cannot_load_fails_loudly(
    rbac_db, example, monkeypatch
):
    broken = dataclasses.replace(
        example, permission_modules=("ccure_example.no_such_module",)
    )
    monkeypatch.setattr(
        registry,
        "MODULES",
        (*[m for m in registry.MODULES if m.key != "example"], broken),
    )
    with pytest.raises(CatalogueError, match="cannot be loaded"):
        composition.load_permission_sources()


def test_a_permission_module_without_permissions_fails_loudly(example, monkeypatch):
    import ccure_example.permissions as declared

    monkeypatch.delattr(declared, "PERMISSIONS")
    with pytest.raises(CatalogueError, match="exports no PERMISSIONS"):
        composition.load_permission_sources()


def test_a_module_cannot_claim_the_platforms_or_another_modules_namespace():
    from ccure_platform.modules.manifest import ManifestError

    with pytest.raises(ManifestError, match="platform's"):
        registry.build({**IDENTITY, "permission_namespace": "platform"}, root=FIXTURE)
    with pytest.raises(
        ManifestError, match="both declare permission namespace 'audit'"
    ):
        registry._check(
            (
                *registry.MODULES,
                registry.build(
                    {**IDENTITY, "permission_namespace": "audit"}, root=FIXTURE
                ),
            )
        )


def test_the_namespaces_are_reserved_from_the_day_a_product_is_registered():
    held = registry.permission_namespaces()
    assert held == {
        "platform": "platform",
        "policy": "policy_pro",
        "audit": "audit",
        "rank": "rank",
        "ir": "ir",
    }


def test_no_rbac_file_knows_this_module_exists():
    """The zero-change claim: nothing in the capability names the proof module."""
    for path in sorted((BACKEND_ROOT / "ccure_platform" / "rbac").glob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        assert "ccure_example" not in text and "example.widget" not in text, path.name
    text = (BACKEND_ROOT / "ccure_platform" / "composition.py").read_text().lower()
    assert "ccure_example" not in text

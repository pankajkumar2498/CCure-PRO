"""Frozen native permission metadata and system grants, independent of old RBAC."""

import json
from pathlib import Path

import pytest

from ccure_platform import composition
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacPermission, RbacRole, granted_keys
from rbac_testing import rbac_db_fixture  # noqa: F401

EXPECTED = json.loads(
    (Path(__file__).parents[1] / "fixtures/rbac_catalogue.json").read_text()
)


def test_native_declarations_match_frozen_permission_metadata():
    declarations = {
        p.key: p
        for source in composition.load_permission_sources()
        for p in source.permissions
    }
    assert len(declarations) == 69
    assert sum(k.startswith("platform.") for k in declarations) == 32
    assert sum(k.startswith("audit.") for k in declarations) == 37
    assert set(declarations) == {p["key"] for p in EXPECTED["permissions"]}
    for permission in EXPECTED["permissions"]:
        declaration = declarations[permission["key"]]
        for field in (
            "scope_kind",
            "sensitivity",
            "delegable_to_org_roles",
            "continuity",
        ):
            assert getattr(declaration, field) == permission[field]
    for role_key, keys in EXPECTED["role_grants"].items():
        actual = (
            set(declarations)
            if role_key == "platform.superadmin"
            else {p.key for p in declarations.values() if role_key in p.default_grants}
        )
        assert actual == set(keys)


@pytest.mark.parametrize(
    "key,count",
    [
        ("platform.superadmin", 69),
        ("platform.org_admin", 47),
        ("platform.analyst", 23),
        ("platform.viewer", 9),
        ("platform.scanner", 4),
    ],
)
def test_native_sync_materializes_exact_frozen_grants(rbac_db, key, count):
    sources = composition.load_permission_sources()
    sync(rbac_db, sources, audit=False)
    role = rbac_db.query(RbacRole).filter_by(key=key).one()
    grants = granted_keys(rbac_db, role.id)
    assert len(grants) == count
    assert grants == frozenset(EXPECTED["role_grants"][key])
    if role.assignable_scope == "organization":
        for permission in rbac_db.query(RbacPermission).filter(
            RbacPermission.key.in_(grants)
        ):
            assert permission.scope_kind == "organization"
            assert permission.delegable_to_org_roles
    again = sync(rbac_db, sources, audit=False)
    assert not again.registered and not again.updated
    assert not any(again.grants_added.values()) and not any(
        again.grants_removed.values()
    )

"""
RBAC-7 — Platform administration authorization is permission-key based.

users, organisations, roles, settings (split), audit logs and the compliance emergency
bypass no longer name a legacy atom or a role: each route asks for one granular
permission from the RBAC catalogue, with the legacy rule as the rollback path.
"""

from __future__ import annotations


import re

import pytest

from ccure_platform import composition
from ccure_platform.rbac.catalogue import sync
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)
from routers import compliance
from testpaths import BACKEND_ROOT

ADMIN_FILES = (
    "ccure_platform/administration/users.py",
    "ccure_platform/administration/organizations.py",
    "ccure_platform/administration/rbac_admin.py",
    "ccure_platform/audit_log/router.py",
)


def test_no_platform_admin_route_names_a_legacy_atom_or_a_role():
    for rel in ADMIN_FILES:
        text = (BACKEND_ROOT / rel).read_text(encoding="utf-8")
        assert "require_permission(" not in text, rel
        assert "require_role(" not in text, rel
        assert not re.search(r'\.role\.name|role_name\(|== "superadmin"', text), rel
    for rel in ("routers/assets.py", "routers/remediation.py"):
        text = (BACKEND_ROOT / rel).read_text(encoding="utf-8")
        assert '"settings", "update"' not in text  # the split atom is gone


def test_settings_authorization_uses_the_split_permissions():
    assets = (BACKEND_ROOT / "routers/assets.py").read_text()
    remediation = (BACKEND_ROOT / "routers/remediation.py").read_text()
    assert 'require_authorized("audit.asset.import_amt")' in assets
    assert 'require_authorized("audit.remediation.manage_sla")' in remediation


def test_every_key_a_platform_admin_route_names_exists_in_the_catalogue():
    keys = {p.key for s in composition.load_permission_sources() for p in s.permissions}
    for rel in ADMIN_FILES + ("routers/assets.py", "routers/remediation.py"):
        text = (BACKEND_ROOT / rel).read_text(encoding="utf-8")
        for key in re.findall(r'require_authorized\("([a-z_.]+)"\)', text):
            assert key in keys, (rel, key)


@pytest.fixture
def w(rbac_db, monkeypatch):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db, w.a = rbac_db, make_org(rbac_db)

    def person(rbac_role=None, name=None):
        u = make_user(rbac_db, w.a)
        rbac_db.flush()
        rbac_db.refresh(u)
        if rbac_role:
            assign(rbac_db, u, role(rbac_db, rbac_role))
        return u

    w.person = person
    return w


def test_the_compliance_emergency_bypass_needs_the_approval_permission(w, monkeypatch):
    approve = lambda u: compliance._may_bypass_maker_checker(w.db, u)  # noqa: E731
    assert approve(w.person("platform.superadmin"))
    assert approve(w.person("platform.org_admin"))
    assert not approve(w.person("platform.analyst"))
    assert not approve(w.person("platform.viewer"))
    assert not approve(w.person("platform.scanner"))
    # no assignment, whatever the (deprecated) legacy column says, holds nothing
    assert not approve(w.person())


def test_the_bypass_follows_grants_not_names_when_the_new_model_decides(w, monkeypatch):
    spoof = w.person("platform.viewer")  # legacy name says admin, no grant
    real = w.person("platform.org_admin")
    assert compliance._may_bypass_maker_checker(w.db, spoof) is False
    assert compliance._may_bypass_maker_checker(w.db, real) is True
    # and the permission is the existing approval key, no broader bypass key
    keys = {p.key for s in composition.load_permission_sources() for p in s.permissions}
    assert not [k for k in keys if "bypass" in k]


def test_the_directory_and_audit_scope_helpers_use_cross_organisation_reach(
    w, monkeypatch
):
    from ccure_platform.administration import users as users_mod
    from ccure_platform.audit_log import router as audit_mod

    spoof = w.person("platform.viewer")
    real = w.person("platform.superadmin")
    for helper in (users_mod._is_superadmin, audit_mod._is_superadmin):
        assert helper(spoof) is False and helper(real) is True


def test_a_user_directory_query_is_confined_to_the_organisation_without_reach(w):
    from ccure_platform.administration import users as users_mod

    admin = w.person("platform.org_admin")
    q = users_mod._scoped_users_query(w.db, admin)
    assert "org_id" in str(q.statement.compile())
    sa = w.person("platform.superadmin")
    assert "org_id" not in str(
        users_mod._scoped_users_query(w.db, sa).statement.compile()
    ).split("WHERE")[-1].replace("users.org_id AS", "")

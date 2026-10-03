"""
RBAC-4 — the proof that makes a path eligible: with the default grants, the new engine
and the legacy rule agree for every legacy role on every migrated path, and the new
engine is the one answering (not a fallback).
"""

from __future__ import annotations

import json

import pytest

import ccure_platform.rbac.dependencies as legacy
from ccure_platform import composition
from ccure_platform.rbac import authority as au
from ccure_platform.rbac import legacy_map
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
from db.models import Role
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)
from testpaths import BACKEND_ROOT

INVENTORY = BACKEND_ROOT / "data" / "rbac" / "authorization_migration_inventory.json"


REPLACED_KEYS = frozenset(
    {
        "platform.email_domain.read",
        "platform.email_domain.manage",
        "platform.audit_log.retention",
        "audit.vuln_feed.manage",
        "audit.compliance.manage_shared_rules",
    }
)


@pytest.fixture(autouse=True)
def authority_on(monkeypatch):
    au.recorder.reset()
    au.set_migrated_paths(None)
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "enforce")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "*")
    yield
    au.set_migrated_paths(None)


@pytest.fixture
def people(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    org = make_org(rbac_db)
    out = {}
    for entry in legacy_map.load_golden()["roles"]:
        user = make_user(rbac_db, org)
        user.role_id = (
            rbac_db.query(Role).filter(Role.name == entry["legacy_role"]).one().id
        )
        rbac_db.flush()
        rbac_db.refresh(user)
        assign(rbac_db, user, role(rbac_db, entry["role_key"]))
        out[entry["legacy_role"]] = user
    return out


def migrated_paths():
    sites = json.loads(INVENTORY.read_text())["sites"]
    return sorted({s["path_id"] for s in sites if s["migrated"] and s["path_id"]})


def test_every_migrated_atom_agrees_for_every_role(rbac_db, people):
    mismatches, answered_by_new = [], 0
    for path in migrated_paths():
        if ":" not in path:
            continue
        resource, action = path.split(":")
        for name, user in people.items():
            want = legacy._legacy_decision(rbac_db, user, resource, action)
            got = au.decide_atom(rbac_db, user, resource, action, want)
            assert got.source == au.SOURCE_NEW, (path, name, got)
            answered_by_new += 1
            if got.allowed != want:
                mismatches.append((path, name, want, got.allowed))
    assert answered_by_new > 100
    assert mismatches == []


def test_every_migrated_key_agrees_for_every_role(rbac_db, people):
    keys = [p for p in migrated_paths() if ":" not in p]
    assert set(keys) >= REPLACED_KEYS
    for key in keys:
        for name, user in people.items():
            want = legacy._legacy_key_decision(user, key)
            got = au.decide_key(rbac_db, user, key, want)
            assert got.source == au.SOURCE_NEW, (key, name, got)
            assert got.allowed == want, (key, name)


def test_only_the_superadmin_role_holds_the_replaced_role_name_keys(rbac_db, people):
    for key in REPLACED_KEYS:
        allowed = {
            n
            for n, u in people.items()
            if au.decide_key(rbac_db, u, key, False).allowed
        }
        assert allowed == {"superadmin"}, key

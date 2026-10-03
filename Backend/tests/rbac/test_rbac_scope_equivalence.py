"""
RBAC-5 — legacy versus new for every scope decision, with the default grants.

The comparison the phase is judged on: for each of the five legacy roles, in the
account's own organisation and in another, the legacy rule and the new engine agree
on cross-organisation reach, on the organisation a request acts in, and on
organisation-wide read visibility. Where they differ it is a *named* difference, here.
"""

from __future__ import annotations

import pytest

import ccure_platform.api as api
from ccure_platform import composition
from ccure_platform.rbac import authority as au
from ccure_platform.rbac import legacy_map, scope
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac import dependencies as legacy
from config import AppConfig
from db.models import Role
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)

ROLES = [e["legacy_role"] for e in legacy_map.load_golden()["roles"]]


@pytest.fixture
def world(rbac_db, monkeypatch):
    au.recorder.reset()
    au.set_migrated_paths(None)
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("W", (), {})()
    w.db, w.a, w.b = rbac_db, make_org(rbac_db), make_org(rbac_db)
    w.people = {}
    for entry in legacy_map.load_golden()["roles"]:
        u = make_user(rbac_db, w.a)
        u.role_id = (
            rbac_db.query(Role).filter(Role.name == entry["legacy_role"]).one().id
        )
        rbac_db.flush()
        rbac_db.refresh(u)
        assign(rbac_db, u, role(rbac_db, entry["role_key"]))
        w.people[entry["legacy_role"]] = u
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_MODE", "enforce")
    monkeypatch.setattr(AppConfig, "RBAC_AUTHORITY_PATHS", "*")
    yield w
    au.set_migrated_paths(None)


def test_cross_organisation_reach_matches_for_every_role(world):
    for name, u in world.people.items():
        assert api.acts_across_organisations(
            u
        ) == legacy.legacy_acts_across_organisations(u), name
    snap = au.recorder.snapshot()
    assert snap["divergences"] == []
    assert {k.split("|")[1] for k in snap["by_path"]} == {"new"}


def test_the_active_organisation_matches_for_every_role_and_target(world):
    for name, u in world.people.items():
        for requested in (None, world.a.id, world.b.id):
            with scope.use_audit_session(world.db):
                got = api.resolve_active_organisation(u, requested)
            want = requested if (requested and name == "superadmin") else world.a.id
            assert got == want, (name, requested)
    assert au.recorder.snapshot()["divergences"] == []


def test_read_all_matches_the_legacy_answer_in_each_organisation(world):
    for name, u in world.people.items():
        for org in (world.a.id, world.b.id):
            legacy_atom = legacy._legacy_decision(world.db, u, "scans", "read_all")
            want = legacy_atom and (org == world.a.id or name == "superadmin")
            got = api.user_has_permission(
                world.db, u, "scans", "read_all", authoritative=True, org_id=org
            )
            assert got == want, (name, org)
    assert au.recorder.snapshot()["divergences"] == []


def test_assignment_hierarchy_matches_legacy_except_the_named_differences(world):
    """For the accounts that can reach the assignment routes at all (the roles
    holding platform.user.update), every non-self assignment in the actor's
    organisation agrees. Named differences — new model stricter, legacy has no rule:

    D8 self-assignment is refused (legacy let an administrator change its own role);
    D9 the permission ceiling and scope rules apply to every role, not only superadmin.
    No such difference arises for the default grants, so the table below is empty.
    """
    differences = []
    for actor_name in ("superadmin", "org_admin"):
        actor = world.people[actor_name]
        for target in ROLES:
            row = world.db.query(Role).filter(Role.name == target).one()
            want = legacy.legacy_assignment_allowed(actor, row)
            with scope.use_audit_session(world.db):
                v = api.check_role_assignment(
                    actor, row, target_user_id="other", target_org_id=world.a.id
                )
            if v.allowed != want:
                differences.append((actor_name, target, want, v.violations))
    assert differences == []
    assert all(k.split("|")[1] == "new" for k in au.recorder.snapshot()["by_path"])

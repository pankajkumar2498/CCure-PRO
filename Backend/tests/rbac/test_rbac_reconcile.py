"""
RBAC-4 — the reconciliation report: five conditions, read-only by default, and an
apply that closes only ``missing``.
"""

from __future__ import annotations

import pytest

from ccure_platform import composition
from ccure_platform.rbac import reconcile as rc
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacUserRole
from db.models import Role
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)


def legacy(db, user, name):
    user.role_id = db.query(Role).filter(Role.name == name).one().id
    db.flush()
    db.refresh(user)
    return user


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    return rbac_db, make_org(rbac_db)


def ids(findings):
    return {f.user_id for f in findings}


def test_missing_and_correct(world):
    db, org = world
    ok = legacy(db, make_user(db, org), "analyst")
    assign(db, ok, role(db, "platform.analyst"))
    gap = legacy(db, make_user(db, org), "viewer")
    r = rc.reconcile(db)
    assert gap.id in ids(r.missing) and ok.id not in ids(r.missing)
    assert ok.id not in ids(r.incorrect)
    f = next(x for x in r.missing if x.user_id == gap.id)
    assert f.expected_role_key == "platform.viewer"


def test_incorrect_assignment(world):
    db, org = world
    u = legacy(db, make_user(db, org), "viewer")
    assign(db, u, role(db, "platform.analyst"))
    assert u.id in ids(rc.reconcile(db).incorrect)


def test_a_superadmin_must_hold_the_platform_scope_role(world):
    db, org = world
    u = legacy(db, make_user(db, org), "superadmin")
    assign(db, u, role(db, "platform.org_admin"))
    assert u.id in ids(rc.reconcile(db).incorrect)


def test_duplicate_conflicting_assignments(world):
    db, org = world
    u = legacy(db, make_user(db, org), "analyst")
    assign(db, u, role(db, "platform.analyst"))
    assign(db, u, role(db, "platform.viewer"))
    r = rc.reconcile(db)
    assert u.id in ids(r.duplicate)


def test_revoked_legacy_user_still_assigned(world):
    db, org = world
    u = legacy(db, make_user(db, org, active=False), "analyst")
    assign(db, u, role(db, "platform.analyst"))
    d = legacy(db, make_user(db, org, deleted=True), "viewer")
    assign(db, d, role(db, "platform.viewer"))
    r = rc.reconcile(db)
    assert {u.id, d.id} <= ids(r.revoked_but_assigned)
    assert u.id not in ids(r.missing)


def test_a_revoked_assignment_is_history_not_a_holding(world):
    from datetime import datetime, timezone

    db, org = world
    u = legacy(db, make_user(db, org), "analyst")
    row = assign(db, u, role(db, "platform.analyst"))
    row.revoked_at = datetime.now(timezone.utc)
    row.revoke_reason = "manual"
    db.flush()
    assert u.id in ids(rc.reconcile(db).missing)


def test_reconcile_writes_nothing(world):
    db, org = world
    legacy(db, make_user(db, org), "viewer")
    before = db.query(RbacUserRole).count()
    rc.reconcile(db)
    rc.plan(db)
    assert db.query(RbacUserRole).count() == before


def test_apply_assigns_only_the_missing_with_the_golden_role_and_scope(world):
    db, org = world
    a = legacy(db, make_user(db, org), "analyst")
    s = legacy(db, make_user(db, org), "superadmin")
    wrong = legacy(db, make_user(db, org), "viewer")
    assign(db, wrong, role(db, "platform.analyst"))  # incorrect: must NOT be touched
    inactive = legacy(db, make_user(db, org, active=False), "viewer")
    planned = rc.plan(db)
    mine = {
        p.user_id: p
        for p in planned
        if p.user_id in {a.id, s.id, wrong.id, inactive.id}
    }
    assert set(mine) == {a.id, s.id}
    assert (mine[a.id].role_key, mine[a.id].scope_type, mine[a.id].scope_org_id) == (
        "platform.analyst",
        "organization",
        org.id,
    )
    assert (mine[s.id].role_key, mine[s.id].scope_type, mine[s.id].scope_org_id) == (
        "platform.superadmin",
        "platform",
        None,
    )
    assert rc.apply(db, [mine[a.id], mine[s.id]]) == 2
    after = rc.reconcile(db)
    assert a.id not in ids(after.missing) and s.id not in ids(after.missing)
    assert a.id not in ids(after.incorrect) and s.id not in ids(after.incorrect)
    assert wrong.id in ids(after.incorrect)


def test_apply_skips_an_account_that_gained_an_assignment_meanwhile(world):
    db, org = world
    u = legacy(db, make_user(db, org), "viewer")
    planned = [p for p in rc.plan(db) if p.user_id == u.id]
    assign(db, u, role(db, "platform.viewer"))
    assert rc.apply(db, planned) == 0


def test_the_script_never_applies_to_the_live_database_names():
    from scripts.rbac import reconcile_assignments as script

    assert {"ccure_db", "ccure_test"} <= script.LIVE_DATABASES

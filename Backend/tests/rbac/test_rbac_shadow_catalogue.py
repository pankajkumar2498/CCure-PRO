"""
RBAC-2 — a catalogue-level shadow check: the golden mapping, run through the real
shadow comparator.

For every legacy role and every legacy atom, the legacy verdict is "does this role
hold this atom" (the superadmin holds everything) and the new verdict comes from the
new engine over the populated catalogue. They must agree for every mapped or
replaced atom, and a retired atom must say so rather than claim a match.

This is **read-only and test-only**: it runs in a rolled-back transaction, writes
nothing, and the comparator is wired into no request (RBAC-1 asserts that). It is the
shape RBAC-3's live shadow will take, proven here on data.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from ccure_platform import composition
from ccure_platform.rbac import legacy_map as lm
from ccure_platform.rbac import shadow
from ccure_platform.rbac.catalogue import sync
from ccure_platform.rbac.model import RbacLegacyMap
from db.migrate_production_schema import PERMISSIONS, ROLE_PERMISSIONS
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,
    role,
)  # noqa: F401

GOLDEN = lm.load_golden()
LEGACY_ATOMS = [f"{r}:{a}" for r, a, _ in PERMISSIONS] + ["audit_logs:read"]


def legacy_set(role_name):
    if role_name == "superadmin":
        return set(LEGACY_ATOMS)
    held = set(ROLE_PERMISSIONS[role_name])
    return held | ({"audit_logs:read"} if role_name == "org_admin" else set())


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    rbac_db.query(RbacLegacyMap).delete()
    rbac_db.flush()
    lm.sync_legacy_map(rbac_db, GOLDEN, audit=False)
    org = make_org(rbac_db)
    users = {}
    for r in GOLDEN["roles"]:
        user = make_user(rbac_db, org)
        assign(rbac_db, user, role(rbac_db, r["role_key"]))
        users[r["legacy_role"]] = user
    return rbac_db, users


def counts(db):
    return {
        t: db.execute(text(f"SELECT count(*) FROM {t}")).scalar()
        for t in (
            "rbac_roles",
            "rbac_user_roles",
            "rbac_role_permissions",
            "rbac_permissions",
            "rbac_legacy_map",
            "rbac_role_revisions",
            "audit_logs",
            "platform_audit_events",
        )
    }


@pytest.mark.parametrize(
    "legacy_role", ["superadmin", "org_admin", "analyst", "viewer", "scanner"]
)
def test_the_new_decision_matches_the_legacy_one_for_every_atom(world, legacy_role):
    db, users = world
    held = legacy_set(legacy_role)
    retired = {a["atom"] for a in GOLDEN["atoms"] if a["status"] == "retired"}
    disagreements, retired_seen = [], 0
    for atom in LEGACY_ATOMS:
        resource, action = atom.split(":")
        outcome = shadow.shadow_compare(
            db, users[legacy_role], resource, action, atom in held
        )
        if atom in retired:
            assert outcome.kind == shadow.RETIRED, atom
            assert outcome.new_allowed is None and outcome.permission_keys == ()
            retired_seen += 1
        elif outcome.kind != shadow.MATCH:
            disagreements.append((atom, outcome))
    assert not disagreements, disagreements
    assert retired_seen == 10


def test_the_comparison_is_read_only(world):
    db, users = world
    before = counts(db)
    recorder = shadow.ShadowRecorder()
    for user in users.values():
        for atom in LEGACY_ATOMS:
            resource, action = atom.split(":")
            shadow.shadow_compare(db, user, resource, action, True, recorder=recorder)
    assert counts(db) == before


def test_a_recorder_over_the_whole_matrix_has_no_mismatch_for_the_exact_legacy_verdicts(
    world,
):
    db, users = world
    recorder = shadow.ShadowRecorder()
    for legacy_role, user in users.items():
        held = legacy_set(legacy_role)
        for atom in LEGACY_ATOMS:
            resource, action = atom.split(":")
            shadow.shadow_compare(
                db, user, resource, action, atom in held, recorder=recorder
            )
    assert (
        recorder.counts.get("mismatch", 0) == 0 and recorder.counts.get("error", 0) == 0
    )
    assert recorder.counts["retired"] == 50  # 10 retired atoms x 5 roles
    assert recorder.counts["match"] == 5 * 56


def test_a_wrong_legacy_verdict_is_a_mismatch_so_the_check_can_fail(world):
    db, users = world
    # the viewer cannot start a scan; if the legacy side said it could, the check must notice
    outcome = shadow.shadow_compare(db, users["viewer"], "scans", "execute", True)
    assert outcome.kind == shadow.MISMATCH
    # and a merged key needs every atom: a scanner is allowed to run scans
    assert (
        shadow.shadow_compare(db, users["scanner"], "scans", "execute", True).kind
        == shadow.MATCH
    )
    assert (
        shadow.shadow_compare(db, users["scanner"], "scans", "create", True).kind
        == shadow.MATCH
    )


def test_a_split_atom_is_allowed_only_when_every_part_is(world):
    db, users = world
    out = shadow.shadow_compare(db, users["org_admin"], "users", "update", True)
    assert out.kind == shadow.MATCH and len(out.permission_keys) == 4
    out = shadow.shadow_compare(db, users["analyst"], "users", "update", False)
    assert out.kind == shadow.MATCH and out.new_allowed is False


def test_the_legacy_verdict_is_carried_through_untouched(world):
    db, users = world
    for verdict in (True, False):
        assert (
            shadow.shadow_compare(
                db, users["viewer"], "scans", "read", verdict
            ).legacy_allowed
            is verdict
        )

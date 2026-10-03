"""
RBAC-3 — the RBAC-2 golden equivalence, re-run through the actual shadow mechanism.

RBAC-2 proved the role sets agree by recomputing them. This runs the *legacy checks
themselves*: for each of the five roles, a user holding that legacy role and the
matching new role is asked ``user_has_permission`` about every legacy atom with
shadow mode on, so every answer is compared by the real hook, evaluator and
recorder (``scripts/rbac/shadow_equivalence.py``). Known-equivalent cases must give
``legacy == new``; anything else is classified and listed, never hidden.

**RBAC-3 = SHADOW ONLY.** The legacy decision is what each call returns; the matrix
only observes.
"""

from __future__ import annotations

import pytest

from ccure_platform import composition
from ccure_platform.rbac import legacy_map as lm
from ccure_platform.rbac import shadow as sh
from ccure_platform.rbac import shadow_runtime as rt
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
from db.models import RolePermission
from rbac_testing import rbac_db_fixture  # noqa: F401
from scripts.rbac import shadow_equivalence as eq

GOLDEN = lm.load_golden()
ROLES = ["superadmin", "org_admin", "analyst", "viewer", "scanner"]


@pytest.fixture
def report(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    return eq.run_equivalence(rbac_db, GOLDEN), rbac_db


def by_role(rep):
    return {r.legacy_role: r for r in rep.roles}


def test_all_five_roles_are_covered_and_the_report_is_clean(report):
    rep, _ = report
    assert [r.legacy_role for r in rep.roles] == ROLES
    assert [r.role_key for r in rep.roles] == [f"platform.{n}" for n in ROLES]
    assert rep.ok


@pytest.mark.parametrize("legacy_role", ROLES)
def test_every_enforced_atom_matches_and_every_retired_atom_says_so(
    report, legacy_role
):
    rep, _ = report
    r = by_role(rep)[legacy_role]
    assert r.total == 66  # every legacy atom, once
    assert r.matches == 56 and r.retired == 10
    assert r.mismatches == [] and r.errors == []
    assert set(k[0] for k in r.counts) == {sh.MATCH, sh.NOT_COMPARABLE}
    assert r.counts[(sh.NOT_COMPARABLE, sh.RETIRED_ATOM)] == 10


def test_the_decisions_are_split_between_allow_both_and_deny_both_as_the_roles_differ(
    report,
):
    rep, _ = report
    allow = {r.legacy_role: r.counts[(sh.MATCH, sh.ALLOW_BOTH)] for r in rep.roles}
    # superadmin allows every enforced atom; the others hold what RBAC-2 said they hold
    assert allow["superadmin"] == 56
    assert (
        allow["org_admin"] > allow["analyst"] > allow["viewer"] > allow["scanner"] > 0
    )
    for r in rep.roles:
        assert (
            r.counts[(sh.MATCH, sh.ALLOW_BOTH)] + r.counts[(sh.MATCH, sh.DENY_BOTH)]
            == 56
        )


def test_known_equivalent_cases_have_legacy_equal_to_new(rbac_db):
    """Per atom, not just per count: every match has the same decision on both sides."""
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    rt.reset_recorder()
    results = []
    original = sh.ShadowRecorder.record

    def spy(self, result):
        results.append(result)
        original(self, result)

    sh.ShadowRecorder.record = spy
    try:
        eq.run_equivalence(rbac_db, GOLDEN)
    finally:
        sh.ShadowRecorder.record = original
    assert len(results) == 5 * 66
    for result in results:
        if result.kind == sh.MATCH:
            assert result.legacy_decision == result.new_decision, result.legacy_atom
        else:
            assert (result.kind, result.classification) == (
                sh.NOT_COMPARABLE,
                sh.RETIRED_ATOM,
            )
    assert len({(r.principal_id, r.legacy_atom) for r in results}) == 5 * 66


def test_the_superadmin_is_equivalent_through_grants_alone(report):
    rep, _ = report
    r = by_role(rep)["superadmin"]
    assert (
        r.counts[(sh.MATCH, sh.ALLOW_BOTH)] == 56
        and r.counts.get((sh.MATCH, sh.DENY_BOTH), 0) == 0
    )


def test_the_run_writes_nothing_and_restores_the_flag(rbac_db):
    from sqlalchemy import text

    sync(rbac_db, composition.load_permission_sources(), audit=False)
    tables = (
        "rbac_user_roles",
        "users",
        "organizations",
        "audit_logs",
        "platform_audit_events",
    )
    before = {
        t: rbac_db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables
    }
    mode = AppConfig.RBAC_SHADOW_MODE
    eq.run_equivalence(rbac_db, GOLDEN)
    assert AppConfig.RBAC_SHADOW_MODE == mode == "off"
    # the throwaway org, five users and five assignments exist only inside the caller's transaction
    after = {
        t: rbac_db.execute(text(f"SELECT count(*) FROM {t}")).scalar() for t in tables
    }
    assert after["rbac_user_roles"] == before["rbac_user_roles"] + 5
    rbac_db.rollback()
    assert rbac_db.execute(text("SELECT count(*) FROM rbac_user_roles")).scalar() == 0


# ── the matrix can fail ──────────────────────────────────────────────────────


def test_a_legacy_grant_the_new_model_lacks_is_reported_as_a_classified_mismatch(
    rbac_db,
):
    """Give the legacy viewer an atom the new viewer does not hold: the matrix must
    notice, name the atom and classify it."""
    from db.models import Permission, Role

    sync(rbac_db, composition.load_permission_sources(), audit=False)
    viewer = rbac_db.query(Role).filter_by(name="viewer").one()
    perm = rbac_db.query(Permission).filter_by(resource="scans", action="execute").one()
    rbac_db.add(RolePermission(role_id=viewer.id, permission_id=perm.id))
    rbac_db.flush()
    rep = eq.run_equivalence(rbac_db, GOLDEN)
    r = by_role(rep)["viewer"]
    assert not rep.ok and len(r.mismatches) == 1
    m = r.mismatches[0]
    assert (m["legacy_atom"], m["classification"]) == (
        "scans:execute",
        "new_denies_legacy_allows",
    )
    assert m["legacy_decision"] is True and m["new_decision"] is False
    assert "audit.scan.run:missing_permission" in m["reason"]
    assert [x.legacy_role for x in rep.roles if x.mismatches] == ["viewer"]


def test_a_legacy_atom_removed_from_a_role_is_a_mismatch_in_the_other_direction(
    rbac_db,
):
    from db.models import Permission, Role

    sync(rbac_db, composition.load_permission_sources(), audit=False)
    scanner = rbac_db.query(Role).filter_by(name="scanner").one()
    perm = rbac_db.query(Permission).filter_by(resource="scans", action="read").one()
    rbac_db.query(RolePermission).filter_by(
        role_id=scanner.id, permission_id=perm.id
    ).delete()
    rbac_db.flush()
    rep = eq.run_equivalence(rbac_db, GOLDEN)
    (m,) = by_role(rep)["scanner"].mismatches
    assert (m["legacy_atom"], m["classification"]) == (
        "scans:read",
        "new_allows_legacy_denies",
    )


def test_an_unsynced_catalogue_is_not_comparable_rather_than_all_mismatches(rbac_db):
    from sqlalchemy import text

    from ccure_platform.rbac.catalogue import ensure_system_roles

    ensure_system_roles(rbac_db)
    rbac_db.execute(text("DELETE FROM rbac_role_permissions"))
    rbac_db.execute(text("DELETE FROM rbac_legacy_map"))
    rbac_db.execute(text("DELETE FROM rbac_permissions"))
    rep = eq.run_equivalence(rbac_db, GOLDEN)
    for r in rep.roles:
        assert not r.mismatches and not r.errors
        assert r.counts[(sh.NOT_COMPARABLE, sh.CATALOGUE_NOT_POPULATED)] == 56
        assert r.matches == 0


def test_the_operator_script_prints_a_table_and_exits_zero_when_equivalent(
    rbac_db, monkeypatch, capsys
):
    import db.base as base

    sync(rbac_db, composition.load_permission_sources(), audit=False)

    class Wrapper:
        def __getattr__(self, name):
            return getattr(rbac_db, name)

        def rollback(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(base, "SessionLocal", Wrapper)
    assert eq.main() == 0
    out = capsys.readouterr().out
    assert "equivalent." in out and "platform.superadmin" in out
    for n in ROLES:
        assert n in out

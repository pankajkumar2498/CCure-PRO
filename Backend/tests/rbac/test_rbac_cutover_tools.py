"""
RBAC-8 — the operator tools: the readiness assessment, the cutover script's refusals and
read-only commands, the bootstrap script's refusals, and the machine-readable checklist.
Nothing here commits or changes a live database: the mutating paths are exercised only up
to their refusals; the writes they would perform are covered through the services in
test_rbac_provisioning.
"""

from __future__ import annotations

import json

import pytest

from ccure_platform import composition
from ccure_platform.rbac import provisioning, readiness
from ccure_platform.rbac.catalogue import sync
from rbac_testing import (
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
)
from scripts.rbac import bootstrap_admin, cutover

SOURCES = composition.load_permission_sources


@pytest.fixture
def w(rbac_db):
    sync(rbac_db, SOURCES(), audit=False)
    w = type("W", (), {})()
    w.db, w.a = rbac_db, make_org(rbac_db)
    return w


# ── readiness ────────────────────────────────────────────────────────────────


def test_an_empty_database_is_not_ready_and_says_why(rbac_db):
    result = readiness.assess(rbac_db, SOURCES())
    assert not result.ready
    assert any("catalogue" in b for b in result.blockers)


def test_without_an_administrator_the_platform_is_not_ready(w):
    result = readiness.assess(w.db, SOURCES())
    assert not result.ready
    assert any("administered" in b for b in result.blockers)


def test_with_an_administrator_that_blocker_is_gone(w):
    user = make_user(w.db, w.a)
    provisioning.grant_platform_administrator(w.db, user.id, reason="test")
    result = readiness.assess(w.db, SOURCES())
    assert not any("administered" in b for b in result.blockers)
    assert result.counts["administrators"] == 1


def test_a_missing_default_role_is_a_note_not_a_blocker(w):
    result = readiness.assess(w.db, SOURCES())
    assert any("default role" in n for n in result.notes)
    assert not any("default role" in b for b in result.blockers)


def test_a_legacy_role_account_with_no_assignment_blocks_readiness(w):
    from db.models import Role

    user = make_user(w.db, w.a)
    user.role_id = w.db.query(Role).filter(Role.name == "viewer").one().id
    w.db.flush()
    result = readiness.assess(w.db, SOURCES())
    assert any("no RBAC assignment" in b for b in result.blockers)


def test_an_account_with_no_legacy_role_is_reported_and_holds_nothing(w):
    make_user(w.db, w.a)
    result = readiness.assess(w.db, SOURCES())
    assert any("no role at all" in n for n in result.notes)


# ── the cutover script ───────────────────────────────────────────────────────


def test_apply_refuses_without_the_database_named(capsys):
    assert cutover.main(["apply", "--allow-database", "not_this_one"]) == 3
    assert "refused" in capsys.readouterr().err


def test_apply_refuses_a_live_database_without_the_recorded_approval(
    monkeypatch, capsys
):
    monkeypatch.setattr(cutover, "_db_name", lambda db: "ccure_db")
    assert cutover.main(["apply", "--allow-database", "ccure_db"]) == 3
    assert "production-approved" in capsys.readouterr().err


def test_rollback_prepare_apply_is_refused_the_same_way(monkeypatch, capsys):
    monkeypatch.setattr(cutover, "_db_name", lambda db: "ccure_test")
    assert (
        cutover.main(["rollback-prepare", "--apply", "--allow-database", "ccure_test"])
        == 3
    )


def test_plan_is_read_only_and_reports_counts(capsys):
    assert cutover.main(["plan", "--json"]) in (0, 2)
    out = json.loads(capsys.readouterr().out)
    assert {"database", "readiness", "reconciliation", "would_assign"} <= set(out)


def test_the_backup_gate_refuses_when_there_is_no_recent_dump(tmp_path):
    step = cutover._backup_ok(24.0, str(tmp_path / "missing.dump"))
    assert step["ok"] is False


# ── the bootstrap script ─────────────────────────────────────────────────────


def test_bootstrap_refuses_without_the_database_named(capsys):
    code = bootstrap_admin.main(
        [
            "--email",
            "nobody@example.test",
            "--reason",
            "drill",
            "--allow-database",
            "other",
        ]
    )
    assert code == 3 and "refused" in capsys.readouterr().err


def test_bootstrap_names_the_live_databases_it_protects():
    assert {"ccure_db", "ccure_test"} <= bootstrap_admin.LIVE_DATABASES
    assert {"ccure_db", "ccure_test"} <= cutover.LIVE_DATABASES


# ── the checklist ────────────────────────────────────────────────────────────


def test_the_checklist_is_complete_ordered_and_machine_readable(capsys):
    data = json.loads(cutover.CHECKLIST.read_text(encoding="utf-8"))
    ids = [s["id"] for s in data["steps"]]
    assert len(ids) == len(set(ids))
    for needed in (
        "backup",
        "schema",
        "catalogue",
        "provision",
        "administrator",
        "default_role",
        "organisations",
        "deploy",
        "smoke",
        "audit",
        "legacy",
        "rollback",
    ):
        assert needed in ids, needed
    for step in data["steps"]:
        assert {
            "id",
            "title",
            "who",
            "command",
            "verify",
            "rollback",
            "requires_approval",
        } <= set(step)
    assert (
        ids.index("backup")
        < ids.index("schema")
        < ids.index("provision")
        < ids.index("deploy")
    )
    assert cutover.main(["checklist", "--md"]) == 0
    assert "backup" in capsys.readouterr().out

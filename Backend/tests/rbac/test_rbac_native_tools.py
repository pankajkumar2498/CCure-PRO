"""Native readiness and guarded administrator bootstrap tooling."""

from __future__ import annotations


import pytest

from ccure_platform import composition
from ccure_platform.rbac import provisioning, readiness
from ccure_platform.rbac.catalogue import sync
from rbac_testing import (
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
)
from scripts.rbac import bootstrap_admin

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

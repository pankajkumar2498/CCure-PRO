"""The native catalogue operator: transactional dry-run, apply and validation.

Tests use the suite's rolled-back session and never a live database.
"""

from __future__ import annotations

import pytest

import db.base as db_base
from ccure_platform import composition
from ccure_platform.rbac.model import RbacPermission
from rbac_testing import rbac_db_fixture  # noqa: F401
from scripts.rbac import sync_catalogue


class Session:
    """The suite's session behind the script's ``SessionLocal()``: ``commit`` only
    flushes, ``close`` does nothing, and ``rollback`` discards the writes."""

    def __init__(self, db):
        self._db = db
        self.committed = False
        self.rolled_back = False

    def __getattr__(self, name):
        return getattr(self._db, name)

    def commit(self):
        self.committed = True
        self._db.flush()

    def rollback(self):
        self.rolled_back = True

    def close(self):
        pass


@pytest.fixture
def run(rbac_db, monkeypatch, capsys):
    session = Session(rbac_db)
    monkeypatch.setattr(db_base, "SessionLocal", lambda: session)

    def go(*args):
        code = sync_catalogue.main(list(args))
        return code, capsys.readouterr(), session

    return rbac_db, go


def test_a_dry_run_reports_and_commits_nothing(run):
    db, go = run
    code, out, session = go()
    assert (
        code == 0
        and "dry run" in out.out
        and not session.committed
        and session.rolled_back
    )
    assert "permissions:               +67 registered" in out.out


def test_apply_commits(run):
    db, go = run
    code, out, session = go("--apply")
    assert code == 0 and session.committed and "applied." in out.out
    assert db.query(RbacPermission).count() == 67


def test_applying_twice_changes_nothing_the_second_time(run):
    db, go = run
    go("--apply")
    code, out, _ = go("--apply")
    assert code == 0
    assert (
        "permissions:               +0 registered, 0 updated, 0 deprecated" in out.out
    )
    assert "role grants:               +0 added, -0 removed" in out.out


def test_it_stops_on_an_invalid_declaration_with_every_problem_listed(run, monkeypatch):
    from ccure_platform.rbac import contract as c

    bad = c.ModuleDeclarations(
        module_key="platform",
        namespace="platform",
        permissions=(
            c.PermissionDecl(
                key="audit.sneaky.read", description="d", scope_kind="organization"
            ),
        ),
    )
    monkeypatch.setattr(composition, "load_permission_sources", lambda: [bad])
    db, go = run
    code, out, session = go("--apply")
    assert code == 1 and not session.committed


def test_the_script_is_not_wired_into_start_up():
    from testpaths import BACKEND_ROOT

    for name in ("main.py", "start.sh", "Dockerfile"):
        text_ = (BACKEND_ROOT / name).read_text(encoding="utf-8")
        assert (
            "sync_catalogue" not in text_ and "sync_permission_catalogue" not in text_
        ), name

    allowed = {
        "ccure_platform/composition.py",
        "scripts/rbac/sync_catalogue.py",
        "scripts/audit/bench_audit_queries.py",
    }
    for path in BACKEND_ROOT.rglob("*.py"):
        relative = path.relative_to(BACKEND_ROOT)
        if relative.parts[0] in {"tests", ".venv", "venv", "__pycache__", "alembic"}:
            continue
        if relative.as_posix() in allowed:
            continue
        assert "sync_permission_catalogue" not in path.read_text(encoding="utf-8"), path

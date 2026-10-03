"""
RBAC-3 — running the comparison beside a legacy check.

``shadow_runtime`` is whether and how the comparison runs. Four properties make
shadow mode safe, and each has tests here: it is **off by default and free when
off**; it **returns nothing**; it **cannot raise**; and it **cannot touch the
request's transaction** (its own read-only session). Plus sampling, re-entrancy and
the privacy of what it records.
"""

from __future__ import annotations

import inspect
import logging

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from ccure_platform import composition
from ccure_platform.rbac import shadow as sh
from ccure_platform.rbac import shadow_runtime as rt
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,  # noqa: F401
    role,
)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    rt.reset_recorder()
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "off")
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_SAMPLE_RATE", 1.0)
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_LOG_MATCHES", False)
    yield
    rt.reset_recorder()


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    org = make_org(rbac_db)
    user = make_user(rbac_db, org)
    assign(rbac_db, user, role(rbac_db, "platform.scanner"))
    return rbac_db, user


def observe(db, user, atom="scans:execute", legacy=True, **kw):
    resource, action = atom.split(":")
    return rt.observe_permission(db, user, resource, action, legacy, **kw)


# ── off by default ───────────────────────────────────────────────────────────


def test_shadow_is_off_by_default_in_config():
    from config import RbacShadowConfig

    assert RbacShadowConfig.MODE == "off"
    import os

    assert (
        "RBAC_SHADOW_MODE" not in os.environ
    )  # nothing in this environment turns it on


def test_the_deployed_configuration_does_not_enable_it():
    from testpaths import BACKEND_ROOT, REPO_ROOT

    for path in (REPO_ROOT / "docker-compose.yml", BACKEND_ROOT / ".env.example"):
        if not path.is_file():  # the compose file is outside the API container's mount
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if "RBAC_SHADOW_MODE" in line:
                assert line.lstrip().startswith("#") or "off" in line, (path.name, line)


def test_off_means_nothing_is_evaluated_queried_or_recorded(world, monkeypatch):
    db, user = world

    def boom(*a, **k):
        raise AssertionError("shadow ran while off")

    monkeypatch.setattr(sh, "shadow_compare", boom)
    monkeypatch.setattr(rt, "_shadow_session", boom)
    for mode in ("off", "", "OFF", None):
        monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", mode)
        assert not rt.enabled()
        assert observe(db, user) is None
    assert rt.recorder().total() == 0


@pytest.mark.parametrize(
    "value", ["on", "true", "1", "enforce", "observe!", "shadow", "yes"]
)
def test_anything_but_exactly_observe_is_off_and_a_typo_is_logged_once(
    monkeypatch, caplog, value
):
    rt._warned_mode.clear()
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", value)
    with caplog.at_level(logging.WARNING, logger="ccure.rbac.shadow"):
        assert rt.mode() == "off" and rt.mode() == "off"
    assert len([r for r in caplog.records if "stays off" in r.getMessage()]) == 1


def test_observe_is_the_only_value_that_enables_it_and_case_and_space_are_forgiven(
    monkeypatch,
):
    for value in ("observe", "OBSERVE", "  Observe  "):
        monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", value)
        assert rt.enabled()


# ── when on ──────────────────────────────────────────────────────────────────


@pytest.fixture
def on(monkeypatch, world):
    db, user = world
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    with rt.use_session(db):
        yield db, user


def test_observing_records_a_comparison_and_returns_nothing(on):
    db, user = on
    assert observe(db, user, "scans:execute", True) is None
    assert observe(db, user, "scans:purge", False) is None
    snap = rt.recorder().snapshot()
    assert snap["by_kind"] == {"match": 2}


def test_observe_has_no_return_value_a_caller_could_branch_on():
    for fn in (rt.observe_permission, rt.observe_role_check):
        assert inspect.signature(fn).return_annotation in ("None", None)


def test_the_requests_own_session_is_never_used_by_the_comparison(on, monkeypatch):
    """``observe_permission`` is handed the request's ``db`` and must not touch it."""
    _, user = on

    class Untouchable:
        def __getattr__(self, name):
            raise AssertionError(f"the request session was used: {name}")

    assert observe(Untouchable(), user) is None
    assert rt.recorder().total(sh.MATCH) == 1


def test_it_records_nothing_that_could_carry_a_secret(on):
    db, user = on
    observe(db, user, "scans:execute", True, operation="POST /scan/host")
    (key,) = [k for k in rt.recorder().by_atom]
    assert key == ("scans:execute", "match")


# ── sampling ─────────────────────────────────────────────────────────────────


def test_a_zero_sample_rate_evaluates_nothing(on, monkeypatch):
    db, user = on
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_SAMPLE_RATE", 0.0)
    for _ in range(20):
        observe(db, user)
    assert rt.recorder().total() == 0


def test_a_sample_rate_selects_a_fraction(on, monkeypatch):
    db, user = on
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_SAMPLE_RATE", 0.5)
    import random

    monkeypatch.setattr(random, "random", iter([0.1, 0.9, 0.1, 0.9, 0.1, 0.9]).__next__)
    for _ in range(6):
        observe(db, user)
    assert rt.recorder().total() == 3


@pytest.mark.parametrize(
    "value,expected", [(5, 1.0), (-1, 0.0), ("junk", 1.0), (0.25, 0.25)]
)
def test_the_sample_rate_is_clamped_and_a_bad_value_cannot_break_anything(
    monkeypatch, value, expected
):
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_SAMPLE_RATE", value)
    assert rt._sample_rate() == expected


# ── it cannot raise ──────────────────────────────────────────────────────────


def test_a_comparison_that_raises_is_swallowed(on, monkeypatch):
    db, user = on

    def boom(*a, **k):
        raise RuntimeError("shadow bug")

    monkeypatch.setattr(sh, "shadow_compare", boom)
    assert observe(db, user) is None


def test_a_recorder_that_raises_is_swallowed(on, monkeypatch):
    db, user = on
    monkeypatch.setattr(
        rt, "recorder", lambda: (_ for _ in ()).throw(RuntimeError("recorder bug"))
    )
    assert observe(db, user) is None
    assert rt.observe_role_check(user, ["x"], True) is None


def test_a_broken_configuration_cannot_raise(monkeypatch, world):
    db, user = world
    monkeypatch.setattr(
        rt, "_config", lambda: (_ for _ in ()).throw(RuntimeError("config bug"))
    )
    assert observe(db, user) is None
    assert rt.observe_role_check(user, ["x"], True) is None
    assert rt.operation_of(object()) is None


def test_a_session_that_cannot_be_opened_is_swallowed(world, monkeypatch):
    db, user = world
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    monkeypatch.setattr(rt, "_session_provider", None)
    import db.base as base

    def refuse():
        raise RuntimeError("database down")

    monkeypatch.setattr(base, "SessionLocal", refuse)
    assert observe(db, user) is None
    assert rt.recorder().total() == 0


def test_an_evaluator_error_inside_the_comparison_is_recorded_as_an_error(
    on, monkeypatch
):
    from ccure_platform.rbac import resolver

    db, user = on
    monkeypatch.setattr(
        resolver, "load_catalogue", lambda d: (_ for _ in ()).throw(RuntimeError("x"))
    )
    assert observe(db, user, "scans:execute", True) is None
    snap = rt.recorder().snapshot()
    assert (
        snap["by_kind"] == {"error": 1}
        and snap["errors"][0]["classification"] == "evaluator_error"
    )
    assert snap["errors"][0]["legacy_decision"] is True


# ── its own session ──────────────────────────────────────────────────────────


def test_without_an_injected_session_the_comparison_opens_its_own_read_only_one(
    world, monkeypatch
):
    db, user = world
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_STATEMENT_TIMEOUT_MS", 321)
    import db.base as base

    class Spy:
        def __init__(self):
            self.statements, self.params, self.rolled_back, self.closed = (
                [],
                [],
                False,
                False,
            )

        def execute(self, statement, params=None):
            self.statements.append(str(statement))
            self.params.append(params)

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    spy = Spy()
    monkeypatch.setattr(base, "SessionLocal", lambda: spy)
    seen = {}

    def fake_compare(session, *a, **k):
        seen["session"] = session

    monkeypatch.setattr(sh, "shadow_compare", fake_compare)
    observe(db, user)
    assert seen["session"] is spy and seen["session"] is not db
    assert (
        spy.statements[0].strip().upper() == "SET TRANSACTION READ ONLY"
    )  # the first statement
    assert "statement_timeout" in spy.statements[1] and spy.params[1] == {"ms": "321"}
    assert spy.rolled_back and spy.closed


def test_the_own_session_is_closed_even_when_the_comparison_fails(world, monkeypatch):
    db, user = world
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    import db.base as base

    class Spy:
        closed = False

        def execute(self, *a, **k):
            pass

        def rollback(self):
            pass

        def close(self):
            Spy.closed = True

    monkeypatch.setattr(base, "SessionLocal", Spy)
    monkeypatch.setattr(
        sh, "shadow_compare", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    assert observe(db, user) is None and Spy.closed


def test_the_real_own_session_path_is_read_only_against_a_real_database(monkeypatch):
    """Not injected: a real session, a real ``SET TRANSACTION READ ONLY``. A write
    through it is refused by the database itself."""
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    with rt._shadow_session() as session:
        assert session.execute(text("SHOW transaction_read_only")).scalar() == "on"
        with pytest.raises(DBAPIError, match="read-only"):
            session.execute(text("CREATE TEMP TABLE shadow_must_not_write (x int)"))


def test_re_entrancy_a_comparison_cannot_trigger_a_comparison(on, monkeypatch):
    db, user = on
    calls = []

    def nested(session, *a, **k):
        calls.append(1)
        observe(db, user)  # what a comparison that ran a legacy check would do
        observe(db, user)

    monkeypatch.setattr(sh, "shadow_compare", nested)
    observe(db, user)
    assert calls == [1]


# ── role-name observation ────────────────────────────────────────────────────


def test_a_role_name_guard_is_recorded_as_rbac_4_evidence(on):
    _, user = on
    rt.observe_role_check(
        user, ["superadmin"], False, operation="GET /admin/email-domains/"
    )
    snap = rt.recorder().snapshot()
    assert snap["by_classification"] == {"not_comparable/role_name_check": 1}


def test_a_role_name_observation_is_off_when_off(monkeypatch, world):
    _, user = world
    rt.observe_role_check(user, ["superadmin"], False)
    assert rt.recorder().total() == 0


# ── the operation label ──────────────────────────────────────────────────────


def test_the_operation_is_a_route_template_never_a_raw_path_or_query():
    app = FastAPI()
    seen = {}

    @app.get("/things/{thing_id}")
    def thing(thing_id: str, request: Request):
        seen["op"] = rt.operation_of(request)
        return {}

    client = TestClient(app)
    client.get(
        "/things/secret-id-123?token=abc&password=hunter2",
        headers={"Authorization": "Bearer sekret", "Cookie": "s=1"},
    )
    assert seen["op"] == "GET /things/{thing_id}"
    assert not any(
        w in seen["op"] for w in ("secret", "token", "abc", "hunter2", "sekret")
    )


def test_the_operation_is_none_without_a_request_and_the_method_without_a_route():
    assert rt.operation_of(None) is None

    class R:
        method, scope = "POST", {}

    assert rt.operation_of(R()) == "POST"

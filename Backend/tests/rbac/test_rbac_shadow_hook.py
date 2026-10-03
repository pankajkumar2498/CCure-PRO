"""
RBAC-3 — the hook in the legacy guards, and the proof that shadow cannot change an
authorization outcome.

**RBAC-3 = SHADOW ONLY. LEGACY AUTHORIZATION = AUTHORITATIVE.** Every test here runs
the *real* legacy guards (``require_permission``, ``require_role``,
``user_has_permission``) on a real route and compares what a client gets with shadow
off against what it gets with shadow on:

* **shadow ALLOW cannot grant access** — the new model would allow, legacy denies,
  the response is still 403;
* **shadow DENY cannot remove access** — the new model would deny, legacy allows,
  the response is still 200;
* **shadow ERROR cannot change access** — the comparison blows up, in every way it
  can, and the response is whatever legacy decided.

The legacy tables are the real seeded ones; the RBAC data lives in a rolled-back
transaction, and the shadow session is injected so it can see it.
"""

from __future__ import annotations

import inspect
import itertools
import random

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import ccure_platform.api as api
import ccure_platform.rbac.dependencies as legacy
from ccure_platform import composition
from ccure_platform.identity.dependencies import get_current_user
from ccure_platform.rbac import resolver
from ccure_platform.rbac import shadow as sh
from ccure_platform.rbac import shadow_runtime as rt
from ccure_platform.rbac.catalogue import sync
from config import AppConfig
from db.base import get_db
from db.models import Role
from rbac_testing import (
    assign,
    make_org,
    make_user,
    rbac_db_fixture,
    role,
)  # noqa: F401

LEGACY_ROLES = ("superadmin", "org_admin", "analyst", "viewer", "scanner")


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    rt.reset_recorder()
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "off")
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_SAMPLE_RATE", 1.0)
    yield
    rt.reset_recorder()


def with_legacy_role(db, user, name):
    user.role_id = db.query(Role).filter(Role.name == name).one().id
    db.flush()
    db.refresh(user)
    return user


@pytest.fixture
def world(rbac_db):
    sync(rbac_db, composition.load_permission_sources(), audit=False)
    w = type("World", (), {})()
    w.db, w.org = rbac_db, make_org(rbac_db)
    w.current = {}
    app = FastAPI()

    @app.post("/scan")
    def scan(who=Depends(legacy.require_permission("scans", "execute"))):
        return {"ok": True}

    @app.get("/users")
    def users(who=Depends(legacy.require_permission("users", "read"))):
        return {"ok": True}

    @app.get("/admin")
    def admin(who=Depends(legacy.require_role("superadmin"))):
        return {"ok": True}

    app.dependency_overrides[get_current_user] = lambda: w.current["user"]
    app.dependency_overrides[get_db] = lambda: rbac_db
    w.client = TestClient(app)
    w.app = app

    def person(legacy_role, rbac_role=None):
        user = with_legacy_role(rbac_db, make_user(rbac_db, w.org), legacy_role)
        if rbac_role:
            assign(rbac_db, user, role(rbac_db, rbac_role))
        return user

    w.person = person
    return w


def call(world, user, method, path):
    world.current["user"] = user
    r = world.client.request(method, path)
    return r.status_code, r.json()


def shadow_on(monkeypatch, db):
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    return rt.use_session(db)


# ── the hook preserves what the guards were ──────────────────────────────────


def test_the_legacy_guards_are_the_same_objects_as_before():
    assert api.require_permission is legacy.require_permission
    assert api.require_role is legacy.require_role
    assert legacy.user_has_permission.__name__ == "user_has_permission"
    assert list(inspect.signature(legacy.user_has_permission).parameters) == [
        "db",
        "user",
        "resource",
        "action",
        "operation",
        "authoritative",  # RBAC-4: off unless a migrated path asks for it
    ]
    assert (
        inspect.signature(legacy.user_has_permission).parameters["operation"].kind
        is inspect.Parameter.KEYWORD_ONLY
    )
    assert (
        inspect.signature(legacy.user_has_permission)
        .parameters["authoritative"]
        .default
        is False
    )
    assert (
        api.user_has_permission
    )  # the platform API wrapper still exists and still takes four


def test_the_decision_logic_does_not_mention_shadow_or_the_new_engine():
    """The legacy rule is its own function, untouched by the hook."""
    source = inspect.getsource(legacy._legacy_decision)
    for word in ("shadow", "engine", "resolver", "rbac_", "Rbac"):
        assert word not in source


def test_the_guards_hand_over_their_decision_and_return_nothing_from_the_hook():
    for fn in (
        legacy._observe_permission,
        legacy._observe_role_check,
        legacy._operation,
    ):
        src = inspect.getsource(fn)
        assert "return None" in src or "return operation_of" in src
    assert "shadow_runtime" in inspect.getsource(legacy)


def test_the_hook_adds_no_parameter_to_the_openapi_contract(world):
    schema = world.app.openapi()
    for path in ("/scan", "/users", "/admin"):
        for op in schema["paths"][path].values():
            assert not [p for p in op.get("parameters", []) if p["name"] == "request"]


def test_the_application_routes_and_guard_count_are_unchanged():
    from main import app

    assert len(app.routes) == 274
    guards = sum(
        1
        for route in app.routes
        for dep in getattr(getattr(route, "dependant", None), "dependencies", [])
        if getattr(dep.call, "__qualname__", "").startswith(
            ("require_permission.", "require_role.")
        )
    )
    assert guards > 150


# ── shadow ALLOW cannot grant access ─────────────────────────────────────────


def test_shadow_allow_cannot_grant_access(world, monkeypatch):
    viewer = world.person(
        "viewer", "platform.superadmin"
    )  # the new model would allow everything
    off = call(world, viewer, "POST", "/scan")
    assert off[0] == 403
    with shadow_on(monkeypatch, world.db):
        on = call(world, viewer, "POST", "/scan")
    assert on == off  # status and body identical
    snap = rt.recorder().snapshot()
    assert snap["by_classification"] == {
        "mismatch/new_allows_legacy_denies": 1
    }  # it saw the disagreement
    assert (
        snap["mismatches"][0]["new_decision"] is True
        and snap["mismatches"][0]["legacy_decision"] is False
    )


def test_shadow_allow_cannot_grant_a_role_name_guarded_route_either(world, monkeypatch):
    analyst = world.person("analyst", "platform.superadmin")
    assert call(world, analyst, "GET", "/admin")[0] == 403
    with shadow_on(monkeypatch, world.db):
        assert call(world, analyst, "GET", "/admin")[0] == 403


# ── shadow DENY cannot remove access ─────────────────────────────────────────


def test_shadow_deny_cannot_remove_access(world, monkeypatch):
    admin = world.person(
        "org_admin", "platform.viewer"
    )  # the new model would deny scanning
    off = call(world, admin, "POST", "/scan")
    assert off == (200, {"ok": True})
    with shadow_on(monkeypatch, world.db):
        on = call(world, admin, "POST", "/scan")
    assert on == off
    snap = rt.recorder().snapshot()
    assert snap["by_classification"] == {"mismatch/new_denies_legacy_allows": 1}
    assert (
        snap["mismatches"][0]["new_decision"] is False
        and snap["mismatches"][0]["legacy_decision"] is True
    )


def test_a_user_with_no_rbac_role_keeps_every_legacy_permission(world, monkeypatch):
    analyst = world.person("analyst")  # not provisioned in RBAC at all
    with shadow_on(monkeypatch, world.db):
        assert call(world, analyst, "POST", "/scan")[0] == 200
        assert call(world, analyst, "GET", "/users")[0] == 403
    assert rt.recorder().snapshot()["by_classification"] == {
        "not_comparable/principal_not_provisioned": 2
    }


# ── shadow ERROR cannot change access ────────────────────────────────────────

FAILURES = {
    "catalogue query raises": lambda mp: mp.setattr(
        resolver, "load_catalogue", lambda d: (_ for _ in ()).throw(RuntimeError("x"))
    ),
    "grants query raises": lambda mp: mp.setattr(
        resolver,
        "resolve_grants",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
    ),
    "golden mapping unreadable": lambda mp: mp.setattr(
        sh, "golden_index", lambda: (_ for _ in ()).throw(sh.MappingUnavailable("x"))
    ),
    "comparison raises": lambda mp: mp.setattr(
        sh, "shadow_compare", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    ),
    "recorder raises": lambda mp: mp.setattr(
        rt, "recorder", lambda: (_ for _ in ()).throw(RuntimeError("x"))
    ),
    "session cannot open": lambda mp: mp.setattr(
        rt, "_shadow_session", lambda: (_ for _ in ()).throw(RuntimeError("x"))
    ),
    "config raises": lambda mp: mp.setattr(
        rt, "_config", lambda: (_ for _ in ()).throw(RuntimeError("x"))
    ),
    "hook import fails": lambda mp: mp.setitem(
        __import__("sys").modules, "ccure_platform.rbac.shadow_runtime", None
    ),
}


@pytest.mark.parametrize("failure", sorted(FAILURES))
@pytest.mark.parametrize("who", ["allowed", "denied"])
def test_shadow_error_cannot_change_access(world, monkeypatch, failure, who):
    user = (
        world.person("scanner", "platform.scanner")
        if who == "allowed"
        else world.person("viewer", "platform.viewer")
    )
    expected = 200 if who == "allowed" else 403
    assert call(world, user, "POST", "/scan")[0] == expected  # shadow off
    with monkeypatch.context() as mp:
        mp.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
        with rt.use_session(world.db):
            FAILURES[failure](mp)
            assert call(world, user, "POST", "/scan")[0] == expected
            assert call(world, user, "GET", "/admin")[0] == 403


def test_an_evaluator_failure_is_recorded_as_an_error_and_the_request_continues(
    world, monkeypatch
):
    user = world.person("scanner", "platform.scanner")
    monkeypatch.setattr(
        resolver, "load_catalogue", lambda d: (_ for _ in ()).throw(RuntimeError("x"))
    )
    with shadow_on(monkeypatch, world.db):
        assert call(world, user, "POST", "/scan") == (200, {"ok": True})
    snap = rt.recorder().snapshot()
    assert (
        snap["by_kind"] == {"error": 1} and snap["errors"][0]["legacy_decision"] is True
    )


# ── the property: whatever shadow does, the decision is legacy's ─────────────

SHADOWS = {
    "off": lambda mp, db: None,
    "real": lambda mp, db: mp.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe"),
    "garbage mode": lambda mp, db: mp.setattr(AppConfig, "RBAC_SHADOW_MODE", "enforce"),
    "always errors": lambda mp, db: (
        mp.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe"),
        mp.setattr(
            sh,
            "shadow_compare",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x")),
        ),
    ),
    "mutating evaluator": lambda mp, db: (
        mp.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe"),
        mp.setattr(sh, "shadow_compare", lambda *a, **k: True),
    ),
    "sampled out": lambda mp, db: (
        mp.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe"),
        mp.setattr(AppConfig, "RBAC_SHADOW_SAMPLE_RATE", 0.0),
    ),
}


def test_every_legacy_role_and_atom_gets_the_same_answer_whatever_shadow_does(
    world, monkeypatch
):
    """5 legacy roles x 5 RBAC roles (and none) x 12 atoms x 6 shadow behaviours: the
    legacy decision is the only thing that ever reaches a caller."""
    atoms = [
        ("scans", "read"),
        ("scans", "execute"),
        ("users", "update"),
        ("organizations", "read"),
        ("audit", "purge"),
        ("scans", "cancel"),
        ("widgets", "frob"),
        ("roles", "read"),
        ("compliance", "approve_exception"),
        ("findings", "accept_risk"),
        ("settings", "update"),
        ("reports", "delete"),
    ]
    rbac = [
        None,
        "platform.superadmin",
        "platform.org_admin",
        "platform.analyst",
        "platform.viewer",
        "platform.scanner",
    ]
    people = [
        (lr, rr, world.person(lr, rr))
        for lr, rr in itertools.product(LEGACY_ROLES, rbac)
    ]
    baseline = {
        (lr, rr, a): legacy.user_has_permission(world.db, u, *a)
        for lr, rr, u in people
        for a in atoms
    }
    for name, arrange in SHADOWS.items():
        with monkeypatch.context() as mp:
            arrange(mp, world.db)
            with rt.use_session(world.db):
                got = {
                    (lr, rr, a): legacy.user_has_permission(world.db, u, *a)
                    for lr, rr, u in people
                    for a in atoms
                }
        assert got == baseline, name
    assert all(isinstance(v, bool) for v in baseline.values())


def test_the_legacy_decision_itself_is_unchanged_from_the_seeded_rules(
    world, monkeypatch
):
    from db.migrate_production_schema import ROLE_PERMISSIONS

    with shadow_on(monkeypatch, world.db):
        for name in LEGACY_ROLES:
            user = world.person(
                name, "platform.viewer"
            )  # the RBAC side is deliberately unrelated
            for atom in (
                "scans:read",
                "scans:execute",
                "users:create",
                "organizations:read",
            ):
                r, a = atom.split(":")
                expected = (
                    True if name == "superadmin" else atom in ROLE_PERMISSIONS[name]
                )
                assert legacy.user_has_permission(world.db, user, r, a) is expected, (
                    name,
                    atom,
                )


def test_a_legacy_exception_still_propagates_the_hook_does_not_swallow_the_guards_own_errors(
    world, monkeypatch
):
    user = world.person("viewer")
    monkeypatch.setattr(AppConfig, "RBAC_SHADOW_MODE", "observe")
    monkeypatch.setattr(
        legacy,
        "_legacy_decision",
        lambda *a: (_ for _ in ()).throw(ValueError("legacy bug")),
    )
    with pytest.raises(ValueError, match="legacy bug"):
        legacy.user_has_permission(world.db, user, "scans", "read")


def test_the_platform_api_wrapper_still_answers_from_the_legacy_rule(
    world, monkeypatch
):
    viewer = world.person("viewer", "platform.superadmin")
    with shadow_on(monkeypatch, world.db):
        assert api.user_has_permission(world.db, viewer, "scans", "execute") is False
        assert api.user_has_permission(world.db, viewer, "scans", "read") is True
        assert api.user_has_permission(world.db, viewer.id, "scans", "read") is True


# ── require_role: evidence, not a comparison ─────────────────────────────────


def test_require_role_decides_exactly_as_before(world, monkeypatch):
    for name, expected in (("superadmin", 200), ("org_admin", 403), ("viewer", 403)):
        user = world.person(name)
        assert call(world, user, "GET", "/admin")[0] == expected
        with shadow_on(monkeypatch, world.db):
            assert call(world, user, "GET", "/admin")[0] == expected


def test_a_role_name_guard_is_recorded_with_its_route_template(world, monkeypatch):
    boss, other = world.person("superadmin"), world.person("viewer")
    with shadow_on(monkeypatch, world.db):
        call(world, boss, "GET", "/admin")
        call(world, other, "GET", "/admin")
    snap = rt.recorder().snapshot()
    assert snap["by_classification"] == {"not_comparable/role_name_check": 2}
    assert rt.recorder().by_atom[(None, "not_comparable")] == 2


def test_the_observed_operation_is_the_route_template(world, monkeypatch):
    user = world.person("org_admin", "platform.viewer")
    with shadow_on(monkeypatch, world.db):
        call(world, user, "POST", "/scan")
    assert rt.recorder().snapshot()["mismatches"][0]["operation"] == "POST /scan"


def test_shadow_off_records_and_queries_nothing_through_the_real_guards(
    world, monkeypatch
):
    user = world.person("org_admin", "platform.viewer")
    monkeypatch.setattr(
        rt,
        "_shadow_session",
        lambda: (_ for _ in ()).throw(AssertionError("opened a session")),
    )
    for _ in range(3):
        assert call(world, user, "POST", "/scan")[0] == 200
    assert rt.recorder().total() == 0


def test_a_random_walk_of_requests_never_differs_from_the_legacy_baseline(
    world, monkeypatch
):
    rng = random.Random(7)
    people = [
        world.person(
            lr,
            rng.choice(
                [None, "platform.viewer", "platform.superadmin", "platform.scanner"]
            ),
        )
        for lr in LEGACY_ROLES
        for _ in range(2)
    ]
    plan = [
        (
            rng.choice(people),
            rng.choice([("POST", "/scan"), ("GET", "/users"), ("GET", "/admin")]),
        )
        for _ in range(60)
    ]
    baseline = [call(world, u, m, p) for u, (m, p) in plan]
    with shadow_on(monkeypatch, world.db):
        assert [call(world, u, m, p) for u, (m, p) in plan] == baseline

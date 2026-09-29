"""
Phase 10.2c — the gateway route policy generated from the live route table.

What is pinned here:

* the counts and the exact membership of every class, as characterised in
  Phase 10.1 (17 public, 251 bearer, 3 ticket_or_bearer, 2 WebSocket);
* the frozen decisions: OPTIONS is never authenticated, unrouted requests are
  forwarded so the application answers 404/405/307 (X6-a), ``/api/ir/*`` is
  unrouted, ``DELETE /reports/{scan_id}`` is ticket_or_bearer, and no
  ``WWW-Authenticate`` appears (X2-a);
* **parity with Starlette's own router**: for every route, and for requests
  that match none, the class the nginx map would give equals the route
  Starlette would dispatch to — so route order and exact-versus-regex keys are
  proven, not assumed;
* determinism, and **drift**: the committed ``gateway/policy/*`` files must be
  byte-identical to a fresh generation from the live application, and the
  inventory must equal the Phase 10.1 characterisation. Both are skipped, with
  the reason, where the checkout is not reachable (the api container mounts
  only ``Backend/`` and ``docs/``); CI runs on a full checkout.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

import pytest

from scripts.gateway import route_policy as rp
from testpaths import BACKEND_ROOT, REPO_ROOT

PUBLIC = [
    ("GET", "/auth/check-username"),
    ("GET", "/auth/check-email"),
    ("POST", "/auth/register"),
    ("POST", "/auth/verify-email"),
    ("POST", "/auth/resend-verification"),
    ("POST", "/auth/login"),
    ("POST", "/auth/logout"),
    ("GET", "/auth/jwks.json"),
    ("POST", "/auth/refresh"),
    ("POST", "/auth/forgot-password"),
    ("POST", "/auth/reset-password"),
    ("POST", "/auth/login/send-email-otp"),
    ("POST", "/auth/login/verify-mfa"),
    ("POST", "/auth/service-token"),
    ("GET", "/"),
    ("GET", "/api/pipeline-modes"),
    ("GET", "/api/workflow-example"),
]
TICKET_OR_BEARER = [
    ("GET", "/reports/download/{scan_id}"),
    ("GET", "/reports/export/{scan_id}"),
    ("DELETE", "/reports/{scan_id}"),
]
WEBSOCKETS = ["/scans/{scan_id}/progress", "/web-scans/{scan_id}/progress"]


@pytest.fixture(scope="module")
def app():
    logging.disable(logging.CRITICAL)
    try:
        from main import app as application
    finally:
        logging.disable(logging.NOTSET)
    return application


@pytest.fixture(scope="module")
def policy(app):
    return rp.compile_policy(rp.live_inventory(app))


def _entries(policy, route_class):
    return [
        (e["method"], e["path"]) for e in policy["routes"] if e["class"] == route_class
    ]


# ── counts and membership ────────────────────────────────────────────────────


def test_counts_are_the_characterised_ones(policy):
    assert policy["counts"] == {
        "public": 17,
        "bearer": 251,
        "ticket_or_bearer": 3,
        "websocket": 2,
        "total": 273,
    }


def test_the_public_allowlist_is_exactly_the_characterised_17(policy):
    assert sorted(_entries(policy, "public")) == sorted(PUBLIC)


def test_bearer_routes(policy):
    bearer = _entries(policy, "bearer")
    assert len(bearer) == 251
    assert ("GET", "/scans") in bearer and ("POST", "/auth/ticket") in bearer
    assert all(
        e["checker_policy"] == "bearer"
        for e in policy["routes"]
        if e["class"] == "bearer"
    )


def test_ticket_or_bearer_routes_include_delete_report(policy):
    assert _entries(policy, "ticket_or_bearer") == TICKET_OR_BEARER
    delete = next(
        e
        for e in policy["routes"]
        if (e["method"], e["path"]) == ("DELETE", "/reports/{scan_id}")
    )
    assert delete["checker_policy"] == "ticket_or_bearer"


def test_websocket_routes(policy):
    ws = [e for e in policy["routes"] if e["class"] == "websocket"]
    assert [e["path"] for e in ws] == WEBSOCKETS
    assert all(
        e["scope"] == "websocket"
        and e["method"] == "GET"
        and e["checker_policy"] == "ticket"
        for e in ws
    )


def test_class_to_checker_policy(policy):
    assert policy["class_to_checker_policy"] == {
        "public": "none",
        "bearer": "bearer",
        "ticket_or_bearer": "ticket_or_bearer",
        "websocket": "ticket",
        "options": "none",
        "unrouted": "none",
    }
    assert policy["default"] == {"class": "unrouted", "checker_policy": "none"}


# ── OPTIONS, unrouted (X6-a), /api/ir/* ──────────────────────────────────────


def test_options_is_never_authenticated(policy):
    for entry in policy["routes"]:
        path = entry["path"].replace("{scan_id}", "x").replace("{", "").replace("}", "")
        assert rp.evaluate(policy, "http", "OPTIONS", path) == "options"
    assert rp.evaluate(policy, "http", "OPTIONS", "/no/such/route") == "options"
    assert rp.CHECKER_POLICY["options"] == "none"


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/no-such-route"),
        ("GET", "/scans/"),  # trailing-slash redirect (307) in the app
        ("GET", "/scan/host-discovery"),  # POST-only route: 405 in the app
        ("DELETE", "/scans"),
        ("PUT", "/auth/login"),
        ("HEAD", "/"),
        ("HEAD", "/scans"),
        (
            "GET",
            "/api/scans",
        ),  # the prefix is stripped before the map; a doubled one is unknown
    ],
)
def test_unrouted_requests_are_forwarded_unauthenticated(policy, method, path):
    assert rp.evaluate(policy, "http", method, path) == "unrouted"


@pytest.mark.parametrize(
    "path", ["/ir", "/ir/", "/ir/health", "/ir/incidents", "/ir/incidents/x/evidence"]
)
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE"])
def test_api_ir_stays_unrouted_in_phase_10(policy, method, path):
    assert rp.evaluate(policy, "http", method, path) == "unrouted"


def test_a_plain_get_to_a_websocket_path_is_unrouted(policy):
    assert rp.evaluate(policy, "http", "GET", "/scans/x/progress") == "unrouted"
    assert rp.evaluate(policy, "websocket", "GET", "/scans/x/progress") == "websocket"


# ── parity with Starlette's router (order, exact vs regex) ───────────────────


def _starlette_class(app, policy, scope_type, method, path):
    from starlette.routing import Match

    by_order = {}
    for entry in policy["routes"]:
        by_order.setdefault((entry["order"], entry["method"]), entry["class"])
    scope = {
        "type": scope_type,
        "path": path,
        "root_path": "",
        "method": method,
        "headers": [],
        "query_string": b"",
    }
    for order, route in enumerate(app.routes):
        match, _ = route.matches(scope)
        if match == Match.FULL:
            return by_order[(order, method)]
    return "unrouted"


def _instances(path):
    return (
        path.replace("{", "<").replace("}", ">").replace("<scan_id>", "p1")
        if "{" in path
        else path
    )


def _concrete(path):
    import re

    return re.sub(r"\{[^}]+\}", "p1", path)


def test_every_route_resolves_as_starlette_dispatches_it(app, policy):
    mismatches = []
    for entry in policy["routes"]:
        path = _concrete(entry["path"])
        got = rp.evaluate(policy, entry["scope"], entry["method"], path)
        want = _starlette_class(app, policy, entry["scope"], entry["method"], path)
        if got != want:
            mismatches.append(
                f"{entry['scope']} {entry['method']} {path}: map {got}, starlette {want}"
            )
    assert not mismatches, "\n".join(mismatches)


def test_unmatched_requests_agree_with_starlette(app, policy):
    samples = set()
    methods = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")
    for entry in policy["routes"]:
        path = _concrete(entry["path"])
        for method in methods:
            samples.add(("http", method, path))
        samples.add(("http", "GET", path.rstrip("/") + "/extra"))
        samples.add(
            ("http", "GET", path + "/" if not path.endswith("/") else path[:-1])
        )
    samples |= {
        ("http", "GET", "/ir/health"),
        ("http", "GET", "/no-such"),
        ("websocket", "GET", "/scans"),
    }
    mismatches = []
    for scope_type, method, path in sorted(samples):
        got = rp.evaluate(policy, scope_type, method, path)
        want = _starlette_class(app, policy, scope_type, method, path)
        if got != want:
            mismatches.append(
                f"{scope_type} {method} {path}: map {got}, starlette {want}"
            )
    assert len(samples) > 1500
    assert not mismatches, "\n".join(mismatches[:20])


def test_route_order_is_preserved(app, policy):
    orders = [e["order"] for e in policy["routes"]]
    assert orders == sorted(orders)
    assert orders[0] == 0 and orders[-1] == len(app.routes) - 1
    regexes = [e for e in policy["routes"] if e["match"] == "regex"]
    assert [e["order"] for e in regexes] == sorted(e["order"] for e in regexes)
    rendered = rp.render_map(policy)
    positions = [rendered.index(f"  # {e['order']}\n") for e in policy["routes"]]
    assert positions == sorted(positions)


def test_no_duplicate_or_conflicting_policies(policy):
    keys = [(e["scope"], e["method"], e["path"]) for e in policy["routes"]]
    assert len(keys) == len(set(keys))
    map_keys = [e["map_key"] for e in policy["routes"]]
    assert len(map_keys) == len(set(map_keys))
    assert policy["shadowed"] == []


# ── the generator's refusals ─────────────────────────────────────────────────


def _r(order, method, path, route_class, scope="http"):
    return rp.Route(order, scope, method, path, route_class, f"m.f{order}")


def test_a_duplicate_route_with_a_different_class_is_refused():
    with pytest.raises(rp.PolicyError, match="declared twice"):
        rp.compile_policy([_r(0, "GET", "/a", "public"), _r(1, "GET", "/a", "bearer")])


def test_a_duplicate_with_the_same_class_is_recorded_not_emitted_twice():
    p = rp.compile_policy([_r(0, "GET", "/a", "bearer"), _r(1, "GET", "/a", "bearer")])
    assert len(p["routes"]) == 1 and p["shadowed"][0]["reason"] == "duplicate"


def test_a_literal_shadowed_by_an_earlier_template_is_a_regex_or_refused():
    same = rp.compile_policy(
        [_r(0, "GET", "/scans/{id}", "bearer"), _r(1, "GET", "/scans/events", "bearer")]
    )
    assert [e["match"] for e in same["routes"]] == ["regex", "regex"]
    assert same["shadowed"][0]["reason"] == "template"
    with pytest.raises(rp.PolicyError, match="shadowed"):
        rp.compile_policy(
            [
                _r(0, "GET", "/scans/{id}", "bearer"),
                _r(1, "GET", "/scans/events", "public"),
            ]
        )


def test_a_literal_before_a_template_stays_exact():
    p = rp.compile_policy(
        [_r(0, "GET", "/scans/events", "public"), _r(1, "GET", "/scans/{id}", "bearer")]
    )
    assert [e["match"] for e in p["routes"]] == ["exact", "regex"]
    assert rp.evaluate(p, "http", "GET", "/scans/events") == "public"
    assert rp.evaluate(p, "http", "GET", "/scans/x") == "bearer"


@pytest.mark.parametrize(
    "route",
    [
        _r(0, "GET", "/files/{name:path}", "bearer"),
        _r(0, "OPTIONS", "/a", "public"),
        _r(0, "GET", "/a b", "bearer"),
        _r(0, "GET", "/a", "service"),
    ],
)
def test_unrepresentable_routes_are_refused(route):
    with pytest.raises(rp.PolicyError):
        rp.compile_policy([route])


def test_a_service_token_route_is_refused():
    with pytest.raises(rp.PolicyError, match="Phase 14"):
        rp._classify({"require_service_scope.<locals>.dependency"})


# ── rendering and determinism ────────────────────────────────────────────────


def test_rendering_is_deterministic(app):
    assert rp.generate(app) == rp.generate(app)


def test_two_independent_processes_generate_identical_bytes():
    outputs = []
    for _ in range(2):
        run = subprocess.run(
            [sys.executable, "-m", "scripts.gateway.route_policy", "--emit", "json"],
            cwd=BACKEND_ROOT,
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        outputs.append(run.stdout)
    assert outputs[0] == outputs[1] and outputs[0].startswith("{")


def test_the_map_is_ascii_names_every_route_and_adds_no_challenge(policy):
    rendered = rp.render_map(policy)
    rendered.encode("ascii")
    assert "WWW-Authenticate" not in rendered  # X2-a: the map adds no challenge
    as_json = rp.render_json(policy)
    assert (
        as_json.count("WWW-Authenticate") == 1
        and "no WWW-Authenticate" in policy["decisions"]["X2"]
    )
    for entry in policy["routes"]:
        assert f"    {entry['map_key']} " in rendered
    assert "    default" in rendered and "unrouted;" in rendered
    assert "~^http:OPTIONS:" in rendered


def test_the_generator_describes_policy_and_verifies_nothing():
    import ast

    tree = ast.parse(
        (BACKEND_ROOT / "scripts" / "gateway" / "route_policy.py").read_text()
    )
    imported = {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    imported |= {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
    }
    assert not any(
        m.split(".")[0] in ("jose", "jwt") or "verification" in m or "tokens" in m
        for m in imported
    ), imported


# ── drift ────────────────────────────────────────────────────────────────────


def test_committed_policy_matches_the_live_application(app):
    """A route added, removed, reordered or re-guarded must be regenerated."""
    paths = rp.output_paths(REPO_ROOT)
    if not paths["json"].parent.is_dir():
        pytest.skip(f"gateway/policy is not reachable from {REPO_ROOT}")
    rendered = rp.generate(app)
    stale = [
        kind
        for kind, path in paths.items()
        if not path.is_file() or path.read_text(encoding="utf-8") != rendered[kind]
    ]
    assert not stale, (
        f"gateway/policy/{stale} is stale: the application's routes changed. Review the change, "
        "re-run the Phase 10 characterisation if a route's authentication changed, then "
        "`python -m scripts.gateway.route_policy --write`."
    )


def test_inventory_matches_the_phase_10_1_characterisation(policy):
    for candidate in (REPO_ROOT / "docs", "/docs"):
        table = os.path.join(
            str(candidate), "architecture", "phase10", "route_table.json"
        )
        if os.path.isfile(table):
            break
    else:
        pytest.skip("docs/architecture/phase10/route_table.json is not reachable")
    with open(table) as fh:
        characterised = json.load(fh)
    auth = {
        "public": "public",
        "bearer": "bearer",
        "ticket_or_bearer": "ticket_or_bearer",
        "ws_ticket": "websocket",
    }
    recorded = [
        (
            "GET" if r["method"] == "WS" else r["method"],
            r["path"],
            auth[r["auth"]],
            r["endpoint"],
        )
        for r in characterised
    ]
    generated = [
        (e["method"], e["path"], e["class"], e["endpoint"]) for e in policy["routes"]
    ]
    assert generated == recorded, (
        "the live route inventory no longer matches the Phase 10.1 characterisation; "
        "re-characterise before regenerating the gateway policy"
    )

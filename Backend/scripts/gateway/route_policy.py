"""
The gateway's route policy, generated from the live application's route table
(Phase 10.2c).

For every route the application serves, in **the application's own route
order**, this names which credential the gateway must ask ``gateway-auth`` to
check. It describes policy only — nothing here verifies anything; that stays in
``ccure_platform.identity.verification`` and ``gateway/token_check``.

Route classes, and the ``gateway-auth`` policy each is checked with:

=================  ==================  =============================================
class              checker policy      what it is
=================  ==================  =============================================
public             none                the characterised 17-route allowlist
bearer             bearer              ``HTTPBearer()`` routes
ticket_or_bearer   ticket_or_bearer    ``get_current_user_flexible`` routes
websocket          ticket              the WebSocket ticket logins
options            none                every ``OPTIONS`` request, whatever the path
unrouted           none                no route matches (X6-a, below)
=================  ==================  =============================================

**X6-a (owner decision, 29 Sep 2026).** A request matching no route —
unknown path, wrong method, trailing-slash redirect, ``HEAD`` on a ``GET``
route, all of ``/api/ir/*`` — is forwarded to the application unauthenticated,
so its own 404 / 405 / 307 is what the client sees, exactly as today.
**X2-a**: nothing here adds ``WWW-Authenticate``.

**The match key** is ``<scope>:<METHOD>:<application path>``, where scope is
``http`` or ``websocket`` (Starlette routes the two separately: a plain ``GET``
to a WebSocket path is a 404) and the application path is the request path
with ``/api`` removed, exactly as host nginx strips it today.

**Order is Starlette's.** Starlette takes the first route whose path *and*
method match. An nginx ``map`` checks exact keys before any regex and regexes
in order of appearance, so a literal route is emitted as an exact key only
when no earlier route of the same scope and method could match its path;
otherwise it is emitted as a regex in its place, and every templated route is
a regex in its place. :func:`evaluate` implements the nginx semantics so the
tests can prove the two agree for every route.

**Refusals, not guesses.** The generator refuses an inventory it cannot
represent faithfully: a route authenticated by a mechanism it does not know
(service tokens have no consumer until Phase 14), a path with a converter,
a duplicate ``(scope, method, path)`` with a different class, or a key nginx
could misparse.

**Drift.** The generated files are committed under ``gateway/policy/`` and
``tests/repo/test_gateway_route_policy.py`` regenerates them from the live
application and compares bytes — a route added, removed, reordered or
re-guarded without regenerating fails the build rather than leaving the
gateway with a stale policy.

Usage (from ``Backend/``; the application is imported, nothing is written
unless asked)::

    python -m scripts.gateway.route_policy --check        # exit 1 on drift
    python -m scripts.gateway.route_policy --write        # needs ../gateway/
    python -m scripts.gateway.route_policy --emit json    # to stdout
    python -m scripts.gateway.route_policy --emit map     # to stdout
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

SCHEMA = "ccure.gateway.route_policy/1"
GENERATOR = "Backend/scripts/gateway/route_policy.py"

#: Route class → the policy gateway-auth checks it with (gateway/token_check/checker.py POLICIES).
CHECKER_POLICY = {
    "public": "none",
    "bearer": "bearer",
    "ticket_or_bearer": "ticket_or_bearer",
    "websocket": "ticket",
    "options": "none",
    "unrouted": "none",
}
ROUTE_CLASSES = ("public", "bearer", "ticket_or_bearer", "websocket")

#: Dependencies that decide a route's class, matched on the qualified name.
_FLEXIBLE = ("get_current_user_flexible",)
_BEARER = ("get_current_user", "get_current_auth_context")
_SERVICE = ("require_service_scope", "service_principal_for")

#: Characters a key may carry unquoted in an nginx map.
_NGINX_SAFE = re.compile(r"^[A-Za-z0-9_\-./:\[\]^$+\\~]+$")
_PARAM = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class PolicyError(ValueError):
    """The inventory cannot be represented faithfully."""


@dataclass(frozen=True)
class Route:
    """One (route, method) of the application, in route order."""

    order: int
    scope: str  # http | websocket
    method: str
    path: str
    route_class: str
    endpoint: str

    @property
    def key(self) -> str:
        return f"{self.scope}:{self.method}:{self.path}"


# ── the live inventory ───────────────────────────────────────────────────────


def _dependency_names(dependant) -> set[str]:
    names = set()
    for dep in dependant.dependencies:
        names.add(
            getattr(
                dep.call, "__qualname__", getattr(dep.call, "__name__", repr(dep.call))
            )
        )
        names |= _dependency_names(dep)
    return names


def _classify(names: set[str]) -> str:
    if any(any(s in n for s in _SERVICE) for n in names):
        raise PolicyError(
            "a route authenticates service tokens; the gateway has no policy for them "
            "until Phase 14 has a consumer"
        )
    if any(any(f in n for f in _FLEXIBLE) for n in names):
        return "ticket_or_bearer"
    if any(any(b in n for b in _BEARER) for n in names):
        return "bearer"
    return "public"


def live_inventory(app) -> list[Route]:
    """The application's routes, one entry per method, in route order."""
    from fastapi.routing import APIRoute, APIWebSocketRoute

    routes: list[Route] = []
    for order, route in enumerate(app.routes):
        endpoint = getattr(route, "endpoint", None)
        name = f"{endpoint.__module__}.{endpoint.__name__}" if endpoint else repr(route)
        if isinstance(route, APIRoute):
            route_class = _classify(_dependency_names(route.dependant))
            for method in sorted(route.methods):
                routes.append(
                    Route(order, "http", method, route.path, route_class, name)
                )
        elif isinstance(route, APIWebSocketRoute):
            routes.append(
                Route(order, "websocket", "GET", route.path, "websocket", name)
            )
        else:
            raise PolicyError(
                f"route type {type(route).__name__} at {getattr(route, 'path', '?')} "
                "is not represented by the gateway policy"
            )
    return routes


# ── compilation ──────────────────────────────────────────────────────────────


def path_regex(path: str) -> str:
    """Starlette's matcher for ``path`` ({param} = one segment), anchored."""
    for match in re.finditer(r"\{([^}]*)\}", path):
        if ":" in match.group(1):
            raise PolicyError(f"{path}: path converters are not supported")
    parts, last = [], 0
    for match in _PARAM.finditer(path):
        parts.append(re.escape(path[last : match.start()]))
        parts.append("[^/]+")
        last = match.end()
    parts.append(re.escape(path[last:]))
    return "".join(parts)


def _is_template(path: str) -> bool:
    return bool(_PARAM.search(path))


def compile_policy(routes: Iterable[Route]) -> dict:
    routes = list(routes)
    seen: dict[str, Route] = {}
    entries, shadowed = [], []
    for index, route in enumerate(routes):
        if route.route_class not in ROUTE_CLASSES:
            raise PolicyError(f"{route.key}: unknown route class {route.route_class!r}")
        if route.method == "OPTIONS":
            raise PolicyError(
                f"{route.key}: an OPTIONS route would be shadowed by the OPTIONS rule"
            )
        if route.key in seen:
            first = seen[route.key]
            if first.route_class != route.route_class:
                raise PolicyError(
                    f"{route.key}: declared twice with different classes "
                    f"({first.route_class} at {first.order}, {route.route_class} at {route.order})"
                )
            shadowed.append(
                {"key": route.key, "by_order": first.order, "reason": "duplicate"}
            )
            continue
        seen[route.key] = route
        regex = f"^{re.escape(route.scope)}:{route.method}:{path_regex(route.path)}$"
        match = "regex"
        if not _is_template(route.path):
            # An exact key wins over every regex in an nginx map, so it may only
            # be exact if no earlier same-scope, same-method route matches it.
            earlier = [
                r
                for r in routes[:index]
                if (r.scope, r.method) == (route.scope, route.method)
                and _is_template(r.path)
                and re.fullmatch(path_regex(r.path), route.path)
            ]
            if earlier:
                first = earlier[0]
                if first.route_class != route.route_class:
                    raise PolicyError(
                        f"{route.key} is shadowed by {first.key} (order {first.order}) with a "
                        f"different class; Starlette would never reach it"
                    )
                shadowed.append(
                    {"key": route.key, "by_order": first.order, "reason": "template"}
                )
            else:
                match = "exact"
        key = route.key if match == "exact" else "~" + regex
        if not _NGINX_SAFE.match(key):
            raise PolicyError(f"{route.key}: key {key!r} is not safe in an nginx map")
        entries.append(
            {
                "order": route.order,
                "scope": route.scope,
                "method": route.method,
                "path": route.path,
                "match": match,
                "map_key": key,
                "class": route.route_class,
                "checker_policy": CHECKER_POLICY[route.route_class],
                "endpoint": route.endpoint,
            }
        )

    counts = {c: sum(1 for e in entries if e["class"] == c) for c in ROUTE_CLASSES}
    counts["total"] = len(entries)
    inventory = [
        [e["order"], e["scope"], e["method"], e["path"], e["class"], e["endpoint"]]
        for e in entries
    ]
    digest = hashlib.sha256(
        json.dumps(inventory, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema": SCHEMA,
        "generator": GENERATOR,
        "source": "the live application's route table (main.app.routes), in route order",
        "decisions": {
            "X2": "X2-a: no WWW-Authenticate is added",
            "X6": "X6-a: unrouted requests are forwarded unauthenticated; the application answers 404/405/307",
            "ir": "/api/ir/* has no route and is therefore unrouted (404) throughout Phase 10",
            "delete_report": "DELETE /reports/{scan_id} stays ticket_or_bearer, as characterised",
        },
        "key_format": "<scope>:<METHOD>:<application path>  (scope: http | websocket; path without /api)",
        "class_to_checker_policy": dict(CHECKER_POLICY),
        "rules": [
            {
                "match": "~^http:OPTIONS:",
                "class": "options",
                "checker_policy": "none",
                "note": "every OPTIONS request, before any route",
            },
        ],
        "default": {"class": "unrouted", "checker_policy": "none"},
        "counts": counts,
        "inventory_sha256": digest,
        "routes": entries,
        "shadowed": shadowed,
    }


# ── evaluation (nginx map semantics) ─────────────────────────────────────────


def evaluate(policy: dict, scope: str, method: str, path: str) -> str:
    """The class nginx's map would give: rules, exact keys, regexes in order, default."""
    key = f"{scope}:{method}:{path}"
    for rule in policy["rules"]:
        if re.search(rule["match"][1:], key):
            return rule["class"]
    exact = {
        e["map_key"]: e["class"] for e in policy["routes"] if e["match"] == "exact"
    }
    if key in exact:
        return exact[key]
    for entry in policy["routes"]:
        if entry["match"] == "regex" and re.search(entry["map_key"][1:], key):
            return entry["class"]
    return policy["default"]["class"]


# ── rendering ────────────────────────────────────────────────────────────────


def render_json(policy: dict) -> str:
    return json.dumps(policy, indent=1, ensure_ascii=True) + "\n"


def render_map(policy: dict) -> str:
    """The nginx fragment: two maps, generated, deterministic."""
    width = max(len(e["map_key"]) for e in policy["routes"]) + 1
    lines = [
        "# GENERATED by Backend/scripts/gateway/route_policy.py - do not edit.",
        f"# schema {policy['schema']}  inventory sha256 {policy['inventory_sha256']}",
        "# Key: $ccure_scope:$request_method:$ccure_app_path (defined by the gateway configuration).",
        "# X6-a: anything unmatched is 'unrouted' and reaches the application unauthenticated.",
        "",
        'map "$ccure_scope:$request_method:$ccure_app_path" $ccure_route_class {',
        f"    {'default':<{width}} unrouted;",
    ]
    for rule in policy["rules"]:
        lines.append(f"    {rule['match']:<{width}} {rule['class']};")
    for entry in policy["routes"]:
        lines.append(
            f"    {entry['map_key']:<{width}} {entry['class']};  # {entry['order']}"
        )
    lines.append("}")
    lines.append("")
    lines.append("map $ccure_route_class $ccure_policy {")
    lines.append(f"    {'default':<18} none;")
    for route_class in (
        "public",
        "bearer",
        "ticket_or_bearer",
        "websocket",
        "options",
        "unrouted",
    ):
        lines.append(f"    {route_class:<18} {CHECKER_POLICY[route_class]};")
    lines.append("}")
    return "\n".join(lines) + "\n"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def output_paths(root: Optional[Path] = None) -> dict[str, Path]:
    base = (root or repo_root()) / "gateway" / "policy"
    return {"json": base / "route_policy.json", "map": base / "route_policy.map"}


def generate(app=None) -> dict[str, str]:
    if app is None:
        from main import app  # noqa: PLC0415 — the live application
    policy = compile_policy(live_inventory(app))
    return {"json": render_json(policy), "map": render_map(policy)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--check", action="store_true", help="exit 1 if the committed files are stale"
    )
    group.add_argument("--write", action="store_true", help="write gateway/policy/*")
    group.add_argument(
        "--emit", choices=("json", "map"), help="print one file to stdout"
    )
    args = parser.parse_args(argv)

    import logging

    logging.disable(logging.CRITICAL)
    rendered = generate()
    if args.emit:
        sys.stdout.write(rendered[args.emit])
        return 0
    paths = output_paths()
    if args.write:
        for kind, path in paths.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered[kind], encoding="utf-8")
        return 0
    stale = [
        str(p)
        for kind, p in paths.items()
        if not p.is_file() or p.read_text(encoding="utf-8") != rendered[kind]
    ]
    if stale:
        print(
            "gateway route policy is stale; regenerate with "
            "`python -m scripts.gateway.route_policy --write`:\n  "
            + "\n  ".join(stale),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

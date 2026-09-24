#!/usr/bin/env python3
"""Dump every route the API actually serves, with the permission it demands.

Runs **inside the API container**, because it imports the application:

    docker cp scripts/audit/api_surface_inventory.py ccure-api:/tmp/i.py
    docker exec -w /app ccure-api python /tmp/i.py > /tmp/routes.json

`/openapi.json` is not an option here: this deployment serves it 404, and even
where it is enabled it says nothing about which permission atom a route
demands — which is half of what a coverage matrix is for.

Three things this reads that a naive `app.routes` walk does not:

* **The permission atom, from the closure.** ``require_permission(resource,
  action)`` returns a nested ``_guard``; the two strings live in its closure
  cells, reachable through ``__code__.co_freevars``. Reading the dependency's
  ``__name__`` alone gives ``_guard`` for every guarded route in the product,
  which is the same as not measuring it.

* **Every dependency, transitively.** A route's auth can arrive through a
  router-level dependency or through another dependency, not only through its
  own signature.

* **Whether a route is authenticated at all**, which is a different question
  from which permission it holds — the ticket-or-bearer dependency the report
  downloads use authenticates without naming an atom, and CLAUDE.md records an
  earlier audit that reported four such routes as unauthenticated.
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, "/app")

from main import app  # noqa: E402

#: Dependency callables that establish an identity without naming an atom.
AUTH_MARKERS = {
    "get_current_user",
    "get_current_active_user",
    "get_current_user_flexible",
    "require_permission",
    "_guard",
    "require_role",
    "_role_guard",
}


def _closure(fn, *names):
    """The named free variables of a closure, or None where absent."""
    code = getattr(fn, "__code__", None)
    cells = getattr(fn, "__closure__", None)
    if code is None or cells is None:
        return {}
    free = dict(zip(code.co_freevars, cells))
    out = {}
    for name in names:
        cell = free.get(name)
        if cell is None:
            continue
        try:
            out[name] = cell.cell_contents
        except ValueError:  # pragma: no cover - empty cell
            continue
    return out


def walk(dependant, seen=None):
    """Every dependency callable reachable from a route, transitively."""
    seen = seen if seen is not None else set()
    if dependant is None or id(dependant) in seen:
        return []
    seen.add(id(dependant))
    found = []
    call = getattr(dependant, "call", None)
    if call is not None:
        found.append(call)
    for sub in getattr(dependant, "dependencies", []) or []:
        found.extend(walk(sub, seen))
    return found


def describe(route):
    deps = walk(getattr(route, "dependant", None))
    names = {getattr(d, "__name__", "") for d in deps}

    perms, roles = [], []
    for dep in deps:
        name = getattr(dep, "__name__", "")
        if name == "_guard":
            got = _closure(dep, "resource", "action")
            if "resource" in got and "action" in got:
                perms.append(f"{got['resource']}:{got['action']}")
        # `require_role`'s inner function is also called `_guard` and closes
        # over `allowed_set`, a lower-cased set built in the outer scope — so
        # the two guards are told apart by which free variables they carry,
        # never by the name.
        got = _closure(dep, "allowed_set")
        if "allowed_set" in got:
            roles.extend(sorted(str(v) for v in got["allowed_set"]))

    return {
        "path": route.path,
        "methods": sorted(m for m in (route.methods or set()) if m != "HEAD"),
        "name": getattr(route, "name", ""),
        "tags": list(getattr(route, "tags", []) or []),
        "permissions": sorted(set(perms)),
        "roles": sorted(set(roles)),
        "authenticated": bool(names & AUTH_MARKERS),
    }


def main() -> int:
    rows = [
        describe(r)
        for r in app.routes
        if hasattr(r, "methods") and getattr(r, "path", "").startswith("/")
    ]
    rows = [r for r in rows if r["methods"]]
    rows.sort(key=lambda r: (r["path"], r["methods"]))
    json.dump(rows, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

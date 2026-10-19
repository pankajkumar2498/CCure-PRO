"""
The interfaces a refactoring step must leave unchanged, as one JSON document.

    python -m scripts.architecture.interface_snapshot > before.json     # from Backend/
    ...make the change...
    python -m scripts.architecture.interface_snapshot > after.json
    python -m scripts.architecture.interface_snapshot --compare before.json after.json

The working rules for Phase B (docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md
§10) require the OpenAPI document, the route table, the limiter keys, Celery's
registered tasks and the beat schedule to be compared before and after every
step. This records all of them from the application itself:

* every route: its methods, its path and the module and name of the function
  serving it;
* every rate limit slowapi registered, keyed by route function (that key is what
  a limit is enforced under, so a renamed or moved handler shows up here);
* whether each router, ``main`` and ``scan_helpers`` hold the one limiter
  ``main`` registers (``core.rate_limiter.limiter``);
* the name of every Celery task once the worker's task modules are loaded;
* the beat schedule: each entry's task and schedule;
* a SHA-256 of the OpenAPI document the application generates.

It imports ``main`` and the Celery app and connects to nothing: no database, no
Redis, no network. Run it with ``SKIP_DOTENV_LOAD=1`` (it sets that itself when
unset) so ``Backend/.env`` is not read and two machines produce the same output.
The document is sorted and carries no timestamp, so two runs over the same code
are byte-identical and ``--compare`` can name what moved. It changes nothing.

``--compare`` exits 0 when the two snapshots agree and 1 when they differ, with
one line per difference.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]


def snapshot() -> dict:
    """Load the application and return its interfaces as plain, sorted data."""
    os.environ.setdefault("SKIP_DOTENV_LOAD", "1")
    if str(BACKEND_ROOT) not in sys.path:
        sys.path.insert(0, str(BACKEND_ROOT))

    import main  # noqa: F401  (mounts every router)
    import scan_helpers
    from core.celery_app import celery_app
    from core.rate_limiter import limiter as canonical

    app = main.app
    routes = sorted(
        [
            sorted(getattr(route, "methods", None) or []),
            route.path,
            f"{route.endpoint.__module__}.{route.endpoint.__name__}",
        ]
        for route in app.routes
        if hasattr(route, "endpoint")
    )
    route_limits = {
        key: sorted(str(limit.limit) for limit in limits)
        for key, limits in sorted(canonical._route_limits.items())
    }
    holders = {}
    for name, module in sorted(sys.modules.items()):
        if module is None or not (
            name.startswith("routers.") or name in ("main", "scan_helpers")
        ):
            continue
        held = getattr(module, "limiter", None)
        if held is not None:
            holders[name] = held is canonical

    # The worker loads these before it accepts a task; without them the
    # registry holds only what main happened to import.
    celery_app.loader.import_default_modules()
    tasks = sorted(name for name in celery_app.tasks if not name.startswith("celery."))
    beat = {
        name: {"task": entry["task"], "schedule": str(entry["schedule"])}
        for name, entry in sorted(celery_app.conf.beat_schedule.items())
    }
    openapi = json.dumps(app.openapi(), sort_keys=True, separators=(",", ":"))

    return {
        "routes": routes,
        "route_count": len(routes),
        "route_limits": route_limits,
        "route_limit_count": len(route_limits),
        "app_state_limiter_is_canonical": app.state.limiter is canonical,
        "scan_helpers_limiter_is_canonical": scan_helpers.limiter is canonical,
        "limiter_holders_are_canonical": holders,
        "celery_tasks": tasks,
        "celery_task_count": len(tasks),
        "beat": beat,
        "openapi_sha256": hashlib.sha256(openapi.encode("utf-8")).hexdigest(),
    }


def _as_set(items: list) -> set[str]:
    return {json.dumps(item, sort_keys=True) for item in items}


def compare(before: dict, after: dict) -> list[str]:
    """One line per difference between two snapshots; empty when they agree."""
    problems: list[str] = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if isinstance(old, list) and isinstance(new, list):
            for gone in sorted(_as_set(old) - _as_set(new)):
                problems.append(f"{key}: removed {gone}")
            for added in sorted(_as_set(new) - _as_set(old)):
                problems.append(f"{key}: added {added}")
        elif isinstance(old, dict) and isinstance(new, dict):
            for item in sorted(set(old) | set(new)):
                if old.get(item) != new.get(item):
                    problems.append(
                        f"{key}[{item}]: {json.dumps(old.get(item))} -> "
                        f"{json.dumps(new.get(item))}"
                    )
        else:
            problems.append(f"{key}: {json.dumps(old)} -> {json.dumps(new)}")
    return problems


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("BEFORE", "AFTER"),
        help="compare two saved snapshots instead of taking one",
    )
    args = parser.parse_args(argv)

    if args.compare:
        before, after = (
            json.loads(Path(path).read_text(encoding="utf-8")) for path in args.compare
        )
        problems = compare(before, after)
        for line in problems:
            print(line)
        print(
            "interfaces identical" if not problems else f"{len(problems)} difference(s)"
        )
        return 1 if problems else 0

    print(json.dumps(snapshot(), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(cli())

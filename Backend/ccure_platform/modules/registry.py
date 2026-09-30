"""
The CCure module registry (Phase 11).

The core service hosts three modules — Policy Pro, Audit and Rank — beside the
shared platform (``docs/architecture/CCURE_PLATFORM_MODULAR_ARCHITECTURE.md``
§3.3, §4). This is the one list of them. ``main.py`` mounts what the enabled
modules declare and ``core/celery_app.py`` loads their task modules and queues.

**A leaf, by design.** This package imports the standard library and itself,
nothing else — no FastAPI, no Celery, no module's code. ``core/celery_app.py``
is shared infrastructure (``infrastructure-is-foundation``) and reads it, so a
registry that imported a module would put that module in every importer's
dependency tree. Routers are resolved from dotted strings only by
``mount_module_routers``, which the composition root calls.
``tests/repo/test_module_registry.py`` pins the leaf property.

**A fixed list, not a filesystem scan.** Adding a fourth module is a platform
decision and one entry here; a stray folder or a half-copied branch can never
register itself. Adding a route, table, migration or task *inside* an existing
module is the module's own business (Phase 11.2).

Phase 11.1 state: the three identities exist. Audit is enabled and declares
nothing to mount — ``main.py`` still mounts Audit's routers itself and
``core/celery_app.py`` still lists Audit's task modules, until Phase 16 moves
Audit's code into ``ccure_audit``. Policy Pro and Rank are disabled and empty:
their teams build them later.
"""

from __future__ import annotations

import importlib

from ccure_platform.modules.manifest import ManifestError, ModuleManifest

MODULES: tuple[ModuleManifest, ...] = (
    ModuleManifest(
        key="policy_pro",
        title="Ccure Policy",
        package="ccure_policy",
        db_schema="policy_pro",
        route_prefix="/policy",
        task_prefix="ccure.policy",
        permission_prefixes=("policy",),
        tile_state="not_yet_available",
        enabled=False,
    ),
    ModuleManifest(
        key="audit",
        title="Ccure Audit",
        package="ccure_audit",
        db_schema="public",
        # Audit's URLs predate the registry and are never renamed (plan §10).
        route_prefix="",
        # Audit's existing task names (ccure.tasks.*, compliance.*, …) are
        # strings in the broker and the beat schedule and never change; this is
        # the prefix for any it adds.
        task_prefix="ccure.audit",
        tile_state="available",
        enabled=True,
    ),
    ModuleManifest(
        key="rank",
        title="Ccure Rank",
        package="ccure_rank",
        db_schema="rank",
        route_prefix="/rank",
        task_prefix="ccure.rank",
        permission_prefixes=("rank",),
        tile_state="not_yet_available",
        enabled=False,
    ),
)


def _check(modules: tuple[ModuleManifest, ...]) -> None:
    """Refuse any two modules sharing a key, package, schema, route prefix,
    task prefix, queue or task module."""

    def unique(field: str, values: list[tuple[str, str]]) -> None:
        seen: dict[str, str] = {}
        for key, value in values:
            if value in seen:
                raise ManifestError(
                    f"modules {seen[value]!r} and {key!r} both declare {field} {value!r}"
                )
            seen[value] = key

    unique("key", [(m.key, m.key) for m in modules])
    unique("package", [(m.key, m.package) for m in modules])
    unique("db_schema", [(m.key, m.db_schema) for m in modules])
    unique("route_prefix", [(m.key, m.route_prefix) for m in modules])
    unique("task_prefix", [(m.key, m.task_prefix) for m in modules])
    unique("queue", [(m.key, q) for m in modules for q in m.queues])
    unique("task module", [(m.key, t) for m in modules for t in m.task_modules])
    # A task prefix that is another's prefix would let one module's names
    # shadow the other's (ccure.rank vs ccure.rank.extra).
    prefixes = sorted(m.task_prefix for m in modules)
    for a, b in zip(prefixes, prefixes[1:]):
        if b.startswith(a + "."):
            raise ManifestError(f"task prefix {b!r} nests inside {a!r}")


_check(MODULES)


def modules() -> tuple[ModuleManifest, ...]:
    """Every registered module, enabled or not, in registry order."""
    return MODULES


def enabled_modules() -> tuple[ModuleManifest, ...]:
    return tuple(m for m in MODULES if m.enabled)


def get(key: str) -> ModuleManifest:
    for m in MODULES:
        if m.key == key:
            return m
    raise KeyError(f"no module {key!r} is registered")


def task_modules() -> list[str]:
    """Task modules of the enabled modules, for ``celery_app``'s ``include``."""
    return [t for m in enabled_modules() for t in m.task_modules]


def queues() -> list[str]:
    """Queues the enabled modules declare, for ``celery_app``'s ``task_queues``."""
    return [q for m in enabled_modules() for q in m.queues]


def mount_module_routers(app) -> list[tuple[str, str]]:
    """
    Mount every enabled module's routers on ``app`` under its route prefix, and
    return what was mounted as ``(prefix, "package.module:attribute")`` pairs.

    Called once by the composition root (``main.py``). The import happens here,
    by name, so this package never imports module code at import time.
    """
    mounted: list[tuple[str, str]] = []
    for m in enabled_modules():
        for target in m.routers:
            module_name, _, attr = target.partition(":")
            router = getattr(importlib.import_module(module_name), attr)
            app.include_router(router, prefix=m.route_prefix)
            mounted.append((m.route_prefix, target))
    return mounted

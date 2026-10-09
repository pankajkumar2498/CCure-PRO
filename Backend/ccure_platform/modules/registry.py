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
register itself.

**Two halves, two owners (Phase 11.2).** The platform owns a module's
*identity* — key, package, schema, route and task prefixes, tile, and whether it
is enabled — in ``_IDENTITIES`` below. The module owns what it *contributes* —
its routers, task modules and model metadata — in its own
``<package>/manifest.toml``, read here as data with ``tomllib``. So a team adds
a route, a table or a task by editing files inside its own folder only; turning
the module on for production stays a platform decision.

Current state: Audit is enabled and its manifest declares nothing to mount —
``main.py`` still mounts Audit's routers itself and ``core/celery_app.py`` still
lists Audit's task modules, until Phase 16 moves Audit's code into
``ccure_audit``. Policy Pro and Rank are disabled and declare nothing: their
teams build them later.
"""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

from ccure_platform.modules.manifest import (
    ManifestError,
    ModuleManifest,
    Product,
    ServiceProduct,
)

#: Backend/ — the import root every module package sits in.
BACKEND_ROOT = Path(__file__).resolve().parents[2]

#: What a module's manifest.toml may declare, under ``[module]``.
CONTRIBUTIONS = (
    "routers",
    "task_modules",
    "models",
    "audit_event_modules",
    "permission_modules",
)


def load_contributions(package: str, key: str, root: Path = BACKEND_ROOT) -> dict:
    """
    Read ``<root>/<package>/manifest.toml`` — the module's own declaration of
    what it contributes. Data only: nothing in the module is imported.

    A registered module without the file is refused: every module's
    contributions are explicit, even when there are none.
    """
    path = root / package / "manifest.toml"
    if not path.is_file():
        raise ManifestError(f"module {key!r}: {package}/manifest.toml is missing")
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"module {key!r}: {package}/manifest.toml: {exc}") from exc
    section = data.get("module")
    if not isinstance(section, dict) or set(data) != {"module"}:
        raise ManifestError(
            f"module {key!r}: manifest.toml must hold one [module] table"
        )
    if section.get("key") != key:
        raise ManifestError(
            f"module {key!r}: {package}/manifest.toml declares key {section.get('key')!r}"
        )
    unknown = sorted(set(section) - {"key", *CONTRIBUTIONS})
    if unknown:
        raise ManifestError(
            f"module {key!r}: manifest.toml may declare only {CONTRIBUTIONS}; "
            f"not {unknown} (identity is the platform's, in the registry)"
        )
    out = {}
    for name in CONTRIBUTIONS:
        value = section.get(name, [])
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ManifestError(
                f"module {key!r}: manifest.toml {name} must be a list of strings"
            )
        out[name] = tuple(value)
    return out


def build(identity: dict, root: Path = BACKEND_ROOT) -> ModuleManifest:
    """A module's full manifest: the platform's identity plus the module's own
    contributions."""
    return ModuleManifest(
        **identity, **load_contributions(identity["package"], identity["key"], root)
    )


#: The platform-owned half of each module: who it is, not what it contains.
_IDENTITIES: tuple[dict, ...] = (
    dict(
        key="policy_pro",
        title="CCure Policy Pro",
        description=(
            "Responsible for your organisation's security policies and controls, "
            "and for the baseline — which controls apply, with what parameters — "
            "that the other products assess against."
        ),
        entry_path="/policy-dashboard",
        package="ccure_policy",
        db_schema="policy_pro",
        route_prefix="/policy",
        task_prefix="ccure.policy",
        permission_prefixes=("policy",),
        permission_namespace="policy",
        tile_state="not_yet_available",
        enabled=False,
    ),
    dict(
        key="audit",
        title="CCure Audit",
        description=(
            "Responsible for finding and assessing your assets: network and web "
            "scanning, vulnerability and configuration audits, compliance against "
            "frameworks, remediation tracking and reports."
        ),
        # Audit's dashboard; /dashboard stays a compatibility redirect (12.2).
        entry_path="/audit-dashboard",
        package="ccure_audit",
        db_schema="public",
        # Audit's URLs predate the registry and are never renamed (plan §10).
        route_prefix="",
        # Audit's existing task names (ccure.tasks.*, compliance.*, …) are
        # strings in the broker and the beat schedule and never change; this is
        # the prefix for any it adds.
        task_prefix="ccure.audit",
        permission_namespace="audit",
        tile_state="available",
        enabled=True,
    ),
    dict(
        key="rank",
        title="CCure Rank",
        description=(
            "Responsible for scoring and ranking your organisation's security "
            "posture from the results the other products produce."
        ),
        entry_path="/rank-dashboard",
        package="ccure_rank",
        db_schema="rank",
        route_prefix="/rank",
        task_prefix="ccure.rank",
        permission_prefixes=("rank",),
        permission_namespace="rank",
        tile_state="not_yet_available",
        enabled=False,
    ),
)

MODULES: tuple[ModuleManifest, ...] = tuple(build(identity) for identity in _IDENTITIES)

#: Products CCure Home lists that the core service does not host (Phase 12).
#: CCure IR is a separate service with its own database (Stage 4): it is never a
#: module here, so nothing is mounted, loaded or migrated for it.
_SERVICES: tuple[dict, ...] = (
    dict(
        key="ir",
        title="CCure IR",
        description=(
            "Responsible for incident response: recording and managing security "
            "incidents, and feeding what is learned back to the other products."
        ),
        entry_path="/ir-dashboard",
        tile_state="not_yet_available",
        permission_namespace="ir",
    ),
)

SERVICES: tuple[ServiceProduct, ...] = tuple(ServiceProduct(**s) for s in _SERVICES)


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
    unique(
        "permission namespace",
        [(m.key, m.permission_namespace) for m in modules if m.permission_namespace],
    )
    unique("task module", [(m.key, t) for m in modules for t in m.task_modules])
    # A task prefix that is another's prefix would let one module's names
    # shadow the other's (ccure.rank vs ccure.rank.extra).
    prefixes = sorted(m.task_prefix for m in modules)
    for a, b in zip(prefixes, prefixes[1:]):
        if b.startswith(a + "."):
            raise ManifestError(f"task prefix {b!r} nests inside {a!r}")


_check(MODULES)


def _check_products(
    modules: tuple[ModuleManifest, ...], services: tuple[ServiceProduct, ...]
) -> None:
    """Refuse two products — module or service — sharing a key, a title or an
    entry address: each is one card and one page on CCure Home."""
    for field in ("key", "title", "entry_path"):
        seen: dict[str, str] = {}
        for product in (*modules, *services):
            value = getattr(product, field)
            if value in seen:
                raise ManifestError(
                    f"products {seen[value]!r} and {product.key!r} both declare "
                    f"{field} {value!r}"
                )
            seen[value] = product.key


_check_products(MODULES, SERVICES)


def modules() -> tuple[ModuleManifest, ...]:
    """Every registered module, enabled or not, in registry order."""
    return MODULES


def services() -> tuple[ServiceProduct, ...]:
    """Products outside the core service, in registry order."""
    return SERVICES


def products() -> tuple[Product, ...]:
    """
    Every product CCure Home shows (Phase 12), in order: the core modules in
    registry order, then the separate services — Policy Pro, Audit, Rank, IR.

    Every product is listed whatever its state; a product is never left out
    because it is not built yet (owner decision D12-4).
    """
    return tuple(
        Product(
            key=m.key,
            title=m.title,
            kind="core_module",
            description=m.description,
            entry_path=m.entry_path,
            tile_state=m.tile_state,
        )
        for m in MODULES
    ) + tuple(
        Product(
            key=s.key,
            title=s.title,
            kind="service",
            description=s.description,
            entry_path=s.entry_path,
            tile_state=s.tile_state,
        )
        for s in SERVICES
    )


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


def audit_event_modules() -> list[str]:
    """Audit-event definition modules of the enabled modules, loaded by name by
    the audit log (``ccure_platform/audit_log/taxonomy.py``)."""
    return [t for m in enabled_modules() for t in m.audit_event_modules]


def permission_modules() -> list[str]:
    """Permission-declaration modules of the enabled modules. The composition
    root (``ccure_platform/composition.py``) loads them by name and hands what
    they declare to RBAC as data; RBAC never reads this list."""
    return [t for m in enabled_modules() for t in m.permission_modules]


def permission_namespaces() -> dict[str, str]:
    """``{namespace: owner key}`` for every permission namespace held by a
    module or a service — enabled or not — plus the platform's own. A namespace
    is reserved from the day its product is registered."""
    held = {"platform": "platform"}
    for m in MODULES:
        if m.permission_namespace:
            held[m.permission_namespace] = m.key
    for s in SERVICES:
        if s.permission_namespace:
            held[s.permission_namespace] = s.key
    return held


def queues() -> list[str]:
    """Queues the enabled modules declare, for ``celery_app``'s ``task_queues``."""
    return [q for m in enabled_modules() for q in m.queues]


def resolve(target: str):
    """The object a manifest's ``"package.module:attribute"`` names, imported
    now — never at registry import time."""
    module_name, _, attr = target.partition(":")
    return getattr(importlib.import_module(module_name), attr)


def module_metadatas(manifest: ModuleManifest) -> list:
    """The SQLAlchemy ``MetaData`` objects a module declares in ``models``."""
    return [resolve(target) for target in manifest.models]


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
            app.include_router(resolve(target), prefix=m.route_prefix)
            mounted.append((m.route_prefix, target))
    return mounted

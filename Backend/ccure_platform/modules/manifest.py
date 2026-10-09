"""
What a CCure module declares to the platform (Phase 11).

A manifest is data. It names a module — its key, package, database schema,
route prefix and task-name prefix — and lists what the module contributes: the
routers the application mounts, the Celery task modules and queues workers
load. Everything that could be a *reference to code* is a dotted string, never
an import, so the registry that holds manifests stays a leaf: it is read by
``core/celery_app.py``, which is shared infrastructure and may import no
feature (``layer_rules``: ``infrastructure-is-foundation``).

Validation happens at construction, so a manifest that could collide with
another module or reach outside its own package is refused where it is written,
with the module's name in the error — never discovered as a request answered by
the wrong code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

TILE_STATES = ("available", "not_yet_available")

#: What a product on CCure Home is (Phase 12): a module inside the core service,
#: or a separate service the platform lists but does not host (IR).
PRODUCT_KINDS = ("core_module", "service")

#: A product's description states what it is responsible for, in a sentence or
#: two — never what it can do today (docs/architecture/PHASE12_FRONTEND_SHELL.md §3.1).
DESCRIPTION_MAX = 300

_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
_PACKAGE = re.compile(r"^ccure_[a-z][a-z0-9_]*$")
_SCHEMA = re.compile(r"^[a-z][a-z0-9_]*$")
_PREFIX = re.compile(r"^(/[a-z][a-z0-9-]*)?$")  # "" (Audit's legacy URLs) or "/name"
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_QUEUE = re.compile(r"^[a-z][a-z0-9_.-]*$")
#: The first segment of every permission key a product declares (RBAC-1):
#: ``audit.scan.run`` belongs to the namespace ``audit``. ``platform`` is the
#: platform's own and no product may claim it.
_PERMISSION_NAMESPACE = re.compile(r"^[a-z][a-z0-9_]*$")
RESERVED_PERMISSION_NAMESPACES = ("platform",)
#: A product's entry address on the frontend: one absolute path segment.
_ENTRY_PATH = re.compile(r"^/[a-z][a-z0-9-]*$")


class ManifestError(ValueError):
    """A module manifest that cannot be registered as written."""


def _product_problems(
    title: str, description: str, entry_path: str, tile_state: str
) -> list[str]:
    """What CCure Home shows for a product, checked the same way for a core
    module and for a separate service."""
    problems = []
    if not title.strip():
        problems.append("title is empty")
    if not description.strip():
        problems.append("description is empty")
    elif len(description) > DESCRIPTION_MAX:
        problems.append(f"description is longer than {DESCRIPTION_MAX} characters")
    if not _ENTRY_PATH.match(entry_path):
        problems.append(
            f"entry_path {entry_path!r} must be one absolute path segment, '/<name>'"
        )
    if tile_state not in TILE_STATES:
        problems.append(f"tile_state {tile_state!r} is not one of {TILE_STATES}")
    return problems


@dataclass(frozen=True, slots=True, kw_only=True)
class ModuleManifest:
    #: Stable identifier: ``policy_pro``, ``audit``, ``rank``.
    key: str
    #: The name a person sees on CCure Home (Phase 12).
    title: str
    #: What the product is responsible for, shown on its CCure Home card.
    description: str
    #: The frontend address its CCure Home card opens (Phase 12).
    entry_path: str
    #: The top-level Python package holding the module: ``ccure_<name>``.
    package: str
    #: The PostgreSQL schema the module's tables live in.
    db_schema: str
    #: Where the module's routers are mounted. Audit's is "" — its URLs predate
    #: the registry and are never renamed (plan §10). A new module gets its own.
    route_prefix: str
    #: Every Celery task the module defines is named ``<task_prefix>.<name>``, so
    #: two modules' tasks can never share a broker name.
    task_prefix: str
    #: Permission-atom resources the module owns (``policy``, ``rank``; Audit's
    #: existing ones). Declarative in Phase 11; seeding stays where it is.
    permission_prefixes: tuple[str, ...] = ()
    #: ``"package.module:attribute"`` of each APIRouter the application mounts.
    routers: tuple[str, ...] = ()
    #: Dotted names of the modules defining this module's Celery tasks.
    task_modules: tuple[str, ...] = ()
    #: Dotted names of the modules that register this module's audit-event
    #: definitions (severities). Loaded by the platform by name, in whichever
    #: process writes an audit event — the API, a Celery worker, a script — so a
    #: module's events are classified wherever they are emitted.
    audit_event_modules: tuple[str, ...] = ()
    #: The first segment of every permission key the module declares
    #: (``audit`` → ``audit.scan.run``). Platform-owned, like the rest of the
    #: identity: a module cannot choose another module's namespace. Empty only
    #: for a module that declares no permissions.
    permission_namespace: str = ""
    #: Dotted names of the modules that declare this module's permission
    #: catalogue (RBAC-1). Each exports ``PERMISSIONS``, a tuple of
    #: ``ccure_platform.api.PermissionDecl``. Loaded by name by the composition
    #: root (``ccure_platform/composition.py``), never imported by the RBAC
    #: engine, which learns them as data.
    permission_modules: tuple[str, ...] = ()
    #: Celery queues this module declares (none until a module needs isolation).
    queues: tuple[str, ...] = ()
    #: ``"package.module:attribute"`` of each SQLAlchemy ``MetaData`` holding the
    #: module's tables. Every table in it must live in ``db_schema`` and be
    #: registered to the module in ``table_ownership.yaml`` (Phase 11.2).
    models: tuple[str, ...] = ()
    #: Availability on CCure Home (Phase 12). A product that is not available
    #: still has a card and an entry page, and the page says it is not
    #: available yet — never an empty page (CLAUDE.md, UI semantic integrity).
    tile_state: str = "not_yet_available"
    #: Whether the application mounts the routers and workers load the tasks.
    enabled: bool = False

    def __post_init__(self) -> None:
        def refuse(message: str) -> None:
            raise ManifestError(f"module {self.key!r}: {message}")

        if not _KEY.match(self.key):
            refuse("key must be lower-case letters, digits and underscores")
        for problem in _product_problems(
            self.title, self.description, self.entry_path, self.tile_state
        ):
            refuse(problem)
        if not _PACKAGE.match(self.package):
            refuse(f"package {self.package!r} must be a top-level ccure_<name> package")
        if not _SCHEMA.match(self.db_schema):
            refuse(f"db_schema {self.db_schema!r} is not a plain schema name")
        if not _PREFIX.match(self.route_prefix):
            refuse(f"route_prefix {self.route_prefix!r} must be '' or '/<name>'")
        if not _DOTTED.match(self.task_prefix) or not self.task_prefix.startswith(
            "ccure."
        ):
            refuse(
                f"task_prefix {self.task_prefix!r} must be a dotted name starting 'ccure.'"
            )
        for kind, targets in (("router", self.routers), ("models", self.models)):
            for target in targets:
                module, sep, attr = target.partition(":")
                if not sep or not _DOTTED.match(module) or not attr.isidentifier():
                    refuse(f"{kind} {target!r} must be 'package.module:attribute'")
                if not self._inside(module):
                    refuse(
                        f"{kind} {target!r} is outside the module's package {self.package!r}"
                    )
        for module in self.task_modules:
            if not _DOTTED.match(module):
                refuse(f"task module {module!r} is not a dotted module name")
            if not self._inside(module):
                refuse(
                    f"task module {module!r} is outside the module's package {self.package!r}"
                )
        for module in self.audit_event_modules:
            if not _DOTTED.match(module):
                refuse(f"audit-event module {module!r} is not a dotted module name")
            if not self._inside(module):
                refuse(
                    f"audit-event module {module!r} is outside the module's package {self.package!r}"
                )
        for module in self.permission_modules:
            if not _DOTTED.match(module):
                refuse(f"permission module {module!r} is not a dotted module name")
            if not self._inside(module):
                refuse(
                    f"permission module {module!r} is outside the module's package {self.package!r}"
                )
        if self.permission_namespace:
            if not _PERMISSION_NAMESPACE.match(self.permission_namespace):
                refuse(
                    f"permission_namespace {self.permission_namespace!r} must be "
                    "lower-case letters, digits and underscores"
                )
            if self.permission_namespace in RESERVED_PERMISSION_NAMESPACES:
                refuse(
                    f"permission_namespace {self.permission_namespace!r} is the platform's"
                )
        elif self.permission_modules:
            refuse("permission_modules need a permission_namespace")
        for queue in self.queues:
            if not _QUEUE.match(queue):
                refuse(f"queue {queue!r} is not a valid queue name")
        if self.routers and not self.route_prefix and self.key != "audit":
            refuse(
                "a module other than Audit must mount its routers under its own route_prefix"
            )

    def _inside(self, dotted: str) -> bool:
        return dotted == self.package or dotted.startswith(self.package + ".")


@dataclass(frozen=True, slots=True, kw_only=True)
class ServiceProduct:
    """
    A product CCure Home lists that the core service does not host (Phase 12):
    CCure IR, a separate service (Stage 4). No package, schema, routes or tasks —
    nothing is mounted from it; the platform only says what it is and where its
    card goes.
    """

    key: str
    title: str
    description: str
    entry_path: str
    tile_state: str = "not_yet_available"
    #: The permission namespace reserved for the service (``ir`` → ``ir.*``).
    #: It declares no permissions inside the core service; the namespace is held
    #: so no module can claim it.
    permission_namespace: str = ""

    def __post_init__(self) -> None:
        if not _KEY.match(self.key):
            raise ManifestError(
                f"service {self.key!r}: key must be lower-case letters, digits and underscores"
            )
        if self.permission_namespace and not _PERMISSION_NAMESPACE.match(
            self.permission_namespace
        ):
            raise ManifestError(
                f"service {self.key!r}: permission_namespace "
                f"{self.permission_namespace!r} is not a plain namespace"
            )
        for problem in _product_problems(
            self.title, self.description, self.entry_path, self.tile_state
        ):
            raise ManifestError(f"service {self.key!r}: {problem}")


@dataclass(frozen=True, slots=True, kw_only=True)
class Product:
    """One card on CCure Home: a core module or a separate service, as the
    platform describes it. Plain values only."""

    key: str
    title: str
    kind: str
    description: str
    entry_path: str
    tile_state: str

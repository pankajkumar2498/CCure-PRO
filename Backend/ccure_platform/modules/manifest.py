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

_KEY = re.compile(r"^[a-z][a-z0-9_]*$")
_PACKAGE = re.compile(r"^ccure_[a-z][a-z0-9_]*$")
_SCHEMA = re.compile(r"^[a-z][a-z0-9_]*$")
_PREFIX = re.compile(r"^(/[a-z][a-z0-9-]*)?$")  # "" (Audit's legacy URLs) or "/name"
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_QUEUE = re.compile(r"^[a-z][a-z0-9_.-]*$")


class ManifestError(ValueError):
    """A module manifest that cannot be registered as written."""


@dataclass(frozen=True, slots=True, kw_only=True)
class ModuleManifest:
    #: Stable identifier: ``policy_pro``, ``audit``, ``rank``.
    key: str
    #: The name a person sees (the homepage tile, Phase 12).
    title: str
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
    #: Celery queues this module declares (none until a module needs isolation).
    queues: tuple[str, ...] = ()
    #: Homepage tile state (Phase 12). A module that is not ready says so and is
    #: never a link to an empty page (CLAUDE.md, UI semantic integrity).
    tile_state: str = "not_yet_available"
    #: Whether the application mounts the routers and workers load the tasks.
    enabled: bool = False

    def __post_init__(self) -> None:
        def refuse(message: str) -> None:
            raise ManifestError(f"module {self.key!r}: {message}")

        if not _KEY.match(self.key):
            refuse("key must be lower-case letters, digits and underscores")
        if not self.title.strip():
            refuse("title is empty")
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
        if self.tile_state not in TILE_STATES:
            refuse(f"tile_state {self.tile_state!r} is not one of {TILE_STATES}")
        for target in self.routers:
            module, sep, attr = target.partition(":")
            if not sep or not _DOTTED.match(module) or not attr.isidentifier():
                refuse(f"router {target!r} must be 'package.module:attribute'")
            if not self._inside(module):
                refuse(
                    f"router {target!r} is outside the module's package {self.package!r}"
                )
        for module in self.task_modules:
            if not _DOTTED.match(module):
                refuse(f"task module {module!r} is not a dotted module name")
            if not self._inside(module):
                refuse(
                    f"task module {module!r} is outside the module's package {self.package!r}"
                )
        for queue in self.queues:
            if not _QUEUE.match(queue):
                refuse(f"queue {queue!r} is not a valid queue name")
        if self.routers and not self.route_prefix and self.key != "audit":
            refuse(
                "a module other than Audit must mount its routers under its own route_prefix"
            )

    def _inside(self, dotted: str) -> bool:
        return dotted == self.package or dotted.startswith(self.package + ".")

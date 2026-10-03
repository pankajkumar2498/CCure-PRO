"""
ccure_platform/composition.py — where the platform's pieces are wired together.

RBAC is module-agnostic: it validates and applies permission declarations but
does not know which modules exist or where they live. Something has to read the
module registry, load each module's declaration module **by name**, and hand RBAC
the result as data. That is this file, and it is the only place the two meet.

    module manifest.toml (permission_modules) ─┐
    module registry (namespace, enabled)       ├→ composition → rbac.catalogue.sync
    the platform's own declaration modules ────┘

* A module's identity — including the **permission namespace** it owns — is the
  platform's, in the registry. A declaration module cannot choose its namespace;
  RBAC then refuses any key outside it.
* Only **enabled** modules are loaded, like routers and tasks.
* A declaration module that cannot be imported, exports no ``PERMISSIONS``, or
  exports something that is not a ``PermissionDecl`` raises ``CatalogueError``
  naming the module. There is no fallback to the modules that loaded fine: a
  partly loaded catalogue is a partly granted one.

RBAC-1 is dark: nothing calls ``sync_permission_catalogue`` at start-up. It is
exercised by tests and will be called by the application in RBAC-2, when the
catalogue is finalised.
"""

from __future__ import annotations

import importlib

from ccure_platform.modules import registry
from ccure_platform.rbac import contract as c
from ccure_platform.rbac.catalogue import CatalogueError, SyncReport, sync
from sqlalchemy.orm import Session

#: Dotted names of the modules that declare the **platform's own** permissions
#: (``platform.*``). None until RBAC-2 finalises the catalogue.
PLATFORM_PERMISSION_MODULES: tuple[str, ...] = ()

PLATFORM_NAMESPACE = "platform"


def _load_declarations(dotted: str, label: str) -> tuple[c.PermissionDecl, ...]:
    try:
        module = importlib.import_module(dotted)
    except Exception as exc:  # noqa: BLE001 - re-raised, typed, naming the module
        raise CatalogueError(
            [f"{label}: permission module {dotted!r} cannot be loaded: {exc!r}"]
        ) from exc
    declared = getattr(module, "PERMISSIONS", None)
    if declared is None:
        raise CatalogueError([f"{label}: {dotted!r} exports no PERMISSIONS"])
    if not isinstance(declared, (tuple, list)):
        raise CatalogueError(
            [f"{label}: {dotted!r}.PERMISSIONS must be a tuple of PermissionDecl"]
        )
    bad = [d for d in declared if not isinstance(d, c.PermissionDecl)]
    if bad:
        raise CatalogueError(
            [f"{label}: {dotted!r}.PERMISSIONS holds {bad[0]!r}, not a PermissionDecl"]
        )
    return tuple(declared)


def load_permission_sources() -> list[c.ModuleDeclarations]:
    """The permission declarations of the platform and every enabled module, as
    data. Raises ``CatalogueError`` if any declaration module fails."""
    sources: list[c.ModuleDeclarations] = []
    platform_decls: list[c.PermissionDecl] = []
    for dotted in PLATFORM_PERMISSION_MODULES:
        platform_decls.extend(_load_declarations(dotted, "platform"))
    if platform_decls:
        sources.append(
            c.ModuleDeclarations(
                module_key=PLATFORM_NAMESPACE,
                namespace=PLATFORM_NAMESPACE,
                permissions=tuple(platform_decls),
            )
        )
    for module in registry.enabled_modules():
        decls: list[c.PermissionDecl] = []
        for dotted in module.permission_modules:
            decls.extend(_load_declarations(dotted, f"module {module.key!r}"))
        if decls:
            sources.append(
                c.ModuleDeclarations(
                    module_key=module.key,
                    namespace=module.permission_namespace,
                    permissions=tuple(decls),
                )
            )
    return sources


def sync_permission_catalogue(
    db: Session, *, actor_id: str | None = None, audit_org_id: str | None = None
) -> SyncReport:
    """Load every declaration and apply it. Writes in ``db``'s transaction and
    does not commit."""
    return sync(
        db, load_permission_sources(), actor_id=actor_id, audit_org_id=audit_org_id
    )

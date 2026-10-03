"""
How module code reaches identity, measured from source — Phase 8 of the
modular-platform programme.

Sign-in, users, organisations and roles belong to the platform
(``ccure_platform``), and Phase 8's goal is that modules reach them through
``ccure_platform.api`` and nothing else. This file measures how far the code is
from that and holds the baseline. ``tests/repo/test_identity_boundary.py`` turns
the baseline into a ratchet that fails in both directions, like
``KNOWN_VIOLATIONS`` in ``layer_rules.py``:

* a new identity import, or a new query of an identity table, fails CI;
* a recorded one that no longer exists also fails, with the instruction to
  delete it — so the baseline can only shrink.

**Why this is not a layer rule.** ``layer_rules.py`` works on module edges, and
``from db.models import User`` resolves to the edge ``… -> db.models`` — the
package every module legitimately imports its own models through. An edge
cannot tell ``User`` from ``Scan``, so identity is measured here by *symbol*.

Two measurements:

* **Identity imports** — a symbol imported from ``auth``, an identity model
  imported from ``db.models`` / ``db.models.users`` / ``db.models.rbac``, or
  anything imported from ``ccure_platform`` other than ``ccure_platform.api``.
  Imports inside functions count, as they do in the import graph.
* **Identity queries** — ``.query(M…)``, ``select(M…)``, ``.get(M, …)``,
  ``delete(M)`` and ``update(M)`` where an argument is rooted at an identity
  model; and, recorded separately, ``.join(M…)`` / ``.outerjoin(M…)`` and eager
  loads (``joinedload(M.attr)`` …) rooted at one.

What it cannot see: navigation through a relationship an Audit model declares
towards identity (``joinedload(Scan.created_by_user)``, ``scan.organization``).
Those are rooted at an Audit model; removing them is a model change, reviewed
in steps 8.3 and 8.4, not something a static count can hold.

    python -m scripts.architecture.identity_boundary          # counts
    python -m scripts.architecture.identity_boundary --list   # every site
    python -m scripts.architecture.identity_boundary --baseline

Run from ``Backend/``. Nothing is imported; every module is parsed with ``ast``.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from scripts.architecture.import_graph import BACKEND_ROOT, discover_modules

#: The identity models. ``AuditLog`` and ``Notification`` are platform-owned
#: too, but they are cross-cutting services every module writes to, not
#: identity, and Phase 8 does not move them.
IDENTITY_MODELS = frozenset(
    {
        "User",
        "RefreshTokenSession",
        "PasswordResetToken",
        "EmailVerificationToken",
        "Organization",
        "Role",
        "Permission",
        "RolePermission",
        # the RBAC capability's tables (RBAC-1): private to ccure_platform, so a
        # module importing one is an identity import and the ratchet counts it
        "RbacPermission",
        "RbacRole",
        "RbacRoleRevision",
        "RbacRolePermission",
        "RbacUserRole",
        "RbacDefaultRole",
        "RbacLegacyMap",
    }
)

#: Modules an identity model can be imported from: the registry, the legacy
#: paths, and (since Phase 8.2) where the models now live.
IDENTITY_MODEL_SOURCES = (
    "db.models",
    "db.models.users",
    "db.models.rbac",
    "ccure_platform.models",
    "ccure_platform.models.users",
    "ccure_platform.models.rbac",
)

#: The legacy path of identity's code (aliases since Phase 8.2): any import from
#: here is an identity import. Imports of ``ccure_platform`` internals are too.
IDENTITY_PACKAGES = ("auth",)

#: The one way into the platform once Phase 8 is complete.
PLATFORM_PACKAGE = "ccure_platform"
PLATFORM_API = "ccure_platform.api"

#: Names ``ccure_platform.api`` exports that *are* an identity model. Importing
#: one is not an identity import (it goes through the API), but querying
#: through one is still a direct identity query and is counted as one.
API_MODEL_ALIASES = {"CurrentUser": "User"}

#: Everything ``ccure_platform.api`` may ever export. It holds shared identity,
#: tenancy and RBAC primitives only — never Audit's quotas, scan scope or any
#: other module's business logic. A name added here needs a reason in review.
PLATFORM_API_SURFACE = frozenset(
    {
        # planned in the Phase 8 proposal
        "current_user",
        "current_user_flexible",
        "require_permission",
        "require_role",
        # RBAC-4: permission-key guards that replaced role-name checks
        "require_authorized",
        "has_permission",
        "user_display_names",
        "users_holding_permission",
        "organisation",
        "OrganisationView",
        "is_organisation_active",
        # added in step 8.3, each for callers whose semantics the planned
        # names did not cover (PHASE8_PLATFORM_IDENTITY.md §10)
        "user_has_permission",
        "user",
        "UserView",
        "active_members_with_roles",
        # step 8.5: the type routes annotate the authenticated principal with
        "CurrentUser",
        # step 8.4: the organisation plan, one removable feature per group
        "ScanLimits",
        "ScanLimitsView",
        "scan_limits",
        "ScanScopeView",
        "scan_scope",
        "RemediationSlaSettingView",
        "remediation_sla_setting",
        "store_remediation_sla_setting",
        # in-app notifications — every module raises them through the platform
        "NotificationCategory",
        "NotificationType",
        "create_notification",
        "fan_out_notification",
        "register_notification_categories",
        # the platform's audit log — every module records events through it
        "log_audit_event",
        # a module registers the severities of its own audit events
        "register_event_severities",
        # a product registers the schema of its own user-preference block
        "register_product_preferences",
        # the RBAC capability (RBAC-1, dark): how a module declares a permission
        # and the new authorization API. Used by no live route; the legacy
        # require_permission / require_role stay authoritative until RBAC-3+.
        "PermissionDecl",
        "ScopeContext",
        "Principal",
        "AuthorizationDecision",
        "EffectivePermissionSet",
        "authorize",
        "can",
        "effective_permissions",
        "require",
        # the offboarding contract: a module registers what it detaches from a
        # purged account, so the platform never touches the module's tables
        "register_user_purge_hook",
    }
)

#: The organisation's plan fields, stored on ``organizations``. Platform-owned
#: (project owner, 29 Sep 2026): ``ccure_platform.plan`` reads and writes them,
#: and a module reaches them only through ``ccure_platform.api``. The 8.1 ratchet
#: assumed the opposite ownership and was inverted in step 8.4.
PLAN_FIELDS = (
    "max_assets",
    "max_users",
    "max_scans_per_day",
    "max_concurrent_scans",
    "scan_scope_cidrs",
    "remediation_sla",
)

#: Identity's own code and its own consumers, which are the platform and are
#: exempt: the package itself, the identity models, the routers that *are*
#: identity's administration surface, and the composition root.
PLATFORM_SIDE_PREFIXES = (
    "auth",
    "ccure_platform",
    "db.models.users",
    "db.models.rbac",
    "main",
    "routers.admin_orgs",
    "routers.admin_users",
    "routers.admin_rbac",
    "routers.admin_email_domains",
    "routers.user_profile",
    "routers.audit",  # the audit-log viewer — a platform service
    "routers.notifications",  # a platform service
    # Alias stub: moved to ccure_platform.identity in step 8.3.
    "core.email_security_tasks",
    # Alias stubs: the audit-log service moved to ccure_platform.audit_log.
    "core.audit",
    "core.audit_taxonomy",
    "core.audit_retention",
    "reporting.audit_export",
    "core.notifications",
)
#: Exempt as an exact name only: the model registry re-exports every model, and
#: a prefix would exempt Audit's model modules with it.
PLATFORM_SIDE_EXACT = frozenset({"db.models"})

_QUERY_FUNCTIONS = frozenset({"select", "delete", "update"})
_JOIN_METHODS = frozenset({"join", "outerjoin"})
_EAGER_LOADS = frozenset(
    {"joinedload", "selectinload", "subqueryload", "contains_eager", "lazyload"}
)


@dataclass(frozen=True)
class Site:
    module: str
    line: int
    kind: str  # "import" | "query" | "join"
    what: str  # the imported symbol, or the model queried


def is_platform_side(module: str) -> bool:
    if module in PLATFORM_SIDE_EXACT:
        return True
    return any(
        module == p or module.startswith(p + ".") for p in PLATFORM_SIDE_PREFIXES
    )


def _under(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def _is_identity_package(module: str) -> bool:
    return any(_under(module, p) for p in IDENTITY_PACKAGES)


#: The module registry (Phase 11) declares which modules the core hosts. It
#: holds no identity code and imports only the standard library
#: (tests/repo/test_module_registry.py), so reading it is not reaching identity.
PLATFORM_MODULES = "ccure_platform.modules"


def _is_platform_internal(module: str) -> bool:
    return (
        _under(module, PLATFORM_PACKAGE)
        and not _under(module, PLATFORM_API)
        and not _under(module, PLATFORM_MODULES)
    )


def _root_name(node: ast.AST, dotted: frozenset[str] = frozenset()) -> str | None:
    """
    The name an expression such as ``User.id`` or ``func.count(User.id)`` hangs
    off. ``dotted`` holds ``alias.Name`` pairs (``platform_api.CurrentUser``)
    that count as a root in their own right.
    """
    while True:
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and f"{node.value.id}.{node.attr}" in dotted
        ):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Call) and node.args and not node.keywords:
            # func.count(User.id), distinct(User.email) …
            node = node.args[0]
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def _callee(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    if isinstance(node.func, ast.Name):
        return node.func.id
    return None


def scan_source(module: str, source: str, package: str | None = None) -> list[Site]:
    """Every identity import and query in one module's source."""
    tree = ast.parse(source)
    if package is None:
        package = module.rpartition(".")[0]
    sites: list[Site] = []
    bound: dict[str, str] = {}  # local name -> identity model

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                anchor = package.split(".") if package else []
                if node.level > 1:
                    anchor = anchor[: len(anchor) - (node.level - 1)]
                base = ".".join(anchor + ([base] if base else []))
            for alias in node.names:
                symbol = f"{base}.{alias.name}"
                if _is_identity_package(base):
                    sites.append(Site(module, node.lineno, "import", symbol))
                elif base in IDENTITY_MODEL_SOURCES and alias.name in IDENTITY_MODELS:
                    sites.append(Site(module, node.lineno, "import", symbol))
                    bound[alias.asname or alias.name] = alias.name
                elif base == PLATFORM_API and alias.name in API_MODEL_ALIASES:
                    bound[alias.asname or alias.name] = API_MODEL_ALIASES[alias.name]
                elif base == PLATFORM_PACKAGE and alias.name not in ("api", "modules"):
                    sites.append(Site(module, node.lineno, "import", symbol))
                elif _is_platform_internal(base) and base != PLATFORM_PACKAGE:
                    sites.append(Site(module, node.lineno, "import", symbol))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _is_identity_package(alias.name) or (
                    _is_platform_internal(alias.name) and alias.name != PLATFORM_PACKAGE
                ):
                    sites.append(Site(module, node.lineno, "import", alias.name))

    # ``from ccure_platform import api as X`` makes ``X.CurrentUser`` a model too.
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == PLATFORM_PACKAGE:
            for alias in node.names:
                if alias.name == "api":
                    for name, model in API_MODEL_ALIASES.items():
                        bound[f"{alias.asname or alias.name}.{name}"] = model
    dotted = frozenset(k for k in bound if "." in k)

    if not bound:
        return sites

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _callee(node)
        if name is None or not node.args:
            continue
        # ``delete``/``update`` only as the bare SQLAlchemy constructs:
        # ``session.delete(obj)`` and ``dict.update(...)`` are not statements.
        is_statement = (
            (name == "query" and isinstance(node.func, ast.Attribute))
            or name == "select"
            or (name in _QUERY_FUNCTIONS and isinstance(node.func, ast.Name))
        )
        if is_statement:
            for arg in node.args:
                root = _root_name(arg, dotted)
                if root in bound:
                    sites.append(Site(module, node.lineno, "query", bound[root]))
                    break
        elif name == "get" and isinstance(node.func, ast.Attribute):
            first = node.args[0]
            root = (
                first.id
                if isinstance(first, ast.Name)
                else (
                    _root_name(first, dotted)
                    if isinstance(first, ast.Attribute)
                    else None
                )
            )
            if root in bound and (isinstance(first, ast.Name) or root in dotted):
                sites.append(Site(module, node.lineno, "query", bound[root]))
        elif (name in _JOIN_METHODS and isinstance(node.func, ast.Attribute)) or (
            name in _EAGER_LOADS
        ):
            root = _root_name(node.args[0], dotted)
            if root in bound:
                sites.append(Site(module, node.lineno, "join", bound[root]))
    return sites


def plan_field_references(module: str, source: str) -> list[Site]:
    """
    Every mention of an Audit setting in one module, as a name, an attribute, a
    keyword, a parameter or a string. Column definitions in a model class body
    are not a mention: ``organizations`` keeps those columns, untouched and
    unused, for a release after step 8.4.
    """
    tree = ast.parse(source)
    settings = set(PLAN_FIELDS)
    definitions: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for stmt in node.body:
                targets = (
                    stmt.targets
                    if isinstance(stmt, ast.Assign)
                    else [stmt.target] if isinstance(stmt, ast.AnnAssign) else []
                )
                definitions.update(id(t) for t in targets)
    sites: list[Site] = []
    for node in ast.walk(tree):
        if id(node) in definitions:
            continue
        found = None
        if isinstance(node, ast.Name) and node.id in settings:
            found = node.id
        elif isinstance(node, ast.Attribute) and node.attr in settings:
            found = node.attr
        elif isinstance(node, ast.keyword) and node.arg in settings:
            found = node.arg
        elif isinstance(node, ast.arg) and node.arg in settings:
            found = node.arg
        elif isinstance(node, ast.Constant) and node.value in settings:
            found = node.value
        if found:
            sites.append(Site(module, getattr(node, "lineno", 0), "setting", found))
    return sites


def measure_module_plan_fields(root: Path = BACKEND_ROOT) -> list[Site]:
    """Plan fields named by module code — code outside the platform."""
    sites: list[Site] = []
    for module, path in sorted(discover_modules(root).items()):
        if is_platform_side(module):
            continue
        sites.extend(plan_field_references(module, path.read_text(encoding="utf-8")))
    return sites


def measure(root: Path = BACKEND_ROOT) -> tuple[int, list[Site]]:
    """(modules scanned, identity sites in module code outside the platform)."""
    modules = discover_modules(root)
    sites: list[Site] = []
    for module, path in sorted(modules.items()):
        if is_platform_side(module):
            continue
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:  # pragma: no cover
            continue
        sites.extend(scan_source(module, source, package))
    return len(modules), sites


def imports_by_module(sites: list[Site]) -> dict[str, frozenset[str]]:
    out: dict[str, set[str]] = defaultdict(set)
    for s in sites:
        if s.kind == "import":
            out[s.module].add(s.what)
    return {m: frozenset(v) for m, v in out.items()}


def counts_by_module(sites: list[Site], kind: str) -> dict[str, dict[str, int]]:
    out: dict[str, Counter] = defaultdict(Counter)
    for s in sites:
        if s.kind == kind:
            out[s.module][s.what] += 1
    return {m: dict(sorted(c.items())) for m, c in out.items()}


# ── baseline — measured 28 Sep 2026 (step 8.1) ───────────────────────────────
# Regenerate with ``--baseline`` only to *remove* entries; a new entry needs an
# explicit reason in review. Steps 8.3 and 8.5 bring all three to empty.

#: module -> identity symbols it imports. 32 modules and 80 symbols on
#: 28 Sep 2026; 3 after step 8.5, each kept on purpose:
#:
#: * ``core.tasks`` re-exports the five mail tasks from ``auth.mail_tasks`` so
#:   the patch targets ``core.tasks.send_*_task`` keep resolving. It is a
#:   legacy compatibility path, kept while the other legacy paths are (8.5
#:   deletes none of them).
#: * ``routers.scan_history`` and ``routers.web_scans`` authenticate a WebSocket
#:   ticket themselves (``decode_token`` plus a ``User`` query). That is gateway
#:   work, deliberately left for Phase 10.
KNOWN_IDENTITY_IMPORTS: dict[str, frozenset[str]] = {
    "core.tasks": frozenset(
        {
            "auth.mail_tasks.send_account_approved_email_task",
            "auth.mail_tasks.send_mfa_otp_task",
            "auth.mail_tasks.send_password_changed_email_task",
            "auth.mail_tasks.send_password_reset_email_task",
            "auth.mail_tasks.send_verification_email_task",
        }
    ),
    "routers.scan_history": frozenset(
        {"auth.jwt_handler.decode_token", "db.models.User"}
    ),
    "routers.web_scans": frozenset({"auth.jwt_handler.decode_token", "db.models.User"}),
}

#: module -> {identity model: direct queries}. 53 queries in 23 modules on
#: 28 Sep 2026; step 8.3 lowers it batch by batch.
KNOWN_IDENTITY_QUERIES: dict[str, dict[str, int]] = {
    "routers.scan_history": {"User": 1},
    "routers.web_scans": {"User": 1},
}

#: module -> {identity model: joins and eager loads}. 8 in 4 modules. The
#: proposal's count (query() and select() only) did not look for these.
KNOWN_IDENTITY_JOINS: dict[str, dict[str, int]] = {
    "routers.scan_history": {"User": 1},
    "routers.web_scans": {"User": 1},
}

#: module -> {plan field: mentions} in module code. Measured 29 Sep 2026 when
#: step 8.4 made the plan platform-owned: the four seams read the columns
#: themselves. Step 8.4 moved every read behind ``ccure_platform.api``, and it
#: reached zero there: module code names no plan field, and must not start.
KNOWN_MODULE_PLAN_FIELD_REFERENCES: dict[str, dict[str, int]] = {}


def _print_baseline(sites: list[Site]) -> None:
    imports = imports_by_module(sites)
    print("KNOWN_IDENTITY_IMPORTS: dict[str, frozenset[str]] = {")
    for m in sorted(imports):
        names = ", ".join(repr(n) for n in sorted(imports[m]))
        print(f"    {m!r}: frozenset({{{names}}}),")
    print("}")
    for label, kind in (
        ("KNOWN_IDENTITY_QUERIES", "query"),
        ("KNOWN_IDENTITY_JOINS", "join"),
    ):
        counts = counts_by_module(sites, kind)
        print(f"{label}: dict[str, dict[str, int]] = {{")
        for m in sorted(counts):
            print(f"    {m!r}: {counts[m]!r},")
        print("}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--list", action="store_true", help="print every site")
    parser.add_argument(
        "--baseline", action="store_true", help="print the baseline literals"
    )
    args = parser.parse_args(argv)
    scanned, sites = measure()
    if args.baseline:
        _print_baseline(sites)
        return 0
    if args.list:
        for s in sorted(sites, key=lambda s: (s.kind, s.module, s.line)):
            print(f"{s.kind:6s} {s.module}:{s.line}  {s.what}")
        return 0
    imports = imports_by_module(sites)
    queries = [s for s in sites if s.kind == "query"]
    joins = [s for s in sites if s.kind == "join"]
    print(f"modules scanned: {scanned}")
    print(f"module files importing identity: {len(imports)}")
    print(
        f"direct identity queries: {len(queries)} in "
        f"{len({s.module for s in queries})} modules  "
        f"({dict(Counter(s.what for s in queries).most_common())})"
    )
    print(
        f"identity joins and eager loads: {len(joins)} in "
        f"{len({s.module for s in joins})} modules"
    )
    area = Counter(m.split(".")[0] for m in imports)
    print("importers by area:", dict(area.most_common()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

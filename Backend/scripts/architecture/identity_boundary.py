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
    }
)

#: Modules an identity model can be imported from today.
IDENTITY_MODEL_SOURCES = ("db.models", "db.models.users", "db.models.rbac")

#: Identity's own code: any import from here is an identity import.
IDENTITY_PACKAGES = ("auth",)

#: The one way into the platform once Phase 8 is complete.
PLATFORM_PACKAGE = "ccure_platform"
PLATFORM_API = "ccure_platform.api"

#: Everything ``ccure_platform.api`` may ever export. It holds shared identity,
#: tenancy and RBAC primitives only — never Audit's quotas, scan scope or any
#: other module's business logic. A name added here needs a reason in review.
PLATFORM_API_SURFACE = frozenset(
    {
        "current_user",
        "current_user_flexible",
        "require_permission",
        "require_role",
        "user_display_names",
        "users_holding_permission",
        "organisation",
        "OrganisationView",
        "is_organisation_active",
    }
)

#: Audit's configuration that sits on ``organizations`` today. Step 8.4 moves it
#: to the Audit-owned ``audit_organisation_settings``; it must never become a
#: platform concern, so no name in ``ccure_platform`` may mention it.
AUDIT_SETTINGS_ON_ORGANIZATIONS = (
    "max_assets",
    "max_scans_per_day",
    "max_concurrent_scans",
    "scan_scope_cidrs",
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


def _is_platform_internal(module: str) -> bool:
    return _under(module, PLATFORM_PACKAGE) and not _under(module, PLATFORM_API)


def _root_name(node: ast.AST) -> str | None:
    """The name an expression such as ``User.id`` or ``func.count(User.id)`` hangs off."""
    while True:
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
                elif base == PLATFORM_PACKAGE and alias.name != "api":
                    sites.append(Site(module, node.lineno, "import", symbol))
                elif _is_platform_internal(base) and base != PLATFORM_PACKAGE:
                    sites.append(Site(module, node.lineno, "import", symbol))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _is_identity_package(alias.name) or (
                    _is_platform_internal(alias.name) and alias.name != PLATFORM_PACKAGE
                ):
                    sites.append(Site(module, node.lineno, "import", alias.name))

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
                root = _root_name(arg)
                if root in bound:
                    sites.append(Site(module, node.lineno, "query", bound[root]))
                    break
        elif name == "get" and isinstance(node.func, ast.Attribute):
            first = node.args[0]
            if isinstance(first, ast.Name) and first.id in bound:
                sites.append(Site(module, node.lineno, "query", bound[first.id]))
        elif (name in _JOIN_METHODS and isinstance(node.func, ast.Attribute)) or (
            name in _EAGER_LOADS
        ):
            root = _root_name(node.args[0])
            if root in bound:
                sites.append(Site(module, node.lineno, "join", bound[root]))
    return sites


def audit_setting_references(module: str, source: str) -> list[Site]:
    """
    Every mention of an Audit setting in one module, as a name, an attribute, a
    keyword, a parameter or a string. Column definitions in a model class body
    are not a mention: ``organizations`` keeps those columns, untouched and
    unused, for a release after step 8.4.
    """
    tree = ast.parse(source)
    settings = set(AUDIT_SETTINGS_ON_ORGANIZATIONS)
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


def measure_platform_settings(root: Path = BACKEND_ROOT) -> list[Site]:
    """Audit settings mentioned by platform-side code (identity, its routers)."""
    sites: list[Site] = []
    for module, path in sorted(discover_modules(root).items()):
        if not is_platform_side(module):
            continue
        sites.extend(audit_setting_references(module, path.read_text(encoding="utf-8")))
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

#: module -> identity symbols it imports. 32 modules, 80 symbols.
KNOWN_IDENTITY_IMPORTS: dict[str, frozenset[str]] = {
    "ccure_audit.services.assessment_read": frozenset({"db.models.Organization"}),
    "ccure_audit.services.baseline_mapping": frozenset({"db.models.Organization"}),
    "ccure_audit.services.finding_read": frozenset({"db.models.User"}),
    "core.audit": frozenset({"db.models.User"}),
    "core.email_security_tasks": frozenset(
        {
            "auth.email_domain_guard.evaluate_email",
            "auth.email_risk_signals.collect_signals",
            "auth.email_utils.canonicalize_email",
            "db.models.User",
        }
    ),
    "core.notifications": frozenset({"db.models.Role", "db.models.User"}),
    "core.quota": frozenset({"db.models.rbac.Organization"}),
    "core.remediation.reporting": frozenset({"db.models.rbac.Organization"}),
    "core.remediation.workflow": frozenset({"db.models.rbac.Organization"}),
    "core.scheduling.dispatcher": frozenset({"db.models.Organization"}),
    "core.tasks": frozenset(
        {
            "auth.mail_tasks.send_account_approved_email_task",
            "auth.mail_tasks.send_mfa_otp_task",
            "auth.mail_tasks.send_password_changed_email_task",
            "auth.mail_tasks.send_password_reset_email_task",
            "auth.mail_tasks.send_verification_email_task",
            "db.models.Organization",
            "db.models.RefreshTokenSession",
            "db.models.User",
            "db.models.rbac.Organization",
        }
    ),
    "core.topology.engine": frozenset({"db.models.Organization"}),
    "routers.admin_nvd": frozenset({"auth.rbac.require_role", "db.models.User"}),
    "routers.assets": frozenset({"auth.rbac.require_permission", "db.models.User"}),
    "routers.compliance": frozenset({"auth.rbac.require_permission", "db.models.User"}),
    "routers.config_audit": frozenset(
        {"auth.rbac.require_permission", "db.models.User"}
    ),
    "routers.credentialed": frozenset(
        {"auth.rbac.require_permission", "db.models.Organization", "db.models.User"}
    ),
    "routers.credentials": frozenset(
        {"auth.rbac.require_permission", "db.models.Organization", "db.models.User"}
    ),
    "routers.dashboard": frozenset(
        {
            "auth.rbac.require_permission",
            "db.models.User",
            "db.models.rbac.Organization",
        }
    ),
    "routers.findings": frozenset({"auth.rbac.require_permission", "db.models.User"}),
    "routers.health": frozenset({"auth.rbac.require_permission", "db.models.User"}),
    "routers.phase_scans": frozenset(
        {"auth.rbac.require_permission", "db.models.Organization", "db.models.User"}
    ),
    "routers.remediation": frozenset(
        {"auth.rbac.require_permission", "db.models.Organization", "db.models.User"}
    ),
    "routers.reports": frozenset(
        {
            "auth.dependencies.get_current_user_flexible",
            "db.models.Permission",
            "db.models.RolePermission",
            "db.models.User",
        }
    ),
    "routers.scan_history": frozenset(
        {
            "auth.jwt_handler.decode_token",
            "auth.rbac.require_permission",
            "db.models.Permission",
            "db.models.RolePermission",
            "db.models.User",
        }
    ),
    "routers.scan_policies": frozenset(
        {"auth.rbac.require_permission", "db.models.Organization", "db.models.User"}
    ),
    "routers.scan_schedules": frozenset(
        {"auth.rbac.require_permission", "db.models.Organization", "db.models.User"}
    ),
    "routers.topology": frozenset({"auth.rbac.require_permission", "db.models.User"}),
    "routers.traditional_scans": frozenset(
        {"auth.rbac.require_permission", "db.models.User"}
    ),
    "routers.web_scans": frozenset(
        {
            "auth.jwt_handler.decode_token",
            "auth.rbac.require_permission",
            "auth.rbac.user_has_permission",
            "db.models.User",
            "db.models.rbac.Organization",
        }
    ),
    "scans.db_helpers": frozenset(
        {"db.models.rbac.Organization", "db.models.users.User"}
    ),
    "scans.progress": frozenset(
        {"db.models.Permission", "db.models.RolePermission", "db.models.User"}
    ),
}

#: module -> {identity model: direct queries}. 53 queries in 23 modules.
KNOWN_IDENTITY_QUERIES: dict[str, dict[str, int]] = {
    "ccure_audit.services.assessment_read": {"Organization": 1},
    "ccure_audit.services.baseline_mapping": {"Organization": 1},
    "ccure_audit.services.finding_read": {"User": 1},
    "core.email_security_tasks": {"User": 3},
    "core.notifications": {"Role": 1, "User": 2},
    "core.quota": {"Organization": 1},
    "core.remediation.reporting": {"Organization": 1},
    "core.remediation.workflow": {"Organization": 1},
    "core.scheduling.dispatcher": {"Organization": 1},
    "core.tasks": {"Organization": 3, "RefreshTokenSession": 1, "User": 5},
    "core.topology.engine": {"Organization": 1},
    "routers.credentialed": {"Organization": 1},
    "routers.credentials": {"Organization": 2},
    "routers.dashboard": {"Organization": 1},
    "routers.phase_scans": {"Organization": 1},
    "routers.remediation": {"Organization": 1, "User": 1},
    "routers.reports": {"RolePermission": 3},
    "routers.scan_history": {"RolePermission": 2, "User": 1},
    "routers.scan_policies": {"Organization": 2},
    "routers.scan_schedules": {"Organization": 2},
    "routers.web_scans": {"Organization": 1, "User": 1},
    "scans.db_helpers": {"Organization": 3, "User": 6},
    "scans.progress": {"RolePermission": 1, "User": 1},
}

#: module -> {identity model: joins and eager loads}. 8 in 4 modules. The
#: proposal's count (query() and select() only) did not look for these.
KNOWN_IDENTITY_JOINS: dict[str, dict[str, int]] = {
    "routers.reports": {"Permission": 3},
    "routers.scan_history": {"Permission": 2, "User": 1},
    "routers.web_scans": {"User": 1},
    "scans.progress": {"Permission": 1},
}

#: platform-side module -> {Audit setting: mentions}. 11 in 2 modules, measured
#: 28 Sep 2026. Registration gives a new self-service organisation an Audit
#: asset quota (``auth.router``), and the organisation administration router
#: edits quotas and scan scope. Step 8.4 moves both to Audit — the URLs stay —
#: and this reaches zero there.
KNOWN_AUDIT_SETTING_REFERENCES: dict[str, dict[str, int]] = {
    "auth.router": {"max_assets": 1},
    "routers.admin_orgs": {"max_assets": 6, "scan_scope_cidrs": 4},
}


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

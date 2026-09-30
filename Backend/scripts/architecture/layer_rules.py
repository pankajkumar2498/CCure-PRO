"""
Layering rules for the backend, and the violations that exist today.

Each rule forbids one direction of dependency and says why. ``KNOWN_VIOLATIONS``
is every edge that broke a rule when the rules were introduced (Phase 2 of the
modular-platform programme, 25 Sep 2026). The guard in
``tests/repo/test_architecture_guardrails.py`` is a ratchet:

* an edge that breaks a rule and is **not** listed fails CI — nothing new may be
  added;
* a listed edge that **no longer exists** also fails CI, with the instruction to
  delete it — so the list can only shrink, and a fixed violation cannot quietly
  come back.

Refactoring phases remove entries from ``KNOWN_VIOLATIONS``; nothing adds to it.
A new entry needs a reason in its review, the same way a new endpoint-limit
allowlist entry does.

Rules are matched on dotted module names. ``importer`` and ``forbidden`` are
tuples of prefixes; a prefix matches the module itself and everything under it.
``exempt_importers`` narrows who the rule applies to, and ``exempt_targets``
narrows what it forbids — for a rule that forbids a whole package except a few
named modules in it.
"""

from __future__ import annotations

from dataclasses import dataclass

from scripts.architecture.import_graph import Edge

#: Every application top-level package, for rules that forbid "anything else".
_APP_PACKAGES = (
    "ccure_audit",
    "ccure_platform",
    "auth",
    "core",
    "engines",
    "orchestrator",
    "reporting",
    "routers",
    "scans",
    "scan_helpers",
    "main",
)


@dataclass(frozen=True)
class Rule:
    name: str
    importer: tuple[str, ...]
    forbidden: tuple[str, ...]
    reason: str
    exempt_importers: tuple[str, ...] = ()
    exempt_targets: tuple[str, ...] = ()


def _matches(module: str, prefixes: tuple[str, ...]) -> bool:
    return any(module == p or module.startswith(p + ".") for p in prefixes)


RULES: tuple[Rule, ...] = (
    Rule(
        name="http-edge",
        importer=("",),  # everyone …
        exempt_importers=("routers", "main"),  # … except the HTTP layer itself
        forbidden=("routers",),
        reason=(
            "Routers are the HTTP edge. Code below them importing one depends on "
            "FastAPI request handling and cannot run in a worker, a script or "
            "another application. Move the shared helper down instead."
        ),
    ),
    Rule(
        name="nothing-imports-main",
        importer=("",),
        exempt_importers=("main",),
        forbidden=("main",),
        reason="main.py is the composition root; importing it imports the whole application.",
    ),
    Rule(
        name="models-are-leaves",
        importer=("db", "ccure_platform.models"),
        forbidden=_APP_PACKAGES,
        # The platform's models are models (Phase 8.2): db.models.users and
        # db.models.rbac are alias stubs of them, and they register their
        # legacy names through ccure_platform._legacy, which imports nothing.
        exempt_targets=("ccure_platform.models", "ccure_platform._legacy"),
        reason=(
            "Models and the session layer sit at the bottom: every capability "
            "imports them, so a model importing a capability puts that capability "
            "in everyone's dependency tree. Only db and config are allowed."
        ),
    ),
    Rule(
        name="engines-are-libraries",
        importer=(
            "engines",
            "core.checks",
            "core.config_audit",
            "core.scap",
            "core.discovery",
            "core.nmap",
        ),
        forbidden=(
            "routers",
            "orchestrator",
            "core.tasks",
            "scan_helpers",
            "main",
            "scans",
            "reporting",
            "auth",
            "ccure_platform",
            "db",
        ),
        reason=(
            "Engines take their inputs as arguments and return results; the "
            "orchestration layer persists them. An engine reaching into the task "
            "hub, the persistence helpers, the database or the HTTP layer cannot "
            "run in a CLI, a test or another application (the target in "
            "docs/architecture, roadmap Phases 3 and 8)."
        ),
    ),
    Rule(
        name="task-hub-is-a-leaf",
        importer=(
            "core",
            "scans",
            "engines",
            "reporting",
            "auth",
            "ccure_platform",
            "db",
            "orchestrator",
        ),
        exempt_importers=("core.tasks",),
        forbidden=("core.tasks",),
        reason=(
            "core/tasks.py is the Celery task hub and depends on 22 components. "
            "Anything it depends on importing it back creates the cycle the "
            "baseline measured. Dispatch through a task *name* or a port."
        ),
    ),
    Rule(
        name="infrastructure-is-foundation",
        importer=(
            "core.constants",
            "core.utils",
            "core.redis_client",
            "core.celery_app",
            # Moved to auth/ in Phase 3; kept so it cannot return here importing auth.
            "core.mail_dispatch",
            "core.rate_limit_audit",
            "core.rate_limit_middleware",
            "core.rate_limiter",
            "core.throttle",
            "core.security_crypto",
        ),
        forbidden=(
            "auth",
            "ccure_platform",
            "reporting",
            "routers",
            "scans",
            "orchestrator",
            "engines",
            "core.tasks",
            "core.web",
            "scan_helpers",
        ),
        # The platform module registry (Phase 11) is a leaf — standard library
        # only, pinned by tests/repo/test_module_registry.py — so reading it
        # loads nothing. core.celery_app takes each enabled module's task
        # modules and queues from it.
        exempt_targets=("ccure_platform.modules",),
        reason=(
            "Shared infrastructure is imported by nearly everything. When it "
            "imports a feature, every importer loads that feature too — which is "
            "how importing the discovery engine came to load the PDF generator "
            "and the database layer."
        ),
    ),
    Rule(
        name="identity-below-scanning",
        importer=("auth",),
        forbidden=(
            "scan_helpers",
            "scans",
            "orchestrator",
            "engines",
            "core.tasks",
            "reporting",
        ),
        reason=(
            "Identity is a platform service all four CCure modules will share. "
            "It must not depend on the scanning code of one of them."
        ),
    ),
    Rule(
        name="platform-is-shared-foundation",
        importer=("ccure_platform",),
        forbidden=(
            "ccure_audit",
            "core",
            "scans",
            "scan_helpers",
            "engines",
            "orchestrator",
            "reporting",
            "routers",
            "main",
            # Audit's models. The platform's own (users, rbac, email_security,
            # notifications) and db.base stay importable.
            "db.models.amt",
            "db.models.assets",
            "db.models.compliance",
            "db.models.findings",
            "db.models.scan_policies",
            "db.models.scan_reports",
            "db.models.scan_schedules",
            "db.models.scans",
            "db.models.topology",
            "db.models.web_scans",
        ),
        # The shared infrastructure identity uses today (measured from auth/ on
        # 28 Sep 2026), so moving auth/ here in step 8.2 needs no exception.
        exempt_targets=(
            "core.audit",
            "core.celery_app",
            "core.ip_resolver",
            "core.rate_limiter",
            "core.redis_client",
            "core.throttle",
            "core.user_agent",
        ),
        reason=(
            "ccure_platform is what all four CCure modules share: identity, "
            "tenancy and RBAC. Importing a module's code — Audit's scans, "
            "findings, compliance, reports or models — would make every module "
            "depend on Audit and turn the platform into a place Audit logic "
            "hides (Phase 8). Shared infrastructure is named one module at a "
            "time in exempt_targets."
        ),
    ),
    Rule(
        name="platform-does-not-use-legacy-paths",
        importer=("ccure_platform",),
        forbidden=("auth", "db.models.users", "db.models.rbac"),
        reason=(
            "auth.* and db.models.users/rbac are compatibility aliases of modules "
            "that moved into ccure_platform in Phase 8.2, kept for module code "
            "until step 8.5. The platform imports its own modules by their real "
            "names (models through the db.models registry), so the aliases can "
            "be deleted without touching it."
        ),
    ),
    Rule(
        name="contracts-are-leaves",
        importer=("ccure_contracts",),
        forbidden=_APP_PACKAGES + ("db", "config"),
        reason=(
            "ccure_contracts is the one package every CCure module may import, so "
            "it may import no module's code. A contract that reached into Audit's "
            "models or services would expose Audit's internals to Policy Pro, "
            "Rank and IR and couple all four to them (Phase 4)."
        ),
    ),
    Rule(
        name="integration-is-an-adapter",
        importer=("ccure_audit.integration",),
        forbidden=(
            "db",
            "config",
            "core",
            "engines",
            "scans",
            "orchestrator",
            "reporting",
            "routers",
            "scan_helpers",
            "auth",
            "ccure_platform",
            "main",
        ),
        reason=(
            "The Audit integration adapter translates service views into "
            "contract messages and back. Reaching past ccure_audit.services to "
            "the database or a capability is how an ORM row ends up inside a "
            "contract other modules depend on (Phase 5)."
        ),
    ),
    Rule(
        name="services-do-not-speak-contracts",
        importer=("ccure_audit.services",),
        forbidden=(
            "ccure_contracts",
            "ccure_audit.integration",
            "routers",
            "main",
            "core.tasks",
        ),
        reason=(
            "Audit's application services return Audit's own views. If they "
            "spoke contract types, a new contract version would force a change "
            "to every service; translation belongs to the adapter. Services are "
            "neither HTTP handlers nor the task hub (Phase 5)."
        ),
    ),
    Rule(
        name="foundations-do-not-import-audit-module",
        importer=("core", "engines", "scans", "orchestrator", "db", "auth"),
        forbidden=("ccure_audit",),
        reason=(
            "ccure_audit sits above the existing capabilities and uses them. A "
            "capability importing it back re-creates the upward dependencies "
            "and cycles Phase 3 removed (Phase 5)."
        ),
    ),
    Rule(
        name="reporting-below-http",
        importer=("reporting",),
        forbidden=("routers", "orchestrator", "core.tasks", "main"),
        reason="Report renderers take a payload and return a document; they do not dispatch or serve.",
    ),
)


def violations(edges: list[Edge]) -> list[tuple[str, Edge]]:
    """Every (rule name, edge) where the edge breaks the rule."""
    found: list[tuple[str, Edge]] = []
    for rule in RULES:
        for edge in edges:
            if rule.importer != ("",) and not _matches(edge.src, rule.importer):
                continue
            if rule.exempt_importers and _matches(edge.src, rule.exempt_importers):
                continue
            if rule.exempt_targets and _matches(edge.dst, rule.exempt_targets):
                continue
            if _matches(edge.dst, rule.forbidden):
                found.append((rule.name, edge))
    return found


#: (rule, importer, imported) — the violations still allowed to exist.
#: Phase 2 recorded twenty-one on 25 Sep 2026; Phase 3 removed all of them, so the
#: set is empty and every rule above now holds without exception. Do not add to
#: it: a new entry needs an explicit reason in review.
KNOWN_VIOLATIONS: frozenset[tuple[str, str, str]] = frozenset()

#: Module-level import cycles that are allowed to exist (measured with lazy
#: imports counted). Phase 2 recorded three on 25 Sep 2026 and Phase 3 broke all
#: of them: the task-hub cycle (`_detect_os` moved to engines,
#: `create_notification` to core.notifications, and the scheduler and scan
#: persistence dispatch by task name through core/task_names.py), constants <->
#: cve_database (CVE_DB moved into core/utils.py), and core.web.injection <->
#: its engine (the engine imports its payloads module rather than reading it
#: off the package that re-exports the engine). Any cycle now fails CI.
KNOWN_CYCLES: tuple[frozenset[str], ...] = ()

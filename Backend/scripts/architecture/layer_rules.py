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
"""

from __future__ import annotations

from dataclasses import dataclass

from scripts.architecture.import_graph import Edge

#: Every application top-level package, for rules that forbid "anything else".
_APP_PACKAGES = (
    "ccure_audit",
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
        importer=("db",),
        forbidden=_APP_PACKAGES,
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
            "reporting",
            "routers",
            "scans",
            "orchestrator",
            "engines",
            "core.tasks",
            "core.web",
            "scan_helpers",
        ),
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

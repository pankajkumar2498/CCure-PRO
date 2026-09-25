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


#: (rule, importer, imported) — every violation present on 25 Sep 2026.
#: Delete entries as refactoring removes them. Do not add to this set.
KNOWN_VIOLATIONS: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("engines-are-libraries", "core.checks.contract", "scans.cvss"),
        ("engines-are-libraries", "core.checks.contract", "scans.finding_normalizer"),
        (
            "engines-are-libraries",
            "core.config_audit.compliance_sync",
            "db.models.compliance",
        ),
        (
            "engines-are-libraries",
            "core.config_audit.findings",
            "scans.finding_normalizer",
        ),
        (
            "engines-are-libraries",
            "engines.port.port_engine",
            "scans.finding_normalizer",
        ),
        (
            "engines-are-libraries",
            "engines.vulnerability.vulnerability_engine",
            "scans.finding_normalizer",
        ),
    }
)

#: Module-level import cycles present on 25 Sep 2026 (measured with lazy imports
#: counted). A new cycle, or a new module joining one of these, fails CI; a
#: cycle that is broken must be deleted here. Phase 3 broke the task-hub cycle
#: (`_detect_os` moved to engines, `create_notification` to core.notifications,
#: and the scheduler and scan persistence now dispatch by task name through
#: core/task_names.py) and the constants <-> cve_database cycle (CVE_DB moved
#: into core/utils.py).
KNOWN_CYCLES: tuple[frozenset[str], ...] = (
    frozenset({"core.web.injection", "core.web.injection.engine"}),
)

"""
Architecture guardrails — Phase 2 of the modular-platform programme.

Three ratchets, each of which fails in both directions so the codebase can only
move towards the target architecture:

* **Layering** (``scripts/architecture/layer_rules.py``). A dependency that
  breaks a rule and is not in ``KNOWN_VIOLATIONS`` fails — nothing new may be
  added. A listed violation that no longer exists also fails — delete it, so a
  fixed violation cannot come back unnoticed.
* **Import cycles.** A new module-level cycle, or a module joining an existing
  one, fails. A cycle that shrank or disappeared must be updated in
  ``KNOWN_CYCLES``.
* **Table ownership** (``scripts/architecture/table_ownership.yaml``). Every
  table the models define has exactly one owning module, and the registry names
  no table that does not exist.

The import graph is measured from source with ``ast``; nothing is imported, so
lazy imports inside functions count — they are where this codebase hides its
cycles, and a dependency that resolves at call time is still a dependency.
"""

from __future__ import annotations

import pytest
import yaml

from scripts.architecture.import_graph import Edge, collect_edges, module_cycles
from scripts.architecture.layer_rules import (
    KNOWN_CYCLES,
    KNOWN_VIOLATIONS,
    RULES,
    violations,
)
from testpaths import BACKEND_ROOT

OWNERSHIP_FILE = BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml"
RULES_BY_NAME = {rule.name: rule for rule in RULES}


@pytest.fixture(scope="module")
def graph():
    return collect_edges()


@pytest.fixture(scope="module")
def current_violations(graph):
    _, edges = graph
    return {(rule, edge.src, edge.dst) for rule, edge in violations(edges)}


# ── the measurement itself must be measuring something ───────────────────────


def test_the_import_graph_is_not_vacuous(graph):
    """A walker that found nothing would make every guard below pass."""
    modules, edges = graph
    assert len(modules) > 250, f"only {len(modules)} modules found — walker broken?"
    assert len(edges) > 1000, f"only {len(edges)} edges found — parser broken?"
    pairs = {(e.src, e.dst) for e in edges}
    assert ("main", "config") in pairs or any(src == "main" for src, _ in pairs)
    # Imports inside functions must be counted — they are where this codebase
    # hid its cycles. Checked by volume rather than by one named edge, because
    # the named edges are exactly what the refactoring phases remove.
    lazy = sum(1 for e in edges if e.lazy)
    assert lazy > 300, f"only {lazy} inside-function imports seen; are they counted?"


# ── layering ──────────────────────────────────────────────────────────────────


def test_no_new_layer_violations(current_violations):
    added = sorted(current_violations - KNOWN_VIOLATIONS)
    assert not added, (
        "new dependency against the layering rules:\n"
        + "\n".join(
            f"  [{rule}] {src} -> {dst}\n      why forbidden: {RULES_BY_NAME[rule].reason}"
            for rule, src, dst in added
        )
        + (
            "\nMove the shared code down a layer instead. Adding an entry to "
            "KNOWN_VIOLATIONS needs an explicit reason in review."
        )
    )


def test_fixed_violations_are_removed_from_the_list(current_violations):
    stale = sorted(KNOWN_VIOLATIONS - current_violations)
    assert not stale, (
        "these violations no longer exist — delete them from KNOWN_VIOLATIONS in "
        "scripts/architecture/layer_rules.py so they cannot come back:\n"
        + "\n".join(f"  ({rule!r}, {src!r}, {dst!r})," for rule, src, dst in stale)
    )


def test_every_known_violation_names_a_real_rule():
    unknown = sorted({rule for rule, _, _ in KNOWN_VIOLATIONS} - set(RULES_BY_NAME))
    assert not unknown, f"KNOWN_VIOLATIONS names rules that do not exist: {unknown}"


def test_every_rule_says_why():
    for rule in RULES:
        assert len(rule.reason) > 40, f"rule {rule.name!r} needs a real reason"


@pytest.mark.parametrize(
    "src, dst, rule",
    [
        ("core.foo", "routers.bar", "http-edge"),
        ("scans.x", "main", "nothing-imports-main"),
        ("db.models.thing", "core.anything", "models-are-leaves"),
        ("engines.port.x", "scans.finding_normalizer", "engines-are-libraries"),
        ("core.config_audit.y", "db.models.z", "engines-are-libraries"),
        ("core.constants", "reporting.pdf_generator", "infrastructure-is-foundation"),
        ("auth.router", "scan_helpers", "identity-below-scanning"),
        ("scans.db_helpers", "core.tasks", "task-hub-is-a-leaf"),
        ("ccure_contracts.x", "db.models.scans", "contracts-are-leaves"),
        ("ccure_contracts.x", "core.checks.contract", "contracts-are-leaves"),
        ("ccure_contracts.x", "ccure_audit.services.views", "contracts-are-leaves"),
        ("ccure_audit.integration.m", "db.models.scans", "integration-is-an-adapter"),
        ("ccure_audit.integration.m", "reporting.exports", "integration-is-an-adapter"),
        ("ccure_audit.integration.m", "core.remediation", "integration-is-an-adapter"),
        (
            "ccure_audit.services.s",
            "ccure_contracts.common.v1",
            "services-do-not-speak-contracts",
        ),
        (
            "ccure_audit.services.s",
            "ccure_audit.integration",
            "services-do-not-speak-contracts",
        ),
        (
            "ccure_audit.services.s",
            "routers.reports",
            "services-do-not-speak-contracts",
        ),
        (
            "core.findings.comparison",
            "ccure_audit.services",
            "foundations-do-not-import-audit-module",
        ),
        (
            "db.models.findings",
            "ccure_audit.services.views",
            "foundations-do-not-import-audit-module",
        ),
        ("scans.db_helpers", "ccure_audit", "foundations-do-not-import-audit-module"),
        (
            "ccure_platform.identity.x",
            "scans.db_helpers",
            "platform-is-shared-foundation",
        ),
        ("ccure_platform.tenancy", "db.models.scans", "platform-is-shared-foundation"),
        (
            "ccure_platform.api",
            "core.compliance_tasks",
            "platform-is-shared-foundation",
        ),
        (
            "ccure_platform.rbac",
            "ccure_audit.services",
            "platform-is-shared-foundation",
        ),
        ("ccure_platform.api", "routers.admin_orgs", "platform-is-shared-foundation"),
        ("ccure_contracts.x", "ccure_platform.api", "contracts-are-leaves"),
        ("db.models.scans", "ccure_platform", "models-are-leaves"),
        ("engines.port.x", "ccure_platform.api", "engines-are-libraries"),
        ("core.constants", "ccure_platform.api", "infrastructure-is-foundation"),
        (
            "ccure_audit.integration.m",
            "ccure_platform.api",
            "integration-is-an-adapter",
        ),
        (
            "ccure_platform.identity.router",
            "auth.jwt_handler",
            "platform-does-not-use-legacy-paths",
        ),
        (
            "ccure_platform.rbac.dependencies",
            "db.models.users",
            "platform-does-not-use-legacy-paths",
        ),
        (
            "ccure_platform.models.users",
            "ccure_platform.identity.router",
            "models-are-leaves",
        ),
        ("db.models.scans", "ccure_platform.identity", "models-are-leaves"),
    ],
)
def test_the_rules_catch_what_they_describe(src, dst, rule):
    found = {name for name, _ in violations([Edge(src, dst, lazy=False)])}
    assert rule in found


@pytest.mark.parametrize(
    "src, dst",
    [
        ("routers.web_scans", "routers.scan_history"),  # routers may use routers
        ("main", "routers.web_scans"),  # the composition root mounts them
        ("core.tasks", "scans.db_helpers"),  # the task hub may depend downwards
        ("routers.phase_scans", "core.tasks"),  # the HTTP layer dispatches tasks
        ("db.models.users", "db.base"),  # models may use the session layer
        ("ccure_audit.integration.m", "ccure_contracts.common.v1"),  # its job
        ("ccure_audit.integration.m", "ccure_audit.services.views"),  # its job
        ("ccure_audit.services.s", "db.models.findings"),  # services own queries
        ("ccure_audit.services.s", "core.remediation.sla"),  # and use capabilities
        ("reporting.exports", "ccure_audit.services"),  # the Phase 5 transition
        ("ccure_platform.identity.x", "core.rate_limiter"),  # shared infrastructure
        ("ccure_platform.identity.x", "core.audit"),  # the platform's audit log
        ("ccure_platform.identity.x", "db.models"),  # the model registry
        ("ccure_platform.models.users", "db.base"),  # the platform's models are models
        ("db.models.users", "ccure_platform.models.users"),  # the legacy alias stub
        ("ccure_platform.models.rbac", "ccure_platform._legacy"),
        ("ccure_platform.tenancy", "db.base"),
        ("ccure_platform.api", "config"),
        ("routers.scan_history", "ccure_platform.api"),  # the way in
        ("ccure_audit.services.s", "ccure_platform.api"),
        ("core.tasks", "ccure_platform.api"),
    ],
)
def test_the_rules_allow_ordinary_downward_dependencies(src, dst):
    assert violations([Edge(src, dst, lazy=False)]) == []


def test_task_names_resolve_to_the_hub_tasks(monkeypatch):
    """
    Code below core.tasks dispatches by registered name (core/task_names.py)
    rather than importing the hub. A constant that drifted from its decorator
    would otherwise surface as NotRegistered on a live dispatch.

    The module attribute is Celery's lazy proxy to the registered task, so the
    check is on the object behind it — and on the property the scan tests rely
    on: a ``.delay`` patched through ``core.tasks`` is what a by-name dispatch
    calls.
    """
    import core.tasks as hub
    from core import task_names
    from core.celery_app import registered_task

    expected = {
        "RUN_HOST_DISCOVERY": hub.run_host_discovery_task,
        "RUN_CREDENTIALED_SCAN": hub.run_credentialed_scan_task,
        "SYNC_HOST_DISCOVERY": hub.sync_host_discovery_task,
        "SYNC_ASSET_DISCOVERY": hub.sync_asset_discovery_task,
        "SYNC_VULNERABILITY_AUDIT": hub.sync_vulnerability_audit_task,
    }
    declared = {name for name in vars(task_names) if name.isupper()}
    assert declared == set(expected)
    for const, task in expected.items():
        resolved = registered_task(getattr(task_names, const))
        assert resolved is task._get_current_object(), const

        def fake_delay(*args, **kwargs):
            return None

        monkeypatch.setattr(task, "delay", fake_delay)
        assert resolved.delay is fake_delay, const


# ── import cycles ─────────────────────────────────────────────────────────────


def test_no_new_import_cycles(graph):
    _, edges = graph
    grown = [
        sorted(cycle)
        for cycle in module_cycles(edges)
        if not any(cycle <= known for known in KNOWN_CYCLES)
    ]
    assert not grown, (
        "new or enlarged module-level import cycle(s):\n"
        + "\n".join("  " + " <-> ".join(c) for c in grown)
        + "\nA cycle means neither side can be extracted or tested without the other."
    )


def test_broken_cycles_are_removed_from_the_list(graph):
    _, edges = graph
    current = set(module_cycles(edges))
    stale = [sorted(k) for k in KNOWN_CYCLES if k not in current]
    assert not stale, (
        "these recorded cycles changed or no longer exist — update KNOWN_CYCLES "
        "in scripts/architecture/layer_rules.py to the current state:\n"
        + "\n".join("  " + " <-> ".join(c) for c in stale)
    )


# ── table ownership ───────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def ownership():
    return yaml.safe_load(OWNERSHIP_FILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def model_tables():
    import db.models  # noqa: F401  (registers every model on the metadata)
    from ccure_platform.modules import registry
    from db.base import Base

    tables = set(Base.metadata.tables)
    # Phase 11.2: each module's own MetaData, declared in its manifest.toml;
    # its tables are keyed "<schema>.<table>", as table_ownership.yaml names them.
    for m in registry.modules():
        for md in registry.module_metadatas(m):
            tables |= set(md.tables)
    return tables


def test_every_table_has_an_owner(ownership, model_tables):
    unowned = sorted(model_tables - set(ownership["tables"]))
    assert not unowned, (
        "tables with no owning module — add them to "
        "scripts/architecture/table_ownership.yaml:\n  " + "\n  ".join(unowned)
    )


def test_the_registry_names_only_real_tables(ownership, model_tables):
    phantom = sorted(set(ownership["tables"]) - model_tables)
    assert (
        not phantom
    ), "registry entries for tables no model defines — remove them:\n  " + "\n  ".join(
        phantom
    )


def test_every_owner_is_a_declared_module(ownership):
    modules = set(ownership["modules"])
    assert modules == {"platform", "audit", "policy_pro", "rank", "ir"}
    bad = {
        table: entry.get("owner")
        for table, entry in ownership["tables"].items()
        if entry.get("owner") not in modules or not entry.get("capability")
    }
    assert not bad, f"entries without a declared owner or a capability: {bad}"

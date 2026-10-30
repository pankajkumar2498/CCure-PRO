"""
E1 and the rest of E2 (Group 3; docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md
§10, Phase E): the layer rules over capabilities, and the scan engines' load
profiles pinned (scripts/architecture/capability_map.py).

* no layer-3 capability imports a higher layer (engines-are-libraries,
  widened to every layer-3 module);
* nothing outside the scans capability and ``main`` imports ``scan_helpers``;
* the platform's entry points load no Audit capability;
* the port and network-check engines, the Nmap wrapper and the version
  matcher load none of SQLAlchemy, FastAPI, Celery or Redis.

All four are absolute: a rewritten baseline admits no breach. The mutations
below are made to the source, on a copy of the tree, so the rules are shown to
fail on the code they are about and not only on a hand-built measurement.

And the registrations the engines' ports depend on load in the worker and the
API, as the host directory's do.
"""

import copy
import shutil
from pathlib import Path

import pytest
from scripts.architecture import capability_map as cm
from testpaths import BACKEND_ROOT


@pytest.fixture(scope="module")
def measurement():
    return cm.measure()


def test_the_layer_rules_hold(measurement):
    assert cm.layer_rule_problems(measurement) == []


def test_the_scan_engines_load_no_forbidden_package(measurement):
    assert cm.library_problems(measurement["load_profiles"]) == []
    for entry in cm.PINNED_ENGINES:
        assert entry in cm.ENTRY_POINTS


def test_the_topology_engine_is_not_pinned_yet():
    """It persists its own links through SQLAlchemy; pinning it would fail,
    and nothing exempts it (the log's Group 3 records why)."""
    assert "core.topology.engine" not in cm.PINNED_ENGINES


def test_the_measured_boundaries_moved_where_g3_put_them():
    for module, capability in (
        ("core.oui_lookup", "scan_kernel"),
        ("core.device_classifier", "scan_kernel"),
        ("core.scan_targets", "scan_kernel"),
        ("routers.credentialed", "scans"),
        ("core.mac_vendor_cache", "assets"),
        ("core.topology_assets", "assets"),
        ("core.vuln_intel_repository", "vuln_intel"),
        ("engines.vulnerability.cve_lookup", "network_checks"),
    ):
        assert cm.capability_of(module) == capability, module


# ── Mutations of a hand-built measurement ────────────────────────────────────


def test_a_layer_3_upward_edge_breaks_the_rule(measurement):
    grown = copy.deepcopy(measurement)
    grown["upward_edges"].append(["core.discovery.engine", "db.models.assets:Asset"])
    problems = cm.layer_rule_problems(grown)
    assert any(
        "engines-are-libraries: core.discovery.engine (discovery, layer 3)" in p
        for p in problems
    )


def test_an_upward_edge_from_layer_4_is_not_this_rule(measurement):
    grown = copy.deepcopy(measurement)
    grown["upward_edges"].append(["core.findings.comparison", "scans.db_helpers"])
    assert cm.layer_rule_problems(grown) == []


def test_scan_helpers_outside_scans_breaks_the_rule(measurement):
    grown = copy.deepcopy(measurement)
    grown["scan_helpers_importers"].append("core.scheduling.dispatcher")
    assert cm.layer_rule_problems(grown) == [
        "scan_helpers is the scans capability's: core.scheduling.dispatcher "
        "(scheduling) imports it (E1)"
    ]


def test_the_platform_loading_audit_breaks_the_rule(measurement):
    grown = copy.deepcopy(measurement)
    grown["load_profiles"]["ccure_platform.api"]["capabilities"].append("scans")
    assert cm.layer_rule_problems(grown) == [
        "the platform loads no Audit model: importing ccure_platform.api loads "
        "['scans'] (E1)"
    ]


@pytest.mark.parametrize("entry", cm.PINNED_ENGINES)
def test_a_pinned_engine_loading_redis_breaks_e2(measurement, entry):
    grown = copy.deepcopy(measurement)
    grown["load_profiles"][entry]["third_party"].append("redis")
    assert (
        f"library engine: importing {entry} loads ['redis'], which an engine "
        "library may never load (E2)"
    ) in cm.library_problems(grown["load_profiles"])


def test_a_rewritten_baseline_cannot_admit_a_layer_breach(measurement):
    grown = copy.deepcopy(measurement)
    grown["scan_helpers_importers"].append("routers.scan_schedules")
    problems = cm.ratchet_problems(grown, cm.baseline_from(grown))
    assert any("scan_helpers is the scans capability's" in p for p in problems)


# ── Mutations of the source, on a copy of the tree ──────────────────────────


@pytest.fixture(scope="module")
def tree_copy(tmp_path_factory):
    root = tmp_path_factory.mktemp("g3") / "Backend"
    skip_top = {"tests", "data", "reports", "logs"}

    def ignore(directory, names):
        here = Path(directory)
        return [
            n
            for n in names
            if n.startswith(".")
            or n == "__pycache__"
            or (here == BACKEND_ROOT and n in skip_top)
            or ((here / n).is_file() and not n.endswith((".py", ".yaml", ".json")))
        ]

    shutil.copytree(BACKEND_ROOT, root, ignore=ignore)
    return root


@pytest.mark.parametrize(
    "module, line, expected",
    [
        (
            "core/discovery/engine.py",
            "from db.models.assets import Asset  # mutation",
            "engines-are-libraries: core.discovery.engine (discovery, layer 3)",
        ),
        (
            "core/scheduling/dispatcher.py",
            "import scan_helpers  # mutation",
            "scan_helpers is the scans capability's: core.scheduling.dispatcher",
        ),
        (
            "engines/port/port_engine.py",
            "import redis  # mutation",
            "importing engines.port.port_engine loads ['redis']",
        ),
    ],
)
def test_a_source_mutation_fails(tree_copy, module, line, expected):
    path = tree_copy / module
    original = path.read_text(encoding="utf-8")
    path.write_text(original + f"\n{line}\n", encoding="utf-8")
    cm._tree.cache_clear()  # parsed files are cached by path
    try:
        mutated = cm.measure(tree_copy)
    finally:
        path.write_text(original, encoding="utf-8")
        cm._tree.cache_clear()
    problems = cm.layer_rule_problems(mutated) + cm.library_problems(
        mutated["load_profiles"]
    )
    assert any(expected in p for p in problems), problems


# ── The registrations the ports depend on ────────────────────────────────────


@pytest.mark.parametrize(
    "registration",
    [
        "ccure_audit.vendor_cache",
        "ccure_audit.engine_ports",
        "ccure_audit.topology_directory",
    ],
)
def test_the_worker_and_the_api_load_the_registration(registration):
    from core.celery_app import celery_app

    assert registration in celery_app.conf.imports
    assert registration in celery_app.loader.default_modules


def test_the_registrations_answer_once_loaded():
    from core.celery_app import celery_app

    celery_app.loader.import_default_modules()
    from core import mac_vendor_cache, oui_lookup
    from core.nmap import wrapper
    from core.topology import directory
    from core.vuln_intel_repository import REPOSITORY
    from engines.credentialed import vuln_matcher

    assert oui_lookup._shared_cache() is mac_vendor_cache.STORE
    assert wrapper._lease_client is not None and wrapper._cache_client is not None
    assert vuln_matcher.registered_cve_repository() is REPOSITORY
    assert directory.directory().scan_targets is not None

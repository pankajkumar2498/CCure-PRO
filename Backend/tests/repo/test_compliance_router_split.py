"""
The compliance router is mounted from its parts, and its reports are rendered
by renderers (G6, C8; docs/architecture/MODULAR_REFACTORING_LOG.md §6).

``routers/compliance.py`` was 7,481 lines. Its routes now live in
``routers/compliance_{catalogue,assessment,attestation,schedules,remediation,
reports,framework_reports,common}.py``, mounted by ``routers/compliance.py`` in the order the API
always listed them, and its 21 PDF/DOCX generators in ``reporting/compliance/``
(20 from G6; the executive report's joined them in G2).
These pin:

* every compliance route keeps ``routers.compliance`` as its module, so its
  limiter key, gateway policy entry and model names are unchanged;
* the routes are listed section by section in their historical order;
* ``routers.compliance`` refuses a patch, naming the part to patch instead;
* every name the old module defined is still importable from it, as the same
  object;
* the renderers import nothing of compliance, no model and no database code;
* no compliance router module regrows past the analysis's 1,500-line target.
"""

import ast
import importlib
import inspect

import pytest

from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

PARTS = (
    "routers.compliance_assessment",
    "routers.compliance_attestation",
    "routers.compliance_catalogue",
    "routers.compliance_common",
    "routers.compliance_framework_reports",
    "routers.compliance_remediation",
    "routers.compliance_reports",
    "routers.compliance_schedules",
)

#: The first path of each section, in the order the API has always listed them.
SECTION_ORDER = (
    "/compliance/marketplace",
    "/compliance/policies",
    "/compliance/scans",
    "/compliance/findings",
    "/compliance/controls/{control_id}/attest",
    "/compliance/frameworks/{framework_id}/controls",
    "/compliance/controls/{control_id}/evidence",
    "/compliance/scans/{run_id}",
    "/compliance/schedules",
    "/compliance/credentials",
    "/compliance/findings/{id}/remediate",
    "/compliance/remediations/requests",
    "/compliance/findings/{id}/exception",
    "/compliance/summary",
    "/compliance/reports/soa",
    "/compliance/reports/cis_v8_1",
)

#: Shared reads the split introduced, which the old module never offered.
NEW_IN_G6 = {"_findings_with_assets", "_asset_of"}


def _compliance_routes():
    from routers.compliance import router

    return [r for r in router.routes if hasattr(r, "endpoint")]


def test_every_route_keeps_the_routers_module():
    routes = _compliance_routes()
    assert len(routes) == 47
    handlers = [inspect.unwrap(r.endpoint) for r in routes]
    assert {h.__module__ for h in handlers} == {"routers.compliance"}
    assert {h.__code__.co_filename.rsplit("/", 1)[1] for h in handlers} == {
        f"{p.rsplit('.', 1)[1]}.py" for p in PARTS if not p.endswith("common")
    }


def test_the_sections_are_listed_in_their_historical_order():
    paths = [r.path for r in _compliance_routes()]
    firsts = [paths.index(p) for p in SECTION_ORDER]
    assert firsts == sorted(firsts)


def test_the_limiter_keys_are_the_routers():
    from core.rate_limiter import limiter

    keys = {k for k in limiter._route_limits if "compliance" in k}
    assert keys and all(k.startswith("routers.compliance.") for k in keys)
    assert not any(k.startswith("routers.compliance_") for k in keys)


def test_the_router_refuses_a_patch_and_names_the_part():
    import routers.compliance as facade

    with pytest.raises(AttributeError, match="routers.compliance_attestation"):
        facade.scan_for_malware = None
    with pytest.raises(AttributeError):
        del facade.control_sort_key


def test_every_name_the_parts_define_is_offered_by_the_router():
    import routers.compliance as facade

    for name in PARTS:
        part = importlib.import_module(name)
        tree = ast.parse((BACKEND_ROOT / (name.replace(".", "/") + ".py")).read_text())
        for node in tree.body:
            if (
                isinstance(node, (ast.FunctionDef, ast.ClassDef))
                and node.name not in NEW_IN_G6
            ):
                assert getattr(facade, node.name) is getattr(part, node.name), node.name


def test_the_renderers_import_nothing_of_compliance():
    _, edges = collect_edges()
    beyond = sorted(
        (e.src, e.dst)
        for e in edges
        if e.src.startswith("reporting.compliance")
        and not e.dst.startswith("reporting.compliance")
    )
    assert beyond == []
    assert capability_map.capability_of("reporting.compliance.soa") == "renderers"


def test_the_generators_are_renderers():
    generators = []
    for path in sorted((BACKEND_ROOT / "reporting" / "compliance").glob("*.py")):
        tree = ast.parse(path.read_text())
        generators += [
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("_generate_")
        ]
    # 20 moved in G6, and the executive report's in G2.
    assert len(generators) == 21
    for name in PARTS + ("routers.compliance",):
        source = (BACKEND_ROOT / (name.replace(".", "/") + ".py")).read_text()
        assert "def _generate_" not in source, name


@pytest.mark.parametrize("name", PARTS + ("routers.compliance",))
def test_no_compliance_router_module_regrows_past_the_target(name):
    path = BACKEND_ROOT / (name.replace(".", "/") + ".py")
    assert len(path.read_text().splitlines()) <= 1500

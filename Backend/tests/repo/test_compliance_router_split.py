"""
The compliance reports are rendered by renderers (G6, C8;
docs/architecture/MODULAR_REFACTORING_LOG.md §6).

The 20 PDF/DOCX generators that lived in ``routers/compliance.py`` are in
``reporting/compliance/``, and the routes hand them what they read. These pin:

* the renderers import nothing of compliance, no model and no database code;
* all twenty are there, and none is left in the router.
"""

import ast

from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT


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


def test_the_twenty_generators_are_renderers():
    generators = []
    for path in sorted((BACKEND_ROOT / "reporting" / "compliance").glob("*.py")):
        tree = ast.parse(path.read_text())
        generators += [
            n.name
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name.startswith("_generate_")
        ]
    assert len(generators) == 20
    source = (BACKEND_ROOT / "routers" / "compliance.py").read_text()
    assert "def _generate_" not in source

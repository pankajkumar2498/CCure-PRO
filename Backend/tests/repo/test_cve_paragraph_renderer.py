"""
The CVE paragraph is a renderer's helper (G6;
docs/architecture/MODULAR_REFACTORING_LOG.md §6).

``make_pdf_cve_paragraph`` lived in ``scan_helpers``, and the web scan's PDF
renderer imported it from there: the one edge that kept web DAST in the
capability cycle at the end of Phase B. It lives in
``reporting/report_helpers.py`` now. These pin:

* the web PDF renderer imports nothing of the scans capability;
* web DAST is in no capability cycle;
* the old name is the same function, and loading ``scan_helpers`` still does
  not load it (or ReportLab) until something asks for it.
"""

import scan_helpers
from reporting import report_helpers
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges


def test_the_web_pdf_renderer_imports_nothing_of_the_scans_capability():
    _, edges = collect_edges()
    into_scans = sorted(
        e.dst
        for e in edges
        if e.src == "reporting.web_pdf_generator"
        and capability_map.capability_of(e.dst.split(":")[0]) == "scans"
    )
    assert into_scans == []


def test_web_dast_is_in_no_capability_cycle():
    cycles = capability_map.measure()["cycles"]
    assert not any("web_dast" in cycle for cycle in cycles)


def test_the_old_name_is_the_renderers_function():
    assert "make_pdf_cve_paragraph" not in vars(scan_helpers)
    assert scan_helpers.make_pdf_cve_paragraph is report_helpers.make_pdf_cve_paragraph

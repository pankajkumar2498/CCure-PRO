"""
B7: the report renderers import no engine.

``reporting/pdf_generator.py`` imported the credentialed audit's coverage rows
(``engines.credentialed.coverage``) and the sentence describing a truncated
candidate search (``core.candidate_enumeration``, which loads the
vulnerability-intelligence database layer). Both now travel with the payload as
``report_inputs``, built by ``scans.report_inputs.with_report_inputs`` when a
report is rendered, and the renderer refuses a payload without them.

These pin the purpose (no renderer imports anything but renderers and the check
kernel, and the PDF renderer loads no engine or database module), the refusals,
what the inputs carry, and that both production callers attach them. The
orchestrator's caller swallows every exception into "no report", so a caller
that forgot would otherwise fail silently. B7's byte-identical golden capture
is recorded in the refactoring log (§6).
"""

import ast
import json
import subprocess
import sys

import pytest

from core.candidate_enumeration import describe
from engines.credentialed.coverage import COVERAGE_ROWS
from reporting.pdf_generator import (
    ScanReportGenerator,
    _report_inputs,
    _truncated_searches_row,
)
from scans.report_inputs import report_inputs, with_report_inputs
from scripts.architecture import capability_map
from scripts.architecture.import_graph import collect_edges
from testpaths import BACKEND_ROOT

TRUNCATED = [
    {"host": "10.0.0.5", "port": 22, "search": "openssh", "source": "nvd", "cap": 500},
    {"host": "10.0.0.6", "search": "cpe:/o:linux:linux_kernel:6.8", "cap": 2000},
]


def test_no_renderer_imports_beyond_renderers_and_the_check_kernel():
    """Lazy imports count; they are how the codebase hid its couplings."""
    _, edges = collect_edges()
    beyond = sorted(
        (e.src, e.dst)
        for e in edges
        if capability_map.capability_of(e.src) == "renderers"
        and capability_map.capability_of(e.dst) not in ("renderers", "check_kernel")
    )
    assert beyond == []


_IMPORT = r"""
import json, sys
import reporting.pdf_generator
print(json.dumps(sorted(
    m for m in sys.modules
    if m.split(".")[0] in ("engines", "sqlalchemy", "config", "db")
    or m in ("core.candidate_enumeration", "core.vuln_intel")
)))
"""


def test_importing_the_pdf_renderer_loads_no_engine_or_database():
    done = subprocess.run(
        [sys.executable, "-c", _IMPORT],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    assert json.loads(done.stdout.strip().splitlines()[-1]) == []


def test_a_payload_without_inputs_is_refused(tmp_path):
    with pytest.raises(ValueError, match="with_report_inputs"):
        ScanReportGenerator(output_dir=str(tmp_path)).generate_technical_pdf(
            {"data": [], "summary": {}, "metadata": {}}, "vulnerability_audit"
        )
    with pytest.raises(ValueError, match="with_report_inputs"):
        _report_inputs({"report_inputs": {"coverage_rows": []}})


def test_notes_that_do_not_match_the_truncations_are_refused():
    summary = {"candidate_searches_truncated": TRUNCATED}
    with pytest.raises(ValueError, match="1 of the 2"):
        _truncated_searches_row({}, summary, {"summary": ["only one"]})
    with pytest.raises(ValueError, match="0 of the 2"):
        _truncated_searches_row({}, summary, {"metadata": ["wrong source", "x"]})


def test_the_inputs_carry_the_engines_own_rows_and_sentences():
    meta = {"candidate_searches_truncated": TRUNCATED[1:]}
    summary = {"candidate_searches_truncated": TRUNCATED}
    inputs = report_inputs(meta, summary)
    assert inputs["coverage_rows"] == [list(row) for row in COVERAGE_ROWS]
    assert inputs["truncated_search_notes"] == {
        "summary": [describe(t) for t in TRUNCATED],
        "metadata": [describe(t) for t in TRUNCATED[1:]],
    }
    # A source that recorded nothing gets no notes: absent stays absent.
    assert report_inputs({}, {})["truncated_search_notes"] == {}


def test_wrapping_copies_the_payload_and_leaves_it_alone():
    result = {"data": [], "summary": {"candidate_searches_truncated": TRUNCATED}}
    wrapped = with_report_inputs(result)
    assert "report_inputs" not in result
    assert wrapped["summary"] is result["summary"]
    assert wrapped["report_inputs"] == report_inputs({}, result["summary"])


@pytest.mark.parametrize(
    "module", ["routers/reports.py", "orchestrator/scan_orchestrator.py"]
)
def test_both_production_callers_attach_the_inputs(module):
    tree = ast.parse((BACKEND_ROOT / module).read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("generate", "generate_technical_pdf")
    ]
    assert calls, f"{module} no longer renders a scan report"
    for call in calls:
        first = call.args[0] if call.args else None
        assert (
            isinstance(first, ast.Call)
            and getattr(first.func, "id", None) == "with_report_inputs"
        ), f"{module}:{call.lineno} renders a payload without report_inputs"


def test_the_router_regenerates_both_reports_with_the_inputs(
    db_session, monkeypatch, tmp_path
):
    """
    The regeneration path a report download takes when no file is stored:
    routers.reports._load_scan_report_paths, against the database. Only the
    stored-payload reader is replaced, with a payload that carries coverage
    rows and truncated searches, so the router's own wiring is what runs.
    """
    import copy
    import os
    import uuid

    import routers.reports as reports
    from db.models import Organization, Scan, ScanPhase
    from testpaths import SCRIPTS_DIR

    sys.path.insert(0, str(SCRIPTS_DIR / "verification"))
    from verify_report_integrity import SAMPLE_PAYLOAD

    org_id = f"org_{uuid.uuid4().hex[:8]}"
    db_session.add(
        Organization(
            id=org_id,
            name="B7",
            slug=f"b7-{uuid.uuid4().hex[:8]}",
            is_active=True,
            settings={},
        )
    )
    db_session.flush()
    scan = Scan(
        id=f"scn_b7_{uuid.uuid4().hex[:8]}",
        org_id=org_id,
        scan_no=7,
        target_str="10.0.0.5",
        scan_type="vulnerability_audit",
        pipeline_mode="vulnerability_audit",
        status="complete",
        options={},
    )
    db_session.add(scan)
    db_session.flush()
    db_session.add(
        ScanPhase(
            id=f"sph_{scan.id}_va",
            scan_id=scan.id,
            phase_key="vulnerability_assessment",
            phase_order=3,
            status="complete",
            summary={},
        )
    )
    db_session.flush()
    db_session.expire(scan)

    payload = copy.deepcopy(SAMPLE_PAYLOAD)
    payload.setdefault("metadata", {})[
        "authenticated_checks"
    ] = "Package inventory matched"
    payload.setdefault("summary", {})["candidate_searches_truncated"] = TRUNCATED
    monkeypatch.setattr(
        reports, "build_legacy_scan_results", lambda db, sid: {"phase3": payload}
    )
    monkeypatch.setattr(reports, "_REPORTS_DIR", str(tmp_path))

    paths = reports._load_scan_report_paths(db_session, scan)

    assert set(paths) == {"executive_pdf", "technical_pdf"}
    assert all(os.path.getsize(p) > 0 for p in paths.values())

"""
The findings writer (G3, C3; docs/architecture/MODULAR_REFACTORING_LOG.md §6).

``core/findings/writer.py`` took the findings writes of the modules outside the
findings capability, unchanged. These tests hold what the move must keep true.
"""

import ast

from testpaths import BACKEND_ROOT

WRITER = BACKEND_ROOT / "core" / "findings" / "writer.py"
SYNCER = BACKEND_ROOT / "scans" / "asset_syncer.py"


def _live_definitions(path) -> dict[str, str]:
    """Each top-level name's last definition, the one the module's code calls."""
    found = {}
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.FunctionDef):
            found[node.name] = ast.dump(node)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = ast.dump(node)
    return found


def test_the_writers_value_helpers_are_the_asset_syncers():
    """
    The writer keeps copies of four helpers the asset syncer's identity code
    still uses: the placeholder vocabulary, the test for a real value, the text
    cleaner and the source-name normaliser. Importing them from the asset
    syncer would put the findings capability back above the assets one, so
    they are copied, and must not drift: a placeholder the writer reads as a
    value and the syncer as absence is two answers about one host.

    ``_clean`` is the asset syncer's *second* definition, which replaces its
    first at import and is the one its code calls.
    """
    writer, syncer = _live_definitions(WRITER), _live_definitions(SYNCER)
    for name in ("EMPTY_VALUES", "_has_value", "_clean", "_normalize_source"):
        assert writer[name] == syncer[name], name


def test_the_writers_text_cleaner_is_the_credentialed_syncs():
    """
    ``_clean_text`` came with the credentialed audit's findings code and stays
    in the credentialed sync for its identity code, for the same reason.
    """
    sync = _live_definitions(BACKEND_ROOT / "scans" / "tasks" / "credentialed_sync.py")
    assert _live_definitions(WRITER)["_clean_text"] == sync["_clean_text"]


# ── One writer of the findings tables ───────────────────────────────────────

#: Application modules outside the findings capability that write a findings
#: table in SQL text, which the capability map counts as a reference only.
#: Each needs a reason; a new one is a write that belongs in the writer.
RAW_SQL_WRITERS = {
    "scans.nvd_sync": (
        "the NVD feed sync loads the CVE catalogue into vulnerability_definitions; "
        "it is the feed's ingest, not a scan's finding, and G3 left it "
        "(refactoring log §7)"
    ),
}


def _findings_tables() -> set[str]:
    from scripts.architecture import capability_map as cm

    return {t for t, cap in cm.table_owners().items() if cap == "findings"}


def test_the_registry_makes_findings_and_remediation_one_capability():
    """D-6: the remediation workflow's code and its event table are findings'."""
    from scripts.architecture import capability_map as cm

    assert "remediation" not in cm.CAPABILITIES
    for module in ("core.remediation.workflow", "routers.remediation"):
        assert cm.capability_of(module) == "findings", module
    assert {
        "services",
        "tls_details",
        "http_security_details",
        "vulnerability_definitions",
        "asset_vulnerabilities",
        "finding_remediation_events",
    } == _findings_tables()


def test_only_the_findings_capability_writes_the_findings_tables():
    """
    G3 moved the last three writers outside the capability — the asset syncer,
    the credentialed sync and Audit's purge hook — into core/findings/writer.py.
    A model construction or a bulk insert, update or delete of a findings table
    anywhere else is a write the writer should make.
    """
    from scripts.architecture import capability_map as cm

    tables = _findings_tables()
    foreign = [
        (cap, table)
        for cap, table in cm.measure()["foreign_table_writes"]
        if table in tables
    ]
    assert not foreign, foreign


def test_no_other_module_writes_a_findings_table_in_sql():
    import re

    from scripts.architecture import capability_map as cm
    from scripts.architecture.import_graph import discover_modules

    tables = "|".join(sorted(_findings_tables()))
    statement = re.compile(
        rf"\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+\"?(?:public\.)?(?:{tables})\b",
        re.I,
    )
    writers = set()
    for module, path in discover_modules().items():
        if cm.capability_of(module) == "findings":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and statement.search(node.value)
            ):
                writers.add(module)
    assert writers == set(RAW_SQL_WRITERS), sorted(writers)


def test_the_writer_imports_no_asset_or_scan_model_and_nothing_above_it():
    """
    The asset's change log is the caller's, through ``record_change``, and the
    scan's assessment record is the caller's too: the writer depends only
    downward, so the findings capability no longer needs the assets one to
    write a finding.
    """
    from scripts.architecture import capability_map as cm

    measured = cm.measure()
    outgoing = [
        (src, dst)
        for kind in ("upward_edges", "lateral_edges")
        for src, dst in measured[kind]
        if src == "core.findings.writer"
    ]
    assert not outgoing, outgoing
    imported = set()
    for node in ast.walk(ast.parse(WRITER.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{a.name}" for a in node.names)
        elif isinstance(node, ast.Import):
            imported.update(a.name for a in node.names)
    forbidden = {
        "db.models.assets",
        "db.models.scans",
        "scans.asset_syncer",
        "db.models.Asset",
        "db.models.AssetChangeLog",
        "db.models.Scan",
    }
    assert not imported & forbidden, sorted(imported & forbidden)

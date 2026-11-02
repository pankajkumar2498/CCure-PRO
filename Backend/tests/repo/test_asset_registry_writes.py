"""
The asset registry changes its own rows (1 Nov 2026).

A row loaded from an asset-registry table and then changed is a write, as a
model construction or a bulk update is, but the capability map counts it only
as a reference. Compliance's ``reboot_pending`` mark was such a write until
``core.asset_compliance.mark_reboot_pending`` took it. This is the asset-side
twin of ``test_findings_writer.py``'s row-change guard.
"""

import ast

from row_changes import models_owned_by, rows_changed
from testpaths import BACKEND_ROOT

#: Modules outside the asset registry that still change its rows, each with
#: its reason. Empty since 1 Nov 2026, when the standalone credentialed
#: audit's identity sync moved into core.asset_credentialed; a new entry is a
#: write that belongs to the registry.
KNOWN_ROW_WRITERS: dict = {}


def _changers() -> dict:
    from scripts.architecture import capability_map as cm
    from scripts.architecture.import_graph import discover_modules

    models = models_owned_by("assets")
    found = {}
    for module, path in discover_modules().items():
        if cm.capability_of(module) == "assets":
            continue
        changed = rows_changed(ast.parse(path.read_text(encoding="utf-8")), models)
        if changed:
            found[module] = changed
    return found


def test_the_asset_models_are_the_registrys():
    assert {"Asset", "AssetChangeLog", "AssetNote", "AssetTag"} <= models_owned_by(
        "assets"
    )


def test_the_detector_sees_the_compliance_write_it_exists_for():
    """``_finalize_successful_remediation`` before 1 Nov 2026, in miniature."""
    old = ast.parse(
        "def finalize(db, finding):\n"
        "    asset = db.query(Asset).filter_by(id=finding.asset_id).first()\n"
        "    if asset:\n"
        "        attrs = dict(asset.custom_attributes or {})\n"
        "        attrs['reboot_pending'] = True\n"
        "        asset.custom_attributes = attrs\n"
    )
    assert rows_changed(old, models_owned_by("assets")) == [
        (6, "asset.custom_attributes")
    ]


def test_no_other_module_changes_a_loaded_asset_row():
    found = _changers()
    assert set(found) == set(KNOWN_ROW_WRITERS), {
        m: rows for m, rows in found.items() if m not in KNOWN_ROW_WRITERS
    }


def test_compliance_tasks_load_no_asset_row():
    """Its asset reads and its one write all go through core.asset_compliance."""
    tree = ast.parse((BACKEND_ROOT / "core" / "compliance_tasks.py").read_text())
    imported = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and node.module in ("db.models", "db.models.assets")
        for alias in node.names
    }
    assert not imported & models_owned_by("assets"), imported

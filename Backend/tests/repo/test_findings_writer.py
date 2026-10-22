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

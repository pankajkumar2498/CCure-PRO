"""
Anchors for every filesystem path the test suite needs.

Tests are grouped into subdirectories, so a test module's own depth below
``tests/`` is no longer a constant. Thirty-odd call sites used to spell their
anchors as ``os.path.dirname(os.path.dirname(os.path.abspath(__file__)))``,
which silently resolves one directory short the moment a file moves — and
"one short" is ``tests/`` rather than ``Backend/``, so a seed file lookup
fails with a confusing "no such file" instead of an import error.

Everything here is derived from this module's own location, which sits
directly in ``tests/`` and stays there. Import these rather than counting
``..`` segments:

    from testpaths import BACKEND_ROOT, SCRIPTS_DIR

``tests/`` is on ``sys.path`` for every test, whichever subdirectory it lives
in: the grouping directories are packages, so pytest's rootdir walk stops at
``tests/`` and puts it there.
"""

from pathlib import Path

#: ``Backend/tests`` — the directory holding conftest.py and this module.
TESTS_ROOT = Path(__file__).resolve().parent

#: ``Backend`` — the importable application root.
BACKEND_ROOT = TESTS_ROOT.parent

#: The repository checkout root, one above ``Backend``. ``docs/`` lives here.
REPO_ROOT = BACKEND_ROOT.parent

#: ``Backend/scripts`` — seeders, enrichment scripts and compliance seed JSON.
SCRIPTS_DIR = BACKEND_ROOT / "scripts"

#: ``Backend/core`` — shared engine code some tests read as source text.
CORE_DIR = BACKEND_ROOT / "core"

#: ``Backend/main.py`` — read as source by the framework bootstrap tests.
MAIN_PY = BACKEND_ROOT / "main.py"

__all__ = [
    "TESTS_ROOT",
    "BACKEND_ROOT",
    "REPO_ROOT",
    "SCRIPTS_DIR",
    "CORE_DIR",
    "MAIN_PY",
]

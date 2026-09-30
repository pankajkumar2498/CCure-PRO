"""
Ccure Rank — the module's own test folder (Phase 11.2).

The Rank team's tests live here: inside Backend/tests/, so the suite's
database-safety guards apply, and in this folder, so CODEOWNERS gives them to
the team and tests/repo/test_module_boundaries.py can hold the line.

These first tests pin only the structure Phase 11 created — no Rank
functionality exists yet. The team replaces or extends them as it builds.
"""

from __future__ import annotations

import importlib

import pytest

from ccure_platform.modules import registry
from testpaths import BACKEND_ROOT

PACKAGE = "ccure_rank"
SUBPACKAGES = ("api", "models", "schemas", "services", "repositories")


def test_the_package_imports():
    assert importlib.import_module(PACKAGE).__name__ == PACKAGE


@pytest.mark.parametrize("sub", SUBPACKAGES)
def test_the_agreed_layout_exists(sub):
    importlib.import_module(f"{PACKAGE}.{sub}")
    assert (BACKEND_ROOT / PACKAGE / sub / "__init__.py").is_file()


def test_the_registry_knows_the_module_by_its_manifest():
    m = registry.get("rank")
    assert (m.package, m.db_schema, m.route_prefix, m.task_prefix) == (
        PACKAGE,
        "rank",
        "/rank",
        "ccure.rank",
    )
    assert (BACKEND_ROOT / PACKAGE / "manifest.toml").is_file()
    assert (BACKEND_ROOT / PACKAGE / "README.md").is_file()

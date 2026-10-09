"""
Phase 11.2 — the module boundaries, applied to the real modules.

The proof that each guardrail *catches* a violation is in
``tests/modules/example/test_module_example_proof.py``, against the test-only
module. Here the same checks run over ``ccure_policy``, ``ccure_rank`` and
``ccure_audit`` and must find nothing:

* the generated import rules exist for every non-Audit module and hold on the
  live import graph (``tests/repo/test_architecture_guardrails.py`` fails on any
  violation of any rule, these included);
* every module's declared tables are in its schema and registered to it, and
  the ownership registry's schema-qualified entries agree with the modules'
  schemas;
* no module's source names another module's table;
* every test importing a module lives in that module's test folder;
* CODEOWNERS has an owner line for every module package and test folder, with
  syntactically valid owners (placeholders until the project owner supplies
  real ones).
"""

from __future__ import annotations

import re

import pytest
import yaml

from ccure_platform.modules import registry
from scripts.architecture import layer_rules
from scripts.architecture import module_boundaries as mb
from testpaths import BACKEND_ROOT, REPO_ROOT

OWNERSHIP = BACKEND_ROOT / "scripts" / "architecture" / "table_ownership.yaml"
CODEOWNERS = REPO_ROOT / ".github" / "CODEOWNERS"
TESTS_ROOT = BACKEND_ROOT / "tests"

#: Each non-Audit module's test folder, relative to Backend/tests.
MODULE_TEST_DIRS = {"ccure_policy": "modules/policy_pro", "ccure_rank": "modules/rank"}


@pytest.fixture(scope="module")
def ownership():
    return yaml.safe_load(OWNERSHIP.read_text(encoding="utf-8"))


def _non_audit():
    return [m for m in registry.modules() if m.key != "audit"]


# ── imports ──────────────────────────────────────────────────────────────────
def test_the_isolated_packages_are_the_registrys_non_audit_modules():
    assert layer_rules.MODULE_PACKAGES == tuple(m.package for m in _non_audit())


def test_every_non_audit_module_has_both_generated_rules_in_force():
    names = {r.name for r in layer_rules.RULES}
    for m in _non_audit():
        assert f"module-isolation:{m.package}" in names
        assert f"module-is-private:{m.package}" in names


def test_a_module_may_import_only_itself_the_platform_api_and_the_session_layer():
    rule = next(
        r for r in layer_rules.RULES if r.name == "module-isolation:ccure_policy"
    )
    assert rule.exempt_targets == ("ccure_platform.api", "db.base")
    for forbidden in (
        "ccure_audit",
        "ccure_rank",
        "core",
        "engines",
        "scans",
        "routers",
        "reporting",
        "orchestrator",
        "db",
        "config",
        "ccure_platform",
        "auth",
    ):
        assert forbidden in rule.forbidden, forbidden
    assert "ccure_policy" not in rule.forbidden
    assert "ccure_contracts" not in rule.forbidden


# ── tables ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("key", ["policy_pro", "audit", "rank"])
def test_module_tables_are_in_the_module_schema_and_registered_to_it(key, ownership):
    m = registry.get(key)
    assert mb.module_table_problems(m, registry.module_metadatas(m), ownership) == []


def test_schema_qualified_ownership_entries_match_the_module_schemas(ownership):
    schema_owner = {
        m.db_schema: m.key for m in registry.modules() if m.db_schema != "public"
    }
    for name, entry in ownership["tables"].items():
        if "." in name:
            schema = name.split(".", 1)[0]
            assert schema_owner.get(schema) == entry["owner"], (
                f"{name}: schema {schema!r} belongs to {schema_owner.get(schema)!r}, "
                f"not {entry['owner']!r}"
            )
        else:
            assert entry["owner"] in ("platform", "audit"), (
                f"{name}: a table in 'public' belongs to the platform or Audit; "
                f"module {entry['owner']!r} registers its tables as '<schema>.<table>'"
            )


@pytest.mark.parametrize("m", _non_audit(), ids=lambda m: m.key)
def test_no_module_names_another_modules_table(m, ownership):
    assert mb.foreign_table_references(BACKEND_ROOT / m.package, m.key, ownership) == []


# ── tests ────────────────────────────────────────────────────────────────────
def test_every_module_has_its_own_test_folder():
    for m in _non_audit():
        assert (TESTS_ROOT / MODULE_TEST_DIRS[m.package]).is_dir(), m.key
        # a group folder, not a package (CLAUDE.md, "Test layout")
        assert not (TESTS_ROOT / MODULE_TEST_DIRS[m.package] / "__init__.py").exists()


def test_every_test_importing_a_module_lives_in_that_modules_folder():
    assert mb.misplaced_tests(TESTS_ROOT, MODULE_TEST_DIRS) == []


# ── ownership ────────────────────────────────────────────────────────────────
# The api container mounts only Backend/ and docs/, so .github/ is not
# reachable there; CI runs on a full checkout (the gateway route-policy drift
# test has the same shape).
needs_checkout = pytest.mark.skipif(
    not CODEOWNERS.is_file(),
    reason=".github/CODEOWNERS is not reachable from this checkout",
)


def _required_codeowners_paths():
    paths = [f"/Backend/{m.package}/" for m in registry.modules()]
    paths += [f"/Backend/tests/{d}/" for d in MODULE_TEST_DIRS.values()]
    paths += [
        "/Backend/ccure_platform/",
        "/gateway/",
        "/Backend/tests/modules/example/",
    ]
    return paths


@needs_checkout
def test_codeowners_names_an_owner_for_every_module_and_its_tests():
    assert (
        mb.codeowners_gaps(
            CODEOWNERS.read_text(encoding="utf-8"), _required_codeowners_paths()
        )
        == []
    )


def test_the_codeowners_check_catches_a_missing_or_ownerless_line():
    text = "*  @TODO-project-owner\n/Backend/ccure_rank/\n# /Backend/ccure_policy/ @x\n"
    assert mb.codeowners_gaps(
        text, ["/Backend/ccure_policy/", "/Backend/ccure_rank/"]
    ) == [
        "CODEOWNERS has no rule for /Backend/ccure_policy/",
        "CODEOWNERS rule for /Backend/ccure_rank/ names no owner",
    ]


@needs_checkout
def test_codeowners_owners_are_syntactically_valid():
    owner = re.compile(
        r"^@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:/[A-Za-z0-9._-]+)?$"
    )
    for raw in CODEOWNERS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            pattern, *owners = line.split()
            assert owners, pattern
            for o in owners:
                assert owner.match(o), f"{pattern}: {o!r} is not a GitHub owner"

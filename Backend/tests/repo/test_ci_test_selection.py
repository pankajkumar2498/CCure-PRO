"""scripts/ci/select_tests.py: the one mapping from a change to its tests.

The selector decides what the required pull-request checks run, so its failure
mode matters more than its precision: an unrecognised path must widen the
selection, never narrow it.
"""

import importlib.util

from testpaths import REPO_ROOT

_spec = importlib.util.spec_from_file_location(
    "select_tests", REPO_ROOT / "scripts" / "ci" / "select_tests.py"
)
sel = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sel)


def _groups(*files):
    return sel.select(list(files))["backend"]


def test_baseline_always_runs():
    for files in (
        ["docs/x.md"],
        ["Backend/core/risk.py"],
        ["Frontend/src/modules/audit/a.jsx"],
    ):
        b = _groups(*files)
        assert b["scope"] == "targeted"
        assert {"repo", "security"} <= set(b["groups"])


def test_unmapped_backend_path_widens_to_full():
    assert _groups("Backend/brand_new_package/x.py")["scope"] == "full"
    assert _groups("Backend/tests/fixtures/x.json")["scope"] == "full"


def test_cross_cutting_backend_paths_are_full():
    for f in (
        "Backend/db/models/scans.py",
        "Backend/main.py",
        "Backend/config.py",
        "Backend/requirements.txt",
        "Backend/tests/conftest.py",
        "Backend/tests/rbac_testing.py",
    ):
        assert _groups(f)["scope"] == "full", f


def test_unknown_top_level_directory_is_full():
    assert _groups("mystery/thing.py")["scope"] == "full"


def test_module_change_selects_its_own_group():
    assert "compliance" in _groups("Backend/routers/compliance.py")["groups"]
    assert "scans" in _groups("Backend/scans/cvss.py")["groups"]
    assert _groups("Backend/tests/web/test_a.py")["groups"] == [
        "repo",
        "security",
        "web",
    ]


def test_platform_change_selects_the_shared_groups():
    groups = set(_groups("Backend/ccure_platform/rbac/engine.py")["groups"])
    assert {"auth", "rbac", "audit_boundary", "modules"} <= groups


def test_migration_selects_roundtrip_and_platform_groups():
    r = sel.select(["Backend/alembic/versions/a1.py"])
    assert r["migrations"] is True
    assert r["backend"]["scope"] == "targeted"
    assert "rbac" in r["backend"]["groups"]


def test_frontend_scopes():
    assert sel.select(["docs/a.md"])["frontend"]["scope"] == "none"
    one = sel.select(["Frontend/src/modules/audit/pages/A.jsx"])["frontend"]
    assert one["scope"] == "targeted" and one["related"] == [
        "src/modules/audit/pages/A.jsx"
    ]
    for f in (
        "Frontend/package-lock.json",
        "Frontend/src/shell/x.jsx",
        "Frontend/src/design-system/a.jsx",
    ):
        assert sel.select([f])["frontend"]["scope"] == "full", f


def test_full_request_selects_everything():
    r = sel.select([], full=True)
    assert r["backend"]["scope"] == "full" and r["frontend"]["scope"] == "full"
    assert sel.pytest_args(r["backend"]) == []


def test_every_selected_group_is_a_real_test_directory():
    names = {p.name for p in (REPO_ROOT / "Backend" / "tests").iterdir() if p.is_dir()}
    assert sel.KNOWN_GROUPS <= names
    for _, groups in sel.BACKEND_AREAS:
        assert set(groups) <= sel.KNOWN_GROUPS


def test_groups_whose_tests_import_a_module_are_selected_with_it():
    # Found by checking the ownership table against the tests: each of these is
    # imported by tests outside the group that owns the file.
    assert "auth" in _groups("Backend/core/rate_limiter.py")["groups"]
    assert "rbac" in _groups("Backend/scans/progress.py")["groups"]
    assert "scans" in _groups("Backend/ccure_platform/api.py")["groups"]
    assert "web" in _groups("Backend/core/scan_control.py")["groups"]
    assert "audit" in _groups("Backend/core/upload_guard.py")["groups"]


def test_patch_strings_count_as_references():
    refs, _ = sel._test_references()
    assert any(n.startswith("core.tasks") for names in refs.values() for n in names)


def test_openapi_contract_change_is_not_a_full_run():
    assert _groups("Backend/openapi.json")["scope"] == "targeted"


def test_chromium_runs_only_for_visual_paths_or_a_full_run():
    def fe(f):
        return sel.select([f])["frontend"]

    assert fe("Frontend/src/modules/audit/pages/A.jsx")["browser"] is False
    for f in (
        "Frontend/browser-tests/closure.spec.mjs",
        "Frontend/src/design-system/Button.jsx",
        "Frontend/src/styles/app.css",
        "Frontend/playwright.config.mjs",
    ):
        assert fe(f)["browser"] is True, f
    assert sel.select([], full=True)["frontend"]["browser"] is True
    assert sel.select(["docs/a.md"])["frontend"]["browser"] is False


def test_documentation_beside_the_tests_is_not_a_full_run():
    # Found when the first pull request (which edited tests/README.md) selected
    # the whole backend suite.
    assert _groups("Backend/tests/README.md")["scope"] == "targeted"
    assert _groups("Backend/tests/fixtures/x.json")["scope"] == "full"

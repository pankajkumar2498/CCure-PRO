"""
The pre-commit hook that regenerates ``Backend/openapi.json`` must produce what
CI's OpenAPI Schema Diff Check produces, and must run on the commits that can
change it. A hook that serialised differently would stage a contract CI then
rejects, on every backend commit, which is worse than having no hook.
"""

import re

import yaml

from testpaths import BACKEND_ROOT, REPO_ROOT
from scripts.openapi import generate

CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
PRECOMMIT_CONFIG = REPO_ROOT / ".pre-commit-config.yaml"


def _hook():
    config = yaml.safe_load(PRECOMMIT_CONFIG.read_text(encoding="utf-8"))
    for repo in config["repos"]:
        for hook in repo["hooks"]:
            if hook["id"] == "openapi-contract":
                return hook
    raise AssertionError(
        "openapi-contract hook is missing from .pre-commit-config.yaml"
    )


def test_the_generator_serialises_exactly_as_ci_does():
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    calls = re.findall(r"json\.dumps\(app\.openapi\(\),\s*([^)]*)\)", ci)
    assert (
        calls
    ), "ci.yml no longer generates the contract with json.dumps(app.openapi(), …)"
    kwargs = {f"{key}={value!r}" for key, value in generate.DUMPS_KWARGS.items()}
    for call in calls:
        assert {arg.strip() for arg in call.split(",")} == kwargs, (
            f"ci.yml serialises the contract with ({call}); "
            f"scripts/openapi/generate.py uses {generate.DUMPS_KWARGS}"
        )


def test_the_generator_pins_the_rendering_libraries_requirements_pins():
    pins = generate.pinned_versions()
    assert set(pins) == set(generate.RENDERING_PACKAGES), (
        "requirements.txt must pin fastapi and pydantic with ==: the hook refuses "
        "to generate under any other version, and needs a pin to compare with"
    )


def test_the_hook_runs_last_and_on_the_files_that_can_change_the_contract():
    config = yaml.safe_load(PRECOMMIT_CONFIG.read_text(encoding="utf-8"))
    last = config["repos"][-1]["hooks"][-1]
    assert (
        last["id"] == "openapi-contract"
    ), "the contract is regenerated after the formatters"

    hook = _hook()
    assert hook["pass_filenames"] is False
    # Without it pre-commit hides the line naming what the regeneration
    # changed, and the contract would move inside a commit unannounced.
    assert hook.get("verbose") is True
    files = re.compile(hook["files"])
    for path in (
        "Backend/routers/assets.py",
        "Backend/ccure_platform/identity/router.py",
        "Backend/main.py",
        "Backend/openapi.json",
        "Backend/requirements.txt",
    ):
        assert files.search(path), f"the hook must run when {path} is staged"
    for path in (
        "Backend/tests/repo/test_docs_integrity.py",
        "Frontend/src/App.jsx",
        "docs/ci/BRANCH_PROTECTION.md",
    ):
        assert not files.search(path), f"the hook must not run for {path}"


def test_the_hook_entry_exists():
    entry = _hook()["entry"].split()
    assert (REPO_ROOT / entry[-1]).is_file()
    assert (BACKEND_ROOT / "openapi.json").is_file()

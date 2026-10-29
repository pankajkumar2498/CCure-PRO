"""
tests/repo/test_ci_architecture_guards.py
─────────────────────────────────────────────────────────────────────────────
E3 (docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md §10): the architecture
guards run on every push to GitHub.

Two workflows share the pushes between them, and each half is pinned here:

* ``ci.yml`` — pull requests, pushes to main/master, tags, nightly and manual.
  Its Backend Validation job runs ``check.py``, ``tests/repo`` (every
  selection carries it) and the D1 harness.
* ``architecture.yml`` — a push of any other branch, and nothing else. Its
  branch filter is the complement of ci.yml's, so no push starts both, and its
  test targets are ``scripts/ci/local_guard_tests.sh``'s default set, so the
  local run and the GitHub run cannot drift apart.

Like ``test_ci_postgres_version.py`` this needs the files above ``Backend/``:
it skips in the API container and is live on a CI checkout and in
``local_guard_tests.sh``, which stages the whole repository.
"""

import importlib.util
import re

import pytest
import yaml

from testpaths import REPO_ROOT

WORKFLOWS = REPO_ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
ARCHITECTURE = WORKFLOWS / "architecture.yml"
LOCAL_SCRIPT = REPO_ROOT / "scripts" / "ci" / "local_guard_tests.sh"
SELECTOR = REPO_ROOT / "scripts" / "ci" / "select_tests.py"

STDLIB_GUARDS = "Backend/scripts/architecture/check.py"
HARNESS = "-m scripts.architecture.library_isolation"

pytestmark = pytest.mark.skipif(
    not all(p.is_file() for p in (CI, ARCHITECTURE, LOCAL_SCRIPT, SELECTOR)),
    reason=f"the workflows and scripts/ci are not reachable from {REPO_ROOT} "
    "(the API container mounts Backend/ only); this test runs on the CI checkout",
)


def _load(path):
    workflow = yaml.safe_load(path.read_text())
    # YAML 1.1 reads a bare `on:` key as the boolean True.
    workflow["on"] = workflow.pop(True, workflow.get("on"))
    return workflow


def _job(workflow, job_id):
    return workflow["jobs"][job_id]


def _runs(job):
    return [step.get("run", "") for step in job["steps"]]


def _index(job, needle, *, key="run"):
    for i, step in enumerate(job["steps"]):
        if needle in str(step.get(key, "")):
            return i
    raise AssertionError(f"no step with {needle!r} in its {key}")


def test_the_two_workflows_split_branch_pushes_without_overlap():
    ci, arch = _load(CI)["on"], _load(ARCHITECTURE)["on"]

    assert set(ci["push"]["branches"]) == {"main", "master"}
    assert set(ci["pull_request"]["branches"]) == {"main", "master"}
    assert set(arch["push"]["branches-ignore"]) == set(ci["push"]["branches"])
    # A push of a branch only: no pull_request (ci.yml's), no tags (ci.yml's
    # full run), no schedule, no path filter that could skip a change the
    # guard tests read (they read docs, workflows and the frontend too).
    assert set(arch) == {"push"}
    assert set(arch["push"]) == {"branches-ignore"}


def test_every_push_runs_the_stdlib_guards_first_and_the_harness():
    for path, job_id in (
        (CI, "backend-validation"),
        (ARCHITECTURE, "architecture-guards"),
    ):
        job = _job(_load(path), job_id)
        guards = _index(job, STDLIB_GUARDS)
        assert guards < _index(job, "actions/setup-python", key="uses"), (
            f"{path.name}: check.py is standard library only and should fail "
            "before the dependency install, not after it"
        )
        _index(job, HARNESS)


def test_ci_carries_tests_repo_in_every_selection():
    spec = importlib.util.spec_from_file_location("select_tests", SELECTOR)
    selector = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(selector)
    assert "repo" in selector.BASELINE


def test_the_architecture_workflow_runs_the_local_scripts_default_set():
    script = LOCAL_SCRIPT.read_text()
    block = re.search(r"DEFAULT_TARGETS=\((.*?)\)", script, re.S)
    assert block, "DEFAULT_TARGETS not found in local_guard_tests.sh"
    local = block.group(1).split()

    job = _job(_load(ARCHITECTURE), "architecture-guards")
    pytest_run = job["steps"][_index(job, "python -m pytest")]["run"]
    remote = [tok for tok in pytest_run.split() if tok.startswith("tests/")]

    assert remote == local


def test_the_architecture_workflow_matches_ci_s_services_and_token():
    ci = _load(CI)
    arch = _load(ARCHITECTURE)
    ci_services = _job(ci, "backend-validation")["services"]
    arch_services = _job(arch, "architecture-guards")["services"]
    # test_ci_postgres_version.py holds ci.yml to production's major.
    assert arch_services["postgres"]["image"] == ci_services["postgres"]["image"]
    assert arch_services["redis"]["image"] == ci_services["redis"]["image"]
    assert arch["permissions"] == {"contents": "read"}

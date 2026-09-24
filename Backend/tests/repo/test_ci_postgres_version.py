"""
tests/repo/test_ci_postgres_version.py
─────────────────────────────────────────────────────────────────────────────
CI must test against the PostgreSQL major version production runs.

Why this exists
───────────────
Production moved to PostgreSQL 18 on 17 Sep 2026 (the ``db`` service in
``docker-compose.yml``). The CI workflow's ``postgres`` service container stayed
on 15, so every migration, constraint and query the backend suite proved was
proven on a server nobody deploys. Nothing noticed, because the two version
strings live in different files and neither mentions the other.

Only the *major* is compared. A patch release is not a compatibility boundary,
and pinning the two to the same minor would make this fail on every routine
image bump.

Where it runs
─────────────
Both files sit above ``Backend/``. The API container mounts ``./Backend`` alone,
so there they are absent and the test skips, saying so. On the CI runner the
whole checkout is present and the test is live — which is the place it has to
be, because that is where the workflow file takes effect.
"""

import re

import pytest
import yaml

from testpaths import REPO_ROOT

WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
COMPOSE = REPO_ROOT / "docker-compose.yml"

_MAJOR = re.compile(r"^postgres:(\d+)(?:[.\-]|$)")


def _major(image: str, where: str) -> int:
    match = _MAJOR.match(image or "")
    assert match, (
        f"{where} uses PostgreSQL image {image!r}, which names no major version. "
        "Pin a major (e.g. postgres:18-alpine); a floating tag changes the "
        "server under the suite without any commit saying so."
    )
    return int(match.group(1))


def test_ci_postgres_major_matches_production():
    present = [p for p in (WORKFLOW, COMPOSE) if p.is_file()]
    if not present:
        pytest.skip(
            "neither .github/workflows/ci.yml nor docker-compose.yml is reachable "
            f"from {REPO_ROOT} (the API container mounts Backend/ only); "
            "this test runs on the CI checkout"
        )
    assert (
        len(present) == 2
    ), f"only {present[0]} is reachable; both files are needed to compare versions"

    workflow = yaml.safe_load(WORKFLOW.read_text())
    compose = yaml.safe_load(COMPOSE.read_text())

    ci_image = workflow["jobs"]["backend-validation"]["services"]["postgres"]["image"]
    prod_image = compose["services"]["db"]["image"]

    ci_major = _major(ci_image, "ci.yml backend-validation")
    prod_major = _major(prod_image, "docker-compose.yml db")

    assert ci_major == prod_major, (
        f"CI tests against PostgreSQL {ci_major} ({ci_image}) but production "
        f"runs {prod_major} ({prod_image}). Change the two together."
    )

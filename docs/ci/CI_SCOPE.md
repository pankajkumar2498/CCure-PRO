# CI scope: targeted on pull requests, full every night

Pull requests are gated on what they change. The full regression runs every
night, on a release tag and on demand. Decided 15 Oct 2026 after the full
backend suite (about 28 minutes, one process) set a 31-minute floor under every
merge.

## The two scopes

| Scope        | When                                                      | What runs                                                                                                                                                                                                                    |
| ------------ | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **targeted** | `pull_request`, push to `main`/`master`                   | Always: Bandit, ruff, OpenAPI contract, gateway hermetic suites, documentation integrity, `tests/repo` and `tests/security`, secret scan, dependency audits, reset validation. Plus the test groups the changed paths map to |
| **full**     | nightly 00:30 IST, `v*` tag, manual (`workflow_dispatch`) | Everything the pipeline ran before: every backend group with coverage, the migration round-trip, the whole vitest suite, the Chromium browser suite                                                                          |

Image builds and Trivy (`images.yml`), the three-engine browser matrix
(`browser-matrix.yml`) and the gateway harness (`gateway.yml`) are not on the
pull-request path; see [BRANCH_PROTECTION.md](BRANCH_PROTECTION.md).

## How a change is mapped

`scripts/ci/select_tests.py` is the one mapping, used by both CI jobs and by
AI agents and developers locally:

```bash
python scripts/ci/select_tests.py --base origin/master   # this branch
python scripts/ci/select_tests.py --files Backend/core/risk.py
python scripts/ci/select_tests.py --full
```

It prints JSON: the backend groups (`pytest_args`), the frontend scope, and
whether a migration or the gateway is touched. It only ever widens when unsure:

- a Backend path it does not recognise, the test harness (`tests/conftest.py`,
  `native_rbac.py`, `rbac_testing.py`), `db/`, `main.py`, `config.py`,
  `requirements.txt` or `openapi.json` selects the whole backend suite;
- a Frontend change to `package*.json`, `vite.config.js`, `modules.config.js`,
  the design system, the shell, styles, `scripts/` or the test setup selects the
  whole vitest suite;
- a Frontend change to the browser tests, Playwright config, UX4G harness,
  design system or styles also runs the Chromium suite on the pull request
  (it otherwise runs only in the full scope);
- no usable base commit (schedule, tag, new branch, force-push) is a full run.

Changing the mapping is a code change to that file; add the case to
`Backend/tests/repo/test_ci_test_selection.py`.

## What the targeted scope gives up

A failure that only a group outside the mapping would show waits for the
nightly run. The mapping is by module ownership, so cross-module effects go
through the shared groups (`repo`, `security`, and `auth`/`rbac`/`audit`/
`modules` for platform changes). The Chromium browser suite no longer runs on
every pull request (only for visual/accessibility paths): UI changes must still be checked in a browser by the author
(`docs/ux4g/UX4G_STANDARD.md`), and the nightly run is the regression net.
A red nightly run is a task for the owner, not noise.

## Known limit: transitive effects

The mapping is ownership plus **direct use**: the selector adds every test group
whose tests import or `patch` a changed module (found from the tests' own AST).
It does not follow the import graph further. `core` is imported by almost
everything, so a change two imports away from a test can be missed until the
nightly full run. Measured 15 Oct 2026: 0 of 567 backend modules lack a
directly-importing group; 318 still have a transitively-importing group that is
not selected.

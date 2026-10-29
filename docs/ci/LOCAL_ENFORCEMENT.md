# What enforces the architecture rules, and where

The architecture ratchets — layering, import cycles, the identity boundary, the
capability map — and the secret-handling guards are tests. A test protects
nothing unless something runs it before a change lands. This page records what
runs them, when, and what was **not** running when it was written, so that "CI
enforces it" is only said where it is true. Measured 16 Oct 2026.

## The three paths

| Path                                                                                | Runs                                                                                          | Needs                                                                                     | Covers                                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Pre-commit hook `architecture-guards`** (`Backend/scripts/architecture/check.py`) | Every commit that stages backend code (not tests), in ~12 s                                   | Python 3 only — no database, no network                                                   | Layering, module-level import cycles, the identity boundary, organisation-setting references, the capability ratchet, and the sudo-password and session-password guards                                                                                                                                                 |
| **`scripts/ci/local_guard_tests.sh`**                                               | On demand                                                                                     | Docker and the backend image                                                              | The database-backed tests: by default `tests/repo` (all architecture ratchets, table ownership, schema drift, documentation integrity), the sudo-password tests and the credential-API authorization tests, then the library isolation harness (D1); any pytest target can be passed, and then the harness does not run |
| **`scripts/validation/live_scan.sh`**                                               | Before and after a change on a scan path (B2, B3, C2, C3, C6)                                 | Docker, the backend image and the validation targets (`scripts/validation/targets.sh up`) | Live scans of disposable targets on an internal network with one commit's code; `compare_live_scans.py` compares two runs ([`LIVE_SCAN_VALIDATION.md`](LIVE_SCAN_VALIDATION.md))                                                                                                                                        |
| **GitHub Actions** (`.github/workflows/ci.yml`; [CI_SCOPE.md](CI_SCOPE.md))         | Pull requests and pushes **on the `github` remote**, and nightly at 19:00 UTC on its `master` | GitHub-hosted runners                                                                     | Everything above and the rest of the suite                                                                                                                                                                                                                                                                              |

`git commit --no-verify` skips the hook. CLAUDE.md forbids it, and the hook is
fast and environment-independent so that nobody has a reason to.

## What was and was not running, 16 Oct 2026

- **GitHub Actions runs again.** The scheduled full run passed on `23f8e72` at
  21:50 UTC on 15 Oct. The runs earlier that day had failed because the
  account's Actions minutes were blocked, not because of the code.
- **GitHub only tests what reaches the `github` remote.** Since 15 Oct the
  primary remote (`origin`) is the C-DAC GitLab, where merge requests land.
  `github/master` was at `23f8e72` while `origin/master` was at `c0c0f4e`, ten
  commits later. Those ten include a Python base-image bump that no CI run had
  exercised.
- **GitLab runs no pipeline.** The repository has no `.gitlab-ci.yml`, and the
  instance had no usable runner.

Until one of the following happens, the pre-commit hook and the local script
are the only enforcement a GitLab merge request gets:

- every merge to GitLab is also pushed to `github`;
- a GitLab runner is registered;

This choice is decision D-5 in
[`../architecture/MODULE_INDEPENDENCE_ANALYSIS.md`](../architecture/MODULE_INDEPENDENCE_ANALYSIS.md).

## Running them

```bash
python3 Backend/scripts/architecture/check.py      # the stdlib guards, any directory
scripts/ci/local_guard_tests.sh                    # the database-backed guard set, then D1
scripts/ci/local_guard_tests.sh tests/security     # any pytest targets, from Backend/
python3 scripts/ci/select_tests.py --base origin/master   # what CI would select
```

`local_guard_tests.sh` builds everything it uses and removes it on exit:

- a copy of the tracked and untracked-but-not-ignored files, never `.env` or `backups/`;
- a throwaway PostgreSQL and Redis on an internal Docker network;
- credentials generated for that run.

With the default set it then runs the library isolation harness
(`Backend/scripts/architecture/library_isolation.py`, D1) in the backend image,
with no network at all and the staged copy mounted read-only. Each engine
library is imported, and then run by its own tests, in a fresh interpreter
that admits only the modules and packages it declares. The script fails if
either step fails.

It never connects to `ccure-db`. Tests that need the DBA-installed audit chain
skip themselves there with "NOT VERIFIED, not passing"; a run reports those
skips, and they are not passes.

## Keeping this true

When a rule is added to `scripts/architecture/`, add it to `check.py` if it can be
decided from source alone. `tests/repo/test_architecture_check_command.py`
fails if the command stops passing on the tree, stops reporting a breach, or
gains a dependency outside the standard library.

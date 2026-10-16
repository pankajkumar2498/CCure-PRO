# Modular refactoring — execution record

The step-by-step record of the work that follows from
[`MODULE_INDEPENDENCE_ANALYSIS.md`](MODULE_INDEPENDENCE_ANALYSIS.md): what was changed,
how it was tested, and what was decided. Each entry is written when its step is committed.
The analysis says what to do; this records what was done.

## 1. Starting state (16 Oct 2026)

|                              |                                                                                                                                                                                                                                                                                                                            |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Branch                       | `refactor/modular-architecture`, created without upstream tracking, so a stray `git push` cannot target `master`                                                                                                                                                                                                           |
| Base                         | `master` @ `c0c0f4e`, equal to `origin/master` (GitLab). Local `master` was fast-forwarded from `23f8e72` first.                                                                                                                                                                                                           |
| Difference from the analysis | The analysis measured `23f8e72` (`Improvements`). The ten commits up to `c0c0f4e` change documentation, CI action versions, `.env.example` and the Dockerfile's Python base image. `git diff 23f8e72 c0c0f4e -- Backend` touches only `Backend/Dockerfile` and `Backend/.env.example`, so every measurement still applies. |
| Working tree carried over    | `docs/architecture/MODULE_INDEPENDENCE_ANALYSIS.md` (untracked), one row in `docs/architecture/README.md`, and `docs/gap_closure/NESSUS_CAPABILITY_STUDY.md` (untracked, unrelated to this work — carried over and **not** committed here)                                                                                 |
| Concurrent work              | A Codex extension process was running, with no session activity in the preceding two hours and no changed files. Commits were built in a detached worktree; the branch was moved to each commit with `git reset --mixed`, which leaves files untouched.                                                                    |

### Test environment, and its limits

Database-backed tests ran in the release image (`ccure-audit-pro-backend:latest`, `3a0dde6d4580`,
release `3212d6b`) against a throwaway PostgreSQL 18 and Redis 7 on an internal Docker network.
The code under test was a copy of the tracked and untracked-but-not-ignored files: no `.env`,
`backups/` or venv. The schema and catalogue were bootstrapped as CI does
(`migrate_production_schema`, `seed_compliance`, `seed_real_rules`). The live `ccure_db` was
never connected to. `scripts/ci/local_guard_tests.sh` (S4) is this setup, committed.

- **The image sets `ENV=production`.** `core/security_crypto` therefore refuses to fall back to
  the built-in key, and every run needs a throwaway `COMPLIANCE_ENCRYPTION_KEY`. Without one,
  the first S1 baseline attempt failed one test for that reason alone: 28 passed, 1 failed.
- **The image has no `pytest-rerunfailures`,** so CI's `--reruns 1` is not used here.
- **The throwaway database lacks the DBA-installed audit chain and retention bootstrap.** 209
  audit tests skip themselves there with "NOT VERIFIED, not passing". They are reported as
  skipped, never as passed.
- **The frontend was not changed.** For every step, `select_tests.py` reports frontend scope `none`.

## 2. Phase 0

| Item | Commit    | Change                                                                                                                                                                                                                                                                                          |
| ---- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S1   | `6925b2b` | Compliance remediation sends the sudo password on the remote command's stdin (`SSHScanner.run_sudo`) instead of `echo '<pw>' \| sudo -S`. Commands that pipe into sudo are refused when a password would be needed. Output and errors are redacted. An application-wide source guard was added. |
| S2   | `cb62582` | `core/credential_vault.py`: one credential service. `/credentials` and `/compliance/credentials` both require `audit.credential.read`/`.manage`/`.delete`, with the same rate limits and the canonical audit actions. The legacy path keeps its paths, schemas, status codes and messages.      |
| S3   | `9a32319` | Queue-to-worker mapping recorded and a privilege split proposed ([`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md)). A characterisation test pins the routing. Nothing deployed.                                                                                               |
| S4   | `2d4509d` | `Backend/scripts/architecture/check.py`, the stdlib guards, run as the `architecture-guards` pre-commit hook. `scripts/ci/local_guard_tests.sh` for the database-backed guards. [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md).                                                     |

### Test evidence

Database-backed runs used `python -m pytest -p no:cacheprovider -q -rfEs <targets>` in the
environment above. Every pre-commit hook passed on every commit; prettier reformatted Markdown
tables, which were re-staged.

| Step                 | Command / targets                                                                                                                                                                           | Passed | Failed | Skipped | Notes                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | --------------------------------------------------------------------------- |
| S1 baseline (before) | `tests/credentialed/test_sudo_password_safety.py tests/compliance/test_compliance_remediation.py tests/compliance/test_remediation_safety.py`                                               |     29 |      0 |       0 | First attempt 28/1/0: missing throwaway key (see above)                     |
| S1 after             | same                                                                                                                                                                                        |     47 |      0 |       0 | 18 new tests                                                                |
| S1 mutation          | new tests against `HEAD`'s `core/compliance_tasks.py`                                                                                                                                       |     31 | **12** |       0 | Expected to fail: proves the tests see the vulnerability                    |
| S1 regression        | `tests/compliance tests/credentialed tests/repo tests/scans tests/security` (the selector's groups)                                                                                         |  5,137 |      0 |       1 | Skip: `alembic.ini is already activated`, by design; 341 s                  |
| S2                   | `tests/security/test_credential_api_consolidation.py` + `tests/credentialed/test_windows_winrm.py`, `test_auth_methods.py`, `test_smb_transport.py`, `tests/scans/test_database_content.py` |    630 |      0 |       0 |                                                                             |
| S2 new file alone    | `tests/security/test_credential_api_consolidation.py`                                                                                                                                       |     22 |      0 |       0 |                                                                             |
| S2 mutation          | new file against `HEAD`'s `routers/compliance.py`                                                                                                                                           |     11 | **11** |       0 | The 11 that still pass are the compatibility tests, which must pass on both |
| S2 regression        | `tests/assets tests/audit tests/compliance tests/credentialed tests/rbac tests/repo tests/reports tests/scans tests/security`                                                               |  6,513 |      0 |     210 | 209 audit-chain "NOT VERIFIED" skips, plus the `alembic.ini` one; 496 s     |
| S2 API contract      | `python -m scripts.openapi.generate --check` (Backend venv)                                                                                                                                 |      — |      — |       — | Exit 0: `openapi.json` byte-identical                                       |
| S2 RBAC inventory    | `python -m scripts.rbac.build_migration_inventory --check`                                                                                                                                  |      — |      — |       — | "inventory is current" after `--write`                                      |
| S3 + S4              | `tests/repo/test_worker_queue_mapping.py tests/repo/test_architecture_check_command.py tests/credentialed/test_sudo_password_safety.py`                                                     |     54 |      0 |       0 |                                                                             |
| S4 command           | `python3 Backend/scripts/architecture/check.py`                                                                                                                                             |      — |      — |       — | Exit 0; 4.8 s                                                               |
| S4 negative          | the same command on a scratch copy with an injected layer breach, piped-sudo f-string and identity import                                                                                   |      — |      — |       — | Exit 1; layering, cycles, identity and secret handling all reported         |
| S4 hook              | `pre-commit run architecture-guards --all-files`, and inside the S4 commit                                                                                                                  |      — |      — |       — | Passed                                                                      |
| S4 runner            | `scripts/ci/local_guard_tests.sh` (default targets)                                                                                                                                         |    770 |      0 |       1 | Exit 0; no containers or networks left behind                               |

Not run during Phase 0: the full backend suite as one run (its groups were covered by the two
regression runs above, apart from `auth`, `topology`, `web` and `modules`), the frontend suites
and the browser suites. No frontend file changed.

### Behaviour that changed, by design

- **S1:** a remediation that pipes into sudo (`echo X | sudo tee F`) now fails, with a reason,
  when the credential has a password. Three parked NIS2 fix commands have this shape. The old
  code wrote an empty file, or, where sudo needed no password, wrote the password itself into
  the file.
- **S2:** on `/compliance/credentials`:

  - `platform.viewer`, and any role holding only compliance permissions, are refused (403);
  - `platform.scanner` may now list credentials;
  - `platform.analyst` may create;
  - an inactive home organisation is refused;
  - new rows get canonical ids and `ssh`/`ssh` type and transport;
  - the audit actions are `credential.created`/`.deleted` (HIGH) instead of
    `create_credential`/`delete_credential`, which no severity table classified.

  `audit.compliance.manage_integrations` now gates no route.

## 3. Phase A

### A1 — authoritative documentation (this revision)

The current-state documents:

- [`README.md`](README.md) is the map;
- [`MODULE_INDEPENDENCE_ANALYSIS.md`](MODULE_INDEPENDENCE_ANALYSIS.md) is the measured state and
  the plan;
- this file is the execution record.

The analysis keeps its 16 Oct measurements as the baseline. §0 records progress, and three
statements about CI were corrected in place, marked "Corrected". The September baseline and
plan revision 4 stay outside the repository, as the owner instructed at the time; committing
them as history is D-9. No other documentation was reorganised.

Tests (selector: `repo`, `security`): `tests/repo tests/security` → 957 passed, 0 failed, 1 skipped
(the `alembic.ini` skip).

## 4. Decisions awaiting the project owner

| #   | Decision                                                                                                                                                | From                                                               |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| D-4 | Approve the worker privilege split (S3)                                                                                                                 | [`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md) |
| D-5 | Push every GitLab merge to `github`, or register a GitLab runner                                                                                        | [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)         |
| D-9 | Commit the September baseline and plan rev 4 under `docs/archive/architecture/`, or not                                                                 | analysis §13                                                       |
| new | Retire or repurpose `audit.compliance.manage_integrations`, which now gates no route                                                                    | S2                                                                 |
| new | Rewrite the three NIS2 remediations that pipe into sudo as `sudo sh -c '…'` (seeded catalogue data)                                                     | S1                                                                 |
| new | Align the compliance workspace's credential buttons (gated on `manage_frameworks`) and the scan pickers' error handling with the credential permissions | S2                                                                 |

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
- **The frontend was not changed until S2b**, which changed one comment (§4). For every earlier
  step, `select_tests.py` reports frontend scope `none`.

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

### A2 — capability map and ratchet

`Backend/scripts/architecture/capability_map.py` (stdlib only) classifies all 481 backend
modules into 29 capabilities. Layers follow the analysis §8.2. Its ratchet fails when coupling
grows and when removed coupling is left in the baseline:

- the capabilities in a cycle;
- every upward or lateral module edge;
- every table a capability references or writes that another owns;
- what 25 entry points load.

`capability_baseline.json` holds the detail. Its sizes are capped by `CEILINGS`, which are
pinned in a test at the figures below and may only fall. It runs in the `architecture-guards`
hook and in `tests/repo/test_capability_ratchet.py`.

How the map differs from the analysis's Appendix A, and why:

- **No catch-all for the mixed packages.** `core`, `db`, `routers`, `scans`, `reporting`,
  `orchestrator` and `engines` have no default for their direct children, so a new flat module
  fails until it is classified.
- **`renderers` is a capability.** The report generators are separate from the read side (`reporting.exports`, `routers.reports`).
- **Ambiguous modules, with the reason beside each entry:**
  - `core.scan_scope` → scan kernel;
  - `orchestrator.host_discovery_api` and `routers.health` → scans;
  - `db.migrate_production_schema` → composition root;
  - `core.oui_lookup` and `core.device_classifier` → assets, the owner of the data they use.
- **Model imports are attributed per class.** A class goes to the capability owning its table,
  through `table_ownership.yaml`; the registry's own re-exports are nobody's dependency; relative
  imports between model files are resolved.

Reproduction and reconciliation (`python -m scripts.architecture.capability_map`, from `Backend/`):

| Method                                 | Tree                          | Largest cycle, all / top-level  | Cross-capability imports, top / lazy | Upward | Lateral | Foreign refs | Foreign writes |
| -------------------------------------- | ----------------------------- | ------------------------------- | ------------------------------------ | -----: | ------: | -----------: | -------------: |
| The analysis's own method and grouping | `23f8e72`                     | 23 / 20                         | 424 / 386                            |     57 |       — |            — |              — |
| `capability_map.py`                    | `23f8e72`                     | 22 / 13 (+ `infra`↔`platform`) | 452 / 392                            |     50 |      72 |           80 |             18 |
| `capability_map.py` — **the baseline** | `2d4509d` + A1, after Phase 0 | 22 / 13 (+ `infra`↔`platform`) | 457 / 392                            |     50 |      74 |           80 |             17 |

**The analysis's figures reproduce exactly with its method.** The differences in the second row
are method, not code: the grouping refinements above, and per-class attribution. The analysis's
"57 upward" used the old grouping, and its foreign-table table left out `main` and
`infrastructure`.

Phase 0 moved two figures:

- foreign writes fell from 18 to 17, because compliance no longer writes the vault's table (S2);
- lateral edges rose from 72 to 74: the new credential service reads the scheduling and
  compliance model files.

The two-member top-level cycle is `infra`↔`platform`, through the stdlib module registry that
`core.celery_app` reads, which the layer rules already exempt.

Known limits are stated in the module's docstring:

- an edge is an import, not a call path;
- writes through attribute assignment are counted as references, so write sets are a floor;
- raw SQL is found by table name in literals;
- load profiles ignore `sys.modules` aliasing. They were checked against real imports in the
  release image on 16 Oct.

`check.py` gained the ratchet as a sixth parallel check: 11.3 s wall-clock for the whole command.
Parsing is cached per file, and raw-SQL detection is one pass per module. Both changes leave the
measurement byte-identical.

Tests:

| Command / targets                                                                     | Passed | Failed |           Skipped |
| ------------------------------------------------------------------------------------- | -----: | -----: | ----------------: |
| `tests/repo/test_capability_ratchet.py tests/repo/test_architecture_check_command.py` |     18 |      0 |                 0 |
| `tests/repo tests/security` (selector)                                                |    970 |      0 | 1 (`alembic.ini`) |
| `python -m scripts.architecture.capability_map --check`                               |      — |      — |            exit 0 |
| `pre-commit run architecture-guards --all-files`                                      |      — |      — |            Passed |

The first run of the new tests failed one: `db.migrate_production_schema` does `import db.models`,
a whole-registry import that genuinely loads every model. The test was too strict and was
corrected to allow exactly that form.

### A3 — shared JSON-contract shape tests

`Backend/tests/scans/test_shared_json_contracts.py` (33 tests) pins shape only:

- each writer's output;
- the keys each reader consumes;
- what a reader does with a legacy record that lacks the key.

No stored record, key name or behaviour changes.

**Pinned:**

- **`scans.options["scan_policy"]`**
  - Writer: `core.scan_policy.snapshot.snapshot_payload`.
  - Readers: `read_policy_snapshot`, the reports and the policy-usage query.
  - Pinned: the exact key set; the raw readers' keys (`recorded`, `policy_name`, `fingerprint`, `policy_id`) are written; round trip with sibling keys kept; absent, empty or unrecorded means no policy, and two unknown policies are not comparable.
- **`scans.options["assessment_scope"]`**
  - Writer: `core.findings.record_assessment_scope`, from `core.tasks` and the package matcher.
  - Readers: the comparison and remediation verification.
  - Pinned: shape `{recorded, assets, families, detail}` with sorted string lists; merge rather than replace; unrecorded covers nothing; a missing or malformed check list restricts no check.
- **`scans.options["credentials"]`**
  - Writer: the host-discovery request model.
  - Reader: `core.tasks._credentialed_plan_for_scan`.
  - Pinned: both use `core.credential_scope`; a plan the writer accepts resolves on the reader; no plan means no credentialed pass.
- **The five port options** (`custom_ports`, `exclude_ports`, `exclude_ot_from_nmap`, `passive_first`, `exclude_ips`)
  - Writers: `POST /scan/asset-discovery`, and the schedule dispatcher, which forwards them.
  - Reader: the phase tasks, from `scans.options`.
  - Pinned: every key read is written and forwarded under its own name; the defaults for a missing key (`exclude_ot_from_nmap` true, `passive_first` false).
- **`assets.custom_attributes["credentialed_status"]`**
  - Writers: `scans.asset_syncer.set_credentialed_status` and `core/tasks.py`.
  - Reader: `core.compliance_evidence`.
  - Pinned: vocabulary `success`/`failed` at every write site; reassigned, not mutated; only `success` counts as authenticated; absent means not authenticated.
- **`assets.custom_attributes["password_policy"]`**
  - Writer: `core/tasks.py`, from the collectors.
  - Reader: `core.compliance_evidence`.
  - Pinned: the five keys written are exactly the five read; a collected key reaches compliance; an uncollected one is absent, never defaulted.

**Documented, not pinned** — their contract is not established in one place, so a schema here would be invented:

- **`scans.options["credentialed_report"]`** — three shapes (pipeline-nested, standalone, multi-host list) defined by the collectors. The reporting tests cover them (11 files). This is the typed hand-off of roadmap C6.
- **`scans.options["snmp"]`**
  - Comes from the request's free-form `options`, validated nowhere; read by `core.tasks` and `core.topology.engine`.
  - Candidate for a validator like `validate_credential_options`.
- **`assets.custom_attributes["credentialed_system_info"]`** and **`["provenance"]`** — written in `core/tasks.py` and `scans/asset_syncer.py`, read by compliance adapters and the asset view, with no single definition.
- **`scan_phases.summary`** (`assessed`, `results`, `reason`, `platform`, `network_plugin_coverage`, `scan_duration`) — written per phase by the task hub and read by findings, assets, `ccure_audit` services and reports. Its shape varies by phase, and each reader tolerates absence. This also belongs to C6.

Two observations, recorded and not changed:

- `scan_policy` names two different things: a snapshot dict in `scans.options`, and a preset name in `web_scans.options`.
- `credentialed_status` has two write sites, not the one CLAUDE.md describes, both using the shared constants; the vocabulary test covers both.

Mutation check: three breaks in a scratch copy were each caught (4 failures):

- a flipped reader default;
- a password-policy key dropped from the reader;
- a renamed snapshot key.

Tests: the new file passed 33 of 33.

### Milestone — full backend suite after Phase 0 and Phase A

`python -m pytest -p no:cacheprovider -q -rfEs tests` ran in the environment of §1, on the
complete tree: Phase 0, A1, A2 and A3.

| Passed | Failed | Skipped | Time        |
| -----: | -----: | ------: | ----------- |
|  7,870 |  **0** |     211 | 14 min 28 s |

The 211 skips are all environmental:

- **165** need the audit tamper-evidence chain and **44** the audit-retention bootstrap. Both
  are DBA-installed and absent from a throwaway database; the tests report "NOT VERIFIED, not
  passing".
  - They were deliberately not installed here. The chain's security model assumes the
    application role is not a superuser, and in a throwaway PostgreSQL it is, so running them
    there would test the wrong thing.
  - CI's database has the same limit.
- **1** is the by-design `alembic.ini is already activated` skip.
- **1** needs the live OSV npm feed, which the internal-only test network cannot reach.

The frontend suites were not run: no frontend file changed in Phase 0 or A, and the selector
reports frontend scope `none` for every step.

## 4. S2b — the schedule credential picker

Commit `c12851b`. It was committed in place, without a worktree or a reset: every modified file
was staged, so pre-commit had no unstaged change to stash. The untracked Nessus study was left
as it was. Every hook passed, including `architecture-guards` and `openapi-contract` (no
change to `openapi.json`).

### What changed

- **`GET /scan-schedules/credentials` requires `audit.credential.read`**, the key every other
  credential listing requires, and lists through `credential_vault.list_for_org`. Before, it
  required `audit.scan_schedule.read`. These are unchanged: the response shape (`id`, `name`,
  `username`, `auth_method`, `port`), the 60/minute limit, the ordering by name, and the
  docstring, which is the published OpenAPI description.
- **The schedule router's other two credential reads go through the service too:**

  - the name shown on a schedule (`_serialize`), now read with `get_for_org` for the
    schedule's organisation. The answer cannot differ, because attaching already requires the
    credential to belong to that organisation;
  - the tenant check when a credential is attached (`_validate_credential`), with the same 404
    and message.

  `routers/scan_schedules.py` no longer imports `ComplianceCredential`.

- **Capability baseline:** the lateral edge
  `routers.scan_schedules -> db.models.compliance:ComplianceCredential` is replaced by
  `routers.scan_schedules -> core.credential_vault`. Every count is unchanged: cycle 22/13,
  upward 50, lateral 74, foreign references 80, foreign writes 17. The schedule dispatcher
  (`core/scheduling/dispatcher.py`) still reads `ComplianceCredential` directly; that is C5's
  work and was not touched.
- **Records:**
  - authorization inventory regenerated (`--write`, then `--check`: "inventory is current");
  - the row in `BACKEND_API_REFERENCE.md`;
  - a "superseded" note on `GAP_TRACKER.md` §4.4;
  - the comment above `listScheduleCredentials` in `Frontend/src/modules/audit/api/scanSchedules.js` (a comment only).

Who can list, with the default grants:

| Role                                     | Before | After | Why                                                                                                                                   |
| ---------------------------------------- | ------ | ----- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `platform.viewer`                        | 200    | 403   | Holds `scan_schedule.read`, not `credential.read`. It cannot create or edit a schedule, so it loses no workflow.                      |
| `platform.analyst`, `platform.org_admin` | 200    | 200   | Hold both keys. These are the roles holding `scan_schedule.manage`, so picking a credential for a schedule works as before.           |
| `platform.scanner`                       | 403    | 200   | Holds `credential.read`, not `scan_schedule.read`. Since S2 it can list the same rows at `/credentials`, so nothing new is disclosed. |
| `platform.superadmin`                    | 200    | 200   | Holds every key through materialised grants.                                                                                          |

### Tests

Seven tests (nine cases) were added to
`Backend/tests/security/test_credential_api_consolidation.py`. The route also joined the
file's permission and rate-limit parity tables, which adds one rate-limit case. The file went
from 22 to 32 cases.

- a viewer is refused, and neither the credential's name nor its username appears in the
  response;
- a role holding only `audit.scan_schedule.read`, the route's old key, is refused;
- a role holding only `audit.credential.read` is served;
- the analyst, org-admin and scanner roles are served exactly the five fields, ordered by name,
  with no secret and nothing named `encrypted`;
- another organisation's credential is never listed, including when a caller without the
  organisation-switch grant names that organisation in `?org_id=`;
- the workflow the picker exists for: an analyst lists, picks a credential and creates a
  credentialed schedule. The response carries `credential_name`, and no secret.
- another organisation's credential is still refused when it is attached (404, same message).

| Step                     | Command / targets                                                                                                           | Passed | Failed | Skipped | Notes                                                                                            |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ------------------------------------------------------------------------------------------------ |
| Focused                  | `scripts/ci/local_guard_tests.sh tests/security/test_credential_api_consolidation.py tests/scans/test_scan_schedule_api.py` |     57 |      0 |       0 | Uncommitted tree, before the commit; 43 s with set-up                                            |
| Mutation                 | the consolidation file, on a scratch worktree with the route put back on `audit.scan_schedule.read`                         |     27 |  **5** |       0 | Expected to fail: proves the tests see the disclosure                                            |
| Architecture and secrets | `python3 -I Backend/scripts/architecture/check.py`                                                                          |      — |      — |       — | Exit 0, all six checks `ok`; 11.5 s                                                              |
| Capability ratchet       | `python -m scripts.architecture.capability_map --check`                                                                     |      — |      — |       — | "capability ratchet holds"                                                                       |
| API contract             | `python -m scripts.openapi.generate --check`                                                                                |      — |      — |       — | Exit 0: `openapi.json` unchanged                                                                 |
| RBAC inventory           | `python -m scripts.rbac.build_migration_inventory --check`                                                                  |      — |      — |       — | "inventory is current"                                                                           |
| Frontend                 | `npx vitest related --run src/modules/audit/api/scanSchedules.js` (from `Frontend/`)                                        |     91 |      0 |       0 | 3 files; the change is a comment                                                                 |
| Pre-commit               | every hook, inside the commit                                                                                               |      — |      — |       — | Passed                                                                                           |
| **Full backend suite**   | `scripts/ci/local_guard_tests.sh tests`, on a clean detached worktree of `c12851b`                                          |  7,880 |  **0** |     211 | 14 min 26 s. The milestone's 7,870 plus the 10 new cases; the same 211 environmental skips as §3 |

The mutation run's five failures were these tests:

- the permission parity test;
- the viewer test;
- the old-key-only test;
- the `credential.read`-only test, which a role without `scan_schedule.read` fails on the old key;
- the scanner case.

The other 27 tests do not depend on which key the route answers.

The 211 skips are those of §3's milestone, one for one: 165 need the audit chain, 44 the
retention bootstrap, 1 is the `alembic.ini` skip and 1 the live OSV feed. The run left no
container or network behind.

The selector (`select_tests.py`) named `compliance`, `credentialed`, `repo`, `scans` and
`security` for the backend and the one changed frontend file. The full suite covers every
backend group, so those groups were not also run separately.

### Limitations

- **The first mutation attempt died during set-up.** It printed "starting throwaway PostgreSQL"
  and nothing more, and it reproduced nothing when repeated. The likely cause is that
  `local_guard_tests.sh` checks readiness over the Unix socket. The official PostgreSQL image
  answers there during initdb, then restarts the server, so the second check can land in that
  gap. Checking over TCP (`pg_isready -h 127.0.0.1`), which the init-time server does not
  listen on, would close it. Recorded below, not fixed here: changing the CI tooling is outside
  this task.
- **The published description is now stale.** The route's docstring still says
  `GET /compliance/credentials` "is gated on `compliance:read`". That stopped being true at S2.
  It was left unchanged because editing it changes the published OpenAPI document.
- **What the schedule page does.** `ScanSchedules.jsx` loads the picker when the page opens and
  turns any error into an empty list. It also shows "New schedule" to everyone; that predates
  S2b.
  - **Viewer:** now sees an empty picker. A viewer could never save a schedule (that needs
    `scan_schedule.manage`), so no workflow is lost.
  - **Custom role with `scan_schedule.manage` but not `credential.read`:** would see an empty
    picker with no explanation. This is the "no data ≠ empty result" case in CLAUDE.md. No
    system role is in that state. Recorded below, not changed.

## 5. What the reported test runs covered

The Phase 0 and A report said the new branch was cut from `master` at `c0c0f4e`: "10 commits
ahead of `Improvements` … with no backend code changes". It sat directly beside "the full
backend suite passes on the result". Read together, the two suggest the suite ran on unchanged
backend code. It did not.

**What the statement was about.** It described only the base: the 10 commits from `23f8e72`
(the analysis's tree) to `c0c0f4e`. `git diff --stat 23f8e72 c0c0f4e -- Backend` lists two
files:

- `Backend/Dockerfile`, a new `python:3.11-slim` digest from Dependabot (`a86604a`);
- `Backend/.env.example`, `POSTGRES_DB` changed from `ccure_test` to `ccure_db` (`03d6019`).

Neither is Python source. "No backend code changes" was accurate for the base and
"Python base-image bump" named the Dockerfile; "no backend _source_ changes" would have been
the exact phrase.

**What the branch changed.** The branch itself changes backend production code. The test runs
were on those changes:

| Commit    | Backend production code                                                                                                                 | Backend tests and tooling                                                                                                 |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `6925b2b` | `core/compliance_tasks.py`                                                                                                              | `tests/credentialed/test_sudo_password_safety.py`                                                                         |
| `cb62582` | `core/credential_vault.py` (new), `routers/compliance.py`, `routers/credentials.py`, `data/rbac/authorization_migration_inventory.json` | `tests/security/test_credential_api_consolidation.py`                                                                     |
| `9a32319` | —                                                                                                                                       | `tests/repo/test_worker_queue_mapping.py`                                                                                 |
| `2d4509d` | —                                                                                                                                       | `scripts/architecture/check.py`, `secret_guards.py`; the sudo test                                                        |
| `aa215dc` | —                                                                                                                                       | `scripts/architecture/capability_map.py`, `capability_baseline.json`, `check.py`; `tests/repo/test_capability_ratchet.py` |
| `780d936` | —                                                                                                                                       | `tests/scans/test_shared_json_contracts.py`                                                                               |
| `c12851b` | `routers/scan_schedules.py`, the inventory                                                                                              | the consolidation test; the capability baseline                                                                           |

**What each run covered.** Phase 0 and A were tested on the working tree, and each commit was
built afterwards in a detached worktree. Matching a run to a commit therefore needs evidence.
Two kinds were used:

- the files' modification times, together with which commits touch each file;
- the session record of every file edit, test run and commit.

| Run                                | Started (IST) | Backend tree under test                  | Evidence                                                                                                                                                                                                                                                                                                                                                               |
| ---------------------------------- | ------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S1 regression, 5,137 passed        | 01:26:55      | exactly `6925b2b`                        | `compliance_tasks.py` was last modified at 01:23:42, and `6925b2b` is the only commit that touches it, so its content then is the committed content. The sudo test was last edited at 01:26:01, before the run; its next edit was 01:43:31 (S4), after the commit at 01:33:52. `credential_vault.py` did not exist until 01:30:28.                                     |
| S2 regression, 6,513 passed        | 01:39:23      | exactly `cb62582` (S1 + S2)              | `credential_vault.py`, `routers/credentials.py` and `routers/compliance.py` were last modified at 01:32:18–01:32:40, and only `cb62582` touches them. The test file (01:36:25) and the inventory (01:38:25) were not edited again before the commit at 06:51:47. The S3 and S4 files were created after the run started (01:41 onwards), so they were not in its copy. |
| Milestone full suite, 7,870 passed | 07:27:07      | exactly `780d936` (all of Phase 0 and A) | The run's file list, saved at 07:27:08, is `780d936`'s tree path for path, plus the untracked Nessus study. Between the start and the commit at 07:42:29, only Markdown and memory files were edited. After `git reset --mixed 780d936` at 07:42:39, `git status` showed nothing but the Nessus study. No tracked backend file has a modification time in that window. |
| S2b full suite (this section)      | 09:42:34      | exactly `c12851b`                        | A clean detached worktree of `c12851b`: 1,920 paths, equal to `git ls-tree`, no untracked file.                                                                                                                                                                                                                                                                        |

So the 7,870 result covers `6925b2b`'s and `cb62582`'s backend changes, and everything else up
to `780d936`. S2b is covered by its own run (§4). The groups named in §2 cover what that table
says, and no more.

**What no run covered.** Every run used the release image `3a0dde6d4580` (release `3212d6b`,
Python 3.11.16), which was built from the _previous_ base-image digest. The new
`python:3.11-slim` digest in `c0c0f4e`'s Dockerfile has not been built or tested here. Its
first build is the next release's, and CLAUDE.md requires running the suite inside that image
before it is deployed.

## 6. Phase B — low-risk dependency reduction

The owner approved Phase B on 16 Oct 2026. It runs one change per commit, follows §10's B1–B10
order, and stops for review after each step. Every step is measured on its parent commit and on
its own commit, with the same probes:

- **Interfaces:**
  - `app.routes`, each with its endpoint's module and name;
  - `Limiter._route_limits`, the route-limit registry, keyed by route function;
  - which modules hold the canonical limiter object;
  - Celery's registered task names, after loading every task module;
  - the beat schedule;
  - `openapi.json`, through `--check` and the pre-commit hook.
- **Import cost:** each changed module imported in a fresh interpreter, counting first-party
  modules, all modules, and whether Scapy, python-nmap, ReportLab, paramiko, impacket, sslyze,
  openpyxl or python-docx loaded.
- **Coupling:** `python -m scripts.architecture.capability_map`, which reports the cycle, upward
  and lateral edges, foreign-table access and load profiles.

### B1 — the rate limiter from `core.rate_limiter`

Commit `ffbc170`, committed in place.

**The change.** `main` and 13 routers imported `limiter` from `scan_helpers`, whose import
loads the network orchestrator (`HostDiscoveryAPI`) and, through it, Scapy, python-nmap and
ReportLab. The limiter has lived in `core.rate_limiter` since Phase 3; `scan_helpers` only
re-exports it. All 14 now import it from `core.rate_limiter`.

- It is the same object, so routes, limits and limiter keys are unchanged. slowapi keys a limit
  by the route function's module and name, not by where the limiter was imported from.
- `scan_helpers` keeps the alias, which the tests and `scripts/measure_export_coverage.py` use.
- The RBAC inventory moved eight line numbers, because two routers gained an import line.
- This reverses the 25 Sep "not now" (D-1) for the limiter alias only. `scans.cvss` and
  `scans.finding_normalizer` are left for C3.

**Interfaces: identical.** The probe output is byte-identical before and after:

- 288 routes with the same endpoint names;
- 96 route-limit keys with the same limits;
- `app.state.limiter`, `scan_helpers.limiter` and every router's `limiter` are the same object;
- 36 registered Celery tasks and the same beat schedule;
- `openapi.json` unchanged.

**Import cost:**

| Module                                                                                                | First-party modules | All modules | Scapy, python-nmap, ReportLab                       |
| ----------------------------------------------------------------------------------------------------- | ------------------- | ----------- | --------------------------------------------------- |
| `routers.web_scans`                                                                                   | 125 → 70            | 1,304 → 733 | loaded → none                                       |
| `routers.assets`                                                                                      | 118 → 64            | 1,266 → 695 | loaded → none                                       |
| `routers.credentials`                                                                                 | 119 → 64            | 1,268 → 696 | loaded → none                                       |
| `routers.remediation`                                                                                 | 125 → 70            | 1,274 → 702 | loaded → none                                       |
| `routers.scan_history`                                                                                | 123 → 69            | 1,301 → 731 | loaded → none                                       |
| `routers.scan_policies`                                                                               | 122 → 72            | 1,271 → 704 | loaded → none                                       |
| `routers.scan_schedules`                                                                              | 122 → 67            | 1,277 → 705 | loaded → none                                       |
| `routers.config_audit`                                                                                | 149 → 99            | 1,297 → 730 | loaded → none                                       |
| `routers.compliance`                                                                                  | 123 → 68            | 1,366 → 882 | Scapy and nmap gone; ReportLab and python-docx stay |
| `main`, `routers.credentialed`, `routers.phase_scans`, `routers.reports`, `routers.traditional_scans` | unchanged           | unchanged   | unchanged                                           |

Notes on the table:

- `routers.compliance` still loads ReportLab and python-docx because it holds its own report
  generators.
- The last row's five modules still use other names from `scan_helpers`: `set_api`, `log`, and
  the pipeline and report helpers. Moving those is C1's work.
- `routers.scan_schedules` imports `scan_helpers` only inside a function, so it stops loading it
  at import time but still depends on it statically.

**Coupling:**

| Measure                                    | Before (`af0e76c`) | After (`ffbc170`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Upward edges                               |                 50 |            **43** |
| Lateral edges                              |                 74 |                74 |
| Largest cycle, all / top-level             |            22 / 13 |           22 / 13 |
| Foreign-table references / writes          |            80 / 17 |           80 / 17 |
| Cross-capability imports, top-level / lazy |          458 / 392 |         462 / 392 |

- **The seven upward edges removed** are from `routers.assets`, `compliance`, `config_audit`,
  `credentials`, `remediation`, `scan_policies` and `web_scans` to `scan_helpers`.
  `scan_history` sits in the same capability as `scan_helpers`, so its edge was never counted.
- **The baseline and the ceiling now record this.** The baseline no longer lists the removed
  edges, and `CEILINGS["upward_edges"]` is 43, so the edges cannot return unnoticed.
- **The `routers.web_scans` load profile shrank.** It no longer reaches the `check_kernel`,
  `credentialed_audit`, `discovery`, `network_checks`, `port_inventory`, `renderers`,
  `scan_kernel` and `vuln_intel` capabilities.
- **The cross-capability import count rose by 4.** It counts edges in either direction, and the
  new imports point down to shared infrastructure (`core.rate_limiter`, layer 0). It is not a
  ratcheted figure.
- **The cycle is unchanged, as expected.** §10 predicts that the cycle shrinks only from
  B1–B10 together.

**Against §10's prediction:**

- Eight modules stop depending on `scan_helpers` statically, as predicted. Nine stop loading it
  at import, counting `scan_schedules`.
- `routers.web_scans` no longer loads Scapy, nmap or ReportLab, as predicted.

**Tests:**

| Step                     | Command / targets                                                                   | Passed | Failed | Skipped | Notes                                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- | -----: | -----: | ------: | --------------------------------------------------------------------------------------------- |
| Selector                 | `select_tests.py --files <the 18 files>`                                            |      — |      — |       — | `full`: `Backend/main.py` is cross-cutting                                                    |
| Targeted                 | `tests/repo tests/security`, uncommitted tree                                       |    980 |      0 |       1 | The `alembic.ini` skip; 2 min 57 s                                                            |
| Architecture and secrets | `python3 -I Backend/scripts/architecture/check.py`                                  |      — |      — |       — | All six checks `ok`                                                                           |
| Capability ratchet       | `python -m scripts.architecture.capability_map --check`                             |      — |      — |       — | Holds, after `--write-baseline`                                                               |
| API contract             | `python -m scripts.openapi.generate --check`                                        |      — |      — |       — | Exit 0                                                                                        |
| RBAC inventory           | `python -m scripts.rbac.build_migration_inventory --check`                          |      — |      — |       — | Current after `--write`; only line numbers moved                                              |
| Pre-commit               | every hook, inside the commit                                                       |      — |      — |       — | Passed                                                                                        |
| **Full backend suite**   | `tests`, on a clean detached worktree of `ffbc170` (1,920 paths, nothing untracked) |  7,880 |  **0** |     211 | 14 min 13 s; the same count and the same 211 environmental skips as S2b (§4): B1 adds no test |

No live scan was run, because B1 is not on a scan path (§11 requires live validation for B2, B3,
C2, C3 and C6). The frontend did not change.

**Runner.** `scripts/ci/local_guard_tests.sh` failed during set-up twice more. A trace of one
failure showed the cause:

1. the readiness loop stopped on a successful `pg_isready` over the Unix socket;
2. the confirming check a moment later failed;
3. this is the gap while the official image restarts the server after initdb.

Both B1 runs therefore used a scratch copy of the runner that differs only by `-h 127.0.0.1`
on its two `pg_isready` calls. The image's initdb server does not listen on TCP. Both runs
completed. The committed runner is unchanged, pending the decision in §7.

**Left on purpose:** `routers.credentialed` and `routers.traditional_scans` still take `log`
from `scan_helpers`. It is the same object as `logging.getLogger("ccure.api")`, so one line
each would detach them, but B1 is the limiter only.

## 7. Decisions awaiting the project owner

| #   | Decision                                                                                                                                                                                                               | From                                                               |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| D-4 | Approve the worker privilege split (S3)                                                                                                                                                                                | [`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md) |
| D-5 | Push every GitLab merge to `github`, or register a GitLab runner                                                                                                                                                       | [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)         |
| D-9 | Commit the September baseline and plan rev 4 under `docs/archive/architecture/`, or not                                                                                                                                | analysis §13                                                       |
| new | Retire or repurpose `audit.compliance.manage_integrations`, which now gates no route                                                                                                                                   | S2                                                                 |
| new | Rewrite the three NIS2 remediations that pipe into sudo as `sudo sh -c '…'` (seeded catalogue data)                                                                                                                    | S1                                                                 |
| new | Align the compliance workspace's credential buttons (gated on `manage_frameworks`) and the scan pickers' error handling with the credential permissions                                                                | S2                                                                 |
| new | The schedule page: say why the credential picker is empty when the list answers 403 (a custom role holding `scan_schedule.manage` without `credential.read`), and show "New schedule" only with `scan_schedule.manage` | S2b, §4                                                            |
| new | Correct the picker route's docstring, the published OpenAPI description, which still says `/compliance/credentials` is gated on `compliance:read`                                                                      | S2b, §4                                                            |
| new | `scripts/ci/local_guard_tests.sh`: check PostgreSQL readiness over TCP. Confirmed by a trace during B1, and both B1 runs completed with the TCP check (§6)                                                             | S2b, §4; B1, §6                                                    |
| new | Commit B1's two measurement probes (interface snapshot; import cost per module) as tooling, so B2–B10 are measured the same way                                                                                        | B1, §6                                                             |

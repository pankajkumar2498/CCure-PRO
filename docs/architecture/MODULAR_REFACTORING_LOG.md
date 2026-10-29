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
its own commit, with the same three probes. The first two have been committed tools since
19 Oct 2026. B1 used scratch copies of them, whose figures they reproduce exactly. Run from
`Backend/`:

```bash
python -m scripts.architecture.interface_snapshot > before.json        # interfaces
python -m scripts.architecture.import_cost --json --watch <module> MOD... > cost-before.json
python -m scripts.architecture.capability_map                          # coupling
# ...make the change, then the same three into after files, and:
python -m scripts.architecture.interface_snapshot --compare before.json after.json
python -m scripts.architecture.import_cost --compare cost-before.json cost-after.json
```

- **Interfaces** (`scripts/architecture/interface_snapshot.py`):

  - every route, with its methods, path and the module and name of its handler;
  - `Limiter._route_limits`, the route-limit registry, keyed by route function;
  - which modules hold the canonical limiter object;
  - Celery's registered task names, after loading every task module;
  - the beat schedule;
  - a SHA-256 of the OpenAPI document the application generates. `openapi.json` is also checked
    by `scripts.openapi.generate --check` and the pre-commit hook.

  `--compare` exits 1 and names each difference. The snapshot is sorted and carries no
  timestamp, so two runs over the same code are byte-identical.

- **Import cost** (`scripts/architecture/import_cost.py`): each named module imported in a fresh
  interpreter, counting first-party modules and all modules, the heavy packages that loaded
  (`HEAVY`: the scan, report and browser toolchains, the database and broker clients, the web
  framework), and whether each `--watch` module loaded. It sees what an import loads, not what a
  call loads: a lazy import inside a function counts only once that function runs.
- **Coupling:** `python -m scripts.architecture.capability_map`, which reports the cycle, upward
  and lateral edges, foreign-table access and load profiles, statically.

Both scripts set `SKIP_DOTENV_LOAD=1`, connect to nothing and change nothing.
`tests/repo/test_measurement_scripts.py` pins what they measure.

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
completed. The committed runner was left unchanged in B1 and fixed in `6b81530` (19 Oct 2026, below).

**Left on purpose:** `routers.credentialed` and `routers.traditional_scans` still take `log`
from `scan_helpers`. It is the same object as `logging.getLogger("ccure.api")`, so one line
each would detach them, but B1 is the limiter only.

### Before B2: the runner and the probes

The owner approved both outstanding tooling items on 19 Oct 2026, to be committed separately and
before B2.

**`6b81530`: the runner waits for PostgreSQL over TCP.** `local_guard_tests.sh` now passes
`-h 127.0.0.1` to both `pg_isready` checks.

- The mechanism, sampled inside a fresh `postgres:18-alpine` container: the image's initdb server
  listens on the Unix socket only. The samples ran:
  1. socket ready, TCP down;
  2. socket down twice during the restart, TCP still down;
  3. both ready once the real server listened.
- So a socket check can pass during initdb and fail a moment later. That is the set-up failure
  seen three times on 16 Oct and traced in B1.
- Five consecutive runs of `scripts/ci/local_guard_tests.sh tests/repo/test_architecture_check_command.py`
  completed (5 passed each, 51–56 s) and left no container or network.

**`98f33d1`: the probes are committed.**
`Backend/scripts/architecture/interface_snapshot.py` and `import_cost.py` (§6, method), with
`tests/repo/test_measurement_scripts.py`.

- **Reproducible:** two snapshots of the same tree are byte-identical. The snapshot matches B1's
  scratch probe on every field they share (it adds an OpenAPI digest), and `import_cost`
  reproduces B1's first-party and total counts for all 14 modules.

| Check                                              | Passed | Failed | Skipped             |
| -------------------------------------------------- | -----: | -----: | ------------------- |
| `tests/repo` (the selector's first group)          |    725 |      0 | 1 (`alembic.ini`)   |
| `tests/security` (its second)                      |    263 |      0 | 0                   |
| `python3 -I Backend/scripts/architecture/check.py` |      — |      — | all six checks `ok` |
| Pre-commit, on both commits                        |      — |      — | passed              |

### B2 — engines take a progress sink and a cancellation token

Commit `6986194`, committed in place.

**The change.**

- **`core/engine_ports.py`** declares what an engine takes, as structural protocols with no
  application import:

  - `ProgressSink`: `start`, `publish`, `publish_sync` and `record`;
  - `CancelToken`: `is_cancelled` and `raise_if_cancelled`;
  - `NEVER_CANCELLED`, the token for a run with no scan.

  It is classified as the scan kernel (layer 2), below the engines.

- **The engines take them as arguments instead of a scan id:**

  - `DiscoveryEngine.run(ips, progress, cancel)`;
  - `PortEngine.run(hosts, progress)`;
  - `VulnerabilityEngine.run(hosts, progress)`.

  None of them imports `core.scan_control` or `core.redis_client` any more.

- **The implementations stay in orchestration** (`core.scan_control`):

  - `ScanProgress` publishes to `scan_progress:<id>` and writes `scans.options["progress"]`
    through the same functions as before;
  - `ScanCancelToken` reads the status through `make_cancel_check` and raises `ScanCancelled`,
    which every scan task already catches;
  - `engine_ports(scan_id)` builds both for a scan, or neither when there is no scan id.

  The orchestrator calls it once per phase method, through a lazy import, so importing the
  orchestrator loads nothing new.

- **The web scanner.** It imported `core.scan_control` only for its own terminal-status settler,
  which wrote `web_scans` from inside the `scans` capability.
  - `force_terminal_web_scan_status` and `WEB_TERMINAL_STATUSES` moved to
    `core/web/scan_status.py`. They are byte-identical and keep the logger name
    `ccure.scan_control`, so the log lines do not change.
  - `core.web.tasks`, `core.web.timeout`, `core.tasks` and two web tests import them there.
  - The web engines already took a `cancel_cb` (crawler, injection, OAST, access control, HTTP
    methods), so nothing else changed on that side.
- **Behaviour.**
  - The checks happen at the same points and the same number of times.
  - The port and network-check engines still do not poll for cancellation; the tasks check
    between phases, as before.
  - The only visible difference is one log line: "Scan `<id>` cancelled — stopping discovery…"
    is now "scan `<id>` cancelled — …", printed through the token.
- **Python interfaces changed:**

  - the three engines' `run` signatures;
  - the import path of the web settler.

  Every caller and test double is updated (`test_port_registration_flow`'s double,
  `test_fault_injection`, `test_web_scan_stall_recovery`). `test_ci_test_selection` pinned "a
  change to `core/scan_control.py` selects the web tests", which stopped being true. It now
  samples the same property on `reporting/web_pdf_generator.py`. HTTP APIs, Celery task names and
  the schema are unchanged.

**Interfaces: identical.** `interface_snapshot --compare` on `98f33d1` and `6986194` reports
"interfaces identical": 288 routes, 96 route limits, 36 Celery tasks, the beat schedule and the
OpenAPI digest. `scripts.openapi.generate --check` exits 0, and the RBAC inventory is current.

**Coupling** (`capability_map`):

| Measure                                    | Before (`98f33d1`) | After (`6986194`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Upward edges                               |                 43 |            **40** |
| Lateral edges                              |                 74 |                74 |
| Largest cycle, all / top-level             |            22 / 13 |           22 / 13 |
| Foreign-table references / writes          |            80 / 17 |       **79** / 17 |
| Cross-capability imports, top-level / lazy |          462 / 392 |         466 / 386 |

- **Removed:**

  - the three upward edges into `core.scan_control`, from `core.discovery.engine`,
    `core.web.tasks` and `core.web.timeout`;
  - the reference from `scans` to `web_scans`.

  The baseline records the removals. `CEILINGS` is lowered to 40 upward edges and 79 foreign
  references.

- **The cross-capability counts, exactly** (diffed against a worktree of the parent):

  - nine lazy edges went: four engine imports of `core.redis_client`, and five imports of
    `core.scan_control` (the discovery engine, `core.web.tasks` twice, `core.web.timeout`, and
    `core.tasks`' import of the moved settler);
  - three lazy edges came: `core.scan_control → core.redis_client` twice (the Redis side now lives
    in orchestration), and `core.tasks → core.web.scan_status`;
  - four top-level edges came: the three engines' imports of `core.engine_ports`, and
    `core.web.scan_status → db.base`.

  Every added edge points down a layer.

- **The cycle is unchanged, as expected:** §10 expects it to shrink only once B1–B10 are all done.

**Import cost and run-time load.**

- **At import, nothing heavy changed.** `import_cost --compare` shows each engine gaining one
  first-party module, `core.engine_ports`, and no heavy package: the old imports were lazy, inside
  `run()`, so they never showed at import time.
- **The difference is at run time.** The same script runs the discovery engine on `98f33d1`
  (with a scan id) and on `6986194` (with no orchestrator):

  - before, running it loaded `core.scan_control` and the `Scan` model;
  - after, it loads neither.

  `tests/scans/test_engine_ports.py` pins this for discovery, the network checks and the port
  scan. The port scan still loads `core.redis_client`, through `core.nmap.wrapper`'s process lease
  (the `Lease` port, not B2's).

**Tests.**

| Step                     | Command / targets                                                                                                                                                                                                                   | Passed | Failed | Skipped | Notes                                                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ------------------------------------------------------------------------------------------------------------------------------------- |
| Characterization, before | `tests/scans/test_engine_progress_and_cancellation.py` on `98f33d1` plus the file                                                                                                                                                   |     10 |      0 |       0 | Written first, against the old code                                                                                                   |
| Characterization, after  | the same file, unchanged, on B2                                                                                                                                                                                                     |     10 |      0 |       0 | Same frames, counter writes and status-read counts                                                                                    |
| Focused                  | the characterization file, `test_port_registration_flow`, `test_ot_safety`, `test_tasks`, `test_scan_stall_recovery`, `test_progress`, `tests/web/test_fault_injection.py`, `test_web_scan_stall_recovery`, `test_web_scan_timeout` |     72 |      0 |       0 |                                                                                                                                       |
| New                      | `tests/scans/test_engine_ports.py`                                                                                                                                                                                                  |     13 |      0 |       0 | The first run failed one test, because the probe script imported the port engine before measuring discovery; corrected                |
| Mutation                 | the two files, on a scratch worktree with: M1 the after-batch cancel check removed; M2 `import core.scan_control` back in discovery; M3 the port sink not passed; M4 `ScanProgress.record` doing nothing                            |      — |      — |       — | Caught: M1 by 3 tests, M2 by 2, M3 by 1, M4 by 3. M3's first attempt never applied (black had reformatted the line) and was redone    |
| Targeted groups          | `tests/scans tests/web tests/repo`, uncommitted tree                                                                                                                                                                                |  4,709 |  **1** |       2 | The failure is the stale selector sample above, fixed, then 15 of 15 in `test_ci_test_selection`. Skips: `alembic.ini`, live OSV feed |
| Architecture             | `check.py`; `capability_map --check`; `openapi.generate --check`; `build_migration_inventory --check`; pre-commit                                                                                                                   |      — |      — |       — | All pass                                                                                                                              |
| **Full backend suite**   | `scripts/ci/local_guard_tests.sh tests`, on a clean detached worktree of `6986194` (1,927 paths)                                                                                                                                    |  7,911 |  **0** |     211 | 14 min 40 s: B1's 7,880 plus the 31 new tests (8 probe, 10 characterization, 13 engine-port); the same 211 environmental skips        |

The selector named 12 of the 13 groups, so the full suite covers what it asked for.

**Live validation, before and after.** §11 requires live scans for B2.

- **Targets.** There were no standing targets on the VM; `CLAUDE.md`'s target containers date
  from the Windows host. Disposable targets were built on an internal Docker network,
  `172.30.250.0/24`, and removed afterwards along with their images:
  - `.10`, Ubuntu 24.04 with OpenSSH 9.6p1;
  - `.11`, nginx serving an exposed `.env` and `.git/config` (the `ccure-nuclei-target` shape,
    with dummy values);
  - `.12`, Redis 7 with no authentication;
  - `.13`, PostgreSQL 18;
  - `.14` and `.15`, empty addresses.
- **Code and tools.** Each run used `git archive` of the commit, run in the release image
  (`3a0dde6d4580`), so the image's nmap, Nuclei templates and Scapy apply.
- **The worker's runtime.** Root, `NET_RAW` and `NET_ADMIN`, the worker's scanner settings, and
  Celery eager so a whole scan runs in one process. A throwaway PostgreSQL and Redis sat on a
  second internal network.
- **The host was excluded.** `172.30.250.1` is the host's address on that bridge. The full scan's
  targets were listed explicitly, and the cancel scan covered the /24 minus `.1` (253 addresses,
  as recorded).
- **Dispatch.** The harness creates and dispatches scans exactly as `POST /scan/host-discovery`
  does: `create_scan`, the policy snapshot, the options, `run_host_discovery_task.delay`. It
  records every frame on `scan_progress:*`, then reads back the scan row, its phases, the assets,
  services and findings.
- **Production was not touched.** No live database, no production target and no host networking.

| Run                                          | Before (`98f33d1`)                                                                                                                                                                   | After (`6986194`)                                                                   |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- |
| Full vulnerability audit of `.10`–`.15`      | complete; 3 phases complete; 4 active hosts, 2 inactive; 4 services with product and version; 7 findings; 13 progress frames; 315 s                                                  | identical in every field except time (325 s)                                        |
| Stopped mid-discovery (basic, 253 addresses) | stop applied on the first discovery frame (1.9 s in), during the first batch; honoured at the batch boundary; `cancelled`, no phase recorded; 4 frames; settled 9.1 s after the stop | identical; stop applied on the first frame (1.1 s in); settled 9.1 s after the stop |

- **The seven findings:**
  - Redis without authentication (critical);
  - the exposed `.env` and `.git/config`: two Nuclei findings and the sensitive-path check;
  - three HTTP findings (cleartext, missing headers, version disclosure).
- **What "identical" covers:** the scan rows, phases, assets, services, findings, the task
  results and every frame's content and order. Wall-clock times are excluded.
- **The cancel run's stop** is issued when the first discovery frame arrives, the same moment in
  both runs. Where a stop lands relative to a batch boundary varies with timing, so the identical
  outcome here is one sample, not a proof. The characterization tests pin the before, during and
  between-batch cases deterministically.

Two things the first live attempts settled:

- **The scanner's first interface has to be the target network.** With the database network
  first, the BALANCED and AGGRESSIVE profiles found no host: their raw ARP, ICMP and SYN went out
  of the wrong interface, and the scan ended `unreachable`. FAST still found two hosts by TCP
  connect. Production runs with the host's network, where this cannot arise.
- **The harness queried `scan_phases.phase_number`,** which does not exist. The scan itself had
  completed; the query was corrected and the run repeated from a fresh database.

**Limitations.**

- **Not exercised live:**
  - The vulnerability-intelligence database was the throwaway one in both runs, so no CVE was
    matched either way.
  - The credentialed path, which B2 did not touch.
  - The web DAST pipeline. B2 moved only its settler, which `tests/web` covers, including the
    database-down case.
- **Kept as scratch, not committed:** the live harness and its driver. They were committed
  before B3, as `22aa824`.
- **The engines still load SQLAlchemy** through `core.risk` and `core.utils`. That is B3.
- **The port engine still loads Redis** through the nmap process lease.
- **The port and network-check engines take no cancellation token,** because they never polled
  for cancellation. Adding a check would change when a stop takes effect, which is a behaviour
  change for its own decision.

### Before B3: the live-scan tooling

Commit `22aa824`, committed in place before B3, as the owner asked on 20 Oct 2026.

B2's live validation ran from scratch scripts (§7). They are now `scripts/validation/`, and
[`../ci/LIVE_SCAN_VALIDATION.md`](../ci/LIVE_SCAN_VALIDATION.md) is the procedure.

- **`targets.env`** defines the targets once:
  - the internal network `172.30.250.0/24`;
  - an OpenSSH host (`.10`), nginx serving a dummy `.env` and `.git/config` (`.11`), Redis
    without authentication (`.12`) and PostgreSQL (`.13`);
  - two empty addresses (`.14`, `.15`);
  - every image pinned by digest;
  - the host's own address on the bridge (`.1`), named so that no scan includes it.
- **`targets.sh up|status|down`** manages them.
  - It is idempotent.
  - It creates only an internal network, and refuses an existing one that is not internal.
  - It writes the web target's dummy content at start-up, so nothing secret-shaped is committed.
  - It gives PostgreSQL a random password per start.
- **`live_scan.sh <label> <commit> <out-dir>`** runs one commit's code (`git archive`) in the
  backend image, the way the scanner worker runs. It uses a throwaway PostgreSQL and Redis on a
  per-run internal network, and removes them on exit.
- **`live_scan_harness.py`** is B2's harness. It dispatches and stops scans as the routes do, and
  refuses a target list that holds the host's address.
- **`compare_live_scans.py`** compares two results, ignoring only wall-clock time.

**Tests.** `tests/repo/test_live_scan_tooling.py` holds what can drift without Docker:

- **Isolation:**
  - a private /24 that overlaps none of the installation's networks;
  - internal networks only;
  - no published port or host network in any container command;
  - the host never a target;
  - every image by digest.
- **The scripts:** both parse.
- **The harness:**
  - importing it runs nothing;
  - its dispatch keywords equal the host-discovery route's;
  - it refuses a target list holding the host;
  - its read-back queries run against the real schema;
  - its stop does what the stop route does.
- **The comparison** ignores time and names everything else.

| Check                                              | Passed | Failed | Skipped             |
| -------------------------------------------------- | -----: | -----: | ------------------- |
| `tests/repo/test_live_scan_tooling.py` (new)       |     13 |      0 | 0                   |
| `tests/repo`                                       |    738 |      0 | 1 (`alembic.ini`)   |
| `tests/security`                                   |    263 |      0 | 0                   |
| `python3 -I Backend/scripts/architecture/check.py` |      — |      — | all six checks `ok` |
| Pre-commit                                         |      — |      — | passed              |

Its first use is B3's "before" run below. It reproduced B2's figures: 7 findings and 13 frames.

### B3 — discovery stops loading the vulnerability-intelligence database layer

Commit `ad4aab7`, committed in place.

**Where the dependency was.** Inspected on `22aa824`:

- **`core.risk`** imported `compute_priority` and `merge_alias_fields` from `core.vuln_intel`, at
  top level, to merge duplicate findings. `core.vuln_intel` holds the queries against the
  `vuln_intel` database, and importing it loads SQLAlchemy, `config` and `db.fork_safety`.
- **Discovery** imports `core.risk` for OS fingerprinting (through its ICMP and TCP-SYN
  techniques and the enrichment). So importing the discovery engine loaded 474 modules, the
  database layer among them, for two pure functions.
- **The network-check engine** imports `core.risk` too. The port and network-check engines also
  import `core.utils` (for `extract_version` and `TokenBucket`). `core.utils` builds the CVE
  database client when it is imported (`CVE_DB = get_cve_database()`) for `lookup_cve`, whose
  only engine caller is the `cve_engine` network-check plugin.

**The change.** The smallest safe change: the pure helpers move, and the CVE lookup stays.

- **The move.** `title_case_severity`, `compute_priority`, `_json_safe` and `merge_alias_fields`
  moved, byte-identical, from `core/vuln_intel.py` to the new `core/vuln_scoring.py`, which
  imports only the standard library. `merge_alias_fields` calls the other three, so they move
  together.
- **The re-export.** `core.vuln_intel` re-exports all four. Every other caller gets the same
  function objects under the old name: `core.cve_database`, the credentialed matcher, and the
  dashboard, findings and asset routers.
- **The one changed import.** `core.risk` now imports from `core.vuln_scoring`.
- **The classification.** `core.vuln_scoring` is classified with `vuln_intel`, which owns the
  priority ladder. Classifying it with the scan kernel would have made the two capabilities import
  each other: `core.utils` already imports `core.cve_database`.
- **Behaviour is unchanged.** The functions are the same objects, and a test pins it. No other
  call site, route, task, table or log line changed.

**Half B is deferred.** Moving `core.utils`' CVE database client too, measured on a scratch copy:

- **What it would gain.** The port engine would load 448 modules instead of 568, and the
  network-check engine 339 instead of 510, neither with SQLAlchemy.
- **Why it waits:**
  - **It changes when the vulnerability database is first contacted.** `CVEDatabase.__init__`
    probes it (`can_connect_vuln_db()`) and logs the backend it chose. Today that happens when
    `core.utils` is first imported, in every process that imports it; moved, it would happen at
    the first CVE lookup. That is a behaviour change, not a dependency cut.
  - **Another caller.** `scripts/verification/verify_install.py` imports `lookup_cve` from
    `core.utils`.
  - **The live check cannot validate it.** The throwaway vulnerability database matches no CVE,
    so a broken lookup and a working one produce the same scans.
- It is listed in §7.

**Interfaces: identical.** `interface_snapshot --compare` on `22aa824` and `ad4aab7` reports
"interfaces identical": routes, route limits, Celery tasks, the beat schedule and the OpenAPI
digest. `scripts.openapi.generate --check` exits 0, and the RBAC inventory is current.

**Coupling** (`capability_map`):

| Measure                                    | Before (`22aa824`) | After (`ad4aab7`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Modules classified                         |                483 |           **484** |
| Upward edges                               |                 40 |                40 |
| Lateral edges                              |                 74 |                74 |
| Largest cycle, all / top-level             |            22 / 13 |           22 / 13 |
| Foreign-table references / writes          |            79 / 17 |           79 / 17 |
| Cross-capability imports, top-level / lazy |          466 / 386 |         466 / 386 |

- **One lateral edge replaced by another** between the same two capabilities:
  `core.risk → core.vuln_intel` became `core.risk → core.vuln_scoring`. The count is unchanged
  because the coupling is now to the pure part only. The baseline records the new edge.
- **The discovery engine's load profile** in the baseline no longer lists SQLAlchemy.
- **`CEILINGS` are unchanged:** no ceiling measure fell.

**Import cost** (`import_cost --compare`, first-party / all modules):

| Module                                       |   Before |    After | Watched modules that stopped loading                      |
| -------------------------------------------- | -------: | -------: | --------------------------------------------------------- |
| `core.discovery.engine`                      | 20 / 474 | 17 / 367 | SQLAlchemy, `config`, `core.vuln_intel`, `db.fork_safety` |
| `core.discovery.enrichment`                  | 21 / 476 | 18 / 369 | the same                                                  |
| `core.discovery.techniques.tcp_syn`          | 20 / 474 | 17 / 367 | the same                                                  |
| `core.risk`                                  |  7 / 461 |  4 / 319 | the same                                                  |
| `engines.port.port_engine`                   | 23 / 567 | 24 / 568 | none (still `core.utils` → `core.cve_database`)           |
| `engines.vulnerability.vulnerability_engine` | 24 / 509 | 25 / 510 | none (the same)                                           |
| `orchestrator.scan_orchestrator`             | 58 / 958 | 59 / 959 | none                                                      |
| `core.vuln_intel`                            |  5 / 248 |  6 / 249 | —                                                         |
| `core.cve_database`                          |  6 / 252 |  7 / 253 | —                                                         |
| `core.vuln_scoring` (new)                    |        — |   2 / 19 | loads none of them                                        |

The modules that gained one gained `core.vuln_scoring` itself. At run time, the same probe as
B2's runs the discovery engine with no orchestrator: it loads none of the watched modules, before
the run or after it. `tests/scans/test_vuln_scoring_split.py` pins that.

**Tests.**

| Step                   | Command / targets                                                                                                                                                                                                                  | Passed | Failed | Skipped | Notes                                                                                                                                                                            |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New                    | `tests/scans/test_vuln_scoring_split.py`                                                                                                                                                                                           |     14 |      0 |       0 | Re-export identity; stdlib-only imports; no `core.risk` edge to `vuln_intel`; discovery imports and runs without the database layer; behaviour                                   |
| Mutation               | the new file, on a scratch worktree with: M1 `core.risk` importing from `core.vuln_intel` again; M2 the P2 boundary in `compute_priority` moved from CVSS 9.0 to 9.5; M3 a wrapper copy of `compute_priority` in `core.vuln_intel` |      — |      — |       — | Caught: M1 by 2 tests, M2 by 1, M3 by 1. M3's first attempt put the copy before the re-export, which rebound the name, so it was not a mutation; redone at the end of the module |
| Targeted groups        | `tests/assets tests/compliance tests/credentialed tests/repo tests/scans tests/security`, the groups the selector named                                                                                                            |  5,568 |      0 |       1 | `alembic.ini`                                                                                                                                                                    |
| Architecture           | `check.py`; `capability_map --check`; `openapi.generate --check`; `build_migration_inventory --check`; pre-commit                                                                                                                  |      — |      — |       — | All pass                                                                                                                                                                         |
| **Full backend suite** | `scripts/ci/local_guard_tests.sh tests`, on a clean detached worktree of `ad4aab7`                                                                                                                                                 |  7,938 |  **0** |     211 | 14 min 45 s: B2's 7,911 plus the 13 tooling and 14 B3 tests; the same 211 environmental skips                                                                                    |

**Live validation, before and after.**

- **Set-up.** The tooling above, against the same running targets, with
  `ccure-audit-pro-backend:latest` (`3a0dde6d4580`).
- **Six runs, alternating** between `22aa824` and `ad4aab7`. The first pair differed, so the runs
  were repeated until each difference could be placed.
- **The same in every run.**
  - The full audit completed: 3 phases, 4 active hosts and 2 inactive, 4 services and 13
    frames.
  - The stopped sweep ended `cancelled`, with no phase recorded.

| Run       | Commit    | Full audit            | Stopped sweep: hosts in the first frame; settled after the stop |
| --------- | --------- | --------------------- | --------------------------------------------------------------- |
| `before`  | `22aa824` | 7 findings, 320 s     | 1; 9.1 s                                                        |
| `after`   | `ad4aab7` | **8 findings**, 316 s | **4; 8.5 s**                                                    |
| `before2` | `22aa824` | 7 findings, 308 s     | 1; 9.1 s                                                        |
| `after2`  | `ad4aab7` | 7 findings, 321 s     | **4; 8.5 s**                                                    |
| `before3` | `22aa824` | 7 findings, 319 s     | 1; 9.1 s                                                        |
| `after3`  | `ad4aab7` | 7 findings, 291 s     | 1; 9.1 s                                                        |

**Result: no difference attributable to B3.**

- `after3` is identical, apart from time, to all three `22aa824` runs. So are the three
  `22aa824` runs to each other.
- Every difference the comparison reported between the commits also appears between two runs of
  `ad4aab7` itself: `after` against `after2` (the finding), and `after2` against `after3` (the
  frames).
- What each difference is, measured:

- **One more finding:** `CCURE-CHK-NUCLEI-CVE-2025-46817` (critical) on the Redis target, from
  the Nuclei probe. To test it, the probe's own command line ran on its own, in the same image,
  on the same network and against the same target, with no CCure code:

  | Variant                                                     | Matches | Time      |
  | ----------------------------------------------------------- | ------: | --------- |
  | As the probe runs it (five runs)                            |       0 | 161–193 s |
  | Host-error cutoff disabled (`-nmhe`)                        |      10 | 890 s     |
  | Only the non-HTTP template types (`-pt tcp,javascript,ssl`) |      10 | 27 s      |

  - **The 10 matches:**
    - CVE-2025-46817 and CVE-2025-49844 (critical);
    - CVE-2025-46818 and CVE-2025-46819 (high);
    - `exposed-redis`;
    - `redis-default-logins`, five times.
  - **The mechanism.**
    - The probe hands a non-HTTP port to Nuclei as a bare `host:port`.
    - Nuclei (v3.11.1) runs its HTTP templates against it too, and each one fails.
    - After its per-host error cutoff (`-max-host-error`, default 30) it drops the host. It logged
      "Skipped 172.30.250.12:6379 from target list as found unresponsive 50 times".
    - Whether a Redis template has run by then depends on scheduling at `-c 50`. In the scans, one
      got through in one run of six.
  - **Why it is not B3.** B3 changed nothing on that path. The functions it moved are the same
    objects, and the probe's command line and its parsing are untouched.
  - **It is a pre-existing false negative**, and a serious one: on this target the probe misses
    two critical CVEs most of the time. It is recorded in §7, not fixed here, because it is outside
    B3.

- **The stopped sweep's frames.**
  - **What the frame shows.** Scapy returns every ARP reply at once. `arp.probe` then marks
    hosts active one by one, each only after `classify_mac` returns. For the targets' random MACs
    that means two queries of the MAC-vendor cache and a queued fetch from `api.macvendors.com`,
    which cannot succeed on an internal network.
  - **What it measures.** The live publisher samples every 150 ms. Its first frame holds however
    many hosts those lookups have let through: one in four runs, four in two.
  - **What follows from it.** The stop is issued on that frame, so `after_discovered` follows it.
    The frame that later reports all four hosts is either needed (4 frames) or not (3). The task
    settles either 9.1 s or 8.5 s after the stop, the 0.6 s the other three lookups took.
  - **Why it is not B3.** `after3` shows the "one host" pattern on `ad4aab7`, and the code that
    runs here is the same on both commits. B3 changed one import in `core.risk`, and discovery
    calls none of the moved functions.

**Limitations.**

- **Not exercised live: CVE matching.**
  - The vulnerability database was the throwaway one, so no run matched a CVE.
  - B3 moved the functions that merge and grade CVE records. The behaviour tests and the full
    suite cover them.
- **The port and network-check engines still load SQLAlchemy,** through `core.utils` →
  `core.cve_database`. That is half B, deferred above.
- **Discovery still reaches the application database lazily.** The ARP techniques call
  `core.oui_lookup`. When an address's OUI is not in the bundled registry, it reads its
  MAC-vendor cache (`MacVendorCache`) through `db.base` and `db.models`. The targets' Docker MACs
  are never in that registry, so the live runs took this path.
  - It is not B3's dependency: the application database, not vulnerability intelligence.
  - It loads nothing at import.
  - It is recorded in §7.
- **The comparison cannot tell a scan's own variation from a change.** It reports both as
  differences, and only repeated, alternating runs separated them here. Two kinds were seen:
  - Nuclei's per-host error cutoff, described above;
  - the stopped sweep's first frame, which depends on how long the MAC-vendor lookups take.
    `docs/ci/LIVE_SCAN_VALIDATION.md` now describes both. Since `3f7794f` the comparison
    tolerates the second and prints it (below).
- **Target MAC addresses are Docker's random ones.** A comparison across a re-creation of the
  targets therefore differs in every asset's MAC. Compare runs against the same running targets.
  Fixed since `e7f7368` (below).

### After B3: two live-validation improvements

The owner asked for both on 20 Oct 2026, as tooling committed apart from application code.
Neither changes application code.

**`e7f7368`: each target's MAC address is fixed.**

- **The problem.** Docker chose a random MAC whenever a target was created, so `targets.sh down`
  then `up` changed every asset's MAC (B3, above).
- **The address.**
  - `targets.env` gives each target a MAC in Docker's classic `02:42:<IPv4 in hex>` form,
    `02:42:ac:1e:fa:0a` to `…:0d`.
  - It is locally administered, so no vendor's.
  - It is absent from the bundled OUI registry (`Backend/data/manuf.txt`), so discovery looks it
    up exactly as it did the random ones. The registry misses, the MAC-vendor cache is queried,
    and a vendor fetch is queued.
- **The script.**
  - `targets.sh` starts each target with `--mac-address`.
  - `up` replaces a running target that does not hold its defined address and MAC, and leaves
    one that does alone.
  - `status` prints each target's address and MAC.
- **Docker 29.9 supports it on an internal network.** Measured on a throwaway network first:
  `--mac-address` and `--network name=…,mac-address=…` both set the address.

**`3f7794f`: the comparison tolerates timing-only frame differences.**

- **What it tolerates** is the two things B3 measured:
  - **Discovery's samples.** A phase-1 `running` frame that the next phase-1 `running` frame covers
    completely: the same or more hosts, the same or higher counters, the same sweep size and keys.
    The stop's `after_discovered` is compared as a sample.
  - **The stop route's frame**, compared by count, not position.
- **Tolerated is not hidden.** Every tolerated difference is printed (`tolerated: …`), and the
  exit code stays 0. `--strict` is the exact comparison.
- **What stays exact:**
  - the last sample of every run of samples;
  - a sample the next one does not cover;
  - every port-scan and audit frame, whose counters move once per host;
  - every terminal frame;
  - every stored row. So the Nuclei variation still fails a comparison: it is a stored finding.
- **Why the rule is this narrow.** Collapsing every run of `running` frames would also collapse
  the audit's per-host frames (`scanned_hosts` 0 to 4), and a missing one would pass. A test pins
  that it does not.

**Tests.**

| Check                                                                   | Passed | Failed | Skipped           | Notes                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------------------------------------------------------- | -----: | -----: | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/repo/test_live_scan_tooling.py` on a clean worktree of `e7f7368` |     17 |      0 | 0                 | The original 13, and 4 for the MACs. `up` runs against a stand-in for `docker` that records each call                                                                                                                                                                                                                                                                                                                 |
| The same file on `3f7794f`, the tree committed                          |     33 |      0 | 0                 | Adds 16 comparison tests, built on B3's own cancel frames                                                                                                                                                                                                                                                                                                                                                             |
| Mutation                                                                |      — |      — | —                 | Caught: M1 a target started without `--mac-address` (2 tests); M2 `up` leaving any running target alone (1); M3 every sample "covered" (3); M4 the stop route's frame compared by position (1); M5 the keys and sweep-size check removed (2). M3 and M5 first survived: every regression case ended on a different last sample, which is compared exactly anyway. Three cases that end on the right sample were added |
| `tests/repo tests/security`, the selector's groups, both changes        |  1,021 |      0 | 1 (`alembic.ini`) | 1,001 before, plus the 20 new                                                                                                                                                                                                                                                                                                                                                                                         |
| `check.py`; pre-commit on both commits                                  |      — |      — | —                 | All pass                                                                                                                                                                                                                                                                                                                                                                                                              |

**Live verification.**

- **The four paths of `up`**, against real Docker:
  - the first `up` started each target at its address and MAC;
  - a repeated `up` touched no container;
  - a web target re-created by hand, with Docker's random MAC `3a:2e:0d:74:a2:00`, was
    replaced, and its content rewritten;
  - after `down` and `up`, the same four MACs, and ARP from inside the network answers with them.
- **Across a re-creation.** A scan, `down` and `up` (four new container IDs), then a second scan,
  both on `ad4aab7`:
  - both stored the fixed MACs;
  - they compare identical apart from time, under `--strict` too;
  - against B3's `after3` (random MACs), the only difference is the MAC column of the assets.
- **B3's six recorded runs**, 15 pairs, compared again:

  | Pairs                                                         | Default                                                     | `--strict`                         |
  | ------------------------------------------------------------- | ----------------------------------------------------------- | ---------------------------------- |
  | The 6 pairs among `before`, `before2`, `before3` and `after3` | identical                                                   | identical                          |
  | The 4 pairs of `after2` with those                            | identical, with 2 tolerated (frames and `after_discovered`) | 2 differences                      |
  | The 5 pairs with `after`                                      | 1 difference: the Nuclei finding                            | 3 differences (1 against `after2`) |

**Limitations.**

- **The scanner container's MAC is still random.** It never reaches a stored row or a compared
  frame: the sweep reports only the four targets. So it was left alone.
- **The tolerance covers the two shapes B3 measured.** Any other timing-dependent difference is
  still reported as a difference, which is the safe direction. Repeat the runs in alternation, as
  before.
- **The Nuclei gap on Redis is unchanged**, and was not part of this work. A comparison can still
  fail on it.

### B4 — the benchmark package stops re-exporting its database loader

Commit `f4e05e2`, committed in place.

**The dependency.** Inspected on `908da54`:

- **The re-export.** `core/benchmarks/__init__.py` re-exported `core.benchmarks.loader`, which
  imports SQLAlchemy and the compliance models.
- **Why it reached so far.** Importing a submodule runs the package's `__init__` first. So
  `core.benchmarks.pack`, the pure content parser, loaded the database layer, and so did the SCAP
  compiler, whose `core.scap.translate` imports it.
- **Who used it.** No application module imported a loader name from the package; every import
  in the application already names a submodule (`pack`, `selection`, `loader`). The package-level
  loader names were used by the two operator scripts (`scripts/benchmarks/load_benchmark.py`,
  `load_stig.py`) and one test.

**The change.**

- **The package exports the `pack` names only**, as the same objects as before. Its docstring now
  says why: `loader` and `selection` need the database and are imported by name.
- **The callers.** The two scripts and `tests/compliance/test_benchmark_end_to_end.py` import
  `load_pack_into_db` from `core.benchmarks.loader`. Nothing else changed.
- **Behaviour is unchanged.** No function or table changed. The code that runs at scan time, the
  credentialed audit's `core.benchmarks.selection` and the SCAP collector, is the same code. It
  no longer imports the loader as a side effect.

**Interfaces: identical.** `interface_snapshot --compare` on `908da54` and `f4e05e2` reports
"interfaces identical": routes, route limits, Celery tasks, the beat schedule and the OpenAPI
digest.

**Coupling** (`capability_map`).

- **Every count is unchanged:** 484 modules, 40 upward and 74 lateral edges, the cycle at 22/13,
  79/17 foreign-table references and writes, 466/386 cross-capability imports. The import B4
  removed, `core.benchmarks` → `core.benchmarks.loader`, is inside one capability.
- **What changed is the load profiles.** `core.benchmarks.pack` and `core.scap.oval` no longer
  load ten capabilities or SQLAlchemy. Each now loads `check_kernel` and `infra` only. The
  compiler's 32 modules are 26 of the configuration-audit and SCAP code itself, 5 of
  `core.checks` (`check_kernel`), and the `core` package (`infra`).
  `capability_map --check` refused until the baseline recorded that, and `--write-baseline`
  changed those two entries only.

**Import cost** (`import_cost --compare`, first-party / all modules):

| Module                                                                |    Before |     After | Watched modules that stopped loading                                                           |
| --------------------------------------------------------------------- | --------: | --------: | ---------------------------------------------------------------------------------------------- |
| `core.scap`, `core.scap.oval`, `core.scap.xccdf`, `.translate`        |  61 / 383 |   32 / 90 | SQLAlchemy, `config`, `db.base`, `db.models`, `db.models.compliance`, `core.benchmarks.loader` |
| `core.benchmarks`, `core.benchmarks.pack`                             |  54 / 368 |   25 / 72 | the same                                                                                       |
| `core.benchmarks.selection`                                           |  60 / 374 |  59 / 373 | `core.benchmarks.loader`; it still needs the database                                          |
| `core.benchmarks.loader`, the two scripts, `core.config_audit.engine` | unchanged | unchanged | none: the loader and the scripts need the database by design                                   |

The plan's target was "SCAP compiler 61 → ~30 modules, no database"; it is 32, with none.

**Tests.**

| Step            | Command / targets                                                                                                                                                                                                                   | Passed | Failed | Skipped | Notes                                                                                                                                                                                                                        |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New             | `tests/compliance/test_benchmark_package_split.py`                                                                                                                                                                                  |      6 |      0 |       0 | The package's imports and API; the compiler converts a SCAP fixture and the parser round-trips it and reads a shipped pack with no database module loaded; no caller, scripts included, takes a loader name from the package |
| Mutation        | the new file, on a scratch worktree with: M1 the package as it was before B4; M2 `load_stig.py` importing the loader name from the package again; M3 the pack parser gaining a database import; M4 the package dropping `dump_pack` |      — |      — |       — | Caught: M1 by 3 tests, M2 by 2, M3 by 1, M4 by 3                                                                                                                                                                             |
| Focused         | the new file and every benchmark and SCAP test: `test_benchmark_{end_to_end,pack,loader,compliance}`, `test_scap_{content,parsers}`, `test_scan_policy_selection`, on a clean worktree of `f4e05e2`                                 |    199 |      0 |       0 |                                                                                                                                                                                                                              |
| Targeted groups | `tests/assets tests/compliance tests/credentialed tests/repo tests/scans tests/security`, the groups the selector named                                                                                                             |  5,594 |      0 |       1 | `alembic.ini`. B3's 5,568, the 20 live-validation tests and these 6                                                                                                                                                          |
| Architecture    | `check.py`; `capability_map --check`; pre-commit                                                                                                                                                                                    |      — |      — |       — | All pass                                                                                                                                                                                                                     |

**The full suite was not run.** The selector reported a targeted scope, and `CLAUDE.md` runs a
complete suite only when the selector reports `full` or a step asks for one. The analysis (§11)
puts the next full run at the end of Phase B.

**Runtime validation: the operator scripts, before and after.**

- **No live scan.** The analysis (§11) requires live scans for B2, B3, C2, C3 and C6, not B4.
  The harness could not observe B4 either:
  - its scans are unauthenticated;
  - the only scan-time importers of the package are the credentialed audit's
    `core.benchmarks.selection` and the SCAP collector, which the harness never runs, and whose
    code B4 did not change.
- **What runs differently is the two scripts.** Each commit's code (`git archive`) ran in the
  backend image against its own throwaway PostgreSQL on an internal network, bootstrapped as CI
  does. The steps:
  - `load_benchmark.py --dir data/benchmarks --dry-run`;
  - the same, applied;
  - the same again, to show it is idempotent;
  - `load_stig.py --load` on a datastream built from the SCAP tests' fixtures.
- **Result: identical on `908da54` and `f4e05e2`.**
  - Every step exited 0, with the same output.
  - Every row of `compliance_frameworks`, `_controls`, `_rules` and `_rule_controls` for the
    three benchmark frameworks was the same, timestamps excluded: 3 frameworks, 24 controls, 21
    rules, 21 links.
  - The converted pack was the same.

**Limitations.**

- **The loader, `selection` and the scripts still load the database.** That is their job. B4
  separated the pure half of the package from them; it did not change them.
- **The SCAP compiler still loads two other capabilities.** `check_kernel` is the five
  `core.checks` modules the configuration-audit spec builds on. `infra` is only the `core`
  package's own `__init__`, which every `core.*` import runs. The baseline records both.
- **The runtime check used the scripts' scratch driver**, not committed tooling: the live-scan
  tooling covers scans, and B4 changed no scan.

### B5 — the network checks register their plugins with the check kernel

Commit `54f912d`, committed in place.

**The dependency.** Inspected on `3a38ea6`:

- **What the module does.** `core/checks/legacy_plugins.py` verifies that every plugin the
  network checks can dispatch is callable the way `VulnerabilityEngine` calls it.
  `tests/scans/test_plugin_contract.py` is that guard.
- **How it reached the engine:**
  - a lazy import of `engines.vulnerability.plugin_selector`, for the dispatch tables;
  - an `importlib.import_module("engines.vulnerability.plugins.<name>")` per plugin.
- **The effect.** The kernel every capability imports depended on one engine: two upward edges
  in the capability map. The second reach was a string, so no import graph saw it.
- **The callers:**
  - the guard test;
  - `docs/audits/plugin-audit-2026-10-14/export_inventory.py`, a script inside a dated audit
    record. It is unchanged and still runs: it imports the selector before calling the kernel.

**The change: the plan's "the adapter moves to network checks and registers itself".**

- **The kernel keeps the contract.** `PluginContract` and the two arities stay, and so do its
  functions (`all_dispatchable_plugin_names`, `describe_plugin`, `validate_plugin_module`,
  `validate_all_plugins`), with the same names, signatures and answers.
- **It gains a registration point.** A `PluginSource` is an engine's dispatch table and a loader
  that imports one plugin and raises whatever its import raises. `register_plugin_source` adds
  one; `registered_plugin_sources` lists them. The kernel imports nothing outside the standard
  library and `core.checks`, and nothing by name.
- **The adapter moved into the selector,** reading its own tables: `dispatch_table()` and
  `load_plugin_strictly()`. The selector registers them as `network_checks` when it is imported.
- **Why the selector and not a separate adapter module.** The selector would have had to import
  that module, and the module reads the selector's tables: an import cycle, which the ratchet
  refuses.
- **With nothing registered, every kernel function raises `NoPluginSource`.** It never answers
  with an empty mapping, which would read as "every plugin is callable" about plugins nobody
  looked at.
- **Ambiguity is refused.** A plugin claimed by two sources raises, and so does a name in no
  table when there is more than one source to ask. A source registered again under the same
  name replaces the earlier one.
- **Errors stay findings.** The loader is the old `importlib` call, not the selector's `_load`,
  which logs and skips a broken plugin. A plugin's import error is still reported as one, and
  the source is resolved before the `try`. So a `KeyError` raised inside a plugin's import stays
  a finding about the plugin rather than becoming a lookup refusal.
- **The guard test** imports the selector, which registers the plugins.

**Interfaces: identical.** `interface_snapshot --compare` on `3a38ea6` and `54f912d` reports
"interfaces identical".

**Coupling** (`capability_map`):

| Measure                                    | Before (`3a38ea6`) | After (`54f912d`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Upward edges                               |                 40 |            **38** |
| Lateral edges                              |                 74 |                74 |
| Largest cycle, all / top-level             |            22 / 13 |           22 / 13 |
| Foreign-table references / writes          |            79 / 17 |           79 / 17 |
| Cross-capability imports, top-level / lazy |          466 / 386 |     **467 / 384** |

- **Removed:** `core.checks.legacy_plugins → engines.vulnerability` and
  `→ engines.vulnerability.plugin_selector`. The baseline records the removal, and `CEILINGS`
  lowers the upward edges to 38.
- **Added:** `engines.vulnerability.plugin_selector → core.checks.legacy_plugins`, top-level.
  It points down a layer.
- **The plan's target, "check kernel depends on nothing above it", is met.** The check kernel's
  only remaining cross-capability import is `core.checks.intrusive`'s lazy import of `config`,
  which is `infra`, the shared layer below it. Its count of non-shared capabilities imported fell
  from 1 to 0, the analysis's target for it (§12).
- **It is still counted in the all-imports cycle,** through that `config` import, because `infra`
  is itself in the cycle:
  - the model registry `db.models` imports every capability's models;
  - `core.celery_app` imports the platform registry.
    That is outside B5.

**Import cost** (`import_cost --compare`, first-party / all modules):

- **At import, the kernel is unchanged** (7 / 42): its imports of the engine were always lazy.
- **The selector and the vulnerability engine** each load one more module, the kernel's
  `legacy_plugins`: 10 / 45 → 11 / 46 and 25 / 510 → 26 / 511.
- **The difference is at call time.** Before, calling the kernel's functions imported the
  selector and all fifteen plugins. Now, with nothing registered, they refuse and load no
  engine. A test pins that.

**Behaviour: every plugin-contract answer is unchanged.** One script recorded each answer the
kernel gives, on `3a38ea6` and on a clean worktree of `54f912d` (with the selector imported).
The two outputs are byte-identical:

- the dispatch table (15 plugins, `cve_engine` and `nuclei_probe` serial);
- all fifteen `PluginContract`s;
- `validate_all_plugins` (no broken plugin) and `validate_plugin_module` for each;
- the error for an unknown name:
  `ModuleNotFoundError: No module named 'engines.vulnerability.plugins.<name>'`.

**Tests.**

| Step            | Command / targets                                                                                                                                                                                                                                                                            | Passed | Failed | Skipped | Notes                                                                                                                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| New and guard   | `tests/scans/test_plugin_source_registration.py` (8, new) and `tests/scans/test_plugin_contract.py` (22), on a clean worktree of `54f912d`                                                                                                                                                   |     30 |      0 |       0 | The kernel's imports; no `core.checks` edge above the kernel; the refusal when nothing is registered, with no engine loaded; the selector's own tables; the strict loader; the merge rules |
| Mutation        | the two files, on a scratch worktree with: M1 the kernel importing the selector to register it; M2 an unregistered kernel answering with nothing; M3 the selector not registering; M4 the selector registering its `_load`, which logs and skips; M6 two sources allowed to claim one plugin |      — |      — |       — | Caught: M1 by 3 tests, M2 by 1, M3 at collection (the guard cannot list the plugins), M4 by 1, M6 by 1                                                                                     |
| Targeted groups | `tests/assets tests/audit_boundary tests/compliance tests/credentialed tests/repo tests/scans tests/security tests/web`, the groups the selector named                                                                                                                                       |  6,306 |      0 |       2 | `alembic.ini`; the live OSV npm feed                                                                                                                                                       |
| Architecture    | `check.py`; `capability_map --check`; pre-commit                                                                                                                                                                                                                                             |      — |      — |       — | All pass                                                                                                                                                                                   |

**The full suite was not run.** The selector reported a targeted scope; §11 puts the next full run
at the end of Phase B.

**The dated audit script.** It ran on fresh worktrees of `3a38ea6` and `54f912d`:

- **What is identical:** every plugin's contract, problems, trigger ports, dispatch and `run`
  line, and every count (15 plugins, all loadable and contract-valid).
- **What differs, as it should:**
  - `plugin_selector.py`'s hash and symbols: `dispatch_table` and `load_plugin_strictly` were
    added;
  - two plugins' `test_references`, because the new test file names `snmp_probe` and
    `cve_engine`.
- **Fresh checkouts on both sides are required.** The main working tree holds 184 files with
  CRLF line endings, which `core.autocrlf=input` keeps out of `git status`. A first comparison
  against the main tree differed in 34 file hashes for that reason alone.

**Live validation, before and after.**

- **Why it was run.** §11 does not require it for B5. But B5 changed `plugin_selector`, which
  every vulnerability audit runs.
- **Set-up.** The live-scan tooling, against the targets with fixed MACs. In the repeat, a watcher
  recorded each scanner's interfaces from inside its container while it ran.

| Run       | Commit    | Scanner's `eth0`     | Full audit                                                                 | Stopped sweep: hosts in the first frame |
| --------- | --------- | -------------------- | -------------------------------------------------------------------------- | --------------------------------------- |
| `before`  | `3a38ea6` | not recorded         | **`unreachable`**: discovery found no host by ARP; 1 phase, nothing stored | 2                                       |
| `after`   | `54f912d` | not recorded         | complete: 3 phases, 4 hosts, 4 services, 7 findings, 13 frames             | 4                                       |
| `before2` | `3a38ea6` | the targets' network | the same as `after`                                                        | 1                                       |
| `after2`  | `54f912d` | the targets' network | the same as `after`                                                        | 1                                       |

**The comparisons:**

- `before2` against `after2`: **identical apart from time.** Nothing even needed tolerating.
- `before2` against `after`, and `after` against `after2`: identical apart from time, plus the two
  timing differences, tolerated and printed (the stopped sweep's frames and `after_discovered`).
- **Against `before`:** 9 differences, all from its failed discovery.

**The failed run was the tooling, not B5.**

- **The symptom.** Its full audit's discovery batch ended at 2.1 s with no host marked active by
  ARP, and the stopped sweep found 2 hosts. That is the symptom B2 recorded when the scanner's
  first interface is the database network rather than the targets' (§6, B2).
- **The mechanism, measured.** `live_scan.sh` creates the scanner on the targets' network,
  connects the database network, then starts it, and relies on Docker naming the first network
  `eth0`. Docker does not guarantee that. In 12 trials of the same sequence on throwaway
  networks, one put the second network on `eth0`. Neither network gives a default route that
  would correct it.
- **The defect predates B5.** It has been in the tooling since `22aa824`. It is recorded in §7
  and not fixed here: it is outside B5. Fixed in `44cb889`, before B6, which also found the exact mechanism: Scapy follows the order
  Docker attaches the networks in, not their names (below).
- **The attribution is by symptom.** The failed run's own interfaces were not recorded; the
  watcher was added for the repeat.

**Limitations.**

- **The kernel answers only once an engine has registered.** A process that imports the kernel
  alone gets `NoPluginSource`, by design. Today the guard test and the audit script both import
  the selector first.
- **Registration is process-global.** The tests that register a fake source restore the
  registry afterwards.
- **The check kernel stays in the all-imports cycle** through `infra`, as described above.

### Before B6: the live-scan harness sets Scapy's interface

Commit `44cb889`, tooling only, before B6, as the owner asked on 20 Oct 2026. It settles the §7
item B5 added.

**What B5's failed run was.** Each finding was measured on throwaway internal networks, in the
backend image.

- **Docker does not guarantee attach order.** Created on one network and connected to a
  second before starting, a container got the second network as `eth0` in 1 of 12 trials (B5).
- **Pinning interface names does not help.** Docker obeys an explicit name
  (`com.docker.network.endpoint.ifname`): 20 of 20 trials, and 12 of 12 when the names were
  inverted. But Scapy does not choose by name.
- **What Scapy follows is attach order.** With no default route, Scapy takes the interface of the
  broadest route it knows. That is the multicast route `224.0.0.0/4`, present on every interface
  and listed in attach order. With the database network attached first, Scapy's default was the
  database interface whatever the names said.
- **That is what broke discovery.** With the database network attached first, ARP to the SSH
  target from Scapy's default interface got no reply in 3 of 3 trials. From the targets'
  interface, it was answered in 3 of 3.

**The fix.**

- **The harness sets `scapy.conf.iface` before any scan,** to the interface holding the scanner's
  address on the targets' network. `live_scan.sh` passes that address as
  `CCURE_LIVE_SCANNER_ADDRESS`.
- **It refuses before creating anything** if no interface, or more than one, holds the address.
- **The result records the choice:** the interface used (`pinned`) and the one Scapy would have
  used (`scapy_default`).
- **This mirrors production.** On the worker's host network, Scapy's default is the interface of
  the default route, the one facing the targets.
- **The application's code path is unchanged.** `srp` reads `conf.iface` either way, and no
  discovery or port code names an interface.
- **The scripts are now executable.** `22aa824` committed `live_scan.sh` and `targets.sh` as
  `100644`, because `core.filemode` is false here. In a fresh checkout the documented
  invocations failed with "permission denied". They are recorded as `100755`.

**Verification.**

| Check                                                      | Result                                                                                                                                                                                 |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/repo/test_live_scan_tooling.py`, the tree committed | 37 passed: the 33 before and 4 new (the interface choice; Scapy pointed at it in the order B5 failed in; the refusal before anything is created, twice)                                |
| Mutations                                                  | Caught: T1 `main()` not pinning (2 tests); T2 the pin not setting `conf.iface` (1); T3 falling back to the first interface (2); T4 the script not passing the address (1)              |
| The harness's own pin, in the backend image                | Targets attached first: Scapy's default already right, kept. Database first: default `eth0` (database), moved to `eth1`. No interface holding the address: refused, naming what it saw |
| Live, database network created first, fixed tooling        | The run's own record: `scapy_default` `eth0`, `pinned` `eth1`. It completed: 4 hosts, 4 services, 7 findings, 13 frames                                                                |
| Live, the same set-up, old tooling                         | Also completed. Docker evidently attached the targets' network first in that run: reversing the creation order shifts the odds, it does not force the order                            |
| Live, normal order, fixed tooling                          | B6's pair (below): both runs recorded `scapy_default` and `pinned` as `eth0` (`172.30.250.5`) and completed                                                                            |

**What proves the fix.** It is the fixed run's own record, together with the direct ARP test.
The run recorded the configuration in which ARP gets no reply, and completed anyway. There is no
forced old-against-new reproduction: the old tooling's failure cannot be forced from outside
Docker.

### B6 — the topology engine takes the organisation's slug from its task

Commit `ff7ddca`, committed in place.

**The dependency.** `core/topology/engine.py:57` imported `ccure_platform.api` at module level.
It was used once, in `run_topology_mapping`:

- **The lookup:** `platform_api.organisation(db, org_id)`, for the organisation's slug, or its id
  when the organisation no longer exists.
- **Why the slug matters.** Every network-link id is derived from it (`gen_network_link_id`), so a
  different value re-keys every link.
- **The cost of the import.** The SNMP engine loaded FastAPI, python-jose, Starlette and Redis.

**The change: "identity lookups passed in by the task".**

- **`run_topology_mapping` takes `org_slug`**, keyword-only and required. It is required rather
  than defaulted, so a caller that forgot it cannot fall back silently and re-key every link.
- **The task resolves it.** `run_topology_mapping_task` (`core/tasks.py`, which already imported
  the platform API) applies the engine's old rule.
- **The four test calls** pass `org.slug`, which is what the old lookup returned for them.
- **Behaviour is unchanged.** The slug and the fallback are the same, so the link ids are too. A
  new test pins that links are keyed by the slug passed in.

**Interfaces: identical.** `interface_snapshot --compare` on `44cb889` and `ff7ddca` reports
"interfaces identical".

**Coupling** (`capability_map`).

- **Two top-level cross-capability edges went** (467 → 465): `core.topology.engine` →
  `ccure_platform` and → `ccure_platform.api`. The task module's platform imports are unchanged.
- **Every other count is unchanged:** upward 38, lateral 74, the cycle at 22/13, foreign 79/17,
  lazy 384.
- **The baseline records the engine's smaller load profile:** FastAPI, `jose` and Redis are gone,
  and SQLAlchemy stays.

**Import cost** (first-party / all modules):

| Module                                            |    Before |     After | Stopped loading                                                    |
| ------------------------------------------------- | --------: | --------: | ------------------------------------------------------------------ |
| `core.topology.engine`                            |  62 / 632 |  32 / 345 | the platform API, FastAPI, `jose`, Starlette, Redis                |
| `routers.topology`                                |  61 / 631 |  61 / 631 | none: the router imports the platform API itself, as the HTTP edge |
| `core.tasks`, `core.topology.client`, `.identity` | unchanged | unchanged | none                                                               |

**The plan's target is half met.** "No FastAPI" holds. "~15 modules" does not: 32 remain.

- **Why:** the engine still imports `db.models` for `Asset` and `Scan`.
- **What loads with it:** the model registry brings in `config`, `db`, every capability's models
  and the platform's own models, which is 28 of the 32 modules.
- **What is topology's own:** 4 modules, `core.topology`, the engine, `identity` and
  `db.models.topology`.
- **What reaching ~15 would take:** moving the engine's database reads and writes behind a port.
  That is the "writes assets" coupling the analysis lists for topology; it is recorded in §7.

**Tests.**

| Step             | Command / targets                                                                                                                                                                                                                 | Passed | Failed | Skipped | Notes                                                                                                                                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| New and topology | `tests/topology` (80 before, 7 new in `test_topology_engine_platform_free.py`), on a clean worktree of `ff7ddca`                                                                                                                  |     87 |      0 |       0 | The engine names no platform module; no `core.topology` edge into the platform; no web stack loaded; `org_slug` required; links keyed by the slug passed in; the task passes the slug, with the old fallback |
| Mutation         | the new file, on a scratch worktree with: M1 the engine importing the platform API again; M2 `org_slug` defaulted; M3 the task not passing it; M4 the task passing the id; M5 the engine keying links by the id                   |      — |      — |       — | Caught: M1 by 3 tests, M2 by 1, M3 by 2, M4 by 1, M5 by 1                                                                                                                                                    |
| Targeted groups  | `tests/assets tests/auth tests/compliance tests/credentialed tests/modules tests/rbac tests/repo tests/reports tests/scans tests/security tests/topology tests/web`, the groups the selector named (`core/tasks.py` reaches most) |  7,555 |      0 |       3 | Audit retention not installed; `alembic.ini`; the live OSV npm feed                                                                                                                                          |
| Architecture     | `check.py`; `capability_map --check`; `identity_boundary` (unchanged: 3 importers, 2 queries); pre-commit                                                                                                                         |      — |      — |       — | All pass                                                                                                                                                                                                     |

**The full suite was not run.** The selector reported a targeted scope; §11 puts the next full run
at the end of Phase B.

**Live validation.**

- **Not required.** §11 does not require it for B6, and the harness cannot exercise topology: no
  target speaks SNMP, and the topology task runs only when a scan carries SNMP settings. The
  topology tests drive the real engine against the real database, with stubbed SNMP walks.
- **Run anyway, for two reasons:**
  - B6 changed `core/tasks.py`, which every scan loads;
  - it is the fixed tooling's first use in the normal order.

| Run      | Commit    | Interface (`pinned` / `scapy_default`) | Full audit                                                     | Stopped sweep |
| -------- | --------- | -------------------------------------- | -------------------------------------------------------------- | ------------- |
| `before` | `44cb889` | `eth0` / `eth0`, `172.30.250.5`        | complete: 3 phases, 4 hosts, 4 services, 7 findings, 13 frames | `cancelled`   |
| `after`  | `ff7ddca` | `eth0` / `eth0`, `172.30.250.5`        | the same                                                       | `cancelled`   |

**Identical apart from time**, with nothing even needing tolerance. The scan rows, phases, assets
(with the fixed MACs), services, findings, task results and every frame match.

**Limitations.**

- **The engine still loads the model registry** through its own `Asset` and `Scan` access (above).
- **Topology is not exercised live.** There is no SNMP target among the validation targets.

### B7 — the PDF renderer takes its engine inputs from the payload

Commit `234a423`, committed in place.

**The dependency.** Inspected on `cd354fc`. `reporting/pdf_generator.py` imported two things from
the engines, each for one methodology-appendix row:

- **`COVERAGE_ROWS`** from `engines.credentialed.coverage`: three `(metadata key, label)` pairs
  naming the credentialed coverage claims. The claims' text is already in the scan's metadata.
- **`describe`** from `core.candidate_enumeration`: the sentence for a truncated candidate search.
  That module imports `core.vuln_intel`, which loads SQLAlchemy and the configuration.
- **The effect.** A renderer, meant to be a payload in and a document out, loaded engine code and
  the database layer: two lateral edges, and the renderers inside the capability cycle.
- **`csv_generator.py`**, which the plan also names, imports no engine (only `report_helpers` and
  the check kernel), as it already did on `c0c0f4e`. It is unchanged.

**The change: "coverage rows and candidate-enumeration notes passed in with the payload".**

- **The builder.** `scans/report_inputs.py` builds `report_inputs`:

  - the coverage `(key, label)` pairs;
  - the truncated-search notes, described for the summary's list and the metadata's list
    separately, since the renderer still chooses between them.

  `with_report_inputs(result)` attaches them to a shallow copy of the payload.

- **Built when a report is rendered, never stored with the scan.** So a report regenerated for an
  old scan gets them exactly as a new one does.
- **The callers wrap their payloads.** These are the two production callers: the orchestrator's
  `generate_phase_report` (all four scan-time report paths in `core/tasks.py` go through it) and the
  router's `_load_scan_report_paths` (regeneration on download).
- **The renderer refuses rather than drops.** It rejects a payload without `report_inputs`, and
  notes that do not match their truncation list. A report that silently lost those rows would read
  as a more complete assessment than the scan made.
- **Why the builder sits in `scans`.** It imports two layer-3 capabilities, so it must sit above
  them. The orchestrator (`scans`, layer 5) calls it, so it cannot sit above layer 5. In `scans`
  both directions point down or stay inside one capability. It is mapped in `capability_map`.
- **Every direct caller passes the inputs:** the tests that render a technical report or call the
  two helpers, and `scripts/verification/verify_report_integrity.py`.
- **The RBAC authorization inventory is regenerated.** It records each guard's line, and five
  guards in `routers/reports.py` moved down three lines. The targeted run caught it (below).

**Golden: report bytes identical, the plan's criterion.** This is the Phase 5 method (§3.1 of
`PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md`): capture twice before, then after.

- **What was rendered.** A scratch capture rendered 11 payloads to their executive and technical
  PDFs: 22 files, deterministically (ReportLab `invariant` mode, the renderers' clock frozen).
  - The payloads are the integrity script's sample, plus variants covering every branch of the
    two helpers:
    - full and partial credentialed coverage;
    - truncations in the summary (three, and eight for "and N more");
    - in the metadata only;
    - in both, where the summary wins;
    - an empty list, and absent;
    - all of it together, and a discovery-only scan.
  - On B7 each payload was wrapped with `with_report_inputs`, as production does.
- **The capture is sensitive.** Ten of the 11 technical PDFs differ from one another. The
  eleventh, the sample, is the same as "absent", correctly: the sample records no truncation.

| Capture                                                                                               | Result                                                                          |
| ----------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `cd354fc`, twice                                                                                      | identical: the capture is deterministic                                         |
| B7 working tree, then a clean worktree of `234a423`                                                   | **byte-identical** to `cd354fc`, all 22                                         |
| Through the production wrapper, `ScanOrchestrator.generate_phase_report`, raw payloads, on both trees | both PDFs for all 11 on each; identical between trees and to the direct capture |

**Interfaces: identical** (`interface_snapshot --compare`, `cd354fc` against B7).

**Coupling** (`capability_map`):

| Measure                                    | Before (`cd354fc`) | After (`234a423`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Lateral edges                              |                 74 |            **72** |
| Largest cycle, all imports                 |                 22 | **16** (and 4, 2) |
| Largest cycle, top-level                   |                 13 |            **12** |
| Upward edges                               |                 38 |                38 |
| Foreign-table references / writes          |            79 / 17 |           79 / 17 |
| Cross-capability imports, top-level / lazy |          465 / 384 |         466 / 384 |

- **The two lateral edges are gone:** `reporting.pdf_generator` → `core.candidate_enumeration` and
  → `engines.credentialed.coverage`. The builder's imports of them point down a layer.
- **The capability knot split.** The 22-capability cycle became three:
  - 16 Audit feature capabilities;
  - 4: `check_kernel`, `infra`, `platform`, `renderers`;
  - 2: `scan_kernel`, `vuln_intel`.
- **The renderers left the top-level cycle.** `CEILINGS` now holds the largest cycle at 16, the
  top-level at 12 and the lateral edges at 72.
- **What keeps the renderers in the 4-cycle** is one lazy edge into them:
  `ccure_platform.audit_log.export` → `reporting.report_helpers`, the platform's audit-log export
  borrowing a renderer helper. That edge is not the renderers importing anything, so it is
  outside B7. It is recorded in §7.

**Import cost** (first-party / all modules):

| Module                                                         |     Before |      After | Stopped loading                                                              |
| -------------------------------------------------------------- | ---------: | ---------: | ---------------------------------------------------------------------------- |
| `reporting.pdf_generator`                                      |   24 / 380 |   15 / 218 | SQLAlchemy, `config`, `core.vuln_intel`, both engine modules                 |
| `reporting.availability`                                       |   25 / 381 |   16 / 219 | the same (it imports the PDF renderer)                                       |
| `orchestrator.scan_orchestrator`                               |   60 / 960 |   58 / 958 | the coverage module at import: the orchestrator now loads it when it renders |
| `routers.reports`                                              | 121 / 1269 | 122 / 1270 | none (adds `scans.report_inputs`)                                            |
| `reporting.csv_generator`, `host_assessment`, `report_helpers` |  unchanged |  unchanged | none                                                                         |

**Tests.**

| Step            | Command / targets                                                                                                                                                                                                                                                                                                            | Passed | Failed | Skipped | Notes                                                                                                                                                                                                                                   |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New             | `tests/reports/test_renderer_report_inputs.py`                                                                                                                                                                                                                                                                               |      9 |      0 |       0 | Renderer edges and load; the two refusals; what the inputs carry; the payload left alone; both callers statically; the router's regeneration end to end against the database                                                            |
| Mutation        | the new file, on a scratch worktree with: M1 the renderer importing the coverage rows again; M2 a missing input defaulted instead of refused; M3 the router rendering without inputs; M4 the orchestrator rendering without them; M5 the builder dropping the metadata's notes; M6 the renderer not checking the notes match |      — |      — |       — | Caught: M1 by 2 tests, M2 by 1, M3 by 2 (static and the router end to end), M4 by 1 (static: the orchestrator swallows the error, so only the static test can see it), M5 by 1, M6 by 1                                                 |
| Focused         | the new file with every directly affected file and `test_report_integrity`                                                                                                                                                                                                                                                   |    231 |      0 |       0 | Before the router test was added                                                                                                                                                                                                        |
| Targeted groups | `tests/audit tests/compliance tests/credentialed tests/rbac tests/repo tests/reports tests/scans tests/security tests/topology`, the groups the selector named                                                                                                                                                               |  6,485 |  **2** |     210 | Both failures were the RBAC inventory's stale line numbers (above). After regenerating it, `tests/rbac tests/repo`: 1,381 passed, 0 failed, 2 skipped. The 210 skips are the audit-chain and retention DBA bootstraps and the usual two |
| Committed tree  | a clean worktree of `234a423`: the B7 file, every directly affected file and both inventory tests; `build_migration_inventory --check`                                                                                                                                                                                       |    201 |      0 |       0 | "inventory is current"                                                                                                                                                                                                                  |
| Architecture    | `check.py`; `capability_map --check`; pre-commit                                                                                                                                                                                                                                                                             |      — |      — |       — | All pass                                                                                                                                                                                                                                |

**The full suite was not run.** The selector reported a targeted scope; §11 puts the next full run
at the end of Phase B.

**No live scan.**

- **Not required.** §11 requires live scans for B2, B3, C2, C3 and C6, not B7.
- **It could not observe B7 anyway.** The harness never looks at reports. The orchestrator is
  built `silent=True` and `generate_phase_report` turns any failure into "no report", so a broken
  render inside a live scan leaves no trace.
- **What validates the runtime paths instead:**
  - the orchestrator golden (the production wrapper, all 11 payloads, identical);
  - the router test (the regeneration function against the database).

**A pre-existing failure the verification script shows.**

- **The symptom.** `scripts/verification/verify_report_integrity.py` exits 1 on `cd354fc` and on
  B7 alike, with the same output: the technical report lacks the provenance marker "How this was
  detected".
- **The cause.** That heading stopped being printed on 22 Aug 2026 (`f30e1df`, before this
  branch). It is now a code comment, and the per-finding line reads "Detection: …". The script's
  marker list is stale.
- **Not fixed here;** recorded in §7.

**Limitations.**

- **The renderers stay in a 4-capability cycle** through the platform's audit-log export (above).
- **`web_pdf_generator`** is classified with web DAST and still imports `scan_helpers`. It is not
  one of the renderers B7 named.
- **The golden covers the two touched helpers and whole reports for 11 payloads.** It is not every
  report the product can produce; the targeted groups cover the rest of the renderer's behaviour.

### B8 — the orchestrator composes the engines; the platform registers its models alone

Three commits, one per part of the plan's step, committed in place: `6cd4ca3` (B8a), `eb52943`
(B8b), `a6a23b6` (B8c). A fourth, `fe5baaf`, records a test baseline the full suite called for
(below).

**The scope** (analysis §10, B8): "(a) Port engine and discovery enrichment import sibling engines;
(b) Audit models attach seven back-references onto platform classes; the platform loads all models
→ compose enrichment in orchestration; replace `backref=` with one-sided relationships if nothing
reads them; split the model registry so the platform registers alone." Target: "Platform loads
without Audit's models".

- **Not in the step:** the analysis's §7.3 platform row also says "move `report_helpers` into a shared rendering
  module". The step does not name it, so it stays the §7 item B7 recorded.

#### B8a — the orchestrator composes the engines' enrichment

**The dependency.** Inspected on `bfcf36f`.

- **The port engine** ended every `run()` with `_lightweight_snmp_check` and
  `_ot_enrichment_check`. They imported discovery enrichment's `_snmp_lightweight_probe` and
  `_ot_protocol_probes` (a lateral edge) and the asset registry's `classify_device` (an upward
  edge).
- **Discovery enrichment's SNMP probe** imported twelve names from the network checks'
  `snmp_probe`: the SNMP client, its BER decoders, the OIDs and the enterprise-vendor table (a
  lateral edge).
- **Who calls them.** The orchestrator is the only production caller of either engine.

**The change.** A new module, `orchestrator/host_enrichment.py`, mapped to the scans capability:

- **`enrich_after_port_scan(hosts, *, exclude_ot_from_nmap)`** is the port engine's two steps,
  moved unchanged. The orchestrator awaits it on the hosts it gave the port engine:
  - straight after `port_engine.run` and before OS inference;
  - with the engine's own `exclude_ot_from_nmap`.
- **`snmp_system_query(ip)`** is the SNMP read the probe used to make itself, moved unchanged:
  sysObjectID first, then sysDescr, sysName, forwarding, the interface count and the bridge MIB.
  - **The probe keeps the interpretation** (identity, OS evidence, port registration) and takes the
    read as an argument.
  - **The discovery engine** takes it as `snmp_query` (`core.engine_ports.SnmpSystemQuery`) and
    passes it to `enrich_host`.
  - **The orchestrator gives it to all five discovery engines it builds.** An engine given none
    makes no SNMP request.
- **The imports stay inside the functions**, as they were in the engines, so importing the
  orchestrator loads one module more (the new one) and nothing else.

**Golden: identical.** `b8a_golden.py`, a scratch script, drives the trees' own code with the
network replaced:

- **What is faked:**
  - SNMP agents behind `snmp_probe._snmp_get_raw`: Linux, Windows, a switch, one that fails
    mid-read, a non-OID answer, none;
  - the OT probes and the other discovery probes;
  - nmap's results;
  - discovery's probing (the engine's own `_enrich_active` still runs).
- **What it captures, over eleven hosts:**
  - the orchestrator's port phase, with OT exclusion on and off, light and normal;
  - its AGGRESSIVE and FAST discovery;
  - discovery's enrichment called directly;
  - for each: the phase result, every raw host record after OS inference, and each host's
    sequence of SNMP requests and OT probe calls.
- **The branches it reaches:** 161 closed and open, credentialed OS precedence, OT inclusion and
  exclusion, an already identified host, a failing probe, an inactive host.

| Capture                                                                    | Result                                               |
| -------------------------------------------------------------------------- | ---------------------------------------------------- |
| `bfcf36f`, twice                                                           | identical once the scan timestamp is dropped         |
| B8a working tree; clean worktree of `a6a23b6`                              | **byte-identical** to `bfcf36f`                      |
| Mutation M1 (no enrichment after the port scan); M6 (OT exclusion ignored) | differ by 2,402 and 106 lines: the capture sees both |

**Four existing tests changed their stubs, not their assertions.**

- **Why they had to.** They mocked `PortEngine` inside the orchestrator, or patched its two
  methods, and so skipped the enrichment without saying so.
- **What they do now.** They stub `enrich_after_port_scan` where it lives. Left alone, two of them
  would now send SNMP and OT probes to real addresses, one of them `10.180.12.104` on this LAN.
- **One gains a check.** The passive-first test also asserts that the enrichment runs on the
  scanned hosts only.

**At run time.** Running the port engine on a host with nothing to probe (nmap replaced, UDP 161
closed, no OT port, so no packet leaves) loaded 15 first-party modules on `bfcf36f`: the whole
discovery package, the classifier and `core.risk`. It loads none on `6cd4ca3` or `a6a23b6`.

#### B8b — Audit's models attach nothing to platform classes

**The back-references.**

- `Organization.web_scans`, `.web_findings`, `.web_parameters`, `.web_forms`,
  `.web_api_operations` (`db/models/web_scans.py`).
- `Organization.network_links` (`db/models/topology.py`).
- `User.web_scans` (`db/models/web_scans.py`).

They are one-sided now. The forward attributes (`organization`, `created_by_user`) stay, as do the
Audit-to-Audit back-references (`WebScan.web_parameters`, `Scan.network_links`,
`Asset.links_as_source`, …).

**Who read them: no code, and one flush.** No module, router or frontend reads the seven
attributes, and nothing introspects relationships. But deleting a user made the ORM load
`User.web_scans` and set `web_scans.created_by` to NULL.

- **On the live schema nothing else does that.** The migrations created `web_scans` and
  `web_findings` without the foreign keys their models declare (to `organizations` and `users`).
  Measured in the live catalogue, read only: `web_scans` has no foreign key at all.
- **So no test could tell.** The test schema is built from the models, which do declare
  `ON DELETE SET NULL`.

**The change.**

- **The statement moved to the table's owner.** `core/web/offboarding.detach_user_from_web_scans`
  belongs to the web capability. Audit's purge hook calls it beside the same statement for
  `scans.created_by`.
- **Its effect is the flush's:** `created_by` cleared, `updated_at` stamped (the compiled `UPDATE`
  carries the column's `onupdate`).
- **First version, and why it changed.** It put the statement in `ccure_audit/offboarding.py`
  itself. The capability ratchet refused it: a new foreign-table reference and write
  (`audit_boundary` → `web_scans`) past `CEILINGS`.
- **The stale-account purges run no hooks.** They reach only accounts that are unverified or
  unapproved, which can never sign in, so never started a web scan. Approval is never revoked
  (`approved_at` is set to `None` only at registration).

**Shown by the test, both ways.** The purge test drops the creator's foreign key inside its own
rolled-back transaction, so it purges against the schema production has.

| Tree                                   | Mapper tests (2) | Purge test                                    |
| -------------------------------------- | ---------------- | --------------------------------------------- |
| `6cd4ca3` (B8a) plus the new test file | fail             | passes: the back-reference clears the creator |
| B8b without the hook's statement       | pass             | **fails**: the creator is left dangling       |
| `eb52943`                              | pass             | passes                                        |

**Mapper shape:** `Organization`'s relationships 7 → 1 (`users`), `User`'s 4 → 3 (`organization`,
`refresh_tokens`, `audit_logs`). The table set and the tables' dependency order are unchanged.

#### B8c — the platform registers its models alone

**The dependency.** The platform imported its models from `db.models` (38 import sites in 27
files), and `db/models/__init__.py` imports every model file. So importing `ccure_platform.api`
loaded all ten of Audit's model files.

**The change.**

- **`ccure_platform.models` is the platform's registry.** Its `__init__` imports and exports the
  platform's models: identity, tenancy, native RBAC, the platform audit ledger, the registration
  policy, email screening and notifications.
- **Two model files moved into it** with `git mv`: `notifications.py` and `email_security.py`, the
  platform-owned files still under `db/models/`.
  - **The Phase 8.2 pattern:** each adopts its legacy name, keeps an alias stub at the old path and
    is recorded in `MOVED_MODULES`.
  - **So nothing observable changes:** class `__module__`, every legacy import and every patch
    target behave as before. `test_platform_identity_move` covers the two new entries, in every
    import order.
- **`db/models/__init__.py` takes the platform's models from that registry in one import**, then
  adds Audit's.
  - **Unchanged:** its `__all__` (same names, same objects), its table set, and the tables'
    dependency order (`sorted_tables`, which `create_all` uses).
  - **Changed:** only the order in which tables are first registered, since the platform's now
    come first. Nothing reads that order.
- **Every platform import names `ccure_platform.models` now.** The layer rule
  `platform-does-not-use-legacy-paths` forbids `db.models` outright; it used to name only
  `db.models.users` and `.rbac`.
- **The guards that named the old arrangement:**
  - `identity_boundary` lists the two new alias stubs as platform-side;
  - `test_legacy_alias_importers` lists `main.py`'s existing import of `db.models.email_security`;
  - the guardrail cases move "the platform imports `db.models`" from allowed to forbidden.

**The target, measured.**

- **No platform module loads `db.models` or an Audit model file.** In one interpreter, all 79
  modules of the platform package import without loading either.
- **The platform's registry configures alone.** In a fresh interpreter it configures every mapper,
  and it registers exactly the platform's tables.
- **The capability baseline locks it in.** `ccure_platform.api`'s load profile went from ten
  capabilities (nine of them Audit's) to shared infrastructure only.

#### Measurements, B8 as a whole

**Interfaces: identical** after each part (`interface_snapshot --compare` against `bfcf36f`). The
RBAC authorization inventory is current.

**Coupling** (`capability_map`):

| Measure                                    | Before (`bfcf36f`) | After B8a (`6cd4ca3`) | After B8 (`a6a23b6`) |
| ------------------------------------------ | -----------------: | --------------------: | -------------------: |
| Upward edges                               |                 38 |                **37** |                   37 |
| Lateral edges                              |                 72 |                **70** |                   70 |
| Largest cycle, all imports                 |      16 (and 4, 2) |     **15** (and 4, 2) |        15 (and 4, 2) |
| Largest cycle, top-level                   |                 12 |                    12 |                   12 |
| Foreign-table references / writes          |            79 / 17 |               79 / 17 |              79 / 17 |
| Cross-capability imports, top-level / lazy |          466 / 384 |             467 / 384 |            468 / 384 |
| `ccure_platform.api` load profile          |    10 capabilities |       10 capabilities |       **infra only** |

- **The three edges are gone:**
  - upward: `engines.port.port_engine` → `core.device_classifier`;
  - lateral: `engines.port.port_engine` → `core.discovery.enrichment`;
  - lateral: `core.discovery.enrichment` → `engines.vulnerability.plugins.snmp_probe`.
- **The port inventory left the capability cycle.** `CEILINGS` now holds the largest cycle at 15,
  upward edges at 37 and lateral edges at 70.
- **Discovery stays in the cycle,** through its techniques' lookup in `core.oui_lookup` (an assets
  module), the §7 item from B3.
- **The cross-capability imports, edge by edge** (`capability_edges`, `bfcf36f` against `a6a23b6`):
  - **two new top-level ones, both pointing down:** discovery enrichment → `core.engine_ports`
    (the interface) and Audit's purge hook → `core.web.offboarding`;
  - **the three lazy ones moved, not added:** the engines' lazy imports of the enrichment, the
    classifier and the SNMP client became `orchestrator.host_enrichment`'s;
  - **renamed:** the moved model files' imports of `db.base`, under their real names.

**Import cost** (first-party / all modules):

| Module                                 | Before (`bfcf36f`) | After (`a6a23b6`) | What changed                                                      |
| -------------------------------------- | -----------------: | ----------------: | ----------------------------------------------------------------- |
| `ccure_platform.api`                   |           59 / 629 |      **49 / 619** | `db.models` and all ten Audit model files no longer load          |
| `ccure_platform.identity.router`       |           49 / 712 |          39 / 702 | the same                                                          |
| `ccure_platform.administration.users`  |           66 / 625 |          56 / 615 | the same                                                          |
| `ccure_platform.audit_log.writer`      |           35 / 492 |          25 / 482 | the same                                                          |
| `ccure_platform.notifications.service` |           34 / 436 |          24 / 426 | the same                                                          |
| `ccure_platform.models`                |              2 / 6 |          18 / 331 | it is the registry now: the platform's model files and SQLAlchemy |
| `ccure_platform.rbac.engine`           |             4 / 29 |            4 / 29 | none                                                              |
| `engines.port.port_engine`             |           24 / 568 |          24 / 568 | none at import: its imports were lazy. Running it: 15 → 0 (above) |
| `orchestrator.scan_orchestrator`       |           58 / 958 |          59 / 959 | adds `orchestrator.host_enrichment`                               |
| `db.models`                            |           28 / 341 |          30 / 343 | the two moved files' real names beside their legacy ones          |
| `main`                                 |         279 / 1942 |        283 / 1946 | the two new modules and those two names                           |

**Tests.**

| Step                 | Command / targets                                                                                                                                                                                                                                                                                                                                                                                         |    Passed | Failed | Skipped | Notes                                                                                                                                                                                |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------: | -----: | ------: | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| B8a, affected        | the nine scan files that touch the two engines or the classifier (`test_ot_safety`, `test_port_registration_flow`, `test_engine_ports`, `test_engine_progress_and_cancellation`, `test_host_identity_precedence`, `test_snmp_ber_decoding`, `test_pipeline_contracts`, `test_vuln_scoring_split`, `test_device_classifier`)                                                                               |       145 |      0 |       0 | After the four stub changes                                                                                                                                                          |
| B8a, new             | `tests/scans/test_engine_composition.py`                                                                                                                                                                                                                                                                                                                                                                  |        14 |      0 |       0 | The edges and the run; every production `DiscoveryEngine` given the read; the order in the orchestrator; the moved behaviour (161 gate, OT gate both ways, failures, inactive hosts) |
| B8a, mutation        | the new file and `test_ot_safety`, on scratch worktrees with: M1 no enrichment after the port scan; M2 the enrichment before it; M3 one discovery engine without the read; M4 the port engine importing enrichment again; M5 enrichment importing the SNMP client again; M6 the OT exclusion ignored; M7 inactive hosts enriched; M8 a closed 161 queried; M9 discovery falling back to a read of its own |         — |      — |       — | Caught: M1 by 3 tests, M2 by 2, M3 by 1, M4 by 2, M5 by 1, M6 by 1, M7 by 2, M8 by 1, M9 by 1. The golden also caught M1 and M6                                                      |
| B8a, targeted groups | `tests/assets tests/compliance tests/credentialed tests/repo tests/reports tests/scans tests/security tests/topology tests/web`, the groups the selector named, on a clean worktree of `6cd4ca3`                                                                                                                                                                                                          |     6,443 |      0 |       2 | Environment-dependent skips; the run did not name them                                                                                                                               |
| B8b, focused         | `tests/repo/test_platform_model_registry.py`, `test_platform_extraction.py`, `tests/web`, `tests/topology`, the RBAC purge, admin tenant-isolation and audit-actor tests                                                                                                                                                                                                                                  |       664 |      0 |       1 | Before the statement moved to `core/web/offboarding.py`; after it, the purge and architecture tests: 171 passed                                                                      |
| B8b, both ways       | the new file on `6cd4ca3`, and on B8b without the hook's statement                                                                                                                                                                                                                                                                                                                                        |         — |      — |       — | The table above                                                                                                                                                                      |
| B8c, focused         | the registry, identity-move, legacy-alias, identity-boundary, architecture, capability, platform-extraction and module-registry tests; the email-domain and notification tests                                                                                                                                                                                                                            |       396 |  **1** |       0 | `test_the_rules_allow_ordinary_downward_dependencies` pinned "the platform imports `db.models`" as allowed. It moved to the forbidden cases; then 74 passed                          |
| B8c, mutation        | C1 a platform module importing `db.models` again; C2 the platform registry dropping a model; C2b the same, with Audit's registry importing it directly; C3 Audit's registry dropping a re-export                                                                                                                                                                                                          |         — |      — |       — | Caught: C1 by the registry test, the layer rule (`check.py` exits 1) and the guardrail test; C2 and C2b by the schema bootstrap, which fails; C3 by the export test                  |
| Full suite           | `tests`, on a clean worktree of `a6a23b6`                                                                                                                                                                                                                                                                                                                                                                 |     8,019 |  **1** |     211 | `test_no_new_audit_vocabulary_enters_the_platform` (below). The skips are the audit-chain and retention DBA bootstraps and the environment ones                                      |
| After the fix        | `tests/repo`, with `fe5baaf`'s content                                                                                                                                                                                                                                                                                                                                                                    |       776 |      0 |       1 |                                                                                                                                                                                      |
| Full suite           | `tests`, on a clean worktree of `fe5baaf` (15 min 22 s)                                                                                                                                                                                                                                                                                                                                                   | **8,020** |  **0** |     211 | The plan's "full suite" for B8; the result for the branch as it stands                                                                                                               |
| Architecture         | `check.py`; `capability_map --check`; `build_migration_inventory --check`; pre-commit                                                                                                                                                                                                                                                                                                                     |         — |      — |       — | All pass                                                                                                                                                                             |

**The one failure the full suite found.**

- **What failed.** The platform-vocabulary ratchet: `models/notifications.py` became a new file inside
  `ccure_platform` carrying an Audit word.
- **What the word is.** One occurrence, the `related_scan_id` column. It is the column
  `notifications/service.py` and `router.py` already name, item 3 of
  `PLATFORM_AUDIT_VOCABULARY.md` (persisted column and API contract, left for compatibility). The
  move brought it along; nothing new entered the platform.
- **The fix,** `fe5baaf`: the baseline records the file at 1 with that reason, and the document
  names the file.

**Live validation.**

- **Not required.** §11 does not require it for B8.
- **Run anyway.** B8a moves code on the port phase's path, and CLAUDE.md asks for a live pair on
  any scan-path change.

| Run      | Commit    | Interface (`pinned` / `scapy_default`) | Full audit                                                             | Stopped sweep |
| -------- | --------- | -------------------------------------- | ---------------------------------------------------------------------- | ------------- |
| `before` | `bfcf36f` | `eth0` / `eth0`, `172.30.250.5`        | complete: 3 phases, 4 assets, 4 services, 7 findings, 13 frames, 321 s | `cancelled`   |
| `after`  | `fe5baaf` | `eth1` / `eth0`, `172.30.250.5`        | the same, 312 s                                                        | `cancelled`   |

- **Identical apart from time**, with nothing needing tolerance: the scan rows, phases, assets
  (with the fixed MACs), services, findings, task results and every frame match.
- **The interface fix earned its keep.** In the `after` run Docker attached the targets' network as
  `eth1`, and Scapy's default was `eth0`, the wrong one. The harness pinned `eth1` (`44cb889`);
  before that fix this run would have found nothing.
- **What the pair can and cannot show.** The moved code is on the full audit's path: the
  AGGRESSIVE discovery's SNMP probe, then the enrichment after the port scan. No validation
  target runs an SNMP agent or an OT service, so the pair shows the phases unchanged when nothing
  answers. The answering branches are the golden's.

**Found on the way, recorded in §7, not fixed:**

- **`web_scans` and `web_findings` lack the foreign keys their models declare.** On this
  installation both tables are empty, so a migration adding them would meet no orphans. Two
  consequences until then:
  - deleting an organisation would not cascade into them;
  - a purge leaves `web_findings.accepted_by` naming the removed account. No hook clears it, and
    before B8 nothing did either.

**Limitations.**

- **Importing one platform model file now loads them all.** `ccure_platform.models` went from 2 to
  18 first-party modules, because its `__init__` is the registry. They are the platform's own
  files, and they need one another to configure (`Organization.users`).
- **The renderers' 4-capability cycle remains,** through the platform's audit-log export, as B7
  recorded.
- **The golden replaces the network.** What the real SNMP and OT exchanges look like is shown live
  only as far as the validation targets reach (above).

### B9 — the TLS engine moves below the network checks and web DAST

Commit `bc4f7da`, committed in place.

**The scope** (analysis §10, B9): "Network-check TLS plugin reaches into `core.web.sslyze` → move
the sslyze wrapper to a shared engine module both use". Files: `tls_scanner.py`,
`core/web/sslyze/`. Target: "Network scan runs without the web module".

**The dependency.** Inspected on `f8e9f67`.

- **The plugin's import.** `engines/vulnerability/plugins/tls_scanner.py` imported
  `SSLyzeWrapper` from `core.web.sslyze.wrapper`, lazily, for its deep assessment. That is a
  lateral edge, network checks → web DAST.
- **The wrapper's own imports:** the standard library, `sslyze` and `cryptography`, and no
  application code. The coupling was only where the file lived.
- **What it cost, measured.** In an interpreter where `core.web` cannot be imported, the plugin's
  import failed. `_deep_audit` swallows that as "sslyze not installed", so every endpoint was
  assessed by the handshake probe alone: against an expired, self-signed listener, `deep_assessed`
  false and two findings instead of four.
- **The other importer** is the web orchestrator's audit phase. Nothing else on the network path
  imports `core.web`: `core/tasks.py`'s one import is the web scans' status settler.

**The change.**

- **The move.** `git mv core/web/sslyze/wrapper.py engines/tls/wrapper.py`, unchanged but for
  its header. `engines/tls/` is the TLS engine both scan paths use.
- **Its own capability, at layer 2** (`tls`, in `capability_map`), below both users, so neither
  import of it is lateral. That is the analysis's §8.3 rule 1, dependencies point down. As a
  layer-3 engine its users' imports would still have been lateral.
- **The callers.** `tls_scanner` and `orchestrator/web_orchestrator.py` import
  `engines.tls.wrapper`, still inside the functions that use it.
- **The old path stays,** as a `sys.modules` alias of the same module (`core/web/sslyze/wrapper.py`).
  It is the pattern `scans.cvss` uses, and §8.3 rule 8's: old imports, `patch` targets and
  `isinstance` checks hold.
- **The logger keeps its name,** `ccure.web.sslyze`: log filters match on it.
- **The tests that imported the old path** (`test_network_check_promotion`, `test_tls_deep`,
  `test_tls_starttls`, `test_cookies_and_tls`) import the new one.

**Golden: identical.** `b9_golden.py`, a scratch script, runs a threaded HTTPS listener on
127.0.0.1. It serves a fixed certificate: self-signed, expired in 2021, generated once so both
trees see the same bytes. Captured, through real sslyze:

- the network plugin end to end (`tls_scanner.run`, the port identified as https): the handshake
  probe, the deep audit, the findings;
- the plugin's deep audit on its own;
- the wrapper run the way the web orchestrator runs it, imported from the path that tree's web
  orchestrator imports.

| Capture                                      | Result                                                                                |
| -------------------------------------------- | ------------------------------------------------------------------------------------- |
| `f8e9f67`, twice                             | identical: the capture is deterministic                                               |
| B9 working tree; clean worktree of `bc4f7da` | **byte-identical** to `f8e9f67`                                                       |
| What running the plugin loaded               | before: `core.web`, `core.web.sslyze`, the wrapper. After: `engines.tls`, the wrapper |

The capture saw TLS 1.2 and 1.3 enumerated, and four findings from the network plugin: expired,
self-signed, no trusted root, no OCSP staple.

**Interfaces: identical** (`interface_snapshot --compare`, `f8e9f67` against B9).

**Coupling** (`capability_map`):

| Measure                                    | Before (`f8e9f67`) | After (`bc4f7da`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Lateral edges                              |                 70 |            **69** |
| Upward edges                               |                 37 |                37 |
| Largest cycle, all imports / top-level     |     15 (4, 2) / 12 |    15 (4, 2) / 12 |
| Foreign-table references / writes          |            79 / 17 |           79 / 17 |
| Cross-capability imports, top-level / lazy |          468 / 384 |         470 / 385 |

- **The edge that went:** `engines.vulnerability.plugins.tls_scanner` → `core.web.sslyze.wrapper`
  (lateral, lazy). `CEILINGS` holds lateral edges at 69.
- **The four that came, all pointing down to layer 2:** the two callers' (lazy) imports of
  `engines.tls.wrapper`, and the alias stub's two (top-level), of `engines.tls` and its wrapper.
- **The cycle does not shrink.** Each of the two stays in it through one upward edge of its own,
  not through this one:
  - the network checks: `engines.vulnerability.vulnerability_engine` → `core.device_classifier`
    (an assets module);
  - web DAST: `reporting.web_pdf_generator` → `scan_helpers` (the scans capability).

**Import cost** (first-party / all modules): unchanged at import, because both callers import the
engine inside the function that uses it.

| Module                                       |   Before |    After | Note                                      |
| -------------------------------------------- | -------: | -------: | ----------------------------------------- |
| `engines.vulnerability.plugins.tls_scanner`  |  14 / 61 |  14 / 61 | the engine loads when the deep audit runs |
| `engines.vulnerability.vulnerability_engine` | 26 / 511 | 26 / 511 |                                           |
| `orchestrator.scan_orchestrator`             | 59 / 959 | 59 / 959 |                                           |
| `orchestrator.web_orchestrator`              |   3 / 57 |   3 / 57 |                                           |
| `engines.tls.wrapper`                        |        — |   3 / 28 | no sslyze until it runs                   |
| `core.web.sslyze.wrapper` (the alias)        |   4 / 29 |   7 / 32 | it loads the engine package               |

**Tests.**

| Step            | Command / targets                                                                                                                                                                                                                                                                       | Passed | Failed | Skipped | Notes                                                                                                                                                                                                                                                                                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New             | `tests/scans/test_tls_engine_shared.py`                                                                                                                                                                                                                                                 |      5 |      0 |       0 | No network-check import of the web module (lazy included); the engine imports no application code and sits below both users; production code uses its own path; the old path is the same module, logger unchanged; with `core.web` unimportable, the plugin's deep assessment runs against a local listener |
| Focused         | the new file, the four that changed their import, the capability and architecture tests                                                                                                                                                                                                 |    287 |      0 |       0 | Nothing skipped: sslyze is in the image, so both live-listener tests ran (this one and `test_cookies_and_tls`'s expired certificate)                                                                                                                                                                        |
| Mutation        | the new file and the capability ratchet, on scratch worktrees with: N1 the plugin importing the old path again; N2 the engine importing web code; N3 the web orchestrator using the alias; N4 the old path a re-export instead of the same module; N5 the engine classified as web DAST |      — |      — |       — | Caught: N1 by 4 tests and `check.py`; N2 by 3 and `check.py`; N3 by 1; N4 by 1; N5 by 3 and `check.py`                                                                                                                                                                                                      |
| Targeted groups | `tests/credentialed tests/repo tests/reports tests/scans tests/security tests/topology tests/web`, the groups the selector named, on a clean worktree of `bc4f7da`                                                                                                                      |  5,910 |      0 |       2 | `alembic.ini` already activated; the live OSV npm feed                                                                                                                                                                                                                                                      |
| Architecture    | `check.py`; `capability_map --check`; pre-commit                                                                                                                                                                                                                                        |      — |      — |       — | All pass                                                                                                                                                                                                                                                                                                    |

**The full suite was not run.** The selector reported a targeted scope, and the plan does not ask
for one at B9. §11 puts the next full run at the end of Phase B, which is B10; B8's ran on
`fe5baaf` (8,020 passed, 0 failed).

**Live validation.**

- **Not required.** §11 does not require it for B9.
- **Run anyway.** B9 changes what the network checks' TLS plugin imports, and CLAUDE.md asks for a
  live pair on any scan-path change.

| Run      | Commit    | Interface (`pinned` / `scapy_default`) | Full audit                                                             | Stopped sweep |
| -------- | --------- | -------------------------------------- | ---------------------------------------------------------------------- | ------------- |
| `before` | `f8e9f67` | `eth0` / `eth0`, `172.30.250.5`        | complete: 3 phases, 4 assets, 4 services, 7 findings, 13 frames, 305 s | `cancelled`   |
| `after`  | `bc4f7da` | `eth0` / `eth0`, `172.30.250.5`        | the same, 312 s                                                        | `cancelled`   |

- **Identical apart from time**, with nothing needing tolerance.
- **What it cannot show: the engine at work.** No validation target offers TLS.
  - **PostgreSQL** is the only service the plugin reaches (STARTTLS on 5432), and its `ssl` is off.
  - **What the plugin does then.** A failed negotiation is skipped by design ("not a finding about
    the host") and leaves nothing in what the harness stores.
  - **So the pair shows only** that the audit is unchanged where nothing offers TLS.
  - **The engine's work is the golden's,** against a real listener.

**Limitations.**

- **`engines.tls` is a new capability.** The analysis's Appendix A and §8.2 list none for it. It is
  recorded here, and the layer is the one the rules leave: below both users.
- **The alias stub keeps `core.web` → `engines.tls` edges** until the old path is retired. They point
  down and cost nothing on the network path.
- **The golden's listener speaks TLS 1.2 and 1.3 only,** which is Python's default. The weak-protocol
  and weak-cipher branches are pinned by `test_tls_deep`'s truth tables, not by a live listener.

### B10 — the executor and the version matcher are injected into the configuration audit

Commit `cbd94fe`, committed in place, on top of `abbe662`. That is the merge of this branch into
`master` through GitLab (21 Oct 2026, 14:35–14:37 IST), which the branch was then fast-forwarded
to; its tree is `858e904`'s exactly.

**The scope** (analysis §10, B10): "Config-audit database collector and SCAP evaluator import
credentialed engines lazily → executor and matcher injected". Files: `database.py`,
`evaluate.py`. Target: "Config audit depends only on the check kernel".

**The dependency.** Inspected on `abbe662`. Two lateral edges, config audit → credentialed audit,
both lazy:

- **The database collector's engine backstop** (`_engine_mismatch`) imported `normalize_engine`
  from `engines.credentialed.database_executor`, to fold a rule's engine names ("postgres",
  "MariaDB", "SQL Server") and the session's onto canonical ones. The collector already had the
  executor: the `DatabaseSession` arrives as `ctx.executor`.
- **The SCAP evaluator** imported `compare_distro_versions` from
  `engines.credentialed.vuln_matcher` for every OVAL comparison of a `version`, `evr_string`,
  `debian_evr_string` or `ios_version`.
  - **What one comparison loaded:** that module brings the vulnerability-intelligence layer with
    it, so one version comparison inside the evaluator loaded `config`, `db` and
    `core.vuln_intel`, 142 modules in all.
  - **With `engines` unimportable,** the comparison raised `ModuleNotFoundError` out of
    `evaluate_definition`. The backstop silently stood down, and a query in another engine's
    dialect ran.

**The change.**

- **The executor folds the names.** `DatabaseSession.normalize_engine` is the module function as a
  method, and the collector asks the session it was handed.
  - **An executor that cannot fold gets no backstop:** the query runs and its answer stands, which
    is what a failed import used to mean.
  - **Only one test's fake session was affected:** `test_database_collector`'s gains the method.
    The database-areas fake always matches the rule's own engine.
- **The context carries the comparator.** `CollectionContext.version_compare` (optional) is
  threaded by the evaluator from `_evaluate_test` through `_apply_filters`, `_item_satisfies` and
  `_compare`.
  - **No comparator means the comparison cannot be made:** it reads as unknown, never a verdict,
    and never a naive order. A naive order is the backport defect CLAUDE.md records.
  - **Who builds a context:** only `core/tasks.py`, in two places, the credentialed host's audit
    and the database audit. Both pass `compare_distro_versions`, imported inside the function
    beside the code that already imported the credentialed engine.
  - **The evaluation tests' context helper** carries it as well, as production's do.

**Golden: identical.** `b10_golden.py`, a scratch script, runs production's own composition, so
the contexts are the ones `core/tasks.py` builds:

- **SCAP:** `_run_configuration_audit` over the Linux built-ins plus 15 `scap_rule` checks, with a
  fake shell.
  - **The cases are those naive ordering gets wrong:** an epoch, a tilde, a backported release,
    `1.0` against `1.0.0`, a Debian EVR and an IOS version.
  - **Also:** an object filter that keeps items above a version, and an integer control.
- **Database:** `audit_database_target` for PostgreSQL, MySQL, MariaDB and SQL Server.
  - **The session** is a stand-in subclass of the real `DatabaseSession`: connection and query
    replaced, its product naming, read-only guard and, on B10, its folding its own.
  - **The checks:** the 49 built-in database rules plus ten rules naming engines by alias, each
    reaching the backstop.

| Capture                                       | Result                                                                            |
| --------------------------------------------- | --------------------------------------------------------------------------------- |
| `abbe662`, twice                              | identical: the capture is deterministic                                           |
| B10 working tree; clean worktree of `cbd94fe` | **byte-identical** to `abbe662`                                                   |
| Mutations P4 and P5 (below)                   | differ by 195 and 17 lines: the capture sees a comparator that is not passed down |

What the capture shows:

- **The version cases:** 13 of the 15 hold. `1.0 equals 1.0.0` fails, as rpmvercmp orders it, and
  `abc equals abd` fails, as it should.
- **The aliases fold as the module does:** "postgres", "PostgreSQL" and "pgsql" to PostgreSQL;
  "MariaDB" to MySQL; "SQL Server" to SQL Server.
- **The backstop:** a mismatch is not applicable, and the unknown "oracle" is not a mismatch.

**Interfaces: identical.** **Coupling** (`capability_map`):

| Measure                                    | Before (`abbe662`) | After (`cbd94fe`) |
| ------------------------------------------ | -----------------: | ----------------: |
| Lateral edges                              |                 69 |            **67** |
| Upward edges                               |                 37 |                37 |
| Largest cycle, all imports / top-level     |     15 (4, 2) / 12 |    15 (4, 2) / 12 |
| Foreign-table references / writes          |            79 / 17 |           79 / 17 |
| Cross-capability imports, top-level / lazy |          470 / 385 |         470 / 385 |

- **The two edges went and none came** (`capability_edges`, edge by edge). `core/tasks.py`
  already imported the matcher and the executor module. The statement count stays the same because
  its two new lazy imports replace the two removed. `CEILINGS` holds lateral edges at 67.
- **The target, read exactly.** Every cross-capability import of `core.config_audit` is now into the
  check kernel, and so is every one of `core.scap` but one.
  - **The exception:** `core.scap.cci` → `core.compliance_seeds` (lazy), the CCI crosswalk resolving
    the seeded NIST catalogue's path. It is a seed-file lookup, not an engine, and the new test
    names it.
- **What still holds config audit in the cycle** is `core.benchmarks`: the loader writes the
  compliance catalogue and selection reads it. The plan gives that to C4.

**Import cost:** unchanged at import (both imports were lazy). `core.config_audit` 23/64,
`core.scap.evaluate` 32/90, `core.tasks` 140/1456 first-party/all, before and after. At run time,
the evaluator's version comparison loaded 142 modules on `abbe662` and loads none on B10; the
comparator arrives with the context.

**Tests.**

| Step                | Command / targets                                                                                                                                                                                                                                                                                                                                                                           | Passed | Failed | Skipped | Notes                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -----: | -----: | ------: | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Affected, first run | the configuration-audit, SCAP, database, middleware, container and privilege tests, the benchmark end-to-end and the SMB transport (16 files)                                                                                                                                                                                                                                               |  1,413 |  **3** |       0 | All three were fixtures without the new interface: `test_database_collector`'s fake session could not fold names, and `test_scap_evaluation`'s context carried no comparator (two version cases). Both fixtures now provide what production does                                                                                                                                          |
| New                 | `tests/scans/test_config_audit_injection.py`                                                                                                                                                                                                                                                                                                                                                |     11 |      0 |       0 | The engine and SCAP evaluation import only the check kernel (one named exception); no config-audit module imports an engine; both run with `engines` unimportable; every production context carries the comparator, and only `core/tasks.py` builds one; no comparator is unknown; the matcher's order decides states and filters; the executor's folding is used and equals the module's |
| Mutation            | the new file, the two fixture files and the capability ratchet, on scratch worktrees with: P1 the evaluator falling back to importing the matcher; P2 the collector falling back to importing the executor module; P3 the database audit's context without the comparator; P4 the state comparison not passing it; P5 the filter not passing it; P6 the executor without `normalize_engine` |      — |      — |       — | Caught: P1 by 5 tests and `check.py`; P2 by 4 and `check.py`; P3 by 1; P4 by 4; P5 by 1; P6 by 2. The golden also saw P4 and P5                                                                                                                                                                                                                                                           |
| Architecture        | `check.py`; `capability_map --check`; pre-commit                                                                                                                                                                                                                                                                                                                                            |      — |      — |       — | All pass                                                                                                                                                                                                                                                                                                                                                                                  |

**The new test's first run failed, on the test.** Its stand-in executor's fold table had no entry
for `postgresql` itself. The instance's own engine folded to nothing, the backstop stood down and
the query ran, which is the collector folding both names through the session, as designed. The
table was corrected.

**Live validation.**

- **Not required.** §11 does not require it for B10.
- **Run anyway.** B10 changes `core/tasks.py`, which every scan loads, as B6 did.

| Run      | Commit    | Interface (`pinned` / `scapy_default`) | Full audit                                                             | Stopped sweep |
| -------- | --------- | -------------------------------------- | ---------------------------------------------------------------------- | ------------- |
| `before` | `abbe662` | `eth0` / `eth0`, `172.30.250.5`        | complete: 3 phases, 4 assets, 4 services, 7 findings, 13 frames, 313 s | `cancelled`   |
| `after`  | `cbd94fe` | `eth0` / `eth0`, `172.30.250.5`        | the same, 320 s                                                        | `cancelled`   |

- **Identical apart from time**, with nothing needing tolerance.
- **What it cannot show: the configuration audit.** That runs only inside a credentialed scan, and
  the harness's scans are unauthenticated.
  - **What covers it instead:** the golden, which drives the two functions `core/tasks.py` builds
    contexts in;
  - and the full suite, whose credentialed and benchmark end-to-end tests run the audit through the
    task code.

#### End of Phase B

**Full suite, the end-of-Phase-B milestone** (§11): `tests` on a clean worktree of `cbd94fe`,
**8,036 passed, 0 failed, 211 skipped** (15 min 41 s). The skips are the audit-chain and retention
DBA bootstraps and the environment-dependent ones, the same 211 as every full run on this branch.
The selector had named a targeted scope of 12 of the 14 groups, because `core/tasks.py` reaches
most of them; the full run covers it.

| Measure (capability map)          | When the ratchet was introduced (A2, `aa215dc`) | End of Phase B (`cbd94fe`) |
| --------------------------------- | ----------------------------------------------: | -------------------------: |
| Upward edges                      |                                              50 |                         37 |
| Lateral edges                     |                                              74 |                         67 |
| Largest cycle, all imports        |                                              22 |              15 (and 4, 2) |
| Largest cycle, top-level          |                                              13 |                         12 |
| Foreign-table references / writes |                                         80 / 17 |                    79 / 17 |

**Against the plan's simulation.** §10 predicted the cycle would shrink "from 20 capabilities to
10", with "every engine, kernel and renderer" leaving it.

- **What left:** the port inventory (B8). B7 split two cycles out of the 22-capability knot: the
  renderers with the check kernel, infra and the platform (4), and the scan kernel with
  vulnerability intelligence (2).
- **Six engines are still in it,** each through edges no B step named:

| Engine             | The edge that holds it                                                                                                 | Where it is answered                                               |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Discovery          | `core.discovery.techniques.arp`/`arp_cache` → `core.oui_lookup` (assets)                                               | §7 (B3); the analysis's target grouping puts it in the scan kernel |
| Network checks     | `vulnerability_engine` → `core.device_classifier` (assets)                                                             | §7 (B9); the same target grouping                                  |
| Credentialed audit | `routers.credentialed` → `core.tasks`, `scan_orchestrator`, `scan_helpers`, `scans.db_helpers`, `scans.policy_binding` | C1 (dispatch by name, a scan-creation service)                     |
| Config audit       | `core.benchmarks.loader`/`selection` → the compliance catalogue                                                        | C4                                                                 |
| Topology           | `core.topology.engine` → `Asset` and `Scan`, `core.oui_lookup`                                                         | §7 (B6)                                                            |
| Web DAST           | `reporting.web_pdf_generator` → `scan_helpers.make_pdf_cve_paragraph`, a rendering helper kept in the scans module     | §7 (new, below)                                                    |

- **The simulation's grouping differs from the ratchet's.** It counted the classifier and the
  MAC-vendor lookup as scan kernel, so on its terms discovery and the network checks would
  already be out.

### Before Phase C: the credentialed live harness (T0)

Commit `4ee2abc`, tooling only, on top of `3541224`. It is the first group of the Phase C plan
proposed on 22 Oct 2026 (T0, then G1–G6). C2, C3 and C6 need a live check, and analysis §11 asks
that it run "concurrent credentialed and unauthenticated scans". Until T0 the harness ran no
credentialed scan at all. The application is unchanged.

**What changed.** All of it is in `scripts/validation/`, plus its tests.

- **Two audit accounts on the targets.**
  - **The SSH target** gains `ccure-audit`: created locked (password field `!`), with sudo that
    asks for the password (no `NOPASSWD`). The image also installs `iproute2`, for `ss`. The
    image tag is now `ccure-validation-ssh:ubuntu-24.04-audit`, and `targets.sh up` replaces a
    target running any other image.
  - **The PostgreSQL target** gains the role `ccure_audit`, made by the first run with
    `pg_read_all_settings` and `pg_read_all_stats`, and `NOLOGIN` outside a run.
  - **Nothing can log in outside a run.** `targets.sh status` prints both accounts' state.
- **Throwaway credentials per run** (`live_scan.sh`).
  - **Made and granted.** Two random passwords, held in unexported shell variables and given
    only to `printf`, so they are in no process's arguments. They are granted over
    `docker exec -i` stdin, the role's in a session with statement logging off.
  - **Handed over.** They reach the harness as one JSON line on its stdin.
  - **Searched for.** After the scans, the run's output, every container's log since the run
    began, the scanner's configuration and a dump of the throwaway database are searched for
    them. A find is exit 3, and the message names where, never what.
  - **Revoked.** On exit, whatever happened, both are revoked and read back from the targets. An
    unconfirmed revocation is exit 4.
- **Four scans at once, then the stop** (`live_scan_harness.py`).
  - **Credentials are stored as production stores them:** through `core.credential_vault`,
    encrypted. The harness keeps only the ids.
  - **The scans,** each dispatched as its route dispatches it:
    - the unauthenticated vulnerability audit, as before;
    - a vulnerability audit carrying the SSH credential in `options.credentials` (the pipeline's
      Phase 3.5);
    - the standalone credentialed host audit;
    - the standalone database audit.
  - **They run concurrently,** one thread each; the cancel run then runs alone.
  - **What is recorded:** each credentialed scan's verdicts, read as the export reads them, and
    the organisation's assets, services and findings once after the four.
  - **A run whose credentialed scans did not authenticate exits 5**, after writing its result.
- **The comparison** reads the new runs, the shared end state and the authentication record. It
  ignores the send time the credentialed task stamps on its frames.

**Verification.**

| Check                                                      | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `tests/repo/test_live_scan_tooling.py`, the tree committed | 53 passed: the 37 before and 16 new (the audit account; where a credential may go; the non-logging role session; revocation on every exit; the leak check, three planted and one clean; credentials read from stdin; the credentialed dispatch pinned to the route; storage encrypted; the Phase 3.5 plan merged as the route merges it; the authentication refusal and its exit 5; the comparison of the credentialed runs; `up` replacing another image)                  |
| Mutations                                                  | 13 of 13 caught, each by the one test aimed at it (1 failed, 52 passed): a password in the scanner's environment, or exported; the role session logging statements; cleanup not revoking; the leak check skipping the database dump, or a target's log; the authentication check ignoring verdicts; the harness not exiting 5; a password stored beside the ciphertext; the comparison ignoring verdicts, or comparing send times; `NOPASSWD` sudo; `up` ignoring the image |
| Smoke run, `3541224`                                       | Exit 0. full: 7 findings, 313.7 s. credentialed (Phase 3.5): 86 verdicts, 228 s. host: 86 verdicts, 7.8 s. database: 49 verdicts, 1.0 s. After the four: 4 assets, 5 services, 13 findings. Every authentication check true                                                                                                                                                                                                                                                 |
| During a run                                               | The account read `P` and the role `login`                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| After each run                                             | The account locked (`!`), no process of it; the role `NOLOGIN`, no password, no session. No `ccure-live-*` container or network, no work directory left. The targets publish no port                                                                                                                                                                                                                                                                                        |
| Secret check                                               | Passed on every run: neither password in any place searched                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Two consecutive runs, `3541224`, the same targets          | Both exit 0. **Identical apart from time**, with nothing tolerated; `--strict` agrees. Each: full 7 findings (323.5 s, 309.2 s); credentialed 86 verdicts (263 s); host 86; database 49; after the four, the same 4 assets, 5 services and 13 findings. Against the smoke run, run 1 differs in one row: the `.env` template (below)                                                                                                                                        |

**What the credentialed runs found.** These are pre-existing product behaviour, not caused by
T0. All but the last are in §7.

- **Port 22's service is named `0.0.0.0:*` after a credentialed audit.**
  - **The defect:** `engines/credentialed/linux_collector._parse_ss_output` takes the last column
    of `ss -tlnp` as the process.
  - **When it bites:** if the scanning account cannot see process names, that column is empty and
    the last one is the peer address.
  - **What it costs:** the audit's record replaces the port scan's `ssh`/`OpenSSH`.
- **Nuclei's corroborated `.env` finding is stored under whichever template Nuclei printed first.**
  - **The defect:** `nuclei_probe._collapse_corroborating` merges the templates that matched one
    URL and keeps `max(group, key=severity)`. On a tie that is the first in Nuclei's output order.
  - **What varies:** `codeigniter-env` and `laravel-env` are both high. Every run from B3 to B10
    stored `CCURE-CHK-NUCLEI-CODEIGNITER-ENV`, and so did T0's smoke run. Both runs of T0's pair
    stored `…-LARAVEL-ENV`. Run 2's stored evidence names all three templates
    (`codeigniter-env,generic-env,laravel-env`) as matching, and its id is Laravel's, so the
    choice among them is what varied.
  - **Why now:** this is the first time it has varied, in runs where four scans load the host at
    once. The comparison reports it as a difference, as it does the Redis template variation.
- **The network-path evidence links a minted id to NVD.** The stored `.env` finding's evidence
  ends `Reference : https://nvd.nist.gov/vuln/detail/CCURE-CHK-NUCLEI-…`, a page that does not
  exist. `scans/asset_syncer.py` writes that line for any identifier, while the credentialed
  writer in `core/tasks.py` writes it only for a real CVE. CLAUDE.md ("Network checks") says a
  minted id must never carry an NVD link.
- **The two SSH scans file the same configuration findings differently.** The Phase 3.5 pipeline
  records them as `credentialed_package` and the standalone audit as `config_check`. Each scan
  keeps its own rows (the key includes `scan_id`), so these are not duplicates. Whether the two
  paths should agree is not settled here.
- **The host audit records Docker's embedded DNS listener** (`127.0.0.11`, a port chosen when the
  container starts) as a host-only service. It is a real socket, so it is not a defect, but it
  makes a `down` and `up` between a before and an after a difference. The guide says to compare
  against the same targets.

**What T0 does not cover.**

- **Credentialed coverage is Linux over SSH and PostgreSQL only.** There is no WinRM, SMB, MySQL
  or SQL Server target.
- **No CVE matching.** There is no vulnerability feed, so credentialed package matching reports
  "not assessed".
- **No process-level isolation.** The four scans are threads in one process; the worker runs them
  in separate processes.

The image the SSH target used before T0, `ccure-validation-ssh:ubuntu-24.04`, is no longer used.
It is kept until its removal is approved.

### G1 — C1 and C2: the routers dispatch by name, and the task hub becomes `scans/tasks/`

Commits `b2c4303` (C1), `9c47298` (C2) and `57b4d04` (a test the mutation check called for), on top of
`92c224c`. G1 is the first code group of
Phase C, approved by the owner on 22 Oct 2026 with the grouping proposed that day (T0, G1–G6, F).
Phase C's record continues in this section, so that §7 keeps its number.

**The scope** (analysis §10):

- **C1.** "Dispatch by name everywhere. Routers stop importing `core.tasks` (`phase_scans`,
  `traditional_scans`, `credentialed`, `assets`, `credentials`). A scan-creation service in the
  scans capability replaces the credentialed router's use of `scan_orchestrator`, `db_helpers` and
  `policy_binding`." Unlocks: "No capability imports the hub".
- **C2.** "Split `core/tasks.py` into per-capability task modules … Every `name=` is kept; the
  `include` list is updated." Unlocks: "Hub gone".
- **The owner's terms (22 Oct):**
  - keep every task name, queue, limit and beat entry, every API and permission, and scan
    behaviour;
  - retarget the 66 test patches, and guard against patching the facade's re-exports;
  - run the full suite, show the task registry and the API interfaces unchanged, and compare
    credentialed and unauthenticated live scans on the same target instances.

#### C1 — `b2c4303`: the routers dispatch by name

- **By-name dispatch.** `core/task_names.py` gains the four tasks the routers start: asset
  discovery, the vulnerability audit, the traditional scan and AMT reconciliation. The hub
  registers them under the constants, with their names unchanged.
  - **The routers:** `phase_scans`, `traditional_scans`, `credentialed` and `assets` call
    `registered_task(NAME).delay(...)`.
  - **What that returns:** the registered task itself, so queues, limits, eager execution and a
    patched `.delay` behave as before.
- **Loading the task modules.** `main.py` loads the worker's task modules once at start-up
  through Celery's loader: the include list a worker loads.
  - **Why:** with no router importing them, the first by-name dispatch would otherwise import
    the scan pipeline inside a request.
  - **No static edge:** the loader takes module names as strings, so this adds no import edge
    and does not undo the decoupling.
- **The scan-creation service** (`scans/scan_creation.py`). It holds the credentialed route's
  target expansion, the target ceiling (`MAX_CREDENTIALED_TARGETS`, moved from the hub) and the
  scan row with its policy snapshot, all moved unchanged.
  - **The route** no longer imports the orchestrator, `scan_helpers`, the persistence helpers or
    the policy binding.
  - **Logging** stays under the `ccure.api` logger.
- **The credential vault decrypts its own rows.** `core.credential_vault.resolve()` and
  `connection_material()` hold what the hub's `_resolve_stored_credential` did.
  - **The hub's wrapper** reads the scan's organisation and delegates. The vault sits below the
    scans capability, so it does not read the `scans` table.
  - **The credentials route's validate call** uses the row it already found in its organisation,
    instead of looking it up again unscoped.
- **The layer rule.** `task-hub-is-a-leaf` now covers `routers`, `main` and `ccure_audit`.
- **The interface probe.** `interface_snapshot` now records each task's queue, time limits,
  retry and acknowledgement options and signature, and the beat entries' options and arguments.
  - **The pin:** `scripts/architecture/task_registry.json` was written from `92c224c`.
  - **The test:** `tests/repo/test_task_registry.py` compares the live registry with the pin.
- **The live harness** (`4ee2abc`) follows the routes. It dispatches by name, and takes the
  credentialed scan record from `scans.scan_creation` on a commit that has it and from the old
  helpers on one that does not. So a before and an after run each exercise their own route.

#### C2 — `9c47298`: `core/tasks.py` split into `scans/tasks/`

| Module              | Lines | Tasks | Contents                                                                       |
| ------------------- | ----: | ----: | ------------------------------------------------------------------------------ |
| `common`            |   224 |     0 | the scoped orchestrator, cancellation, task ids, settling a failure            |
| `credentialed_sync` |   814 |     0 | writing a credentialed audit's identity, services and findings                 |
| `credentialed`      | 2,948 |     1 | the credentialed scan, host and database audits, configuration audit, 3.5      |
| `topology`          |   234 |     1 | SNMP topology mapping and when a scan chains it                                |
| `phases`            |   930 |     7 | host and asset discovery, the vulnerability audit, the sync tasks, traditional |
| `maintenance`       |   135 |     3 | risk-acceptance expiry, AMT reconciliation, MAC vendors                        |
| `schedules`         |   114 |     1 | recurring scans that are due                                                   |
| `reapers`           |   362 |     2 | settling scans nothing is working on                                           |

- **Moved verbatim.** Every one of the 55 definitions is AST-identical to the hub's.
  - **The one exception:** the two lazy self-imports that chained phase 2 and phase 3 are
    gone. The chained task is now a global of the same module.
  - **Logging:** every module logs under `ccure.tasks`.
  - **Imports:** each module has only the imports its own code reads.
  - **Direction:** the modules import one another one way only, with `common` at the bottom and
    `phases` at the top. The import-cycle ratchet holds.
- **The worker.** It loads the six modules that define tasks (`core/celery_app.py`'s include
  list) and no longer loads `core/tasks.py`.
- **The facade** (`core/tasks.py`, 144 lines).
  - **What it offers:** every name the hub defined (62, including the mail tasks and
    `MAX_CREDENTIALED_TARGETS`), as the same objects.
  - **What it refuses:** setting or deleting an attribute raises `AttributeError`. The message
    names the module to patch.
- **The layer rules.** `task-hub-is-a-leaf`, `services-do-not-speak-contracts` and
  `reporting-below-http` forbid `scans.tasks` as they forbid `core.tasks`.
- **The capability map.** `task_hub` is gone, and `core.tasks` and `scans.tasks` are the scans
  capability.

**The 66 patches.**

- **45 are retargeted to the module whose code reads the name.**
  - **Where one function calls another:** `mark_scan_failed` is read inside `_settle_failure`,
    in `common`, so the four patches of it go there. The task that fails reaches it only through
    that call.
- **19 patch the mail tasks' `.delay`.** They now name `ccure_platform.identity.mail_tasks`.
- **2 are removed.** In `tests/scans/test_tasks.py` both patched `create_completed_scan`, which
  `run_host_discovery_task` never reads. They replaced nothing before the split. After it they
  would raise, because `scans.tasks.phases` does not hold the name.

**What else the tests needed.**

- **Tests that read the hub's source.** These read it by path or with `inspect.getsource`, and
  now read the `scans/tasks` modules.
  - **Those that assert absence:** two of them, and the status-vocabulary check, which is a
    subset test, would otherwise have passed silently on the facade.
  - **Equivalence:** the option reads and status writes across the modules equal the old hub's.
- **Imports.** Test imports name the defining module.
  - **Why:** the CI selector chooses test groups by the names tests import and patch. A test
    importing through the facade would not be selected when `scans/tasks/` changes.
- **Indirect module references.** The end-to-end credentialed tests name the module they patch
  themselves, instead of taking it from a fixture, which the static check cannot follow.

**The guards** (`tests/repo/test_task_modules.py`):

- **No patch through the facade,** in any form: a string target, a module alias in the
  function's scope, or a direct assignment.
- **Every patch on a task module replaces a name that module's own code reads.** A name a
  module only re-exports is the hazard.
- **The scan's forms are pinned** against a fixture, so a blind scanner cannot pass.
- **The facade refuses at run time,** and offers all 62 names as their own objects.
- **The worker loads the six task modules and not the facade.**

#### Verification

| Check                                                                                                                         | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Full suite, C1 as first committed (`0b030a7`)                                                                                 | 8,055 passed, **2 failed**, 211 skipped. Both failures were the RBAC migration inventory: it was regenerated before black re-wrapped two routers in the commit hook, so its line numbers were stale. C1 was amended with the regenerated file (`b2c4303`; the only difference, `git diff --stat`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `tests/rbac` and `tests/repo`, `b2c4303`                                                                                      | 1,416 passed, 2 skipped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Full suite, `9c47298` (C2, the whole of G1), a clean worktree                                                                 | **8,069 passed, 0 failed, 211 skipped** (15 min 47 s). The skips are the same environment-dependent ones as every full run on this branch                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Interfaces, `interface_snapshot --compare` against `92c224c`                                                                  | Identical after C1 and after C2: routes, limiter keys, the OpenAPI digest, every task's queue, limits, options and signature, the beat schedule                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| The task registry against its pin                                                                                             | Byte-identical after C1 and after C2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| A worker started from the backend image (`celery inspect registered` with queue, limits and options), `92c224c` and `9c47298` | The same 36 tasks with the same attributes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| The split, statically                                                                                                         | All 55 definitions AST-identical to the hub's (the two self-imports aside)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Live, credentialed and unauthenticated, `92c224c` against `9c47298`, the same target instances                                | Both exit 0; the secret check passed and the credentials were revoked and confirmed after each. **Identical apart from time**, with nothing tolerated; `--strict` agrees. Each: the unauthenticated audit 7 findings; the Phase 3.5 and standalone host audits 86 verdicts each; the database audit 49; the stopped sweep cancelled; after the four, 4 assets, 5 services, 13 findings. The four targets kept the same container ids from before the first run to after the second                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Mutations                                                                                                                     | 15 mutations of `9c47298`, each in its own worktree, against `tests/repo` and the five test files with the most patches. **14 caught**: a patch through the facade, as a string (M1) or through an alias (M3); a patch on a module whose code does not read the name (M2); the facade accepting a patch (M4) or dropping a name (M5); the worker loading the facade (M6) or missing a task module (M7, caught by the worker test and the include-list pin, not by the registry test, because that test's process had already imported the module another way); a time limit (M8), a signature default (M9) or a beat entry (M10) changing; a router importing a task module (M11) or the orchestrator again (M12); the vault returning an NTLM hash as a password (M14); a task module importing the facade back (M15, a cycle). **Survived:** M13, the credentialed route's section fallback dropped from the service. Nothing tested it, before C1 moved it or after. `57b4d04` adds `tests/scans/test_scan_creation.py`, which catches it |

#### Coupling and load profiles

| Measure                           |     `92c224c` | C1 `b2c4303` | C2 `9c47298` |
| --------------------------------- | ------------: | -----------: | -----------: |
| Capability cycle, all imports     | 15 (and 4, 2) |           14 |           14 |
| Capability cycle, top-level       |    12 (and 2) |           11 |           11 |
| Upward edges                      |            37 |           31 |           31 |
| Lateral edges                     |            67 |           65 |           59 |
| Foreign-table references / writes |       79 / 17 |      78 / 17 |      73 / 16 |

- **What C1 changed:** dependencies.
  - **Upward edges:** the credentialed router's six into the scans capability's internals
    went, and so did the assets and credentials routers' imports of the hub. One edge is new,
    the credentialed router's call of `scans.scan_creation`.
  - **Lateral edges:** the phase-scan and traditional-scan routers' imports of the hub.
  - **Foreign references:** the hub's read of `compliance_credentials`.
  - **The cycle:** the task hub left it.
- **What C2 changed:** classification only. The hub became part of the scans capability, so
  its six imports of scans internals and its reads of `scans` and `scan_phases` became
  internal. Its other table access is now the scans capability's, so the baseline records
  `scans -> web_scans` and writes to `assets` and the two findings tables, which were the hub's.
  No dependency changed.

Import cost (first-party / all modules):

| Module                                                        |   `92c224c` |                                                         `9c47298` |
| ------------------------------------------------------------- | ----------: | ----------------------------------------------------------------: |
| `routers.credentialed`                                        | 149 / 1,591 |                 75 / 1,011: no Scapy, nmap, ReportLab or psycopg2 |
| `routers.phase_scans`                                         | 149 / 1,466 | 143 / 1,455 (still loads the orchestrator through `scan_helpers`) |
| `routers.traditional_scans`                                   | 142 / 1,458 |                                                       126 / 1,437 |
| `main`                                                        | 283 / 1,946 |        301 / 1,967: the worker's task modules, loaded at start-up |
| `core.tasks`                                                  | 140 / 1,456 |                  150 / 1,466 (the facade loads every task module) |
| `scans.tasks.maintenance`, `.schedules`, `.reapers`           |           — |                                   13–14 / 484–485: no scan engine |
| `scans.tasks.credentialed_sync`                               |           — |                                                          69 / 639 |
| `scans.tasks.common`, `.topology`, `.credentialed`, `.phases` |           — |                                             127–142 / 1,217–1,453 |

#### What G1 leaves, and what it found

- **Credentialed audit is still in the capability cycle, through one edge.**
  - **The edge:** `routers.credentialed -> scans.scan_creation`. The capability map (A2) puts
    the router in the credentialed-audit capability, an engine layer, so its call into the
    scans capability points up.
  - **What the router is:** it serves one route, `POST /scan/credentialed`, which creates a
    scan, as `routers.phase_scans` does in the scans capability.
  - **What reclassifying it would do,** measured, not committed: credentialed audit leaves the
    cycle (14 -> 13, top-level 11 -> 10), and upward edges fall 31 -> 29.
  - **Decision:** a classification decision for the owner (§7). G1 leaves the map as A2 set it.
- **The plan's "credentialed audit gets an application service of its own" is
  `scans.tasks.credentialed`,** in the scans capability's orchestration layer.
  - **Why there:** placed in the credentialed-audit capability, an engine layer, its writes to
    findings and assets and its use of the scans internals would all be upward edges.
- **`scans.tasks.common` imports the orchestrator at module level,** verbatim from the hub.
  - **The effect:** the topology, credentialed and phase modules load the scan engines (Scapy,
    nmap) at import.
  - **Not affected:** the housekeeping modules do not import `common` and load 13–14 modules.
  - **The fix:** importing it inside `_new_orchestrator` and `_bind_scan_scope` would let the
    credentialed and topology modules load without them. A small follow-up (§7).
- **`core.tasks.MAX_CREDENTIALED_TARGETS`** was absent at C1 alone, because the facade did not
  exist yet. Nothing in the repository read it there: the live harness reads it from where it
  lives. C2 restores it.
- **Test selection follows the split.** `scripts/ci/select_tests.py` maps a change in
  `scans/tasks/` to the groups whose tests import or patch that module: for example
  `credentialed_sync.py` selects assets and topology, and `reapers.py` selects web. A change in
  `core/tasks.py` used to select twelve groups.
- **CLAUDE.md still names `core/tasks.py`** where it describes the scan pipeline. Every name
  still resolves through the facade, read-only. The file is the owner's to revise.
- **The old SSH validation image** (`ccure-validation-ssh:ubuntu-24.04`) was removed on the
  owner's approval (22 Oct 2026).

### G2 — C5: the credential vault becomes a capability of its own

Commits `123cc33` (the model) and `c1192d1` (resolution through the vault), on top of `9c96582`.

**The scope** (analysis §10, C5): "Credential vault capability. Model out of
`db/models/compliance.py` (same table, alias kept); one API; `resolve()` used by credentialed
audit, scheduling and compliance remediation." Unlocks: "Credentialed audit stops depending on
compliance's model file".

**The owner's terms (22 Oct):**

- keep the encrypted records, the APIs, the permissions and scan behaviour unchanged;
- keep the old model import paths as compatibility aliases, and route credential resolution
  through the vault service;
- run the credential API tests, the related regression tests, the architecture guards and a
  credentialed live smoke test, and update `CLAUDE.md` where needed.

"One API" was already true at the service level: S2 made both HTTP surfaces, `/credentials`
and `/compliance/credentials`, adapters over `core.credential_vault`. G2 adds no route and
removes none. Whether the legacy surface is retired is still D-3.

#### The model — `123cc33`

- **The move.** `db/models/credentials.py` holds `ComplianceCredential` and the 27
  vocabularies its CHECK constraints are rendered from.
  - **Verbatim:** all 28 definitions are AST-identical to the originals.
  - **The data is untouched:** the same table, constraints and encrypted rows, and no
    migration.
- **The old import paths still work.**
  - **The alias:** `db/models/compliance.py` re-exports all 28 names.
  - **The registry:** it imports the class from its new module.
  - **The test:** every old path resolves to the same object
    (`tests/repo/test_credential_vault_boundary.py`).
- **A shared helper.** `_sql_in_list`, used by both model files' constraints, moved to
  `db/constraint_sql.py`, so neither model module imports the other for it.
- **Imports.** Imports of the moved names name `db.models.credentials`, in the application,
  its scripts and the tests.
- **The platform rule.** `platform-is-shared-foundation` forbids the new model module to the
  platform, as it forbids every Audit model; the identity-boundary test requires every model
  module to be classified.

#### Resolution through the vault — `c1192d1`

| Reader                                     | Before                                          | After                               |
| ------------------------------------------ | ----------------------------------------------- | ----------------------------------- |
| The credentialed route                     | queried the table by id and organisation        | `credential_vault.get_for_org`      |
| The two compliance remediation routes      | the same                                        | `get_for_org`                       |
| The schedule dispatcher                    | the same                                        | `get_for_org`                       |
| Compliance remediation's stored credential | queried by id and decrypted both secrets itself | `credential_vault.stored_secrets`   |
| A credential's deletion                    | the vault counted `scan_schedules` rows itself  | scheduling's own registered counter |

- **The three `get_for_org` callers.** The query is unchanged, scoped to the same
  organisation, and each answers a missing credential as it did: the two 404s and the
  dispatch error.
- **`stored_secrets`** is the form remediation has always used, moved unchanged:

  - the username as stored, not `principal()`;
  - every secret the row holds, whatever the auth method, so a key credential that also
    stores a sudo password keeps it;
  - looked up by id alone. The routes check the organisation first.

  The collectors' `connection_material` differs on all three. Choosing one is a decision
  (§7).

- **The reference counters.**
  - **The registry:** the vault keeps one, the user-purge hook pattern.
  - **Scheduling's answer:** `core/scheduling/credential_references.py`, imported by
    `main.py`, registers the count the vault used to run.
  - **Unchanged:** the API's `schedules_affected` and the audit event.
  - **Newly tested:** nothing tested that figure before; a test now deletes a credential
    through the API and finds the schedule's reference cleared.
- **The live harness** reads the credential through `get_for_org`, as the route does. It
  exists on every commit since S2.

**The guards** (`tests/repo/test_credential_vault_boundary.py`):

- **Only the vault's modules import the credential model,** lazily or not. The two
  re-exporters are the exception.
- **The vault depends on nothing beside or above it.**
- **The application registers scheduling's counter,** and a counter cannot be replaced under
  its name.

#### Verification

| Check                                                                                                                            | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The model move's nearest groups (`repo`, `security`, `credentialed`, `compliance`, the schedule and database-content scan tests) | 2,362 passed, **2 failed**. The new model module needed classifying for the platform rule; the RBAC inventory test had run before the commit hook re-formatted two routers, and the regenerated inventory matched `HEAD`. After both: the failed tests and the boundary tests, 95 passed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Commit B's nearest groups (the same, and `rbac`)                                                                                 | 2,990 passed, 2 skipped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Full suite, `c1192d1`, a clean worktree                                                                                          | **8,082 passed, 0 failed, 211 skipped** (15 min 58 s)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Interfaces against `9c96582`                                                                                                     | Identical after each commit: routes, limiter keys, OpenAPI, the task registry, beat                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| The model move, statically                                                                                                       | 28 of 28 definitions AST-identical                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Credentialed live pair, `9c96582` against `c1192d1`, the same target instances                                                   | Four runs, two of each commit in alternation; each exited 0 and authenticated, the secret check passed, and the credentials were revoked and confirmed. **Every stored result is identical across all four:** scan rows, phases, task results, the verdicts (86, 86, 49) and the 4 assets, 5 services and 13 findings. The comparison reported one difference in three pairings, including **both same-commit pairings**: two of the host audit's progress frames, "Collected Software Inventory" and "Collected Login Events" (both 45 %), in either order. Both orders occur on both commits. The Linux collector runs its sections in a thread pool and reports each as it finishes, so this is timing, not G2. The fourth pairing (`9c96582` against the second `c1192d1`) is identical apart from time. Recorded as a known variation in the validation guide; the comparison still reports it |
| Mutations                                                                                                                        | 6 of 6 caught, each in its own worktree of `c1192d1`: a router importing the credential model again (boundary test and ratchet); the vault reading `scan_schedules` again (the lower-layers test and ratchet); scheduling's counter not registered (the registration test, and the API deletion reporting 0 schedules); a key credential losing its stored password in `stored_secrets` (remediation test); the dispatcher looking the credential up in another organisation (the scheduled-dispatch test); the alias dropping a name (alias test)                                                                                                                                                                                                                                                                                                                                                  |

#### Coupling

| Measure                           | `9c96582` |    `123cc33` | `c1192d1` |
| --------------------------------- | --------: | -----------: | --------: |
| Capability cycle, all imports     |        14 |           14 |        14 |
| Capability cycle, top-level       |        11 | 5 (and 2, 2) |         5 |
| Upward edges                      |        31 |           31 |        31 |
| Lateral edges                     |        59 |           59 |        58 |
| Foreign-table references / writes |   73 / 16 |      73 / 16 |   69 / 16 |

- **What the model move changed.**
  - **The vault and its router** no longer import the compliance model file.
  - **The compatibility alias** adds the compliance model file's import of the vault's: the
    direction compliance already depended in.
  - **The top-level capability cycle** falls 11 → 5, because the vault's top-level
    dependency on compliance is gone.
- **What routing through the vault changed.**
  - **Foreign-table references (four gone):** compliance's, the credentialed audit's and
    scheduling's reads of `compliance_credentials`, and the vault's of `scan_schedules`.
  - **Edges:** each former reader now has an edge to `core.credential_vault`, replacing its
    edge to the model.
- **The vault now depends only on lower layers:** the platform, infrastructure, the scan
  kernel's scope admission, and the credentialed engines it tests a credential with.
- **It is still in the capability cycle.** That's not its own doing: `routers.credentialed`
  (the credentialed audit's) reaches up into it and into the scans capability. Classifying
  that router as the scans capability's API, the decision G1 recorded, would take the vault
  and the credentialed audit out of the cycle (14 → 12, upward edges 31 → 29), measured.

**Import cost** rises slightly (first-party modules, `9c96582` → `c1192d1`):

| Module                       | Before | After |
| ---------------------------- | -----: | ----: |
| `core.credential_vault`      |     63 |    65 |
| `routers.credentials`        |     66 |    68 |
| `core.scheduling.dispatcher` |     34 |    36 |
| `core.compliance_tasks`      |     61 |    63 |
| `routers.credentialed`       |     75 |    79 |

The two new modules account for this. Importing any `db.models.*` module runs the model
registry, which loads every model, so moving the credential model is a structural
decoupling, not an import-time saving.

#### What G2 leaves, and what it found

- **The vault's cycle membership:** see Coupling, and §7.
- **Two credential forms.** Remediation authenticates with every secret the row stores and
  the username as stored. The collectors use `principal()` and only the secret their method
  needs. G2 kept both, in the vault, side by side (§7).
- **Remediation copies ciphertext out of the vault's table.**
  - **What happens:** the maker-checker routes copy a stored credential's _encrypted_
    password and key into `compliance_remediation_requests`, and into the task's arguments
    for an emergency bypass.
  - **The consequence:** a second copy of the secret, which outlives the credential's
    deletion.
  - **Status:** pre-existing and unchanged (§7).
- **The load-profile ratchet** records that the topology engine and the web-scan router now
  load the vault's model module. Both load the model registry, and the class was already
  loaded as part of the compliance file, so this is a reclassification.
- **Line endings.** `tests/compliance/test_compliance_remediation.py` is CRLF in this
  working tree. Git stores it LF, before and after, and the commit's diff is the added lines
  only.

### G3 — C3: one writer of the findings tables

Commits, on top of `595f068`:

- **The code:** `39700ab` (the pipeline's writes), `b05aea4` (the credentialed sync's),
  `ed29279` (the purge hook's), `49d09b5` (D-6);
- **The tooling:** `a160fd2` and `833c351` (the findings golden), `38b28c6` (the
  rescans).

**The scope** (analysis §10, C3): "One findings writer. A findings service owns writes to
`services`, `tls_details`, `http_security_details`, `asset_vulnerabilities` and
`vulnerability_definitions`. `asset_syncer` keeps asset identity only; the hub's credentialed sync
calls the service. Merge remediation into the same capability (D-6)." Unlocks: "Findings and assets
leave each other's cycle; one place for the fixed-sweep rules".

**The owner's terms (22 Oct):**

- centralise the findings writes in a findings service, covering the asset syncer, the
  credentialed task hub and Audit's purge hook;
- apply D-6 with metadata changes only and no migration;
- validate against a restored database copy: replay stored payloads, with identical rows,
  byte-identical exports and identical comparison and verification outcomes;
- run the full suite, then live credentialed and unauthenticated scans plus a rescan covering
  fixed, reappeared and not-assessed findings, after confirming no live scan is in progress;
- small commits, behaviour preserved, and not G4.

#### Before the change: a replay golden and live rescans

- **The findings golden** (`Backend/scripts/verification/findings_golden/`, `a160fd2`,
  extended in `833c351`).
  - **The data:** the full dump of 22 Oct 2026, 20:17, restored into a throwaway PostgreSQL 18
    on an internal network: 11 scans, six of them vulnerability audits, four of whose hosts
    carried a credentialed report. With it goes a frozen subset of `vuln_intel`: the rows for
    the 3,706 CVEs the payloads name, read once, read-only.
  - **The code:** one commit's, in the backend image, against fresh copies of the restored
    database.
  - **Three modes:**
    - `asis`: the restored rows' exports and comparisons, plus each audit's verification and
      Audit's purge hook, each rolled back;
    - `on_top`: every stored phase payload replayed in time order over the restored rows;
    - `from_empty`: the same replay after the organisation's assets, and every findings row
      with them, are deleted.
  - **What the replay runs:**
    - each vulnerability audit's comparison and `verify_scan`;
    - for every credentialed host, three synthetic standalone credentialed scans: every
      finding, then four in five, then every finding again. These run the standalone sweep's
      fix and the reopen.
  - **What it captures:**
    - every table hashed, and the findings tables in full;
    - every scan's workbook, export JSON and CSVs and legacy CSV, rendered as the routes do;
    - every comparison and verification outcome.
  - **Determinism.** The clock, `random`, `secrets`, `uuid4`, the ZIP entry times and the hash
    seed are fixed, and autovacuum and parallel plans are off on the throwaway server.
  - **One exception, the change log's `id`.** It is compared without that column: a sweep logs
    each finding it retires from a query with no `ORDER BY`, all at one timestamp, so which row
    gets which sequence number is PostgreSQL's choice. Two captures of `595f068` paired 738 ids
    with different findings, every other column equal.
  - **What the replay reaches:** new, still-open, fixed, reappeared and not-assessed findings;
    verification that verifies, withholds and reopens; the pipeline's sweep (5,230 fixed and
    5,902 reopened in `on_top`); the standalone sweep (2,874 fixed in each replay mode).
- **The rescans** (`38b28c6`; "The rescans" in `docs/ci/LIVE_SCAN_VALIDATION.md`). Ten
  rescans, one at a time, change the targets between them, so findings are fixed, reappear and
  go unassessed on the scans' own terms:

  - **the pipeline's credentialed pass:** fixed, then reappeared;
  - **the standalone audit:** fixed with verification verifying, then reappeared with
    verification reopening;
  - **an unauthenticated rescan of credentialed findings:** not assessed;
  - **the web target's removed exposures:** not assessed, then still open.

  The first version expected the web exposures fixed and then reappeared. The first run on
  `595f068` refused itself (exit 6) for that alone. The pipeline retires a network finding only
  after a complete plugin run, and some probe always reports unsupported here (§7).

#### The writer — `core/findings/writer.py`

| Commit    | From                               | Moved                                                                                                                                                                                                                                                                | Verbatim                                                                                                                   |
| --------- | ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `39700ab` | `scans/asset_syncer.py`            | the services a port scan or a credentialed pass observed; each host's catalogue rows, findings and the sweep of those the scan retired (`write_host_findings`, the per-host block of `sync_vulnerability_audit`); the TLS reading; the asset risk from open findings | 29 definitions and both blocks (14 statements, and the TLS block) AST-identical, apart from three renames and the callback |
| `b05aea4` | `scans/tasks/credentialed_sync.py` | the standalone audit's catalogue rows and findings (`_sync_credentialed_vulnerabilities`), and its sweep (`sweep_credentialed_findings`)                                                                                                                             | 4 definitions and the 8-statement sweep AST-identical, apart from the callback and the asset's id in place of the row      |
| `ed29279` | `ccure_audit/offboarding.py`       | clearing a purged account from `accepted_by` (`detach_user_from_findings`)                                                                                                                                                                                           | the one statement, unchanged                                                                                               |

- **The callers keep what is theirs.**
  - **The asset:** its identity, change log, risk columns and last-seen record. A finding that
    reopens, is retired or is ruled out goes into the asset's change log through the
    `record_change` callback the caller passes. The writer imports no asset or scan model.
  - **The scan:** what it assessed is recorded on its row
    (`record_assessment_scope`, into `scans.options`). The caller writes it, from what
    `write_host_findings` and `sweep_credentialed_findings` return.
  - **The intel enrichment** stays in the asset syncer: seven tests patch
    `asset_syncer._enrich_findings_with_intel`, and the sync calls it before any host.
- **Order.** Each caller calls the writer exactly where the code was, so every statement runs in
  the order it did, the change log's entries included.
- **Names.** Three functions other capabilities call became public:
  - `upsert_network_service`, was `_upsert_network_service`;
  - `service_identity_from_process`, was `_service_identity_from_process`;
  - `risk_from_open_findings`, was `_recalculate_asset_risk`.
- **Unchanged otherwise:**
  - **Loggers:** `scans.asset_syncer` for the pipeline's code, `ccure.tasks` for the standalone
    audit's, as before.
  - **The facade:** `core/tasks.py` still offers the three moved hub names, as the same objects,
    now from the writer.
  - **Tests:** seven test files import a moved name from the writer, and no test patched one.
- **Two things the writer could not carry verbatim:**
  - the credentialed function's `asset: Asset` annotation (only the row's id is read);
  - its lazy import of the writer's own helpers.
- **Copies.** The writer keeps copies of five helpers its callers still use:

  - the asset syncer's placeholder vocabulary, value test, text cleaner and source-name
    normaliser;
  - the credentialed sync's `_clean_text`.

  Tests hold each copy equal to its original. The writer's `_clean` is the asset syncer's
  _second_ definition, which replaces the first at import and is the one the moved code always
  called (§7).

#### D-6 — `49d09b5`

Metadata only. The capability registry has no `remediation`: `core.remediation` and
`routers.remediation` belong to `findings`, and `table_ownership.yaml` files
`finding_remediation_events` under it.

**The guards** (`tests/repo/test_findings_writer.py`):

- **The registry holds the merge.** The findings capability owns the six findings tables.
- **No ORM write from outside.** No module outside the capability writes a findings table by
  model construction or a bulk insert, update or delete.
- **No SQL write from outside either.** The capability map counts SQL text as a reference
  only, so this test reads it separately. The one exception is `scans.nvd_sync`, the NVD feed
  sync, which loads the CVE catalogue; it is recorded with its reason (§7).
- **The writer depends only downward.** It has no upward or lateral edge, and imports no asset
  or scan model and not the asset syncer.

#### Verification

| Check                                                                          | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No live scan in progress                                                       | Confirmed before each golden and the live pair: the 11 scans complete or unreachable, no web scan running, both workers idle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| The moves, statically                                                          | `39700ab` 29 definitions and both blocks, `b05aea4` 4 definitions and the sweep: AST-identical apart from the stated renames                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Each commit's selected groups                                                  | `39700ab`: eight groups, 6,044 passed, 1 skipped. `b05aea4`: ten groups, 6,715 passed, 2 skipped. `ed29279`: eleven groups, `rbac` and `audit` added for the purge, 7,092 passed, 210 skipped (the audit chain's and retention's DBA bootstrap). `49d09b5`: `tests/repo`, 830 passed, 1 skipped                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Full suite, `49d09b5`, a clean worktree                                        | **8,088 passed, 0 failed, 211 skipped** (18 min 22 s); the 211 are the environment skips G2 also had                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Interfaces, `595f068` against `49d09b5`                                        | Identical: routes, limiter keys, OpenAPI, the task registry, beat                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Golden, before the extension (316 files)                                       | Two captures of `595f068` byte-identical; `39700ab`, `b05aea4` and `49d09b5` each byte-identical to them                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Golden, extended (412 files)                                                   | Two captures of `595f068` byte-identical; `49d09b5` byte-identical to them: every row, every export file (workbooks, export JSON and CSVs, legacy CSVs), every comparison and every verification outcome                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Mutations, each in its own worktree of `49d09b5`                               | 11 of 12 caught. Six guard mutations: a findings write back in the asset syncer, a SQL write in a router, the writer importing the asset syncer, a copied helper drifting, remediation leaving the capability, the facade losing a moved name. Six golden mutations: the pipeline's evidence text, the standalone sweep keeping every package CVE, the purge hook clearing nothing, a reopen going unrecorded, and a TLS rescan losing its cipher, all caught. The sixth, a TLS first insert losing its cipher, survived: every TLS host here is rescanned, and the rescan's upsert writes the cipher back, so on this data it changes nothing                                                                                                                                                                                                             |
| Live pair with rescans, `595f068` against `49d09b5`, the same target instances | Both runs exited 0. Each authenticated, passed the secret check, and had its credentials revoked and confirmed and its targets restored. **Every stored result is identical:** scan rows, phases, task results, the verdicts (86, 86, 49), the 4 assets, 5 services and 13 findings, and for each of the ten rescans its row, comparison, remediation events (4 verified, 2 reopened), verification preview and the target's findings; rescan coverage complete on both. One difference, the known variation (G2): the host audit's "Collected Login Events" and "Collected Software Inventory" frames, both 45 %, in either order. A first attempt was stopped when an unrelated commit on this branch (12:24) stashed and restored the then-uncommitted harness and dropped its scripts' execute bit; the pair was re-run once the harness was committed |

#### Coupling

| Measure                           | `595f068` | `39700ab` | `b05aea4` | `ed29279` | `49d09b5` |
| --------------------------------- | --------: | --------: | --------: | --------: | --------: |
| Capability cycle, all imports     |        14 |        14 |        14 |        14 |        13 |
| Capability cycle, top-level       |         5 |         5 |         5 |         5 |         5 |
| Upward edges                      |        31 |        31 |        31 |        31 |        31 |
| Lateral edges                     |        58 |        51 |        51 |        51 |        44 |
| Foreign-table references / writes |   69 / 16 |   68 / 12 |   68 / 10 |    68 / 9 |    66 / 9 |

- **One writer.** Outside the findings capability, seven ORM writes to findings tables
  were the asset syncer's four, the credentialed sync's two and the purge hook's one. None
  remain. The remaining nine foreign writes are to other capabilities' tables.
- **One place for the fixed-sweep rules.** Both sweeps, the pipeline's and the standalone
  audit's, are in the writer.
- **Findings and assets have not left each other's cycle.** The writes go one way now (the
  asset syncer calls the writer), but the reads go both ways:

  - findings → assets: `routers.findings`, `routers.remediation` and
    `core.remediation.reporting` read the asset model;
  - assets → findings: `routers.assets` reads the findings models, and the asset syncer
    calls `core.findings` (the scope record) and the writer.

  The reads are routers and a report. The analysis puts them in C7 (§7).

- **D-6 is a reclassification.** Remediation's six edges into findings and the one back become
  internal, and the cycle counts one member fewer because two merged.

**Import cost** (first-party modules, `595f068` → `49d09b5`):

| Module                          | Before | After |
| ------------------------------- | -----: | ----: |
| `scans.asset_syncer`            |     50 |    51 |
| `scans.tasks.credentialed_sync` |     71 |    81 |
| `ccure_audit.offboarding`       |     67 |    82 |
| `core.findings.writer`          |      — |    48 |

- **The modules added:** the writer's top-level imports, the check kernel, the CVSS module, the
  credentialed coverage module and the findings helpers.
- **Why they are new here:** the credentialed sync used to reach that code through lazy
  imports, and the purge hook not at all.
- **What is not added:** any heavy package.

#### What G3 leaves, and what it found

- **The cycle:** see Coupling, and §7.
- **The NVD sync writes the catalogue in SQL** (`scans.nvd_sync`, the vulnerability-intel
  capability). It is the feed's ingest, not a scan's finding, and G3 left it, recorded in the
  guard with its reason (§7).
- **The purge hook's other three statements** (asset notes, asset tags, scans) are other
  capabilities' tables, outside G3.
- **Found by the golden: open findings marked verified fixed.**
  - **What it measured:** after the `from_empty` replay, 3,000 findings have `status = open`
    and `remediation_state = verified_fixed`.
  - **Which findings:** the pipeline's credentialed rows, which carry pipeline-shaped ids.
  - **How:** a standalone credentialed scan writes its findings under its own ids, so its
    comparison reads the pipeline's rows as absent, classifies them fixed, and verification
    confirms them. Its own sweep correctly leaves them open, because it reports the same CVEs.
  - **Who is affected:** any host audited both ways. The live database holds none, because no
    standalone scan has run since the reset.
  - **Status:** pre-existing, and preserved by G3 as a refactoring must (§7).
- **Pipeline scans never verify.** Only the standalone credentialed task calls
  `verify_from_comparison`. A pipeline rescan that shows a fix leaves the finding's remediation
  state where it was. Pre-existing (§7).
- **The asset syncer defines `_clean` twice.** The second replaces the first at import, so the
  code calls the placeholder-aware one. `upsert_credentialed_services` therefore raises
  `TypeError` on a listener with no service, name or process: `_clean("unknown")` is `None`.
  The writer keeps that behaviour (§7).

### G4 — C4: compliance consumes evidence providers and owns its catalogue code

Commits, on top of `f00056c`:

- **The code:** `1e6f93c` (the severity floor), `0201d79` (benchmark content reads nothing of
  compliance), `d763203` (the benchmark loader and selection), `4d27190` (scan policy's
  catalogue reads), `3d89365` (the evidence providers);
- **The tooling:** `2c5c5df` (the compliance golden).

**The scope** (analysis §10, C4): "Producers register providers for their sources.
`core/compliance_evidence.py` becomes a registry. The benchmark loader and selection become
compliance's catalogue writer. Scan-policy validation reads the catalogue through
`ComplianceCatalogueService`." Unlocks: "Compliance stops querying five capabilities' tables;
config audit depends on nothing above it". Risk: "scores must not move; compare full compliance
runs before and after".

**The owner's terms (23 Oct):**

- G4 / C4 only, preserving assessment results, evidence, APIs and exports;
- targeted compliance evidence and catalogue tests, the architecture guards, and a before/after
  compliance comparison on a restored database copy;
- a short live smoke if needed;
- the full suite only if the targeted tests show unexpected failures or the change proves
  broader;
- stop after verification, and not G5.

#### Before the change: a compliance golden

`Backend/scripts/verification/compliance_golden/` (`2c5c5df`), on the pattern of G3's findings
golden.

- **The copy.** `run.sh up` restores a full dump into a throwaway PostgreSQL 18 on an internal
  network. It never connects to the live server: `up` reads the dump file only.
- **The inputs.** The development installation has three assets, no web scan, no network link
  and two installed catalogues, too little to exercise most adapters. `setup.sql` adds, once and
  before any capture:
  - every catalogue installed for `org_development`, and a policy for each that had none
    (19 policies, 2,293 policy rules);
  - three assets: a Windows host whose attributes answer every evidence key, a Linux host
    answering some (an unparseable date, a NULL, an empty list), and an unauthenticated host
    with no OS;
  - services in every state, TLS details, anti-malware names under a port and a process;
  - copies of real findings, some with no severity or score of their own;
  - network links;
  - web scans matched by address and by host name, superseded, failed and deleted, with
    findings in every status.
- **What it captures, each step at its own frozen time.** The code is loaded as the worker
  loads it (Celery's `import_default_modules()`), then:
  - every asset's evidence for every source and for an undeclared one, translated and through
    the cache (miss, hit, the cached value);
  - two rounds of compliance scans of all 19 catalogues, and four scoped scans (asset ids, tags,
    a CDE scope, an empty scope);
  - re-verification of every asset-level finding of an automated rule;
  - scan-policy validation of ten policies in both organisations, with and without a
    credential;
  - benchmark selection for every narrowing argument;
  - both shipped benchmark packs loaded twice;
  - `scripts/benchmarks/load_stig.py` over the SCAP fixture, with and without a CCI list, as an
    operator runs it;
  - every table's digest, and every `compliance_*` table in full.
- **Determinism.**
  - The clock is frozen, `random` seeded and `PYTHONHASHSEED` fixed.
  - `secrets` and `uuid4` are counters spread over every digit. The tool's first version used
    plain counters, as the findings golden does. Compliance history ids are
    `uuid4().hex[:24]`, all zeros for a small counter, so every history insert collided and
    every finding was skipped. A capture of one finding showed it before anything was compared.
  - The evidence cache is emptied before each step that reads it.
- **Measured.** Two captures of `f00056c` were byte-identical (38 files). The tool then changed
  once, to load the code through `import_default_modules()` and to log the module list instead
  of writing it. A third capture of `f00056c` with that version differs from the first two only
  in `summary.json`, by that list. The comparisons below are against the third.

#### Configuration audit imports nothing above it — `1e6f93c`, `0201d79`, `d763203`

- **The severity floor** (`1e6f93c`).
  - **What moved.** `SEVERITY_ORDER` and `severity_at_least` moved verbatim from
    `core/scan_policy/spec.py` to `core/checks/contract.py`, and the spec re-exports both as the
    same objects.
  - **Why.** Benchmark selection imported them from scan policy. Once selection was
    compliance's, that import and validation's reads would have joined compliance and scan
    policy in a cycle.
  - **Why the kernel and not the configuration-audit spec.** The scan-policy resolver's pinned
    load profile holds the kernel already, and would have gained configuration audit.
- **The framework-id prefix** (`0201d79`).
  - `BENCHMARK_FRAMEWORK_PREFIX` is defined with the pack format, which names the framework a
    pack becomes.
  - `core.compliance_frameworks.is_benchmark_framework` reads it in the function, so importing
    that module still loads only the standard library.
- **The NIST catalogue** (`0201d79`).
  - **The move.** The CCI crosswalk read the seeded NIST SP 800-53 catalogue through
    `core.compliance_seeds`. Its reader moved verbatim to
    `core.compliance_seeds.nist_800_53_control_numbers`, with the same cache and the same
    warning under the same logger.
  - **The parameter.** `crosswalk_entries` and `to_pack` take `nist_controls`, and the STIG
    loader passes it.
  - **Behaviour.** When the catalogue is supplied, the result is unchanged. When none is
    supplied, nothing is checked, which is what an unreadable seed did before.
  - **A pre-existing discrepancy, not changed.** The reader's docstring says an unreadable seed
    yields no crosswalk at all; the code has always emitted unchecked entries (§7).
- **The loader and selection** (`d763203`).
  - **Where they went.** Both moved unchanged, apart from their docstring headers, to
    `core/compliance_catalogue/benchmark_loader.py` and `benchmark_selection.py`.
  - **The old paths** are `sys.modules` aliases of the same module objects, the pattern
    `scans.cvss` uses. Module code imports the new paths, and a guard refuses an import of the
    old ones.
  - **Unchanged.** Logger names, the scripts' command lines, the pack format.

#### Scan policy reads the catalogue through compliance — `4d27190`

- **What moved.** Validation's queries of five compliance tables, and its call to
  `compliance_frameworks.is_active`, moved unchanged to `core/compliance_catalogue/reads.py`.
- **What it answers.** Plain values: the framework ids that exist, whether one is offered, the
  ids an organisation installed, and the active rule links per framework.
- **Unchanged.** Validation's messages and its warning.
- **A difference from the plan.** The plan names `ComplianceCatalogueService`. It is in
  `ccure_audit` (the audit boundary, layer 6), and `core` may not import it
  (`foundations-do-not-import-audit-module`). So the reads are in the compliance capability,
  where that service could read them too (§7).

#### The evidence providers — `3d89365`

- **The registry.** `core/compliance_evidence.py` keeps the declared sources, the cache and its
  keys, and the answer for an undeclared source. Its eight adapters are gone. It has
  `register_evidence_provider`, which refuses an undeclared source and a second provider for one
  source.
- **The providers**, moved body for body to the tables they read:

  | Capability   | Module                      | Sources                                                                    |
  | ------------ | --------------------------- | -------------------------------------------------------------------------- |
  | Findings     | `core/findings/evidence.py` | `vulnerability_audit`, `services_ports`, `tls_certificates`; service names |
  | Assets       | `core/asset_evidence.py`    | `credential_validation`, `offline_configuration`, `malware_scan`; identity |
  | Topology     | `core/topology/evidence.py` | `network_topology`                                                         |
  | Web scanning | `core/web/evidence.py`      | `web_vulnerability_audit`                                                  |

- **The two mixed sources.** Each read two capabilities' tables, and now takes the other
  capability's part as an argument:

  - `malware_scan` is handed the service names, in the order its own query returned them;
  - `web_vulnerability_audit` is handed the asset's identity (organisation, address, host name)
    instead of the row.

  An AST comparison with the old adapters shows only those two seams.

- **Who registers them: Audit's composition root**, `ccure_audit/evidence_providers.py`, which
  also composes the two mixed sources.
  - **A difference from the plan.** Principle 6 says each producer registers. A producer
    importing compliance's registry would be a lateral edge (findings, assets) or an upward one
    (topology and web scanning sit a layer below compliance). So the producers declare and the
    composition root registers (§7).
- **Every process registers them.** Celery's `imports` names the module, so the worker loads it
  at start-up, and `main.py` loads it through `import_default_modules()`. The task `include`
  list, pinned to task modules, is unchanged.
- **One behaviour change, in a misconfigured process only.** A declared source with no provider
  raises `EvidenceProviderMissing`. Otherwise a process that evaluated compliance without its
  providers would score every automated rule as not assessed, which looks like a quiet host.

#### Verification

| Check                                                           | Result                                                                                                                                                                                                                                                                                                                                                                                                                            |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No live scan in progress                                        | None running or queued before the dump. The golden and the smoke used a throwaway server restored from it                                                                                                                                                                                                                                                                                                                         |
| The moves, statically                                           | Loader and selection identical apart from the docstring header; the eight adapters AST-identical apart from the two seams; the severity floor verbatim                                                                                                                                                                                                                                                                            |
| Stage 1: the changed code's tests and `tests/repo` (27 targets) | **1,517 passed, 0 failed, 1 skipped** (the Alembic rehearsal, which skips on an activated `alembic.ini`), 6 min 18 s                                                                                                                                                                                                                                                                                                              |
| Stage 2: the selector's groups                                  | 13 groups (`assets`, `audit`, `audit_boundary`, `auth`, `compliance`, `credentialed`, `modules`, `repo`, `reports`, `scans`, `security`, `topology`, `web`): **7,503 passed, 0 failed, 210 skipped**, 16 min 5 s. The skips are the environment ones: the audit chain's and retention's DBA bootstrap, the Alembic rehearsal, the live OSV feed                                                                                   |
| Full suite                                                      | Not run. The selector reports `full` only because `main.py` changed, and that change is a comment; without it the selector names the 13 groups above. Nothing in either stage failed                                                                                                                                                                                                                                              |
| Interfaces, `f00056c` against `3d89365`                         | Identical: routes, limiter keys, OpenAPI, the task registry, beat                                                                                                                                                                                                                                                                                                                                                                 |
| Compliance golden, `f00056c` against `3d89365`                  | **Byte-identical, 38 files.** That covers the evidence of 7 assets for 9 sources; 42 scan runs; 8,049 findings (2,988 pass, 1,273 fail, 3,704 manual review, 84 not applicable); 11,145 history rows; 270 scores; 7,200 re-verifications (1,306 pass, 631 fail, 1,159 manual review, 4,104 refused for a parked framework); 10 policies validated; 21 selection cases (955 checks by default); 2 packs loaded twice; 2 STIG loads |
| Live smoke, `f00056c` against `3d89365`                         | A real worker, started with `docker-compose.yml`'s command (prefork, the three queues), on a fresh copy, given `compliance.run_scan` by name for ISO 27001 and NIST CSF. Both runs completed at both commits; the 1,146 findings (asset, control, rule, status) and 25 score rows are identical; no `EvidenceProviderMissing`. Importing `main.py`, as the API does, registered all eight sources at `3d89365`                    |

#### Coupling

| Measure                           | `f00056c` | `1e6f93c` | `0201d79` | `d763203` | `4d27190` | `3d89365` |
| --------------------------------- | --------: | --------: | --------: | --------: | --------: | --------: |
| Capability cycle, all imports     |        13 |        13 |        13 |        12 |        12 |        12 |
| Capability cycles, top-level      |   5, 2, 2 |   5, 2, 2 |   5, 2, 2 |      5, 2 |      5, 2 |      5, 2 |
| Upward edges                      |        31 |        30 |        28 |        19 |        19 |        19 |
| Lateral edges                     |        44 |        44 |        44 |        44 |        39 |        33 |
| Foreign-table references / writes |    66 / 9 |    66 / 9 |    66 / 9 |    61 / 5 |    56 / 5 |    50 / 5 |

- **Configuration audit depends on nothing above it.** No configuration-audit module imports a
  higher layer, and the capability has left both cycles; its top-level pair with compliance is
  gone.
- **Compliance.**

  - **The evidence path queries nothing outside compliance.** Compliance's foreign references
    fell from eight tables to two, and it has no foreign write.
  - **What is left, outside the evidence path:**

    - the compliance scan reads `assets` for its scope, prerequisites and platform;
    - the remediation executor sets `services.state` and an asset attribute by assignment, which
      the ratchet counts as references;
    - the router joins `assets`.

    The analysis's target for compliance is no foreign table, so it is not met yet (§7).

- **Scan policy names no compliance table.** One lateral edge remains, to compliance's reads.
- **Unchanged.** The audit boundary's `ComplianceCatalogueService` still reads the five catalogue
  tables (§7).

**Import cost** (first-party modules / all modules, `f00056c` → `3d89365`):

| Module                                                                                                                                            |    Before |     After |
| ------------------------------------------------------------------------------------------------------------------------------------------------- | --------: | --------: |
| `core.compliance_evidence`                                                                                                                        |  35 / 395 |   4 / 335 |
| `core.benchmarks.selection` (now an alias)                                                                                                        |  63 / 377 |  60 / 374 |
| `core.benchmarks.loader` (now an alias)                                                                                                           |  58 / 372 |  60 / 374 |
| `core.compliance_tasks`, `core.scan_policy.validation`, `core.benchmarks.pack`, `core.scap`, `core.compliance_frameworks`, `ccure_audit.services` | unchanged | unchanged |

#### What G4 leaves, and what it found

- **Compliance's remaining reads of assets and services**, outside the evidence path (Coupling,
  §7).
- **`ComplianceCatalogueService` and the reads** (§7).
- **Principle 6's wording**, against a composition root that registers the providers (§7).
- **Found by the golden's inputs: Windows Defender is not recognised as anti-malware.**
  - **What the collector stores.** The Windows collector records the Defender service as name
    `WinDefend` and description "Microsoft Defender Antivirus Service".
  - **What the evidence reads.** The name first. It matches `defender`, which `windefend` does
    not contain.
  - **The effect.** A Windows host protected only by Defender fails `crl_malware_agent_v1` and
    ISO A.8.16's `crl_iso_monitor_agent_v1`.
  - **Status.** Pre-existing, and preserved (§7).
- **Found reading the SCAP crosswalk: an unreadable NIST seed is documented as emitting no
  crosswalk, and emits an unchecked one.** Pre-existing, and preserved (§7).

### G5 — C6: a typed phase hand-off, and one pipeline definition

Commits, on top of `4b77625`:

- **The code:** `f533e61` (the hand-off and the pipeline, defined), `c011844` (the phase
  tasks hand over through the pipeline), `ec415b7` (the browser's continuation too);
- **The tooling:** `07bd679` and `518777a` (the phase-pipeline golden).

**The scope** (analysis §10, C6): "Typed phase hand-off. `HostRecord` and `ServiceInventory`
between phases; one pipeline definition instead of each task starting the next." Unlocks: "The
network pipeline becomes composable". Risk: Medium–High.

**The owner's terms (24 Oct):**

- G5 / C6 only;
- inspect the plan's phase hand-off before editing, and replace the untyped hand-off with the
  typed contract, changing only the producers, consumers and tests that need it;
- validate phase payload compatibility, ordering and failure propagation, with targeted
  orchestration tests and the architecture guards first, and broader tests only if those
  expose a regression;
- stop after verification, and not G6.

#### What crossed between phases before C6

- **The hand-off.** Host discovery dispatched asset discovery, and asset discovery the
  vulnerability audit, by calling the next task's `.delay()` with `hosts=` a list of dicts.
  - **Which hosts:** the active ones, picked with `h.get("is_active")`.
  - **Whether to continue:** from `get_terminal_phase` and the interactive setting.
- **The identity merge.** The vulnerability audit restored the hosts' identity from what it was
  handed (`_merge_host_identity`), in its own module.
- **The browser's continuation.** `POST /scan/asset-discovery` and `/scan/vulnerability-audit`
  dispatched the same tasks by registered name, with the records the browser posted.
- **The records** are projections of `core.models.HostResult`:

  - phase 1 hands over `to_phase1_dict()` or `to_basic_dict()`;
  - phase 2 hands over `to_clean_dict()`.

  The stored phase payloads carry exactly those key sets, which was read off the live database
  before the change.

- **The aliasing that matters.** The receiving phase gives the dicts to its engines, which add
  to them and edit their port records in place. Phase 3's merge reads those edits back from the
  dicts it was handed: Nmap's pre-enrichment of the ports reaches the stored payload only that
  way.

#### The hand-off — `core/phase_handoff.py` (`f533e61`)

In the scan kernel; it imports only the standard library.

- **`HostRecord`** is one host: its address (`ip_address`, or `ip` where only that is written),
  whether it answered, the services found on it (`ServiceRecord`, read from `open_ports`), and
  the record itself.
- **`ServiceInventory`** is what asset discovery hands the audit: the hosts in order, `active()`,
  and `restore_identity`, the merge moved verbatim as `merge_host_identity`. Its key list is
  `HOST_IDENTITY_FIELDS`.
- **The wire form is unchanged, deliberately.**
  - **Why it must be:** Celery carries JSON; the tasks' signatures are pinned; the browser posts
    back the records it was shown; and a message queued before a deploy is read after it.
  - **How:** a record crosses as its producer's dict, every key in order. `HostRecord.wire()`
    returns that dict itself, not a copy, so the in-place edits and the merge keep working.
- **One change in behaviour, in a malformed hand-off only.** A record that is not a mapping is
  refused with `HandoffError` when the receiving phase reads it. Before, it failed inside that
  phase's engines. Either way the phase fails and the scan is settled as failed.

#### The pipeline — `scans/pipeline.py` (`f533e61`, `c011844`, `ec415b7`)

- **One definition.**
  - **The table:** which phases each mode runs, moved verbatim from `scan_helpers.py`.
    `scan_helpers` re-exports the same objects, under the same logger.
  - **The phases:** the three network phases and their registered task names.
  - **`next_phase`:** the rule each phase task applied before. A phase continues to the next
    unless it is the mode's terminal phase, or the scan is interactive.
  - **`hand_over`:** dispatches a phase by registered name, with its hosts as their own dicts.
- **No phase task starts another** (`c011844`):
  - host discovery hands asset discovery the `HostRecord`s that answered;
  - asset discovery hands the audit the active part of its `ServiceInventory`;
  - each reads its input as the typed hand-off, and the audit restores identity through the
    inventory;
  - `_merge_host_identity` stays a name of the task module, because `core/tasks.py` offers it.
- **The browser's continuation hands over through the pipeline too** (`ec415b7`). The request
  models, the checks before dispatch and the response are unchanged.
- **The task names, queues, limits and signatures are unchanged**, and so is what each task
  receives.
- **The guard is `tests/repo/test_phase_pipeline_boundary.py`.** It refuses:
  - a read of asset discovery's or the audit's registered name outside their definition, their
    task module and the pipeline;
  - a direct `.delay` or `.apply_async` of either task;
  - a hand-off module importing beyond the standard library.

#### Before the change: a phase-pipeline golden

`Backend/scripts/verification/pipeline_golden/` (`07bd679`, `518777a`).

- **Where it runs.** On the findings golden's restored server (`findings_golden/run.sh up`), on a
  fresh copy of its template, Celery eager, with one commit's code.
- **What runs for real.** The phase tasks, the scan-phase writers, the asset syncer, the
  findings writer, the credentialed enrichment and the topology check are the commit's own code.
- **What is replaced.** Only the orchestrator, by a recorder. It takes each phase's input as the
  task hands it over and answers from the phase results the restored database stores. Like the
  real phase 3, it edits the port records it was handed in place and returns hosts without open
  ports, hostname or vendor, which the task then restores.
- **Sixteen scenarios**, each started by dispatching host discovery by name (two start a later
  phase directly):
  - the three pipeline modes;
  - options forwarded from the request and from the scan record, and explicit ports;
  - no active host;
  - an interactive scan continued with the browser's records (extra keys, an address under
    `ip`, a truthy non-boolean `is_active`);
  - a phase reporting failure, one raising, two cancelled between phases;
  - a broker refusing phase 2, and one refusing phase 3;
  - asset discovery started with a host that did not answer;
  - a phase-3 hand-off with records that carry no address.
- **What it records:**
  - every dispatch's name and arguments as the broker carries them;
  - every orchestrator call's arguments;
  - every progress frame and each result;
  - every table's digest, and the `scans` and `scan_phases` rows in full.
- **Determinism.** The clock is frozen; `secrets`, `uuid4` and the Celery task ids are counters.
  `audit_chain_heads.updated_at`, which PostgreSQL stamps itself, is left out of that row.

#### Verification

| Check                                                                                                                                                                          | Result                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No live scan in progress                                                                                                                                                       | None running or queued before the dump; the golden used a throwaway server restored from it                                                                                                                                                                                                                                                                                                               |
| The hand-off as before, statically                                                                                                                                             | The merge's body and key list equal to the pre-C6 one; the pipeline table and helpers moved verbatim and re-exported as the same objects; every dispatch passes the same keyword arguments                                                                                                                                                                                                                |
| New tests (`test_phase_handoff`, `test_scan_pipeline`, `test_phase_pipeline_boundary`)                                                                                         | Records cross as the same dicts, key order kept, edits downstream visible; `is_active` read for truth as before; the merge equal to the pre-C6 one over six shapes, key order included; `next_phase` equal to the pre-C6 rule for every mode, phase and interactive setting (48 cases); a refused dispatch raises; the boundary                                                                           |
| Quick set (the new tests, the phase tasks, the continuation route, the task, registry and capability guards)                                                                   | 200 passed, uncommitted tree                                                                                                                                                                                                                                                                                                                                                                              |
| Stage 1, `ec415b7`, clean worktree: `tests/repo` and the 27 pipeline-touching files of `tests/scans`, the three rate-limit inventories, two report tests and one topology test | **1,335 passed, 0 failed, 1 skipped** (the Alembic rehearsal, an environment skip), 6 min 6 s                                                                                                                                                                                                                                                                                                             |
| Broader tests                                                                                                                                                                  | Not run. The selector names 9 groups (targeted, not full); stage 1 showed no regression, so the owner's terms did not call for them                                                                                                                                                                                                                                                                       |
| Interfaces, `4b77625` against `ec415b7`                                                                                                                                        | Identical: routes, limiter keys, OpenAPI, the task registry, beat                                                                                                                                                                                                                                                                                                                                         |
| Pipeline golden, first version (15 scenarios)                                                                                                                                  | Two captures of `4b77625` identical (19 files); `c011844` and `ec415b7` identical to them                                                                                                                                                                                                                                                                                                                 |
| Pipeline golden, final version (16 scenarios)                                                                                                                                  | Two captures of `4b77625` identical (20 files); `ec415b7` identical                                                                                                                                                                                                                                                                                                                                       |
| Golden mutations, each committed in a scratch worktree, never on a branch                                                                                                      | 4 of 4 caught: records copied at hand-over (the stored phase-3 payloads differ); asset discovery handing on hosts that did not answer (caught once the sixteenth scenario existed: in the automatic pipeline phase 1 had already dropped them, so the first version compared it identical); interactive mode ignored (9 files); a refused dispatch swallowed (the two broker scenarios and the scan rows) |
| Guard mutations                                                                                                                                                                | A phase task dispatching the audit directly, and the router dispatching it by name: each caught by two of the boundary tests                                                                                                                                                                                                                                                                              |

#### Coupling

Unchanged: capability cycles 12 and 5, 2 (top-level); upward edges 19; lateral 33;
foreign-table references 50 and writes 5. The new modules belong to the scan kernel (the
hand-off) and the scans capability (the pipeline), and every edge they add points down.

**Import cost** (first-party modules, `4b77625` → `ec415b7`):

| Module                | Before | After |
| --------------------- | -----: | ----: |
| `scans.tasks.phases`  |    145 |   147 |
| `routers.phase_scans` |    146 |   148 |
| `scan_helpers`        |     93 |    96 |
| `core.phase_handoff`  |      — |     2 |
| `scans.pipeline`      |      — |     5 |

#### Differences from the plan

- **The hand-off is typed at the phase boundary, and the engines still work on the dicts.** The
  plan's interface table gives the engines `discover(…) → list[HostRecord]` and
  `inventory(hosts, …) → ServiceInventory`. That is an engine refactor:

  - the engines read and edit the records in place, and phase 3 depends on it;
  - C6 asks for the hand-off "between phases".

  So the records cross as their own dicts, with the typed fields read beside them (§7).

- **§12's target for `scans`, "imports engines only through the pipeline definition", is not
  met.** C6 moved the chaining; the orchestrator, in the scans capability, still imports the
  engines itself (§7).
- **No live scan.** §11 asks for live validation of C6, and the owner's terms asked for targeted
  tests first and broader validation only on a regression; there was none.
  - **Why the golden stands in:** the live harness runs Celery eager too, and C6 changes neither
    the orchestrator nor an engine.
  - **What neither exercises:** a real broker's JSON round trip of the hand-off. It carries the
    same dicts with the same keyword arguments, under the same task names and queues, so it is
    unchanged by construction, and it was not measured.
- **Host discovery is still dispatched by the routes and the scheduler.** It starts a scan from
  a request; nothing is handed to it.

#### What G5 leaves, and what it found

- **A phase run beyond its mode's terminal phase still chains on.** For example, asset
  discovery in a basic scan dispatches the audit. That was the rule, and `next_phase` keeps it.
  The routes refuse a phase outside the scan's mode, so only a direct task call reaches it (§7).
- **Found by the golden: a continued scan's posted records reach the stored phase-3 payload key
  for key.**
  - **How:** the identity merge starts from the record the audit was handed and lays the audit's
    own record over it.
  - **The effect:** a key the browser posted that the audit does not itself write is stored as a
    scan result.
  - **Who can do it:** a person with `audit.scan.run`, continuing their own scan, for hosts its
    scope admits.
  - **Status:** pre-existing, and preserved (§7).
- **The engines' own record type** (§7), and the scans capability's direct engine imports (§7).

### G6 — C7 and C8: findings and assets read each other through their own modules, and the compliance router is mounted from its parts

Commits, on top of `b6ae9bf`:

- **C7:** `1ee36b5` (the findings side reads hosts through a port), `bf7390d` (the assets router
  reads findings through the findings reads);
- **B10's follow-up:** `604157e` (the CVE paragraph is a renderer's helper);
- **C8:** `125da93` (the 20 generators become renderers), `5222695` (the router mounted from its
  parts);
- **The tooling:** `a324220` (the API golden).

**The scope:**

- **C7** (analysis §10): "Read side. Dashboard and reports consume read services … instead of
  querying tables." Unlocks: "Read models stop coupling to storage". With it, this log's §7 row
  from G3: `routers.findings`, `routers.remediation` and `core.remediation.reporting` read the
  asset model, and `routers.assets` reads the findings models.
- **C8:** "Split `routers/compliance.py`: catalogue, assessment, attestation and evidence,
  schedules, remediation, reports. The 20 PDF/DOCX generators move to `reporting/compliance/`."
  Unlocks: "Compliance reports become renderers".
- **This log's §7 row from B10:** move `make_pdf_cve_paragraph` out of `scan_helpers` into the
  renderers.

**The owner's terms (24 Oct):**

- G6 / C7 + C8 only, following the plan;
- decouple the remaining findings/assets read paths in the routers and the remediation report,
  split the compliance router as planned, and move `make_pdf_cve_paragraph` to its owner;
- keep to those items; targeted tests, the architecture guards and the relevant golden
  comparisons;
- validate the real broker JSON round trip if the changed paths affect it, otherwise record it as
  unverified;
- update this log, stop after G6, and not F1–F3.

#### C7 — findings and the asset registry

**What read what before.**

- **Findings read assets.** The findings and remediation routers and the remediation report
  joined `Asset` to scope a finding by its organisation, and the findings list and detail to
  label and search it by its host. After a person changed a finding's status, the findings
  router also wrote the asset's open-finding counts, risk score and risk level. The ratchet
  counts an assignment to a loaded row's attribute as a reference, not a write, so it had
  recorded that write as a read.
- **Assets read findings.** The assets router queried `services`, `tls_details` and
  `asset_vulnerabilities` through the findings models: each asset's open-service count, an
  asset's services and findings, and the estate's certificate, service and service-host
  listings.

**The direction.** G3 settled it: the asset syncer hands a scan's findings to the findings writer,
and the writer imports no asset model. So the asset registry may depend on findings, and findings
may not depend on the asset registry.

**The port — `core/findings/hosts.py`** (`1ee36b5`). The findings side names the host columns it
reads (`HOST_COLUMNS`) and keeps a registry for one directory:

- `hosts()` is a subquery of exactly those columns, to join findings to;
- `record_open_findings(db, asset_id, counts)` hands the asset write over.

The asset registry answers it in `core/asset_hosts.py`. The counts-and-risk write moved there
verbatim. Audit's composition root registers it (`ccure_audit/host_directory.py`), named in
Celery's `imports` beside G4's evidence providers. So the worker loads it, for the remediation
section of a credentialed report, and so does the API (through `import_default_modules`). A read
with none registered raises `HostDirectoryMissing`.

**The SQL is one statement, as before.** PostgreSQL pulls a plain subquery up into the join. The
golden's `EXPLAIN` of every findings, grouped, detail, remediation and asset query is identical to
the direct join's (122 statement sets), so the order of rows that tie under a sort is unchanged.
Scoping is still by the asset's organisation; §7 records the alternative.

**The findings reads — `core/findings/reads.py`** (`bf7390d`). The assets router asks it for all
six reads and gets plain values back; the queries and the rows they make moved verbatim. The router
keeps its routes, permissions, asset checks, the port-risk table and the response envelopes.

The three estate listings join hosts through the port and select the host's columns. Before, they
loaded the asset through `Service.asset`, an eager outer join. With the host inner-joined, every
value is the one the relationship gave.

**A defect the golden found before the commit.** In the first version of `bf7390d`, the
certificate listing could not be built. Its `join(Service)` relied on inference, and once the
host's columns were added SQLAlchemy re-inferred it against two candidate left sides. All 17
certificate requests raised `InvalidRequestError`, and no test reached that route. The ON clause
is named now (the one inference chose before), and `tests/scans/test_findings_reads_for_assets.py`
runs the listing with every sort, in two organisations.

#### B10's follow-up — the CVE paragraph (`604157e`)

`make_pdf_cve_paragraph` moved, unchanged, to `reporting/report_helpers.py`, and the web scan's
PDF renderer imports it from there. `scan_helpers` keeps the name through a module `__getattr__`,
imported on first use, so loading `scan_helpers` still loads no ReportLab.

That was the one edge holding web DAST in the capability cycle, and it leaves the cycle. The
renderer now loads 3 first-party modules, not 97, and no longer FastAPI, SQLAlchemy, Redis, Scapy
or nmap.

#### C8 — the compliance router

**The renderers** (`125da93`). The 20 generators (2,563 lines) moved, unchanged, to
`reporting/compliance/`:

- one module per document family: `soa`, `nist_csf`, `pci_dss`, `privacy`, `nist_800_53`,
  `iec_62443`, `nist_800_82`, `nerc_cip`, `nis2`;
- `common` holds the verdict accessor four of them share.

A renderer takes the controls and rolled-up verdicts its route read and returns the document. It
imports nothing of compliance, no model and no database code.

**One signature changed.** The NIST CSF pair grouped the controls themselves with `_csf_group`,
which orders by `core.nist_csf`, compliance's catalogue knowledge. The route now groups them and
hands the groups over. `_csf_group` is pure, and nothing between the verdict read and the generator
call can raise, so the document is the same.

**The parts** (`5222695`), moved unchanged. Seven parts against the plan's six: the report routes
are in two modules, to keep every file under the analysis's 1,500-line target.

| Module                         | Lines | Sections                                                  |
| ------------------------------ | ----: | --------------------------------------------------------- |
| `compliance_catalogue`         |   774 | the marketplace; policy baselines and rules; the register |
| `compliance_assessment`        |   816 | starting a scan; its findings; its runs; the summary      |
| `compliance_attestation`       |   715 | attestation; evidence files; exception waivers            |
| `compliance_schedules`         |   231 | recurring scans                                           |
| `compliance_remediation`       |   833 | credentials; applying a fix; the maker-checker queue      |
| `compliance_reports`           |   625 | the SoA, the executive report, gap analysis, NIST CSF     |
| `compliance_framework_reports` |   943 | the other eleven framework reports                        |
| `compliance_common`            |   336 | what they share                                           |
| `compliance` (the router)      |   261 | the sections mounted in order; the old module's names     |

**The API is the one it was.**

- **The route order is kept.** Each section is a router of its own, and `routers/compliance.py`
  mounts the 15 sections in the order the routes were always listed. The gateway's committed route
  policy pins that order and each route's endpoint name.
- **The names are kept.** Each part sets its `__name__` to `routers.compliance`, as the platform's
  moved modules adopt their legacy names. So the limiter keys, the gateway policy's endpoints and
  the models' module stay `routers.compliance.<name>`.
- **No patch through the router.** `routers/compliance.py` re-exports every name the old module
  defined and, like `core/tasks.py`, refuses a patch, naming the part to patch. Eight test patches
  in three files moved to the parts that read the names: the evidence path's to
  `compliance_attestation`, the refusal audit's to `compliance_common`.
- **One change that is not a move.** Compliance's two reads of the asset model are written once,
  in `compliance_common`, instead of in the two parts that use them. They are the findings list's
  join and the remediation queue's label lookup. Otherwise the split would count compliance's one
  existing dependency on assets twice, and the lateral-edge ceiling, which may only be lowered,
  would have to rise. The SQL is the same.

The guard is `tests/repo/test_compliance_router_split.py`. It pins:

- the routes' module, and the order of the sections;
- the limiter keys, and the refusal of a patch;
- the old module's names;
- the renderers' imports and the twenty generators;
- the 1,500-line target.

#### Before the change: an API golden

`Backend/scripts/verification/api_golden/` (`a324220`) runs on the compliance golden's restored
server: the 24 Oct 13:16 full dump with that golden's `setup.sql`. It works on a fresh copy of the
template, with one commit's code, and drives 450 requests through `main.app`:

- **Findings:** the list, groups and detail under every filter and sort, in both organisations
  (the golden adds a host with services, TLS and findings to the second one).
- **Remediation:** the summary, the queues and the history.
- **Assets:** the list and detail, an asset's services and findings, the estate's certificates
  and services under every sort, and the hosts of every service signature.
- **Writes:** the findings and remediation writes.
- **Compliance:** every compliance route. All 14 catalogues are activated, so all 13 report routes
  render, as PDF and DOCX, for every installed catalogue. Also the evidence upload, attestation,
  schedules, policies, credentials and exceptions, and the four remediation paths.

What it captures:

- every response: JSON as rendered, a PDF as its SHA-256 (ReportLab invariant), a DOCX as each
  member's SHA-256;
- `EXPLAIN (COSTS OFF)` of every SELECT the findings, remediation and asset reads ran;
- every broker message;
- every table's digest, and the touched tables in full.

**The broker is real.** Celery is not eager: kombu serialises each dispatch to the Redis beside
the database. After each request every queue is read back and decoded with kombu's own
deserialiser, which is what a worker receives. Each record holds:

- the task, arguments, keyword arguments and routing;
- the headers that do not name the run (task ids are counters; the origin host is dropped).

A compliance scan's message is then run in-process from the decoded arguments, as a worker runs
it. A remediation's is recorded and not run: it would open a session to a host. Its encrypted
credential is recorded as whether it decrypts to the posted placeholder, never as text.

**Who is signed in.** The restored platform administrator, by overriding the identity dependency.
The RBAC engine still decides every permission.

#### Verification

| Check                                                                     | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Interfaces, `b6ae9bf` against `5222695`                                   | The route table in order (288 routes, with each route's module, name, tags, status code, response model and dependencies), every limiter key and the OpenAPI document as generated (key order kept) identical at C8a and C8b. The interface snapshot names five differences, all expected: the new parts hold the canonical limiter                                                                                                                                         |
| API golden, determinism                                                   | Two captures of `b6ae9bf` identical (654 files)                                                                                                                                                                                                                                                                                                                                                                                                                             |
| API golden, C7 (`bf7390d`)                                                | Every response, broker message and table identical. 63 plan files differ, all the certificate and service-host listings: the redundant second (eager) join to `assets` is gone, and the driving joins are unchanged. The other 122 plans are identical                                                                                                                                                                                                                      |
| API golden, C7's first version                                            | 17 certificate requests raised `InvalidRequestError`; fixed before commit (above)                                                                                                                                                                                                                                                                                                                                                                                           |
| API golden, `604157e`, `125da93`, `5222695`                               | Each byte-identical to C7's capture, plans included: all 47 compliance routes' responses, every PDF digest and DOCX member, the broker record, the tables                                                                                                                                                                                                                                                                                                                   |
| Broker round trip, the four moved compliance dispatches                   | 23 messages on the `compliance` queue, identical at every commit: 20 `compliance.run_scan` (each then run from its decoded arguments) and the three `compliance.run_remediation` paths (an emergency bypass, an approval by someone other than the requester, a bypass rollback). The bypass's credential decrypts to the posted value                                                                                                                                      |
| Guard mutations, each in a scratch copy                                   | 7 of 7 caught: the findings router importing the asset model again; the assets router importing a findings model again; the worker not loading the host directory (2 tests); the web PDF renderer back on `scan_helpers` (2 tests: the edge, and web DAST back in the cycle); a part without the router's name; two sections mounted out of order; a renderer importing compliance (2 tests)                                                                                |
| Golden mutations, each committed in a scratch worktree, never on a branch | 3 caught, 1 not: the moved rollback route dispatching with `is_rollback` flipped (`broker.jsonl`); the findings list without its tenant filter (9 responses, 21 plans); a rendered NIST CSF label, "Non-compliant" (4 report responses, PDF and DOCX). Not caught: the label of a _passing_ CSF control. No NIST CSF control passes in the restored data (26 fail, 80 not assessed), so that label is never drawn and the golden does not exercise the branch (§7)          |
| Targeted tests, `5222695` from a clean worktree, throwaway containers     | The selector's 14 groups (assets, audit, audit_boundary, auth, compliance, credentialed, modules, rbac, repo, reports, scans, security, topology, web): **8,247 passed, 0 failed, 211 skipped**, 19 min. The skips are environment ones: 165 need the DBA-installed audit chain and 44 audit retention, one the live OSV feed, one the Alembic rehearsal. The gateway route-policy drift test ran and passed. Not run: the rest of the suite (the selector did not name it) |
| Live scan                                                                 | Not run: neither C7 nor C8 touches a scan path; the compliance scans ran from real broker messages in the golden                                                                                                                                                                                                                                                                                                                                                            |

#### Coupling

`b6ae9bf` → `5222695`:

| Figure                                  | Before | After |
| --------------------------------------- | -----: | ----: |
| Capability cycle, all imports (largest) |     12 |    11 |
| Capability cycle, top-level (largest)   |      5 |     5 |
| Upward edges                            |     19 |    18 |
| Lateral edges                           |     33 |    29 |
| Foreign-table references                |     50 |    46 |
| Foreign-table writes                    |      5 |     5 |

- **Web DAST left the cycle**, through the paragraph's move.
- **Findings and assets are out of each other's cycle.** No findings module imports the asset
  registry or names its table. The asset router reads findings through `core.findings.reads`,
  and the syncer calls the writer, both in the direction G3 set.
- **Foreign-table writes stay at 5.** The uncounted findings → assets write is gone (above).

**Import cost** (first-party modules, `b6ae9bf` → `5222695`):

| Module                        | Before | After |
| ----------------------------- | -----: | ----: |
| `reporting.web_pdf_generator` |     97 |     3 |
| `routers.compliance`          |     72 |    92 |
| `routers.assets`              |     69 |    73 |
| `routers.findings`            |     79 |    82 |
| `routers.remediation`         |     74 |    75 |
| `core.remediation.reporting`  |     41 |    41 |
| `scan_helpers`                |     96 |    96 |

The compliance router loads its eight parts and ten renderer modules.

#### Differences from the plan

- **C7 named the dashboard and the reports API; G6 did the read paths the owner named.** Those
  are the findings, remediation and asset routers and the remediation report. The dashboard (11
  foreign tables) and `routers.reports`' direct reads are unchanged (§7).
- **Hosts are read through a port, not through `ccure_audit/services`.** A findings router is a
  layer-4 module, and the audit boundary is layer 6. A read service there would be an upward
  edge, so the asset registry's answer is registered at the composition root instead, as G4 did
  for evidence.
- **The port carries a SQL projection, not plain values.** That keeps every query one statement
  with the same plan. The coupling to the asset table is now a declared contract (`HOST_COLUMNS`,
  checked at registration) rather than an import (§7).
- **Eight modules where the plan named six parts.** The report routes are split in two, and
  `compliance_common` holds what the parts share.
- **The executive compliance report still draws its PDF inline.** It is not one of the 20
  generators (§7).

#### What G6 leaves, and what it found

- **Found: the findings router wrote the asset row.** Counts, risk score and risk level, after a
  status change: a cross-capability write the ratchet recorded only as a reference. The asset
  registry writes it now, through the port.
- **Found by the golden: the certificate listing's broken first version.** Fixed before commit;
  the route had no test.
- **`/assets/services/assets` pages with no `ORDER BY`.** Pre-existing: which rows a page holds is
  whatever the plan returns (§7).
- **Findings is still in the capability cycle,** through edges outside C7: the comparison reads
  the scan model; the writer imports the credentialed coverage and the router the distribution
  version comparator; the credentialed scope reads configuration-audit findings; the comparison
  imports scan policy (§7).
- **Compliance's reads of assets and services outside the evidence path** stand, as G4 recorded,
  now in `compliance_common` and the scan task.
- **The network pipeline's broker round trip** (G5's §7 row) is still unverified: G6 measured the
  compliance dispatches only.

### F1 — the compliance workspace calls through `api/compliance.js`, and is split by tab

Commits, on top of `f3f602f`:

- `cc5670c` — the workspace's calls go through `src/modules/audit/api/compliance.js`;
- `38902a2` — the page is split by tab.

**The scope** (analysis §10, "Frontend, in parallel and low risk"): "Compliance calls go through
an `api/compliance.js` module, and `ComplianceWorkspace.jsx` is split by tab." F2 and F3 are not
started. The credential calls are still the compliance alias of the vault's API
(`/compliance/credentials`); moving the screens to one credential API is F3.

#### The API module (`cc5670c`)

The analysis counted 31 direct calls. There were **34**: three more were written as chains
(`axiosInstance\n  .get(…)\n  .then(…)`) that a one-line search does not see — the marketplace's
active-framework read on mount, the dashboard's per-framework summaries, and the credential list
the remediation dialog loads. All 34 go through 29 functions, each sending the method, path,
query, body and config the page sent, built the same way: a one-argument `post` stays
one-argument, the multipart header and `responseType: "arraybuffer"` are the module's, and the
exception decision still encodes its id. The workspace tests assert the requests on the wire
(`expect(api.post.mock.calls).toEqual(…)`) and passed unchanged.

`ComplianceWorkspace.api.test.js` keeps the HTTP client out of the page and its tab parts.
Mutation: an `axiosInstance` import put back into the page fails it.

#### The split (`38902a2`)

The page went from 5,183 lines to **3,040**. What moved, verbatim, to
`src/modules/audit/components/compliance/workspace/`:

| Part                           | Lines | Props | What it is                                                   |
| ------------------------------ | ----- | ----- | ------------------------------------------------------------ |
| `ComplianceDashboardTab.jsx`   | 476   | 26    | the Dashboard tab                                            |
| `ComplianceMarketplaceTab.jsx` | 134   | 8     | the Marketplace tab                                          |
| `CompliancePoliciesTab.jsx`    | 249   | 8     | the Policies tab                                             |
| `ComplianceControlsTab.jsx`    | 211   | 8     | the Controls tab                                             |
| `ComplianceFindingsTab.jsx`    | 328   | 21    | the Findings tab                                             |
| `ExceptionsPanel.jsx`          | 175   | —     | the Exceptions tab, already a component in the page          |
| `ComplianceCredentialsTab.jsx` | 294   | 24    | the Credentials Manager tab                                  |
| `ComplianceApprovalsTab.jsx`   | 378   | 14    | the Approvals Queue tab                                      |
| `shared.jsx`                   | 230   | —     | score bands, theme labels and badges, and the paging control |

The Schedules tab was already its own component (`ComplianceSchedules.jsx`) and is rendered as it
was.

**The page keeps the state, the requests, the handlers and the dialogs.** The dialogs are opened
from several tabs (an attestation from Controls and Findings, a rule edit from Policies and
Findings), so they belong to the page that owns the state they share. A tab is a function of
its props and holds no hook; the page renders it under the same `activeTab` condition, in the
same place, so the DOM is the one it was. `useId` values do not move either: React 18 numbers
them in mount order on the client, and a component that calls no hook adds none.

**The stylesheets stay imported by the page**, in the order they were, so the bundle's CSS order
and the cascade are unchanged.

**How the props were chosen.** A script parsed the page (`espree`, `eslint-scope`) and, for each
tab's JSX, listed every name it reads that the component's scope defines (a prop) or the
module defines (an import, or a helper moved to `shared.jsx`). JSX element names are not
references to `eslint-scope`, so they were collected from the tree. ESLint then checked the
result with `no-undef`, `react/jsx-no-undef` and `no-unused-vars` on: nothing undefined, nothing
unused, in the page or any part. The unused imports the page was left with were removed the
same way.

**Prettier re-wrapped three labels, and the browser saw it.** At the tabs' shallower indentation
Prettier joined text it had split before: `Download{" "}` / `{reportFmt.toUpperCase()} Report`
became `Download {reportFmt.toUpperCase()}{" "}` / `Report`, and `Rule Code:{" "}` and
`Target Host:{" "}` became `Rule Code: ` and `Target Host: `. The words are the same, but React
renders each JSX child as its own text node, so the nodes were not (`" Download"`, `" "`, `"PDF"`,
`" Report"` became `" Download "`, `"PDF"`, `" "`, `"Report"`), and how Chrome draws a label
depends on how it is split. The harness's first after-capture showed it: 42 pixels of the
dashboard's "Download PDF Report" button, on the "Re", in every dashboard and gap-analysis state, by up to
57 levels, and in no capture of the same build twice. The three labels now write their text
pieces as string children (`{"Rule Code:"}`, `{" Download"}`, `{" Report"}`), which Prettier
cannot merge with the whitespace beside them, and the nodes are the page's again.

The harness's DOM comparison did not catch this: it records an element's text as a hash of the
content, not of its nodes. A token comparison did, once written: each moved block before and
after, through `espree`'s tokenizer, with JSX text reduced the way the JSX transform reduces it and a string
literal alone in braces read as the text child it is. All seven tabs, `ExceptionsPanel` and the
five shared helpers are identical under it, and so are the page's unmoved regions (the
component body, the panel's other children, the dialogs, and the module-level code left in
place). Putting one of the joined labels back makes it fail.

**The tests that read the source.** Six workspace tests sliced a tab's markup out of the page by
its `{activeTab === "…" && (` marker and asserted on it (design-system parts only, no inline
style, no hand-built control). They now read the tab's own file and assert that the page
renders the tab at that marker; the dialog slices and the stylesheet checks are unchanged.

#### Verification

All on the final code unless named.

- **The workspace's tests**, the eight files that render it and assert its requests, the API
  guard and the module-boundary test: 10 files, 271 tests passed. `vitest related` over the
  changed files, before the label fix: 10 files, 289 passed.
- **The full frontend unit suite**, which the CI selector asks for because the authorization
  inventory changed: 123 files, **3,187 passed**, 0 failed.
- **Lint and the UX4G gates:** `npm run lint`, `ux4g:check -- --dependencies-only`,
  `ux4g:architecture`, the build with `VITE_API_BASE_URL=/api` (its two runs byte-identical),
  `ux4g:verify`, `ux4g:check -- --dist` and the authorization inventory's `--check`: all pass.
- **The backend groups the selector names**, `tests/repo` and `tests/security`, in throwaway
  containers (`scripts/ci/local_guard_tests.sh`): **1,145 passed**, 1 skipped
  (`test_alembic_module_branches`, which skips where `alembic.ini` is already activated).
- **The token comparison** above: the seven tabs, `ExceptionsPanel`, the five shared helpers and
  the page's unmoved regions identical; the mutation caught.
- **The browser, before and after.** The UX4G harness built `cc5670c` and the split as
  production images and captured the 55 compliance states (95 captures, light and dark where a
  state has both) twice each, with every request answered from fixtures. No capture showed a
  refused write, an unstubbed read, an off-origin request, a CSP report or a page exception.
  Before against after, in all four pairings, every category but the screenshot (accessible
  names, roles, ARIA states, text, classes, computed styles, element boxes, contrast, tab order,
  requests among them) identical in every capture; 88 to 93 of the 95 screenshots identical.
  Every screenshot that differs differs in the same 25 × 4 px of the header (x 1323–1348,
  y 18–22), in the light theme, by at most 6 levels, and the same area differs between two
  captures of one build (4 captures before, 5 after), so it is the environment, not the change.
  The first after-capture also differed in the download button (above); the second did not.

#### What is left

- **The page is still 3,040 lines**, about 760 of them the dialogs. F1 split it by tab, as
  planned; splitting the dialogs out is a further step, if wanted (§7).
- **The prop lists are long** (26 for the dashboard, most of them the report's scoping filters
  and their setters). They are what the markup reads; grouping them would change the tabs' interfaces and was not F1's
  business.
- **The harness's determinism gate does not pass on this VM.** Two captures of one build
  differ in 4 or 5 of 95 screenshots, always in the header area above. The gate was read with
  that recorded rather than loosened (§7).
- **`npm run test:browser` was not run.** The selector reports `browser: false` for these files;
  the harness covered the compliance states instead.
- **`AppLayout.test.jsx` is intermittent.** One test failed in about one run in three on its own
  while this was verified; it imports nothing F1 changed, `vitest related` does not select it,
  and it passed in the full run (§7).

### F2 — scans and credentialed results meet only in Audit's shared layer

Commit `2a055e1`, on top of `8b27a7a`.

**The scope** (analysis §10): "`ScanContext` moves out of the shared layout's imports, and the
components shared by scans and credentialed results move to Audit's shared layer." §7.3 measured
it as "scans ↔ credentialed import each other; the shared layout imports `ScanContext`".

**What was coupled.** `components/layout/` held `ScanStepper`, the one layout file that read
`ScanContext`; only the three phase-results pages use it. `components/scan/` held two kinds of
file besides the scan screens' own: two components both features use, and seven sections only
`CredentialedResults` renders (one of them, `FindingsListSection`, says it was extracted from
that page). So the credentialed page imported eight files from the scans feature's folder.

**What moved**, by use rather than by name, each with `git mv`:

| File                                                                                                                                                                     | From      | To                    | Used by                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | --------------------- | --------------------------------------- |
| `ScanStepper`                                                                                                                                                            | `layout/` | `scan/`               | the three phase-results pages           |
| `ReportExportPanel`                                                                                                                                                      | `scan/`   | `common/`             | `ScanComparison`, `CredentialedResults` |
| `RiskBadge`                                                                                                                                                              | `scan/`   | `common/`             | `ScanHistory`, `CredentialedResults`    |
| `ConfigAuditSection`, `FindingsListSection`, `FindingEnrichment`, `PackageCoverageSection`, `PackageInventorySection`, `ScanPolicySnapshot`, `SuppressedFindingsSection` | `scan/`   | `credentialed/` (new) | `CredentialedResults` only              |

`scripts/audit/manifests/field_coverage.json` already listed the seven sections as the
credentialed renderers. `RiskBadge` keeps its deprecation: it is the adapter its header says it
is, now in the folder its two consumers share. Seven test files moved with their components;
`Phase1RealResponse.test.jsx` exercises only credentialed sections, with the credentialed
fixture, so it went with them.

**Nothing else changed in the files**: seven moved byte-identical, and `ScanStepper` and
`RiskBadge` differ only in the path their header names. **The production bundle is
byte-identical before and after** — every file in `dist/`, compared by content — so nothing the
browser receives changed, and no harness capture was needed to show it.

**What still crosses.** The credentialed screens call the scan APIs (`api/scans.js` for the scan
record, `api/scanPolicies.js` for the policy snapshot). Those are the HTTP boundary, not the scans
feature, and the guard allows them.

**The guard**, `src/__tests__/modules/audit/featureBoundaries.test.js`: the shared layout
imports no scan state, no feature component and no page; the credentialed screens and
`components/credentialed/` import nothing of the scan screens, `components/scan/` or
`ScanContext`; and the reverse. Each of the three rules fails its mutation (a `ScanContext`
import in `AppLayout`, `ExportPanel` in `CredentialedResults`, `ConfigAuditSection` in
`ScanHistory`). Audit's README describes the folders.

#### Verification

- The full frontend unit suite before the guard was written: 123 files, **3,187 passed**, the
  same counts as before the move (the tests moved; none was lost). The guard's 4 tests pass, and
  F3's full run below includes them.
- Lint, `ux4g:check -- --dependencies-only`, `ux4g:architecture`, the build with
  `VITE_API_BASE_URL=/api`, `ux4g:verify` (byte-identical over two runs) and the authorization
  inventory's `--check` (one entry moved with `ReportExportPanel`): all pass.
- The bundle comparison above.
- Backend, in throwaway containers: the selector's `tests/repo` and `tests/security`, plus
  `tests/reports/test_report_field_coverage.py`, which reads the manifest the move edited and the
  selector does not name: **1,200 passed**, 1 skipped (`test_alembic_module_branches`, which
  skips where `alembic.ini` is already activated).

### F3 — the credential screens use one API

Commit `debf8c1`, on top of `2a055e1`.

**The scope** (analysis §10, after S2): "The credential screens use one API." S2 left the backend
with one credential service and one permission set, and kept `/compliance/credentials` as an
adapter over it for "the three screens [that] still call [it]": the scan setup
(`NewScan.jsx`), the credentialed scan (`CredentialedScan.jsx`) and the compliance workspace
(its Credentials Manager tab and its remediation dialog). `ScanCredentials.jsx` already used
`/credentials`.

**What changed.** All three read and write through `api/credentials.js`, the credential store's
client: `listCredentials()`, `createCredential()`, `deleteCredential()`. `api/compliance.js`
loses its three credential functions. No frontend source names `/compliance/credentials`
any more.

**What the screens now send and read.** The rows are the same — both routes list through
`credential_vault.list_for_org` with no type filter, and the screens read only `id`, `name`,
`username`, `port` and `auth_method`, which both carry. The differences are the store's
contract:

- **The list** arrives as `{credentials, total}` instead of a bare array; the screens read
  `credentials`.
- **Create** sends the store's body: `credential_type: "ssh"` (what the alias created by
  default), `private_key` instead of `key_content`, the unused secret omitted rather than null,
  and `domain: null` and `options: {}`. Both routes create through `credential_vault.create`.
- **Refusals** carry the store's wording: a duplicate name is 409 "A credential named 'x'
  already exists." where the alias answered 400 "A credential with this name already exists".
  The workspace prints whatever `detail` says, so the toast follows.
- **Delete** answers `{success, id, name, schedules_affected, note}`. The workspace still says
  "Credential deleted successfully." and does not show the note (§7).

**One behaviour changes, in the right direction: the organisation.** The alias always acted in
the user's home organisation — it never read the `org_id` the client sends with every request
(`resolve_active_organisation(user)`). A superadmin switched into another organisation was
offered, and could create and delete, the home organisation's credentials, while the scan the
picker fed ran in the switched one. `/credentials` resolves the requested organisation like
every other Audit route, so the screens now show the credentials of the organisation they are
in. For anyone not switched, nothing changes.

**The alias stays.** Its routes, shapes and tests are unchanged; only its comment, which said
three screens still call it, is corrected (same line count, so the RBAC migration inventory is
unchanged). Retiring it is decision D-3 (§7).

**The tests.** Seven test files followed the screens: the five workspace files, `NewScan`'s
contract test and the credentialed-scan test now mock `/credentials` with the store's envelope
and assert its body and paths. The UX4G harness's fixtures and the Playwright catalogue serve
`/credentials` for these screens; the catalogue's alias stub, now reached by nothing, is gone.
`src/__tests__/modules/audit/credentialApi.test.js` keeps it so: nothing names
`/compliance/credentials`, and only `api/credentials.js` names `/credentials`. Both rules fail
their mutation.

#### Verification

- **The affected tests**: the five workspace files, `NewScan`'s contract test, the
  credentialed-scan test and `ScanCredentials`' tests: 13 files, 427 tests, all passing once
  `NewScan`'s read allow-list named `/credentials` (8 failed until then, all on that check).
- **The full frontend unit suite**, which the selector asks for because the authorization
  inventory moved (one `NewScan` site, by a line): 125 files, **3,193 passed**, 0 failed — F2's
  and F3's guards included.
- **Lint and the UX4G gates**: `npm run lint`, `ux4g:check -- --dependencies-only`,
  `ux4g:architecture`, the build with `VITE_API_BASE_URL=/api`, `ux4g:verify` (byte-identical over
  two runs) and the inventory's `--check`: all pass.
- **Backend**, in throwaway containers: the selector's `tests/compliance`, `tests/repo` and
  `tests/security` (for the router comment), plus `tests/credentialed/test_auth_methods.py`, which
  pins `/credentials`' contract the screens now depend on (`tests/security/` holds the alias's
  consolidation tests): **1,462 passed**, 1 skipped (the same `alembic.ini` skip).
- **The browser, before and after.** The UX4G harness built `2a055e1` and F3 and captured the
  compliance workspace's and the scan setup's states (114 captures each), each with its own
  commit's fixtures. Every capture ready in both; none with an unstubbed read, a refused write,
  an off-origin request, a CSP report or an exception. In 23 captures the requests differ, and in
  every one the difference is the same single swap — `GET /api/compliance/credentials?org_id=o-1`
  out, `GET /api/credentials?org_id=o-1` in — with the count unchanged. In 5 the screenshot
  differs, all in the header's noisy area recorded under F1 (four at x 1323–1348, one at
  x 326–352 on the phone-width mission view, where the same element sits), by at most 6 levels.
  Every other category is identical in every capture.

#### What is left

- **The workspace does not show the store's delete note** ("N schedule(s) referenced this
  credential and will now fail …"), which Scan Credentials can; the alias never sent one (§7).
- **The scan setup's empty state still points to Compliance** to register a credential, though
  the credential store's own page is Scan Credentials (§7).
- **The workspace's credential buttons are still gated on `manage_frameworks`** — the §7 row
  from S2, unchanged by F3, which moved the calls and not the gates.
- **`npm run test:browser` was not run**; the selector reports `browser: false`. The Playwright
  catalogue's stubs were changed with the screens and are exercised only by that suite.

### Group 1 — D1 and E2: the engine libraries, isolated and pinned

**The scope** (analysis §10, Phases D and E; the grouped plan's Group 1): D1's harness for
the libraries that should already pass, and E2's forbidden-package pin for the same set.

**D1 — `Backend/scripts/architecture/library_isolation.py`.** `LIBRARIES` declares eight
libraries: each one's entry points, the first-party module prefixes and the third-party
packages it may use, and its existing tests. Each is checked twice, each time in a fresh
interpreter started with `-P`, holding no settings, database URL or credentials and only
the parent's package directories on its path:

- **import:** every first-party import is checked against the declaration. Afterwards
  nothing undeclared may be in `sys.modules`, nothing first-party may have loaded from
  outside the checkout (the backend image also carries its baked `/app`), and none of
  SQLAlchemy, FastAPI, Celery or Redis may have loaded, whoever imported it;
- **exercise:** its existing tests run under pytest without `tests/conftest.py`. The tests
  may import anything; every import the library's own code makes is checked. The guard
  sits on `builtins.__import__` as well as `sys.meta_path`, because a module the tests
  already loaded is answered from `sys.modules` without asking any finder.

A refused import raises `ImportError` and is recorded, so a library that catches it and
carries on still fails.

**E2 — `capability_map.library_problems`.** Every declared entry point's load profile may
hold none of `FORBIDDEN`. The ratchet runs it on the tree, and `--write-baseline` refuses
a measurement that breaks it, so unlike a load-profile ratchet entry no rewritten
baseline admits one. The ceilings are unchanged.

**Not declared, deliberately:** the port and network-check engines, the nmap wrapper,
the version matcher and the topology engine. Each loads a forbidden package (§12.1) and
joins in Group 3. Nothing exempts them.

**Integration.** `scripts/ci/local_guard_tests.sh`, with its default set, runs the harness
after pytest in the backend image, with no network and the staged checkout read-only.

#### Results

| Library           | First-party modules loaded | Its tests in isolation                                                       |
| ----------------- | -------------------------: | ---------------------------------------------------------------------------- |
| `ssh_transport`   |                          3 | `test_sudo_password_safety.py`: 44 passed                                    |
| `winrm_transport` |                          4 | `test_windows_winrm.py`, its transport tests by name: 15 passed              |
| `smb_transport`   |                          4 | `test_smb_transport.py`: 63 passed                                           |
| `config_audit`    |                         23 | `test_config_audit_engine.py`, `test_config_audit_collectors.py`: 106 passed |
| `scap_compiler`   |                         32 | `test_scap_parsers.py`, `test_scap_evaluation.py`: 100 passed                |
| `check_kernel`    |                          8 | `test_check_framework.py`: 32 passed                                         |
| `renderers`       |                         16 | `test_export_workbook.py`, `test_report_integrity.py`: 76 passed             |
| `discovery`       |                         17 | `test_host_identity_precedence.py`, `test_ot_probes.py`: 39 passed           |

No library fails isolation, and no import was refused. The module counts equal the static
closures `import_graph` computes, so the real imports and the static measurement agree.

The first run's one failure was test selection, not the library: 16 tests in
`test_windows_winrm.py` exercise the credential API, its validation and its audit trail
through `conftest`'s database fixtures. The declaration now names the file's transport
tests (`TestWinRMConfiguration`, `TestWinRMThreadSafety`, the shell-type test).

#### Verification

- `scripts/ci/local_guard_tests.sh`, default set, in `ccure-audit-pro-backend:latest`:
  `tests/repo`, the sudo-password tests and the credential-API tests **970 passed, 0 failed,
  1 skipped** (the `alembic.ini` rehearsal); the harness **8 isolated, 0 failed**; exit 0.
- `tests/repo/test_library_isolation.py` (12 tests, inside that run), the mutations among
  them:
  - **SQLAlchemy in an engine:** appended to `core/config_audit/engine.py`. E2 names it
    from the load profiles, and D1 refuses it in a copy of the source.
  - **`config` in discovery:** appended to `core/discovery/engine.py`; D1 refuses it. E2
    cannot see this one: discovery already loads the `infra` capability.
  - Each D1 mutation runs on a copy that passes first, so a pass is not vacuous.
  - A baseline recording a forbidden package still fails the ratchet.
  - A library's lazy import of a module its tests already loaded is still refused.
- `capability_map --check` and the `architecture-guards` hook: hold.

#### What is left

- **D1 vouches only for the paths its tests reach.** Discovery's tests never run ARP, the
  path that lazily imports `core.oui_lookup` and through it `db.models` (log §7, from B3).
- **The harness runs locally only** until CI runs again (D-5; Group 5).
- **Five engines join in Group 3.**

### Group 2 — the dashboard and the report routes read through their owners (C7's remainder)

Commits `b6db6f7` (the golden, before the change) and `0687924` (the change), on top of
`a019399`.

**The scope** (analysis §10, C7; the grouped plan's Group 2): the read side G6 left — the
dashboard's 17 routes and the three report routes — reads each capability through that
capability's own lower-layer read module; `routers.reports` stops importing `scan_helpers`;
and the executive compliance PDF, the one document still drawn inside a route, becomes a
renderer.

#### Before the change: the API golden extended

`Backend/scripts/verification/api_golden/` (`b6db6f7`) now drives, besides everything G6
drove:

- **all 17 dashboard routes** in both organisations, and 26 variants: every window, limit
  and severity filter, every web drill-down filter and page, an invalid date and an
  out-of-range window;
- **the three report routes:** download in every format and alias for four scans (a
  credentialed audit, a basic scan, an unreachable one and an asset discovery), a bad
  format and a missing scan; the export in every format and dataset, with severity,
  verdict, scope, baseline and organisation filters, and its four refusals; deleting a
  scan's reports, then the download that regenerates them.

The restored copy held no discovered endpoints and no HTTP security details, and its web
findings carried no OWASP category, tool or verification, so the golden seeds them: a recent,
a running and an other-organisation web scan, six web findings, six endpoints (distinct
timestamps, so no ordering rests on a tie) and three HTTP detail rows. The report routes
authenticate with a ticket or a bearer token (`current_user_flexible`), overridden like the
bearer dependency; they write into a directory of the run's own, since the stored report
files are not in the checkout and the first download of each regenerates it.

Two captures of `a019399` were byte-identical (855 files) once two things were fixed in the
golden: an endpoint row's `updated_at` defaulted to the server clock, and a workbook's file
digest carried each zip entry's write time (the files are now recorded member by member, as
the responses already were).

#### The change (`0687924`)

| Read                                                  | Was                                         | Now                                                                                |
| ----------------------------------------------------- | ------------------------------------------- | ---------------------------------------------------------------------------------- |
| Findings, services, TLS and HTTP details (17 queries) | the dashboard, joining the asset model      | `core/findings/summaries.py`, scoped through the host port `core.findings.hosts`   |
| Assets and the change log (14 queries)                | the dashboard; the export's lifecycle dates | `core/asset_reads.py`                                                              |
| Scan records (6 queries), a scan's stored phases      | the dashboard; `reporting.exports`          | `scans/reads.py`                                                                   |
| Web scans, findings and endpoints (16 queries)        | the dashboard                               | `core/web/reads.py`                                                                |
| The export lookup (`_scan_for_user`)                  | `routers/reports.py`                        | `scans.scan_access.report_scan_or_404`, moved unchanged; the router keeps the name |
| What a report says about its scan                     | `scan_helpers`                              | `scans/report_context.py`, moved unchanged; `scan_helpers` re-exports every name   |
| Recording and clearing a scan's report paths          | the report routes, by attribute             | `scans.reads.record_report_paths` / `forget_report_paths`                          |
| The executive compliance PDF                          | drawn in the route                          | `reporting/compliance/executive.py`; the route keeps its two queries               |

Every query is moved unchanged but for the host port, so a response is byte for byte what it
was. The routers keep routing, permissions, organisation resolution and the arithmetic that
shapes each response; every route's docstring, which is its OpenAPI description, is
unchanged. The writes of a scan's report paths were not counted by the ratchet (an
attribute assignment is a reference), and went through the owner anyway, as G6 did for the
findings → assets write.

#### Verification

- **The API golden, `a019399` against `0687924`:** byte-identical in all 855 files — every
  response (the 20 new routes' included), every report file (8 PDFs, 9 CSVs and 5
  workbooks, member by member), every broker message, every table, and every query plan:
  scoping through the host port's subquery gives the same plans as the join to the asset
  table did.
- **Golden mutations**, one scratch commit (`3ed72b5`, on no branch): the web drill-down
  without its organisation filter, the finding-status counts without theirs, and a label in
  the moved executive PDF. All three caught: 9 responses and 13 plans differ — the
  executive report's digest, risk-breakdown in both organisations, and the web drill-down in
  both organisations and four variants (the other variants' filters already confine them to
  one organisation's rows, so only their plans moved).
- **Interfaces**, `interface_snapshot` in the backend image, `a019399` against the change:
  identical — routes, limiter keys, the OpenAPI digest, the task registry and beat.
- **Tests:** the selector's 14 groups (assets, audit, audit_boundary, auth, compliance, credentialed, modules, rbac, repo, reports, scans, security, topology, web) on `0687924`, in throwaway containers: **8,271 passed, 0 failed, 211 skipped** (18 min). The skips are the environment ones every run on this branch has: the DBA-installed audit chain and retention, the live OSV feed, the Alembic rehearsal. A first run was cut off at 44% when its session ended, clean until its database container went with the session; it was rerun whole. No frontend file changed (the selector: frontend none).
- **The ratchet:** foreign-table references 46 → 32 (the dashboard's 11, the reporting
  capability's 3); the ceiling is lowered, the baseline rewritten (14 entries removed, none
  added). Cycles, upward and lateral edges, writes and load profiles are unchanged.
  `tests/repo/test_compliance_router_split.py` counts 21 generators (20 from G6, the
  executive report's from G2).

#### What is left

- **Neither capability is in a cycle, and both now meet their §12 foreign-table targets:**
  the dashboard and reporting reference no foreign table. Reporting's §12 row also asks
  that the renderers be in no cycle; they are still in the 4-capability cycle through
  `ccure_platform.audit_log.export` (log §7, from B7).
- **The routers still hold ORM rows** the read modules return — a `Scan`, an `Asset`, a
  `WebFinding` — rather than views. Converting them is a change to the renderers and the
  exports, which take the same rows.
- **§12.1** is the dated E4 measurement and is not regenerated here.

## 7. Decisions awaiting the project owner

| #   | Decision                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | From                                                               |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| D-4 | Approve the worker privilege split (S3)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | [`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md) |
| D-5 | Push every GitLab merge to `github`, or register a GitLab runner                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)         |
| D-9 | Commit the September baseline and plan rev 4 under `docs/archive/architecture/`, or not                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | analysis §13                                                       |
| new | Retire or repurpose `audit.compliance.manage_integrations`, which now gates no route                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | S2                                                                 |
| new | Rewrite the three NIS2 remediations that pipe into sudo as `sudo sh -c '…'` (seeded catalogue data)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | S1                                                                 |
| new | Align the compliance workspace's credential buttons (gated on `manage_frameworks`) and the scan pickers' error handling with the credential permissions                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | S2                                                                 |
| new | The schedule page: say why the credential picker is empty when the list answers 403 (a custom role holding `scan_schedule.manage` without `credential.read`), and show "New schedule" only with `scan_schedule.manage`                                                                                                                                                                                                                                                                                                                                                                                                                         | S2b, §4                                                            |
| new | Correct the picker route's docstring, the published OpenAPI description, which still says `/compliance/credentials` is gated on `compliance:read`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | S2b, §4                                                            |
| new | Whether the port and network-check engines poll a `CancelToken`. Today they never do, and the tasks check between phases; polling would make a stop take effect mid-phase, a behaviour change                                                                                                                                                                                                                                                                                                                                                                                                                                                  | B2, §6                                                             |
| new | B3 half B: move `core.utils`' CVE database client and `lookup_cve` beside their one engine caller. The port and network-check engines would stop loading SQLAlchemy, but the vulnerability database would first be contacted at the first CVE lookup instead of at import                                                                                                                                                                                                                                                                                                                                                                      | B3, §6                                                             |
| new | Fix the Nuclei probe's starved network templates (a pre-existing false negative). Against the Redis target, the probe's command matched nothing in five runs, while the non-HTTP template types alone matched 10, two of them critical CVEs, in 27 s                                                                                                                                                                                                                                                                                                                                                                                           | B3, §6                                                             |
| new | Whether discovery's MAC-vendor lookup (`core.oui_lookup`, which reads `MacVendorCache` through `db.models`) becomes a port passed in, as B2 did for progress and cancellation                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | B3, §6                                                             |
| new | Whether the topology engine's asset reads and writes move behind a port. After B6 the engine loads 32 first-party modules, 28 of them the model registry, which it imports for `Asset` and `Scan`; the plan's "~15" needs that access out of the engine                                                                                                                                                                                                                                                                                                                                                                                        | B6, §6                                                             |
| new | Take the renderers out of the remaining 4-capability cycle: `ccure_platform.audit_log.export` lazily imports `reporting.report_helpers`, the only edge into the renderers from the cycle. The analysis's §7.3 assigns it to B8, but B8's step does not name it, so B8 left it                                                                                                                                                                                                                                                                                                                                                                  | B7, §6                                                             |
| new | Correct `scripts/verification/verify_report_integrity.py`'s provenance markers: it expects "How this was detected", which the technical report stopped printing on 22 Aug 2026 (`f30e1df`), so it fails on every tree                                                                                                                                                                                                                                                                                                                                                                                                                          | B7, §6                                                             |
| new | Add the foreign keys the migrations never created on `web_scans` and `web_findings`: `org_id` to `organizations`, `created_by` and `accepted_by` to `users`, as their models declare. Both tables are empty on this installation. Until then a purge leaves `web_findings.accepted_by` naming the removed account, and no test can see the gap, because the test schema is built from the models                                                                                                                                                                                                                                               | B8, §6                                                             |
| new | Take the network checks and web DAST out of the capability cycle. After B9 each is held by one upward edge: `engines.vulnerability.vulnerability_engine` imports `core.device_classifier` (assets; the analysis's target grouping puts the classifier in the scan kernel), and `reporting.web_pdf_generator` imports `scan_helpers` (scans)                                                                                                                                                                                                                                                                                                    | B9, §6                                                             |
| new | **Done in G6** (§6, `604157e`): moved to `reporting/report_helpers.py`; web DAST is out of the capability cycle. Was: move `make_pdf_cve_paragraph` out of `scan_helpers` into the renderers. `reporting.web_pdf_generator` imports it from there, which is the one edge holding web DAST in the capability cycle at the end of Phase B                                                                                                                                                                                                                                                                                                        | B10, §6                                                            |
| new | Fix the Linux collector's `ss` parser (a pre-existing defect). When the scanning account cannot see process names, `_parse_ss_output` takes the peer address (`0.0.0.0:*`) as the process, and a credentialed audit renames port 22's `ssh`/`OpenSSH` with it                                                                                                                                                                                                                                                                                                                                                                                  | T0, §6                                                             |
| new | Give the Nuclei probe's corroboration merge a deterministic tie-break, for example severity and then template id. Today a severity tie keeps whichever template Nuclei printed first, so the stored finding's id can change between runs of the same code                                                                                                                                                                                                                                                                                                                                                                                      | T0, §6                                                             |
| new | Write the evidence's NVD reference only for a real CVE in `core/findings/writer.py`'s `_build_finding_evidence` (the pipeline's, moved from `scans/asset_syncer.py` in G3), as the standalone audit's already does. Today every network-check and Nuclei finding's evidence links its minted `CCURE-CHK-…` id to an NVD page that does not exist                                                                                                                                                                                                                                                                                               | T0, §6                                                             |
| new | Whether the Phase 3.5 pipeline and the standalone credentialed audit should record a configuration finding under the same detection method. Today one files it as `credentialed_package` and the other as `config_check`                                                                                                                                                                                                                                                                                                                                                                                                                       | T0, §6                                                             |
| new | Classify `routers.credentialed` as the scans capability's API, as `routers.phase_scans` is. It serves one route, `POST /scan/credentialed`, which creates a scan. Measured, not committed: after G2, the credentialed audit and the credential vault both leave the capability cycle (14 → 12) and upward edges fall 31 → 29                                                                                                                                                                                                                                                                                                                   | G1, G2, §6                                                         |
| new | Import the orchestrator inside `scans.tasks.common`'s two functions that use it, so the credentialed and topology task modules load without the scan engines (Scapy, nmap). Today `common` imports it at module level, as the hub did                                                                                                                                                                                                                                                                                                                                                                                                          | G1, §6                                                             |
| new | Choose one credential form. Compliance remediation authenticates with every secret a credential row stores and the username as stored (`credential_vault.stored_secrets`); the collectors use `principal()` and only the secret their auth method needs (`connection_material`). G2 kept both                                                                                                                                                                                                                                                                                                                                                  | G2, §6                                                             |
| new | Whether a remediation request should keep copying a stored credential's encrypted password and key into `compliance_remediation_requests`, and into the task's arguments for an emergency bypass. The copy outlives the credential's deletion; referring to the credential by id, as scans and schedules do, would not                                                                                                                                                                                                                                                                                                                         | G2, §6                                                             |
| new | Teach `compare_live_scans.py` to tolerate the credentialed collector's section frames in either order (consecutive collection frames at one percentage), as B3 taught it discovery's sampled frames. Measured in G2: two runs of the same commit differ only in that order. Until then the comparison reports it, and a pair is repeated to place it                                                                                                                                                                                                                                                                                           | G2, §6                                                             |
| new | Stop a standalone credentialed scan verifying the pipeline's open credentialed findings as fixed. The two paths file one CVE on one host under different finding ids (the pipeline's carry `network_service` in the id, the standalone audit's `credentialed_package`), so the standalone comparison reads the pipeline's rows as absent and verification marks them `verified_fixed` while their status stays `open`: 3,000 such rows after the G3 golden's `from_empty` replay, none in the live database. Options: one finding id per CVE per host whichever path writes it, or a comparison that counts a CVE the scan reported as present | G3, §6                                                             |
| new | Whether the vulnerability-audit pipeline verifies remediation, as the standalone credentialed task does. Today a pipeline rescan that shows a finding fixed leaves its remediation state where it was                                                                                                                                                                                                                                                                                                                                                                                                                                          | G3, §6                                                             |
| new | Decide which of the asset syncer's two `_clean` definitions is meant. The second replaces the first at import, so `upsert_credentialed_services` (in the findings writer since G3) raises `TypeError` on a listener with no service, name or process. The writer keeps the behaviour, and a test holds its copy equal to the syncer's                                                                                                                                                                                                                                                                                                          | G3, §6                                                             |
| new | **Done in G6** (§6, `1ee36b5`, `bf7390d`): findings read hosts through `core.findings.hosts`, the assets router reads findings through `core.findings.reads`. Was: take findings and assets out of each other's cycle (C7). After G3 the writes go one way, but `routers.findings`, `routers.remediation` and `core.remediation.reporting` read the asset model, and `routers.assets` reads the findings models                                                                                                                                                                                                                                | G3, §6                                                             |
| new | Whether an unsupported probe should leave a network assessment incomplete. The pipeline retires a network finding only when every plugin outcome is complete, and some probe reports unsupported on every host measured (`default_creds` on a host with no Basic challenge, `heartbleed_probe` where the server refuses a legacy handshake), so a network finding is never fixed by a rescan: on the G3 rescans, removing the web target's `.env` and `.git` read as not assessed. Safe in direction (absence is not remediation), but no network finding is ever retired by a rescan                                                          | G3, §6                                                             |
| new | Whether the NVD sync's SQL writes to `vulnerability_definitions` go through the findings writer, or the catalogue's ingest stays the vulnerability-intel capability's. It is the one recorded exception in the findings-writer guard                                                                                                                                                                                                                                                                                                                                                                                                           | G3, §6                                                             |
| new | Recognise Windows Defender as anti-malware. The Windows collector records the service as name `WinDefend`, description "Microsoft Defender Antivirus Service"; the `malware_scan` evidence reads the name first and matches `defender`, which `windefend` does not contain. A Windows host protected only by Defender therefore fails `crl_malware_agent_v1` and ISO A.8.16's `crl_iso_monitor_agent_v1`. Options: match the service names (`WinDefend`, `MsMpEng`, `Sense`), or read the description as well as the name                                                                                                                      | G4, §6                                                             |
| new | Decide what an unreadable NIST SP 800-53 seed does to a STIG crosswalk. The reader's docstring says no crosswalk is emitted; the code (`if catalogue: controls &= catalogue`) has always emitted the entries unchecked, and since G4 a caller that passes no catalogue gets the same. Options: emit nothing without a catalogue, as documented, or correct the docstring                                                                                                                                                                                                                                                                       | G4, §6                                                             |
| new | Take compliance's remaining reads and writes of other capabilities' tables through their services, to meet the analysis's target of no foreign table. After G4: the compliance scan reads `assets` for its scope, prerequisites and platform (`core.compliance_tasks`); the remediation executor sets `services.state` and `network_reachable`, and an asset's `reboot_pending`; the router joins `assets` for its findings list and remediation requests. Options: an asset read service, and the findings writer and an asset service for the writes                                                                                         | G4, §6                                                             |
| new | Whether `ComplianceCatalogueService` (`ccure_audit`, the audit boundary) reads the catalogue through `core.compliance_catalogue.reads` too. C4 named that service for scan policy's reads, which `core` may not import; it still queries the five catalogue tables itself                                                                                                                                                                                                                                                                                                                                                                      | G4, §6                                                             |
| new | Confirm or amend principle 6 ("each producing capability registers a provider"). Since G4 the producers declare their providers and Audit's composition root (`ccure_audit/evidence_providers.py`) registers them, because a producer importing compliance would be a lateral or upward edge, and two sources compose two producers                                                                                                                                                                                                                                                                                                            | G4, §6                                                             |
| new | Whether a continued scan's posted host records should reach the stored results. The vulnerability audit's identity merge starts from the record it was handed and lays its own over it, so a key the browser posted to `/scan/vulnerability-audit` that the audit does not itself write is stored in the phase-3 payload as a scan result. The person needs `audit.scan.run` and their own scan, and the hosts must be in its scope. Options: merge only `HOST_IDENTITY_FIELDS` from the handed-over record, or validate the posted records against the phase's own projection (`HostResult`)                                                  | G5, §6                                                             |
| new | Whether a phase run beyond its pipeline mode's terminal phase should chain onward. Asset discovery in a basic scan dispatches the audit, as each phase task did before C6 and `scans.pipeline.next_phase` still does. The routes refuse a phase outside the scan's mode, so only a direct task call reaches it. Option: stop at the mode's own phases (`PIPELINE_PHASES`)                                                                                                                                                                                                                                                                      | G5, §6                                                             |
| new | Give the engines the typed records (the analysis's `discover(…) → list[HostRecord]`, `inventory(hosts, …) → ServiceInventory`). C6 typed the hand-off between phases; the engines still read and edit the records as dicts in place, and phase 3's identity merge depends on those edits                                                                                                                                                                                                                                                                                                                                                       | G5, §6                                                             |
| new | Take the scans capability's direct engine imports through the pipeline definition (§12's target for `scans`). The orchestrator still imports the discovery, port and vulnerability engines itself                                                                                                                                                                                                                                                                                                                                                                                                                                              | G5, §6                                                             |
| new | Run C6's live validation (§11) if wanted: about two hours for a before/after pair. The phase-pipeline golden covers the hand-off with the tasks' own code; the live harness runs Celery eager too, so neither exercises a real broker's JSON round trip, which C6 leaves unchanged by construction                                                                                                                                                                                                                                                                                                                                             | G5, §6                                                             |
| new | **Done in G2** (§6, `0687924`): the dashboard and the report routes read through their owners' read modules. Was: the read side C7 names that G6 did not change: the dashboard (`routers/dashboard.py`, 11 foreign tables) and `routers.reports`' direct reads                                                                                                                                                                                                                                                                                                                                                                                 | G6, §6                                                             |
| new | Scope findings by their own `org_id` and drop the host join where only scoping needs it (the remediation routes and report). The finding's column is written from its asset's organisation and agrees on every row today (0 of 3,854), but no constraint enforces it; a composite foreign key `(asset_id, org_id)` → `assets(id, org_id)` would, and needs a unique key on `assets` first                                                                                                                                                                                                                                                      | G6, §6                                                             |
| new | Whether the findings side's host port should carry plain values instead of a SQL projection. G6 chose the projection so that every query stays one statement with the same plan; the findings capability is then coupled to the asset table's columns by a declared contract (`HOST_COLUMNS`) rather than by an import                                                                                                                                                                                                                                                                                                                         | G6, §6                                                             |
| new | Give `/assets/services/assets` an `ORDER BY`. The service-host listing pages with none, so which hosts a page holds is whatever the plan returns (pre-existing; G6 kept the query as it was)                                                                                                                                                                                                                                                                                                                                                                                                                                                   | G6, §6                                                             |
| new | **Done in G2** (§6, `0687924`): `reporting/compliance/executive.py`. Was: move the executive compliance report's inline PDF (`download_executive_compliance_report`) into `reporting/compliance/` like the 20 generators                                                                                                                                                                                                                                                                                                                                                                                                                       | G6, §6                                                             |
| new | Take findings out of the capability cycle: it reaches the scan model (the comparison), the credentialed audit (the writer's coverage import, the router's version comparator), configuration audit (the credentialed scope) and scan policy (the comparison)                                                                                                                                                                                                                                                                                                                                                                                   | G6, §6                                                             |
| new | Whether the compliance router's parts keep `routers.compliance` as their `__name__` or take their own. Renaming changes every compliance limiter key and the gateway route policy's endpoints, so it needs the policy regenerated and the gateway rebuilt in the same release                                                                                                                                                                                                                                                                                                                                                                  | G6, §6                                                             |
| new | Give the API golden a passing NIST CSF control. In the restored data no CSF control passes (26 fail, 80 not assessed), so the renderer's label for a pass is never drawn and a change to it went uncaught (G6's golden mutations); `setup.sql` could add a passing attestation                                                                                                                                                                                                                                                                                                                                                                 | G6, §6                                                             |
| new | Split the compliance workspace's dialogs out of the page (about 760 of its 3,040 lines), as F1 split its tabs. They share the page's state with several tabs, so each would take its state as props as the tabs do                                                                                                                                                                                                                                                                                                                                                                                                                             | F1, §6                                                             |
| new | Fix the intermittent `AppLayout — reads on mount › shows running-scan and critical badges from the summary` (`src/__tests__/modules/audit/components/layout/AppLayout.test.jsx`): it fails in about one run in three on its own, on code F1 did not touch                                                                                                                                                                                                                                                                                                                                                                                      | F1, §6                                                             |
| new | Make the UX4G harness run on the Node it names. The README says Node 20 or later, but `lib/chrome.mjs` uses the global `WebSocket`, which Node 20 has only behind `--experimental-websocket`; this VM runs Node 20.20, so every capture failed at start until `NODE_OPTIONS=--experimental-websocket` was set                                                                                                                                                                                                                                                                                                                                  | F1, §6                                                             |
| new | Find what changes the header's 25 × 4 px (x 1323–1348, y 18–22) between two harness captures of one build. In the light theme 4 or 5 of the 95 compliance captures differ there by up to 6 levels, so the determinism gate fails on this VM whatever the change; F1 read it with the area recorded                                                                                                                                                                                                                                                                                                                                             | F1, §6                                                             |
| new | Show the credential store's delete note in the compliance workspace's Credentials Manager tab, as Scan Credentials does: since F3 the delete answers how many schedules the credential leaves without one, and the tab still says only "Credential deleted successfully."                                                                                                                                                                                                                                                                                                                                                                      | F3, §6                                                             |
| new | Point the scan setup's "no stored credentials" state at Scan Credentials, the credential store's own page, rather than at Compliance                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | F3, §6                                                             |
| new | D-3 can now be decided on its own: since F3 no screen calls `/compliance/credentials`. Retiring it removes three routes from the API and from the gateway policy; keeping it costs nothing the frontend sees                                                                                                                                                                                                                                                                                                                                                                                                                                   | F3, §6                                                             |

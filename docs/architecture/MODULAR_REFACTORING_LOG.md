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
    `docs/ci/LIVE_SCAN_VALIDATION.md` now describes both.
- **Target MAC addresses are Docker's random ones.** A comparison across a re-creation of the
  targets therefore differs in every asset's MAC. Compare runs against the same running targets.

## 7. Decisions awaiting the project owner

| #   | Decision                                                                                                                                                                                                                                                                  | From                                                               |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| D-4 | Approve the worker privilege split (S3)                                                                                                                                                                                                                                   | [`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md) |
| D-5 | Push every GitLab merge to `github`, or register a GitLab runner                                                                                                                                                                                                          | [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)         |
| D-9 | Commit the September baseline and plan rev 4 under `docs/archive/architecture/`, or not                                                                                                                                                                                   | analysis §13                                                       |
| new | Retire or repurpose `audit.compliance.manage_integrations`, which now gates no route                                                                                                                                                                                      | S2                                                                 |
| new | Rewrite the three NIS2 remediations that pipe into sudo as `sudo sh -c '…'` (seeded catalogue data)                                                                                                                                                                       | S1                                                                 |
| new | Align the compliance workspace's credential buttons (gated on `manage_frameworks`) and the scan pickers' error handling with the credential permissions                                                                                                                   | S2                                                                 |
| new | The schedule page: say why the credential picker is empty when the list answers 403 (a custom role holding `scan_schedule.manage` without `credential.read`), and show "New schedule" only with `scan_schedule.manage`                                                    | S2b, §4                                                            |
| new | Correct the picker route's docstring, the published OpenAPI description, which still says `/compliance/credentials` is gated on `compliance:read`                                                                                                                         | S2b, §4                                                            |
| new | Whether the port and network-check engines poll a `CancelToken`. Today they never do, and the tasks check between phases; polling would make a stop take effect mid-phase, a behaviour change                                                                             | B2, §6                                                             |
| new | B3 half B: move `core.utils`' CVE database client and `lookup_cve` beside their one engine caller. The port and network-check engines would stop loading SQLAlchemy, but the vulnerability database would first be contacted at the first CVE lookup instead of at import | B3, §6                                                             |
| new | Fix the Nuclei probe's starved network templates (a pre-existing false negative). Against the Redis target, the probe's command matched nothing in five runs, while the non-HTTP template types alone matched 10, two of them critical CVEs, in 27 s                      | B3, §6                                                             |
| new | Whether discovery's MAC-vendor lookup (`core.oui_lookup`, which reads `MacVendorCache` through `db.models`) becomes a port passed in, as B2 did for progress and cancellation                                                                                             | B3, §6                                                             |
| new | Make the live comparison tolerate the stopped sweep's timing (compare its outcome, not its frames), and pin the targets' MAC addresses in `targets.sh`                                                                                                                    | B3, §6                                                             |

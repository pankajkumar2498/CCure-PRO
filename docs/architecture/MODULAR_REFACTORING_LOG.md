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

## 7. Decisions awaiting the project owner

| #   | Decision                                                                                                                                                                                                                                                                                                                                                                                         | From                                                               |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------ |
| D-4 | Approve the worker privilege split (S3)                                                                                                                                                                                                                                                                                                                                                          | [`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md) |
| D-5 | Push every GitLab merge to `github`, or register a GitLab runner                                                                                                                                                                                                                                                                                                                                 | [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)         |
| D-9 | Commit the September baseline and plan rev 4 under `docs/archive/architecture/`, or not                                                                                                                                                                                                                                                                                                          | analysis §13                                                       |
| new | Retire or repurpose `audit.compliance.manage_integrations`, which now gates no route                                                                                                                                                                                                                                                                                                             | S2                                                                 |
| new | Rewrite the three NIS2 remediations that pipe into sudo as `sudo sh -c '…'` (seeded catalogue data)                                                                                                                                                                                                                                                                                              | S1                                                                 |
| new | Align the compliance workspace's credential buttons (gated on `manage_frameworks`) and the scan pickers' error handling with the credential permissions                                                                                                                                                                                                                                          | S2                                                                 |
| new | The schedule page: say why the credential picker is empty when the list answers 403 (a custom role holding `scan_schedule.manage` without `credential.read`), and show "New schedule" only with `scan_schedule.manage`                                                                                                                                                                           | S2b, §4                                                            |
| new | Correct the picker route's docstring, the published OpenAPI description, which still says `/compliance/credentials` is gated on `compliance:read`                                                                                                                                                                                                                                                | S2b, §4                                                            |
| new | Whether the port and network-check engines poll a `CancelToken`. Today they never do, and the tasks check between phases; polling would make a stop take effect mid-phase, a behaviour change                                                                                                                                                                                                    | B2, §6                                                             |
| new | B3 half B: move `core.utils`' CVE database client and `lookup_cve` beside their one engine caller. The port and network-check engines would stop loading SQLAlchemy, but the vulnerability database would first be contacted at the first CVE lookup instead of at import                                                                                                                        | B3, §6                                                             |
| new | Fix the Nuclei probe's starved network templates (a pre-existing false negative). Against the Redis target, the probe's command matched nothing in five runs, while the non-HTTP template types alone matched 10, two of them critical CVEs, in 27 s                                                                                                                                             | B3, §6                                                             |
| new | Whether discovery's MAC-vendor lookup (`core.oui_lookup`, which reads `MacVendorCache` through `db.models`) becomes a port passed in, as B2 did for progress and cancellation                                                                                                                                                                                                                    | B3, §6                                                             |
| new | Whether the topology engine's asset reads and writes move behind a port. After B6 the engine loads 32 first-party modules, 28 of them the model registry, which it imports for `Asset` and `Scan`; the plan's "~15" needs that access out of the engine                                                                                                                                          | B6, §6                                                             |
| new | Take the renderers out of the remaining 4-capability cycle: `ccure_platform.audit_log.export` lazily imports `reporting.report_helpers`, the only edge into the renderers from the cycle. The analysis's §7.3 assigns it to B8, but B8's step does not name it, so B8 left it                                                                                                                    | B7, §6                                                             |
| new | Correct `scripts/verification/verify_report_integrity.py`'s provenance markers: it expects "How this was detected", which the technical report stopped printing on 22 Aug 2026 (`f30e1df`), so it fails on every tree                                                                                                                                                                            | B7, §6                                                             |
| new | Add the foreign keys the migrations never created on `web_scans` and `web_findings`: `org_id` to `organizations`, `created_by` and `accepted_by` to `users`, as their models declare. Both tables are empty on this installation. Until then a purge leaves `web_findings.accepted_by` naming the removed account, and no test can see the gap, because the test schema is built from the models | B8, §6                                                             |

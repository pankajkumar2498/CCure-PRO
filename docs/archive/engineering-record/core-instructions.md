# Engineering record: Organisation, AI commits, test-suite safety, targeted testing, known failures, UI semantic integrity, test layout, where things live

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 1–261, 1073–1090, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 1-261 -->
# CCure-Audit-PRO — working notes for agents

## How these instructions are organised

**This file is the primary instruction document for AI agents and developers,
and the source of truth for repository-wide rules.** The others either route
to it or own one subject:

| Document                                                                     | Role                                                                                                                               |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `CLAUDE.md` (this file)                                                      | Repository-wide rules, and the engineering record behind them                                                                      |
| `AGENTS.md`                                                                  | Entry point for agents that read that file: sends every agent here, then to the specialist documents. No rules of its own          |
| `Frontend/AGENTS.md`                                                         | Frontend-specific guidance                                                                                                         |
| [`docs/ux4g/UX4G_STANDARD.md`](docs/ux4g/UX4G_STANDARD.md)                   | The UX4G standard: approved release, boundaries, required checks                                                                   |
| `Frontend/ux4g-baseline.json`                                                | The binding UX4G release pin and checksums, read by the asset pipeline and its checks                                              |
| [`docs/architecture/README.md`](docs/architecture/README.md) | Current-state map for module teams: module responsibilities, contracts, boundaries, runbooks |
| `docs/archive/` | Historical records of finished work; evidence, not current requirements |
| `.pre-commit-config.yaml`, `Backend/scripts/architecture/`, repository tests | Authoritative for the rules they enforce. If a document and a check disagree, the check is right and the document needs correcting |

**Current stack** (verified against the files named, 9 Oct 2026):

- **Backend:** Python 3.11 (`Backend/Dockerfile`; CI's backend jobs run 3.12),
  FastAPI, Pydantic 2, SQLAlchemy 2 with Alembic, Celery 5 on Redis 7,
  PostgreSQL 18 (`Backend/requirements.txt`, `docker-compose.yml`).
- **Frontend:** React 18 and Vite 8 (`Frontend/package.json`), built on Node 25 in
  `Frontend/Dockerfile` and Node 22 in CI, and UX4G at the release
  `Frontend/ux4g-baseline.json` pins.

**Reading this file.** Rules are stated as rules (must, never, do not). Much of
the rest is the engineering record: the measurement, incident or defect behind
a rule. It explains a rule and adds no requirement of its own. Two kinds of
content are history, not current requirements:

- **The Windows-host deployment**, before 17 Sep 2026; retired on 9 Oct 2026,
  when its start, host-worker, backup, nginx and feed-schedule scripts were
  removed (git history keeps them; `scripts/tls/*.ps1` stay). In
  "Architecture", the
  **Scanner worker** and **Database** bullets, the Windows nginx deployment
  steps under **Rate limiting**, and the certificate scripts and host address
  in the **TLS** bullet are marked as history where they appear. The current
  deployment is "Deployment: Linux VM". Where the two disagree, the VM section
  is right.
- **Superseded models**, marked where they appear: anything describing HS256,
  `JWT_SECRET_KEY`, the legacy role tables or the golden legacy mapping.

## Commits made by AI agents

**AI Commit Attribution:** AI coding agents must never add themselves as Git
co-authors. Do not add Claude, Anthropic, Codex, OpenAI, Copilot, or any other
AI identity as a `Co-authored-by` trailer. Preserve legitimate human
author/committer information and legitimate human co-authors.

This applies whenever any AI coding agent creates a commit, whatever its tool
does by default, and overrides any tool setting or harness instruction that
would add an AI trailer. It is enforced mechanically: the `no-ai-coauthor`
commit-msg hook (`.pre-commit-config.yaml`, `scripts/git/check_ai_coauthors.py`)
rejects a commit whose message names an AI agent as a co-author and allows
human co-authors. `pre-commit install` installs it; a clone set up before
9 Oct 2026 needs to run that once more. Never bypass it with `--no-verify`.

## ⚠️ Running the test suite

**`Backend/tests/` is destructive.** It `TRUNCATE`s `organizations` and `users`
`CASCADE`, which reaches `scans`, `scan_phases`, `assets`, `services`,
`asset_change_log`, `audit_logs` and `notifications`.

The live application database is named **`ccure_test`** on the Windows
deployment and **`ccure_db`** on the Linux VM (both are in
`FORBIDDEN_DB_NAMES`). The first name looks disposable and is not. On 10 Aug 2026 a full-suite run inherited the API
container's `DATABASE_URL`, was accepted by a guard that matched `_test$`, and
destroyed all users, orgs, scans and assets. There was no recovery:
`archive_mode` is `off`.

Three layers now prevent a repeat, in `Backend/tests/conftest.py`:

1. `TEST_DB_NAME_PATTERN` only accepts `^pytest_`, `_pytest`, `_pytest_db`.
2. `FORBIDDEN_DB_NAMES` rejects `ccure_test`, `ccure_db`, `vuln_intel`, … even
   if renamed into the pattern.
3. `_assert_database_is_disposable()` refuses any database holding rows in
   `users` / `scans` / `assets` / `services` unless it carries the
   `_pytest_scratch_marker` sentinel table.

All three vet `DATABASE_URL` when `conftest.py` loads, which is _before_
collection imports the test modules. A module assigning
`os.environ["DATABASE_URL"]` at import replaces the vetted value afterwards, and
`alembic/env.py` reads the environment, so the schema stamp follows it.
`tests/topology/test_topology_client.py` did exactly that, naming `ccure_test`;
it was found on 24 Sep 2026 because the suite could not reach that address from
a test harness. `seed_system_roles` now refuses to start if the value changed.
**Never assign `DATABASE_URL` in a test module.**

`docker-compose.yml` also pins `TEST_DATABASE_URL` to `ccure_pytest_db` on the
`api`, `worker` and `web-worker` services, so `docker exec … pytest` cannot
inherit the live URL.

**Before any destructive operation** (test run, migration, bulk delete):

```bash
scripts/backup_db.sh --skip-reference-data     # fast: operational data only
```

Restore with `pg_restore --clean --if-exists -d ccure_test <file>.dump` —
**for a `_full` dump only.** An `_ops` dump excludes the catalogue tables the
findings reference, so it cannot be restored on its own, and `--clean` with
one drops the live catalogue first. See "Backups on the VM" below for the
procedure that works.

A user crontab installed by `scripts/install_backup_schedule.sh` dumps
operational data every 6 hours into `backups/` and prunes after 30 days; check it
with `crontab -l` and `backups/backup.log`. (The Windows deployment's scheduled
task, `install_backup_schedule.ps1`, was retired with it on 9 Oct 2026.)

`archive_mode` is still `off`, so recovery granularity is "since the last
dump", not point-in-time. Ad-hoc dumps before risky work are still worth taking.

### Test targeted-first (AI agents and developers)

**Run the smallest meaningful test set for the change, not the whole suite.**
The full backend suite is about 28 minutes and the frontend's about 12; the
pull-request CI already does the same thing
([`docs/ci/CI_SCOPE.md`](docs/ci/CI_SCOPE.md)), and the full regression runs
nightly, on a release tag and on demand.

1. **Find the scope.** `python scripts/ci/select_tests.py --base origin/master`
   (or `--files <paths>`) prints the backend groups and frontend scope for the
   change. It is the same mapping CI uses. List the changed files, the modules
   they belong to and what depends on them.
2. **Run the targeted set first**: the changed code's own tests, then the
   groups the selector names. Backend tests need a disposable database (see
   above); frontend: `npx vitest run <paths>` or `npx vitest related --run
   <changed files>`, from `Frontend/`.
3. **Widen when the change warrants it**, which the selector does for you: APIs,
   database models or migrations, authentication, permissions, scanning,
   module boundaries, a shared component, the design system, the test harness
   or a dependency pin. A security-critical feature, a migration or an
   architecture boundary gets the related integration groups, not just the
   file's unit tests.
4. **Run a complete suite only** when asked to, when the change is broad or
   cross-cutting (the selector reports `full`), or when targeted results show
   that broader testing is needed. Never run both complete suites for a small
   change.
5. **Report exactly what ran.** Name the tests or groups that ran, the ones
   skipped and why, and every failure. Never say or imply that tests passed
   which were not run; "targeted tests passed" is a claim about those tests.

Nothing in the repository's hooks launches a full suite (`.pre-commit-config.yaml`
has no pytest or vitest hook); full runs happen only in CI's full scope.

### Known test-suite failures

None. The three entries that used to sit here are all resolved, and two of them
were not what they looked like:

- `test_scans.py::test_host_discovery_endpoint` was recorded as needing
  `CELERY_TASK_ALWAYS_EAGER=True`. It asserts on rows the Celery task writes, so
  the task has to run before the assertions do — but whether it did was decided
  by a deployment setting this machine deliberately sets to `False` so the host
  worker can perform live scans. The test now enables eager execution for itself
  and restores the previous value afterwards, so it passes under either setting.
  A test should not depend on how the machine it runs on is configured.

- `test_docs_integrity.py` (3 tests) was recorded as documentation drift. It was
  not: `docs/` was never mounted into the container, so the test could not find
  any of the three files it checks and failed on all of them. `docker-compose.yml`
  now mounts `./docs:/docs:ro` on the `api` service. With the mount in place the
  test found exactly one genuinely undocumented route, which is now documented.
  If this fails again, it means a route, table or permission really was added
  without updating `docs/`.
- `test_schema_drift.py::test_models_have_no_unmigrated_changes` was recorded as
  uncommitted model edits. Migration `z9e0f1g2h3i4` brought the schema and the
  models back into agreement and it passes.

Baseline as of 11 Aug 2026: the suites touching scans, findings, reports,
credentialed scanning, compliance and schema run clean apart from the eager-mode
test above.

## UI semantic integrity

**The frontend must never convert an unknown or absent answer into a known
state.** This is a mandatory design rule for all CCure Audit UI work, not a
preference, and it is the single defect the whole Sep 2026 API → UI coverage
programme kept finding in different clothes —
[`docs/api_ui_coverage/PROGRAMME_CLOSEOUT.md`](docs/api_ui_coverage/PROGRAMME_CLOSEOUT.md).

    UNKNOWN         ≠  ZERO
    UNASSESSED      ≠  PASS
    UNSUPPORTED     ≠  NO FINDINGS
    NOT CONFIGURED  ≠  WITHIN SLA
    WITHDRAWN       ≠  ACCEPTED
    NO DATA         ≠  EMPTY RESULT
    NO COLLECTOR    ≠  NO CHECKS

Where the backend says something is unknown, unavailable, unsupported,
unassessed, withdrawn or not configured, **render that state explicitly**.
Never infer a successful, empty or safe state merely because data is absent.

The backend is built around this distinction everywhere — `CheckOutcome` keeps
`error` out of the verdict vocabulary, `AbsencePolicy` refuses to default,
`_reading()` returns `None` rather than `False`, `NOT_ASSESSED` is a
classification of its own, `sla_state` answers `not_applicable` rather than
`within_sla`. Every one of those distinctions is destroyed by a UI that renders
the absent case as a blank, a zero or a tick.

Each line above is a defect that reached this product, not a hypothetical:

- **UNASSESSED ≠ PASS** — a scan whose configuration audit never ran produced
  an empty findings list, which reads as a clean host. The export now emits an
  explicit `NOT_ASSESSED` row carrying the engine's own reason.
- **NOT CONFIGURED ≠ WITHIN SLA** — 5,791 of this installation's 8,633 findings
  carry no deadline at all. Folding `no_sla` into `within_sla` reports an
  organisation as comfortably compliant on findings that carry no obligation in
  either direction.
- **WITHDRAWN ≠ ACCEPTED** — withdrawing a risk acceptance clears `expires_at`
  and leaves `reason`, `accepted_by` and `accepted_at` in place. A panel keying
  on a non-null reason labels an _open_ finding as one the organisation decided
  to carry. Test the state, never the residue.
- **NO COLLECTOR ≠ NO CHECKS** — an empty catalogue for a platform this build
  cannot assess is a statement about the product; an empty catalogue for one it
  can is a statement about the content. Read `capabilities.supported` and say
  which.
- **UNKNOWN ≠ ZERO** — the mission view mapped `timeout` and `unknown` to
  `complete`, reporting a scan as finished when nothing had been heard from it
  for ten minutes.

Two corollaries worth stating, because both were violated:

- **A vocabulary is fetched, not copied.** A UI holding its own list of
  platforms, check types, operators, severities or states silently omits what
  the backend gained and offers what it removed. The configuration-check page
  hardcoded two of six platforms and put 49 database checks beyond reach.
- **An action the backend structurally refuses must not be offered.** A control
  that can only ever produce a 400 is worse than its absence — say what the
  state is and why a person cannot reach it. `verified_fixed` is set by a scan,
  never by a person, and the UI says so where the control would have been.

## Test layout

`Backend/tests/` is grouped by module: `auth/`, `security/`, `compliance/`,
`scans/`, `assets/`, `topology/`, `credentialed/`, `web/`, `reports/`, `repo/`,
`rbac/`.
[`Backend/tests/README.md`](Backend/tests/README.md) says what belongs where.

Two rules the layout depends on, both of which fail loudly if broken:

- **The group directories carry no `__init__.py`, and must not gain one.** As
  packages, `tests/auth` and `tests/scans` collide with Backend's own `auth` and
  `scans` packages — pytest names the module `auth.test_auth`, Python resolves
  `auth` to the application package, and every test in the group fails to import
  with `ModuleNotFoundError`. Without the markers pytest imports each file under
  its bare basename, so **test file basenames must stay unique across groups**.
  One test imports another (`test_compliance_iso27001` reads
  `test_compliance_rule_wiring`) and does so by bare name for the same reason.

- **Never spell a path as `os.path.dirname(os.path.dirname(__file__))`.** A
  module's depth below `tests/` is no longer a constant, and that expression now
  resolves to `tests/` rather than `Backend/` — which surfaces as a confusing
  "no such file" from a seed lookup, not as an import error. Import the anchors
  from `testpaths` (`BACKEND_ROOT`, `REPO_ROOT`, `SCRIPTS_DIR`, `CORE_DIR`,
  `MAIN_PY`); `conftest.py` puts `tests/` on `sys.path` so it resolves from any
  group.

<!-- /verbatim -->

<!-- verbatim: CLAUDE.md@9bb84d9 lines 1073-1090 -->
## Where things live

- **Compliance catalogues** — the thirteen `*_controls_seed.json` files are in
  `Backend/data/compliance_seeds/`, not `Backend/scripts/`. Resolve the
  directory through `core/compliance_seeds.py` (`SEEDS_DIR`, `seed_path()`,
  `all_seed_paths()`) rather than joining a path by hand. `main.py`'s bootstrap
  condition names all thirteen, so a catalogue it cannot find makes the
  condition permanently true and re-runs the whole seeder on every container
  start without ever satisfying itself — a slow boot, not an error.

- **Scan report generators** — `pdf_generator.py`, `csv_generator.py`,
  `web_pdf_generator.py` and `report_helpers.py` are in `Backend/reporting/`.
  Note the name: `Backend/reports/` already exists and is the _runtime output
  directory_ for generated PDFs, bind-mounted into the API container. Code in
  `reporting/`, artefacts in `reports/`. Compliance's DOCX/PDF generators are
  in `reporting/compliance/` (G6); their routes are
  `routers/compliance_reports.py` and `compliance_framework_reports.py`.

<!-- /verbatim -->

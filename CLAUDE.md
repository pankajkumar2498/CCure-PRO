# CCure-Audit-PRO — working notes for agents

## How these instructions are organised

**This file is the primary instruction document for AI agents and developers,
and the source of truth for repository-wide rules.** It holds only what applies
in every session. The rest has one home each:

| Document                                                                     | Role                                                                                                                               |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `CLAUDE.md` (this file)                                                      | Repository-wide rules, the invariants every module keeps, and the map to everything else                                           |
| `AGENTS.md`                                                                  | Entry point for every agent: sends it here, then routes it to the module rules, skills and specialist documents. No rules of its own |
| `.claude/rules/*.md`                                                         | Module rules, one copy each. Claude Code loads one when it reads or edits a file matching its `paths`; `AGENTS.md` routes every other agent to it |
| `.claude/skills/*/SKILL.md`                                                  | Task procedures (release, backup and restore), loaded when invoked or relevant                                                     |
| `Frontend/AGENTS.md`                                                         | The frontend standard and the frontend module rules, for every agent (Claude Code reads it through `Frontend/CLAUDE.md`)            |
| [`docs/ux4g/UX4G_STANDARD.md`](docs/ux4g/UX4G_STANDARD.md)                   | The UX4G standard: approved release, boundaries, required checks                                                                   |
| `Frontend/ux4g-baseline.json`                                                | The binding UX4G release pin and checksums, read by the asset pipeline and its checks                                              |
| [`docs/architecture/README.md`](docs/architecture/README.md)                 | Current-state map for module teams: module responsibilities, contracts, boundaries, runbooks                                       |
| `docs/archive/`                                                              | Historical records of finished work; evidence, not current requirements. `engineering-record/` is this file, verbatim, before the 30 Oct 2026 split |
| `.pre-commit-config.yaml`, `Backend/scripts/architecture/`, repository tests | Authoritative for the rules they enforce. If a document and a check disagree, the check is right and the document needs correcting |

**Current stack** (verified against the files named, 9 Oct 2026):

- **Backend:** Python 3.11 (`Backend/Dockerfile`; CI's backend jobs run 3.12),
  FastAPI, Pydantic 2, SQLAlchemy 2 with Alembic, Celery 5 on Redis 7,
  PostgreSQL 18 (`Backend/requirements.txt`, `docker-compose.yml`).
- **Frontend:** React 18 and Vite 8 (`Frontend/package.json`), built on Node 25 in
  `Frontend/Dockerfile` and Node 22 in CI, and UX4G at the release
  `Frontend/ux4g-baseline.json` pins.

**Reading these instructions.** Rules are stated as rules (must, never, do
not). Much of a module rule file is the engineering record behind its rules:
the measurement, incident or defect each one answers. It explains a rule and
adds no requirement of its own. **Before changing code in an area, read its
rule file** (the map at the end of this file); Claude Code loads it for you
when you read or edit a matching file, but not when you only search. Two kinds
of content in the rule files are history, not current requirements:

- **The Windows-host deployment**, before 17 Sep 2026; retired on 9 Oct 2026,
  when its start, host-worker, backup, nginx and feed-schedule scripts were
  removed (git history keeps them; `scripts/tls/*.ps1` stay; the VM's own
  backup and feed schedules are `scripts/install_backup_schedule.sh` and
  `scripts/install_feed_schedule.sh`). The Windows nginx
  deployment steps under **Rate limiting** and the certificate scripts and host
  address in the **TLS** bullet are marked as history where they appear; the
  Windows scanner-worker and database bullets are in the engineering record
  only. The current deployment is `.claude/rules/deployment.md`. Where the two
  disagree, the VM text is right.
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

## Strict token-efficiency policy

These instructions apply to every development, debugging, refactoring and
implementation task.

### 1. Minimise investigation

- Never reanalyse the entire codebase unless explicitly required.
- Inspect only files directly related to the task.
- Reuse previous findings, architecture documents and Git history.
- Do not reread unchanged files unnecessarily.
- Do not investigate unrelated modules.

### 2. Minimise planning

- Avoid lengthy plans for small changes.
- Do not explain obvious implementation details.
- Identify the exact problem and proceed with the smallest safe solution.
- Ask questions only when a genuine blocker or ambiguity exists.

### 3. Minimise code changes

- Modify only necessary files.
- Prefer incremental changes over module rewrites.
- Avoid unrelated cleanup, refactoring and formatting.
- Preserve existing working functionality.
- Never duplicate existing implementations.

### 4. Minimise testing costs

"Test targeted-first" below is the procedure; these are its principles.

- Run targeted tests first.
- Expand testing only when the change requires it.
- Do not repeatedly execute previously passing tests without justification.
- Run the full suite at appropriate integration or release checkpoints.
- Reuse existing test results only when the relevant code and environment
  remain unchanged.

### 5. Prevent repeated work

- Check Git history and existing implementation before starting.
- Never repeat completed phases.
- Do not recreate existing documentation.
- Update only affected documentation.
- Track completed work and outstanding blockers.

### 6. Concise communication

- Report only essential findings.
- List changed files and reasons.
- Summarise test results.
- Mention genuine risks and blockers.
- Avoid lengthy explanations unless requested.

### 7. Mandatory execution strategy

For every task:

1. Understand the requirement.
2. Inspect the minimum necessary code.
3. Identify the exact change.
4. Implement the smallest safe solution.
5. Run targeted verification.
6. Report the outcome concisely.

**Core rule: spend tokens on solving problems, not repeatedly understanding
problems that have already been solved.**

Do not sacrifice correctness, security, architectural boundaries or regression
prevention merely to reduce token consumption.

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

None recorded in the backend suite. The three entries that used to sit here are
resolved; what each turned out to be is in
`docs/archive/engineering-record/core-instructions.md`.

One frontend test is recorded as intermittent and not yet fixed:
`AppLayout — reads on mount › shows running-scan and critical badges from the
summary` (`Frontend/src/__tests__/modules/audit/components/layout/AppLayout.test.jsx`)
fails about one run in three on its own, on code nothing recent touched
(`docs/architecture/MODULAR_REFACTORING_LOG.md`, F1 and its follow-up list).

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

## Repository-wide invariants

Rules no module may break, for an agent that has not opened that module's rule
file yet. Each line is a summary: **the file named in brackets is
authoritative** and holds the detail and the reasons. Changing one of these
rules means changing that file and this line together.

**Architecture and module boundaries**

- The layering, import-cycle, table-ownership and identity ratchets fail CI on
  any new violation. `KNOWN_VIOLATIONS` and `KNOWN_CYCLES` are empty: never add
  an entry to make a build pass; move the shared code down a layer instead.
  Imports inside functions count as dependencies. [architecture-boundaries]
- `python3 Backend/scripts/architecture/check.py` runs the stdlib ratchets (the
  `architecture-guards` hook); `scripts/ci/local_guard_tests.sh` runs the
  database-backed guard tests in throwaway containers. GitLab runs no
  pipeline; GitHub Actions tests only what is pushed to `github`.
  [architecture-boundaries]
- A new table needs an entry in `Backend/scripts/architecture/table_ownership.yaml`
  in the same change. [architecture-boundaries]
- Code that starts a scan task dispatches it by name (`core/task_names.py`,
  `core.celery_app.registered_task`); nothing outside `scans/tasks/` imports a
  task module, and a new scan task declares its own time limits. `core/tasks.py`
  is gone (2 Nov 2026): import a name from the module that owns it.
  `routers/compliance.py` refuses a patch: patch the module whose code reads
  the name. [architecture-boundaries, scan-lifecycle]
- Only `core/credential_vault.py` touches `compliance_credentials`; only
  `core/findings/writer.py` writes the findings tables; the findings side never
  imports the asset registry; a new evidence source needs its provider
  registered in the same change. [architecture-boundaries]
- `ccure_platform` is shared, never Audit's: it imports no Audit code or model.
  Module code reaches identity, RBAC and organisation settings only through
  `ccure_platform.api`. Moved modules keep their legacy `__name__`; do not
  "fix" it in passing. [identity-platform]
- A module imports only itself, `ccure_platform.api`, `ccure_contracts` and
  `db.base`, and nothing imports a module. Nothing in production imports
  `ccure_contracts` or the integration adapter yet. [modules-contracts]
- Alembic has three heads: always `upgrade heads` / `stamp heads`. A change to
  `alembic.ini` needs `docker compose restart api`. No migration creates a
  database role or grants to one. `.github/CODEOWNERS` handles are placeholders;
  never invent a real one. [modules-contracts]
- A new route means regenerating the gateway policy and re-dumping
  `docs/architecture/phase10/route_table.json` in the same commit. An
  endpoint's docstring is its OpenAPI description. [modules-contracts,
  identity-platform]
- The frontend follows `docs/ux4g/UX4G_STANDARD.md`; a product never imports
  another product and the shell names none. [Frontend/AGENTS.md]

**Identity, security and secrets**

- Platform RBAC is the only authorization model: `require_authorized(key)` and
  `has_permission(db, account, key)`. Never decide on a role's name or key,
  never add a wildcard, never hand-copy a superadmin check; roles are retired,
  never deleted. [identity-platform]
- Tokens are signed and verified only in `ccure_platform.identity.tokens`
  (ES256 with a `kid`). Never reintroduce HS256, a shared secret or a fallback
  to "roll back" to: a release rolls back with git. [identity-platform]
- Never change `MFA_ENCRYPTION_KEY`. Workers hold no secrets. Containers run
  with `SKIP_DOTENV_LOAD`, so editing `Backend/.env` changes nothing in a
  container; host-side scripts read `Backend/.env` through `config.py`.
  Dotenv backups live outside the tree. [identity-platform, vuln-feeds]
- Login checks account state only after the password verifies; only the
  lockout check precedes it. Do not reorder these. [api-security]
- Every unauthenticated or expensive route needs a recorded rate-limit
  decision; adding `@limiter.limit` means adding `response: Response`.
  `TRUSTED_PROXIES` names reverse proxies, never a user network. [api-security]
- Exactly two endpoints accept a file, both through `core/upload_guard.py`; a
  new one must too. Validate before you destroy; scan, then persist. [uploads]
- Audit-log retention is installed but disabled; no HTTP endpoint deletes an
  audit row; the append-only trigger's two conditions are not relaxed without
  the phase-6b approval. [audit-retention]
- Never put a secret in `compliance_credentials.options` or `scans.options`:
  both are returned to clients. A schedule stores a credential reference, never
  a secret. [findings-remediation, scan-lifecycle]
- The sudo password goes on the remote command's stdin, never in the command.
  There is no elevation mechanism on the Windows path and none may be
  invented. [credentialed]

**Scanning and data integrity**

- A scan must always reach a terminal state: never call `mark_scan_failed`
  directly from an `except` block. [scan-lifecycle]
- `is_verdict` is true for exactly PASS and FAIL, and every roll-up gates on
  it. ERROR is never a verdict, a FAIL with no evidence is refused, and absence
  is not a fix. [checks-network-tls, config-audit, findings-remediation]
- No human action can reach `verified_fixed`; only a scan's comparison does.
  [findings-remediation]
- No CIS Benchmark content ships in this repository or may be committed, and
  no benchmark, STIG or check content is written from memory. [config-audit]
- A non-CVE condition never goes in `cve_id`; mint identifiers with
  `core.checks.definitions.definition_id_for_check`. Timestamps are
  timezone-aware UTC; never a naive `datetime.now()`. [findings-remediation,
  checks-network-tls]

**Database, deployment and production safety** (the test-database rules are
above)

- Since 13 Oct 2026 the VM runs images, not bind-mounted source: a code change
  reaches it only as a release. Never deploy with a plain `docker compose up`;
  follow the `release` skill (backup, idle workers, `compose.sh`, exactly one
  beat). [skills/release, deployment]
- Every dump, verification and restore goes through `docker exec ccure-db`; an
  `_ops` dump cannot be restored on its own; never restore over `ccure_db`
  while it is serving. [skills/db-backup-restore]
- A new compose service carries `logging: *default-logging`. TLS to PostgreSQL
  is off only because the port is bound to `127.0.0.1`; widening it voids that
  decision. Portainer is never on the LAN. [deployment]
- Never edit `/etc/nginx/conf.d/ccure.conf` by hand; switch with
  `scripts/linux/gateway_edge_switch.sh`. Raise HSTS `max-age` only in nginx
  and `main.py` together. [edge-gateway]

## Where things live

- **Compliance catalogues** — the fourteen `*_controls_seed.json` files are in
  `Backend/data/compliance_seeds/`, not `Backend/scripts/`. Resolve the
  directory through `core/compliance_seeds.py` (`SEEDS_DIR`, `seed_path()`,
  `all_seed_paths()`) rather than joining a path by hand. `main.py`'s bootstrap
  condition names all fourteen, so a catalogue it cannot find makes the
  condition permanently true and re-runs the whole seeder on every container
  start without ever satisfying itself — a slow boot, not an error.

- **Scan report generators** — `pdf_generator.py`, `csv_generator.py`,
  `web_pdf_generator.py` and `report_helpers.py` are in `Backend/reporting/`.
  Note the name: `Backend/reports/` already exists and is the _runtime output
  directory_ for generated PDFs, bind-mounted into the API container. Code in
  `reporting/`, artefacts in `reports/`. Compliance's DOCX/PDF generators are
  in `reporting/compliance/` (G6); their routes are
  `routers/compliance_reports.py` and `compliance_framework_reports.py`.

## Instruction map

Where each part of the former single file lives. Code comments and documents
cite sections as `CLAUDE.md, "<name>"`; find the name in the last column.

| File | Loads for | Sections it holds |
| ---- | --------- | ----------------- |
| `CLAUDE.md` | every session | "Commits made by AI agents", "⚠️ Running the test suite", "Test targeted-first (AI agents and developers)", "UI semantic integrity", "Where things live" |
| [`.claude/rules/backend-tests.md`](.claude/rules/backend-tests.md) | `Backend/tests/**`, `Backend/pytest.ini` | "Test layout" |
| [`.claude/rules/architecture-boundaries.md`](.claude/rules/architecture-boundaries.md) | `Backend/**`, `scripts/ci/**` and 1 more | "Architecture guardrails (modular-platform programme)" |
| [`.claude/rules/identity-platform.md`](.claude/rules/identity-platform.md) | `Backend/ccure_platform/**`, `Backend/auth/**` and 11 more | "RBAC capability (`ccure_platform/rbac/`) — **the only authorization model since RBAC-8**", "Backend platform extraction (backend alignment, steps 1–2)" |
| [`.claude/rules/modules-contracts.md`](.claude/rules/modules-contracts.md) | `Backend/ccure_audit/**`, `Backend/ccure_policy/**` and 12 more | "Audit boundary layers (`Backend/ccure_audit/`) — Phase 5", "Core modules: Policy Pro, Audit, Rank (Phase 11)", "Integration contracts (`Backend/ccure_contracts/`) — Phase 4, draft" |
| [`.claude/rules/deployment.md`](.claude/rules/deployment.md) | `docker-compose*.yml`, `Backend/Dockerfile` and 13 more | "Deployment: Linux VM (`ccurepro`, 10.180.22.127) — since 17 Sep 2026", "Architecture" |
| [`.claude/rules/api-security.md`](.claude/rules/api-security.md) | `Backend/routers/**`, `Backend/main.py` and 13 more | (part of a section) |
| [`.claude/rules/edge-gateway.md`](.claude/rules/edge-gateway.md) | `gateway/**`, `scripts/host-nginx/**` and 9 more | (part of a section) |
| [`.claude/rules/scan-lifecycle.md`](.claude/rules/scan-lifecycle.md) | `Backend/scans/**`, `Backend/orchestrator/**` and 14 more | "A scan must always reach a terminal state", "Scan pipeline", "Scan scheduling (`core/scheduling/`)" |
| [`.claude/rules/credentialed.md`](.claude/rules/credentialed.md) | `Backend/engines/credentialed/**`, `Backend/core/credential_vault.py` and 8 more | "Windows credentialed collection (`engines/credentialed/winrm_executor.py`)", "Windows over SMB / Remote Registry / WMI (`engines/credentialed/smb_executor.py`)", "Credential authentication methods", "Credentialed transport and port resolution (`engines/credentialed/transport_resolver.py`)", "Elevation on the credentialed path", "Windows assessment" |
| [`.claude/rules/config-audit.md`](.claude/rules/config-audit.md) | `Backend/core/config_audit/**`, `Backend/core/benchmarks/**` and 5 more | "Configuration audit engine (`core/config_audit/`)", "Benchmark content (`core/benchmarks/`)", "Local privilege checks (`core/config_audit/collectors/privilege_*.py`)" |
| [`.claude/rules/middleware-containers.md`](.claude/rules/middleware-containers.md) | `Backend/core/config_audit/structured.py`, `Backend/core/config_audit/containers.py` and 6 more | "Middleware configuration assessment (`core/config_audit/structured.py`)", "Five things real containers settled, each of which had shipped looking right", "Content", "Test targets", "Coverage", "Container and Kubernetes assessment (`core/config_audit/containers.py`)", "Three things real targets settled", "Content", "Test targets", "Coverage" |
| [`.claude/rules/scap.md`](.claude/rules/scap.md) | `Backend/core/scap/**`, `Backend/core/config_audit/collectors/scap.py` and 3 more | "STIG and SCAP content (`core/scap/`)", "Applicability is not optional, and the measurement says so", "Six defects real content found, and one a warning found", "Validation", "Coverage", "The Windows OVAL schema (Phase 15)", "Reporting is part of done" |
| [`.claude/rules/scan-policy.md`](.claude/rules/scan-policy.md) | `Backend/core/scan_policy/**`, `Backend/routers/scan_policies.py` and 2 more | "Scan policy (`core/scan_policy/`)" |
| [`.claude/rules/findings-remediation.md`](.claude/rules/findings-remediation.md) | `Backend/core/findings/**`, `Backend/core/remediation/**` and 6 more | "Remediation and SLA (`core/remediation/`)", "Scan comparison and finding lifecycle (`core/findings/`)", "Data model notes" |
| [`.claude/rules/reporting.md`](.claude/rules/reporting.md) | `Backend/reporting/**`, `Backend/routers/reports.py` and 1 more | "Exports (`reporting/exports.py`, `reporting/xlsx_generator.py`)", "Reports" |
| [`.claude/rules/checks-network-tls.md`](.claude/rules/checks-network-tls.md) | `Backend/core/checks/**`, `Backend/engines/vulnerability/**` and 4 more | "Assessment framework (`core/checks/`)", "Network checks (`engines/vulnerability/network_checks.py`)", "Deep TLS on the network path", "Active template verification (Nuclei)", "Test targets", "Coverage figures" |
| [`.claude/rules/vuln-feeds.md`](.claude/rules/vuln-feeds.md) | `Backend/scripts/vuln/**`, `Backend/core/vuln_intel.py` and 7 more | "Vulnerability feeds (`vuln_intel`)" |
| [`.claude/rules/database-assessment.md`](.claude/rules/database-assessment.md) | `Backend/engines/credentialed/database_executor.py`, `Backend/core/config_audit/collectors/database.py` and 2 more | "Database assessment (`engines/credentialed/database_executor.py`)", "Content, and the false positives real targets caught", "Test targets", "Coverage" |
| [`.claude/rules/compliance.md`](.claude/rules/compliance.md) | `Backend/core/compliance*.py`, `Backend/core/compliance_catalogue/**` and 12 more | "Policy Compliance Engine", "ISO/IEC 27001:2022", "Which frameworks are switched on", "NIST CSF 2.0" |
| [`.claude/rules/uploads.md`](.claude/rules/uploads.md) | `Backend/core/upload_guard.py`, `Backend/routers/compliance_attestation.py` and 2 more | "File uploads" |
| [`.claude/rules/audit-retention.md`](.claude/rules/audit-retention.md) | `Backend/ccure_platform/audit_log/**`, `Backend/core/audit_retention.py` and 2 more | "Audit-log retention (phase 6a)" |
| [`.claude/skills/release/SKILL.md`](.claude/skills/release/SKILL.md) | `/release`, or when relevant | "Releases (since 13 Oct 2026)" |
| [`.claude/skills/db-backup-restore/SKILL.md`](.claude/skills/db-backup-restore/SKILL.md) | `/db-backup-restore`, or when relevant | "Backups on the VM" |
| [`Frontend/AGENTS.md`](Frontend/AGENTS.md) | any file under `Frontend/` | "Frontend modules (Phase 12)" |
| [`docs/archive/engineering-record/`](docs/archive/engineering-record/README.md) | never (read on demand) | All of the above as it stood at `9bb84d9`, plus what lives only there: "How these instructions are organised" (old), "Known test-suite failures" (resolved entries), the 13–14 Oct release changes and live verification, the Windows scanner-worker and database bullets |

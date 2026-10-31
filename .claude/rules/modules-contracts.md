---
paths:
  - "Backend/ccure_audit/**"
  - "Backend/ccure_policy/**"
  - "Backend/ccure_rank/**"
  - "Backend/ccure_contracts/**"
  - "Backend/ccure_platform/modules/**"
  - "Backend/ccure_platform/hub/**"
  - "Backend/alembic/**"
  - "Backend/alembic.ini"
  - "Backend/scripts/db/**"
  - "Backend/scripts/contracts/**"
  - "Backend/scripts/integration/**"
  - "Backend/tests/modules/**"
  - "scripts/db/**"
  - ".github/CODEOWNERS"
---

# Audit boundary layers, core modules and integration contracts

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 621–714, 1034–1072) and is maintained here. Frozen original: `docs/archive/engineering-record/modules-and-contracts.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Audit boundary layers (`Backend/ccure_audit/`) — Phase 5

Design: [`docs/architecture/PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md`](docs/architecture/PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md).
`ccure_audit/services/` answers questions about Audit's data and returns
**views**; `ccure_audit/integration/` turns views into contract messages. The
existing `core/`, `engines/`, `scans/` and `reporting/` code is used, not moved.

- **A view is declared with `@view`** (frozen, slotted, keyword-only
  dataclass) and holds only plain values — no ORM object, no list or dict, no
  naive datetime. `impurities()` checks one; service tests run it over
  everything a service returns.
- **`integration-is-an-adapter`**: the adapter imports `ccure_contracts` and
  `ccure_audit.services` only. **`services-do-not-speak-contracts`**: services
  never import a contract type. **`foundations-do-not-import-audit-module`**:
  `core`, `engines`, `scans`, `orchestrator`, `db` and `auth` never import
  `ccure_audit`. `reporting → ccure_audit.services` is allowed on purpose — the
  transition while the export's read logic moves into the services.
- **Nothing in production imports the adapter** until the integration phase;
  `test_nothing_in_production_imports_the_integration_adapter_yet` enforces it.
  Only the adapter may import `ccure_contracts`.

## Core modules: Policy Pro, Audit, Rank (Phase 11)

The core service holds three modules. Record and decisions:
[`docs/architecture/PHASE11_MODULE_FOLDERS.md`](docs/architecture/PHASE11_MODULE_FOLDERS.md);
each module's `README.md` is the guide its team works from.

| Module                    | Package                 | Key / schema       | Routes                            | State                                                                 |
| ------------------------- | ----------------------- | ------------------ | --------------------------------- | --------------------------------------------------------------------- |
| Ccure Policy (Policy Pro) | `Backend/ccure_policy/` | `policy_pro`       | `/policy`                         | empty, disabled                                                       |
| Ccure Audit               | `Backend/ccure_audit/`  | `audit` / `public` | unprefixed (predate the registry) | the product; most code still in `core/`, `engines/`, … until Phase 16 |
| Ccure Rank                | `Backend/ccure_rank/`   | `rank`             | `/rank`                           | empty, disabled                                                       |

- **The registry is `ccure_platform/modules/`**, a stdlib-only leaf read by
  `main.py` and `core/celery_app.py`. The platform owns each module's identity
  (key, package, schema, route and task prefix, enabled) in `_IDENTITIES`; the
  module owns what it contributes — `routers`, `task_modules`, `models` — in its
  own `manifest.toml`. Turning a module on is a platform change. **Audit's
  manifest is deliberately empty**: `main.py` still mounts its routers, and
  declaring them there too would mount each twice.
- **Policy Pro and Rank ship no routes, tables or tasks.** Nothing may be added
  to them outside their teams' own work; 93 rate-limited routes, 21 tasks at
  import and 11 beat entries are the regression gate for any change here. The
  application has **284 API routes** (`docs/architecture/phase10/route_table.json`,
  last regenerated 12 Oct 2026, `d8a6294`; it held 282 on 3 Oct and 285 on
  11 Oct, and `tests/repo/test_gateway_route_policy.py` pins the gateway
  policy's total at 284); `len(app.routes)` was 286 in this development
  installation on 7 Oct 2026, not re-measured since, which
  also serves FastAPI's four documentation routes. It was 274 after Phase 12.1
  added the platform's own `GET /platform/modules`, 273 through Phase 11.
- **CCure Home's product list comes from the registry** (Phase 12,
  [`docs/architecture/PHASE12_FRONTEND_SHELL.md`](docs/architecture/PHASE12_FRONTEND_SHELL.md)).
  Each module's identity carries a `description` and an `entry_path`; CCure IR
  is a `ServiceProduct` — listed, never a module. `GET /platform/modules`
  (`ccure_platform/hub/`) returns all four products to any signed-in user,
  filtered by nothing. A new route means regenerating the gateway policy
  (`--emit` in the api container, written on the host) and re-dumping
  `docs/architecture/phase10/route_table.json` in the same commit.
- **Boundaries, all enforced in CI:** `module-isolation:<pkg>` (a module
  imports only itself, `ccure_platform.api`, `ccure_contracts` and `db.base`)
  and `module-is-private:<pkg>` (nothing imports a module; it is mounted from
  its manifest's dotted names); `scripts/architecture/module_boundaries.py`
  checks that a module's tables are in its schema and registered to it, that no
  module's SQL names another's table, that module tests live in
  `tests/modules/<key>/`, and that `CODEOWNERS` has a line per module. The
  test-only `tests/modules/example/fixture/ccure_example` proves a route, table,
  migration and task end to end and is never on the production list.
- **The Alembic history has three heads**: Audit's (unlabelled, in
  `alembic/versions/`), `policy_pro` and `rank` (each in
  `<package>/migrations/`, base revision `<key>_0001`, which creates only the
  empty schema). Live since 30 Sep 2026; `alembic_version` holds three rows.
  - Always `upgrade heads` / `stamp heads`; `head` fails with several heads.
    Roll back by name: `alembic downgrade <revision-or-branch>@-1`.
  - A fresh install stamps **Audit's** head only, then runs `upgrade heads`, so
    the module branches create their schemas as real migrations.
  - A module migration names `schema=<own>` on every table operation, and no
    SQL in it names another schema or touches roles, grants or owners
    (`migration_problems`).
  - `version_locations` in `alembic.ini` is what makes a branch visible, and is
    written only by `python -m scripts.db.alembic_module_branches --write`.
    **A change to `alembic.ini` needs `docker compose restart api`** — `up -d`
    sees an unchanged service definition, answers `Running` and runs nothing.
  - Every API start runs `alembic upgrade heads`, so a merged migration is
    live at the next restart. `scripts/db/rehearse_module_branches.sh` is the
    restore-and-fingerprint rehearsal to copy for anything non-trivial.
- **No module database roles before Phase 18** (decision D11-1). The `policy_pro`
  and `rank` schemas are owned by `ccure_user`, like `public`. `ccure_user` has
  no `CREATEROLE`, so a migration creating a role or granting to one would stop
  the start-up migrator and with it the API; `migration_problems` refuses them
  and a test pins the ownership. Phase 18 adds roles through a DBA bootstrap,
  never a migration.
- **`.github/CODEOWNERS` owners are placeholders** (`@TODO-project-owner`,
  `@TODO-audit-team`, `@TODO-policy-pro-team`, `@TODO-rank-team`); never invent
  a real handle. Since Phase 12.5 it has a line per frontend module folder too
  (IR's goes to the project owner until an IR team is named). "Require review from Code Owners" stays off until they are
  replaced — `docs/ci/BRANCH_PROTECTION.md`, "Code owners".


## Integration contracts (`Backend/ccure_contracts/`) — Phase 4, draft

What Policy Pro, Audit, Rank and IR exchange. Design and review document:
[`docs/architecture/contracts/PHASE4_INTEGRATION_CONTRACTS.md`](docs/architecture/contracts/PHASE4_INTEGRATION_CONTRACTS.md).
**Nothing in the application uses them yet** — a test fails if anything
imports `ccure_contracts` before the integration adapter is built (plan Phase 14).

- **The Pydantic models are the source; the JSON Schemas are generated.** Never
  hand-edit `*/v1/schemas/*.json`. After changing a model run
  `python -m scripts.contracts.generate_schemas`; on the VM the API container
  cannot write into the bind mount, so render there and write on the host:
  `docker exec -w /app ccure-api python -m scripts.contracts.generate_schemas --bundle | python3 scripts/contracts/write_bundle.py`.
- **Every field is declared with `owned(owner, …)`** and carries
  `x-ccure-owner` / `x-ccure-availability` into the schema. A field Audit
  cannot populate is `not_implemented` and must be optional or a
  `CcureMeasuredValueV1` with a reason — never a required value Audit would have
  to invent. The tests enforce both.
- **`ccure_contracts` imports only the standard library and Pydantic**
  (`contracts-are-leaves`). It must never import an Audit model: contracts do
  not expose SQLAlchemy rows, and translation happens in the adapter.
- **Class names are `Ccure…V1`** — FastAPI names OpenAPI components after the
  class, and a bare `Finding` would replace an existing schema.
- **Policy Pro sends controls and parameters, never executable checks**, and IR
  can never move a finding to `verified_fixed`. Both are refused by the models.
- v1 is `draft` until the first team builds against it (project-owner decision,
  28 Sep 2026; the project owner approves every later version). Once a
  contract is `published` its schema digest
  is pinned in `schema_lock.json` and changes need a new `schema_version`.
- **`scripts/integration/` is operator tooling for Contract 1, outside the
  import graph.** `policypro_library_to_baseline.py` is the reference
  translation of a PolicyPro policy library plus an organisation's SoA answers
  into a `PolicyBaseline`. It never invents applicability: no SoA means a
  refusal unless `--demo-all-applicable`, which labels the output. It refuses a
  HIPAA library: its ids are PolicyPro's own, not the CFR paragraphs
  Audit's HIPAA catalogue uses.
  `baseline_coverage_report.py` answers a baseline with `BaselineCoverage`
  over a **read-only** session. What PolicyPro must export, and why:
  [`docs/architecture/policypro/POLICYPRO_BASELINE_EXPORT_REQUIREMENTS.md`](docs/architecture/policypro/POLICYPRO_BASELINE_EXPORT_REQUIREMENTS.md).

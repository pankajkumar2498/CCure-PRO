# Phase 11 — Module folders in the core (proposal, for review)

|                               |                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**                    | **Approved by the owner, 30 Sep 2026**, with decisions: D11-1 **roles deferred to Phase 18** (no Policy Pro/Rank roles in Phase 11); module identities `policy_pro`, `audit`, `rank`; no Policy Pro or Rank functionality — structure only. Implemented one step per commit with a review stop after each. **11.1 (module registry) committed with this revision.** Written at HEAD `280800f` from measurements of the live tree and database. |
| **Plan**                      | [`CCURE_PLATFORM_MODULAR_ARCHITECTURE.md`](CCURE_PLATFORM_MODULAR_ARCHITECTURE.md) rev 4: Phase 11 (Stage 3), §3.3, §3.7, §4 (module registry), §5 (data ownership), §13 (traps). Owner decisions of 28 Sep 2026: module-first folders; `Backend/` and the `ccure_` names kept.                                                                                                                                                                |
| **Done when (from the plan)** | "Another team can add a route, table, migration and task inside its own folder without editing any file outside it; CI rejects any import across modules."                                                                                                                                                                                                                                                                                     |
| **Out of scope**              | Phase 12 (frontend shell and homepage); moving Audit's code into `ccure_audit/` (Phase 16); per-module database roles for **existing** tables (Phase 18); any Policy Pro or Rank feature (their teams build those); 10.8.                                                                                                                                                                                                                      |

## 1. What Phase 11 delivers

| #   | Deliverable                                                                                                                                            | Plan wording                                                                                                         |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| 1   | `Backend/ccure_policy/` and `Backend/ccure_rank/`, **empty**: `api/ models/ schemas/ services/ repositories/ workers/ migrations/`, plus `manifest.py` | "Empty `ccure_policy/` and `ccure_rank/`, each with api / models / schemas / services / repositories and a manifest" |
| 2   | `ccure_platform/modules/`: the **module registry**, read by `main.py` and `core/celery_app.py`                                                         | "The `ccure_platform` module registry, which `main.py` and `core/celery_app.py` read"                                |
| 3   | The `policy_pro` and `rank` schemas in `ccure_db` (and, per decision **D11-1**, their roles)                                                           | "`policy_pro` and `rank` schemas and roles"                                                                          |
| 4   | **Alembic branches** for Policy Pro and Rank; every `head` → `heads` in the same change, rehearsed on a restored copy                                  | "Alembic branches — `tests/conftest.py` `head` → `heads` in the same change, rehearsed on a restored copy"           |
| 5   | `CODEOWNERS`                                                                                                                                           | "`CODEOWNERS`" (and D6: the Project Owner owns `ccure_platform` and `gateway/` until now)                            |
| 6   | The CI import rule and the table registry extended to the new folders                                                                                  | "The CI import rule and the table registry extended to the new folders"                                              |

**Nothing a user sees changes.** Policy Pro and Rank ship **no routes, no tables and
no tasks** in Phase 11. The OpenAPI document, the 273 routes, the 93 rate-limited
routes, the 21 Celery tasks and the 11 beat entries stay identical, and that is
the phase's main regression gate. The registry is proven by a **test-only** module
(§3.6), never shipped.

## 2. What was measured (30 Sep 2026, HEAD `280800f`)

| Fact                                                                                                                                                                                                                                                        | Consequence for Phase 11                                                                                                                                                                             |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Every API start runs `alembic upgrade head`** (`db/migrate_production_schema.py:511`, from `start.sh`), and `stamp head` on an empty database (line 509). With a second head both fail with "Multiple head revisions" and the script calls `sys.exit(1)`. | **The API would not start.** The plan names only `tests/conftest.py`; the start-up migrator must change to `heads` **in the same commit** as the first branch, or the next API restart is an outage. |
| `tests/conftest.py` `_build_test_schema` stamps and upgrades `"head"` (lines 528, 534).                                                                                                                                                                     | Changes with it, as the plan says.                                                                                                                                                                   |
| **21** scripts and docs say `upgrade head` / `stamp head`.                                                                                                                                                                                                  | Updated in the same change; a runbook that still says `head` fails the operator on the day they need it.                                                                                             |
| 66 migrations, **one** lineage, no `branch_labels`; `alembic.ini` has no `version_locations`.                                                                                                                                                               | The existing history stays untouched and unlabelled; the two new branches are new bases (§3.3).                                                                                                      |
| `alembic/env.py` targets `db.base.Base.metadata` only and does **not** set `include_schemas`.                                                                                                                                                               | Autogenerate would never see a table in `policy_pro` or `rank`. `env.py` gains the module metadata, and a schema filter so it keeps ignoring `audit_chain` / `audit_retention`.                      |
| `migrate_production_schema.py` bootstraps an empty database with `Base.metadata.create_all()`.                                                                                                                                                              | A module table in its own schema would fail there until the schema exists; the bootstrap creates the module schemas first.                                                                           |
| Database `ccure_db` is **owned by `ccure_user`**, the application's login. It has **no `CREATEROLE`**. Existing schemas: `public`, `audit_chain` (owner `audit_chain_writer`), `audit_retention` (owner `audit_maintenance`).                               | A migration running as `ccure_user` **can** `CREATE SCHEMA`. It **cannot** create a role — the same wall the audit-chain bootstrap hit, solved there with a DBA script (§3.4, D11-1).                |
| `core/celery_app.py`: an explicit `include=[…]` of 6 task modules and 7 queues; `beat_schedule` a literal dict. The compose workers subscribe to named queues (`-Q`).                                                                                       | The registry appends each **enabled** module's task modules and queues. A new queue also needs a consumer — see D11-4.                                                                               |
| `main.py` mounts **28** routers explicitly, all Audit or platform.                                                                                                                                                                                          | Unchanged in Phase 11 (moving them is Phase 16). The registry mounts only what a module's manifest declares, under the module's prefix.                                                              |
| `scripts/architecture/table_ownership.yaml` already lists `modules: [platform, audit, policy_pro, rank, ir]`. `layer_rules.py` has 14 rules; `ccure_audit` is protected, the other modules are not named.                                                   | The owners exist; the rules and the schema check are what is added.                                                                                                                                  |
| No `CODEOWNERS` anywhere.                                                                                                                                                                                                                                   | New.                                                                                                                                                                                                 |
| The gateway's route policy is **generated from the live route table** (10.2c) and `tests/repo/test_gateway_route_policy.py` fails on drift. `/api/policy/*` and `/api/rank/*` are unrouted today, so the application answers 404 (X6-a).                    | Phase 11 adds no route, so nothing changes. A team's first route is a route-policy regeneration in the same commit — written into the module README (§3.7).                                          |
| `fingerprint.sh` and the alongside stack read `select version_num from alembic_version` as a single value.                                                                                                                                                  | With three heads the table holds three rows; both are updated to read the set.                                                                                                                       |

## 3. Design

### 3.1 The module folders

```
Backend/ccure_policy/            (and ccure_rank/, identical shape)
  __init__.py
  manifest.py                    the module's declaration (§3.2)
  README.md                      what goes where, and the three rules below
  api/        __init__.py        FastAPI routers — mounted under /policy (gateway: /api/policy)
  models/     __init__.py        SQLAlchemy models; MetaData(schema="policy_pro")
  schemas/    __init__.py        request/response Pydantic models (not contracts)
  services/   __init__.py        application services
  repositories/ __init__.py      data access
  workers/    __init__.py        Celery task modules; task names ccure.policy.*
  migrations/ <base>_create_policy_pro_schema.py   the Alembic branch (§3.3)
```

The layout is §3.4's Audit layout minus `integration/` and `engines/`, which a
team adds when it needs them. Three rules, each enforced by CI (§3.5):

- a module imports only **its own package**, `ccure_platform.api` and `ccure_contracts`;
- its tables live **only in its schema** and are registered to it in `table_ownership.yaml`;
- its task names start `ccure.<module>.` (§13 of the plan: task names are strings in the broker).

### 3.2 The module registry — `ccure_platform/modules/`

A **manifest** is a frozen dataclass each module exports from `manifest.py`:

| Field                         | Audit (describes today, changes nothing)                               | Policy Pro / Rank (Phase 11)                                     |
| ----------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `key`                         | `audit`                                                                | `policy` / `rank`                                                |
| `title`                       | "Ccure Audit"                                                          | "Ccure Policy" / "Ccure Rank"                                    |
| `package`                     | `ccure_audit`                                                          | `ccure_policy` / `ccure_rank`                                    |
| `route_prefix`                | `""` — Audit's URLs stay where they are (plan §10)                     | `/policy` / `/rank`                                              |
| `routers`                     | `()` — `main.py` still mounts Audit's 28 routers itself until Phase 16 | `()`                                                             |
| `permission_prefixes`         | the existing atoms' resources                                          | `("policy",)` / `("rank",)`                                      |
| `task_modules`, `queues`      | `()` — Audit's stay in `celery_app.py` until Phase 16                  | `()`                                                             |
| `db_schema`, `alembic_branch` | `public`, none (the unlabelled lineage)                                | `policy_pro` / `rank`                                            |
| `tile`                        | `available`, target `/dashboard`                                       | `not_yet_available` (Phase 12 renders it; never a link)          |
| `enabled`                     | `True`                                                                 | `True` for the manifest; a module with no routers mounts nothing |

**Discovery is by a fixed list, not by scanning the filesystem.** `ccure_platform`
names the known packages (`ccure_audit`, `ccure_policy`, `ccure_rank`) — the
"module registry" the plan describes. Scanning for `ccure_*/manifest.py` would let
a stray folder or a half-copied branch activate itself in production. Adding a
**fourth** module is a platform decision and one line; adding a route, table,
migration or task **inside** an existing module is not, which is exactly the
done-test.

**What reads it:**

- `main.py`: after its existing includes, `for m in registry.enabled(): for r in m.routers: app.include_router(r, prefix=m.route_prefix)`. With every `routers` empty, the app is byte-identical.
- `core/celery_app.py`: `include=[…existing…, *registry.task_modules()]` and `task_queues=(…existing…, *registry.queues())`. Empty in Phase 11.
- `table_ownership` / guardrail tests: the manifest's `db_schema` must equal the owner's schema.

A manifest may **not** declare anything that collides: a route prefix used by
another module or by Audit's existing URLs, a queue another module owns, a task
name outside `ccure.<key>.`, a schema that is not its own. The registry refuses
at import, so a collision is a start-up failure with the module's name in it, not
a request answered by the wrong code.

**No HTTP endpoint in Phase 11.** The homepage's tile list (`GET /platform/modules`
or similar) is Phase 12's, where the UI that consumes it is built; adding it now
would be an unused route that changes OpenAPI and the gateway route policy. See D11-2.

### 3.3 Alembic branches and schemas

- **The existing history is untouched.** No file under `alembic/versions` changes; it stays the unlabelled Audit/platform lineage.
- **Each new module is a new base**: `ccure_policy/migrations/<rev>_create_policy_pro_schema.py` with `down_revision = None`, `branch_labels = ("policy_pro",)`, doing only `CREATE SCHEMA IF NOT EXISTS policy_pro` (and the reverse). Same for `rank`.
- **`alembic.ini`** gains `version_locations = %(here)s/alembic/versions %(here)s/ccure_policy/migrations %(here)s/ccure_rank/migrations`. This is the one file outside the module folders that names them — fixed when the folder is created, not touched when a team adds a migration.
- **`alembic/env.py`**: `target_metadata = [Base.metadata, policy_metadata, rank_metadata]`; `include_schemas=True` with an `include_name` filter admitting exactly `public`, `policy_pro`, `rank` — so `audit_chain` and `audit_retention` stay invisible to autogenerate, as today.
- **Every `head` becomes `heads`**, in one commit:
  - `db/migrate_production_schema.py` — `upgrade heads`, `stamp heads`; the empty-database bootstrap creates the module schemas before `create_all`;
  - `tests/conftest.py` `_build_test_schema` — `stamp`/`upgrade` `"heads"`, schemas first;
  - the 21 scripts and docs;
  - `fingerprint.sh` and the alongside stack read the **set** of rows in `alembic_version`.
- **A guard test**: `alembic heads` equals exactly `{<audit head>, policy_pro@head, rank@head}`, and no module's migration imports another module's models or touches a schema that is not its own (static check over `migrations/`).

**The live change is two empty schemas and two `alembic_version` rows.** It is
applied by the ordinary start-up migrator on one API restart (≈21 s, as in 10.7).
Before it, per the plan and CLAUDE.md:

1. a full dump;
2. **rehearsal on a restored copy**: restore the dump into a scratch database, run `upgrade heads` there, compare every `public` table's row count and the schema/constraint digests before and after (they must be identical), check the two schemas exist and are empty, and run `downgrade policy_pro@base rank@base` to prove the reverse;
3. only then the live restart.

### 3.4 Database roles (decision D11-1)

The plan lists "roles" under Phase 11 and "per-module database roles and grants
for the existing tables" under Phase 18. The measured constraint: the
application's role cannot create roles, and giving it `CREATEROLE` would let it
administer every role it creates (the reason the audit chain has its own DBA
bootstrap).

- **Option A — recommended: schemas now, roles in Phase 18.** Phase 11 creates
  the schemas (owned by `ccure_user`, the database owner, like `public`'s
  tables). The application still connects as one role, so a role per module would
  isolate nothing yet — isolation needs separate connections, which is Phase 18's
  work for every module at once. Nothing is lost: the schemas are empty.
- **Option B — roles now, as a DBA bootstrap.** `scripts/db/bootstrap_module_roles.sql`,
  run once as `postgres` (the `bootstrap_chain.sql` pattern): NOLOGIN roles
  `ccure_policy_owner` / `ccure_rank_owner` own their schemas; `ccure_user` gets
  `USAGE, CREATE` on them. Correct, but it adds an ownership arrangement nobody
  exercises until Phase 18, and every later migration in those schemas runs as a
  role that does not own them.

### 3.5 CI: the import rule and the table registry

**New layer rules** (in `scripts/architecture/layer_rules.py`, alongside the 14):

| Rule                                       | Forbids                                                                                                                                                                                                         |
| ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `modules-are-isolated`                     | `ccure_policy.*` → `ccure_audit`, `ccure_rank`, and any Audit code (`core`, `engines`, `scans`, `orchestrator`, `routers`, `reporting`, `db.models` Audit models); the same for `ccure_rank`                    |
| `audit-does-not-import-modules`            | `ccure_audit`, `core`, `engines`, `scans`, `routers`, … → `ccure_policy`, `ccure_rank`                                                                                                                          |
| `modules-use-the-platform-api`             | a module → `ccure_platform.*` other than `ccure_platform.api` (the identity-boundary rule, extended)                                                                                                            |
| `platform-is-shared-foundation` (existing) | extended: `ccure_platform` → any module package, the registry excepted by _name only_ (it holds the list of package names; it imports manifests lazily, and a test pins that it imports nothing else from them) |

**Table registry:** a model whose `__table__.schema` is `policy_pro` must be owned
by `policy_pro` in `table_ownership.yaml`, and vice versa; a table in `public`
may not be owned by `policy_pro`/`rank`. Both directions fail CI, like today's check.

Like the existing rules these are ratchets with **zero** known violations from
day one — the folders are empty.

### 3.6 Proving the done-test without shipping a feature

A test-only module, `Backend/tests/repo/fixtures/ccure_example/` (never on the
production registry list), with the same shape, adds **one route, one table in
schema `example`, one migration and one task**. The test registers it through the
registry's test hook and proves, in the scratch database:

- the route answers under `/example/…` and appears in OpenAPI;
- `upgrade heads` creates its table in schema `example`, `downgrade example@base` removes it;
- the task is registered as `ccure.example.ping` and runs eagerly;
- **nothing outside the fixture folder was edited** — the test lists the files the module defines and asserts none of them is outside it;
- an import from the fixture into `ccure_audit` (and the reverse) fails the layer rule.

That is the plan's done-test, executed rather than asserted.

### 3.7 CODEOWNERS (decision D11-3)

`.github/CODEOWNERS`:

```
*                         @<project-owner>
/Backend/ccure_platform/  @<project-owner>
/gateway/                 @<project-owner>
/Backend/ccure_contracts/ @<project-owner>
/Backend/ccure_audit/     @<audit-team>
/Backend/ccure_policy/    @<policy-pro-team>
/Backend/ccure_rank/      @<rank-team>
/Frontend/src/modules/policy/  @<policy-pro-team>    (Phase 12 creates these)
...
```

The handles are the owner's to supply. `CODEOWNERS` only bites with branch
protection's "require review from Code Owners". `docs/ci/BRANCH_PROTECTION.md`
does not mention it today, so 11.5 adds it there. Turning it on is a
repository setting the owner changes.

Each module's `README.md` states: what goes where; the three rules; that a first
route needs the gateway route policy regenerated in the same commit
(`python -m scripts.gateway.route_policy`), plus the `docs/` entries and the
endpoint-limit inventory decision CLAUDE.md requires of every route.

### 3.8 Celery queues (decision D11-4)

A module's tasks on its **own** queue need a worker consuming it. Today the
workers' `-Q` lists are in `docker-compose.yml`, outside any module folder.

- **Option A — recommended: modules use `default` until they need isolation**, and
  a dedicated queue is then a platform change (one compose line) made with the
  team. The done-test's "task" runs on `default`.
- **Option B**: the worker derives its `-Q` list from the registry at start. It
  removes the edit, but it changes how every worker starts, which is not Phase 11's
  business.

## 4. Steps (one commit each, review stop after each)

| Step     | What                                                                                                                                                                                                  | Live change                                                                           | Gate                                                                                                                                |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **11.1** | `ccure_platform/modules/` registry and manifests (Audit's describing today; Policy/Rank empty); `main.py` and `celery_app.py` read it                                                                 | none (code only; API restart picks up identical routes)                               | OpenAPI hash, 273 / 93 / 21 / 11 identical; full suite                                                                              |
| **11.2** | `ccure_policy/` and `ccure_rank/` skeletons, READMEs; the four layer rules; the table-registry schema check; the `ccure_example` done-test fixture                                                    | none                                                                                  | guardrail suite; done-test green; full suite                                                                                        |
| **11.3** | Alembic branches: `alembic.ini`, `env.py`, two base migrations, **every `head` → `heads`** (start-up migrator, conftest, 21 docs/scripts, fingerprint, alongside). Rehearsed on a restored copy first | **yes**: one API restart creates the two empty schemas and two `alembic_version` rows | backup; rehearsal record (row counts and digests identical, downgrade proven); after: `public` unchanged, schemas empty; full suite |
| **11.4** | D11-1 option B only: the DBA bootstrap for module roles                                                                                                                                               | only if B                                                                             | —                                                                                                                                   |
| **11.5** | `.github/CODEOWNERS`, CLAUDE.md, plan status                                                                                                                                                          | none                                                                                  | —                                                                                                                                   |

## 5. Risks

| Risk                                                                                                    | Handling                                                                                                                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **The API fails to start after 11.3** ("Multiple head revisions")                                       | The start-up migrator changes to `heads` in the same commit; the rehearsal runs the migrator's _own_ code path against the restored copy, not a hand-typed command. Rollback: `downgrade policy_pro@base rank@base` and the previous commit. |
| A runbook or script still says `head`                                                                   | All 21 changed in 11.3; a guard test greps the repository for `upgrade head`/`stamp head` outside the history.                                                                                                                               |
| Autogenerate starts proposing changes to `audit_chain` / `audit_retention` once `include_schemas` is on | `include_name` admits only `public`, `policy_pro`, `rank`; `tests/repo/test_schema_drift.py` must stay green.                                                                                                                                |
| The registry changes Audit's routes or tasks by accident                                                | Audit's manifest declares nothing to mount; invariants gate every step.                                                                                                                                                                      |
| Two teams' manifests collide (prefix, queue, task name, schema)                                         | Refused at import, with both module names in the error.                                                                                                                                                                                      |
| `alembic_version` with three rows confuses tooling                                                      | `fingerprint.sh` and the alongside stack updated in 11.3.                                                                                                                                                                                    |

## 6. Decisions for the owner

| #         | Decision                                                                                                                                                   | Recommendation                                                         |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| **D11-1** | Module database **roles** now (DBA bootstrap) or with Phase 18                                                                                             | **Phase 18** (option A): schemas now, roles when connections are split |
| **D11-2** | Where the homepage's module list endpoint is built                                                                                                         | **Phase 12**, with the UI that consumes it                             |
| **D11-3** | `CODEOWNERS` handles for the project owner and each team; whether to enable "require review from Code Owners"                                              | Owner supplies handles; enabling is a repository setting               |
| **D11-4** | Per-module Celery queues                                                                                                                                   | **`default` until needed** (option A)                                  |
| **D11-5** | Route prefixes `/policy` and `/rank` (gateway: `/api/policy`, `/api/rank`), schemas `policy_pro` and `rank`, task prefixes `ccure.policy.` / `ccure.rank.` | As the plan names them                                                 |
| **D11-6** | Whether 11.3's live restart is scheduled with the owner present, as 10.5–10.7 were                                                                         | Yes                                                                    |

## 7. Step 11.3 as built: preparation and rehearsal (30 Sep 2026)

### 7.1 One deviation from §4: activation is its own step

§4 had `alembic.ini` gain `version_locations` in the same commit as the branches.
It does not, and the reason is a property of this deployment: `./Backend` is
bind-mounted into the live API, and every API start runs
`db/migrate_production_schema.py` → `alembic upgrade heads`. A committed
`version_locations` would therefore apply the module migrations to `ccure_db` on
the next restart for **any** reason — a crash or a reboot — not at a time anyone
chose.

So the 11.3 commit ships everything except the switch:

| In the commit                                                                                          | Effect on the live system                             |
| ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------- |
| `ccure_policy/migrations/policy_pro_0001`, `ccure_rank/migrations/rank_0001` (new bases, own labels)   | none — Alembic does not see the folders yet           |
| `env.py`: every module metadata, `include_schemas`, `include_name` (public + module schemas only)      | none — no module declares a table                     |
| Start-up migrator: `upgrade heads`; a fresh install stamps **Audit's** head only, then `upgrade heads` | a restart runs `upgrade heads` over one head: a no-op |
| conftest compares heads as sets; `alembic_version` readers aggregate every row                         | none                                                  |
| `module_boundaries.migration_problems`, `tests/repo/test_alembic_module_branches.py`                   | none                                                  |
| `scripts/db/alembic_module_branches.py` — the activation, `--status` / `--print` / `--write`           | none until `--write`                                  |
| Runbooks, CI and the PR template say `heads`; `downgrade -1` becomes `<rev>@-1` per head               | none                                                  |

The activation changes exactly `alembic.ini`: one comment and the
`version_locations` line added, `path_separator = os` → `space`. The rehearsal
applies the same `activate()` to the same committed file, so what was rehearsed
is what goes live.

**A fresh install stamps only Audit's history.** `create_all` builds
`Base.metadata` — Audit's and the platform's tables — and nothing of the
modules. Stamping `heads` would record the modules' `CREATE SCHEMA` as applied
when it never ran. So the migrator stamps Audit's head (found as the heads whose
file lives in `alembic/versions`) and then runs `upgrade heads`, and the module
branches build their schemas as real migrations. The first version created the
schemas by importing the module registry into `db/`, which the
`models-are-leaves` layer rule refused; this form needs no registry at all.

### 7.2 Rehearsal record

`scripts/db/rehearse_module_branches.sh <full dump> <out>` on
`ccure_db_20260930_201214_full.dump` (sha256 `a829000f…`), taken at 20:12 IST
and copied to the workstation. Every database it touches is `ccure_rehearsal_*`
(`scripts/db/rehearsal_env.py` refuses any other name); the code runs from a
copy of `Backend` inside `ccure-api`. Each step is fingerprinted by
`scripts/db/rehearsal_snapshot.sql`: `alembic_version`, every schema with owner
and table count, every table's row count **and an md5 over its rows**, and per
schema digests of columns, constraints, indexes, triggers, functions and grants.

| Step                                               | Result                                                                                                      |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| 0 restore                                          | 146 facts; `alembic_version` = `f3b5d7e9a1c4`                                                               |
| 1 start-up migrator, branches **inactive**         | **identical** to 0 — what a restart after this commit does                                                  |
| 2 start-up migrator, branches **active**           | vs 1: exactly `alembic_version` +2 rows, schemas `policy_pro` and `rank` (owner `ccure_user`, **0 tables**) |
| 3 migrator again                                   | identical to 2 (idempotent)                                                                                 |
| 4 `downgrade policy_pro@base`, `rank@base`         | identical to 1                                                                                              |
| 5 `upgrade heads`                                  | identical to 2                                                                                              |
| 6 fresh empty database, migrator, active           | three heads; `policy_pro`, `rank` with 0 tables                                                             |
| 7 CI's loop (`<rev>@-1` per head, `upgrade heads`) | identical to 6; Audit's newest migration and both bases reversed and re-applied                             |
| 8 migration/schema tests, active                   | 143 passed, 13 skipped, on a scratch `…_pytest_db`, which ended at three heads                              |
| 9 cleanup                                          | every rehearsal database dropped                                                                            |

Every public table's rows and content hash, and every digest of `public`,
`audit_chain` and `audit_retention`, were unchanged across all steps.

### 7.3 The live step (not yet taken — owner present, D11-6)

1. `scripts/backup_db.sh --remote pankaj@10.180.6.30:D:/ccure-backups --ssh-key ~/.ssh/ccure_backup_ed25519` (full).
2. `docker exec -w /app ccure-api python -m scripts.db.alembic_module_branches --write`
   — the api container's user cannot write the bind mount on this VM, so in
   practice `--print` there and write the file on the host.
3. `docker compose up -d --no-deps api`; the start-up migrator creates the two
   schemas and the two rows.
4. Verify: `alembic_version` holds three rows; `policy_pro` and `rank` exist
   with no tables; the invariants (OpenAPI hash, 273 / 93 / 21 / 11) and the
   gateway path over `:443` are unchanged.

**Rollback**: `alembic downgrade policy_pro@base` and `rank@base` (drops the
two empty schemas, `RESTRICT`), then `git checkout -- Backend/alembic.ini` and
restart the api. Both were rehearsed in steps 4 and 5.

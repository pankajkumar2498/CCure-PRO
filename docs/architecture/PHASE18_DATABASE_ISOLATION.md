# Phase 18 — per-module database isolation (preparation)

|                    |                                                                                                                                                                                                |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**         | **Prepared, not implemented, not applied.** Written 6 Oct 2026. No application code, migration, role or grant changed; nothing here has run against any database.                              |
| **Decision basis** | D11-1 (30 Sep 2026): no module roles before Phase 18; roles come from a DBA bootstrap, never a migration. `migration_problems` still refuses role/grant SQL, and a test pins schema ownership. |
| **Not done**       | Connection routing in `db/base.py`, the four login roles, the grants, the per-module connection strings. Each is listed in §8 as a step with its own approval.                                 |
| **Artefacts**      | `scripts/db/phase18/` — `bootstrap_module_roles.sql`, `grants_from_registry.py` → `generated_grants.sql`, `prove_isolation.sql`, `rehearse_isolation.sh`.                                      |

## 1. What isolation means here, and what it does not

Today every module connects as one role, `ccure_user`, which owns every table. The
import rules (`module-isolation`, `modules-use-rbac-api-only`) and the table registry
stop **code** crossing a boundary; nothing stops a **query** doing so, and one
compromised or buggy module can read or rewrite every other module's rows.

Phase 18 makes the database enforce what CI already enforces: a module's connection
can touch its own tables and no one else's. It does **not** add tenant isolation
(that is `org_id` scoping and RBAC), does not change the audit chain's own roles
(`audit_chain_writer`, `audit_maintenance`, already isolated), and does not separate
databases: one PostgreSQL database, several roles.

## 2. Roles

| Role                 | Login | Owns nothing; holds DML on                                          |
| -------------------- | :---: | ------------------------------------------------------------------- |
| `ccure_user`         |  yes  | **Owner and migrator** (unchanged). Not an app role after Phase 18. |
| `ccure_platform_app` |  yes  | the 16 `platform` tables of `table_ownership.yaml`                  |
| `ccure_audit_app`    |  yes  | the 46 `audit` tables                                               |
| `ccure_policy_app`   |  yes  | schema `policy_pro` (empty today)                                   |
| `ccure_rank_app`     |  yes  | schema `rank` (empty today)                                         |

Grants are **generated from the ownership registry** (`grants_from_registry.py`), so a
new table needs its owner in the registry — already required — and its grant follows
in the same change. A test should compare the generated file with the registry
(step 18.2). Table ownership (`OWNER TO`) does not move: moving it would break every
migration, which runs as `ccure_user`.

Defaults: `REVOKE ALL … FROM PUBLIC` on the three schemas; `ALTER DEFAULT PRIVILEGES`
so a table the migrator creates later is private until a grant is written.

## 3. Connection routing (design)

`db/base.py` builds one module-level `engine` from `AppConfig.DATABASE_URL`. Phase 18
replaces that with a small registry, **not** a framework:

```
engine_for(module: str) -> Engine      # "platform" | "audit" | "policy_pro" | "rank"
```

- **Configuration:** `DATABASE_URL_PLATFORM`, `DATABASE_URL_AUDIT`, … One variable per
  module. **If a module's variable is unset it falls back to `DATABASE_URL`**, so the
  change ships dark and each module is cut over on its own. A fallback is a logged
  start-up line, never silent, in the style of `log_trust_boundary()`.
- **Who asks:** the module's own `get_db` dependency (a router in `routers/` belongs
  to Audit; `ccure_platform` routers use the platform's). A Celery task opens its
  module's session; `core/celery_app.py` already knows which module owns each task
  prefix (`ccure.<module>.`), so routing by prefix needs no per-task edit.
- **Migrator:** Alembic keeps `DATABASE_URL` (`ccure_user`). `alembic/env.py` reads the
  environment, so the migrator URL must be named distinctly (`DATABASE_URL_MIGRATOR`) at
  the step that introduces the split. This is the one place a wrong default is
  dangerous, and it is why 18.3 is separate from 18.4.
- **Pools:** `pool_size=10, max_overflow=20` per engine would multiply by four. Size each
  from measured use; the platform and Audit get the bulk, the empty modules a minimum.
- **Not in scope:** read replicas, pgbouncer, per-tenant connections.

## 4. The platform access model

A module must not query `users`, `organizations`, `rbac_*`, `audit_logs`,
`notifications`, … It already should not: modules ask `ccure_platform.api`
(`identity_boundary` counts the exceptions: **3 importers, 2 direct `User` queries, 0
joins** on 6 Oct 2026). With separate connections that rule becomes a database fact:

- `ccure_platform.api` functions open a session on **the platform's engine**. A route in
  Audit that calls `api.has_permission(...)` therefore uses two connections in one
  request — the platform's for the decision, Audit's for its data. That is the design,
  not a defect; the cost is one more pooled connection per request, to be measured in
  18.4.
- **The two remaining direct `User` queries must be removed first** (step 18.1): after
  isolation they would fail with permission denied, which is the right outcome but not
  the way to find them.
- **Audit's tables carry foreign keys to `users` and `organizations`.** Whether an
  INSERT by `ccure_audit_app` into such a table needs `SELECT` or `REFERENCES` on the
  referenced platform table is **not assumed**: PostgreSQL runs the referential check
  with the owner's rights on the referenced table's side, which should mean no grant is
  needed, and the rehearsal must prove it rather than this document asserting it. If it
  is needed, the narrowest answer is column-level `SELECT (id)` — and `prove_isolation.sql`
  keeps a refusal probe on the other columns.
- **Joins across the line** (a query joining `scans` to `users`) cannot survive. The
  inventory of such joins is `python -m scripts.architecture.identity_boundary`, whose
  join count is **0**; a module-to-module join the registry does not see (`audit` ↔
  `platform` through raw SQL) needs a `grep` of `text(` / `execute(` over module code in
  step 18.1.
- **Row-level security** is out of scope. It would add a second, per-tenant mechanism
  beside `org_id` scoping and RBAC.

## 5. DBA bootstrap

`scripts/db/phase18/bootstrap_module_roles.sql`, run by a superuser, once per database,
in the pattern of `bootstrap_chain.sql`:

- one transaction, `ON_ERROR_STOP`, guards that `RAISE` — the database is not a reserved
  name, the caller is a superuser, the `policy_pro` and `rank` schemas exist;
- creates the four LOGIN roles only if absent (a re-run is not a reset), with passwords
  passed as psql variables and never written to the file or a log;
- revokes `PUBLIC`, grants schema `USAGE`, then `\i`s the **generated** table grants.

It does not touch the audit chain or retention roles, `ccure_user`, or ownership.

## 6. Restored-database rehearsal (the only way this runs first)

`scripts/db/phase18/rehearse_isolation.sh <…_full.dump>`:

1. refuses any database that is not a freshly named `ccure_rehearsal_p18_*`, whatever the
   caller passes — **it refuses `ccure_db`, `ccure_test`, `ccure_prod`, `vuln_intel` and the
   other reserved names explicitly, and a name outside the pattern**; it accepts only a
   `_full` dump (an `_ops` dump is not restorable alone);
2. restores the dump into the new database, through `docker exec ccure-db`;
3. records every table's row count;
4. applies the bootstrap with generated random passwords;
5. runs `prove_isolation.sql`;
6. records the counts again and diffs them (a grant script must change no data);
7. drops the scratch database on exit.

The refusal logic was exercised on 6 Oct 2026 (`ccure_db`, `ccure_test` and a name outside
the pattern each exit 2 before any docker call). **The restore, bootstrap and proof steps
have not been run.**

## 7. The proof that cross-module access is refused

`prove_isolation.sql` switches to each module role and runs a probe that must fail with
`insufficient_privilege` (42501). Any other failure, or success, aborts the run. A
passing run means all of:

- **Positive controls** — each role reads one of its own tables. Without these, "every
  probe was refused" could mean the roles are simply broken.
- Audit cannot read `users`, `rbac_roles`, cannot write `rbac_user_roles` or `audit_logs`.
- The platform cannot read `scans` or `assets`.
- Policy Pro and Rank read nothing in `public`, and neither can create in the other's
  schema (nor can Audit).
- No module role can `DROP`/`ALTER` a table, reach the `audit_chain` schema or call the
  retention purge function.
- **Membership**, not `SET ROLE`: no module role is a member of `ccure_user`, the chain
  roles or another module's role. (A `SET ROLE` probe from a superuser session proves
  nothing, because a superuser can set any role.)

All probes run in one transaction that ends in `ROLLBACK`.

## 8. Steps, each with its own approval

| Step     | Change                                                                                                                                       | Reversible by          |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| **18.0** | This document, the four artefacts (**done, 6 Oct 2026**)                                                                                     | `git revert`           |
| 18.1     | Remove the two direct `User` queries; grep module code for raw SQL on foreign tables                                                         | `git revert`           |
| 18.2     | A test that `generated_grants.sql` equals the registry; run the rehearsal; record results here                                               | —                      |
| 18.3     | `DATABASE_URL_MIGRATOR` for Alembic; the engine registry with fallback to `DATABASE_URL` (dark)                                              | `git revert`           |
| 18.4     | DBA runs the bootstrap on the live database after a verified `_full` backup; Audit then Platform cut over one at a time by setting their URL | unset the URL, restart |
| 18.5     | Flip the schema-ownership test to the new owners; document D11-1 as closed                                                                   | `git revert`           |

## 9. Open questions (not settled by this preparation)

1. The foreign-key privilege question in §4 — the rehearsal decides it.
2. Whether `ccure_user` should lose its DML on module tables once the module roles are
   live (least privilege, but it is the role the bootstrap data scripts use).
3. Whether the IR service, which is a separate service with its own contract, gets a database
   of its own (the registry reserves `ir`; the generated grants skip it).
4. Per-engine pool sizes (§3) — to be measured in 18.4, not guessed.

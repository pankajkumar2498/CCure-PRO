# Phase 8 — Identity, organisations and roles into `ccure_platform`

|               |                                                                                                                                                                                       |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**    | **Approved** by the project owner, 28 Sep 2026, step by step with a review stop after each commit. **Step 8.1 done** (guardrails only); 8.2 not started.                              |
| **Date**      | 28 Sep 2026                                                                                                                                                                           |
| **Plan**      | [`CCURE_PLATFORM_MODULAR_ARCHITECTURE.md`](CCURE_PLATFORM_MODULAR_ARCHITECTURE.md) rev 4: Phase 8, rule 13, §3.9 (future authentication service), Phase 19 (single-organisation mode) |
| **Builds on** | Phases 1–7: 0 layering violations, 0 import cycles, contracts v1 (draft), Audit's read services                                                                                       |
| **Audience**  | Project owner (owner of `ccure_platform`, D6); Audit team                                                                                                                             |

## 1. What this phase is for

Sign-in, users, organisations and roles are the platform's, not Audit's. Every
module — Audit today; Policy Pro, Rank and IR next — needs them. The API
Gateway (Phase 10) and IR (Phase 13) will depend on them, and a separate
authentication service may one day take them over (§3.9).

Today they sit in `auth/` and `db/models/`, and Audit's code reaches into them
directly. Phase 8 puts them behind one package, `ccure_platform`, and makes that
package the only way in.

**No behaviour changes:**

- The same tables, the same database, the same URLs and the same tokens are
  kept.
- The same login rules are kept, including the lockout-before-password order
  CLAUDE.md warns about.
- The OpenAPI document stays byte-identical.

## 2. What is there today (measured 28 Sep 2026, AST, production code only)

|                                          |                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `auth/`                                  | 11 modules, 4,555 lines: the login/registration router (1,886), JWT handling, RBAC dependencies, mail, email-domain screening                                                                                                                                                                                                                                                                                                                             |
| Identity models                          | `User`, `RefreshTokenSession`, `PasswordResetToken`, `EmailVerificationToken` (`db/models/users.py`); `Organization`, `Role`, `Permission`, `RolePermission` (`db/models/rbac.py`). `AuditLog` lives in `users.py` and is also platform-owned                                                                                                                                                                                                             |
| Identity's own routers                   | `admin_orgs`, `admin_users`, `admin_rbac`, `user_profile`, `admin_email_domains`, `audit` (the audit-log viewer), `notifications` — and `main.py`'s bootstrap                                                                                                                                                                                                                                                                                             |
| **Module code importing identity**       | **32 files**, 80 imported symbols: 18 routers, 9 in `core/`, 2 in `scans/`, 3 in `ccure_audit/`. The imports are overwhelmingly `User`, `Organization` and `require_permission`. Three of the nine in `core/` are platform services that live there today (`core.audit`, `core.notifications`, `core.email_security_tasks`); 8.2 decides whether they move rather than being rewritten                                                                    |
| **Module code querying identity tables** | **53 queries in 23 files**. The largest are `core/tasks.py` (9) and `scans/db_helpers.py` (9). By model: `Organization` 24, `User` 21, `RolePermission` 6, `RefreshTokenSession` 1, `Role` 1. **Plus 8 joins and eager loads in 4 files** (`.join(Permission, …)`, `joinedload(User.role)`), which the first count did not look for                                                                                                                       |
| Audit configuration on `organizations`   | `max_assets`, `max_scans_per_day`, `max_concurrent_scans`, `scan_scope_cidrs` — read for quotas and scope checks. Most of the 24 `Organization` queries above exist to read these. **Identity's own code also touches them, 11 times in 2 files**: registration gives a new self-service organisation `max_assets=100` (`auth/router.py`), and `routers/admin_orgs.py` edits quotas and scan scope. Step 8.4 moves both to Audit, with the URLs unchanged |
| `Organization.assets` / `.scans`         | Relationships with an ORM delete cascade. **No code navigates them**; they only make identity code know Audit's tables                                                                                                                                                                                                                                                                                                                                    |

**A correction to the plan's §3.9.** It quoted "140 files, 32 queries". That was
a grep which included `scripts/` and counted only `User` queries. The AST
figures above replace it, and §3.9 is updated to match. The figures are now
produced by `python -m scripts.architecture.identity_boundary` (from
`Backend/`), which is also what CI checks.

## 3. Target shape

```
Backend/ccure_platform/
  identity/     sign-in, sessions, password reset, email verification, email-domain screening, JWT
  tenancy/      organisations
  rbac/         roles, permissions, the require_permission / require_role dependencies
  api.py        THE way in for every module — the functions below, nothing else
```

`ccure_platform.api` is small on purpose. It holds what modules actually use,
measured above:

| Function                                                       | Replaces                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `current_user`, `current_user_flexible` (FastAPI dependencies) | `auth.dependencies.get_current_user*`                                     |
| `require_permission(resource, action)`, `require_role(*roles)` | `auth.rbac.*`                                                             |
| `user_display_names(user_ids) -> {id: name}`                   | direct `User` queries for names (exports, reports, notifications)         |
| `users_holding_permission(org_id, resource, action)`           | the `RolePermission` / `Role` joins in reports, scan history and progress |
| `organisation(org_id) -> OrganisationView`                     | direct `Organization` queries for name or status                          |
| `is_organisation_active(org_id)`                               | the same, where only the status is needed                                 |

Module code never receives an ORM `User` or `Organization` from these
functions. It receives ids, names and frozen views, the same discipline as
Phase 5. A later authentication service (§3.9) replaces the implementation
behind these functions, not their callers. **Single-organisation mode
(Phase 19) switches on in `tenancy`**, and nowhere else.

## 4. Steps — one commit each, review after each

| Step    | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Risk                                                        | Verified by                                                                           |
| ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **8.1** | **Package and guardrail.** Create `ccure_platform/` (empty `api`). Add the layer rule `modules-reach-identity-through-platform` with today's 32 files recorded as known violations. Add an AST test for direct identity-table queries outside the platform, with today's 53 recorded. Both are ratchets: counts may only fall, and adding one fails CI.                                                                                                                                                        | None                                                        | `tests/repo`                                                                          |
| **8.2** | **Move identity's code.** `auth/*` → `ccure_platform/identity`/`rbac`, and the eight models → `ccure_platform`. The old import paths stay, as **`sys.modules` aliases of the same module objects** (the `scans.cvss` pattern). A second import of a model file under another name would define its tables twice, which SQLAlchemy refuses at start-up. Router prefixes, `@limiter.limit` decorators and Celery task names are unchanged.                                                                       | **Medium** — every request's authentication path            | Full suite; OpenAPI byte-identical; live login, refresh and logout on the running app |
| **8.3** | **The platform functions**, with tests. Then the 53 direct queries are replaced in three commits by area: `core/` + `scans/`, then routers, then `ccure_audit/`. Each commit lowers the ratchet.                                                                                                                                                                                                                                                                                                               | Low–Medium                                                  | The suites of each area, then the full suite                                          |
| **8.4** | **Audit's settings leave `organizations`.** A new Audit-owned table, `audit_organisation_settings` (quotas and scan scope), is filled from the current columns in the same migration. Audit reads its settings from there. The old columns stay, unused, until one release has run cleanly, then a later migration drops them (so rollback is one migration). The `Organization.assets`/`.scans` relationships are removed after checking that the database's own foreign keys cascade exactly as the ORM did. | **Medium** — a migration on live tables, `archive_mode` off | Full dump before; rehearsal on a restored copy; quota and scope tests; one live scan  |
| **8.5** | **Module imports switch to `ccure_platform.api`** (the 32 files). The known-violations list reaches **zero** and is deleted, so the rule then holds without exception.                                                                                                                                                                                                                                                                                                                                         | Low                                                         | `tests/repo`; full suite                                                              |

**Done when** — the plan's definition:

- no module imports `auth.*` or an identity model;
- no module queries or joins an identity table;
- no module configuration lives on `organizations`;
- CI keeps all three true;
- sign-in, quotas and scan scope behave exactly as before.

## 5. What is deliberately not in Phase 8

- **Token signing** (HS256 → RS256, JWKS) and service identities are **Phase 9**.
- **The gateway** is **Phase 10**.
- **Removing organisations** is rejected, and hiding them (single-organisation
  mode) is **Phase 19** (plan rev 4). Phase 8 only puts the switch in one place.
- **A separate authentication service or database** is §3.9's later option. The
  foreign keys into `users` / `organizations` stay; they are the one allowed
  database link (rule 13).
- **Renaming URLs, permissions or roles** is out of scope.
- **The frontend** is unchanged in this phase.

## 6. Risks and how each is contained

| Risk                                                                                            | Containment                                                                                                                                                              |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| A model module imported under two names registers its tables twice and the app refuses to start | Aliases are `sys.modules` entries pointing at one module object, never copies. The step-8.2 test imports every old path and asserts identity (`is`) with the new one     |
| Login order regresses (account state checked before the password) — an account-existence oracle | `auth.router` moves verbatim. `tests/auth` and `tests/security` run on every step. The live login check covers a wrong password, a locked account and a disabled account |
| A rate-limited route loses `response: Response` or its limiter entry                            | `tests/security/test_rate_limit_headers.py` and the endpoint inventory run on every step                                                                                 |
| The OpenAPI document changes (component names are keyed by class)                               | Regenerated and compared byte for byte on every step                                                                                                                     |
| The 8.4 migration loses a quota or a scope                                                      | Filled in the same transaction. Old columns kept. Rehearsed on a restored copy. Row-by-row comparison before and after                                                   |
| A running worker holds old code (the 4 Sep incident)                                            | API **and** worker restarted after every step that changes `core/`, `scans/` or identity                                                                                 |

## 7. Decisions (28 Sep 2026)

1. **Phase 8 approved** as proposed, step by step, with a review stop after each
   commit. The project owner's conditions:

   - 8.1 is guardrails only, with no production change.
   - `ccure_platform` exposes shared identity, tenancy and RBAC primitives only.
     It is never a home for Audit logic, and Audit's quotas and scan scope stay
     out of it.
   - Token signing, service identities and the gateway are not touched
     (Phases 9 and 10).
   - Organisations stay, and so do the `users` / `organizations` tables and the
     modules' foreign keys into them.
   - In 8.2, moved model classes stay the exact same module and class objects.
   - 8.4 needs:

     - a full backup;
     - a rehearsal on a restored copy;
     - a row-by-row comparison before and after;
     - quota and scan-scope verification.

     The old columns stay untouched and unused for at least one clean release.

   - "No behaviour change" means no intentional externally observable change.
     Login, authorisation, URLs, tokens, quotas, scope enforcement and the
     OpenAPI document stay identical.

2. **D6 — owner of `ccure_platform`: the Project Owner**, provisionally, until
   Phase 11 establishes `CODEOWNERS`. Audit maintains the package in the
   meantime, and the ownership can be changed later.

## 8. Step 8.1 — as built

**Package.** `Backend/ccure_platform/__init__.py` (what belongs, what does not,
the owner) and `ccure_platform/api.py` (`__all__ = ()`). Nothing imports
either.

**Measurement.** `scripts/architecture/identity_boundary.py` parses every
application module with `ast` (the same module discovery as the import graph,
so lazy imports count) and holds four baselines.

| Baseline                         | Measured                      | What it counts                                                                                                                                  |
| -------------------------------- | ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `KNOWN_IDENTITY_IMPORTS`         | 32 modules, 80 symbols        | A symbol from `auth.*`; an identity model from `db.models` / `.users` / `.rbac`; anything from `ccure_platform` other than `ccure_platform.api` |
| `KNOWN_IDENTITY_QUERIES`         | 53 in 23 modules              | `.query(M…)`, `select(M…)`, `.get(M, …)`, `delete(M)`, `update(M)`, where an argument is rooted at an identity model (aliases followed)         |
| `KNOWN_IDENTITY_JOINS`           | 8 in 4 modules                | `.join` / `.outerjoin` / eager loads rooted at an identity model                                                                                |
| `KNOWN_AUDIT_SETTING_REFERENCES` | 11 in 2 platform-side modules | Any mention of the four Audit settings in identity's code (column definitions in a model class excepted, because the columns stay)              |

Exempt, as identity's own code and consumers:

- `auth`, `ccure_platform` and the identity model files;
- the model registry `db.models` (the exact name only, so Audit's model files
  are not exempt through it);
- the identity routers (`admin_orgs`, `admin_users`, `admin_rbac`,
  `admin_email_domains`, `user_profile`, `audit`, `notifications`);
- `main`.

**Why not a layer rule, as the proposal said.** Layer rules work on module
edges. `from db.models import User` is the edge `… -> db.models`, which every
module takes for its own models too, so an edge cannot tell `User` from `Scan`.
The identity ratchet is therefore by symbol. What it cannot see is navigation
through a relationship an Audit model declares towards identity, such as
`joinedload(Scan.created_by_user)`. That is a model change for 8.3/8.4.

**Layer rule `platform-is-shared-foundation`** (`layer_rules.py`).
`ccure_platform` may not import:

- `ccure_audit`, `core`, `scans`, `scan_helpers`, `engines`, `orchestrator`,
  `reporting`, `routers` or `main`;
- any of Audit's model files.

The exceptions are the eight shared-infrastructure modules `auth/` imports
today, named one by one in a new `exempt_targets` field. `ccure_platform` also
joined:

- `_APP_PACKAGES`, so contracts and models cannot import it;
- the forbidden lists of `engines-are-libraries`, `infrastructure-is-foundation`
  and `integration-is-an-adapter`;
- the importers of `task-hub-is-a-leaf`.

**Tests** — `tests/repo/test_identity_boundary.py` (28) and additions to
`test_architecture_guardrails.py` (18 rule cases):

- each baseline fails in both directions;
- the detector is checked against twelve source shapes;
- the `api` surface is limited to `PLATFORM_API_SURFACE`;
- platform code imports no module-owned model, by class name through
  `table_ownership.yaml`;
- every model file is classified for the platform rule;
- `auth/`'s current imports, re-homed under `ccure_platform`, already satisfy
  the platform rule, so step 8.2 needs no exception.

A mutation run confirmed the guards fire. A module in `core/` querying `User`,
and one in `ccure_platform/` importing `Scan`, reading `max_assets` and
importing `scans`, failed five tests between them.

**No production change.** Only files under `scripts/`, `tests/` and the new,
unimported package changed. The OpenAPI document generated from the working
tree and from `91f4ebf` is byte-identical: SHA-256 `abc552ad…`, 338,097 bytes,
271 routes. The API and worker were not restarted because there was nothing for
them to load.

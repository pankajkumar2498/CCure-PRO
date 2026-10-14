# Phase 8 — Identity, organisations and roles into `ccure_platform`

|               |                                                                                                                                                                                               |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**    | **Steps 8.1–8.5 done** (29 Sep 2026). Step 8.4 was redesigned — plan and entitlements are platform-owned, see [`ORGANISATION_SETTINGS.md`](ORGANISATION_SETTINGS.md). Phase 9 not started.    |
| **Date**      | 28 Sep 2026                                                                                                                                                                                   |
| **Plan**      | `CCURE_PLATFORM_MODULAR_ARCHITECTURE.md` _(master plan; not versioned in this repository)_ rev 4: Phase 8, rule 13, §3.9 (future authentication service), Phase 19 (single-organisation mode) |
| **Builds on** | Phases 1–7: 0 layering violations, 0 import cycles, contracts v1 (draft), Audit's read services                                                                                               |
| **Audience**  | Project owner (owner of `ccure_platform`, D6); Audit team                                                                                                                                     |

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

| Step    | What                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Risk                                                        | Verified by                                                                           |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| **8.1** | **Package and guardrail.** Create `ccure_platform/` (empty `api`). Add the layer rule `modules-reach-identity-through-platform` with today's 32 files recorded as known violations. Add an AST test for direct identity-table queries outside the platform, with today's 53 recorded. Both are ratchets: counts may only fall, and adding one fails CI.                                                                                                                                                                                                                                                                                                                                          | None                                                        | `tests/repo`                                                                          |
| **8.2** | **Move identity's code.** `auth/*` → `ccure_platform/identity`/`rbac`, and the eight models → `ccure_platform`. The old import paths stay, as **`sys.modules` aliases of the same module objects** (the `scans.cvss` pattern). A second import of a model file under another name would define its tables twice, which SQLAlchemy refuses at start-up. Router prefixes, `@limiter.limit` decorators and Celery task names are unchanged.                                                                                                                                                                                                                                                         | **Medium** — every request's authentication path            | Full suite; OpenAPI byte-identical; live login, refresh and logout on the running app |
| **8.3** | **The platform functions**, with tests. Then the 53 direct queries are replaced in three commits by area: `core/` + `scans/`, then routers, then `ccure_audit/`. Each commit lowers the ratchet.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Low–Medium                                                  | The suites of each area, then the full suite                                          |
| **8.4** | **Superseded 29 Sep 2026** by [`ORGANISATION_SETTINGS.md`](ORGANISATION_SETTINGS.md): plan and entitlements are platform-owned, so nothing moves into Audit. _As first proposed:_ **Audit's settings leave `organizations`.** A new Audit-owned table, `audit_organisation_settings` (quotas and scan scope), is filled from the current columns in the same migration. Audit reads its settings from there. The old columns stay, unused, until one release has run cleanly, then a later migration drops them (so rollback is one migration). The `Organization.assets`/`.scans` relationships are removed after checking that the database's own foreign keys cascade exactly as the ORM did. | **Medium** — a migration on live tables, `archive_mode` off | Full dump before; rehearsal on a restored copy; quota and scope tests; one live scan  |
| **8.5** | **Module imports switch to `ccure_platform.api`** (the 32 files). The known-violations list reaches **zero** and is deleted, so the rule then holds without exception.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Low                                                         | `tests/repo`; full suite                                                              |

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

## 9. Step 8.2 — as built

The owner's conditions for this step (28 Sep 2026 review of 8.1):

- 8.2 only, with no organisation or quota change;
- the models moved without duplication, and every old path resolving to the
  same module and class objects;
- externally observable behaviour identical;
- the three platform services in `core/` classified before anything moves.

**What moved.** Thirteen files moved with `git mv`, so their history follows
them. `ccure_platform/_legacy.py` `MOVED_MODULES` is the record.

| Old path                                                                | Now                                              |
| ----------------------------------------------------------------------- | ------------------------------------------------ |
| `auth/router.py`                                                        | `ccure_platform/identity/router.py`              |
| `auth/jwt_handler.py`                                                   | `ccure_platform/identity/jwt_handler.py`         |
| `auth/dependencies.py`                                                  | `ccure_platform/identity/dependencies.py`        |
| `auth/email_utils.py`, `email_domain_guard.py`, `email_risk_signals.py` | `ccure_platform/identity/` (same names)          |
| `auth/mail_dispatch.py`, `mail_service.py`, `mail_tasks.py`             | `ccure_platform/identity/` (same names)          |
| `auth/registration_limits.py`                                           | `ccure_platform/identity/registration_limits.py` |
| `auth/rbac.py`                                                          | `ccure_platform/rbac/dependencies.py`            |
| `db/models/users.py`                                                    | `ccure_platform/models/users.py`                 |
| `db/models/rbac.py`                                                     | `ccure_platform/models/rbac.py`                  |

The model files moved whole. `users.py` also holds `AuditLog`, which is the
platform's audit trail and not the CCure Audit module. `rbac.py` holds
`Organization` beside the roles. Splitting either would have made one legacy
path two modules. No `tenancy/` package exists yet, because nothing but the
model belongs in it before step 8.3.

**How the old paths keep working.** Three things together:

1. **Stubs.** Each old file is a stub: `import <new> as _module;
sys.modules[__name__] = _module`. This is the `scans.cvss` pattern from
   Phase 3.
2. **`adopt_legacy_name`.** Each moved module calls
   `adopt_legacy_name(__name__, "<legacy>")` as its first statement. It
   registers the alias from inside its own import, so the alias holds
   whichever name is imported first. It sets the legacy package attribute, and
   `auth/__init__.py` and `db/models/__init__.py` answer the other order
   through `__getattr__`.
3. **The legacy `__name__`.** The module keeps its old `__name__`. Everything
   derived from it is therefore unchanged:
   - the limiter's route table (`auth.router.login`);
   - logger names;
   - the `__module__` of Pydantic and SQLAlchemy classes.

The real location stays in `__spec__.name` and `__file__`. Renaming loggers
and limiter keys is a later, deliberate change. The limiter's **Redis** keys
are URL-based (`LIMITS:LIMITER/<ip>//auth/login/10/1/minute`, observed live)
and never depended on the module name.

**Platform code imports its own modules by their real names**, and models
through the `db.models` registry as before. The new layer rule
`platform-does-not-use-legacy-paths` holds that, so the aliases can be deleted
later without touching the platform. `models-are-leaves` now also covers
`ccure_platform.models`, and it exempts the two legacy model stubs, which
import the platform's models.

`component()` in the import graph splits `ccure_platform` by subpackage, as it
already did for `engines`. Otherwise the model stubs would appear to reach the
sign-in router, and the component-level cycle figure would jump from 20 to 32
for a reason that is not real.

**Not changed:**

- module code's imports, which are still `auth.*` / `db.models`. Steps 8.3–8.5
  change them, and the baselines stay 32 / 53 / 8 / 11;
- the `organizations` quota and scope columns;
- the relationships to Audit's models;
- foreign keys, tokens and signing;
- router prefixes;
- Celery task names and `include` (`auth.mail_tasks` is loaded through its
  alias).

**The three platform services in `core/`** were classified by what they do and
what they touch, and none was moved. None had to move for 8.2, and each is a
separate decision.

| Module                      | Belongs to                                                                                                                                                                                          | Plan                                                                                                                                                                                                                                    |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `core.audit`                | **Platform: the audit trail.** It is the single write path for `audit_logs` (platform-owned), used by every module. "Audit" here means the tamper-evident activity log, not the CCure Audit module. | Move as one unit with its family (`audit_taxonomy`, `audit_retention`, `audit_event_translator`, which the DBA bootstrap scripts reference) into `ccure_platform/audit_log/` as its own step after 8.5. It is not identity, and 8.2 is. |
| `core.notifications`        | **Platform: notifications.** The `notifications` table is platform-owned, and any module notifies a user. Its three identity queries find the users who hold a role.                                | Its queries move onto `ccure_platform.api` in 8.3. The module itself moves with the audit-log step or later.                                                                                                                            |
| `core.email_security_tasks` | **Platform: identity.** Email-risk enrichment, the retro-scan, purging unapproved accounts and the disposable-domain sync are all account screening and lifecycle.                                  | **Recommended for 8.3:** move it into `ccure_platform/identity/`, keeping its four task names, queue and `include` entry. That removes one file and three queries from the baseline more honestly than rewriting them onto the API.     |

**Tests** — `tests/repo/test_platform_identity_move.py` (57):

- for every moved module: `old is new` for the module and every model class,
  the legacy `__name__`, the real `__spec__`, and the parent attribute;
- each identity table is mapped once and defined in exactly one source file;
- the aliases hold in three fresh interpreters that import new-first,
  legacy-first and registry-first;
- limiter route keys, logger names and Celery task names are unchanged, and no
  OpenAPI name mentions the new location;
- every legacy file is a stub of exactly its recorded module, `auth/` holds
  nothing else, and each moved module adopts its name before anything reads it.

The guardrail cases gained 8. The 8.1 test that anticipated this move was
removed, because the real edges are now checked instead.

**Verified against `48b7393`**, on the working tree and on a `git archive` of
that commit, in the same container:

- the OpenAPI document is byte-identical (SHA-256 `abc552ad…`, 271 routes);
- the 91 limiter route keys are identical;
- the 45 Celery task names are identical.

After the API, worker, web worker and beat were restarted, a live probe gave
the same status and body as before for:

- login with an unknown account;
- a malformed login;
- refresh and logout without a cookie;
- a missing token;
- a bad token on an identity route and on a permission-guarded route.

The limiter's Redis keys were identical too.

## 10. Step 8.3 — as built

The owner's conditions (review of 8.2):

- classify every access by what the caller needs before replacing it, and do
  not invent a generic API to remove a query;
- no quota or scope ownership moves, and no organisation column changes;
- URLs, permissions, roles, tokens and task names unchanged;
- `core.audit` is not moved;
- `core.notifications` uses the API but stays where it is;
- `core.email_security_tasks` may move as its own change.

**Result:**

| Measure         | Before | After | How                                                        |
| --------------- | ------ | ----- | ---------------------------------------------------------- |
| Direct queries  | 53     | 17    | 32 replaced, 1 removed, 3 moved into the platform, 17 kept |
| Joins and loads | 8      | 2     | 6 replaced, 2 kept                                         |
| Importing files | 32     | 25    | Imports themselves go in 8.5                               |

### What `ccure_platform.api` gained

- **Planned, now implemented:**
  - `current_user`, `current_user_flexible`, `require_permission`,
    `require_role`. These are the existing dependencies, re-exported. They
    still return the ORM `User` that every route reads.
  - `user_display_names`: returns the email address, which is what the export
    printed.
  - `organisation` / `OrganisationView`: id, name and slug only. There is no
    quota, scope, plan or settings field.
- **Added, because no planned name matched the callers' meaning:**
  - `user_has_permission` is the existing single implementation behind
    `require_permission`. Six call sites had hand-copied it.
  - `user` / `UserView` (id, org_id, username, email, in_app_alerts) resolves
    an account by id, for the scan owner's organisation, the activity-log
    actor, and owner membership.
  - `active_members_with_roles` serves the notification fan-out, which selects
    by role _name_.
- **Planned but not implemented**, because no caller has the meaning:

  - `users_holding_permission`: the joins it was meant for all ask whether
    _one_ user holds a permission, not who holds it;
  - `is_organisation_active`.

  Both stay declared in `PLATFORM_API_SURFACE` and can be added when a caller
  needs them.

### Old access → new API

| Caller (line at `7c5786e`)                                                                                                                                                                         | Access                           | Meaning                                                                       | Now                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| `ccure_audit.services.assessment_read:333`                                                                                                                                                         | Organization                     | display name in an export                                                     | `api.organisation().name`                                        |
| `ccure_audit.services.finding_read:71`                                                                                                                                                             | User                             | owner email addresses                                                         | `api.user_display_names()`                                       |
| `core.notifications:163`                                                                                                                                                                           | User                             | a username computed and never used                                            | **removed**                                                      |
| `core.notifications:204, 212`                                                                                                                                                                      | Role, User                       | active members holding these roles                                            | `api.active_members_with_roles()`                                |
| `core.tasks:131, 2669, 4541`                                                                                                                                                                       | User                             | the scan owner's organisation                                                 | `api.user().org_id`                                              |
| `core.tasks:386`                                                                                                                                                                                   | User                             | the owner exists; its organisation                                            | `api.user()`                                                     |
| `core.tasks:432`, `core.topology.engine:865`, `scans.db_helpers:169, 764, 784`, `routers.credentials:492`, `routers.scan_policies:418, 721`, `routers.scan_schedules:574`, `routers.web_scans:499` | Organization                     | slug for building an id, falling back to the id                               | `api.organisation().slug`                                        |
| `scans.db_helpers:132`                                                                                                                                                                             | User                             | the user's organisation                                                       | `api.user().org_id`                                              |
| `scans.db_helpers:189, 286, 556, 698, 865`                                                                                                                                                         | User                             | the activity-log actor (`log_audit_event` reads only id, org_id and username) | `api.user()`                                                     |
| `scans.progress:198, 205` + join                                                                                                                                                                   | User, RolePermission, Permission | may this user read another's scan                                             | `api.user()` + `api.user_has_permission(…, "scans", "read_all")` |
| `routers.reports:373, 403, 430` + 3 joins                                                                                                                                                          | RolePermission, Permission       | reports:read, reports:delete, scans:read_all                                  | `api.user_has_permission()`                                      |
| `routers.scan_history:166` + join                                                                                                                                                                  | RolePermission, Permission       | scans:read_all                                                                | `api.user_has_permission()`                                      |
| `routers.scan_history:434` + join                                                                                                                                                                  | RolePermission, Permission       | the WebSocket's scans:read                                                    | `api.user_has_permission()`                                      |
| `routers.remediation:646`                                                                                                                                                                          | User                             | the owner is a user in this organisation                                      | `api.user()` + an org comparison                                 |
| `core.email_security_tasks:49, 105, 215`                                                                                                                                                           | User                             | account screening and lifecycle                                               | **moved** into `ccure_platform.identity` (below)                 |

### Kept, and why (17 queries, 2 joins)

- **Audit configuration on `organizations`: 13 queries, step 8.4.** Each
  passes the row to a quota, scope or SLA reader:

  - quota: `core.quota:157`, and `routers.dashboard:224` (the plan, to derive
    quota limits);
  - scan scope: `core.tasks:135`, `core.scheduling.dispatcher:202`,
    `routers.credentialed:49`, `routers.credentials:654`,
    `routers.phase_scans:72`, `routers.scan_schedules:445`,
    `ccure_audit.services.baseline_mapping:316`;
  - SLA policy: `core.tasks:4860`, `core.remediation.reporting:154`,
    `core.remediation.workflow:217`, `routers.remediation:135`.

  Replacing these with `OrganisationView` would put Audit configuration into
  the platform view, which the owner's conditions forbid.

  **Two findings for 8.4's scope:**

  - The SLA policy is Audit configuration too, stored in
    `Organization.settings["remediation_sla"]`. 8.4 was defined as quotas and
    scan scope, so it should include the SLA policy.
  - Whether `plan` is a platform attribute (a tier all modules read) or
    Audit's is a decision to take there.

  `baseline_mapping:316` was first classified as an existence check. Its row
  also reaches `_scope()`, which reads `scan_scope_cidrs`, so it was reverted
  and kept.

- **WebSocket ticket logins: 2 queries and 2 eager loads, Phase 10.** They
  are `routers.scan_history:424/425` and `routers.web_scans:1357/1358`. They
  are authentication, not a lookup, and the two differ: one checks
  `scans:read`, the other checks active and not deleted. The gateway
  authenticates WebSockets in Phase 10, so a platform primitive now would be
  designed twice. The permission check inside the first _was_ replaced.
- **Identity maintenance tasks in the Audit task hub: 2 queries.** They are
  `core.tasks:5102` (`purge_stale_unverified_accounts`) and `:5211`
  (`purge_expired_refresh_sessions`). They are identity's, like the
  unapproved-account purge that moved. They were not moved because only
  `core.email_security_tasks` was authorised. **Recommendation:** move both
  into `ccure_platform/identity/`, keeping their task names and beat entries.

### `core.email_security_tasks` moved (commit 8.3b)

It moved to `ccure_platform/identity/email_security_tasks.py`. The old path is
an alias of the same module object, recorded in `MOVED_MODULES`. Its
`__name__`, the Celery `include` entry, the four task names and the `default`
queue are unchanged, and a test pins them. `core/__init__.py` gained the same
`__getattr__` as the other legacy packages. The platform rule no longer
exempts it.

### Behaviour

- **One deliberate difference, reachable only with corrupt data.** A
  `preferences` value that is not a JSON object now reads as "alerts on".
  Before, the notification fan-out raised `AttributeError` on it.
- **Measured against `7c5786e`:**
  - the OpenAPI document is byte-identical (`abc552ad…`, 271 routes);
  - the 91 limiter route keys and the 45 Celery task names are identical;
  - lint findings are unchanged in every touched file (the pre-existing
    unused `typing` imports aside).
- **Graph:** 0 layer violations and 0 module-level cycles. The component-level
  figure reads 24, not 20. The loop is made of components, and each hop uses
  a _different_ module of its component:

  1. `api` → identity (through `identity.dependencies`);
  2. identity → the `core.audit` group (through the sign-in _router_);
  3. that group → `reporting` (through `audit_retention` → `audit_export`);
  4. `reporting` → `scans` → `api`.

  No module-level path closes it. It would disappear if the identity
  component were split into its dependencies and its router, or if the
  activity log moved out of `core/` (the audit-log step).

**Tests:**

- `tests/auth/test_platform_api.py`: every function is checked against the
  query it replaced — missing ids, deleted and inactive accounts, the
  alerts-preference rule, and the permission rule by ORM user and by id.
- the Celery test for the moved screening tasks;
- the identity baselines, lowered at each batch.

## 11. Step 8.5 — as built

**Goal:** module code reaches identity through `ccure_platform.api`, with the
two WebSocket logins left for Phase 10 and the legacy paths kept working.

### Identity imports in module code, before → after

| Module                                                                                                                                                                                                                            | Before 8.5                                                                                                                                               | After                                                                                                                                       |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| 15 routers: `assets`, `compliance`, `config_audit`, `credentialed`, `credentials`, `dashboard`, `findings`, `health`, `phase_scans`, `remediation`, `reports`, `scan_policies`, `scan_schedules`, `topology`, `traditional_scans` | `auth.rbac.require_permission` (`reports`: `auth.dependencies.get_current_user_flexible`); `db.models.User`, as the annotation of the authenticated user | `ccure_platform.api`: `require_permission` / `current_user_flexible` (the same objects) and `CurrentUser`                                   |
| `routers.admin_nvd`                                                                                                                                                                                                               | `auth.rbac.require_role`, `db.models.User`                                                                                                               | `api.require_role`, `api.CurrentUser`                                                                                                       |
| `routers.scan_history`                                                                                                                                                                                                            | `auth.rbac.require_permission`, `auth.jwt_handler.decode_token`, `db.models.User`                                                                        | `api.require_permission` and `api.CurrentUser` for routes. **Kept:** `decode_token` and `User`, for the WebSocket ticket login              |
| `routers.web_scans`                                                                                                                                                                                                               | the same plus `auth.rbac.user_has_permission`                                                                                                            | `api.require_permission`, `api.user_has_permission`, `api.CurrentUser`. **Kept:** `decode_token` and `User`, for the WebSocket ticket login |
| `core.audit`                                                                                                                                                                                                                      | `db.models.User` (the actor's annotation)                                                                                                                | a local `AuditActor` protocol — `id`, `org_id`, `username`, exactly what the log reads                                                      |
| `core.tasks`                                                                                                                                                                                                                      | `auth.mail_tasks.*` ×5 (re-export)                                                                                                                       | **Kept** (below)                                                                                                                            |

**Counts:**

| Measure                  | Before 8.5 | After |
| ------------------------ | ---------- | ----- |
| Files importing identity | 20         | **3** |
| Direct identity queries  | 2          | **2** |
| Joins and eager loads    | 2          | **2** |

### What `ccure_platform.api` gained

One name: **`CurrentUser`**, the type a route annotates the authenticated user
with. It is the identity model itself (`CurrentUser is User`), and the API's
docstring says so rather than pretending otherwise.

Before, a route needed `from db.models import User` purely to write
`user: User = Depends(require_permission(...))`. Now a route depends on the
platform's name for the principal, not on where the model lives, so narrowing
it later (a view, or a separate authentication service, §3.9) changes one
line.

The ratchet treats it as the model it is. Importing `CurrentUser` is not an
identity import, but `db.query(CurrentUser)` or
`db.get(platform_api.CurrentUser, …)` counts as a direct identity query, and a
detector test proves it.

No function was added, and no Audit logic entered the API.

### Kept on purpose

- **`core.tasks` → `auth.mail_tasks`.** `core.tasks` re-exports the five mail
  tasks so the patch targets `core.tasks.send_*_task`, used by 8 tests, keep
  resolving. It is a legacy compatibility path, and 8.5 deletes no legacy
  path. It goes when the legacy paths do.
- **`routers.scan_history` and `routers.web_scans` → `decode_token` and
  `User`.** They authenticate a WebSocket ticket themselves: 2 queries and 2
  eager loads. That is gateway work, reserved for Phase 10 by the owner.

**The legacy paths all still work**: `auth.*`, `db.models.users` / `.rbac`,
`core.email_security_tasks` and `core.tasks.send_*_task`. Deleting them is not
part of Phase 8.

### Behaviour

- **URLs, permissions, roles, authentication, tokens and rate limits are
  unchanged.** Every dependency a route uses is the same function object as
  before, imported by another name.
- **FastAPI does not read a dependency parameter's annotation**, so
  `CurrentUser` changes nothing in the OpenAPI document.

**Verified against `d48770f`, the end of 8.4:**

- the OpenAPI document is byte-identical;
- the 91 limiter route keys and 45 Celery task names are identical;
- the live probe (login, refresh, logout, a missing token, a bad token on an
  identity route and a permission-guarded route) is identical after
  restarting all Python services.

**Architecture checks:** 0 layer violations, 0 module-level cycles, and the
component-level cycle figure is still 24.

### Phase 8 against its definition of done

- **No module imports `auth.*` or an identity model.** True, except the three
  kept imports above, each recorded in the baseline with its reason.
- **No module queries or joins an identity table.** True, except the two
  WebSocket logins reserved for Phase 10.
- **No module configuration lives on `organizations`.** Superseded by the
  owner's decision: the plan is platform-owned, and module code names no plan
  field (a ratchet at zero).
- **CI keeps all of this true.** The identity ratchets, the plan-field
  ratchet, the plan-feature containment test and the layer rules hold it.
- **Sign-in, quotas and scan scope behave exactly as before.** Verified at
  every step as above.

---
paths:
  - "Backend/ccure_platform/**"
  - "Backend/auth/**"
  - "Backend/routers/**"
  - "Backend/main.py"
  - "Backend/db/models/**"
  - "Backend/tests/rbac/**"
  - "Backend/tests/auth/**"
  - "Backend/scripts/rbac/**"
  - "Backend/scripts/security/**"
  - "Backend/data/rbac/**"
  - "gateway/**"
  - "Frontend/src/shell/auth/**"
  - "Frontend/src/shell/admin/**"
---

# Identity boundary, tokens, MFA, RBAC and platform extraction

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 493–620, 715–906) and is maintained here. Frozen original: `docs/archive/engineering-record/architecture-guardrails.md`, `docs/archive/engineering-record/identity-and-rbac.md`. The repository-wide rules in `CLAUDE.md` still apply.

**The identity boundary (Phase 8)** is a fourth ratchet,
`tests/repo/test_identity_boundary.py` over
`scripts/architecture/identity_boundary.py`.

- **What it counts.** Module code importing `auth.*` or an identity model (32
  files on 28 Sep 2026) and querying or joining an identity table (53 queries,
  8 joins). Each figure may only fall.
- **It is by symbol, not by edge.** `from db.models import User` and
  `from db.models import Scan` are the same edge. A layer rule therefore cannot
  hold this line, and `python -m scripts.architecture.identity_boundary` is
  how to see the sites.
- **`ccure_platform` is shared, never Audit's.**
  - `ccure_platform.api` may export only `PLATFORM_API_SURFACE`.
  - The package may import no Audit code or model
    (`platform-is-shared-foundation`).
  - Organisation scan scope and remediation SLA are **platform-owned**.
    `ccure_platform/organisation_settings/` owns their storage and exposes
    them through the platform API. Audit consumes them through
    `core.scan_scope` and `core.remediation.sla`; module code names no storage
    field. See `docs/architecture/ORGANISATION_SETTINGS.md`.
- **Owner (D6):** the Project Owner. `.github/CODEOWNERS` (Phase 11) records it,
  with placeholder handles until real ones are supplied — see "Core modules".
- **Tokens are signed and verified only in `ccure_platform.identity.tokens`**
  (Phase 9.1). No other module imports a JWT library.
  - Verify with `tokens.verify(token, expected_kind=…)`; the kind is required,
    so an endpoint cannot accept the wrong kind of token. Never check
    `payload.get("type")` by hand.
  - The any-kind `decode_token` is kept only for the rate-limit audit. The
    two WebSocket logins it served verify a ticket through
    `ccure_platform.api.websocket_user` since 2 Nov 2026.
  - `tests/repo/test_token_guardrails.py` enforces all of this.
  - **Live token issuance is ES256** since 29 Sep 2026 (step 9.4), with the
    promoted `active` key `7jKp…`. Tokens are signed only by `tokens.sign()`,
    which sets `iss`, `aud`, `ptype`, `nbf` and `jti` itself.
  - **HS256 is gone entirely (Phase 9.6c, 6 Oct 2026).** No HS256 issuance, no
    HS256 verification, no `JWT_SECRET_KEY`, no `CCURE_TOKEN_SIGNING_ALG`, no
    `CCURE_ACCEPT_LEGACY_HS256`. ES256 with a `kid` from the platform keyset is
    the only token signed or accepted; a token with no `kid` (every HS256 token
    ever issued) is refused as `missing_kid`. `verification.py` has no `legacy`
    parameter and `Refusal` no `legacy` field. **Do not reintroduce a symmetric
    path or a secret to "roll back" to**: a release rolls back with git.
  - **Deployed 6 Oct 2026, ~09:47–09:49 IST, from `3920908`** (development
    installation, `docker compose` with the base file, `docker-compose.development-rbac.yml`
    and `backups/native_clean_reset_20261004/preserve-runtime.compose.json`, with
    `CCURE_DEVELOPMENT_BACKEND_DIR` / `_FRONTEND_DIR` set). Order used: rebuild
    `gateway-auth` (its image bakes `verification.py`), then recreate `api`, then
    `worker`, `beat`, `web-worker`, then the frontend. Images: `gateway-auth`
    `7035a3b8d96a`, backend `4de065370b9b` (unchanged: code is bind-mounted),
    frontend `31dc0de3008d` (also tagged `9.6c-3920908`). **Rollback** is the
    `pre-9.6c` tag on each image plus `git revert`; there is no runtime switch.
    The api **requires `MFA_ENCRYPTION_KEY`** (compose `:?`) and refuses to start
    without it. Pre-deploy backups: `backups/ccure_db_20261006_092807_ops.dump` and
    `…092808_full.dump`.
  - **With no active key, the API refuses to start** — deliberately (design
    §3.7). There is no HS256 to fall back to; activate a key first.
- **Service identities (step 9.5) are not users.** They live in a static
  registry — `services.json` plus public keys, in `CCURE_SERVICE_REGISTRY_DIR`,
  read-only into the api — never in `users`, `roles` or any table.
  - **The flow.** A service authenticates at `POST /auth/service-token` with an
    assertion signed by **its own** key (RFC 7523). It receives a 10-minute
    ES256 `service_access` token: `aud` = the target service
    (`urn:ccure:core`/`urn:ccure:ir`), `sub` `svc:<id>`, one `tenant`, and
    least-privilege `scope`s.
  - **The registry.** Manage it only with
    `scripts/security/register_service_identity.py`. It refuses private keys
    and platform `kid`s. Changes take effect on an api restart.
  - **The dependencies.** `require_service_scope` and `service_principal_for`
    (`ccure_platform/service_identity/dependencies.py`) take the tenant from
    the verified token only — **never read `X-Tenant-ID`**. They stay out of
    `ccure_platform.api` until their first consumer, Phase 14.
  - **Live state.** The registry is empty; no service is registered. Phase 9
    doc §16.
- **The MFA key is explicit and has no fallback (step 9.2, 9.6c).**
  - `MFA_ENCRYPTION_KEY` derives the Fernet key for `users.totp_secret`. It was
    initialised to the retired JWT secret's value, so the key did not change
    (`scripts/security/verify_mfa_key_continuity.py` proves it without printing
    anything).
  - **Where it comes from.** Containers run with `SKIP_DOTENV_LOAD`, so
    `Backend/.env` is never read there: the value reaches the **api only**
    through the root `.env` and `docker-compose.yml`. Editing `Backend/.env`
    changes nothing in a container.
  - **Never change `MFA_ENCRYPTION_KEY`**: every stored MFA secret would become
    undecryptable.
  - **Unset, the API refuses to start** (`main.py`); `AppConfig.MFA_KEY` is empty
    rather than a key derived from `""`.
  - **Workers hold no secrets of this kind.** `worker`, `beat` and `web-worker`
    get neither `JWT_SECRET_KEY` (gone) nor `MFA_ENCRYPTION_KEY`, set
    `SKIP_DOTENV_LOAD=1`, and have `/app/.env` masked by a `/dev/null` bind so
    the `./Backend` mount cannot hand them `Backend/.env`. **Masking one file is not
    enough**: any `Backend/.env.bak-*` is readable from every worker and holds the same
    secrets, so dotenv backups live outside the tree (`~/ccure-secret-backups/`, mode 700) and a test fails if one reappears.
- **Routes annotate the authenticated user as `ccure_platform.api.CurrentUser`**
  (step 8.5) and take `require_authorized` /
  `current_user_flexible` from the API, never from `auth.*` or `db.models`.
  No identity import remains in module code (`KNOWN_IDENTITY_IMPORTS` is
  empty): both WebSocket ticket logins, the scan history's and web DAST's,
  ask `ccure_platform.api.websocket_user`, and the `core.tasks` mail-task
  re-export went with the facade (all 2 Nov 2026).
- **Module code asks `ccure_platform.api` (since step 8.3)**, never
  `users`/`organizations`/`roles` directly:
  - `api.user()` and `api.organisation()` return frozen views;
  - `api.has_permission(db, account, key)` is the engine's answer. Never hand-copy a
    superadmin or role check.
  - **Organisation settings are platform-owned:** authorised scan scope and
    remediation SLA live in `ccure_platform/organisation_settings/`, one
    module per setting. Audit consumes each through **one seam**:
    `core.scan_scope` and `core.remediation.sla`.
    `tests/repo/test_organisation_settings_containment.py` enforces this.
  - **Platform owns configuration; Audit applies it.** The platform holds
    authorised ranges and configured deadlines. Audit admits targets and
    computes due dates. `OrganisationView` carries identity only; a ratchet
    keeps direct setting storage references in module code at zero.
  - **An endpoint's docstring is its OpenAPI description.** Editing one
    changes the published API document; put notes in comments.
- **Identity's code lives in `ccure_platform` since step 8.2.**
  - **The moves:**
    - `auth/*` → `ccure_platform/identity/`;
    - `auth/rbac.py` → `ccure_platform/rbac/dependencies.py`;
    - `db/models/users.py` and `rbac.py` → `ccure_platform/models/`.
  - **Old paths are stubs.** Every `auth/…` path named elsewhere in this file
    is now a stub aliasing the same module object
    (`ccure_platform/_legacy.py`, `MOVED_MODULES`).
  - **Moved modules keep their legacy `__name__`.** That keeps logger names,
    limiter route keys (`auth.router.login`) and class `__module__` unchanged.
    Do not "fix" this in passing. Renaming them is its own change.
  - **Edit the files under `ccure_platform/`,** never the stubs.
  - **Import rule.** Platform code never imports `auth.*` or
    `db.models.users`/`rbac` (`platform-does-not-use-legacy-paths`). It
    imports models through the `db.models` registry.


## RBAC capability (`ccure_platform/rbac/`) — **the only authorization model since RBAC-8**

The Platform RBAC capability. Records:
[`docs/architecture/RBAC_FOUNDATION.md`](docs/architecture/RBAC_FOUNDATION.md) and, for the
final cutover, [`docs/architecture/RBAC_CUTOVER.md`](docs/architecture/RBAC_CUTOVER.md).
**RBAC-8 made Platform RBAC the sole authority in code**: `require_authorized(key)` /
`has_permission(db, account, key, org_id=)` answer from the engine and nothing else. There is
no legacy fallback, no authority switch (`RBAC_AUTHORITY_*` are gone), no shadow mode, no
`require_permission` / `require_role` / `user_has_permission`, no role-name decision (the
role-name ratchet is **empty and stays empty**) and no read of `users.role_id`.
`tests/repo/test_rbac_final_ratchet.py` fails if any of it returns.

**Current state (native RBAC, since the clean development reset of 4 Oct 2026).** The
installation in `ccure_db` is explicitly a **development** installation, and it was
reset on purpose: record `backups/native_clean_reset_20261004/final-report.md`, revision
`d4f8b2c6e0a1`. The database now holds **1 organisation** (`CCURE Development`,
`org_development`), **1 user** (the bootstrap platform administrator), the six `rbac_*`
tables with **5 system roles, 67 permissions and 1 assignment**, and no scans or assets.
`users.role_id` and the legacy `roles`, `permissions`, `role_permissions` and
`rbac_legacy_map` tables **no longer exist**; historical Alembic migrations that created
them are unchanged and are history. There is no cutover to perform: `cutover.py`, the
golden mapping and the cutover checklist were removed with the legacy model. Anything
below that says "legacy atoms" or "golden mapping" describes how the catalogue was
derived and is **historical**. A production installation would be created native, not
migrated.

- **Provisioning** (`rbac/provisioning.py`): a self-registered account gets the configured
  `rbac_default_roles` role only if it is valid (active, organisation-assignable,
  non-privileged) — otherwise **no role**; the first platform administrator is made only by
  first-run bootstrap or the operator's `bootstrap_admin.py` (idempotent, audited, refuses a
  system that already has one, no permanent bypass); a new organisation's first administrator is
  assigned through the governed assignment API in the same transaction. Users with no assignment
  hold nothing. Recovery of a lost last administrator is the explicit, audited operator script.
- **Test seam.** No account receives a role implicitly in tests either. `tests/native_rbac.py`
  is the fixture API: `create_user`, `system_role(db, key)` for a seeded role by its native
  key, and `fixture_role(db, label, keys=…)` for a custom platform role holding exactly the
  grants a test needs. The suite seeds the catalogue and system roles once per session;
  `rbac_db` TRUNCATEs the `rbac_*` tables inside its rolled-back transaction so RBAC tests
  start empty. (The legacy `role_id` / `RolePermission` listeners went with RBAC-8.)

- **A role is `id` + `key` + `display_name`, and none of them is an authorization
  input** — not the name, not the key (`platform.viewer`), not a legacy role name.
  `engine.decide` is handed _grants_, and `Grant` has no role field. A role is only a
  join path the resolver walks to find permission keys. **Never write
  `role.name == …`, `role.key == …` or `require_role(…)` in new code.**
  `tests/repo/test_rbac_role_identity.py` fails on any new one; the legacy sites
  (0 since RBAC-8, `scripts/architecture/rbac_guardrails.py`) stay at zero. Role keys may be written in `rbac/contract.py` (seed data), the
  legacy map and migrations, bootstrap and tests only.
- **RBAC does not know the modules.** It imports no product (`rbac-is-module-agnostic`),
  does not read the registry and does not import `ccure_platform.api`. Modules
  declare permissions as **data** (`PermissionDecl`, exported by `ccure_platform.api`)
  in a module named by `permission_modules` in their `manifest.toml`; the composition
  root (`ccure_platform/composition.py`) loads it by name and calls
  `rbac.catalogue.sync`. A permission namespace (`audit`, `policy`, `rank`, `ir`,
  `platform`) is platform-owned, in the registry. Modules reach RBAC through
  `ccure_platform.api` only (`modules-use-rbac-api-only`) and never name an `rbac_*`
  table (`rbac-tables-are-private`).
- **Superadmin is permissions plus scope.** There is no wildcard and no
  "if superadmin then allow": a role holding everything holds _materialised grant
  rows_ that catalogue sync inserts (`auto_grant_new_permissions`, which the engine
  never reads).
- **Display names are labels.** Renaming "Superadmin" to "CISO" changes nothing; a
  fuzz test proves a role named `Superadmin` gains nothing. Names are unique among
  live roles within a namespace, so a swap needs two steps.
- **No hard delete.** Roles are retired (`active → retiring → retired`), never
  deleted; role history is append-only; assignments are revoked, never rewritten.
  Triggers enforce this, and the table SQL and trigger SQL in the migration are
  tested equal to the models'.
- **Continuity is capability-based and says "not assessable" rather than "ok"** when
  nothing is declared.
- **Tests never commit.** `tests/rbac/` uses `rbac_db` from `tests/rbac_testing.py`
  (rolled back). The `rbac_*` tables are `ON DELETE RESTRICT` against `organizations`
  and `users`, so a committed row would fail the suite's per-test purge in an
  unrelated test. It is not a `conftest.py` because `test_schema_drift` does
  `import conftest`.
- **RBAC-2 populated the catalogue and role model — prepared, not live.** 67
  permissions: 30 `platform.*` (`ccure_platform/permissions.py`) and 37 `audit.*`
  (`ccure_audit/permissions.py`), declared as data through the manifest seam. Every key,
  its owner, scope, sensitivity, reason and legacy source is in
  [`docs/architecture/RBAC_PERMISSION_CATALOG.md`](docs/architecture/RBAC_PERMISSION_CATALOG.md).
  Keys are **capability-level** and come from what the code enforces, not from the old
  vocabulary; **no key is invented for a future feature** (Policy Pro, Rank, IR declare
  nothing). Verb vocabulary is settled: `read` for reading, domain verbs elsewhere.
- **The golden legacy mapping is history.** It mapped **66 legacy atoms** (65 seeded plus
  `audit_logs:read`) as 50 mapped, 6 replaced, 10 retired, and is how the catalogue was
  derived. `golden_legacy_mapping.json`, `rbac/legacy_map.py` and the `rbac_legacy_map` table
  were removed with the legacy model (`86e105b`, 3 Oct 2026; migration `d4f8b2c6e0a1`); git
  history has them. Nothing reads or tests them now.
- **The catalogue reaches a database only through `scripts/rbac/sync_catalogue.py`** (dry
  run unless `--apply`; validates before it writes; synchronises the declared catalogue and
  the frozen system grants). It is **not** wired into start-up: a failure
  there would stop the API for a dark capability. Back up first (`scripts/backup_db.sh
--skip-reference-data`) before `--apply` on a real database.
- **RBAC-4/RBAC-8: the authority switch and the legacy fallback are deleted.** The inventory
  (`data/rbac/authorization_migration_inventory.json`, generated by
  `python -m scripts.rbac.build_migration_inventory --write`, tested) lists every guard (all
  `migrated`), the kept compatibility records and the removed role-name sites.
- **RBAC-5 = scope** (`rbac/scope.py`, `docs/architecture/RBAC_SCOPE.md`).
  Permission is WHAT, scope is WHERE. Acting outside the home organisation is the
  platform-scope grant of `platform.organization.switch` (superadmin holds it through grants,
  no shortcut); an organisation administrator never crosses. Module code asks
  `ccure_platform.api`: `resolve_active_organisation` (replaced every `_resolve_org` /
  `role == superadmin` copy), `acts_across_organisations`, `resource_organisation_allowed`
  (resource organisation read from the stored row), `check_role_assignment`, and
  `user_has_permission(..., org_id=)` for `read_all` (organisation-wide, never
  cross-organisation). Switch, denied scope and refused escalation are audited
  (`rbac.org_switch.entered`, `rbac.scope.denied`, `rbac.escalation.refused`). Missing,
  inactive or unknown organisations fail closed. Paths `scope.active_organisation`,
  `scope.cross_organisation`, `scope.assign_role`. (At RBAC-5, 9 role-name sites remained; RBAC-7/8 removed them and the topology router's, found later, went on 6 Oct 2026.)
- **RBAC-6/8 = frontend authorization** (`docs/architecture/RBAC_FRONTEND_AUTHORIZATION.md`).
  `/auth/me` carries `authorization` (`rbac/authorization_view.py`): permission keys by scope,
  the validated active organisation, `can_switch_organisation` and display-only assignments (no
  legacy atoms, role or role id). The UI's one helper is `Frontend/src/shell/auth/authorization.js`
  (`can(user, key, {scope, orgId})`): no role is an input, no wildcard, nothing invented;
  `isSuperAdmin`/`hasRole` and `superadminOnly` are gone. Switching goes through the backend
  (`GET /auth/me?org_id=`). A backend without the contract is reported as incompatible
  (`authState = "incompatible"`); there is no older-backend fallback. `Frontend/authorization-inventory.json` (generated, tested) classifies
  every remaining site (RBAC-7/8, display-only, retained). The frontend is advisory; the backend
  enforces.
- **RBAC-7 = Platform RBAC administration** (`docs/architecture/RBAC_ADMINISTRATION.md`):
  `/platform/rbac/*` (`administration/rbac_admin.py` over `rbac/administration.py`) governs roles,
  permissions, custom organisation roles, lifecycle/replacement and assignments with the RBAC-2
  rules; display names are labels; sensitive changes need step-up (`identity/reauth.py`,
  `X-Reauth-Code`); refusals and mutations are audited. Every users/organizations/roles/settings/
  audit-log route asks one granular key through `require_authorized`;
  the compliance emergency bypass is `audit.compliance.approve_exception` (no new permission).
  Frontend: the Roles page and the user Roles panel are catalogue- and backend-driven;
  `frontend authorization-inventory.json` has no rbac7 site left.
- **Audit attribution: an event says who owns it, and nothing is ever attributed to an
  invented organisation.** `audit_logs` is tenant-bound (`org_id` NOT NULL). An event with an
  owning organisation (an organisation role; an organisation-scope assignment; a
  platform-scope assignment, owned by the **member's own** organisation; a user purge) goes
  to that organisation's `audit_logs`; one with no owner (catalogue sync, permission
  lifecycle, system or platform-scope roles, the default role) goes to the append-only
  `platform_audit_events` ledger via `log_platform_event`. `EventDraft.org_id` has no
  default; `rbac.audit.emit` routes by it. The ledger is **not hash-chained** (a DBA
  bootstrap, later) — a recorded limit.
- **User purge is handled by RBAC's offboarding hook** (`rbac/offboarding.py`, registered
  when the purge route's module is imported): it records each assignment in the audit trail
  (with the display name _at that moment_) and removes the rows before the user is deleted.
  `ON DELETE RESTRICT` is unchanged.
- **A role's state change cannot be silent**: the database refuses it unless `revision`
  advances in the same statement. Use `governance.transition_role` (gate + history), or in
  tests `rbac_testing.force_state`. `define_custom_org_role` is the checked way to make an
  organisation role.
- **Shadow authorization (RBAC-3) is retired.** There is no dual authority to compare; the code
  (`rbac/shadow*.py`, the `_observe_*` hooks, `RBAC_SHADOW_*`) is deleted.
- **The 40 role-name sites** are all gone; their history is `Backend/data/rbac/role_name_site_decisions.json`.
- **RBAC emits severities lazily** (on its first event), so a process that ran RBAC code has
  `rbac.*` in the merged audit taxonomy; the two audit tests that pin the platform+Audit set
  exclude that source.

## Backend platform extraction (backend alignment, steps 1–2)

The platform's backend now matches the frontend's Platform Shell. Record:
[`docs/architecture/BACKEND_PLATFORM_EXTRACTION.md`](docs/architecture/BACKEND_PLATFORM_EXTRACTION.md).

- **Moved into `ccure_platform/`:** the audit-log service (`audit_log/`: writer,
  taxonomy, retention, export, router, task), notifications (`notifications/`),
  user/organisation/role/email-domain administration (`administration/`) and
  account/profile/preferences (`identity/profile.py`). Paths, permissions,
  OpenAPI, Celery names and the beat schedule are unchanged; the legacy module
  names are aliases of the same module objects (`MOVED_MODULES`), and the moved
  modules keep their legacy `__name__`.
- **`ccure_platform` imports no Audit code and no Audit model, and has no ORM
  relationship into a module's tables.** Audit reaches it through
  `ccure_platform.api` (`log_audit_event`, `create_notification`, …).
- **A purge asks, never reaches in.** `purge_user` runs
  `run_user_purge_hooks`; Audit's hook is `ccure_audit/offboarding.py`, imported
  by `main.py`. A new module that records who did something registers its own.
- **Do not move a file on its name.** `core/audit_event_translator.py` is Audit's
  asset-timeline code, not the audit log.
- **Preferences are namespaced.** `users.preferences` holds the platform's keys
  and, under `products.<product>`, each product's own block, which the product
  registers and validates (`ccure_platform/preferences.py`; Audit's is
  `ccure_audit/preferences.py`, imported by `main.py`). `default_scan_type` is
  Audit's; `/user/preferences` still returns and accepts it flat for old clients.
- **Notification vocabulary is the product's.** Audit's types and the `scan`
  category are `scans/notification_vocabulary.py` (registered category; the platform
  stores plain strings). `related_scan_id` stays for compatibility.
- **Audit-event severities are the product's.** Audit's definitions are
  `ccure_audit/audit_events.py`, declared in its manifest (`audit_event_modules`) and
  loaded by name by the platform in every process that writes an event; declared
  definitions that cannot load raise instead of defaulting.
- **Boundary review (3 Oct 2026):** `docs/architecture/PLATFORM_AUDIT_BOUNDARY_REVIEW.md`
  — no platform → Audit import, relationship or query; remaining items classified;
  `tests/repo/test_legacy_alias_importers.py` keeps legacy paths out of module code.
- **Still open:** Audit-shaped permission atoms in the
  platform's tables. Classified in
  [`docs/architecture/PLATFORM_AUDIT_VOCABULARY.md`](docs/architecture/PLATFORM_AUDIT_VOCABULARY.md);
  `tests/repo/test_platform_audit_vocabulary.py` lets it only fall.

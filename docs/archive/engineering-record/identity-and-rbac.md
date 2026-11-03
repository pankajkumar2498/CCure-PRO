# Engineering record: RBAC capability and backend platform extraction

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 715–906, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 715-906 -->
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

<!-- /verbatim -->

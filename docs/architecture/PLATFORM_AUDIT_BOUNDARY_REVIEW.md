# Platform / Audit boundary review (backend alignment, follow-up 7)

|            |                                                                                                                                                                 |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status** | Review, 3 Oct 2026, at `14c6765`. One test added; **no production code changed.**                                                                               |
| **Scope**  | `ccure_platform` against `ccure_audit` and Audit's code (`routers/`, `scans/`, `core/`, `engines/`, `orchestrator/`, `reporting/`).                             |
| **Result** | The boundary holds in every direction that was checked. What is left is documented and ratcheted; nothing found needs a code change to complete the extraction. |

## 1. What was checked, and how

| #   | Question                                                          | How                                                                                                                                                                  | Result                                                                                                                                                                                                                                                                                                                                                               |
| --- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | Does the platform import Audit implementation?                    | The import graph with the layer rules (`python -m scripts.architecture.import_graph --violations`), including function-level imports                                 | **0 violations.** The only dynamic imports in `ccure_platform` are `modules/registry.py` (manifest dotted names) and `audit_log/taxonomy.py` (a manifest-declared definitions module) — data, not references                                                                                                                                                         |
| 2   | Does a platform model have an ORM relationship into Audit tables? | `tests/repo/test_platform_extraction.py` (relationship targets), re-read by hand                                                                                     | **None.** `User` and `Organization` carry no relationship to a module's table; Audit keeps one-way links                                                                                                                                                                                                                                                             |
| 3   | Does the platform query Audit-owned tables?                       | All 46 Audit-owned tables from `table_ownership.yaml` mapped to their 46 model classes; every name, import and SQL string in `ccure_platform/**.py` checked          | **No reference** — not a class, not an import, not a `FROM`/`JOIN`/`UPDATE`/`DELETE` of an Audit table. A user purge reaches Audit's data only through the offboarding hook                                                                                                                                                                                          |
| 4   | New Audit vocabulary beyond the ratcheted contracts?              | `tests/repo/test_platform_audit_vocabulary.py`                                                                                                                       | **175 → 108** code-level hits in 11 files, all classified (§3); the ratchet only falls                                                                                                                                                                                                                                                                               |
| 5   | Duplicated models?                                                | `tests/repo/test_platform_identity_move.py` (each identity table defined in exactly one file, mapped once)                                                           | **None.**                                                                                                                                                                                                                                                                                                                                                            |
| 6   | Duplicated services / logic?                                      | Functions over 400 AST characters compared by normalised body, platform against the rest of the backend and within the platform                                      | **Two tiny helper duplicates, no service:** `_is_superadmin` (in two platform routers, ten Audit routers and `scans/scan_access.py`), `_role_name` (`administration/organizations.py`, `routers/topology.py`); and `password_strength` defined three times inside platform code (twice in `identity/router.py`, once in `administration/users.py`). Classified in §3 |
| 7   | Old router implementations left behind?                           | `tests/repo/test_platform_extraction.py`: every legacy router/service file defines no function or class                                                              | **None.** `routers/admin_*.py`, `routers/audit.py`, `routers/notifications.py`, `routers/user_profile.py` and `core/audit*.py`, `core/notifications.py`, `reporting/audit_export.py` are alias stubs                                                                                                                                                                 |
| 8   | Do the legacy aliases point at the canonical modules?             | `tests/repo/test_platform_identity_move.py` (26 aliases, both import orders, `__name__`, `__spec__`)                                                                 | **Yes**, all 26                                                                                                                                                                                                                                                                                                                                                      |
| 9   | Is `ccure_platform.api` the only cross-module channel?            | `scripts/architecture/identity_boundary.py` (module code importing `ccure_platform` internals or identity models) and a scan of Audit packages for legacy stub paths | Audit code imports only `ccure_platform.api`, except the **three ratcheted imports** (`routers/scan_history.py` and `routers/web_scans.py` decode a WebSocket ticket token; `core/tasks.py` re-exports the mail tasks) and two direct `User` queries. Nothing in module code imports an extracted legacy path (new ratchet, §4)                                      |
| 10  | Table ownership, route inventory, module boundaries               | `tests/repo` (`test_architecture_guardrails`, `test_module_boundaries`, `test_gateway_route_policy`) and the endpoint inventory in `tests/security`                  | Pass                                                                                                                                                                                                                                                                                                                                                                 |

## 2. The cross-module channels that exist

Everything one side asks of the other goes through one of these:

- `ccure_platform.api`: identity, RBAC, accounts, the organisation plan,
  `log_audit_event`, `create_notification` and its category registration,
  `register_user_purge_hook`, `register_product_preferences`,
  `register_event_severities`.
- The module manifest (`ccure_audit/manifest.toml`): where the platform finds
  Audit's audit-event definitions, loaded by name.
- Audit's registrations at start-up (`ccure_audit/offboarding.py`,
  `ccure_audit/preferences.py`, `scans/notification_vocabulary.py`,
  `ccure_audit/audit_events.py`).

Each registration is a single function with one purpose; there is no general
plug-in system.

## 3. Known remaining items — classified only, none fixed

| Item                                            | What it is, with evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Class                       | Pre-existing?                     |
| ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | --------------------------------- |
| **AMT permission mismatch**                     | `POST /assets/import-amt` requires `settings:update`, and the sidebar item is gated on `settings:update`, but the frontend route `/admin/amt` is gated on `assets:update`. An analyst (holds `assets:update`, not `settings:update`) can open the page by URL; the backend refuses the import. Backend is the correct, stricter side; the frontend route gate is too loose.                                                                                                                              | Audit-internal RBAC, UI     | Yes                               |
| **Platform denied-route fallback**              | A route a user is refused (`/admin/*` for an analyst or org-admin) falls back to the first page in Audit's `AUDIT_ACCESS_FALLBACKS` (`/audit-dashboard`), so a refused _platform_ page lands the user inside Audit. The rule (D12-8) predates the platform shell and keeps the fallback list in Audit's `accessFallbacks.js`.                                                                                                                                                                            | Frontend routing, platform  | Yes (D12-8)                       |
| **Sign-in branding**                            | "CCure Audit PRO" in the reset-password email subject, the mail template and the TOTP issuer name (`identity/mail_service.py`, `identity/router.py`); the sign-in screens are still `PENDING` in `modules.config.js`. The TOTP issuer is baked into enrolled authenticator entries.                                                                                                                                                                                                                      | Platform branding (D12-9)   | Yes                               |
| **Module-RBAC permission atoms**                | 48 of 65 `permissions` rows are Audit's (`scans:*`, `assets:*`, `findings:*`, `compliance:*`, `credentials:*`, `scan_policies:*`, `scan_schedules:*`, `reports:*`, `dashboard:*`), seeded by `db/migrate_production_schema.py`; read by roles, the roles screen and the frontend's `can()`. `ccure_platform` names none (pinned).                                                                                                                                                                        | RBAC data (D11-1, Phase 18) | Yes                               |
| **Remaining Audit vocabulary**                  | 108 hits in 11 files: the organisation plan (`plan/`, `administration/organizations.py`, `models/rbac.py`, `api.py`: owner decision), `related_scan_id` (notifications service and router: persisted column and API), `organization.scan_scope_changed` (the plan's event), and `retro_scan_email_risk` (not Audit's). Each is in the ratchet baseline with its reason.                                                                                                                                  | Contracts / owner decision  | Yes, narrowed by follow-ups 3–6   |
| **Frontend shell vocabulary**                   | The notification panel maps Audit's type names to icons and lists `scan` as a tab; the shell is otherwise product-free. The backend no longer holds that vocabulary; the frontend contract is unchanged.                                                                                                                                                                                                                                                                                                 | Frontend contract           | Yes                               |
| **Remaining platform/Audit coupling**           | (a) the three ratcheted Audit→identity imports and two `User` queries (`identity_boundary.py`); (b) database foreign keys from Audit tables to `users`/`organizations` (by design); (c) the platform's shared-infrastructure exemptions (`core.celery_app`, `core.rate_limiter`, `core.redis_client`, `core.ip_resolver`, `core.throttle`, `core.upload_guard`, `core.user_agent`, `reporting.report_helpers`); (d) the composition root `main.py` imports platform internals and Audit's registrations. | Documented / by design      | Yes                               |
| **Duplicated helpers**                          | `_is_superadmin` ×13, `_role_name` ×2, `password_strength` ×3 (§1 row 6). The platform's `user_has_permission` is the one implementation of the permission check; the role-name tests are tiny copies, not a second authorisation path.                                                                                                                                                                                                                                                                  | Cleanup candidate           | Yes                               |
| **Obsolete-looking compatibility code**         | 20 of the 26 legacy aliases have no importer in module code (§4). They are kept on purpose: tests, patch targets, operator scripts and one old migration (`alembic/versions/c2d3e4f5a6b7`, which must not be edited) still name them, and the moved modules keep their legacy `__name__` for logger names and limiter keys. Removal goes with the later logger-name and limiter-key rename.                                                                                                              | Deliberate                  | Yes                               |
| **`scans/notification_vocabulary.py` location** | Audit's notification vocabulary sits under `scans/` rather than `ccure_audit/` because `scans` may not import `ccure_audit` (layer rule) and `scans/db_helpers.py` is the producer. It moves when Audit's code does (Phase 16).                                                                                                                                                                                                                                                                          | Legacy location             | New in follow-up 5, by constraint |

## 4. The added guard

`tests/repo/test_legacy_alias_importers.py` counts, per legacy alias, the module-code
files that import it (not tests, `scripts/` or `alembic/`). The 20 aliases of the
audit-log, notification, administration and profile moves have none, and the six
that do are listed with the reason. A new importer fails the test, and so does a
listed one disappearing without the list being lowered.

## 5. What this review did not do

It fixed none of §3. It did not run the full suites or deploy: the final
verification is a separate step.

## 6. Resolved after the review (platform/product boundary and UX cleanup)

Four of the items classified in §3 were fixed in one small change:

- **AMT permission mismatch.** The `/admin/amt` route was gated on `assets:update`
  while the sidebar item and the API (`POST /assets/import-amt`, the page's one
  action) use `settings:update`. Both now use one constant, `AMT_PERMISSION`
  (`modules/audit/config/permissions.js`) = `settings:update`. An analyst, who holds
  `assets:update` but not `settings:update`, can no longer open the page by URL; an
  org admin and a superadmin still can. No permission definition changed.
- **Platform denied-route fallback.** A refused `/admin/*` route no longer
  redirects to Audit's dashboard: `PrivateRoute` takes an optional `deniedElement`,
  and the platform's administration routes pass `shell/pages/AccessDenied.jsx`, which
  renders in the Platform Shell with a way back to CCure Home. Unauthenticated
  visitors still go to `/login`; Audit's refusals (AMT among them) still fall back
  to an Audit page.
- **Platform authentication branding.** The five account emails (password reset,
  MFA code, email verification, password changed, account approved) and the TOTP
  issuer said "CCure Audit PRO"; they say "CCure". Behaviour, tokens, MFA secrets
  and delivery are unchanged (only the issuer label in the provisioning URI for new
  enrolments). **Not changed:** the sign-in screens' own brand marks and legal copy
  (`src/pages/*`, D12-9) and the audit-trail PDF title/author
  (`audit_log/export.py`, "CCure Audit PRO - audit trail export").
- **Frontend shell notification vocabulary.** Audit's type icons and tones and its
  `Scans` tab moved from `shell/notifications/NotificationsPanel.jsx` to
  `modules/audit/config/notificationPresentation.js`, supplied by the composition
  root through `NotificationPresentationProvider`. The panel is generic: an unknown
  type renders with a neutral icon. Display with Audit's presentation is unchanged,
  including the tab order.

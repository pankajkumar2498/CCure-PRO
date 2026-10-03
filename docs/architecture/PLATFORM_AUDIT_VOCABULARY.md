# Audit vocabulary inside `ccure_platform` (backend alignment, follow-up 3)

|              |                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**   | Inventory and classification, 3 Oct 2026. Item 1 (`default_scan_type`) was **resolved by follow-up 4** (preference namespacing, §7); the rest unchanged. One ratchet test (`tests/repo/test_platform_audit_vocabulary.py`).                                                                                                                                                                       |
| **Goal**     | `ccure_platform` independent of Audit's implementation **and** vocabulary, existing behaviour preserved.                                                                                                                                                                                                                                                                                          |
| **Result**   | Implementation independence is already enforced (layer rules, no Audit models, no ORM relationships — [`BACKEND_PLATFORM_EXTRACTION.md`](BACKEND_PLATFORM_EXTRACTION.md)). What remains is **vocabulary**, and every item is persisted data, a public or frontend contract, or an owner decision. None is safe to rename without a migration, and each belongs to a design that is decided later. |
| **Not done** | The AMT permission mismatch and the platform denied-route fallback were **not touched** (instructed). Persisted permission atoms were **not renamed**. Follow-ups 4 and 5 were not started.                                                                                                                                                                                                       |

## 1. Method

Every string constant, identifier, attribute, keyword and column name in
`ccure_platform/**.py` matching Audit's domain words (`scan`, `asset`,
`finding`, `vulnerab`, `compliance`, `remediation`) was listed — docstrings and
comments excluded — and each hit traced to what it is stored as and who sees it.
175 occurrences in 12 files. Persisted values were counted in the live database.

## 2. Classification

| #   | Item                                                                                                                                                                                                                                                                                                                                                                                                                             | Where                                                                                                        | Persisted data                                                                  | Public API | Frontend |               Celery / event id               | Internal only | Class → decision                                                                                                              |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | :--------: | :------: | :-------------------------------------------: | :-----------: | ----------------------------------------------------------------------------------------------------------------------------- |
| 1   | ~~`default_scan_type` and its allowed values~~ — **resolved by follow-up 4** (§7): Audit owns it (`ccure_audit/preferences.py`); `identity/profile.py` no longer names it. The stored key and the API key are unchanged                                                                                                                                                                                                          | `users.preferences` (JSONB), 5 of 10 users                                                                   | yes                                                                             |    yes     |    —     |                       —                       |   **Done**    |
| 2   | ~~Notification types `scan_completed`, `scan_failed`, `scan_paused`, `vulnerability_found`; category `scan`~~ — **resolved by follow-up 5** (§8): Audit's are `scans/notification_vocabulary.py`; the platform's enums hold only `system_message`/`admin_notice` and `security`/`system`/`admin`. Stored values unchanged (`notifications.type`, `.category`)                                                                    | `notifications.type`, `.category`                                                                            | yes                                                                             |    yes     |    —     |                       —                       |   **Done**    |
| 3   | `related_scan_id`                                                                                                                                                                                                                                                                                                                                                                                                                | `notifications/service.py`, `router.py`                                                                      | `notifications.related_scan_id` column                                          |    yes     |   yes    |                       —                       |       —       | Persisted column + API → **leave; follow-up 5**                                                                               |
| 4   | ~~Audit event names (`scan.*`, `web_scan.*`, `finding*`, `credential.*`, …) → severity~~ — **resolved by follow-up 6** (§9): Audit's 63 definitions are `ccure_audit/audit_events.py`, registered with the platform and loaded by name in every process; the platform's table keeps its 47 (`user.*`, `organization.*`, `admin.*`, `auth.*`, `audit.*`, `service.*`). Stored `audit_logs.action` and `severity` values unchanged | `audit_logs.action`, `.severity`                                                                             | (viewer)                                                                        |  (viewer)  |    —     |                       —                       |   **Done**    |
| 5   | Permission atoms `scans:*`, `assets:*`, `findings:*`, `compliance:*`, `credentials:*`, `scan_policies:*`, `scan_schedules:*`, `reports:*`, `dashboard:*`                                                                                                                                                                                                                                                                         | rows in `permissions` (48 of 65 atoms); seeded by `db/migrate_production_schema.py`, not by `ccure_platform` | `permissions`, `role_permissions`                                               |    yes     |   yes    |                       —                       |       —       | RBAC data + API + frontend (`can(resource, action)`) → **leave; module-RBAC phase (D11-1 / Phase 18)**                        |
| 6   | Organisation plan: `max_assets`, `max_scans_per_day`, `max_concurrent_scans`, `scan_scope_cidrs`, `/…/scan-scope`, `ScanLimits`, `scan_scope`, `remediation_sla`                                                                                                                                                                                                                                                                 | `plan/`, `administration/organizations.py`, `models/rbac.py`, `api.py`                                       | `organizations` columns                                                         |    yes     |   yes    |                       —                       |       —       | Owner decision, 29 Sep 2026 (platform-owned, one seam per feature) → **leave**; recipes in `PHASE8_4_ORGANISATION_PLAN.md` §9 |
| 7   | `max_assets=100` for a self-registered organisation                                                                                                                                                                                                                                                                                                                                                                              | `identity/router.py`                                                                                         | `organizations.max_assets`                                                      |     —      |    —     |                       —                       |       —       | Plan default → **leave** with #6                                                                                              |
| 8   | "CCure Audit PRO" in the reset-password email subject and the TOTP issuer name                                                                                                                                                                                                                                                                                                                                                   | `identity/mail_service.py`, `identity/router.py`                                                             | no (the TOTP issuer label is baked into already-enrolled authenticator entries) |  (email)   |    —     |                       —                       |       —       | User-visible branding → **leave; sign-in branding decision (D12-9)**                                                          |
| 9   | `retro_scan_email_risk` / "retro-scan"                                                                                                                                                                                                                                                                                                                                                                                           | `identity/email_security_tasks.py`                                                                           | —                                                                               |     —      |    —     | task name `ccure.tasks.retro_scan_email_risk` |       —       | **Not Audit's**: it re-screens accounts for shared mailboxes. A name collision; the task name is an API.                      |
| 10  | Docstrings and comments mentioning scans, assets, findings (e.g. `rbac/dependencies.py`, `notifications/router.py`)                                                                                                                                                                                                                                                                                                              | various                                                                                                      | —                                                                               |     —      |    —     |                       —                       |      yes      | Prose, no coupling → **leave**                                                                                                |

**RBAC-1 addendum (3 Oct 2026).** The new RBAC capability (`ccure_platform/rbac/`,
[RBAC_FOUNDATION.md](RBAC_FOUNDATION.md)) is the module-RBAC phase item 5 defers to,
and it keeps Audit's vocabulary out: it declares no atom and names no product. One
exception is recorded in the ratchet's `BASELINE`: `rbac/contract.py` carries four
code-level strings for the legacy `scanner` role — its frozen key `platform.scanner`,
its seeded display name and the legacy-name map. It is the role's own name (a
persisted value the RBAC-0 design froze), not Audit logic; the descriptions around it
were reworded to avoid the domain words.

RBAC-2 adds one more: `permissions.py` carries one code-level string, the key
`platform.organization.set_scan_scope`. The organisation's scan scope is a
platform-owned plan feature (owner decision, 29 Sep 2026), and this is the permission
that guards it — the legacy route checks the role name instead.

What is **not** here, and was checked: `ccure_platform` calls `require_permission`
and `user_has_permission` only with whatever `(resource, action)` its callers pass
and names no Audit atom itself (pinned by a test); it imports no Audit module,
service, model or ORM relationship.

## 3. Why nothing was changed

Every item that could be removed changes a value somebody stores or reads:

- **#1–3** are fields in the API and in the frontend's settings and notification
  panels, and values in rows that exist today. Removing the vocabulary from the
  platform means giving the owning product a way to supply it — the design of
  follow-ups 4 and 5 — not deleting the strings.
- **#4 is the one that looks mechanical and is not.** The table maps an action to
  a severity, and `log_audit_event` stores the severity on the row when it writes
  it. Moving Audit's entries to Audit needs a start-up registration, and that
  registration must run in **every process that writes an Audit event**, which
  includes the Celery workers (`scans/db_helpers.py` records `scan.completed`,
  `scan.failed` from the worker, and `ccure-worker` does not import `main.py`).
  A worker that missed it would silently store `MEDIUM` for events classified
  `INFO`: a persisted-data regression with no error. The registration has to be
  loaded from `core/celery_app.py`'s include list as well as `main.py`, and
  `tests/audit/test_audit_action_inventory.py` must follow the split. That is a
  design with a failure mode, not a cleanup.
- **#5** renames rows that roles, the roles screen and the frontend's `can()` all
  read. Atoms keep their names until the module-RBAC phase gives them a
  namespace and a migration.
- **#6–8** are owner or branding decisions already recorded.

## 4. The ratchet

`tests/repo/test_platform_audit_vocabulary.py` counts the code-level hits per
file (the baseline above: 175 in 12 files) and fails when a count grows or a new
file starts to carry Audit's words. It fails the other way too: removing
vocabulary lowers the baseline in the same change, so the number only falls. It
also fails if platform code passes an Audit permission resource to
`require_permission` / `user_has_permission`.

## 5. Recommended designs, for the follow-ups that own these items

- **Preferences (follow-up 4).** Product preferences live under a product key in
  `users.preferences` (`{"audit": {"default_scan_type": …}}`). The platform
  stores and returns keys it does not own opaquely and validates only its own.
  The API accepts and returns the legacy flat `default_scan_type` for as long as
  the frontend needs it, read from the Audit namespace when present, else the
  flat key. Existing rows are interpreted, not rewritten, until a migration is
  scheduled.
- **Notifications (follow-up 5).** `type` and `category` become validated against
  a vocabulary the platform holds for itself (`system_message`, `admin_notice`,
  the `system`/`admin` categories) plus what a product contributes; the persisted
  strings do not change. `related_scan_id` is read as a generic related-entity
  reference with the column kept.
- **Audit taxonomy.** Platform keeps `user.*`, `organization.*`, `admin.*`,
  `auth.*`, `audit.*`; Audit contributes its table through one registration
  function, imported by `main.py` **and** the Celery include list, with a test
  that a worker process resolves `scan.completed` to `INFO`.
- **Permission atoms.** Module-RBAC (D11-1, Phase 18): namespaced atoms with a
  migration of `permissions` / `role_permissions` and a compatibility reading in
  the guard and the frontend's `can()`.

## 6. Left for you to decide

- The AMT permission mismatch (route gated on `assets:update`, sidebar item on
  `settings:update`) and the platform denied-route fallback (a refused platform
  route lands on Audit's dashboard) were requested to be resolved _and_ not
  modified in the same instruction. They are untouched and remain open; say which
  you want.

## 7. Resolved: preferences (follow-up 4, 3 Oct 2026)

`default_scan_type` is Audit's, and `ccure_platform` no longer knows it (175 → 158
hits; `identity/profile.py` carries none).

- **Ownership.** `ccure_platform/preferences.py` is the contract. A product
  registers the schema of its own block once — `register_product_preferences(
namespace, model, legacy_flat_keys=…)`, exported through `ccure_platform.api` —
  and the platform stores and returns the block without reading it. Audit's is
  `ccure_audit/preferences.py` (`AuditPreferences`, with the validator and the
  five allowed values the platform's schema had), imported by `main.py` like the
  offboarding hook. A small registration is required here, and not a larger
  plug-in system: it is the only way the platform can leave the validation and the
  default in the product's hands while the API keeps validating on write.
- **Storage.** `users.preferences`: `{"theme": …, "products": {"audit":
{"default_scan_type": "asset"}}}`. No schema change; no Alembic migration.
- **Live data checked first.** 5 of 10 users hold a full preference document (all
  with `default_scan_type: "asset"`), 5 hold none, and none holds `products`.
- **Compatibility.** (1) _Reading_: a stored flat `default_scan_type` is Audit's
  value when the block has none; a read rewrites nothing. (2) _API_:
  `GET /user/preferences` still returns the flat `default_scan_type` and now also
  `products`; `PUT` accepts the flat key (old clients) and `products` (the new
  frontend), validates it with Audit's model, and answers 422 with Audit's own
  message on a bad value or an unknown namespace. (3) _Writing_: the value is
  stored in the namespace and the flat key it replaces leaves the document in the
  same write — moved, not lost; an unrelated update (the theme) leaves the legacy
  key alone. Where both forms arrive together, the namespaced one wins.
  (4) _Audit trail_: the `user.preferences_updated` change key for this value is
  now `products.audit.default_scan_type`.
- **Frontend.** The settings drawer passes product sections a `setProduct(ns,
key)` setter; Audit's "Scan Defaults" reads `products.audit.default_scan_type`
  (falling back to the flat key) and writes the namespaced block. The drawer, the
  platform preferences and Audit users' experience are otherwise unchanged.
- **OpenAPI.** The two preference schemas change: `default_scan_type` is no longer
  a declared property (the flat key is returned as an additional property) and
  `products` is added. Paths and operations are unchanged.
- **Not done:** the legacy flat key is not removed from the API, and stored flat
  values are not bulk-migrated; both wait until no client needs them.

## 8. Resolved: notification types and categories (follow-up 5, 3 Oct 2026)

The notification service stays the platform's (one service, one table, one SSE
stream); the vocabulary a product raises is the product's.

- **Where it lives.** `ccure_platform/notifications/service.py` keeps the platform's
  own values: types `system_message`, `admin_notice`; categories `security`,
  `system`, `admin`. Audit's types (`scan_completed`, `scan_failed`, `scan_paused`,
  `vulnerability_found`) and its `scan` category are
  `scans/notification_vocabulary.py` (under `scans/`, not `ccure_audit/`, because
  `scans` may not import `ccure_audit` and `scans/db_helpers.py` is the producer).
- **Nothing stored or returned changed.** `type` and `category` were already plain
  strings in the table and the API; `create_notification` and
  `fan_out_notification` now take an enum or a plain string and store the same
  text. Live rows: 18 × `scan_completed`/`scan`, 19 × `admin_notice`/`admin`,
  readable as before.
- **One registration, for one reason.** The unread summary lists every category,
  zero when nothing is unread, in the order `scan, security, system, admin`.
  The platform can no longer spell `scan`, so Audit registers it
  (`register_notification_categories`, exported by `ccure_platform.api`), at import
  of `scans/notification_vocabulary.py`. That module is imported by
  `scans/db_helpers.py` — the only place a scan raises a notification, in the API
  and in the Celery workers alike — so a worker publishing a summary lists the
  same categories as the API; `main.py` imports it too. A category nobody
  registered is still counted when rows carry it: nothing is hidden because a
  product was not imported.
- **Unchanged on purpose.** `related_scan_id` (column, response field, parameters)
  stays for API and persisted-data compatibility. The frontend shell's
  notification panel still maps Audit's type names to icons and lists its
  categories as tabs (`shell/notifications/NotificationsPanel.jsx`); the frontend
  contract is unchanged, and moving that vocabulary to the product is a separate
  frontend change.

## 9. Resolved: audit-event definitions and severity (follow-up 6, 3 Oct 2026)

The audit log stays the platform's; what severity an Audit event carries is
Audit's.

- **Split.** `ccure_platform/audit_log/taxonomy.py` keeps the platform's 47 events
  (`user.*`, `organization.*`, `admin.*`, `auth.*`, `audit.*`, `service.*`) and the
  redaction rules. Audit's 63 (scans, web scans and findings, schedules,
  credentials, remediation, compliance, reports) are
  `ccure_audit/audit_events.py`. `all_severities()` is the merged view; the values
  are the ones the single table held — a test pins the merged 109 to a fingerprint
  of the old table.
- **Every process.** Severity is stored on the row when the event is written, so
  the definitions must be present in the API, the Celery workers, the web worker
  and scripts alike. Audit's manifest declares the module
  (`audit_event_modules = ["ccure_audit.audit_events"]`, one new manifest field,
  validated to lie inside the module's package) and the platform imports it **by
  name the first time it resolves a severity**. No emitter has to remember to
  import anything, and a fresh interpreter that never imports `main` classifies
  `scan.completed` as `info` (tested for a script, the Celery app and the scan
  helpers). `ccure_platform` still imports no Audit code: the name comes from the
  module registry's data.
- **Fails safely.** Definitions that are declared but cannot be loaded raise
  `AuditDefinitionsUnavailable` — the audit write fails loudly, as a failed audit
  write already does — and the failure is not cached. They are never allowed to
  fall back to the default `MEDIUM`, which would store a wrong severity
  permanently. An action nobody classified still takes the documented default and
  is logged once.
- **One thing found.** Widening the action-inventory test to the packages the
  routers moved to (`ccure_platform`, `ccure_audit`) showed `service.token_issued`
  (`POST /auth/service-token`) had never been classified: it took the default,
  `MEDIUM`. It is now named at `MEDIUM`, so no stored severity changes.
- **Unchanged.** `audit_logs.action` and `severity` values, the writer's
  signature, the `core.audit_taxonomy` / `core.audit` legacy names and the
  `core.audit_taxonomy` logger name.

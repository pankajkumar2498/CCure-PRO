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

| #   | Item                                                                                                                                                                                                                    | Where                                                                                                                 | Persisted data                                                                                      | Public API | Frontend |               Celery / event id               | Internal only | Class → decision                                                                                                              |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | :--------: | :------: | :-------------------------------------------: | :-----------: | ----------------------------------------------------------------------------------------------------------------------------- |
| 1   | ~~`default_scan_type` and its allowed values~~ — **resolved by follow-up 4** (§7): Audit owns it (`ccure_audit/preferences.py`); `identity/profile.py` no longer names it. The stored key and the API key are unchanged | `users.preferences` (JSONB), 5 of 10 users                                                                            | yes                                                                                                 |    yes     |    —     |                       —                       |   **Done**    |
| 2   | Notification types `scan_completed`, `scan_failed`, `scan_paused`, `vulnerability_found`; category `scan`                                                                                                               | `notifications/service.py`                                                                                            | `notifications.type`, `.category` (18 × `scan_completed`/`scan`, 19 × `admin_notice`/`admin` today) |    yes     |   yes    |                       —                       |       —       | Persisted + API + frontend → **leave; follow-up 5** (notification ownership)                                                  |
| 3   | `related_scan_id`                                                                                                                                                                                                       | `notifications/service.py`, `router.py`                                                                               | `notifications.related_scan_id` column                                                              |    yes     |   yes    |                       —                       |       —       | Persisted column + API → **leave; follow-up 5**                                                                               |
| 4   | Audit event names (`scan.*`, `web_scan.*`, `finding*`, `credential.*`, `scan_schedule.*`, `remediation.*`, …) → severity                                                                                                | `audit_log/taxonomy.py` (≈63 of 109 entries; the rest are `user.*`, `organization.*`, `admin.*`, `auth.*`, `audit.*`) | `audit_logs.action` — 65 distinct names in use; 233 `scan.*` rows alone                             |  (viewer)  | (viewer) |                       —                       |       —       | Persisted values; severity is **computed at write time and stored** → **leave** (see §3, the worker trap)                     |
| 5   | Permission atoms `scans:*`, `assets:*`, `findings:*`, `compliance:*`, `credentials:*`, `scan_policies:*`, `scan_schedules:*`, `reports:*`, `dashboard:*`                                                                | rows in `permissions` (48 of 65 atoms); seeded by `db/migrate_production_schema.py`, not by `ccure_platform`          | `permissions`, `role_permissions`                                                                   |    yes     |   yes    |                       —                       |       —       | RBAC data + API + frontend (`can(resource, action)`) → **leave; module-RBAC phase (D11-1 / Phase 18)**                        |
| 6   | Organisation plan: `max_assets`, `max_scans_per_day`, `max_concurrent_scans`, `scan_scope_cidrs`, `/…/scan-scope`, `ScanLimits`, `scan_scope`, `remediation_sla`                                                        | `plan/`, `administration/organizations.py`, `models/rbac.py`, `api.py`                                                | `organizations` columns                                                                             |    yes     |   yes    |                       —                       |       —       | Owner decision, 29 Sep 2026 (platform-owned, one seam per feature) → **leave**; recipes in `PHASE8_4_ORGANISATION_PLAN.md` §9 |
| 7   | `max_assets=100` for a self-registered organisation                                                                                                                                                                     | `identity/router.py`                                                                                                  | `organizations.max_assets`                                                                          |     —      |    —     |                       —                       |       —       | Plan default → **leave** with #6                                                                                              |
| 8   | "CCure Audit PRO" in the reset-password email subject and the TOTP issuer name                                                                                                                                          | `identity/mail_service.py`, `identity/router.py`                                                                      | no (the TOTP issuer label is baked into already-enrolled authenticator entries)                     |  (email)   |    —     |                       —                       |       —       | User-visible branding → **leave; sign-in branding decision (D12-9)**                                                          |
| 9   | `retro_scan_email_risk` / "retro-scan"                                                                                                                                                                                  | `identity/email_security_tasks.py`                                                                                    | —                                                                                                   |     —      |    —     | task name `ccure.tasks.retro_scan_email_risk` |       —       | **Not Audit's**: it re-screens accounts for shared mailboxes. A name collision; the task name is an API.                      |
| 10  | Docstrings and comments mentioning scans, assets, findings (e.g. `rbac/dependencies.py`, `notifications/router.py`)                                                                                                     | various                                                                                                               | —                                                                                                   |     —      |    —     |                       —                       |      yes      | Prose, no coupling → **leave**                                                                                                |

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

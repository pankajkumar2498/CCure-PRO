# Backend platform extraction (backend alignment, steps 1–2)

|              |                                                                                                                                                                                                                     |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**   | Implemented and committed, **not deployed** (3 Oct 2026). Step 1 (`e50929d`) moved the audit-log retention task; step 2 (this record) moved the rest of the platform's backend into `ccure_platform`.               |
| **Decided**  | By the project owner: remove the platform's ORM relationships into Audit and use Audit-registered hooks; move preferences and notifications as they are; move the whole audit-log service; keep legacy alias stubs. |
| **Baseline** | `5983e0a` plus `e50929d`. Companion to [`PLATFORM_SHARED_NAVIGATION.md`](PLATFORM_SHARED_NAVIGATION.md): the frontend's Platform Shell and this backend now draw the same boundary.                                 |

## 1. The rule

`ccure_platform` imports no Audit code and names no Audit model — by import, or
by ORM relationship. Audit reaches the platform through `ccure_platform.api`.
When the platform needs a module to act on that module's own data, it asks
through a contract and the module answers; it never reaches in.

## 2. What the frontend Platform Shell uses, and who owns it

| Platform Shell capability     | Endpoints                | Backend now                                                          |
| ----------------------------- | ------------------------ | -------------------------------------------------------------------- |
| Product hub                   | `GET /platform/modules`  | `ccure_platform/hub/router.py` (already)                             |
| Sign-in, MFA, sessions, reset | `/auth/*`                | `ccure_platform/identity/router.py` (already)                        |
| Account, profile, preferences | `/user/*`                | `ccure_platform/identity/profile.py` (moved)                         |
| Users                         | `/admin/users/*`         | `ccure_platform/administration/users.py` (moved)                     |
| Organisations                 | `/admin/organizations/*` | `ccure_platform/administration/organizations.py` (moved)             |
| Roles & permissions           | `/admin/roles/*`         | `ccure_platform/administration/roles.py` (moved)                     |
| Email domain rules            | `/admin/email-domains/*` | `ccure_platform/administration/email_domains.py` (moved)             |
| Audit logs (viewer, export)   | `/admin/audit-logs/*`    | `ccure_platform/audit_log/router.py` (moved; was `routers/audit.py`) |
| Notifications                 | `/notifications/*`       | `ccure_platform/notifications/router.py` + `service.py` (moved)      |

Everything else the frontend's Audit module calls stays Audit's.

## 3. What moved

New homes, with the legacy module name kept (`ccure_platform/_legacy.py`
`MOVED_MODULES`):

- **Audit-log service** → `ccure_platform/audit_log/`: `writer.py` (was
  `core/audit.py`), `taxonomy.py` (`core/audit_taxonomy.py`), `retention.py`
  (`core/audit_retention.py`), `export.py` (`reporting/audit_export.py`),
  `router.py` (`routers/audit.py`), and `tasks.py` (step 1).
- **Notifications** → `ccure_platform/notifications/`: `service.py`
  (`core/notifications.py`), `router.py` (`routers/notifications.py`).
- **Administration** → `ccure_platform/administration/`: `users.py`,
  `organizations.py`, `roles.py`, `email_domains.py`.
- **Account** → `ccure_platform/identity/profile.py` (`routers/user_profile.py`).
- `ccure_platform/accounts.py`: `UserView`, `user`, `user_display_names`,
  `active_members_with_roles`, moved out of `api.py` (which re-exports them) so
  the notification service does not import the facade that imports it.

**Stayed, on purpose:**

- `core/audit_event_translator.py` is not the audit log. It turns **asset
  change-log** rows into the Asset Activity Timeline and is called only by
  `routers/assets.py`: Audit's. The name misleads; the file was not moved on its
  name.
- Shared infrastructure the moved code uses, named in `exempt_targets` of
  `platform-is-shared-foundation`: `core.upload_guard` and
  `reporting.report_helpers` were added (the audit-log export's filename
  header and PDF fonts); `core.rate_limiter`, `core.redis_client`,
  `core.ip_resolver`, `core.celery_app`, `core.throttle`, `core.user_agent`
  were already there. The two exemptions for the audit log itself
  (`core.audit`, `core.audit_retention`) are **gone**.

## 4. Contracts introduced

- **Offboarding** (`ccure_platform/offboarding.py`):
  `register_user_purge_hook(name, hook)`, `run_user_purge_hooks(db, user_id)`.
  `purge_user` clears the platform's own references (`audit_logs`,
  `refresh_token_sessions`) and then runs the hooks on the caller's session and
  transaction; a hook detaches, never commits. Audit's hook is
  `ccure_audit/offboarding.py` (scans, asset notes, asset tags, accepted-risk
  findings), the statements that used to sit in the route, registered when
  `main.py` imports it. There is no organisation hook: organisations are
  archived, never deleted. A future hard purge joins this contract.
- **Platform API additions** (`ccure_platform.api`, and the
  `PLATFORM_API_SURFACE` ceiling): `log_audit_event`, `create_notification`,
  `fan_out_notification`, `NotificationType`, `NotificationCategory`,
  `register_user_purge_hook`. Audit's routers and `scans/db_helpers.py` use
  these instead of `core.audit` / `core.notifications`.

## 5. ORM coupling removed

`User.scans`, `User.asset_notes`, `User.asset_tags`, `Organization.assets` and
`Organization.scans` (the last two with `cascade="all, delete-orphan"`) are
gone from the platform models. Audit's models keep a one-way link
(`Scan.created_by_user`, `Scan.organization`, `Asset.organization`,
`AssetTag.created_by_user`, `AssetNote.user`). Nothing relied on the ORM
cascade: `archive_organization` archives and never deletes, and the database's
`ON DELETE CASCADE` foreign keys are unchanged. No schema change.

## 6. API and behaviour

- Routes (274), the OpenAPI document (byte-identical, sha256 `c8758dc3…`), the
  Celery registry (36 tasks), queues and the beat schedule (11 entries) are
  identical before and after.
- Moved modules keep their legacy `__name__`, so logger names, limiter route
  keys and OpenAPI component names are unchanged. The legacy files are alias
  stubs of the **same module object**; `tests/repo/test_platform_extraction.py`
  proves each is an alias and defines no function or class.
- `routers/health.py` is split. `GET /` answers the scanner runtime's own report
  (`get_api().get_system_info()`), so it is Audit's today; it stays in
  `health.py`, documented as such, because a platform-owned health root would
  change what `/` answers. Scan progress and the pipeline documentation routes
  moved to `routers/scan_progress.py`. Handler names changed for those three, so
  `gateway/policy/` (inventory hash and endpoint names only) and the
  characterisation in `docs/architecture/phase10/` were regenerated; no
  authentication or limit changed.
- Two router-to-router imports inside Audit were removed:
  `routers/dashboard.py` → `core/web/finding_view.py`, and
  `routers/phase_scans.py` → `scans/scan_access.py`. The old private names stay
  as imports in `routers/web_scans.py` and `routers/scan_history.py`.

## 7. Limitations, recorded and not fixed

> Classified item by item in [`PLATFORM_AUDIT_VOCABULARY.md`](PLATFORM_AUDIT_VOCABULARY.md) (follow-up 3), with a ratchet test.

- **Audit vocabulary inside platform code.** (`default_scan_type` is Audit's since
  follow-up 4: see `PLATFORM_AUDIT_VOCABULARY.md` §7.) The notification types and categories still carry
  Audit's words (`scan_completed`, `vulnerability_found`, the `scan` category);
  the audit-event severity table still lists Audit's `scan.*`, `credential.*` and
  finding events. These are strings and data, not imports. Preference
  namespacing and a cross-product notification and taxonomy design are later
  decisions.
- **Audit-shaped permission atoms** (`scans:*`, `assets:*`, …) sit in the
  platform's `permissions` table and are seeded from
  `db/migrate_production_schema.py`. Untouched (D11-1: roles wait for Phase 18).
- **Legacy stubs remain**, as in Phase 8.2: `routers/admin_*.py`,
  `routers/user_profile.py`, `routers/audit.py`, `routers/notifications.py`,
  `core/audit*.py`, `core/notifications.py`, `reporting/audit_export.py`. Tests
  and patch targets use them. Removing them goes with the later logger and
  limiter-key rename.
- **Foreign keys** from Audit's tables to `users` and `organizations` are by
  design and unchanged.
- **Deployment.** The running API and workers load the old code until
  restarted; `ccure-worker` and `ccure-beat` must be restarted to register
  `ccure_platform.audit_log.tasks` (step 1).

## 8. Investigated: "notification stream closed before its first heartbeat" (3 Oct 2026)

A production log line after the `bc73f02` deployment:
`Notification stream for user … closed after 0.0s, before its first heartbeat`.
**Harmless; no code change.**

- **Where:** the `finally` block of `event_generator()` in
  `ccure_platform/notifications/router.py` (`GET /notifications/stream`). It warns
  when a connection ends in under 20 s.
- **What it is:** the **client** ending the request early — a full page load, or
  a layout remount (every page renders its own layout, so each navigation aborts
  the open stream and the hook opens a new one). A browser run of 8 page loads
  and 4 in-app navigations opened 18 streams, all `200`, with gateway durations
  from 0 to 29 s.
- **Why it is rare and inconsistent:** a disconnect cancels the generator, and
  the cleanup in `finally` awaits (`unsubscribe`, `close`). Whether it reaches
  the warning line depends on whether those awaits suspend after the
  cancellation: when they do, nothing is logged. In the browser run above 15
  aborts of under 2 s logged nothing; production has logged the warning three
  times, so its presence is not an incident and its absence proves nothing. The
  comment's reading ("not routine churn") is out of date now that short-lived
  connections are routine, but changing the level is not needed.
- **Redis:** pub/sub only. With an isolated copy of the router and a real Redis,
  aborted clients left no subscription behind (subscriber count 0 immediately
  and 30 s later). No error path (`heartbeat-only mode`, `stream failed`) fired.
- **No notifications are lost by it:** the stream is a live push. The record is
  the `notifications` table; each (re)connect begins with a `connected` frame
  carrying the current unread summary, and the frontend hook reconnects with
  backoff and fetches `GET /notifications/summary` after a drop. An event
  published while no stream is connected is not replayed live (pub/sub), but the
  notification is in the inbox and in the count.
- **Not caused by the move:** the router body is byte-identical to
  `routers/notifications.py` apart from the import path (the same module object
  through the alias), and it keeps the logger name `routers.notifications`. The
  same warning was logged on the previous code on 2 Oct at 12:52:58 and 12:53:17
  (a real user, 0.0 s and 0.2 s).
- **Added:** `tests/auth/test_notification_stream_contract.py`, because the
  stream had no test: first frame `connected` with the durable summary, relay of
  a published message under its own event name, heartbeat on a quiet interval,
  cleanup on close, and the warning as a known client-side early close.

## 9. Follow-ups 3–7

The vocabulary left in the platform is classified in [`PLATFORM_AUDIT_VOCABULARY.md`](PLATFORM_AUDIT_VOCABULARY.md) (preferences §7, notifications §8, audit-event severities §9), and the final boundary review is [`PLATFORM_AUDIT_BOUNDARY_REVIEW.md`](PLATFORM_AUDIT_BOUNDARY_REVIEW.md).

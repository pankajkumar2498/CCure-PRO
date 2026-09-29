# Phase 8.4 — Organisation plan and entitlements in `ccure_platform`

|               |                                                                                                                                                                                                                               |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**    | **Implemented** (Option A), 29 Sep 2026, after the project owner approved Option A and the recommendations for the six questions (§8). No database change.                                                                    |
| **Date**      | 29 Sep 2026                                                                                                                                                                                                                   |
| **Replaces**  | Step 8.4 as first written in [`PHASE8_PLATFORM_IDENTITY.md`](PHASE8_PLATFORM_IDENTITY.md) §4, which moved quota and scope into an Audit-owned `audit_organisation_settings`. The project owner has decided otherwise (below). |
| **Builds on** | Steps 8.1–8.3: identity in `ccure_platform`, `ccure_platform.api`, and 17 identity queries left in module code, 13 of which read the settings this step is about                                                              |

## 1. The decision this design implements

Project owner, 29 Sep 2026:

> `Organization.plan`, quota limits, scan scope, remediation SLA and any other
> organisation-level plan or entitlement settings are **platform-owned**
> (Organization → Organization Plan / Entitlements). CCure Audit consumes them
> and does not own them. Quota may be removed later, so it must stay removable
> without restructuring `ccure_audit`.

### The rule that follows

The owner's decision draws a line that runs through every one of these
settings. Stating it once is what keeps the design consistent:

> **The platform owns what an organisation is entitled to, and what it has
> configured. Each module owns how its own records are checked against that.**

| Setting         | Platform owns (data, defaults, who may change it)          | Audit owns (its own records measured against it)                                                     |
| --------------- | ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Quota           | The plan's limits, and the per-organisation overrides      | Counting its own scans (running, in the last 24 h), expanding targets, and the refusal message       |
| Scan scope      | The authorised CIDR ranges, and whether any are configured | Deciding whether a scan's targets fall inside them, and the refusal                                  |
| Remediation SLA | The organisation's configured deadlines                    | What they mean for a finding: the severity vocabulary, the product defaults, the KEV rule, due dates |

A second rule comes from `CLAUDE.md`: **an absent entitlement is reported as
absent**. The consuming module decides what absence means.
`REQUIRE_SCAN_SCOPE` (an unconfigured scope scans nothing, or scans anything)
therefore stays Audit's decision, and the platform reports only whether a
scope is configured.

## 2. Current inventory (measured 29 Sep 2026)

Live figures come from read-only queries on `ccure_db`, which has 4
organisations. Code figures are from `Backend/`, excluding tests and scripts.

### 2.1 Columns on `organizations`

| Column                                                              | Type / default                                           | Live values                                                                          | Written by                                                                                                                                         | Read by                                                                 | Kind                    |
| ------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ----------------------- |
| `id`, `name`, `slug`                                                | varchar, NOT NULL, unique                                | —                                                                                    | admin, registration                                                                                                                                | everything                                                              | **tenancy identity**    |
| `is_active`, `archived_at`, `archived_by_user_id`, `archive_reason` | —                                                        | all active, none archived                                                            | admin (status, archive, restore)                                                                                                                   | sign-in, admin                                                          | **tenancy lifecycle**   |
| `created_at`, `updated_at`                                          | timestamptz                                              | —                                                                                    | —                                                                                                                                                  | admin                                                                   | tenancy                 |
| `settings`                                                          | jsonb NOT NULL `{}`                                      | one organisation has `{"description": …}`; **no organisation has `remediation_sla`** | `PUT /remediation/sla-policy` (the SLA key only)                                                                                                   | the SLA readers                                                         | **mixed bag** — see 2.2 |
| `plan`                                                              | varchar(50) NOT NULL `'community'`                       | enterprise ×2, pro, community                                                        | `POST`/`PUT /admin/organizations` (`organizations:create`/`update`, held **only by superadmin** in the live role data), registration (`community`) | `core.quota`, dashboard, admin                                          | **plan**                |
| `max_assets`                                                        | int NOT NULL 500                                         | 100000, 10000, 500, 100                                                              | admin create/update, registration (100)                                                                                                            | **admin only — enforced nowhere** (finding F1)                          | **plan**                |
| `max_users`                                                         | int NOT NULL 10                                          | 100, 100, 50, 10                                                                     | admin create/update, registration (50)                                                                                                             | **admin only — enforced nowhere** (F1)                                  | **plan**                |
| `max_scans_per_day`                                                 | int NULL (NULL = plan default)                           | all NULL                                                                             | **no API** (database only)                                                                                                                         | `core.quota.check_scan_quota` (enforcement only; not the displays — F2) | **plan override**       |
| `max_concurrent_scans`                                              | int NULL                                                 | `org_default` = 20 (equal to the enterprise default), others NULL                    | no API                                                                                                                                             | as above                                                                | **plan override**       |
| `scan_scope_cidrs`                                                  | jsonb NULL (NULL = legacy unrestricted, `[]` = deny all) | 3 ranges ×2, `[]` (self-service: deny all), NULL (`org_test_org.com`)                | `PUT /admin/organizations/{id}/scan-scope`, **superadmin only, enforced in code**                                                                  | 9 call sites (§4)                                                       | **plan / entitlement**  |

Constraints are NOT NULL, the primary key, and unique `name` and `slug`.
There is **no CHECK on `plan`**. 38 foreign keys point at `organizations.id`.

### 2.2 Inside `settings`

| Key               | Owner                       | Written by                                                                             | Read by                                                   |
| ----------------- | --------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `remediation_sla` | **plan** (owner's decision) | `PUT /remediation/sla-policy`, `settings:update`, held by **org_admin** and superadmin | `core.remediation.sla.sla_policy_for_org` (via 4 callers) |
| `description`     | tenancy                     | none found in code (it predates it)                                                    | —                                                         |

### 2.3 In code

- **Plan catalogue:** `core.quota._PLAN_LIMITS`. Per plan it holds scans per
  day, concurrent scans, the largest subnet, IPs per scan and custom ports;
  `_DEFAULT_PLAN = "community"`. This is plan data living in Audit's code.
- **Deployment policy:** `config.REQUIRE_SCAN_SCOPE` (default False).
- **SLA defaults:** `core.remediation.sla.DEFAULT_SLA_DAYS`, keyed by Audit's
  severity vocabulary (see question Q2).

### 2.4 Findings from the inventory

None of these is fixed by this design, since each would change behaviour.
They are listed so each can be decided separately.

- **F1 — `max_assets` and `max_users` are enforced nowhere.** The model's
  docstring says `max_assets` is a "hard cap enforced at scan save time".
  Nothing reads either column outside the admin screens.
- **F2 — the displayed limit is not the enforced one.** `check_scan_quota`
  applies the per-organisation overrides; `GET /scan/quota` and the dashboard
  show the plan's defaults. On today's data the one override equals its
  default, so nothing visible differs, but the first real override would make
  the UI lie.
- **F3 — `get_quota_status` reports zeros on failure.** When it cannot read
  the plan it answers `plan: "unknown"` with `scans_used_24h: 0`. That is the
  UNKNOWN ≠ ZERO defect `CLAUDE.md` forbids.
- **F4 — plan changes rest on role data, not code.** Only superadmin holds
  `organizations:update` today, which is what stops an organisation raising
  its own plan. Scan scope is protected in code ("only a superadmin may change
  an organisation's scan scope"); plan and quota are one role grant away from
  self-service.

## 3. Target representation

Two options were designed. Both keep every URL, request and response shape,
permission and behaviour.

### Option A — a platform plan boundary over the existing columns (**recommended**)

The data **stays where it is**. The `organizations` table is already
platform-owned (`table_ownership.yaml`). What is Audit's today is the _code_
that holds the plan catalogue and reads the columns directly. Option A moves
the ownership, not the rows.

```
Backend/ccure_platform/plan/         Organisation plan and entitlements
  catalogue.py        the plans and their default entitlements (from core.quota._PLAN_LIMITS)
  scan_limits.py      quota:     plan defaults + per-org overrides → ScanLimitsView
  scan_scope.py       scope:     the authorised ranges            → ScanScopeView
  remediation_sla.py  SLA:       the configured deadlines          → RemediationSlaSettingView
  (seats and asset allowance are read by admin only — F1)
```

**One module per plan feature.** Removing quota later means deleting
`scan_limits.py`, its API function, and Audit's single consumer of it
(`core.quota`, with its three admission call sites and the two usage
displays). The scan pipeline, engines, findings and reports never see quota:
it is an admission check, and it stays one.

**What `ccure_platform.api` gains** — one function per feature, each
returning a frozen view of plain values:

| Function                                           | Returns                                                                                                                                                                | Semantics                                                                                                                                                                                                                                                       |
| -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scan_limits(db, org_id)`                          | `ScanLimitsView(plan, max_scans_per_day: int \| None, max_concurrent_scans, max_subnet_prefix, max_ips_per_scan, max_custom_ports, plan_defaults: ScanLimitsDefaults)` | The effective limits: an override where one is set, else the plan default. `None` for scans per day means unlimited, as today. `plan_defaults` carries the plan's own figures, so the displays can keep showing what they show today (F2) until that is decided |
| `scan_scope(db, org_id)`                           | `ScanScopeView(configured: bool, cidrs: tuple[str, ...])`                                                                                                              | `configured=False` is today's NULL. `configured=True` with no ranges is deny-all. The platform does not apply `REQUIRE_SCAN_SCOPE`; Audit does                                                                                                                  |
| `remediation_sla_setting(db, org_id)`              | `RemediationSlaSettingView(stored: str \| None)`                                                                                                                       | The organisation's stored setting, as canonical JSON text, **uninterpreted**. Audit's `sla_policy_for_org` keeps its merge, vocabulary and leniency unchanged, so every edge case (partial, malformed, unknown severity) behaves exactly as before              |
| `store_remediation_sla_setting(db, org_id, value)` | —                                                                                                                                                                      | The write behind `PUT /remediation/sla-policy`. The route still validates, merges and writes the audit event; the platform stores the result                                                                                                                    |

**Why the SLA view is text rather than typed fields.** A typed view would
make the platform interpret deadlines, which needs Audit's severity
vocabulary. Interpreting them differently from `sla_policy_for_org` would be
a behaviour change on exactly the malformed values that function was written
to tolerate. Passing the stored value through unchanged keeps the meaning in
Audit and the ownership in the platform.

**No generic API.** There is no `get_setting(key)`, no dictionary view and no
Audit logic in the platform. Counting scans, expanding targets and computing
due dates all stay in `core/`.

**Cost.** No migration and no data touched. Rollback is `git revert`. The
risk is the code changes themselves, which the tests and the comparison in
§6 cover.

### Option B — a separate platform table `organization_plans`

The same code boundary as A, **plus** moving the plan data off the tenant row
into a 1:1 table. This matches the owner's diagram most literally
(Organization → Plan).

```sql
CREATE TABLE organization_plans (            -- owner: platform, capability: plan
  org_id               varchar(100) PRIMARY KEY
                       REFERENCES organizations(id) ON DELETE CASCADE ON UPDATE CASCADE,
  plan                 varchar(50)  NOT NULL DEFAULT 'community',
  max_assets           integer      NOT NULL DEFAULT 500,
  max_users            integer      NOT NULL DEFAULT 10,
  max_scans_per_day    integer      NULL,    -- NULL = plan default
  max_concurrent_scans integer      NULL,    -- NULL = plan default
  scan_scope_cidrs     jsonb        NULL,    -- NULL = not configured; [] = deny all
  remediation_sla      jsonb        NULL,    -- NULL = product default; partial object merges
  created_at           timestamptz  NOT NULL DEFAULT now(),
  updated_at           timestamptz  NOT NULL DEFAULT now()
);
```

The existing 38 foreign keys and every relationship are unchanged. The one new
foreign key is `organization_plans.org_id`.

**What B buys over A:**

- **The tenant row no longer carries commercial configuration.** If identity
  moves to a separate authentication service (plan §3.9), `organizations`
  goes with it and the plan table stays in the core database. The
  per-request entitlement read at scan admission then never crosses a service
  boundary.
- **Removing quota becomes a column drop** on a table that holds nothing
  else.

**What B costs:**

- **A migration on a live table** while `archive_mode` is off. §5 has the full
  procedure.
- **Every organisation creation path must also create its plan row.** In
  production that is two paths (the admin router and self-registration) plus
  four scripts. The tests construct `Organization(...)` **103 times**, and 85
  test lines name `max_assets`. Either every one changes, or `Organization`
  carries compatibility attributes that route to the plan row — which is the
  kind of shim this programme has so far avoided.
- **A compatibility release** in which the old columns exist but are stale
  after the first write, held safe by a test.

### Recommendation

**Option A for step 8.4.** The owner's constraints point this way: "preserve
existing database relationships unless there is a specific migration reason".
The data is already in a platform-owned table, and the only concrete reason
for B — a separate authentication service — is itself undecided (§3.9).

A also makes B cheap when it is wanted. Once every consumer reads through
`ccure_platform.api`, moving the rows becomes a storage change behind four
functions, with no consumer edits. B is designed in full below so it can be
approved on its own when there is a reason.

## 4. Consumer mapping (Option A)

Every reader and writer, and what it uses afterwards. "Kept" means it stays as
it is, for the stated reason.

| Consumer                                                                                                                                                                                                                | Reads / writes today                                                | After 8.4                                                                                                                                                                                                                                                                                                                   |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `core.quota.check_scan_quota` (called by `phase_scans:460, 645`, `scheduling.dispatcher:490`)                                                                                                                           | `organizations` row: plan, 2 overrides; `_PLAN_LIMITS`              | `api.scan_limits()`. Counting and messages unchanged                                                                                                                                                                                                                                                                        |
| `core.quota.get_quota_status` → `GET /scan/quota`                                                                                                                                                                       | plan → `_limits(plan)` (defaults only, F2)                          | `api.scan_limits().plan_defaults`, which keeps today's figures                                                                                                                                                                                                                                                              |
| `routers.dashboard:224` quota panel                                                                                                                                                                                     | plan → `_limits(plan)[:2]`                                          | as above                                                                                                                                                                                                                                                                                                                    |
| `core.scan_scope.scope_for_org` / `enforce_org_scan_scope` (called by `scan_helpers.validate_scan_targets` ← `phase_scans:136, 457, 748`, `scan_schedules:447`, `dispatcher:207`; `credentialed:51`; `credentials:657`) | `org.scan_scope_cidrs` via the row passed in                        | They take a `ScanScopeView`. `REQUIRE_SCAN_SCOPE` and every message are unchanged. Callers stop loading the organisation row: `routers.credentialed:49`, `credentials:654`, `phase_scans:72`, `scan_schedules:445`, `dispatcher:202` (which keeps its "organisation no longer exists" refusal through `api.organisation()`) |
| `orchestrator.scan_orchestrator.apply_scan_scope` ← `core.tasks:135`                                                                                                                                                    | the row                                                             | a `ScanScopeView`                                                                                                                                                                                                                                                                                                           |
| `ccure_audit.services.baseline_mapping:316, 374`                                                                                                                                                                        | the row: existence and scope                                        | `api.organisation()` for existence, `api.scan_scope()` for scope                                                                                                                                                                                                                                                            |
| `core.remediation.sla.sla_policy_for_org` (← `core.tasks:4860`, `remediation.reporting:154`, `remediation.workflow:217`, `routers.remediation:135, 542, 606`)                                                           | `org.settings["remediation_sla"]`                                   | reads `api.remediation_sla_setting()` and interprets it exactly as today                                                                                                                                                                                                                                                    |
| `PUT /remediation/sla-policy` (`routers.remediation`)                                                                                                                                                                   | writes `org.settings`                                               | the same validation, merge and audit event, stored through `api.store_remediation_sla_setting()`                                                                                                                                                                                                                            |
| `routers.admin_orgs` list, create, update, scan scope                                                                                                                                                                   | the columns directly                                                | **Kept** — it is identity's own administration router (platform-side). It reads and writes through `ccure_platform.plan` when that router moves into the platform (8.5 or later)                                                                                                                                            |
| self-registration (`ccure_platform.identity.router`)                                                                                                                                                                    | sets plan, max_assets, max_users on a new self-service organisation | Kept; it is platform code                                                                                                                                                                                                                                                                                                   |
| Frontend: `ScanQuotaBar`, `OrganizationForm`, `OrganizationManagement`, `Remediation`                                                                                                                                   | the four URLs above                                                 | **No change**: same URLs, same JSON                                                                                                                                                                                                                                                                                         |

**Ratchet effect:**

- Direct identity queries fall from 17 to **4**. The 13 settings reads become
  API calls; what remains is the 2 WebSocket logins (Phase 10, as the owner
  directed) and the 2 identity purge tasks (awaiting a decision).
- The 8.1 "Audit settings" ratchet (`KNOWN_AUDIT_SETTING_REFERENCES`) was
  written for the opposite ownership. It is **inverted**: platform code may
  name these fields, and module code may not. Module code's mentions — in
  `core.quota`, `core.scan_scope`, `core.remediation.sla` and
  `baseline_mapping` — are recorded and must reach zero within 8.4.
- A test pins that `ccure_platform.plan` imports nothing from `core`:
  entitlements are data, never Audit logic.

## 5. Option B migration design (for when it is approved)

**Pre-conditions:**

- a full dump (`scripts/backup_db.sh`, the `_full` tier), verified with
  `pg_restore -l`;
- the whole procedure rehearsed on `ccure_db_rehearsal`, restored from that
  dump;
- the API, worker and beat stopped for the migration.

**Up** — one Alembic revision, one transaction:

1. `CREATE TABLE organization_plans` (above).
2. Backfill:

   ```sql
   INSERT INTO organization_plans
     (org_id, plan, max_assets, max_users, max_scans_per_day,
      max_concurrent_scans, scan_scope_cidrs, remediation_sla, …)
   SELECT id, plan, max_assets, max_users, max_scans_per_day,
          max_concurrent_scans, scan_scope_cidrs,
          settings->'remediation_sla', …
   FROM organizations;
   ```

3. In the same transaction, assert that the row counts match and that no
   organisation lacks a plan row. Any failure aborts the migration.
4. **Leave the old columns and the settings key untouched.** They stay for at
   least one clean release, as the owner required. A test fails if any code
   reads them.

**The release that uses the table:**

- `ccure_platform.plan` reads and writes `organization_plans` only.
- Organisation creation creates the plan row, and a missing row is an error,
  never silently the default plan.

**Down (rollback):**

1. Copy `organization_plans` back into the old columns and the settings key,
   so writes made since the migration survive.
2. Drop the table.
3. Redeploy the previous release.

Because the old columns were never dropped, the previous code runs unchanged.

**Row-by-row comparison, three layers, each an empty diff or the step
fails:**

1. **Data.** Take a per-organisation md5 of
   `(plan, max_assets, max_users, max_scans_per_day, max_concurrent_scans,
scan_scope_cidrs::text, settings->'remediation_sla')`: before from
   `organizations`, after from `organization_plans`. Run it again after a
   rehearsed rollback.
2. **Behaviour.** For every organisation, resolve the effective scan limits,
   the scope (with `REQUIRE_SCAN_SCOPE` on and off) and the SLA policy through
   the old code and the new code, and compare the resolved values. Done on the
   rehearsal copy, then on production read-only.
3. **End to end.**
   - Every organisation's `GET /scan/quota`, `GET /remediation/sla-policy` and
     `GET /admin/organizations/{id}/scan-scope` response compared before and
     after.
   - One real scan admitted, and one refused for scope.

**The later drop** of the old columns is its own migration, with its own
approval, after a clean release.

## 6. Verification for Option A (no migration)

- **The behaviour comparison from §5, layer 2**, run read-only against the
  live database. For each of the 4 organisations, the resolved limits, scope
  and SLA policy are computed through the current code and through the API,
  and must be equal.
- **Tests:** the quota, scope, SLA, remediation and dashboard suites, plus the
  new API tests (each against the query it replaces).
- **The full suite.**
- **OpenAPI** byte-identical to `a648d39`; limiter keys and Celery tasks
  identical.
- **Live probe:** `GET /scan/quota`, `GET /remediation/sla-policy` and the
  scan-scope endpoint for each organisation, compared before and after.

## 7. Steps (Option A)

| Step     | What                                                                                                                                                               | Risk                                        |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- |
| **8.4a** | `ccure_platform/plan/`, and the catalogue moved out of `core.quota` (the old name stays importable), the four API functions, their tests, and the inverted ratchet | None; no callers yet                        |
| **8.4b** | Quota consumers switch: `core.quota`, the dashboard                                                                                                                | Low                                         |
| **8.4c** | Scope consumers switch: `core.scan_scope`, the orchestrator, `scan_helpers`, the routers, the dispatcher, `baseline_mapping`                                       | Low–medium: this is the scan admission path |
| **8.4d** | SLA reader and writer switch; ratchet at zero; full suite; behaviour comparison; live probe                                                                        | Low                                         |

One commit each, with focused tests after each and the full suite before the
last.

## 8. Questions for the owner

1. **Option A or B?** The recommendation is A now, with B taken later only
   for a specific reason (a separate authentication service, or plan
   management).
2. **SLA defaults.** The organisation's _configured_ deadlines are plan data.
   Should the product's _default_ deadlines (`DEFAULT_SLA_DAYS`, keyed by
   Audit's severity vocabulary) also move, or stay with Audit as the meaning of
   "no deadline configured"? The design assumes they stay.
3. **`REQUIRE_SCAN_SCOPE`** stays Audit's decision about what an unconfigured
   scope means. The platform reports only "configured or not". Confirm.
4. **F1–F4** are recorded, not fixed. Each would change behaviour: enforcing
   `max_assets` or `max_users`, showing the enforced limit (F2), reporting
   "unknown" rather than zero (F3), and making plan edits superadmin-only in
   code (F4). Which, if any, should be scheduled?
5. **The ORM relationships `Organization.assets` / `.scans`** were in the old
   8.4. They are model coupling, not plan data, and removing them changes ORM
   delete behaviour. The design moves them out of 8.4 to a separate item.
   Confirm.
6. **The two identity purge tasks** still in `core.tasks` (from the 8.3
   report): may they move into `ccure_platform/identity/`? It can be done in
   8.4a or separately.

## 9. Removing a plan feature

The owner's direction (29 Sep 2026): scan limits, scope, SLA and the like are
not needed to run an assessment, and stakeholders may ask for them to go.
Each is therefore contained. It has one platform module, one or two API
functions, and **exactly one Audit seam**. `tests/repo/test_plan_feature_containment.py`
fails if a second Audit module starts calling a feature, or if one feature
module imports another.

**Scan limits (quota):**

1. In `core/quota.py`, make `check_scan_quota` a no-op, or delete it together
   with its three calls in `routers/phase_scans.py` (×2) and
   `core/scheduling/dispatcher.py`.
2. Delete `get_quota_status`, `GET /scan/quota` and the dashboard's quota
   fields, and remove `ScanQuotaBar` from the frontend. These change the API,
   so they need the frontend change in the same release.
3. Delete `ccure_platform/plan/scan_limits.py` and `scan_limits`,
   `ScanLimits` and `ScanLimitsView` from `ccure_platform.api` and
   `PLATFORM_API_SURFACE`.
4. Optionally drop `max_scans_per_day` and `max_concurrent_scans` in a
   migration. `plan` stays while any other feature uses it.

Nothing in the scan pipeline, engines, findings or reports changes.

**Scan scope.** This is a security control: removing it means any
authenticated user can aim the scanner at any address. Decide that
explicitly, then:

1. In `core/scan_scope.py`, make `org_scan_scope` return `None` and
   `scope_for_org` return `None`, meaning unrestricted.
2. Delete `ccure_platform/plan/scan_scope.py` and its API names.
3. Delete the admin scan-scope endpoints.

The callers keep calling the seam and need no change.

**Remediation SLA:**

1. In `core/remediation/sla.py`, make `org_sla_setting` return `None`. Every
   organisation then gets the product defaults.
2. Alternatively, remove SLA computation from Audit altogether. That is a
   larger Audit change, because due dates feed the remediation queue and the
   reports.
3. Delete `ccure_platform/plan/remediation_sla.py` and its API names, and
   remove `PUT /remediation/sla-policy`.

## 10. As built (29 Sep 2026)

**Commits:**

| Commit         | Content                                                                           |
| -------------- | --------------------------------------------------------------------------------- |
| 8.4a `9f0b485` | `ccure_platform/plan/`, the API functions, the plan-field ratchet inverted        |
| 8.4b `b8b5e83` | quota seam: `core.quota`                                                          |
| 8.4c `ec8a765` | scope seam: `core.scan_scope`                                                     |
| 8.4d `67c3f48` | SLA seam: `core.remediation.sla`, plus the containment test                       |
| 8.4e           | the two purge tasks move to `ccure_platform/identity/account_maintenance.py` (Q6) |

**Owner's answers to §8:**

- **Q1:** Option A.
- **Q2 and Q3:** the product SLA defaults and `REQUIRE_SCAN_SCOPE` stay with
  Audit.
- **Q4:** findings F1–F4 are recorded and not fixed.
- **Q5:** removing the ORM relationships `Organization.assets` / `.scans` is a
  separate item.
- **Q6:** the purge tasks moved.

### Old access → new

| Consumer                                                                                                                                                                                                | Before                               | After                                                                                                                                         |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `core.quota.check_scan_quota`                                                                                                                                                                           | organisation row plus `_PLAN_LIMITS` | `effective_scan_limits()` → `api.scan_limits().effective`                                                                                     |
| `get_quota_status`, dashboard                                                                                                                                                                           | `_limits(plan)`                      | `api.scan_limits().plan_defaults` (F2 preserved)                                                                                              |
| `scope_for_org`, `enforce_org_scan_scope`, `validate_scan_targets`, orchestrator                                                                                                                        | organisation row                     | a `ScanScopeView` from `core.scan_scope.org_scan_scope()`; `validate_scan_targets(…, scope=)`                                                 |
| `routers.phase_scans` ×3, `routers.scan_schedules`, `core.scheduling.dispatcher`, `routers.credentialed`, `routers.credentials`, `core.tasks._bind_scan_scope`, `ccure_audit.services.baseline_mapping` | `db.query(Organization)`             | `org_scan_scope(db, org_id)`. None means the organisation does not exist, so the dispatcher's and `baseline_mapping`'s refusals are unchanged |
| `sla_policy_for_org` and its callers (`core.tasks` SLA pass, `remediation.reporting`, `remediation.workflow.apply_sla`, `routers.remediation` ×7)                                                       | `org.settings["remediation_sla"]`    | `sla_policy_for_org_id()` / `org_sla_setting()` → `api.remediation_sla_setting()`; `apply_sla(…, policy=)`                                    |
| `PUT /remediation/sla-policy`                                                                                                                                                                           | wrote `org.settings`                 | `stored_sla_setting()` then `store_sla_setting()` → `api.store_remediation_sla_setting()`                                                     |
| `normalise_scope` (admin write-side validation)                                                                                                                                                         | `core.scan_scope`                    | `ccure_platform.plan.scan_scope`                                                                                                              |
| purge of unverified accounts and expired sessions                                                                                                                                                       | `core.tasks`                         | `ccure_platform.identity.account_maintenance`, with the same names, queue, logger and beat entries                                            |

### Counts

| Measure                         | Before 8.4 | After                                                 |
| ------------------------------- | ---------- | ----------------------------------------------------- |
| Direct identity queries         | 17         | **2**: the WebSocket ticket logins, kept for Phase 10 |
| Identity joins and eager loads  | 2          | **2**: the same two, kept for Phase 10                |
| Module code naming a plan field | 7          | **0**, held at zero by the ratchet                    |
| Files importing identity        | 25         | 20                                                    |

### Verification

- **Behaviour.** Every organisation (4, plus a missing one) was resolved
  read-only against the live database through the old code and then the new,
  and the two JSON documents are identical: enforced and displayed limits,
  the whole `GET /scan/quota` payload, the scope with `REQUIRE_SCAN_SCOPE` on
  and off, and the resolved SLA policy.
- **OpenAPI.** The test pinning it caught one endpoint docstring edit, and a
  second was found by review. Both are restored and noted in comments.
- **Two defects my own edits introduced, caught before commit:**
  - `baseline_mapping` read `org.id` in a second method;
  - the SLA endpoint's docstring change altered OpenAPI.
- **The test pinning a view field to a column name.** `ScanLimits` first
  named its fields like the columns (`max_scans_per_day`), and the inverted
  ratchet flagged the seam as reading the columns. The view's fields were
  renamed (`scans_per_day`, `concurrent_scans`, …) so the two cannot be
  confused.

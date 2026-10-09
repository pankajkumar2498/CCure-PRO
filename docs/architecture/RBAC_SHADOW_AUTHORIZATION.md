# RBAC shadow authorization (RBAC-3)

> **RETIRED (RBAC-8).** The shadow comparison described below was removed with the legacy
> authorization model: Platform RBAC is the only authority and there is no second decision to
> compare. This document is kept as history. See [RBAC_CUTOVER.md](RBAC_CUTOVER.md).

> **RBAC-3 = SHADOW ONLY. LEGACY AUTHORIZATION = AUTHORITATIVE.**

RBAC-3 evaluates the new RBAC engine **beside** every legacy permission check and compares the two decisions. It changes no authorization outcome: the legacy check is computed first, its answer is what the guard returns or raises, and the comparison only _observes_ it. It is **off by default**, it is not enabled in any deployed configuration, and it must not be enabled globally in production. Nothing else changed: `require_permission`, `require_role` and `user_has_permission` decide as they always did, no route was migrated, `/auth/me`, the frontend, authentication, MFA, service tokens, tenant isolation, organisation switching and the gateway are untouched, no production user is assigned to a new role, and no production table or migration was added. See [RBAC_FOUNDATION.md](RBAC_FOUNDATION.md) and [RBAC_PERMISSION_CATALOG.md](RBAC_PERMISSION_CATALOG.md).

## 1. Architecture

```
legacy guard (require_permission / user_has_permission / require_role)
   │  1. decides, exactly as before            ← THE ANSWER
   │  2. hands the decision to the hook (returns nothing)
   ▼
shadow_runtime.observe_*   flag? sample? re-entrant?  → return at once when off
   ▼
own read-only session (SET TRANSACTION READ ONLY, statement timeout)
   ▼
shadow.shadow_compare      golden mapping → catalogue → grants → engine.decide
   ▼
ShadowResult → ShadowRecorder (counts, bounded mismatch buffer, privacy-safe log)
   │
   ▼  3. the guard returns / raises its OWN decision
```

| Piece      | Where                                                                                | Job                                                                                                                                                         |
| ---------- | ------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hook       | `ccure_platform/rbac/dependencies.py` (`_observe_permission`, `_observe_role_check`) | The single reusable point: every permission check in the application is `user_has_permission`, and every guard calls it. Hundreds of routes are not edited. |
| Runtime    | `rbac/shadow_runtime.py`                                                             | Flag, sampling, re-entrancy guard, own session, containment, recorder.                                                                                      |
| Comparison | `rbac/shadow.py`                                                                     | Pure `compare_decision`; `shadow_compare` reads the database; result types; recorder.                                                                       |
| Mapping    | `Backend/data/rbac/golden_legacy_mapping.json` via `rbac/legacy_map.py`              | The RBAC-2 golden mapping — **no second mapping system**.                                                                                                   |
| Matrix     | `scripts/rbac/shadow_equivalence.py`                                                 | Runs every legacy atom for every role through the real hook; always rolled back.                                                                            |
| Evidence   | `Backend/data/rbac/legacy_role_name_dependencies.json`                               | Every remaining role-name decision, for RBAC-4.                                                                                                             |

The legacy decision logic itself moved into `_legacy_decision` **unchanged**. `user_has_permission` is the same function (one new keyword-only `operation`, used only for diagnostics) and `api.require_permission is rbac.dependencies.require_permission` still holds. The guards gained an optional `request` parameter, used only to name the route; it does not appear in OpenAPI.

## 2. Configuration

| Setting                            | Default   | Meaning                                                                                                                                          |
| ---------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `RBAC_SHADOW_MODE`                 | **`off`** | `off` or `observe`. Anything else is `off`, and a typo is logged once — it must never turn on a mechanism that queries the database per request. |
| `RBAC_SHADOW_SAMPLE_RATE`          | `1.0`     | Fraction of legacy checks also evaluated (0.0–1.0; clamped). Use below 1.0 where load matters.                                                   |
| `RBAC_SHADOW_LOG_MATCHES`          | `false`   | Log matches too. Off: matches are only counted.                                                                                                  |
| `RBAC_SHADOW_MISMATCH_BUFFER`      | `200`     | Recent mismatches and errors kept per process.                                                                                                   |
| `RBAC_SHADOW_STATEMENT_TIMEOUT_MS` | `250`     | The shadow session's statement timeout. A slow shadow query is an `ERROR` result, never a slow request.                                          |

Defined in `config.py` (`RbacShadowConfig`, aliased on `AppConfig`) like every other flag, documented in `.env.example`, and **absent from `docker-compose.yml`** and every deployed environment. When off, an observe call returns before it imports, queries or allocates anything. To compare in a controlled way, set `RBAC_SHADOW_MODE=observe` for one process or one staging copy — never globally in production — and read the `ccure.rbac.shadow` log or `shadow_runtime.recorder().snapshot()`.

## 3. Result kinds and classifications

| Kind               | Classification              | Meaning                                                                                                                                                                |
| ------------------ | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **MATCH**          | `allow_both`, `deny_both`   | Both sides answered and agree.                                                                                                                                         |
| **MISMATCH**       | `new_denies_legacy_allows`  | The legacy role holds the atom; the new model does not grant every mapped key. The reason names each key and why (`missing_permission`, `platform_scope_required`, …). |
|                    | `new_allows_legacy_denies`  | The new model grants every mapped key; the legacy role does not hold the atom.                                                                                         |
| **NOT_COMPARABLE** | `retired_atom`              | RBAC-2 retired the atom (nothing enforces it); no new key exists.                                                                                                      |
|                    | `unmapped_atom`             | The atom is not in the golden mapping (unknown).                                                                                                                       |
|                    | `scope_deferred`            | A resource in another organisation, or a scope-driven denial: the deferred scope model (§6).                                                                           |
|                    | `principal_not_provisioned` | The user has **no** RBAC assignment at all, so the new side has nothing to compare.                                                                                    |
|                    | `catalogue_not_populated`   | The RBAC catalogue has not been synced to this database.                                                                                                               |
|                    | `role_name_check`           | A `require_role` guard: there is no permission to compare (RBAC-4 evidence).                                                                                           |
| **ERROR**          | `evaluator_error`           | The comparison failed; the reason is the exception _class_, never its message.                                                                                         |
|                    | `mapping_unavailable`       | The golden mapping could not be read.                                                                                                                                  |
|                    | `mapping_drift`             | The mapping names a key the catalogue lacks.                                                                                                                           |

**Unknown is not a match, and absence is not a pass.** A comparison that cannot be made is `NOT_COMPARABLE`, never counted as a match or a mismatch in either direction. A user who _had_ a role and lost it (an assignment exists, none live) is a real divergence — a `MISMATCH` — not "unprovisioned".

A **split** atom (one legacy atom, several new keys) is ALLOW only if _every_ key is allowed; a **merge** (several atoms, one key) compares each atom on its own. `mapped` and `replaced` atoms are compared; `retired` and unknown ones are not.

## 4. What a result carries

Principal id and kind, the principal's organisation, the legacy role's label (diagnostic only — the new decision is identical whatever it says), the principal's RBAC assignments (role key, state, scope, live), the legacy atom and its mapping status, the mapped keys, **both decisions**, each key's decision and reason, the requested and resource organisation, the operation (`METHOD route-template`, where the route is known), the duration, and the kind, classification and reason. That is enough to diagnose a mismatch without a debugger: which user, which atom, which keys, who said what, and why.

## 5. Failure behaviour

| What fails                                   | What happens                                                                                                                    |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| Flag off, unknown or garbage value           | Nothing runs; legacy decides.                                                                                                   |
| Configuration, sampling or the hook's import | Swallowed; legacy decides.                                                                                                      |
| Opening the shadow session                   | Swallowed; nothing recorded; legacy decides.                                                                                    |
| A shadow query fails or times out            | Rolled back with the shadow's own transaction; recorded as `ERROR`; legacy decides. The request's transaction is never touched. |
| The golden mapping is unreadable or drifted  | Recorded as `ERROR`; legacy decides.                                                                                            |
| The comparison or the recorder raises        | Swallowed; legacy decides.                                                                                                      |
| The **legacy** check itself raises           | Propagates, exactly as before — the hook does not hide the guard's own errors.                                                  |

**Shadow ALLOW cannot grant access; shadow DENY cannot remove access; shadow ERROR cannot change access.** `observe_*` return `None`, so there is nothing for a caller to branch on, and the tests prove it end to end on real routes (`tests/rbac/test_rbac_shadow_hook.py`): a legacy viewer holding the new superadmin role still gets 403; a legacy org_admin holding only the new viewer role still gets 200; and eight different ways of making the evaluator fail leave every response unchanged — across 5 legacy roles × 6 RBAC roles × 12 atoms × 6 shadow behaviours.

## 6. Security and privacy rules

- A result has **no field** for a password, token, cookie, MFA secret, header, query string or request body, so none can be logged. A test asserts the field names.
- The operation is a route **template** (`POST /scans/{scan_id}/stop`) — never a raw path, so an identifier in a path is not logged, and never a query.
- Log values are scalars with whitespace folded and capped at 160 characters, so a value cannot forge a second log line.
- An evaluator error is recorded by exception **class**, not message: a database error message can contain parameter values.
- The comparison runs on its **own read-only session**: even a bug in it cannot write. Nothing is persisted — RBAC-3 adds no table and writes no row.
- `MISMATCH` and `ERROR` log at WARNING every time; `NOT_COMPARABLE` is logged once per (classification, atom) per process; `MATCH` is only counted unless `RBAC_SHADOW_LOG_MATCHES`.

## 7. Scope: what is deferred to RBAC-5

**Permission and scope are kept separate; no cross-organisation superadmin model is invented here.** A legacy permission check carries no organisation, so the comparison runs _at the principal's own organisation_. Anything that depends on the deferred model is `NOT_COMPARABLE` / `scope_deferred` — with both decisions still recorded for diagnosis, never forced into a verdict:

- a resource in an organisation other than the principal's;
- a new denial whose reason is scope-driven (`cross_org`, `no_target_org`, `org_switch_required`) where legacy allows;
- the legacy superadmin's implicit all-organisation visibility — 16 sites that widen a query by role name (`_is_superadmin`, §8). That is scope, not a permission, and is not in the permission check at all;
- organisation switching by `org_id` (`credentialed.py`): `platform.organization.switch` exists in the catalogue, the scope model that gives it meaning is RBAC-5.

## 8. RBAC-2 equivalence through the actual mechanism

`scripts/rbac/shadow_equivalence.py` creates, in a transaction that is always rolled back, one user per legacy role holding both that legacy role and the matching new role, then asks the real `user_has_permission` about **every legacy atom (66)** with shadow on. Result:

| Legacy role → new role               | Atoms | MATCH `allow_both` | MATCH `deny_both` | NOT_COMPARABLE `retired_atom` | MISMATCH | ERROR |
| ------------------------------------ | ----: | -----------------: | ----------------: | ----------------------------: | -------: | ----: |
| `superadmin` → `platform.superadmin` |    66 |                 56 |                 0 |                            10 |    **0** | **0** |
| `org_admin` → `platform.org_admin`   |    66 |                 48 |                 8 |                            10 |    **0** | **0** |
| `analyst` → `platform.analyst`       |    66 |                 28 |                28 |                            10 |    **0** | **0** |
| `viewer` → `platform.viewer`         |    66 |                  9 |                47 |                            10 |    **0** | **0** |
| `scanner` → `platform.scanner`       |    66 |                  5 |                51 |                            10 |    **0** | **0** |

All **56 enforced atoms** match for all five roles, with `legacy decision == new decision` on every one; the 10 retired atoms report `retired_atom`. **No mismatch exists to classify.** The matrix is shown to be able to fail: giving the legacy viewer an atom the new viewer lacks produces exactly one `new_denies_legacy_allows` for `scans:execute` with reason `audit.scan.run:missing_permission`, and removing one from the legacy scanner produces one `new_allows_legacy_denies`. An unsynced catalogue yields `catalogue_not_populated` rather than a wall of false mismatches.

## 9. What the shadow sees in production today

Nothing, deliberately. The production database has no RBAC tables, no catalogue and no assignments (RBAC-1 and RBAC-2 are not deployed). If shadow were enabled there it would record `NOT_COMPARABLE` (`catalogue_not_populated`) and never a mismatch. **Real equivalence evidence needs a staging copy** with the migrations applied, the catalogue synced (`scripts/rbac/sync_catalogue.py --apply`) and users provisioned (RBAC-4 prerequisite 1).

## 10. Remaining legacy role-name dependencies (RBAC-4 evidence)

RBAC-3 migrates and deletes **nothing**. The 40 sites in 22 files the role-identity ratchet counts are recorded in `Backend/data/rbac/legacy_role_name_dependencies.json`, each with its category and what replaces it; a test fails if the list and the code disagree.

| Category               | Sites | Meaning and phase                                                                                                                     |
| ---------------------- | ----: | ------------------------------------------------------------------------------------------------------------------------------------- |
| `scope_cross_org`      |    16 | The superadmin by name widens which organisation's data a query returns. This is scope, not a permission: deferred to RBAC-5.         |
| `permission_guard`     |    10 | A route or router is guarded by a role name. RBAC-4 replaces it with the listed permission.                                           |
| `assignment_hierarchy` |     4 | A rule about which roles may be assigned, by name. RBAC-4 replaces it with the escalation ceiling and platform.role.assign_platform.  |
| `organization_switch`  |     3 | The superadmin names another organisation to act in. RBAC-4/5: platform.organization.switch plus the scope model.                     |
| `permission_bypass`    |     3 | A permission check is skipped for the superadmin by name. RBAC-4 removes the shortcut: the superadmin role holds materialised grants. |
| `provisioning_lookup`  |     1 | A role is looked up by name to give it to a new account. RBAC-4: by role key, in a seed/bootstrap context.                            |
| `default_role`         |     1 | The self-registration default is looked up by role name. RBAC-4: the rbac_default_roles reference.                                    |
| `legacy_authority`     |     1 | The legacy check itself. Removed with the legacy model in RBAC-8.                                                                     |
| `bootstrap`            |     1 | First-run provisioning of the initial administrator. A permitted seed/bootstrap context; moves to a role key.                         |

Files, by what they need:

- **`permission_guard`** — `ccure_platform/administration/email_domains.py`, `ccure_platform/audit_log/router.py`, `routers/admin_nvd.py`, `routers/compliance.py`
- **`permission_bypass`** — `routers/reports.py`, `routers/scan_history.py`
- **`assignment_hierarchy`** — `ccure_platform/administration/users.py`
- **`scope_cross_org`** — `ccure_platform/administration/users.py`, `ccure_platform/audit_log/router.py`, `routers/assets.py`, `routers/compliance.py`, `routers/credentials.py`, `routers/dashboard.py`, `routers/findings.py`, `routers/phase_scans.py`, `routers/remediation.py`, `routers/reports.py`, `routers/scan_history.py`, `routers/scan_policies.py`, `routers/scan_schedules.py`, `routers/web_scans.py`, `scans/scan_access.py`
- **`organization_switch`** — `routers/credentialed.py`
- **`default_role`** — `ccure_platform/identity/router.py`
- **`provisioning_lookup`** — `ccure_platform/administration/organizations.py`
- **`bootstrap`** — `main.py`
- **`legacy_authority`** — `ccure_platform/rbac/dependencies.py`

At runtime, with shadow on, each `require_role` guard that fires is also recorded as `not_comparable/role_name_check` with the roles it named and its route template — live evidence of which routes still decide by role name.

## 11. Required before RBAC-4

1. **Provision assignments in a controlled environment.** Mirror each user's legacy role into `rbac_user_roles` (the golden mapping gives the role key). Until then every comparison is `principal_not_provisioned`. Provisioning must be a reviewed, backed-up operation of its own; RBAC-3 does none.
1. **Apply the migrations and sync the catalogue** (`a7c1e5b3d9f2`, `b8d2f6a4c0e1`; `scripts/rbac/sync_catalogue.py --apply`) on that environment, after a backup.
1. **Run shadow there and reach zero `MISMATCH` and zero `ERROR`** over a representative period, reading `new_denies_legacy_allows` and `new_allows_legacy_denies` by atom. Every `NOT_COMPARABLE` classification must be explained (retired, scope-deferred, role-name) or removed.
1. **Decide the scope model (RBAC-5)** before any route whose behaviour depends on it moves: how a platform-scope assignment reaches another organisation, and what replaces the 16 `_is_superadmin` visibility sites.
1. **Work through the 40 recorded sites**, category by category: the 10 role-name guards become `require`-style permission guards; the 3 superadmin permission bypasses are removed (the grants already cover them); the assignment hierarchy becomes the escalation ceiling; the default role, provisioning and bootstrap lookups move to role keys in seed context.
1. **Decide the start-up wiring** of the catalogue sync, which RBAC-2 deliberately left out.
1. **Decide where mismatches are persisted**, if anywhere: RBAC-3 only logs and counts, per process.

## 12. Tests

`tests/rbac/test_rbac_shadow.py` (the comparison and the real catalogue), `test_rbac_shadow_runtime.py` (flag, sampling, containment, own session, privacy), `test_rbac_shadow_hook.py` (the legacy guards on real routes; the proofs in §5), `test_rbac_shadow_equivalence.py` (§8), `test_rbac_legacy_role_evidence.py` (§10) and `tests/repo/test_rbac_boundaries.py` (only the legacy guards reach the shadow; modules cannot import it; it imports no product).

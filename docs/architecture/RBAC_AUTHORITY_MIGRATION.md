# RBAC-4 — backend authorization migration

> **COMPLETED AND RETIRED (RBAC-8).** The per-path authority switch, the legacy fallback and the
> `RBAC_AUTHORITY_*` settings described below were deleted: Platform RBAC is the only authority.
> Kept as history. See [RBAC_CUTOVER.md](RBAC_CUTOVER.md).

**Status: the mechanism is built and proven in a disposable database; it is OFF in
every deployment.** Legacy authorization (`users.role_id`, `roles`, `role_permissions`)
is still what decides, until an operator switches a path on. Production was not
touched: no user assigned, no flag set, no deploy, no restart.

## What changed

|                                                | Before                                                    | After                                                                                                      |
| ---------------------------------------------- | --------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `require_permission(res, act)`                 | legacy decides                                            | legacy decides; **if the path is switched on, the new engine decides**                                     |
| `user_has_permission(..., authoritative=True)` | –                                                         | same, for in-handler checks the inventory lists as migrated                                                |
| 13 role-name sites                             | `require_role("superadmin")`, `role.name == "superadmin"` | `require_authorized(<key>)` / `has_permission(<key>)`, or the permission check without the name shortcut   |
| Provisioning                                   | none                                                      | `rbac/reconcile.py`, `scripts/rbac/reconcile_assignments.py` (report; apply only in a controlled database) |
| Inventory                                      | 40 sites in prose JSON                                    | `data/rbac/authorization_migration_inventory.json`, generated and tested                                   |

Module code reaches all of it through `ccure_platform.api` (`require_permission`,
`user_has_permission`, `require_authorized`, `has_permission`). Nothing imports RBAC
internals; the 187 `require_permission` call sites were **not** edited — the guard
itself is the seam, which is what makes a per-path rollback a configuration change.

## The authority rule (`rbac/authority.py`)

A **path** is the unit that is switched and rolled back: a legacy atom (`scans:read`) or
a permission key (`platform.email_domain.read`). It is decided by the new engine only if

1. `RBAC_AUTHORITY_MODE=enforce`, **and**
2. the path is in `RBAC_AUTHORITY_PATHS` (comma list, or `*` for every migrated path), **and**
3. the inventory marks it `migrated` (configuration cannot switch on a deferred path), **and**
4. it has not been rolled back (`authority.roll_back(path)`).

Then the engine evaluates the principal's grants (shadow's `compare_decision`, one
mapping — the RBAC-2 golden file — and no second one):

| New side                                                                                                    | Result                                                     |
| ----------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| MATCH or MISMATCH                                                                                           | **the new decision is enforced**; a divergence is recorded |
| principal never provisioned (no assignment row), catalogue not synced, scope-driven denial, evaluator error | **legacy decides**, and the fallback is recorded           |
| principal had a role and lost it, or holds only a retired role                                              | **denied** (the rows exist, none is live)                  |

So enabling a path never locks out an account nobody has provisioned, and removing a
permission, retiring a role or revoking an assignment takes effect on the next request.

No role _name_ is an input: the engine is handed grants. The legacy fallback for a
replaced role-name check is derived from the golden mapping (the legacy roles whose new
role is granted the key), so no role is named in new code, and there is **no superadmin
shortcut** — the superadmin role holds materialised grants like any other.

A user with no _legacy_ role is still refused by the guard before authority is asked
(`users.role_id` stays mandatory until RBAC-8).

## Controlled cutover, per path

1. Sync the catalogue and provision a **disposable** database (`scripts/rbac/sync_catalogue.py --apply`,
   `scripts/rbac/reconcile_assignments.py` report, then `--apply --allow-database <name>`).
2. `python -m scripts.rbac.shadow_equivalence` — every migrated path MATCHes for all five roles.
3. Set `RBAC_AUTHORITY_MODE=enforce`, `RBAC_AUTHORITY_PATHS=<one path>`; keep
   `RBAC_SHADOW_MODE=observe` to watch. `authority.recorder.snapshot()` counts, per path,
   how many decisions were `new` and how many fell back to `legacy`, and lists divergences.
4. Widen the list path by path.

**Rollback:** remove the path from `RBAC_AUTHORITY_PATHS` (or set the mode `off`) and restart
the process. No data, schema or code changes; the legacy implementation was never removed.
In-process, `authority.roll_back(path)` does it for one path.

## What migrated

- **Permission atoms (one-to-one mapped, no hierarchy / switching / cross-organisation
  dependence): 38 atom paths** — assets, compliance, credentials, dashboard, findings, reports,
  scan policies, scan schedules, and the scan lifecycle. 162 route guards plus the
  in-handler `findings:accept_risk`, `reports:read`, `reports:delete` and `scans:read` checks.
- **Role-name sites replaced by keys (13 of 40):** the email-domain routes
  (`platform.email_domain.read` / `.manage`), audit retention preview
  (`platform.audit_log.retention`), NVD/feed sync (`audit.vuln_feed.manage`), shared
  compliance rules (`audit.compliance.manage_shared_rules`), and the superadmin shortcuts in
  `reports.py` (×2) and `scan_history.py`.

## What is deferred, and why (the inventory has every site)

| Deferred                                                               | Count     | Why                                                             | To     |
| ---------------------------------------------------------------------- | --------- | --------------------------------------------------------------- | ------ |
| `scope_cross_org` (`_is_superadmin` widening a query)                  | 16        | scope, not permission; tenant-isolation queries untouched       | RBAC-5 |
| `assignment_hierarchy`                                                 | 4         | which roles may be assigned: needs scope + escalation           | RBAC-5 |
| `organization_switch`                                                  | 3         | `platform.organization.switch` plus the scope model             | RBAC-5 |
| provisioning lookup / default role / bootstrap / the legacy check      | 4         | provisioning, not authorization                                 | RBAC-8 |
| atoms `users:*`, `organizations:*`, `roles:*`, `settings:*`, `audit:*` | 25 guards | hierarchy, provisioning, split atoms, org-scoped log visibility | RBAC-5 |
| in-handler `scans:read_all`                                            | 3         | per-user versus organisation-wide visibility                    | RBAC-5 |

## Provisioning and reconciliation

`reconcile` (read-only) reports, per account: `missing` (no live assignment),
`incorrect` (not the golden role at the golden scope), `duplicate` (conflicting live
assignments), `revoked_but_assigned` (deleted/disabled account still holding one) and
`without_legacy` (an assignment with no legacy role / no such account). `apply` assigns
**only `missing`**, with the golden role (superadmin → platform scope; the rest →
organisation scope in the account's own organisation), audited as `rbac.role.assigned`
with `system:rbac-reconcile`. The script refuses `--apply` unless `--allow-database`
names the connected database, and never on `ccure_db` / `ccure_test` / `vuln_intel`.
**No production user is assigned automatically.**

## Tests

`tests/rbac/test_rbac_authority.py` (behaviour through real guards: authorized,
unauthorized, permission removal, display-name change, multi-role union, retired role,
custom-role limits, wrong organisation, forged claims, spoofed role names, fallback,
rollback, shadow beside authority), `…_authority_equivalence.py` (every migrated path,
all five roles, new engine answering), `…_migration_inventory.py` (deterministic,
complete, honest), `…_reconcile.py`.

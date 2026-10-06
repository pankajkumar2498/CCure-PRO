# RBAC-8 — final cutover: Platform RBAC is the only authorization model

> **Historical record (superseded 4 Oct 2026).** This describes the RBAC-8 plan to migrate an
> existing installation. It was never executed: the development installation was instead
> **reset to a native-only state** (`backups/native_clean_reset_20261004/final-report.md`,
> revision `d4f8b2c6e0a1`), which removed the legacy tables, `users.role_id`, `cutover.py`,
> the golden mapping and the cutover checklist. The "prepared, not executed" status below
> is therefore a statement about that moment, not the current state. Current state: `CLAUDE.md`,
> "RBAC capability".

Status: **code complete and verified in disposable databases; production cutover prepared,
not executed.** Nothing in this phase touched the live database, deployed, or enabled
anything in production. The exact approvals the operator still needs are in §9.

## 1. Final architecture

- **One authority.** `ccure_platform/rbac/dependencies.py` (`require_authorized(key)`,
  `has_permission(db, account, key, org_id=)`, `decide`) answers from the Platform RBAC
  engine and from nothing else. There is no fallback, no authority switch, no per-path
  list, no shadow comparison and no "if superadmin" shortcut.
- **Scope** (`rbac/scope.py`): cross-organisation reach is the platform-scope grant of
  `platform.organization.switch`; the active organisation is validated server-side and
  every switch is audited.
- **Identity payload** (`/auth/me`, sign-in): `authorization` carries permission keys by
  scope, the validated active organisation, `can_switch_organisation` and display-only
  assignment labels. It carries no legacy role, role id, role name or permission atom.
- **Frontend** (`shell/auth/authorization.js`): `can(user, key, ctx)` over that payload.
  A backend without the contract is reported ("Backend not compatible") and nobody is
  signed in; the older-backend fallback is deleted.

## 2. Provisioning

| Concern             | Behaviour                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Existing accounts   | `scripts/rbac/cutover.py apply` (and `reconcile`) assigns the RBAC role the **golden mapping** names for the account's legacy role; nothing else.                                                                                                                                                                                                                                                                                  |
| Categories reported | missing · incorrect · duplicate · revoked-legacy-but-assigned · RBAC-without-legacy · unmapped legacy role · no legacy role.                                                                                                                                                                                                                                                                                                       |
| Unmapped / no role  | The account holds **nothing** and is reported. No role is ever invented.                                                                                                                                                                                                                                                                                                                                                           |
| Default role        | `rbac_default_roles` (purpose `self_registration`): an existing, active, organisation-assignable, non-privileged role, validated on every use (`governance.default_role_violations`). Unset or invalid → the new account has **no role**.                                                                                                                                                                                          |
| First administrator | `provisioning.grant_platform_administrator`, reached only from first-run bootstrap (empty system) and the operator script `scripts/rbac/bootstrap_admin.py`. Idempotent, audited (`rbac.bootstrap.administrator` / `rbac.recovery.administrator`), refuses a system that already has an administrator unless told otherwise, refuses an account that is not active, verified and approved. It is an ordinary revocable assignment. |
| New organisation    | Creating an organisation with a first administrator assigns the organisation-administrator role **through the governed assignment API**, by the creating actor, in the same transaction: no half-provisioned organisation, nothing privileged granted automatically.                                                                                                                                                               |
| Role changes        | Only through Platform RBAC administration (`/platform/rbac/*`, `PATCH /admin/users/{id}/role` → `rbac_role_id`), writing `rbac_user_roles`. The legacy `/admin/roles` routes are removed.                                                                                                                                                                                                                                          |

## 3. Account states (deterministic)

Active with a live assignment → what the roles grant. Active with none → nothing.
Disabled, deleted or purged → nothing. Revoked or expired assignment → nothing on the next
call. Retired role → nothing. Several assignments → the union and nothing more. Purge:
the offboarding hook records and removes the account's assignments, role and audit history
stay, and `ON DELETE RESTRICT` is unchanged.

## 4. Legacy model — what became of it

| Item                                                                                                                                                                                                | Final status                                                                                                                                                                                        |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `users.role_id`                                                                                                                                                                                     | **Deprecated, nullable, non-authoritative** (migration `c9e3a7b5d1f2`). Kept for history and for rollback of the schema; read only by reconciliation. Removal is a later, separately reviewed step. |
| `roles`, `permissions`, `role_permissions` tables                                                                                                                                                   | **Retained, non-authoritative.** History, the target of `users.role_id`'s foreign key, and the input of reconciliation. No runtime decision reads them.                                             |
| Legacy atoms (`scans:read`, …)                                                                                                                                                                      | Only in migration history, documentation, audit data and the deterministic golden mapping.                                                                                                          |
| `require_permission`, `require_role`, `user_has_permission`, `check_role_assignment`, `auth/rbac.py`, `RBAC_AUTHORITY_*`, `RBAC_SHADOW_*`, `rbac/{authority,shadow,shadow_runtime,legacy_scope}.py` | **Deleted.**                                                                                                                                                                                        |
| Role-name authorization sites                                                                                                                                                                       | **0** (was 40). The ratchet baseline is empty and must stay empty.                                                                                                                                  |
| Shadow mode                                                                                                                                                                                         | **Retired.** No dual authority exists to compare.                                                                                                                                                   |

Guards: `tests/repo/test_rbac_final_ratchet.py`, `tests/repo/test_rbac_role_identity.py`,
`Backend/data/rbac/authorization_migration_inventory.json` (generated; statuses
migrated / display-only / compatibility-history / removed) and
`Frontend/authorization-inventory.json`.

## 5. Recovery: losing the last administrator

The governed API refuses to remove the last superadmin or the last organisation role
administrator. If it nevertheless happens (database edit, account lockout), the system is
not permanently unmanageable and there is **no hidden backdoor**:

1. Take a backup (`scripts/backup_db.sh --skip-reference-data`).
2. As the operator, on the host:
   `python -m scripts.rbac.bootstrap_admin --email <account> --reason "<why>" --recover --allow-database <name> [--production-approved <ref>]`
3. Sign in, use RBAC administration to restore the organisation role administrators.

It is explicit, operator-run (needs host/database access), audited as
`rbac.recovery.administrator`, and revocable like any assignment.

## 6. Cutover sequence (idempotent; do not run against production without approval)

Machine-readable: `Backend/data/rbac/cutover_checklist.json`; human-readable:
`python -m scripts.rbac.cutover checklist --md`.

1. **backup** — `scripts/backup_db.sh` (full dump before the window).
2. **plan** — `cutover.py plan` (read-only): readiness, reconciliation counts, what `apply` would do.
3. **schema** — `alembic upgrade heads` (creates/verifies the RBAC schema; adds `c9e3a7b5d1f2`).
4. **catalogue** — sync the 67-permission catalogue.
5. **provision** — reconcile: assign every active account its mapped role.
6. **administrator** — verify a privileged administrator exists (`bootstrap_admin.py` if not).
7. **default_role** — configure the self-registration default (or leave unset).
8. **organisations** — verify every organisation has an organisation administrator.
9. **deploy** — deploy the RBAC-8 release (this is what makes RBAC authoritative; there is no switch).
10. **smoke** — sign in as superadmin / org admin / viewer; critical paths; `cutover.py verify`.
11. **audit** — verify the provisioning and bootstrap events in `audit_logs` / `platform_audit_events`.
12. **legacy** — leave `roles/permissions/role_permissions` and `users.role_id` in place (non-authoritative); removal is a later reviewed change.
13. **rollback** — see §7.

`cutover.py apply` performs steps 1–8 idempotently and stops at the first failing step; it
refuses the live databases without `--production-approved <ref>` and any database without
`--allow-database <name>`.

## 7. Rollback

Rollback is an **external deployment mechanism**, not application logic: redeploy the
previous release image. Before redeploying, `cutover.py rollback-prepare --apply` back-fills
`users.role_id` for accounts created without one from their RBAC assignments (refusing any
it cannot map) so the previous release's authorization can run. No assignment is removed.
The database restore path (§ backups in CLAUDE.md) applies if a restore is preferred. After
a rollback the previous release has no knowledge of RBAC; re-run `plan` before cutting over
again.

## 8. Verification recorded for this change

See the commit and the final report: targeted suites, the full backend suite, the full
frontend suite, lint and build, with exact figures.

## 9. Approvals still required (not guessed, not done)

- DBA/operator approval and a maintenance window for the production database
  (`--production-approved <reference>`), including `alembic upgrade heads` on `ccure_db`.
- Deployment of the release (this phase deploys nothing).
- A decision on the production default role (leaving it unset is safe: new registrations
  hold no role) and on whether any production account has no legacy role and needs one.

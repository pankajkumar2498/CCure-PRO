# RBAC permission catalogue (RBAC-2)

**Status: prepared, not live.** RBAC-2 populates the new permission catalogue and role model and maps every legacy atom onto them. **Legacy authorization remains authoritative**: `users.role_id`, `roles`, `permissions`, `role_permissions`, `require_permission`, `require_role` and `user_has_permission` are the only thing that decides a request, no route uses the new engine, `/auth/me` and the frontend are unchanged, no user is assigned to a new role, and nothing populates these tables until an operator runs `scripts/rbac/sync_catalogue.py --apply`. Design: [RBAC_FOUNDATION.md](RBAC_FOUNDATION.md). Machine-readable form: `Backend/data/rbac/golden_legacy_mapping.json`.

## 1. In numbers

|                                        |                                                                            |
| -------------------------------------- | -------------------------------------------------------------------------- |
| Permissions in the catalogue           | **67** (30 `platform.*`, 37 `audit.*`)                                     |
| Organisation-scope / platform-scope    | 50 / 17                                                                    |
| Privileged (their denials are audited) | 32                                                                         |
| Continuity permissions                 | 4                                                                          |
| Legacy atoms                           | **66** = 65 seeded + 1 found only on the live database (`audit_logs:read`) |
| Mapped / replaced / retired            | **50 / 6 / 10**                                                            |
| System roles                           | 5 (`platform.superadmin`, `.org_admin`, `.analyst`, `.viewer`, `.scanner`) |
| Reserved, declaring nothing            | `policy.*` (Policy Pro), `rank.*` (Rank), `ir.*` (IR)                      |

## 2. Rules every key follows

- **Grammar.** `<namespace>.<resource>.<action>` — exactly three lower-case segments, no wildcard, no role name, no display name. The identity is stable even if the UI wording changes.
- **Ownership.** The first segment is the declaring namespace, which the platform's registry assigns: `platform` is the platform's (declared in `ccure_platform/permissions.py`), `audit` is Audit's (`ccure_audit/permissions.py`). A module cannot declare another's namespace. Administrators cannot invent a key: the only writer of `rbac_permissions` is catalogue sync.
- **Capability-level, not endpoint-level.** The 17 dashboard routes are one permission (`audit.dashboard.read`). Legacy atoms are merged only where every legacy role held all of them or none, so no role gains or loses anything (see §6).
- **Scope.** `organization` — applies inside one organisation; `platform` — applies to a platform-level resource and is reached only through a platform-scope assignment.
- **Sensitivity.** `privileged` where the capability is irreversible, handles secrets, changes who can do what or how an account authenticates, reaches another tenant, or copies or purges the audit trail. A denied attempt at a privileged permission is audited.
- **Delegation.** A platform-scope permission is never delegable to an organisation role (the database refuses it); every organisation-scope permission is.
- **Continuity.** The four frozen keys: `platform.user.assign_role`, `platform.organization.create`, `platform.role.assign_platform`, `platform.role.create_platform` — the system must always keep an active, verified human holding each.
- **Nothing speculative.** Every key exists because a route, a screen or a role-name check needed it today, or because RBAC governance (RBAC-0) names it. Platform/module administration has **no** permission: `GET /platform/modules` is available to any signed-in user and enabling a module is deployment configuration.

## 3. Platform permissions (owner: ccure_platform)

`org` = organisation scope, `pla` = platform scope, ⚑ = privileged, ● = continuity.

| Key                                    | Scope | Sens. | Cont. | Legacy source                  | Why it exists                                                                                                                                                                  |
| -------------------------------------- | ----- | ----- | ----- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `platform.user.read`                   | org   |       |       | `users:read`                   | Gates the user list and the pending-approval list (admin users routes).                                                                                                        |
| `platform.user.create`                 | org   |       |       | `users:create`                 | Gates account creation by an administrator.                                                                                                                                    |
| `platform.user.update`                 | org   |       |       | `users:update`                 | Gates editing an account and changing its active status. Split from the legacy users:update with the same holders.                                                             |
| `platform.user.delete`                 | org   |       |       | `users:delete`                 | Gates the reversible removal of an account. Split from the legacy users:delete with the same holders.                                                                          |
| `platform.user.purge`                  | org   | ⚑     |       | `users:delete`                 | Irreversible: split from the soft delete so it can be withheld on its own. Same holders as the legacy users:delete.                                                            |
| `platform.user.approve`                | org   | ⚑     |       | `users:update`                 | An access decision about a person. Split from the legacy users:update with the same holders.                                                                                   |
| `platform.user.reset_credentials`      | org   | ⚑     |       | `users:update`                 | Changes how an account authenticates. Split from the legacy users:update with the same holders.                                                                                |
| `platform.user.assign_role`            | org   | ⚑     | ●     | `users:update`                 | RBAC governance: who may give a role to whom. Split from the legacy users:update with the same holders. A continuity permission: every active organisation must keep a holder. |
| `platform.user.move_org`               | pla   | ⚑     |       | — (replaces a role-name check) | The legacy route requires users:update and then refuses anyone but a superadmin by name; the name check becomes this permission.                                               |
| `platform.role.read`                   | org   |       |       | `roles:read`                   | Gates the role list. Split from the legacy roles:read with the same holders.                                                                                                   |
| `platform.permission.read`             | org   |       |       | `roles:read`                   | Gates the permissions-of-a-role listing the legacy roles:read also covered; same holders.                                                                                      |
| `platform.role.create`                 | org   | ⚑     |       | `roles:create`                 | RBAC governance. Replaces the legacy roles:create, which no route required and only the superadmin held.                                                                       |
| `platform.role.update`                 | org   | ⚑     |       | `roles:update`                 | RBAC governance. Replaces the legacy roles:update.                                                                                                                             |
| `platform.role.retire`                 | org   | ⚑     |       | `roles:delete`                 | RBAC governance: roles are retired, never deleted. Replaces the legacy roles:delete.                                                                                           |
| `platform.role.create_platform`        | pla   | ⚑     | ●     | `roles:create`                 | RBAC governance (RBAC-0 D13). Replaces the legacy roles:create for platform-scope roles. A continuity permission.                                                              |
| `platform.role.assign_platform`        | pla   | ⚑     | ●     | — (RBAC governance)            | RBAC governance. Without it the legacy rule 'only a superadmin may assign the superadmin role' (a role-name check) has no permission to stand on. A continuity permission.     |
| `platform.role.rename_system`          | pla   | ⚑     |       | — (RBAC governance)            | RBAC governance: a display name is a label, and renaming a system role is a platform decision (RBAC-0).                                                                        |
| `platform.role.retire_system`          | pla   | ⚑     |       | — (RBAC governance)            | RBAC governance (RBAC-0 D12): only platform governance retires a system role.                                                                                                  |
| `platform.role.set_default`            | pla   | ⚑     |       | — (RBAC governance)            | RBAC configuration (RBAC-0 D15). Today's behaviour (Viewer) is unchanged.                                                                                                      |
| `platform.organization.read`           | pla   |       |       | `organizations:read`           | Gates the organisation list and an organisation's detail.                                                                                                                      |
| `platform.organization.create`         | pla   | ⚑     | ●     | `organizations:create`         | Creates a tenancy. A continuity permission.                                                                                                                                    |
| `platform.organization.update`         | pla   | ⚑     |       | `organizations:update`         | Gates organisation edits and status changes.                                                                                                                                   |
| `platform.organization.archive`        | pla   | ⚑     |       | `organizations:delete`         | The legacy routes refuse anyone but a superadmin by name; the legacy organizations:delete was never required. Both become this permission.                                     |
| `platform.organization.set_scan_scope` | pla   | ⚑     |       | — (replaces a role-name check) | The one organisation attribute a tenant administrator must not control; the legacy route checks the role name.                                                                 |
| `platform.organization.switch`         | pla   | ⚑     |       | — (replaces a role-name check) | Superadmins pass an organisation id to act in another tenant today (a role-name check). RBAC-0: reaching another organisation is an explicit, audited permission.              |
| `platform.audit_log.read`              | org   |       |       | `audit:read`                   | Gates the audit-log list and detail routes; the log is a platform service every product writes to.                                                                             |
| `platform.audit_log.export`            | org   | ⚑     |       | `audit:export`                 | Copying the audit trail off the platform is itself an audited event.                                                                                                           |
| `platform.audit_log.retention`         | pla   | ⚑     |       | `audit:purge`                  | The legacy route requires the superadmin role by name and the legacy audit:purge was never required.                                                                           |
| `platform.email_domain.read`           | pla   |       |       | — (replaces a role-name check) | The rules are platform-wide; the legacy routes require the superadmin role by name.                                                                                            |
| `platform.email_domain.manage`         | pla   | ⚑     |       | — (replaces a role-name check) | Platform-wide rules could block another tenant's customers; the legacy routes require the superadmin role by name.                                                             |

## 4. Audit permissions (owner: ccure_audit)

| Key                                    | Scope | Sens. | Cont. | Legacy source                                                              | Why it exists                                                                                                           |
| -------------------------------------- | ----- | ----- | ----- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `audit.dashboard.read`                 | org   |       |       | `dashboard:read`                                                           | Gates the 17 dashboard routes (summary, risk, trends, web-scan views); they are one capability, not 17.                 |
| `audit.scan.read`                      | org   |       |       | `scans:read`                                                               | Gates scan history, progress, web-scan reads, topology and configuration-check reads.                                   |
| `audit.scan.read_all`                  | org   |       |       | `scans:read_all`                                                           | Widens scan visibility from one's own scans to the organisation's.                                                      |
| `audit.scan.run`                       | org   |       |       | `scans:create`, `scans:execute`                                            | Merges the legacy scans:create and scans:execute; every legacy role holds both or neither.                              |
| `audit.scan.lifecycle`                 | org   |       |       | `scans:archive`, `scans:restore`, `scans:recycle`                          | Merges the legacy scans:archive, scans:restore and scans:recycle; the same roles hold all three.                        |
| `audit.scan.purge`                     | org   | ⚑     |       | `scans:purge`                                                              | Irreversible; kept apart from the lifecycle permission.                                                                 |
| `audit.scan_schedule.read`             | org   |       |       | `scan_schedules:read`                                                      | Gates schedule reads: the list, one schedule, its run history, and the timezone and credential pickers.                 |
| `audit.scan_schedule.manage`           | org   |       |       | `scan_schedules:create`, `scan_schedules:update`, `scan_schedules:execute` | Merges the legacy scan_schedules:create, update and execute; the same roles hold all three.                             |
| `audit.scan_schedule.delete`           | org   |       |       | `scan_schedules:delete`                                                    | Held by fewer roles than the rest of schedule management, so it cannot merge into it.                                   |
| `audit.scan_policy.read`               | org   |       |       | `scan_policies:read`                                                       | Gates policy reads: the list, one policy, its usage, settings and validation.                                           |
| `audit.scan_policy.manage`             | org   |       |       | `scan_policies:create`, `scan_policies:update`                             | Merges the legacy scan_policies:create and update; the same roles hold both.                                            |
| `audit.scan_policy.delete`             | org   |       |       | `scan_policies:delete`                                                     | Held by fewer roles than policy management, so it cannot merge into it.                                                 |
| `audit.credential.read`                | org   |       |       | `credentials:read`                                                         | Gates reading credential profile metadata (type, owner, target); the secret itself is never returned.                   |
| `audit.credential.manage`              | org   | ⚑     |       | `credentials:create`, `credentials:update`                                 | Handles secrets. Merges the legacy credentials:create and update; the same roles hold both.                             |
| `audit.credential.validate`            | org   |       |       | `credentials:validate`                                                     | Gates testing a stored credential against a host, which makes an outbound authentication attempt.                       |
| `audit.credential.delete`              | org   | ⚑     |       | `credentials:delete`                                                       | Destroys stored secrets, and is held by fewer roles than creating or editing one.                                       |
| `audit.asset.read`                     | org   |       |       | `assets:read`                                                              | Gates the asset inventory reads: list, detail, services, certificates, change log and coverage.                         |
| `audit.asset.update`                   | org   |       |       | `assets:update`                                                            | Gates editing an asset's tags, notes and metadata.                                                                      |
| `audit.asset.import_amt`               | org   |       |       | `settings:update`                                                          | The route was gated by the generic settings:update; the capability is an asset import, so it is named for what it does. |
| `audit.finding.read`                   | org   |       |       | `findings:read`                                                            | Gates finding reads: the list, grouped views, detail, history and the remediation queues.                               |
| `audit.finding.update`                 | org   |       |       | `findings:update`                                                          | Gates triage and remediation moves: status, notes, assignment and state.                                                |
| `audit.finding.accept_risk`            | org   | ⚑     |       | `findings:accept_risk`                                                     | An organisational decision that clears an overdue list; kept apart from findings:update.                                |
| `audit.report.read`                    | org   |       |       | `reports:read`                                                             | Gates report reads and exports: the report list, downloads and the spreadsheet export.                                  |
| `audit.report.delete`                  | org   |       |       | `reports:delete`                                                           | Gates deleting a generated report; held by fewer roles than reading one.                                                |
| `audit.remediation.manage_sla`         | org   | ⚑     |       | `settings:update`                                                          | The route was gated by the generic settings:update; the capability is the deadline policy.                              |
| `audit.compliance.read`                | org   |       |       | `compliance:read`                                                          | Gates compliance reads: dashboards, frameworks, controls, findings, runs, evidence and schedules.                       |
| `audit.compliance.scan`                | org   |       |       | `compliance:scan`                                                          | Gates starting a compliance scan, which evaluates the organisation's controls on demand.                                |
| `audit.compliance.manage_schedules`    | org   |       |       | `compliance:manage_schedules`                                              | Gates creating, editing and deleting recurring compliance scans.                                                        |
| `audit.compliance.attest`              | org   |       |       | `compliance:attest`                                                        | Gates recording attestations, uploading or deleting evidence, and requesting an exception.                              |
| `audit.compliance.remediate`           | org   |       |       | `compliance:remediate`                                                     | Gates applying a remediation to a finding, and cancelling or rolling back a request.                                    |
| `audit.compliance.manage_rules`        | org   | ⚑     |       | `compliance:manage_rules`                                                  | Gates the organisation's own policy baselines.                                                                          |
| `audit.compliance.manage_frameworks`   | org   | ⚑     |       | `compliance:manage_frameworks`                                             | Changes what the organisation is assessed against.                                                                      |
| `audit.compliance.manage_integrations` | org   | ⚑     |       | `compliance:manage_integrations`                                           | Handles secrets: gates storing and deleting the credentials compliance uses to reach hosts.                             |
| `audit.compliance.approve_exception`   | org   | ⚑     |       | `compliance:approve_exception`                                             | An approval decision: gates approving or rejecting a waiver or a remediation request.                                   |
| `audit.compliance.export_report`       | org   |       |       | `compliance:export_report`                                                 | Gates the framework report downloads, the Statement of Applicability and the executive report.                          |
| `audit.compliance.manage_shared_rules` | pla   | ⚑     |       | — (replaces a role-name check)                                             | Rules are shared by every organisation; the legacy route checks the role name after manage_rules.                       |
| `audit.vuln_feed.manage`               | pla   | ⚑     |       | — (replaces a role-name check)                                             | The feed is global data; the legacy routes require the superadmin role by name.                                         |

## 5. Reserved namespaces

`policy.*` (CCure Policy Pro), `rank.*` (CCure Rank) and `ir.*` (CCure IR) are reserved from the day each product is registered and declare **nothing** until the product's own team does. No permission was invented for a future feature.

## 6. Legacy atom → new permission

Every legacy atom ends in exactly one status; none is dropped silently. **mapped** = the same capability under a new key (one-to-one, a merge or a split); **replaced** = the capability is now expressed differently; **retired** = nothing enforces it, so there is no new key — the atom is preserved in `rbac_legacy_map` with its reason. The old atom is never renamed in the legacy tables.

| Legacy atom                              | Status   | New permission(s)                                                                                               | Reason                                                                                                      |
| ---------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `scans:create`                           | mapped   | `audit.scan.run`                                                                                                | Mapped to the new vocabulary.                                                                               |
| `scans:read`                             | mapped   | `audit.scan.read`                                                                                               | Mapped to the new vocabulary.                                                                               |
| `scans:read_all`                         | mapped   | `audit.scan.read_all`                                                                                           | Mapped to the new vocabulary.                                                                               |
| `scans:update`                           | retired  | —                                                                                                               | No route, task or screen requires it; scan configuration is not editable after launch.                      |
| `scans:archive`                          | mapped   | `audit.scan.lifecycle`                                                                                          | Mapped to the new vocabulary.                                                                               |
| `scans:restore`                          | mapped   | `audit.scan.lifecycle`                                                                                          | Mapped to the new vocabulary.                                                                               |
| `scans:recycle`                          | mapped   | `audit.scan.lifecycle`                                                                                          | Mapped to the new vocabulary.                                                                               |
| `scans:purge`                            | mapped   | `audit.scan.purge`                                                                                              | Mapped to the new vocabulary.                                                                               |
| `scans:execute`                          | mapped   | `audit.scan.run`                                                                                                | Mapped to the new vocabulary.                                                                               |
| `scans:cancel`                           | retired  | —                                                                                                               | No route or screen requires it; stopping a scan is guarded by scans:execute (audit.scan.run).               |
| `scan_schedules:create`                  | mapped   | `audit.scan_schedule.manage`                                                                                    | Mapped to the new vocabulary.                                                                               |
| `scan_schedules:read`                    | mapped   | `audit.scan_schedule.read`                                                                                      | Mapped to the new vocabulary.                                                                               |
| `scan_schedules:update`                  | mapped   | `audit.scan_schedule.manage`                                                                                    | Mapped to the new vocabulary.                                                                               |
| `scan_schedules:delete`                  | mapped   | `audit.scan_schedule.delete`                                                                                    | Mapped to the new vocabulary.                                                                               |
| `scan_schedules:execute`                 | mapped   | `audit.scan_schedule.manage`                                                                                    | Mapped to the new vocabulary.                                                                               |
| `scan_policies:create`                   | mapped   | `audit.scan_policy.manage`                                                                                      | Mapped to the new vocabulary.                                                                               |
| `scan_policies:read`                     | mapped   | `audit.scan_policy.read`                                                                                        | Mapped to the new vocabulary.                                                                               |
| `scan_policies:update`                   | mapped   | `audit.scan_policy.manage`                                                                                      | Mapped to the new vocabulary.                                                                               |
| `scan_policies:delete`                   | mapped   | `audit.scan_policy.delete`                                                                                      | Mapped to the new vocabulary.                                                                               |
| `assets:create`                          | retired  | —                                                                                                               | No route or screen requires it; assets enter the registry through scans and the AMT import.                 |
| `assets:read`                            | mapped   | `audit.asset.read`                                                                                              | Mapped to the new vocabulary.                                                                               |
| `assets:update`                          | mapped   | `audit.asset.update`                                                                                            | Mapped to the new vocabulary.                                                                               |
| `assets:delete`                          | retired  | —                                                                                                               | No route or screen requires it; there is no way to delete an asset.                                         |
| `assets:export`                          | retired  | —                                                                                                               | No route or screen requires it; exports are guarded by reports:read.                                        |
| `findings:read`                          | mapped   | `audit.finding.read`                                                                                            | Mapped to the new vocabulary.                                                                               |
| `findings:update`                        | mapped   | `audit.finding.update`                                                                                          | Mapped to the new vocabulary.                                                                               |
| `findings:export`                        | retired  | —                                                                                                               | No route or screen requires it; exports are guarded by reports:read.                                        |
| `findings:accept_risk`                   | mapped   | `audit.finding.accept_risk`                                                                                     | Mapped to the new vocabulary.                                                                               |
| `reports:create`                         | retired  | —                                                                                                               | No route or screen requires it; reports are generated when a scan completes.                                |
| `reports:read`                           | mapped   | `audit.report.read`                                                                                             | Mapped to the new vocabulary.                                                                               |
| `reports:delete`                         | mapped   | `audit.report.delete`                                                                                           | Mapped to the new vocabulary.                                                                               |
| `users:create`                           | mapped   | `platform.user.create`                                                                                          | Mapped to the new vocabulary.                                                                               |
| `users:read`                             | mapped   | `platform.user.read`                                                                                            | Mapped to the new vocabulary.                                                                               |
| `users:update`                           | mapped   | `platform.user.approve`, `platform.user.assign_role`, `platform.user.reset_credentials`, `platform.user.update` | Mapped to the new vocabulary (one atom to several permissions).                                             |
| `users:delete`                           | mapped   | `platform.user.delete`, `platform.user.purge`                                                                   | Mapped to the new vocabulary (one atom to several permissions).                                             |
| `credentials:create`                     | mapped   | `audit.credential.manage`                                                                                       | Mapped to the new vocabulary.                                                                               |
| `credentials:read`                       | mapped   | `audit.credential.read`                                                                                         | Mapped to the new vocabulary.                                                                               |
| `credentials:update`                     | mapped   | `audit.credential.manage`                                                                                       | Mapped to the new vocabulary.                                                                               |
| `credentials:validate`                   | mapped   | `audit.credential.validate`                                                                                     | Mapped to the new vocabulary.                                                                               |
| `credentials:delete`                     | mapped   | `audit.credential.delete`                                                                                       | Mapped to the new vocabulary.                                                                               |
| `settings:read`                          | retired  | —                                                                                                               | No route or screen requires it.                                                                             |
| `settings:update`                        | replaced | `audit.asset.import_amt`, `audit.remediation.manage_sla`                                                        | A generic settings atom gated two unrelated capabilities; each is now named for what it does.               |
| `dashboard:read`                         | mapped   | `audit.dashboard.read`                                                                                          | Mapped to the new vocabulary.                                                                               |
| `roles:read`                             | mapped   | `platform.permission.read`, `platform.role.read`                                                                | Mapped to the new vocabulary (one atom to several permissions).                                             |
| `roles:create`                           | replaced | `platform.role.create`, `platform.role.create_platform`                                                         | No route required it; role creation is RBAC governance (organisation and platform scope).                   |
| `roles:update`                           | replaced | `platform.role.update`                                                                                          | No route required it; role editing is RBAC governance.                                                      |
| `roles:delete`                           | replaced | `platform.role.retire`                                                                                          | No route required it; roles are retired, never deleted.                                                     |
| `organizations:read`                     | mapped   | `platform.organization.read`                                                                                    | Mapped to the new vocabulary.                                                                               |
| `organizations:create`                   | mapped   | `platform.organization.create`                                                                                  | Mapped to the new vocabulary.                                                                               |
| `organizations:update`                   | mapped   | `platform.organization.update`                                                                                  | Mapped to the new vocabulary.                                                                               |
| `organizations:delete`                   | replaced | `platform.organization.archive`                                                                                 | No route required it; archiving is guarded by a role-name check, which becomes this permission.             |
| `audit:read`                             | mapped   | `platform.audit_log.read`                                                                                       | Mapped to the new vocabulary.                                                                               |
| `audit:export`                           | mapped   | `platform.audit_log.export`                                                                                     | Mapped to the new vocabulary.                                                                               |
| `audit:purge`                            | replaced | `platform.audit_log.retention`                                                                                  | No route required it; the retention preview is guarded by a role-name check, which becomes this permission. |
| `compliance:read`                        | mapped   | `audit.compliance.read`                                                                                         | Mapped to the new vocabulary.                                                                               |
| `compliance:scan`                        | mapped   | `audit.compliance.scan`                                                                                         | Mapped to the new vocabulary.                                                                               |
| `compliance:manage_schedules`            | mapped   | `audit.compliance.manage_schedules`                                                                             | Mapped to the new vocabulary.                                                                               |
| `compliance:attest`                      | mapped   | `audit.compliance.attest`                                                                                       | Mapped to the new vocabulary.                                                                               |
| `compliance:remediate`                   | mapped   | `audit.compliance.remediate`                                                                                    | Mapped to the new vocabulary.                                                                               |
| `compliance:manage_rules`                | mapped   | `audit.compliance.manage_rules`                                                                                 | Mapped to the new vocabulary.                                                                               |
| `compliance:manage_frameworks`           | mapped   | `audit.compliance.manage_frameworks`                                                                            | Mapped to the new vocabulary.                                                                               |
| `compliance:manage_retention`            | retired  | —                                                                                                               | No route or screen requires it; evidence retention is not configurable through the API.                     |
| `compliance:manage_integrations`         | mapped   | `audit.compliance.manage_integrations`                                                                          | Mapped to the new vocabulary.                                                                               |
| `compliance:approve_exception`           | mapped   | `audit.compliance.approve_exception`                                                                            | Mapped to the new vocabulary.                                                                               |
| `compliance:export_report`               | mapped   | `audit.compliance.export_report`                                                                                | Mapped to the new vocabulary.                                                                               |
| `audit_logs:read` _(live database only)_ | retired  | —                                                                                                               | A duplicate of audit:read found only on the live database (not in the seed); no code reads it.              |

## 7. Roles and the role matrix

A role is `id` + `key` + `display_name`; the key and the display name are **never** an authorization input. The display names below are defaults and can change without touching authorization (`platform.superadmin` may become "CISO").

| Legacy role  | Role key              | Default display name | Scope        | Holds                                                                        |
| ------------ | --------------------- | -------------------- | ------------ | ---------------------------------------------------------------------------- |
| `superadmin` | `platform.superadmin` | Superadmin           | platform     | every active permission, as materialised grant rows (no wildcard, no bypass) |
| `org_admin`  | `platform.org_admin`  | Org Admin            | organization | 47 permissions                                                               |
| `analyst`    | `platform.analyst`    | Analyst              | organization | 23 permissions                                                               |
| `viewer`     | `platform.viewer`     | Viewer               | organization | 9 permissions                                                                |
| `scanner`    | `platform.scanner`    | Scanner              | organization | 4 permissions                                                                |

The full matrix (✓ = held). Superadmin holds every active permission through materialised grants; the other four hold exactly what their legacy role held, expressed in the new vocabulary.

| Permission                             | Superadmin | Org Admin | Analyst | Viewer | Scanner |
| -------------------------------------- | :--------: | :-------: | :-----: | :----: | :-----: |
| `platform.user.read`                   |     ✓      |     ✓     |         |        |         |
| `platform.user.create`                 |     ✓      |     ✓     |         |        |         |
| `platform.user.update`                 |     ✓      |     ✓     |         |        |         |
| `platform.user.delete`                 |     ✓      |     ✓     |         |        |         |
| `platform.user.purge`                  |     ✓      |     ✓     |         |        |         |
| `platform.user.approve`                |     ✓      |     ✓     |         |        |         |
| `platform.user.reset_credentials`      |     ✓      |     ✓     |         |        |         |
| `platform.user.assign_role`            |     ✓      |     ✓     |         |        |         |
| `platform.user.move_org`               |     ✓      |           |         |        |         |
| `platform.role.read`                   |     ✓      |     ✓     |         |        |         |
| `platform.permission.read`             |     ✓      |     ✓     |         |        |         |
| `platform.role.create`                 |     ✓      |           |         |        |         |
| `platform.role.update`                 |     ✓      |           |         |        |         |
| `platform.role.retire`                 |     ✓      |           |         |        |         |
| `platform.role.create_platform`        |     ✓      |           |         |        |         |
| `platform.role.assign_platform`        |     ✓      |           |         |        |         |
| `platform.role.rename_system`          |     ✓      |           |         |        |         |
| `platform.role.retire_system`          |     ✓      |           |         |        |         |
| `platform.role.set_default`            |     ✓      |           |         |        |         |
| `platform.organization.read`           |     ✓      |           |         |        |         |
| `platform.organization.create`         |     ✓      |           |         |        |         |
| `platform.organization.update`         |     ✓      |           |         |        |         |
| `platform.organization.archive`        |     ✓      |           |         |        |         |
| `platform.organization.set_scan_scope` |     ✓      |           |         |        |         |
| `platform.organization.switch`         |     ✓      |           |         |        |         |
| `platform.audit_log.read`              |     ✓      |     ✓     |         |        |         |
| `platform.audit_log.export`            |     ✓      |     ✓     |         |        |         |
| `platform.audit_log.retention`         |     ✓      |           |         |        |         |
| `platform.email_domain.read`           |     ✓      |           |         |        |         |
| `platform.email_domain.manage`         |     ✓      |           |         |        |         |
| `audit.dashboard.read`                 |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.scan.read`                      |     ✓      |     ✓     |    ✓    |   ✓    |    ✓    |
| `audit.scan.read_all`                  |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.scan.run`                       |     ✓      |     ✓     |    ✓    |        |    ✓    |
| `audit.scan.lifecycle`                 |     ✓      |     ✓     |         |        |         |
| `audit.scan.purge`                     |     ✓      |     ✓     |         |        |         |
| `audit.scan_schedule.read`             |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.scan_schedule.manage`           |     ✓      |     ✓     |    ✓    |        |         |
| `audit.scan_schedule.delete`           |     ✓      |     ✓     |         |        |         |
| `audit.scan_policy.read`               |     ✓      |     ✓     |    ✓    |   ✓    |    ✓    |
| `audit.scan_policy.manage`             |     ✓      |     ✓     |    ✓    |        |         |
| `audit.scan_policy.delete`             |     ✓      |     ✓     |         |        |         |
| `audit.credential.read`                |     ✓      |     ✓     |    ✓    |        |    ✓    |
| `audit.credential.manage`              |     ✓      |     ✓     |    ✓    |        |         |
| `audit.credential.validate`            |     ✓      |     ✓     |    ✓    |        |         |
| `audit.credential.delete`              |     ✓      |     ✓     |         |        |         |
| `audit.asset.read`                     |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.asset.update`                   |     ✓      |     ✓     |    ✓    |        |         |
| `audit.asset.import_amt`               |     ✓      |     ✓     |         |        |         |
| `audit.finding.read`                   |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.finding.update`                 |     ✓      |     ✓     |    ✓    |        |         |
| `audit.finding.accept_risk`            |     ✓      |     ✓     |    ✓    |        |         |
| `audit.report.read`                    |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.report.delete`                  |     ✓      |     ✓     |         |        |         |
| `audit.remediation.manage_sla`         |     ✓      |     ✓     |         |        |         |
| `audit.compliance.read`                |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `audit.compliance.scan`                |     ✓      |     ✓     |    ✓    |        |         |
| `audit.compliance.manage_schedules`    |     ✓      |     ✓     |    ✓    |        |         |
| `audit.compliance.attest`              |     ✓      |     ✓     |    ✓    |        |         |
| `audit.compliance.remediate`           |     ✓      |     ✓     |    ✓    |        |         |
| `audit.compliance.manage_rules`        |     ✓      |     ✓     |         |        |         |
| `audit.compliance.manage_frameworks`   |     ✓      |     ✓     |         |        |         |
| `audit.compliance.manage_integrations` |     ✓      |     ✓     |         |        |         |
| `audit.compliance.approve_exception`   |     ✓      |     ✓     |         |        |         |
| `audit.compliance.export_report`       |     ✓      |     ✓     |    ✓    |        |         |
| `audit.compliance.manage_shared_rules` |     ✓      |           |         |        |         |
| `audit.vuln_feed.manage`               |     ✓      |           |         |        |         |

Set sizes: Superadmin all 67, Org Admin 47, Analyst 23, Viewer 9, Scanner 4. The hierarchy is the legacy one: Scanner ⊂ Analyst ⊂ Org Admin and Viewer ⊂ Analyst.

## 8. Scope

- Platform roles (`platform.superadmin`, and administrator-created `custom.platform.*` roles) are assigned platform-wide; organisation roles are assigned within one organisation. A role's assignable scope is fixed at creation and the database refuses an assignment at any other scope.
- An organisation-scope grant applies only in its own organisation. A platform-scope grant applies in the principal's own organisation and in another only with `platform.organization.switch`. **Holding a permission never reaches another tenant by itself.**
- An organisation role can never hold a platform-scope or non-delegable permission, and the Org Admin role holds only organisation-scope keys.

## 9. Custom organisation roles (foundation)

- A custom role belongs to **one organisation** (`custom.<org_id>.<slug>`), has a mutable display name, and is `managed_by = admin`.
- It may contain only **delegable, organisation-scope** permissions the creator holds there (the escalation ceiling) — never a platform-only capability, even for a platform administrator.
- It cannot modify a system role, cannot be a system role (its key cannot be `platform.*`), and cannot be assigned outside its organisation; the database enforces the last two.
- Creating one requires `platform.role.create`, which only the superadmin role holds by default (RBAC-0 D12). Delegating it is a data change — a custom role holding it, assigned beside Org Admin — not a code change.
- Internal primitive: `governance.define_custom_org_role`. There is no HTTP API and no UI until RBAC-7.

## 10. Lifecycle

- `active → retiring → retired`, and `retired → active` (reactivation). A role is never deleted.
- A **retiring** role cannot receive new assignments but stays effective, so a retirement is never an outage. A **retired** role grants nothing and cannot be assigned.
- Retiring needs the gate: no live assignments, not a configured default role, no continuity invariant newly broken.
- **A state change cannot be silent**: the database refuses it unless the revision advances in the same statement, and a revision row records the state. Sync and seeding never resurrect a retired role.
- Replacement is a **new role, a migration of its holders, then a retirement** (`replaced_by_role_id`). The old role's assignments stay as history, revoked with a reason. Renaming changes only a label.
- Internal primitive: `governance.transition_role`.

## 11. The default role

Self-registration still gives a new account the **Viewer** role. In the new model the default is configuration (`rbac_default_roles`, seeded to Viewer), not an assumption: it must be an active, organisation-assignable role holding no non-delegable or continuity permission — Viewer holds nine organisation-scope read permissions and nothing privileged. The registration flow does not read it yet.

## 12. User purge

`purge_user` hard-deletes an account, and `rbac_user_roles.user_id` is `ON DELETE RESTRICT`. RBAC registers a hook with the platform's offboarding contract (`ccure_platform/rbac/offboarding.py`): before the user row goes, each of the account's assignments — live or not — is recorded in the audit trail (role id, key and the display name _at that moment_, scope, grantor, whether it was live) and the row is removed. **Role history is untouched** (roles are never deleted; revisions are append-only) and **the foreign key is not weakened**: deleting a user who still has assignments by any other route is still refused.

## 13. Audit attribution

`audit_logs` is tenant-bound (`org_id` is NOT NULL and the chain is per organisation), so it cannot hold an event no organisation owns without borrowing an organisation. The rule is: **an event with an owner goes to that organisation's trail; one without goes to the platform ledger (`platform_audit_events`); nothing is ever attributed to an invented organisation.**

| Event                                                                | Owner                                                             | Sink            |
| -------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------- |
| a role of one organisation changes                                   | that organisation                                                 | `audit_logs`    |
| an organisation-scope assignment or revocation                       | the assignment's organisation                                     | `audit_logs`    |
| a platform-scope assignment or revocation                            | the **member's own** organisation (whose person's access changed) | `audit_logs`    |
| a system or platform-scope role changes                              | nobody                                                            | platform ledger |
| a catalogue sync, a permission's lifecycle, a system role reconciled | nobody                                                            | platform ledger |
| the default role is changed                                          | nobody (a platform setting)                                       | platform ledger |
| a user purge removes assignments                                     | the user's organisation                                           | `audit_logs`    |

An organisation-less event records the actor's organisation as _information_ (`actor_org_id`), never as its owner. The ledger is append-only (trigger) but **not hash-chained**: extending the per-organisation chain to a platform chain is a privileged DBA bootstrap and a separate, reviewed step. This is a recorded limit.

## 14. The golden mapping and how equivalence is proven

`golden_legacy_mapping.json` holds, for every legacy role and atom: the new keys, status and reason; for every new key: owner, scope, sensitivity, delegation, continuity, the legacy atoms it derives from, who holds it and why; the expected set of each role; and the intentional differences. Three independent checks must agree, so RBAC-4 can prove old effective set == new effective set:

1. `validate_golden` — the file is internally consistent and accounts for every legacy atom and every catalogue key (no unexplained gap, no undeclared key);
1. `derive_role_grants` — each role's expected set is **recomputed** from what its legacy role holds: a key is held when _all_ the atoms it derives from are;
1. the declarations' own `default_grants` must equal both.

Also proven: no role **loses** anything but a retired atom, and no role **gains** anything its legacy role did not hold. Run through the real shadow comparator (read-only, test-only), the new decision matches the legacy one for all five roles and all 56 enforced atoms; the 10 retired atoms report `retired`.

### Intentional differences

- **D1 — retired atoms.** Ten legacy atoms have no enforcement point (no route, task or screen requires them). They are preserved in rbac_legacy_map as retired; the roles that hold them lose nothing that any code checks.
- **D2 — superadmin.** Legacy superadmin passes by role name (and holds a row per atom on the live database). The new role holds every active permission as materialised grants; there is no wildcard and no bypass.
- **D3 — name checks become permissions.** 7 role-name checks become platform- or organisation-scope permissions held only by the superadmin role, so their holders are unchanged.
- **D4 — new governance permissions.** Permissions with no legacy counterpart (RBAC governance). Only the superadmin role holds them, so no live user gains a capability.
- **D5 — cross-organisation visibility.** Legacy superadmin sees every organisation's data on list endpoints through per-router role-name helpers. That is scope, not a permission, and the RBAC-2 catalogue does not model it; RBAC-5 decides how platform-scope assignments reach other organisations.
- **D6 — live-only atom.** audit_logs:read exists on the live database (held by superadmin and org_admin) but not in the seed. It is retired with the rest; no code reads it.
- **D7 — assignment hierarchy.** Legacy: an org_admin cannot assign the superadmin role (a role-name check). New: the escalation ceiling and platform.role.assign_platform express the same rule.

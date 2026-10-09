# RBAC-7 — Platform RBAC administration and governance

**Status: built and proven in a disposable database; no deployment, no production
change.** The governance API and UI exist in the repo; the RBAC tables are still empty in
production, so until RBAC-8 provisions accounts nobody can use them there (an account with no
RBAC assignment is told so). The legacy implementation is untouched and remains the rollback.

## What can be administered

|                                   | Where                                                            | Rules (all backend, RBAC-2 `governance.py`)                                                                                                                        |
| --------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Roles: list, detail, history      | `GET /platform/rbac/roles[/{id}]`                                | system roles global; custom roles visible in their organisation only                                                                                               |
| Permission catalogue              | `GET /platform/rbac/permissions`                                 | the UI is built from it; no key can be typed in                                                                                                                    |
| Create a custom organisation role | `POST /platform/rbac/roles`                                      | delegable organisation-scope permissions only; delegation ceiling; one organisation; never a system role                                                           |
| Rename (display name)             | `PATCH /platform/rbac/roles/{id}`                                | a label — changes no authorization; system role needs `platform.role.rename_system`                                                                                |
| Role permissions                  | `PUT /platform/rbac/roles/{id}/permissions`                      | custom roles only; removal always allowed; adding bounded by the ceiling; nobody adds to a role they hold                                                          |
| Lifecycle                         | `POST …/transition`                                              | `active → retiring → retired`, reactivation within the ceiling; retirement gate: no live assignments, not a default role, no continuity regression; no hard delete |
| Replacement                       | `POST …/replace`                                                 | create replacement → migrate (governed, all-or-nothing, old assignments revoked as `migrated`) → verify continuity → retire                                        |
| Assignable roles                  | `GET …/assignable-roles`                                         | every role with `assignable` and the governance `reasons`; plus the actor's delegation summary                                                                     |
| User role view / assign / remove  | `GET/POST …/users/{id}/assignments`, `DELETE …/assignments/{id}` | organisation boundary, scope and permission ceilings, system-role rules, self-assignment, escalation, last-administrator continuity                                |

**System roles** keep their stable keys (`platform.superadmin`, `.org_admin`, `.analyst`,
`.viewer`, `.scanner`); only the display name is configurable. Renaming `platform.superadmin` to
CISO and back, and `platform.org_admin` to anything, leaves every account's effective
permissions identical (tested through the real API).

**Escalation blocked, all server-side and tested:** self-assignment; an org admin assigning
superadmin; organisation A assigning in B (or a B custom role into A); granting what the actor
does not hold; a custom role beyond the ceiling or holding a platform/non-delegable key; a retired
role newly assigned; a system role changed through the API (unknown fields are 422, kind/key are
immutable by trigger); removing the last active superadmin or the last role administrator.

## Step-up (MFA / re-authentication)

`identity/reauth.py`, no second MFA system: a **sensitive** operation — a system or platform
role, a role holding a privileged permission, a privileged permission change, an assignment of such
a role, a cross-organisation change — needs a current authenticator code in `X-Reauth-Code` for an
account with MFA enrolled (`403 reauth_required`; a wrong code is refused and audited as
`rbac.reauth.failed`). An account with no MFA is _recorded_ (`reauth: "not_enrolled"` in the audit
event), not blocked — the existing infrastructure has no other factor; `RBAC_REAUTH_MODE=
require_enrolment` refuses it instead. The UI prompts for the code and retries.

## Audit

Through the platform audit service; ownership never invented. A role of one organisation and an
organisation assignment → that organisation's trail; a system/platform role event → the platform
ledger. Events: `rbac.role.created/renamed/updated/permissions_changed/retiring/retired/
reactivated/replaced/reassigned/assigned/revoked`, `rbac.platform_role.assigned/revoked`,
`rbac.escalation.refused` and `rbac.assignment.denied` (written in their own transaction so the
refusal's rollback cannot erase them), `rbac.reauth.failed`. Each mutation event carries the step-up
outcome.

## Platform administration authorization (migrated)

Every users / organisations / roles / settings / audit-log route asks for one granular key
(`platform.user.read|create|update|delete|purge|approve|assign_role|reset_credentials|move_org`,
`platform.organization.read|create|update|archive|set_scan_scope`, `platform.role.read`,
`platform.permission.read`, `platform.audit_log.read|export|retention`,
`audit.asset.import_amt`, `audit.remediation.manage_sla`) through `require_authorized(key)`;
the legacy rule it replaced is its fallback (the atom for atom-derived keys, so a custom legacy role
is unaffected; the role-name rule for the superadmin-only ones). No generic settings/admin key was
created; `settings:update` stays split. The user-directory, organisation-list and audit-log
visibility helpers are cross-organisation reach (`acts_across_organisations`, RBAC-5), not role
names. `/admin/roles` now returns `assignable` per role, decided by the assignment rules, so the
form no longer recognises a label.

## Compliance emergency bypass

Decision: **no new permission.** The bypass skips the maker-checker queue — the account performs
the approval decision itself — which is exactly what `audit.compliance.approve_exception`
(organisation scope, the organisation's own queue) already grants (approving or rejecting a waiver
or remediation request); it is held by the same roles the legacy `admin`/`superadmin`/
`compliance_officer` name test passed in practice (`superadmin`, `org_admin`). A generic bypass key
would be broader than the behaviour; none exists.

## Not done here

Dual-writing legacy `users.role_id` changes into `rbac_user_roles`, provisioning, the default
role, bootstrap and removing the legacy implementation and the older-backend fallback are RBAC-8.

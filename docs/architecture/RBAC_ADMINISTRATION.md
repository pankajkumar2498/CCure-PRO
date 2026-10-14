# RBAC-7 — Platform RBAC administration and governance

**Status: native RBAC is authoritative.** Role assignments and permission grants live in
`rbac_*` tables; the platform engine is the authorization source. System declarations
are reconciled at startup and by the operator catalogue command. Custom-role changes
use the governed administration API. The October 2026 hardening changes are tested in
an isolated PostgreSQL database; deploying those changes remains a separate operation.

## Approved system-role governance (12 October 2026)

System-role **permission sets remain immutable to every administrator**, including
platform administrators. This is an explicit governance decision. A reviewed catalogue
release controls their grants; administrators cannot unlock them through the UI or
write mappings directly. Startup reconciliation retains its code-owned catalogue policy
and now records actual changes in the platform audit ledger in the same transaction.

Creation, assignment, replacement and retirement are separate governed operations.
Role names and keys do not authorize any of them. Existing custom organisation roles
can be created and edited in place. System labels may be renamed only with the existing
platform-scoped rename authority. System retirement requires the existing platform
retirement authority and all continuity, assignment and default-role gates. Replacement
assignments must pass scope, tenant membership, delegation and self-assignment checks;
replacement does not itself retire the original role. Retired system roles are not
resurrected by catalogue sync. Stable IDs, append-only revisions and audit history remain.

Future platform-role creation or a different system-editing policy requires an explicit
platform governance decision and a governed API; no such new capability is exposed by
this change. A configured recovery procedure remains the recovery path, rather than a
role-name bypass. Do not delete/recreate roles or use database edits to escape these gates.

## What can be administered

|                                   | Where                                                            | Rules (all backend, RBAC-2 `governance.py`)                                                                                                                        |
| --------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Roles: list, detail, history      | `GET /platform/rbac/roles[/{id}]`                                | system roles global; custom roles visible in their organisation only                                                                                               |
| Permission catalogue              | `GET /platform/rbac/permissions`                                 | the UI is built from it; no key can be typed in                                                                                                                    |
| Create a custom organisation role | `POST /platform/rbac/roles`                                      | delegable organisation-scope permissions only; delegation ceiling; one organisation; never a system role                                                           |
| Rename (display name)             | `PATCH /platform/rbac/roles/{id}`                                | a label — changes no authorization; system role needs `platform.role.rename_system`                                                                                |
| Role permissions                  | `PUT /platform/rbac/roles/{id}/permissions`                      | active custom roles only; current revision required; removal preserves administrator continuity; adding bounded by the ceiling; nobody adds to a role they hold    |
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
`rbac.escalation.refused`, `rbac.role.denied` and `rbac.assignment.denied` (written in their own transaction so the
refusal's rollback cannot erase them), `rbac.reauth.failed`. Each mutation event carries the step-up
outcome.

## Platform administration authorization (migrated)

Every users / organisations / roles / settings / audit-log route asks for one granular key
(`platform.user.read|create|update|delete|purge|approve|assign_role|reset_credentials|move_org`,
`platform.organization.read|create|update|archive|set_scan_scope`, `platform.role.read`,
`platform.permission.read`, `platform.audit_log.read|export|retention`,
`audit.asset.import_amt`, `audit.remediation.manage_sla`) through `require_authorized(key)`;
native grants and scope are the only authority. A missing assignment or grant is denied.
No legacy role or permission fallback remains. The user-directory, organisation-list and audit-log
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

## Revision, transaction and tenant hardening

Permission updates require `expected_revision` from the loaded role detail. Missing
preconditions return 428, stale revisions 409. A shared transaction lock serializes role
revisions and administrator-removing changes; stale edits cannot overwrite a newer
permission set. Permission changes, append-only revision records and successful audit
records share the same transaction. Audit or revision failures roll back grant changes.

Governed denials, including immutable system roles and continuity failures, are recorded
as `rbac.role.denied`, assignment denial or escalation refusal in a separate transaction.
Audit failure cannot turn a denied operation into success. Compatibility role assignments
and initial organisation-admin provisioning use the same step-up and denial audit helpers.

Explicit unauthorized tenant selections are rejected for writes; creation honours body or
query organisation and rejects conflicting selections. Inactive tenants cannot receive
new assignments. Account transfers revoke old organisation assignments with preserved
history, and destination assignments need separate authority. The resolver ignores
membership-mismatched grants. Account deactivation/deletion and ending a tenancy containing
platform administrators use the same capability-based continuity protocol.

The catalogue includes every declared implemented key. Ordinary organisation readers
receive organisation-scoped entries; platform catalogue readers receive all entries.
Grantability reflects the current actor's delegation ceiling at each scope. Policy Pro
and Rank declare no implemented permissions here; IR requires separate service verification.

See [current permission inventory](../RBAC_Management_Permissions.md) and
[hardening verification report](../archive/rbac/RBAC_HARDENING_REPORT.md).

# RBAC-5 — scope and tenant authorization

**Status: built and proven in a disposable database; OFF in every deployment.** Legacy
authorization still decides until an operator switches a scope path on. Production was not
touched (no migration — RBAC-5 needed no schema change — no role assigned, no flag set,
no deploy, no restart).

## Permission and scope are separate

> permission = WHAT · scope = WHERE

`principal → effective permissions → permission check → scope check → allow/deny`. The
RBAC-1 engine already carries the model; RBAC-5 makes it reachable from the places that
used to decide _where_ by role name or by trusting a client-supplied organisation id.

| Scope              | Held by                                                                                                | Means                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Platform           | a platform-scope assignment                                                                            | the capability exists platform-wide; says nothing about any organisation by itself |
| Organisation       | an organisation-scope assignment                                                                       | applies in that organisation only                                                  |
| Cross-organisation | the platform-scope grant of `platform.organization.switch`, **plus** the permission held platform-wide | may act in an organisation other than the home one                                 |

Holding an organisation-scoped permission never reaches another tenant, so an
**organisation administrator stays in its organisation**. Platform scope is not "every
organisation" without the switch. **Superadmin has no shortcut**: it holds the switch (and
every other permission) through materialised grants.

## What legacy meant, and the equivalent

| Legacy behaviour                                                                 | Affected resource / operation                                                                                                                             | Why legacy allowed it                                                    | New expression                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| superadmin names `?org_id=`                                                      | every organisation-scoped list and write (assets, findings, dashboard, credentials, schedules, policies, remediation, scan lifecycle, credentialed scans) | `role.name == "superadmin"`; the id was trusted, unvalidated, unrecorded | `resolve_active_organisation`: needs the switch grant, an existing **active** target, and writes `rbac.org_switch.entered` (owned by the entered organisation)                                                                                                                            |
| superadmin looks up a scan / report / web scan by id with no organisation filter | scan reads, report export, scan WebSocket                                                                                                                 | same name test, no organisation filter                                   | `acts_across_organisations` + `resource_organisation_allowed`: the row's own organisation is read from storage and verified before access                                                                                                                                                 |
| non-superadmin names another organisation                                        | same routes                                                                                                                                               | silently ignored (own organisation)                                      | unchanged (own organisation), now recorded as `rbac.scope.denied`                                                                                                                                                                                                                         |
| `scans:read_all`                                                                 | which scans inside the active organisation a user sees (others' as well as their own)                                                                     | permission atom, evaluated with no organisation                          | **organisation-wide visibility within the organisation the request acts in — never cross-organisation.** An organisation-scope permission evaluated for the target organisation (`user_has_permission(..., org_id=)`); a superadmin sees another organisation's scans only by entering it |
| hierarchy: "only a superadmin may hand out superadmin"                           | `POST /admin/users`, `PATCH /admin/users/{id}/role`                                                                                                       | role-name comparison                                                     | `check_role_assignment` → `governance.check_assignment` over the golden system role: organisation boundary, scope ceiling, permission ceiling, system-role restriction, self-assignment                                                                                                   |

The comparison against legacy (`tests/rbac/test_rbac_scope_equivalence.py`) finds **zero
differences** for the five legacy roles with the default grants: reach, active organisation,
read_all per organisation, and the assignment table all agree.

## Fail closed (deterministic)

| Input                                                                                                                               | Result                                    |
| ----------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| organisation missing / nonexistent                                                                                                  | 404                                       |
| organisation inactive (there is no separate "archived" or "deleted" column: deactivation is `is_active=false`, deletion is absence) | 403                                       |
| home organisation inactive                                                                                                          | 403 for every request of that account     |
| another organisation without the switch grant                                                                                       | ignored (home organisation), recorded     |
| cross-organisation resource without reach                                                                                           | 404, recorded                             |
| new model cannot answer (never provisioned, catalogue unsynced, error)                                                              | the legacy answer, recorded as a fallback |
| switch event cannot be written                                                                                                      | 503: an unauditable switch is refused     |

A client-supplied organisation id is a _request_. No header, body or claim is read by the
seam (a test asserts the signatures take none).

## Audit

All written on a session of their own so a read request cannot lose them, through the
platform audit service; nothing is attributed to an invented organisation.

- `rbac.org_switch.entered` — owned by the **entered** organisation, actor real, from/to ids.
- `rbac.scope.denied` — owned by the principal's own organisation (forged id, no grant,
  inactive/missing target, cross-organisation resource).
- `rbac.escalation.refused` — owned by the actor's organisation, with the violation codes.
- role assignment/removal and custom-role events: RBAC-2 governance events, unchanged.

## Switching on and rolling back

Three new paths: `scope.active_organisation`, `scope.cross_organisation`,
`scope.assign_role` (plus the existing atom path `scans:read_all`, now authoritative).
`RBAC_AUTHORITY_MODE=enforce` + `RBAC_AUTHORITY_PATHS=scope.active_organisation,…`.
Rollback is removing the path and restarting; the legacy rules
(`legacy_acts_across_organisations`, `legacy_assignment_allowed`) remain in
`rbac/dependencies.py`.

## What is deferred

Platform administration — the `users`, `organizations`, `roles`, `settings` and `audit`
atoms, the user-directory and audit-log visibility helpers — is out of RBAC-5 and goes to
RBAC-7 (the same reach primitive applies). Provisioning, bootstrap, the default role and the
legacy check itself are RBAC-8. Not done here: dual-writing `users.role_id` changes into
`rbac_user_roles` (so a role change made through the legacy route does not yet create the
matching RBAC assignment — see the reconciliation report).

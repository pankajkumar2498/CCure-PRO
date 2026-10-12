# Current RBAC management and permission coverage

Native RBAC is authoritative. Authorization uses permission keys, live role assignments,
role state and organisation scope. Role names and IDs are not authorization shortcuts.

The catalogue contains **69 implemented permissions**: 32 Common Platform and 37 Audit;
50 are organisation-scoped and 19 platform-scoped. System-role grants are predefined in
module declarations and materialised in the database by catalogue reconciliation.
Custom-role grants are stored in the database and edited through the governed API.

| Product         | Implemented permission declarations | Verification boundary                                                                |
| --------------- | ----------------------------------- | ------------------------------------------------------------------------------------ |
| Common Platform | 32                                  | `Backend/ccure_platform/permissions.py`; role/user/org/audit management and identity |
| CCure Audit     | 37                                  | `Backend/ccure_audit/permissions.py`; implemented Audit API and UI capabilities      |
| Policy Pro      | 0                                   | Disabled module, empty manifest contributions and frontend placeholder               |
| Rank            | 0                                   | Disabled module, empty manifest contributions and frontend placeholder               |
| IR              | 0 in this catalogue                 | Separate service and database; its internals require separate verification           |

No speculative Policy, Rank or IR permissions are introduced. A future implemented
module declares permissions through its manifest and the platform composition seam;
its endpoints use the public platform authorization API. The catalogue coverage test
compares enabled-module declarations, database rows and the administrator API exactly.

## Catalogue visibility and delegation

`GET /platform/rbac/permissions?org_id=…` returns the applicable catalogue with scope,
sensitivity, status, delegability and per-scope grantability. Organisation administrators
receive all 50 organisation-scoped entries, including restricted entries shown disabled.
An actor holding catalogue-read authority through a platform assignment receives the full
69-entry catalogue. Platform grants are not offered to organisation administrators.
The editor renders every returned entry; it does not maintain a separate permission list.
A permission being visible does not authorize granting it. The backend checks the actor's
current delegation ceiling, role scope and tenant membership on every write.

## Editing an existing role

An active custom organisation role can be edited with `platform.role.update` in its
organisation; role creation requires `platform.role.create`, retirement
`platform.role.retire`, and user assignment/replacement `platform.user.assign_role`.
These grants are separate. Existing custom platform roles use the existing platform
role-governance authority; platform-role creation is not exposed by the current API/UI.
Platform assignment requires `platform.role.assign_platform`.

Custom permissions change in place, retaining role and assignment IDs. Permission writes
require the detail response's `revision` as `expected_revision`; missing revisions return
428 and stale revisions 409. Reload after a conflict. Grants, the new revision and the
success audit event commit together; an audit failure cannot commit a grant change.
System-role permissions remain immutable, including for platform administrators, by
explicit governance decision. Their reviewed catalogue releases control grants. System
renaming and controlled retirement retain their existing dedicated platform authorities.

The checked-in Org Admin definition does not grant custom-role create/update authority.
The five original roles in the investigated deployment were all system roles. This
explains the original read-only permission editor: both the API and UI intentionally
protect those roles. An administrator with sufficient delegation authority can create a
custom role containing appropriate management grants and assign it to another account;
no predefined role needs to be unlocked or recreated.

## Enforcement and audit

The resolver queries live grants for each backend authorization decision. Permission
changes affect assigned accounts' next request immediately; membership-mismatched
organisation grants and expired/revoked assignments grant nothing. The editing UI
refreshes its signed-in authorization after a successful change; other clients refresh
through existing session/visibility refresh or reload. There is no new push channel.

Sensitive role operations share the existing authenticator step-up policy across the
RBAC router, compatibility user-role APIs and initial organisation-admin provisioning.
`enforce` requires a code for enrolled accounts and records unenrolled accounts as
`not_enrolled`; `require_enrolment` remains a separate operational decision. Switching
that mode requires MFA enrollment and recovery preparation and is not part of this change.

A shared transaction lock serializes administrator-removing changes across roles,
assignments and account lifecycle operations. Only active, verified, approved accounts
in active tenancies count as viable holders. New continuity violations are denied;
pre-existing violations are not silently repaired. Writes refuse unauthorized explicit
organisation selections rather than redirecting them into the home tenant. Read-context
fallback retains its established contract. Account transfers revoke old organisation
assignments through governance and audit them; destination roles are assigned separately.
Successful role events belong to the role/assignment tenant, or the platform ledger for
global roles. Governed refusals and failed step-up attempts are audited separately so
request rollback cannot erase them; failure to record a governed refusal returns 503.

## Exact implemented inventory

This table is derived from the current module declarations, not proposed capabilities.
The scope/delegability restrictions apply even to an administrator who holds the key.

| Permission                           | Scope        | Delegable to organisation roles | Sensitivity | Capability                                                        |
| ------------------------------------ | ------------ | ------------------------------- | ----------- | ----------------------------------------------------------------- |
| audit.asset.import_amt               | organization | yes                             | normal      | Replace the organisation's AMT inventory from a file.             |
| audit.asset.read                     | organization | yes                             | normal      | View the asset inventory and its details.                         |
| audit.asset.update                   | organization | yes                             | normal      | Edit asset metadata, tags and notes.                              |
| audit.compliance.approve_exception   | organization | yes                             | privileged  | Approve or reject compliance exceptions and remediation requests. |
| audit.compliance.attest              | organization | yes                             | normal      | Record manual control attestations and evidence.                  |
| audit.compliance.export_report       | organization | yes                             | normal      | Export compliance reports.                                        |
| audit.compliance.manage_frameworks   | organization | yes                             | privileged  | Install and remove compliance frameworks.                         |
| audit.compliance.manage_integrations | organization | yes                             | privileged  | Store and delete compliance credentials.                          |
| audit.compliance.manage_rules        | organization | yes                             | privileged  | Create and edit compliance policies.                              |
| audit.compliance.manage_schedules    | organization | yes                             | normal      | Manage recurring compliance scans.                                |
| audit.compliance.manage_shared_rules | platform     | no                              | privileged  | Edit the shared compliance rule catalogue.                        |
| audit.compliance.read                | organization | yes                             | normal      | View compliance dashboards, frameworks and findings.              |
| audit.compliance.remediate           | organization | yes                             | normal      | Apply or roll back remediation on compliance findings.            |
| audit.compliance.scan                | organization | yes                             | normal      | Run a compliance scan.                                            |
| audit.credential.delete              | organization | yes                             | privileged  | Delete credential profiles.                                       |
| audit.credential.manage              | organization | yes                             | privileged  | Store and edit credential profiles.                               |
| audit.credential.read                | organization | yes                             | normal      | View stored credential profiles (never the secrets).              |
| audit.credential.validate            | organization | yes                             | normal      | Test a stored credential against a host.                          |
| audit.dashboard.read                 | organization | yes                             | normal      | View the security dashboards.                                     |
| audit.finding.accept_risk            | organization | yes                             | privileged  | Accept the risk on a finding, or withdraw an acceptance.          |
| audit.finding.read                   | organization | yes                             | normal      | View findings and their remediation records.                      |
| audit.finding.update                 | organization | yes                             | normal      | Triage findings and assign or advance their remediation.          |
| audit.remediation.manage_sla         | organization | yes                             | privileged  | Set the organisation's remediation deadlines.                     |
| audit.report.delete                  | organization | yes                             | normal      | Delete generated reports.                                         |
| audit.report.read                    | organization | yes                             | normal      | View and download scan reports.                                   |
| audit.scan.lifecycle                 | organization | yes                             | normal      | Archive, recycle and restore scans.                               |
| audit.scan.purge                     | organization | yes                             | privileged  | Permanently delete recycled scans.                                |
| audit.scan.read                      | organization | yes                             | normal      | View scans, their progress and results, and the topology map.     |
| audit.scan.read_all                  | organization | yes                             | normal      | View every user's scans in the organisation.                      |
| audit.scan.run                       | organization | yes                             | normal      | Start and stop scans of every kind.                               |
| audit.scan_policy.delete             | organization | yes                             | normal      | Delete scan policies.                                             |
| audit.scan_policy.manage             | organization | yes                             | normal      | Create, edit and version scan policies.                           |
| audit.scan_policy.read               | organization | yes                             | normal      | View scan policies.                                               |
| audit.scan_schedule.delete           | organization | yes                             | normal      | Delete scan schedules.                                            |
| audit.scan_schedule.manage           | organization | yes                             | normal      | Create, edit, enable and run scan schedules.                      |
| audit.scan_schedule.read             | organization | yes                             | normal      | View scan schedules and their runs.                               |
| audit.vuln_feed.manage               | platform     | no                              | privileged  | Start and monitor the vulnerability-feed synchronisation.         |
| platform.audit_log.export            | organization | yes                             | privileged  | Export the audit log.                                             |
| platform.audit_log.read              | organization | yes                             | normal      | View the audit log of an organisation.                            |
| platform.audit_log.retention         | platform     | no                              | privileged  | Preview audit-log retention and what it would remove.             |
| platform.email_domain.manage         | platform     | no                              | privileged  | Create, change and delete email-domain rules.                     |
| platform.email_domain.read           | platform     | no                              | normal      | View the email-domain rules and their statistics.                 |
| platform.organization.archive        | platform     | no                              | privileged  | Archive an organisation and restore an archived one.              |
| platform.organization.create         | platform     | no                              | privileged  | Create an organisation.                                           |
| platform.organization.read           | platform     | no                              | normal      | List and view organisations.                                      |
| platform.organization.set_scan_scope | platform     | no                              | privileged  | Set the address ranges an organisation may target.                |
| platform.organization.switch         | platform     | no                              | privileged  | Act inside an organisation other than one's own.                  |
| platform.organization.update         | platform     | no                              | privileged  | Edit an organisation's metadata, and activate or deactivate it.   |
| platform.permission.read             | organization | yes                             | normal      | View the permission catalogue and what each role holds.           |
| platform.registration.manage         | platform     | no                              | privileged  | Enable or disable self-registration for the entire platform.      |
| platform.registration.read           | platform     | no                              | normal      | View the platform-wide self-registration policy.                  |
| platform.role.assign_platform        | platform     | no                              | privileged  | Assign a platform-scope role to a user.                           |
| platform.role.create                 | organization | yes                             | privileged  | Create a custom role in an organisation.                          |
| platform.role.create_platform        | platform     | no                              | privileged  | Create a platform-scope custom role.                              |
| platform.role.read                   | organization | yes                             | normal      | View the roles available in an organisation.                      |
| platform.role.rename_system          | platform     | no                              | privileged  | Change the display name of a system role.                         |
| platform.role.retire                 | organization | yes                             | privileged  | Retire a custom role in an organisation.                          |
| platform.role.retire_system          | platform     | no                              | privileged  | Retire a system role.                                             |
| platform.role.set_default            | platform     | no                              | privileged  | Choose the role that new self-registered accounts receive.        |
| platform.role.update                 | organization | yes                             | privileged  | Change the permissions of a custom role in an organisation.       |
| platform.user.approve                | organization | yes                             | privileged  | Approve a newly registered account so it can sign in.             |
| platform.user.assign_role            | organization | yes                             | privileged  | Change which role a user holds within an organisation.            |
| platform.user.create                 | organization | yes                             | normal      | Create a user account in an organisation.                         |
| platform.user.delete                 | organization | yes                             | normal      | Soft-delete a user account and restore a soft-deleted one.        |
| platform.user.move_org               | platform     | no                              | privileged  | Move a user account to another organisation.                      |
| platform.user.purge                  | organization | yes                             | privileged  | Permanently erase a user account.                                 |
| platform.user.read                   | organization | yes                             | normal      | List and view the user accounts of an organisation.               |
| platform.user.reset_credentials      | organization | yes                             | privileged  | Reset another account's password or multi-factor enrolment.       |
| platform.user.update                 | organization | yes                             | normal      | Edit a user account and activate or deactivate it.                |

See [administration and governance](architecture/RBAC_ADMINISTRATION.md),
[frontend authorization](architecture/RBAC_FRONTEND_AUTHORIZATION.md),
[tenant scope](architecture/RBAC_SCOPE.md), and
[phase verification and deployment limits](rbac/RBAC_HARDENING_REPORT.md).

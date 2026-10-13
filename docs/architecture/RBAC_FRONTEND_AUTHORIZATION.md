# Native frontend authorization

The backend authorization payload is authoritative. The frontend does not authorize by
role name or interpret a legacy permission vocabulary. `AuthContext` fetches the current
account and stores its native `authorization` response; a response without that contract
is treated as an incompatible backend.

| Field                      | Meaning                                                     |
| -------------------------- | ----------------------------------------------------------- |
| `contract`                 | Native authorization contract version, currently 1          |
| `home_org_id`              | Account membership organisation                             |
| `active_org_id`            | Organisation the backend validated for this session context |
| `permissions.platform`     | Effective platform-scoped keys                              |
| `permissions.organization` | Effective keys for the validated active organisation        |
| `can_switch_organisation`  | Engine decision for the platform switch grant               |
| `assignments`              | Current role display labels and scopes; presentation only   |

`can(user, key)` and its scope/context variants consume those exact keys. A missing key
means denied; there is no wildcard or role-name override. Private routes and product
controls use this payload for visibility, while every backend request checks authority
again using current database grants. Browser storage's active organisation is a request
hint, never authorization evidence.

## Roles and permissions UI

The role editor renders the backend catalogue and detail response. Active custom roles
can be updated in place with the appropriate scope-specific management authority.
System-role permission controls remain read-only. Disabled entries explain retired
permissions, scope restrictions, non-delegability and the actor's delegation ceiling.
Grantability metadata comes from the backend; backend governance remains the final gate.

Creation sends the backend-validated active organisation. Permission changes send
`expected_revision` from the loaded role detail; stale revisions return 409, reload the
role and display the backend explanation. Step-up prompts retry with `X-Reauth-Code`;
the code is not stored. Denied governance operations display backend reasons.

Successful role changes refresh signed-in authorization quietly before reloading role
state. The existing periodic session refresh also fetches effective authorization, so
other clients update their controls without a new push system. Backend enforcement is
immediate even while another browser has old visible controls. Organisation changes
reload the role list and catalogue for the new context.

Assignment and removal controls distinguish organisation assignment authority from
platform assignment authority. Replacement needs assignment authority; retirement
controls use the existing lifecycle authority. Create, edit, retire and assign are not
inferred from a role label. The backend's assignable-role response bounds role choices.

Relevant source: `Frontend/src/shell/auth/authorization.js`, `AuthContext.jsx`,
`admin/pages/RoleManagement.jsx`, `admin/components/RolePermissionEditor.jsx`,
`admin/components/UserRolesPanel.jsx`, and `shell/api/rbac.js`. The checked-in
`Frontend/authorization-inventory.json` is generated from current UI permission checks.

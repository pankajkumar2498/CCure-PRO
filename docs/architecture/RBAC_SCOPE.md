# Native RBAC tenant scope

Permission grants decide what an account may do; assignment scope and tenant context
decide where. The native engine is authoritative and has no legacy or role-name fallback.
Organisation grants apply only to membership-matching assignments in that organisation.
Platform grants remain platform-wide; cross-organisation action additionally requires
`platform.organization.switch`. Holding a role named Superadmin grants no special reach.

`resolve_active_organisation` validates requested organisations and records switches.
Missing organisations return 404, inactive organisations 403, and failure to audit a
switch returns 503. The established read contract ignores an unauthorized foreign hint,
records the denial and uses the active home organisation. Management **writes** use
`mutation_organisation` and reject that foreign hint instead of silently writing at home.
Role creation honours either body or query organisation and rejects conflicting values.
Resource operations use the tenant stored on the resource and govern assignments against
the target's membership; a query parameter cannot manufacture that membership.

Governance checks role ownership, assignment scope, delegation ceilings, self-assignment
and lifecycle. New assignments require an active, unarchived tenant. The database's
scope, role-identity and assignment guards remain in place. The resolver ignores
organisation assignments that no longer match account membership. Account transfers
revoke old organisation assignments through governed operations, preserve their audit
history and require separately authorized destination assignments.

Sensitive cross-tenant role changes require the same existing step-up policy as sensitive
system/platform changes. Administrator-removing operations share a transaction advisory
lock and reject new platform or active-organisation continuity violations. Deactivation
and deletion of accounts, and ending a tenancy containing platform administrators, use
the same continuity protocol. No ordinary organisation administrator can grant or change
platform permissions.

See `Backend/ccure_platform/rbac/scope.py`, `engine.py`, `resolver.py`, `governance.py`,
`administration.py` and the shared HTTP checks in
`ccure_platform/administration/rbac_security.py`. Tests cover rejected tenant contexts,
foreign assignments, inactive tenants, scope-specific delegation and preserved history.

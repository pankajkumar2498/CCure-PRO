# CCure-Audit-PRO — RBAC Management & Permissions Reference

> All data sourced directly from `Backend/db/migrate_production_schema.py` (the authoritative seed file) and `Backend/auth/rbac.py` (the runtime enforcement layer).

## 1. Role Overview

Five system roles are seeded at first boot (`is_system_role = true`). They cannot be deleted via the API.

| Role         | Intended Persona                 | Scan Launch   | Admin Functions                   |
| ------------ | -------------------------------- | ------------- | --------------------------------- |
| `superadmin` | Platform operator — cross-tenant | Yes (any org) | Full                              |
| `org_admin`  | Organization administrator       | Yes (own org) | User + role management within org |
| `analyst`    | Security analyst                 | Yes (own org) | None                              |
| `viewer`     | Read-only stakeholder            | No            | None                              |
| `scanner`    | Automated scan agent / CI-CD     | Yes (own org) | None                              |

## 2. Complete Permission Enumeration

**Total: 51 permissions** (40 core system permissions + 11 policy compliance permissions), derived from the current seed list in [Backend/db/migrate_production_schema.py](Backend/db/migrate_production_schema.py).

### Core System Permissions (40)

| #   | Resource        | Action     | Description                                     |
| --- | --------------- | ---------- | ----------------------------------------------- |
| 1   | `scans`         | `create`   | Create new scans                                |
| 2   | `scans`         | `read`     | View own scans                                  |
| 3   | `scans`         | `read_all` | View all scans in the organization              |
| 4   | `scans`         | `update`   | Update scan metadata                            |
| 5   | `scans`         | `execute`  | Trigger scan execution (Phase 1/2/3 endpoints)  |
| 6   | `scans`         | `cancel`   | Stop an in-progress scan                        |
| 7   | `scans`         | `archive`  | Move scan to Archived Scans                     |
| 8   | `scans`         | `restore`  | Restore scan from archive or recycle bin        |
| 9   | `scans`         | `recycle`  | Move scan to recycle bin                        |
| 10  | `scans`         | `purge`    | Permanently delete from recycle bin             |
| 11  | `assets`        | `create`   | Add new assets                                  |
| 12  | `assets`        | `read`     | View asset inventory                            |
| 13  | `assets`        | `update`   | Update asset metadata, tags, notes              |
| 14  | `assets`        | `delete`   | Delete assets                                   |
| 15  | `assets`        | `export`   | Export asset data to CSV/PDF                    |
| 16  | `findings`      | `read`     | View vulnerability findings                     |
| 17  | `findings`      | `update`   | Triage findings (accept risk, mark fixed, etc.) |
| 18  | `findings`      | `export`   | Export findings to CSV/PDF                      |
| 19  | `reports`       | `create`   | Generate reports                                |
| 20  | `reports`       | `read`     | Download reports                                |
| 21  | `reports`       | `delete`   | Delete generated reports                        |
| 22  | `users`         | `create`   | Create new users                                |
| 23  | `users`         | `read`     | View user list                                  |
| 24  | `users`         | `update`   | Edit user details, activate/deactivate          |
| 25  | `users`         | `delete`   | Soft-delete or permanently remove users         |
| 26  | `roles`         | `create`   | Create custom roles                             |
| 27  | `roles`         | `read`     | View roles and permission assignments           |
| 28  | `roles`         | `update`   | Modify role permissions                         |
| 29  | `roles`         | `delete`   | Delete custom roles                             |
| 30  | `organizations` | `create`   | Create new organizations                        |
| 31  | `organizations` | `read`     | View organization list/details                  |
| 32  | `organizations` | `update`   | Update organization settings                    |
| 33  | `organizations` | `delete`   | Delete organizations                            |
| 34  | `audit`         | `read`     | View the immutable audit log                    |
| 35  | `credentials`   | `create`   | Store SSH credentials for credentialed scans    |
| 36  | `credentials`   | `read`     | List stored credential references               |
| 37  | `credentials`   | `delete`   | Remove stored credentials                       |
| 38  | `settings`      | `read`     | View system/organization settings               |
| 39  | `settings`      | `update`   | Modify settings (e.g., AMT import)              |
| 40  | `dashboard`     | `read`     | View dashboard analytics                        |

### Policy Compliance Engine Permissions (11)

| #   | Resource     | Action                | Description                                                         |
| --- | ------------ | --------------------- | ------------------------------------------------------------------- |
| 41  | `compliance` | `read`                | View compliance dashboards, marketplace and findings                |
| 42  | `compliance` | `scan`                | Trigger manual policy compliance scans                              |
| 43  | `compliance` | `manage_schedules`    | Manage recurring compliance scan schedules                          |
| 44  | `compliance` | `attest`              | Record manual control attestation and upload evidence               |
| 45  | `compliance` | `remediate`           | Trigger automated remediation scripts (Maker action)                |
| 46  | `compliance` | `manage_rules`        | Create and edit compliance policies and rules                       |
| 47  | `compliance` | `manage_frameworks`   | Install and configure compliance frameworks from marketplace        |
| 48  | `compliance` | `manage_retention`    | Configure compliance evidence retention policies                    |
| 49  | `compliance` | `manage_integrations` | Configure compliance credentials and third-party integrations       |
| 50  | `compliance` | `approve_exception`   | Approve exception waivers or remediation execution (Checker action) |
| 51  | `compliance` | `export_report`       | Export Statement of Applicability (SoA) and executive reports       |

## 3. Role → Permission Matrix

A cell marked **✓** means the role has that permission granted.

| Permission (resource:action)     | superadmin | org_admin | analyst | viewer | scanner |
| -------------------------------- | :--------: | :-------: | :-----: | :----: | :-----: |
| `scans:create`                   |     ✓      |     ✓     |    ✓    |        |    ✓    |
| `scans:read`                     |     ✓      |     ✓     |    ✓    |   ✓    |    ✓    |
| `scans:read_all`                 |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `scans:update`                   |     ✓      |     ✓     |         |        |         |
| `scans:execute`                  |     ✓      |     ✓     |    ✓    |        |    ✓    |
| `scans:cancel`                   |     ✓      |     ✓     |    ✓    |        |         |
| `scans:archive`                  |     ✓      |     ✓     |         |        |         |
| `scans:restore`                  |     ✓      |     ✓     |         |        |         |
| `scans:recycle`                  |     ✓      |     ✓     |         |        |         |
| `scans:purge`                    |     ✓      |     ✓     |         |        |         |
| `assets:create`                  |     ✓      |     ✓     |         |        |         |
| `assets:read`                    |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `assets:update`                  |     ✓      |     ✓     |    ✓    |        |         |
| `assets:delete`                  |     ✓      |     ✓     |         |        |         |
| `assets:export`                  |     ✓      |     ✓     |    ✓    |        |         |
| `findings:read`                  |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `findings:update`                |     ✓      |     ✓     |    ✓    |        |         |
| `findings:export`                |     ✓      |     ✓     |    ✓    |        |         |
| `reports:create`                 |     ✓      |     ✓     |    ✓    |        |         |
| `reports:read`                   |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `reports:delete`                 |     ✓      |     ✓     |         |        |         |
| `users:create`                   |     ✓      |     ✓     |         |        |         |
| `users:read`                     |     ✓      |     ✓     |         |        |         |
| `users:update`                   |     ✓      |     ✓     |         |        |         |
| `users:delete`                   |     ✓      |     ✓     |         |        |         |
| `roles:create`                   |     ✓      |           |         |        |         |
| `roles:read`                     |     ✓      |     ✓     |         |        |         |
| `roles:update`                   |     ✓      |           |         |        |         |
| `roles:delete`                   |     ✓      |           |         |        |         |
| `organizations:create`           |     ✓      |           |         |        |         |
| `organizations:read`             |     ✓      |           |         |        |         |
| `organizations:update`           |     ✓      |           |         |        |         |
| `organizations:delete`           |     ✓      |           |         |        |         |
| `audit:read`                     |     ✓      |     ✓     |         |        |         |
| `credentials:create`             |     ✓      |     ✓     |         |        |         |
| `credentials:read`               |     ✓      |     ✓     |    ✓    |        |    ✓    |
| `credentials:delete`             |     ✓      |     ✓     |         |        |         |
| `settings:read`                  |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `settings:update`                |     ✓      |     ✓     |         |        |         |
| `dashboard:read`                 |     ✓      |     ✓     |    ✓    |   ✓    |         |
| **Compliance Permissions**       |            |           |         |        |         |
| `compliance:read`                |     ✓      |     ✓     |    ✓    |   ✓    |         |
| `compliance:scan`                |     ✓      |     ✓     |    ✓    |        |         |
| `compliance:manage_schedules`    |     ✓      |     ✓     |    ✓    |        |         |
| `compliance:attest`              |     ✓      |     ✓     |    ✓    |        |         |
| `compliance:remediate`           |     ✓      |     ✓     |    ✓    |        |         |
| `compliance:manage_rules`        |     ✓      |     ✓     |         |        |         |
| `compliance:manage_frameworks`   |     ✓      |     ✓     |         |        |         |
| `compliance:manage_retention`    |     ✓      |     ✓     |         |        |         |
| `compliance:manage_integrations` |     ✓      |     ✓     |         |        |         |
| `compliance:approve_exception`   |     ✓      |     ✓     |         |        |         |
| `compliance:export_report`       |     ✓      |     ✓     |    ✓    |        |         |

> _`superadmin` receives **all** permissions (`"_"`wildcard in`ROLE_PERMISSIONS`). The seeded `scanner`role receives`credentials:read`only.`credentials:create`and`credentials:delete`are granted to`org_admin`and`superadmin` only.

## 4. Runtime Enforcement (`auth/rbac.py`)

### `require_permission(resource, action)`

FastAPI dependency injected into every protected route handler.

```python
user: User = Depends(require_permission("scans", "execute"))
```

**Logic:**

1. Calls `get_current_active_user()` (validates JWT, loads User + Role from DB, checks `user.is_active`, checks `user.organization.is_active`).
2. If `role.name == "superadmin"` → **bypass**: immediately returns the user.
3. Otherwise performs a DB lookup:
   ```sql
   SELECT rp.id
   FROM role_permissions rp
   JOIN permissions p ON p.id = rp.permission_id
   WHERE rp.role_id = :role_id
     AND p.resource  = :resource
     AND p.action    = :action
   LIMIT 1
   ```
4. If no matching row → raises `HTTP 403 Forbidden`.

### `get_current_user()` / `get_current_active_user()`

- Extracts the `Authorization: Bearer <token>` header (or falls back to the `access_token` cookie, though cookie auth is not the primary flow).
- Loads the user with `joinedload(User.role)` and `joinedload(User.organization)` so permission and org state are available in one round-trip.
- Decodes the JWT via `auth/jwt_handler.decode_token()` (HS256, `JWT_SECRET_KEY`).
- Verifies `payload["type"] == "access"`.
- Loads `User` from DB with `joinedload(User.role)` and `joinedload(User.organization)`.
- Raises `HTTP 401` if the token is invalid, expired, or the user row is missing.
- Raises `HTTP 403` if `user.is_active == False` or `user.organization.is_active == False`.

### `get_current_active_user_ws(ticket)` (WebSocket variant)

Used by the WebSocket progress endpoints (`/scans/{id}/progress`, `/web-scans/{id}/progress`). Reads the `?ticket=` query parameter instead of an `Authorization` header. The ticket is a short-lived JWT with `type: "ticket"` generated by `POST /auth/ticket`.

## 5. Tenant Isolation Pattern

Every router that returns user data, scan data, asset data, or web-scan data applies this two-step isolation pattern in `_resolve_org()`:

```python
def _resolve_org(user: User, requested_org: Optional[str]) -> str:
    if is_superadmin(user) and requested_org:
        return requested_org   # superadmin can inspect any org via ?org_id=
    return str(user.org_id)    # everyone else sees only their own org
```

All subsequent queries include a `WHERE org_id = :org_id` predicate. There is no shared data between organizations at the API layer (the only cross-tenant path is the `superadmin` role).

## 6. Audit Logging

`core/audit.py` provides `log_audit_event(db, org_id, user_id, action, resource_type, resource_id, changes, ip, user_agent, status)`. It is called for all significant state mutations:

- User create/update/delete/activate/deactivate/login/logout
- Organization create/update/delete/activate/deactivate
- Role and permission changes
- Scan create/archive/restore/delete/purge
- Asset import (AMT)
- Password reset requests

Audit rows are **immutable** (no update/delete APIs expose them). The `GET /admin/audit-logs` endpoint is restricted to `audit:read`, which is granted only to `superadmin` and `org_admin`.

## 7. Frontend Permission Mirroring (`src/auth/permissions.js`)

The frontend re-implements the same permission check locally using the `permissions` list embedded in the `/auth/me` response payload:

```js
// can(user, "scans", "execute") → true/false
export function can(user, resource, action) {
  if (!user?.permissions) return false;
  return user.permissions.some(
    (p) => p.resource === resource && p.action === action,
  );
}
```

This is used to conditionally render or disable UI elements (buttons, menu items, routes). The backend remains the **authoritative enforcement point** — frontend permission checks are purely cosmetic / UX optimizations.

`<PrivateRoute>` uses `requiredPermission`, `requiredAny`, `requiredAll`, and `superadminOnly` props to gate entire page routes, redirecting to `/` if the current user's role lacks the required permission(s).

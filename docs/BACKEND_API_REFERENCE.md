# CCure-Audit-PRO — Backend API Reference

> All endpoints verified directly from source code (exact route strings extracted from every router file). Base URL: `http(s)://<host>/` (nginx gateway). Unless noted, all requests and responses use `Content-Type: application/json`. All protected endpoints require `Authorization: Bearer <access_token>`.

## Global Response Envelope

All `HTTPException`s are converted to a standard envelope by the global exception handler in `main.py`:

```json
{
  "success": false,
  "error_code": "HTTP_403",
  "message": "Insufficient permissions",
  "request_id": "req-uuid-..."
}
```

Validation errors (HTTP 422) additionally include an `errors` array. Fields whose paths contain `password`, `key_path`, `secret`, `token`, `api_key`, or `credential` are redacted in echoed `input` values.

---

## 1. Authentication (`/auth`)

### `POST /auth/register`

**Auth:** None

**Request body:**

```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "Secure@123"
}
```

**Response `200`:**

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {
    "id": "...",
    "username": "alice",
    "role": "analyst",
    "org_id": "..."
  }
}
```

Sets `refresh_token` HttpOnly cookie.

---

### `POST /auth/login`

**Auth:** None | **Rate limit:** 5/min

**Request body:**

```json
{ "email": "alice@example.com", "password": "Secure@123" }
```

**Response `200`:** Same as `/auth/register`.

**Errors:** `401` invalid credentials or locked account; `429` rate limit exceeded.

---

### `POST /auth/refresh`

**Auth:** `refresh_token` HttpOnly cookie

Returns a new access token and rotates the refresh token.

**Response `200`:**

```json
{ "access_token": "<new_jwt>", "token_type": "bearer" }
```

**Errors:** `401` if cookie missing, invalid, expired, or already revoked.

---

### `POST /auth/logout`

**Auth:** Bearer

Revokes the current refresh token session and clears the cookie.

**Response `200`:** `{ "detail": "Logged out successfully." }`

---

### `GET /auth/me`

**Auth:** Bearer

**Response `200`:**

```json
{
  "id": "usr_defa_...",
  "username": "alice",
  "email": "alice@example.com",
  "role": "analyst",
  "org_id": "org_acme",
  "is_active": true,
  "permissions": [
    { "resource": "scans", "action": "read" },
    { "resource": "scans", "action": "execute" }
  ]
}
```

---

### `GET /auth/check-username`

**Auth:** None | **Query:** `?q=<value>`

**Response `200`:** `{ "available": true }`

---

### `GET /auth/check-email`

**Auth:** None | **Query:** `?q=<value>`

**Response `200`:** `{ "available": true }`

---

### `POST /auth/forgot-password`

**Auth:** None

**Request body:** `{ "email": "alice@example.com" }`

**Response `200`:** Always returns `{ "detail": "If this email is registered, you will receive a reset link shortly." }` (prevents user enumeration).

---

### `POST /auth/reset-password`

**Auth:** None

**Request body:**

```json
{ "token": "<reset_token_from_email>", "password": "NewSecure@456" }
```

**Response `200`:** `{ "detail": "Your password has been reset successfully." }`

---

### `POST /auth/ticket`

**Auth:** Bearer

Issues a 60-second ticket JWT for WebSocket connections and PDF downloads.

**Response `200`:** `{ "ticket": "<short_lived_jwt>" }`

> **Note:** The real endpoint path is `/auth/ticket` (not `/auth/ws-ticket`). The ticket is passed as `?ticket=<jwt>` to WebSocket endpoints.

---

### `POST /auth/mfa/enable`

**Auth:** Bearer

Initiates Multi-Factor Authentication setup for the current user. Generates a unique TOTP secret and returns it along with a QR code Data URI.

**Response `200`:**

```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,..."
}
```

---

### `POST /auth/mfa/confirm`

**Auth:** Bearer

Confirms the setup code from the authenticator app and enables MFA for the user. Returns 8 single-use hex backup recovery codes.

**Request body:**

```json
{
  "code": "123456"
}
```

**Response `200`:**

```json
{
  "backup_codes": [
    "A1B2C3D4",
    "E5F6A7B8",
    ...
  ]
}
```

---

### `POST /auth/mfa/disable`

**Auth:** Bearer

Disables MFA. Requires password validation for safety.

**Request body:**

```json
{
  "password": "SecurePassword123"
}
```

**Response `200`:**

```json
{
  "success": true
}
```

---

### `POST /auth/login/send-email-otp`

**Auth:** None | **Rate limit:** 5/min

Generates and emails a 6-digit verification code fallback challenge when logging in. Requires the temporary `mfa_token` challenge token returned by the initial `/auth/login` check.

**Request body:**

```json
{
  "mfa_token": "<mfa_challenge_jwt>"
}
```

**Response `200`:**

```json
{
  "success": true
}
```

---

### `POST /auth/login/verify-mfa`

**Auth:** None | **Rate limit:** 5/min

Verifies the verification code (App TOTP, Email OTP, or Recovery Backup Code) using the challenge token to complete the login process and issue the final access + refresh tokens.

**Request body:**

```json
{
  "mfa_token": "<mfa_challenge_jwt>",
  "code": "123456"
}
```

**Response `200`:**

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "user": {
    "id": "...",
    "username": "alice",
    "role": "analyst",
    "org_id": "...",
    "mfa_enabled": true
  }
}
```

---

## 2. Scan History (`/scans`)

**Permission required:** `scans:read` (minimum)

### `GET /scans`

List scans in the current user's organization. Paginated. _(Route registered as `GET /scans` with no trailing slash — FastAPI also accepts `/scans/`.)_

**Query params:**

| Param        | Type   | Default  | Notes                               |
| ------------ | ------ | -------- | ----------------------------------- |
| `skip`       | int    | 0        | Pagination offset                   |
| `limit`      | int    | 50       | Max 200                             |
| `scope`      | string | `active` | `active / archived / deleted / all` |
| `created_by` | string | —        | `me` or a specific user ID          |
| `org_id`     | string | —        | `superadmin` only                   |

**Response `200`:**

```json
{
  "scope": "active",
  "total": 42,
  "scans": [
    {
      "id": "scn_defa_...",
      "scan_no": 17,
      "display_id": 17,
      "target": "192.168.1.0/24",
      "targets": ["192.168.1.0/24"],
      "scan_type": "adaptive",
      "phase": 3,
      "status": "complete",
      "pipeline_mode": "vulnerability_audit",
      "scan_duration": 124.5,
      "created_at": "2026-05-14T09:30:00Z",
      "updated_at": "2026-05-14T09:32:04Z",
      "is_archived": false,
      "is_deleted": false,
      "started_by": {
        "username": "alice",
        "full_name": "Alice Smith",
        "role": "analyst"
      },
      "summary": { "total_hosts": 45, "active_hosts": 32, "total_vulns": 7 }
    }
  ],
  "version": "42|scn_...:17:complete:3:...",
  "emitted_at": "2026-05-14T09:35:00Z"
}
```

---

### `GET /scans/events`

**Permission:** `scans:read`

Server-Sent Events (SSE) stream of scan history snapshots. Adaptive poll interval: **0.5s** while any scan is `running`, **2.0s** otherwise. The endpoint is mounted at `/scans/events` (not `/scan/events`) and emits `connected`, `scans`, and `heartbeat` events.

**Query params:** Same as `GET /scans` plus `interval` (0.5–15.0 seconds).

**Event types:**

- `connected` — initial connection confirmation
- `scans` — full snapshot payload (same shape as `GET /scans` response)
- `heartbeat` — `{ "emitted_at": "..." }` (no state change)

**Response headers:** `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no`

---

### `WEBSOCKET /scans/{scan_id}/progress`

**Auth:** `?ticket=<ticket_jwt>` query param (from `POST /auth/ticket`)

Real-time scan progress via Redis Pub/Sub. Sends an immediate DB snapshot on connect (handles race conditions), then relays all `scan_progress:{scan_id}` Redis messages.

---

### `GET /scans/{scan_id}`

**Permission:** `scans:read`

Full scan detail including all phase results.

---

### `POST /scans/{scan_id}/archive`

**Permission:** `scans:archive`

Move scan to Archived Scans.

**Response `200`:** `{ "archived": true }`

---

### `POST /scans/{scan_id}/restore`

**Permission:** `scans:restore`

Restore from archive or recycle bin.

**Response `200`:** `{ "restored": true, "destination": "active" }`

---

### `POST /scans/{scan_id}/stop`

**Permission:** `scans:execute`

Terminates an active scan: marks scan + active phases as `cancelled`, revokes the Celery task via `celery.control.revoke(terminate=True)`.

**Response `200`:** `{ "stopped": true, "detail": "Scan ... stopped" }`

---

### `DELETE /scans/{scan_id}`

**Permission:** `scans:recycle`

Soft-delete (moves to recycle bin).

**Response `200`:** `{ "moved_to_recycle_bin": true }`

---

### `DELETE /scans/{scan_id}/purge`

**Permission:** `scans:purge`

Permanently deletes a scan already in the recycle bin.

**Response `200`:** `{ "detail": "Scan ... permanently deleted" }`

---

## 3. Phase-Selective Scans (`/scan`)

**Permission required:** `scans:execute` | **Rate limit:** 5/min

> The current implementation exposes these phase-selective endpoints under the `/scan` prefix via [Backend/routers/phase_scans.py](Backend/routers/phase_scans.py), and the scan history SSE feed is separate under [Backend/scans/router.py](Backend/scans/router.py).

### `GET /scan/quota`

**Permission:** `scans:read`

Returns the organization's current scan quota status.

**Response `200`:**

```json
{
  "plan": "community",
  "scans_used_24h": 3,
  "scans_limit_24h": 5,
  "concurrent_running": 1,
  "concurrent_limit": 1,
  "max_ips_per_scan": 254,
  "max_subnet_prefix": 24,
  "quota_exceeded": false,
  "concurrent_exceeded": false
}
```

---

### `POST /scan/host-discovery`

**Permission:** `scans:execute`

Triggers **Phase 1 — Host Discovery** as a background Celery task.

**Request body:**

```json
{
  "targets": ["192.168.1.0/24"],
  "scan_type": "adaptive",
  "pipeline_mode": "vulnerability_audit",
  "phases": [1, 2, 3],
  "discovery_intensity": "normal",
  "port_scan_intensity": "normal",
  "os_detection": true,
  "execution_mode": "automatic",
  "rate_limit": null,
  "max_concurrency": null,
  "wait": false,
  "custom_ports": null
}
```

| Field                 | Values                                | Notes                                                                    |
| --------------------- | ------------------------------------- | ------------------------------------------------------------------------ |
| `pipeline_mode`       | `basic / asset / vulnerability_audit` | Determines terminal phase and auto-chaining                              |
| `discovery_intensity` | `light / normal / deep`               | Asset pipeline Phase 1 only; ignored for `basic` / `vulnerability_audit` |
| `port_scan_intensity` | `light / normal / deep`               | Phase 2 Nmap port range                                                  |
| `execution_mode`      | `automatic / interactive`             | `automatic` auto-chains to next phases                                   |
| `wait`                | `true / false`                        | If `true`, blocks up to 300s and returns inline results                  |
| `custom_ports`        | `"22,80,443,8000-8080"`               | Overrides intensity-based port profile for Phase 2                       |

**Response `200`:**

```json
{
  "success": true,
  "task_id": "celery-task-uuid",
  "scan_id": "scn_defa_...",
  "scan_no": 18,
  "status": "running"
}
```

---

### `POST /scan/asset-discovery`

**Permission:** `scans:execute`

Triggers **Phase 2 — Port Scanning**.

**Request body:**

```json
{
  "hosts": [],
  "intensity": "normal",
  "scan_id": "scn_defa_...",
  "pipeline_mode": "vulnerability_audit",
  "os_detection": true,
  "phases": [2, 3],
  "custom_ports": null
}
```

**Response `200`:** `{ "success": true, "task_id": "...", "status": "running" }`

---

### `POST /scan/vulnerability-audit`

**Permission:** `scans:execute`

Triggers **Phase 3 — Vulnerability Audit + Risk Scoring**.

**Request body:**

```json
{
  "hosts": [],
  "scan_id": "scn_defa_...",
  "pipeline_mode": "vulnerability_audit",
  "vulnerability_profile": "recommended",
  "phases": [3]
}
```

`vulnerability_profile`: `recommended / conservative / deep`

**Response `200`:** `{ "success": true, "task_id": "...", "status": "running" }`

---

### `POST /scan/phases`

**Permission:** `scans:execute`

All phases in a single background task (no live streaming).

**Request body:**

```json
{
  "targets": ["192.168.1.0/24"],
  "phases": "1+2+3+4",
  "scan_type": "adaptive",
  "intensity": "normal"
}
```

**Response `200`:** `{ "success": true, "task_id": "...", "status": "running" }`

---

## 4. Traditional (Legacy) Scan Endpoints (`/scan`)

**Permission:** `scans:execute`

Backward-compatible synchronous endpoints. Block until complete (up to 180s).

### `POST /scan/host`

Single host full-pipeline scan.
**Body:** `{ "target": "192.168.1.1", "scan_type": "adaptive" }`

### `POST /scan/range`

IP range scan (Phase 1 only).
**Body:** `{ "target": "192.168.1.1-50", "scan_type": "adaptive" }`

### `POST /scan/subnet`

CIDR subnet scan (Phase 1 only).
**Body:** `{ "target": "192.168.1.0/24", "scan_type": "adaptive" }`

### `POST /scan/subnets`

Sub-networks of a parent CIDR.
**Body:** `{ "target": "10.0.0.0/16", "subnet_prefix": 24, "scan_type": "adaptive" }`

---

## 5. Credentialed Scans (`/scan`)

**Permission:** `scans:execute`

### `POST /scan/credentialed`

SSH credentialed scan. Tests connectivity synchronously then dispatches `run_credentialed_scan_task` to the `scanner` queue.

**Request body:**

```json
{
  "ip": "192.168.1.10",
  "username": "root",
  "password": "s3cr3t",
  "key_path": null,
  "port": 22,
  "auth_method": "password",
  "sections": null,
  "os_type": "auto"
}
```

| Field         | Values                   | Notes                                      |
| ------------- | ------------------------ | ------------------------------------------ |
| `auth_method` | `password / key`         |                                            |
| `key_path`    | string/null              | Must be within `SCAN_KEY_DIR` env var path |
| `os_type`     | `linux / windows / auto` | `auto` runs 5 detection probes             |
| `sections`    | list/null                | Specific collection modules; null = all    |

**Response `200`:** `{ "success": true, "scan_id": "scn_defa_...", "scan_no": 19, "status": "running" }`

**Errors:** `400` if host unreachable; `503` if paramiko not installed.

---

## 6. Health & Documentation

### `GET /`

**Auth:** None. System health + info from `HostDiscoveryAPI.get_system_info()`.

### `GET /scan/progress/{scan_id}`

**Permission:** `scans:read`

DB-backed real-time progress (multi-worker safe — any worker can serve regardless of which worker started the scan).

**Response `200`:**

```json
{
  "total_ips": 254,
  "discovered": 12,
  "active": 9,
  "status": "running",
  "elapsed_time": 45.2,
  "percentage": 35
}
```

### `GET /api/pipeline-modes`

**Auth:** None. Documentation of available pipeline modes and their phase sequences.

### `GET /api/workflow-example`

**Auth:** None. Documentation of the frontend orchestration workflow.

---

## 7. Assets (`/assets`)

**Permission:** `assets:read` (minimum)

### `GET /assets`

Paginated asset registry.

**Query params:**

| Param             | Default        | Notes                                               |
| ----------------- | -------------- | --------------------------------------------------- |
| `skip`            | 0              |                                                     |
| `limit`           | 50             | Max 500                                             |
| `org_id`          | —              | superadmin only                                     |
| `search`          | —              | Partial match on IP/hostname/MAC/vendor             |
| `risk_level`      | —              | `critical / high / medium / low / info`             |
| `device_category` | —              | Filter by device type                               |
| `is_active`       | —              | `true / false`                                      |
| `is_managed`      | —              | `true / false`                                      |
| `sort_by`         | `last_seen_at` | `risk_score / last_seen_at / ip_address / hostname` |
| `sort_dir`        | `desc`         | `asc / desc`                                        |
| `tag`             | —              | Filter by asset tag                                 |

**Response:** `{ "total": N, "assets": [...] }`

---

### `GET /assets/debug-reconcile`

**Permission:** `assets:read`

Runs the AMT reconciliation algorithm and returns a preview without writing changes.

---

### `GET /assets/reconciliation/drilldown`

**Permission:** `assets:read`

Detailed drilldown breakdown of asset reconciliation provenance and AMT matching history.

---

### `GET /assets/certificates`

**Permission:** `assets:read`

Organization-wide TLS certificate inventory with expiry status.

> **Note:** This endpoint path is `/assets/certificates` — not `/assets/tls-inventory`.

---

### `GET /assets/services`

**Permission:** `assets:read`

Organization-wide open service (port) inventory.

> **Note:** This endpoint path is `/assets/services` — not `/assets/services-inventory`.

---

### `GET /assets/services/assets`

**Permission:** `assets:read`

Assets grouped by service type.

---

### `GET /assets/coverage-stats`

**Permission:** `assets:read`

Asset coverage statistics (managed vs unmanaged, AMT reconciliation coverage).

---

### `GET /assets/{asset_id}`

**Permission:** `assets:read`

Full asset detail including services, TLS details, latest vulnerabilities, notes, tags, and change log.

---

### `GET /assets/{asset_id}/services`

**Permission:** `assets:read`

Open port/service records for this asset across all scans.

---

### `GET /assets/{asset_id}/findings`

**Permission:** `assets:read`

Vulnerability findings for this asset. Optional `?status=` and `?severity=` filters.

> **Note:** This endpoint path is `/assets/{asset_id}/findings` — not `/assets/{asset_id}/vulnerabilities`.

---

### `GET /assets/{asset_id}/changelog`

**Permission:** `assets:read`

Differential scan change log (port_opened, port_closed, os_changed, etc.).

> **Note:** This endpoint path is `/assets/{asset_id}/changelog` — not `/assets/{asset_id}/history`.

---

### `PATCH /assets/{asset_id}`

**Permission:** `assets:update`

Partial update. Supported fields: `owner`, `is_managed`, `custom_attributes`.

---

### `POST /assets/{asset_id}/tags`

**Permission:** `assets:update`

Add tags. Body: `{ "tag": "web-server" }`

---

### `DELETE /assets/{asset_id}/tags/{tag}`

**Permission:** `assets:update`

Remove a single tag from an asset.

---

### `POST /assets/{asset_id}/notes`

**Permission:** `assets:update`

Body: `{ "content": "Analyst note text" }`

---

### `POST /assets/import-amt`

**Permission:** `settings:update`

Upload an AMT inventory JSON file for reconciliation with the scanned asset registry.

**Body:** `multipart/form-data` with `file` field; optional `?org_id=` for superadmin.

---

## 8. Vulnerability Findings (`/findings`)

**Permission:** `findings:read`

### `GET /findings`

**Query params:** `skip`, `limit`, `org_id`, `severity`, `status`, `asset_id`, `scan_id`, `vuln_id`, `search`, `sort_by`, `sort_dir`.

**Response:** `{ "total": N, "findings": [...] }`

---

### `GET /findings/{finding_id}`

**Permission:** `findings:read`

Full finding detail including vulnerability definition, asset, and service.

---

### `PATCH /findings/{finding_id}/status`

**Permission:** `findings:update`

Triage finding status.

**Request body:**

```json
{
  "status": "accepted",
  "accepted_risk_reason": "Mitigated by WAF",
  "remediation_notes": null
}
```

`status` values: `open / accepted / fixed`

---

### `PATCH /findings/{finding_id}/notes`

**Permission:** `findings:update`

Update remediation notes only.

**Request body:** `{ "remediation_notes": "Applied patch CVE-2024-xxxx on 2026-06-01" }`

> **Note:** Findings triage is split into two separate PATCH endpoints: `/status` and `/notes`. There is no single `PATCH /findings/{id}` endpoint.

---

## 9. Dashboard Analytics (`/dashboard`)

**Permission:** `dashboard:read`

All endpoints accept optional `?org_id=` (superadmin only) and `?scan_id=` to scope to a specific scan.

| Method | Path                             | Returns                                                                       |
| ------ | -------------------------------- | ----------------------------------------------------------------------------- |
| `GET`  | `/dashboard/summary`             | Total hosts, active hosts, total/open vulns by severity, scan counts          |
| `GET`  | `/dashboard/risk-breakdown`      | Vulnerability count by severity level                                         |
| `GET`  | `/dashboard/vuln-trends`         | Vulnerability count time series (default: last 30 days)                       |
| `GET`  | `/dashboard/top-assets`          | Top 10 assets by risk score                                                   |
| `GET`  | `/dashboard/top-cves`            | Top CVEs by occurrence count (includes `in_kev`, `epss_score`, `has_exploit`) |
| `GET`  | `/dashboard/services-exposure`   | Open service distribution across the asset inventory                          |
| `GET`  | `/dashboard/tls-health`          | TLS health aggregate (valid/expired/self-signed, grade distribution)          |
| `GET`  | `/dashboard/http-headers`        | HTTP security header compliance                                               |
| `GET`  | `/dashboard/compliance`          | PCI-DSS / ISO 27001 posture summary                                           |
| `GET`  | `/dashboard/asset-breakdown`     | Asset count by device category                                                |
| `GET`  | `/dashboard/scan-activity`       | Scan frequency time series (last 30 days)                                     |
| `GET`  | `/dashboard/insights`            | AI-assisted actionable recommendations                                        |
| `GET`  | `/dashboard/web-scan-summary`    | DAST findings aggregate                                                       |
| `GET`  | `/dashboard/web-owasp-scorecard` | OWASP Top 10 finding distribution from DAST scans                             |
| `GET`  | `/dashboard/web-scan-trends`     | Web finding count time series                                                 |

---

## 10. Reports (`/reports`)

> **Note:** There is no `POST /reports/generate` endpoint. Reports are generated on-demand when downloaded. The `reports` router has exactly two endpoints.

### `GET /reports/download/{scan_id}`

**Permission:** `reports:read`

Download the generated PDF for a scan. Accepts `?fmt=JSON` (default) or `?fmt=XML`. Returns `application/pdf`. Also accepts `?ticket=<jwt>` instead of Bearer header for direct browser download links.

> **Note:** Parameter order in real path is `/reports/download/{scan_id}` — not `/reports/{scan_id}/download`.

---

### `DELETE /reports/{scan_id}`

**Permission:** `reports:delete`

Delete the generated PDF files for a scan.

---

## 11. Admin — Users (`/admin/users`)

**Permission:** `users:read` (list) / `users:create` / `users:update` / `users:delete`

### `GET /admin/users`

List users in the organization. Query: `skip`, `limit`, `search`, `role`, `is_active`, `is_deleted`, `org_id`.

> **Note:** There is no separate `GET /admin/users/deleted` endpoint. Deleted users are filtered via the `is_deleted=true` query parameter on `GET /admin/users`.

---

### `POST /admin/users`

**Permission:** `users:create`

Create a new user.

---

### `PUT /admin/users/{user_id}`

**Permission:** `users:update`

Full update of user details.

> **Note:** This is `PUT` (full replacement), not `PATCH`. There is no `PATCH /admin/users/{user_id}` without a sub-path.

---

### `PATCH /admin/users/{user_id}/status`

**Permission:** `users:update`

Activate or deactivate a user.

**Request body:**

```json
{ "is_active": false, "locked_until": null }
```

> **Note:** Activate/deactivate is done via `PATCH /admin/users/{user_id}/status` with `{ "is_active": true/false }` — not via separate `/activate` and `/deactivate` endpoints.

---

### `PATCH /admin/users/{user_id}/role`

**Permission:** `users:update`

Change a user's role.

**Request body:** `{ "role_id": 3 }`

---

### `PATCH /admin/users/{user_id}/organization`

**Permission:** `users:update` (superadmin only in practice)

Move a user to a different organization.

**Request body:** `{ "organization_id": "org_acme_corp" }`

---

### `DELETE /admin/users/{user_id}`

**Permission:** `users:delete`

Soft-delete.

---

### `DELETE /admin/users/{user_id}/purge`

**Permission:** `users:delete`

Permanent deletion (only for soft-deleted users).

---

### `POST /admin/users/{user_id}/restore`

**Permission:** `users:update`

Restore a soft-deleted user.

---

### `POST /admin/users/{user_id}/reset-password`

**Permission:** `users:update`

Admin-initiated password reset modal with session revocation.

---

### `POST /admin/users/{user_id}/reset-mfa`

**Permission:** `users:update`

Admin action to reset/disable MFA configuration for a user.

---

## 12. Admin — Roles (`/admin/roles`)

**Permission:** `roles:read`

### `GET /admin/roles`

List all roles.

### `GET /admin/roles/{role_id}/permissions`

Full permission list for a specific role.

---

## 13. Admin — Organizations (`/admin/organizations`)

**Permission:** `organizations:read` (minimum; only `superadmin` has this by default)

### `GET /admin/organizations`

List all organizations.

### `POST /admin/organizations`

**Permission:** `organizations:create`

Create a new organization.

### `PUT /admin/organizations/{org_id}`

**Permission:** `organizations:update`

Full update of organization (name, plan, quotas, settings).

### `PATCH /admin/organizations/{org_id}/status`

**Permission:** `organizations:update`

Activate or deactivate an organization.

**Request body:** `{ "is_active": false }`

Deactivation immediately blocks all member logins and refresh token operations.

> **Note:** Activate/deactivate is done via `PATCH /admin/organizations/{org_id}/status` — not via separate `/activate` and `/deactivate` endpoints.

### `DELETE /admin/organizations/{org_id}`

**Permission:** `organizations:delete`

Delete organization (and all cascaded data).

---

## 14. Admin — Audit Logs (`/admin/audit-logs`)

**Permission:** `audit:read`

### `GET /admin/audit-logs`

**Query params:** `skip`, `limit`, `org_id`, `user_id`, `action`, `resource_type`, `status`, `from_date`, `to_date`.

**Response:** `{ "total": N, "logs": [...] }`

---

## 14b. Admin — NVD Catalog Sync (`/api/v1/admin`)

Live synchronisation of the NVD 2.0 vulnerability catalog into the `vuln_intel`
database. Both endpoints require `superadmin` or `org_admin`; anything else is
rejected with `403 Admin privileges required to manage NVD catalog sync.`

### `POST /api/v1/admin/sync-nvd`

Triggers a catalog sync. The work runs as a FastAPI background task, so the call
returns immediately rather than blocking for the duration of the pull.

**Query params:** `days_back` (default `90`, range `1`–`3650`) — how far back to
pull CVE modifications.

**Response — started:**

```json
{
  "success": true,
  "status": "STARTED",
  "message": "NVD 2.0 vulnerability catalog sync initiated for past 90 days.",
  "triggered_by": "admin@example.com"
}
```

**Response — already running:** a second call while a sync is in flight does not
queue another; it returns `status: "SYNCING"` with the current progress in
`details`.

### `GET /api/v1/admin/nvd-sync-status`

**Response:** `{ "success": true, "data": { ... } }` where `data` carries sync
state, the last sync timestamp, and the total CVE count held in `vuln_intel`.

---

## 15. User Profile (`/user`)

### `GET /user/profile`

**Auth:** Bearer. Current user's profile.

### `PUT /user/profile`

**Auth:** Bearer. Update `full_name`, `avatar_url`.

### `POST /user/change-password`

**Auth:** Bearer.

**Request body:** `{ "current_password": "Old@123", "new_password": "New@456" }`

> **Note:** Password change is at `/user/change-password` — not `/auth/change-password`.

---

### `GET /user/preferences`

**Auth:** Bearer. Returns user preferences (theme, default_scan_type, alert flags, timezone, rows_per_page).

### `PUT /user/preferences`

**Auth:** Bearer. Update user preferences.

---

### `GET /user/sessions`

**Auth:** Bearer. List active refresh token sessions (device/IP/expiry).

### `DELETE /user/sessions/{session_id}`

**Auth:** Bearer. Revoke a specific session by its ID.

> **Note:** There is no `DELETE /user/sessions` (delete all) endpoint. Only individual session deletion via `/{session_id}` is supported.

---

## 16. Notifications (`/notifications`)

### `GET /notifications/summary`

**Auth:** Bearer. Unread notification count by category.

### `GET /notifications/stream`

**Auth:** Bearer. SSE stream of new notification events. Also emits `heartbeat` events.

### `PATCH /notifications/{notification_id}/read`

**Auth:** Bearer. Mark a single notification as read.

### `PATCH /notifications/read-all`

**Auth:** Bearer. Mark all notifications as read.

### `DELETE /notifications/{notification_id}`

**Auth:** Bearer. Delete a single notification.

> **Note:** There is no `DELETE /notifications` (delete all) endpoint. Only individual deletion via `/{notification_id}` is supported.

---

## 17. Web Application Scans (`/web-scans`)

All endpoints are in `routers/web_scans.py` (prefix `/web-scans`).

### `POST /web-scans`

**Permission:** `scans:execute` | **Status:** 201 Created

Create and queue a new DAST scan.

**Request body:**

```json
{
  "target_url": "https://example.com",
  "scan_name": "Example Corp DAST",
  "scan_scope": {
    "include_subdomains": false,
    "exclude_paths": ["/logout"],
    "max_depth": 5
  },
  "auth": {
    "type": "none"
  },
  "options": {
    "enable_sqli": true,
    "enable_xss": true,
    "nuclei_severity": ["medium", "high", "critical"],
    "rate_limit": 10
  },
  "authorization_confirmed": true
}
```

`authorization_confirmed: true` is **required** — returns `HTTP 403` if false or missing.

`auth.type` values: `none`, `form_login`, `bearer_token`, `cookie`, `custom_header`

**Response `201`:** `{ "scan_id": "wsc_defa_...", "status": "queued", ... }`

---

### `GET /web-scans`

**Permission:** `scans:read`

List web scans for the organization. Supports `?org_id=` (superadmin), `?scope=`, `?skip=`, `?limit=`.

---

### `GET /web-scans/{scan_id}`

**Permission:** `scans:read`

Full web scan detail including per-phase status, stats, WAF detected, tech stack.

### `GET /web-scans/{scan_id}/findings`

**Permission:** `scans:read`

DAST findings. Query: `severity`, `finding_type`, `status`, `detected_by`, `skip`, `limit`.

### `GET /web-scans/{scan_id}/assets`

**Permission:** `scans:read`

Discovered web endpoints (WebAssets).

### `GET /web-scans/{scan_id}/report`

**Permission:** `reports:read`

Download the web scan PDF report.

### `POST /web-scans/{scan_id}/cancel`

**Permission:** `scans:execute`

Cancel an active web scan (revokes Celery task chain).

> **Note:** The real path uses `/cancel` — not `/stop` as was previously documented.

### `PATCH /web-scans/{scan_id}/findings/{finding_id}`

**Permission:** `findings:update`

Triage a web finding.

### `WEBSOCKET /web-scans/{scan_id}/progress`

**Auth:** `?ticket=<ticket_jwt>` (from `POST /auth/ticket`)

Real-time DAST pipeline progress.

---

## 18. Policy Compliance (`/compliance`)

**Permission required:** `compliance:read` (minimum)

All endpoints are in `routers/compliance.py` (prefix `/compliance`).

### `GET /compliance/marketplace`

**Permission:** `compliance:read`
Lists all global and tenant-custom frameworks in the catalog, indicating whether they are currently installed/enabled for the organization.

**Response `200`:**

```json
[
  {
    "id": "cfw_iso27001_2022",
    "code": "ISO27001_2022",
    "name": "ISO/IEC 27001:2022",
    "version": "1.0",
    "is_installed": true,
    "installed_at": "2026-06-01T12:00:00Z"
  }
]
```

---

### `POST /compliance/marketplace/{id}/install`

**Permission:** `compliance:manage_frameworks`
Installs a framework from the marketplace for the user's organization.

**Response `200`:** `{ "success": true, "installed_framework_id": "cfw_iso27001_2022" }`

---

### `POST /compliance/marketplace/{id}/uninstall`

**Permission:** `compliance:manage_frameworks`
Uninstalls a framework from the organization (deletes tenant-specific policy configurations and scores).

**Response `200`:** `{ "success": true, "uninstalled_framework_id": "cfw_iso27001_2022" }`

---

### `GET /compliance/policies`

**Permission:** `compliance:read`
Lists active policy baselines configured for the organization.

**Query params:** `framework_id` (string, required)

**Response `200`:**

```json
[
  {
    "id": "cpl_defa_iso27001_2022_baseline",
    "name": "ISO 27001:2022 Baseline Policy",
    "target_platform": "any",
    "is_active": true
  }
]
```

---

### `POST /compliance/policies`

**Permission:** `compliance:manage_rules`
Creates a custom tenant-specific policy baseline profile.

**Request body:**

```json
{
  "framework_id": "cfw_iso27001_2022",
  "name": "Acme Custom Security Policy",
  "target_platform": "linux",
  "description": "Baseline checks for Linux environments",
  "rules_selection": ["r_smb_disable_v1", "r_ssh_disable_weak_ciphers"]
}
```

---

### `GET /compliance/policies/{id}/rules`

**Permission:** `compliance:read`
Lists rule check definitions mapped to a policy baseline.

**Response `200`:**

```json
[
  {
    "id": "r_smb_disable_v1",
    "rule_family_code": "CONFIG-SMBV1",
    "version_number": 1,
    "check_type": "port_state",
    "severity": "high",
    "check_definition": {
      "port": 445,
      "operator": "equals",
      "expected": "closed"
    }
  }
]
```

---

### `PUT /compliance/rules/{id}`

**Permission:** `compliance:manage_rules`
Modifies the check parameters, severity, or active state of a custom tenant rule.

**Request body:**

```json
{
  "severity": "critical",
  "check_definition": {
    "port": 445,
    "operator": "equals",
    "expected": "closed"
  }
}
```

---

### `POST /compliance/scans`

**Permission:** `compliance:scan`
Queues a compliance scan run for a framework baseline policy as a background Celery task.

**Request body:**

```json
{
  "framework_id": "cfw_iso27001_2022",
  "policy_id": "cpl_defa_iso27001_2022_baseline",
  "scope": {
    "asset_ids": ["ast_king_192.168.1.10"],
    "asset_tags": []
  }
}
```

**Response `202` Accepted:**

```json
{
  "success": true,
  "scan_run_id": "csr_king_9a8b7c6d",
  "status": "queued"
}
```

---

### `GET /compliance/findings`

**Permission:** `compliance:read`
Lists current compliance findings verdicts.

**Query params:** `framework_id` (required), `status`, `theme`, `control_id`, `asset_id`, `skip`, `limit`

**Response `200`:**

```json
{
  "total": 1,
  "findings": [
    {
      "id": "cfnd_king_192.168.1.10_8.24_r_smbv1",
      "asset_id": "ast_king_192.168.1.10",
      "control_id": "cct_iso27001_2022_8.24",
      "rule_id": "r_smb_disable_v1",
      "status": "fail",
      "source": "auto_scan",
      "evidence": {
        "port": 445,
        "status": "open",
        "message": "SMBv1 is active"
      }
    }
  ]
}
```

---

---

### `GET /compliance/summary`

**Permission:** `compliance:read`

Returns aggregate compliance dashboard posture summary metrics.

---

### `POST /compliance/marketplace/{framework_id}/install`

**Permission:** `compliance:manage_frameworks`

Installs a compliance framework catalog for the tenant.

---

### `POST /compliance/marketplace/{framework_id}/uninstall`

**Permission:** `compliance:manage_frameworks`

Uninstalls a compliance framework catalog for the tenant.

---

### `POST /compliance/controls/{control_id}/attest`

**Permission:** `compliance:attest`
Uploads files and records manual compliance attestation status for controls requiring manual audit validation.

**Body:** `multipart/form-data` with fields `status` (pass/fail), `note` (text), and optional `files` (attachments).

---

### `GET /compliance/credentials`

**Permission:** `compliance:manage_integrations`
Lists references (names, protocols) of stored credentials used for authenticated scans/remediations.

---

### `POST /compliance/credentials`

**Permission:** `compliance:manage_integrations`
Registers credentials, encrypting sensitive fields symmetrically using Fernet.

**Request body:**

```json
{
  "name": "SSH Production Key",
  "username": "admin",
  "auth_method": "key",
  "port": 22,
  "password": null,
  "key_content": "-----BEGIN OPENSSH PRIVATE KEY-----..."
}
```

---

### `DELETE /compliance/credentials/{id}`

**Permission:** `compliance:manage_integrations`
Removes credential reference.

---

### `POST /compliance/findings/{id}/remediate`

**Permission:** `compliance:remediate`
Maker action requesting execution of the automated remediation script on the target asset.

**Request body:**

```json
{
  "credential_id": "crd_ssh_prod_key",
  "jit_username": null,
  "jit_password": null
}
```

**Response `200`:** `{ "success": true, "request_id": "crrq_king_...", "status": "pending_approval" }`

---

### `GET /compliance/remediations/requests`

**Permission:** `compliance:approve_exception`
Lists the queue of pending remediation execution approval tickets (Checker queue).

---

### `POST /compliance/remediations/requests/{id}/approve`

**Permission:** `compliance:approve_exception`
Checker action to approve or reject remediation script execution.

**Request body:**

```json
{
  "approve": true,
  "rejection_reason": null
}
```

**Response `200`:** `{ "success": true, "status": "executed" }`

---

### `POST /compliance/remediations/requests/{id}/cancel`

**Permission:** `compliance:remediate`
Maker action to cancel a pending approval request.

---

### `POST /compliance/remediations/requests/{id}/rollback`

**Permission:** `compliance:remediate`
Rolls back configuration adjustments by executing rollback script scripts.

---

### `POST /compliance/findings/{id}/exception`

**Permission:** `compliance:remediate`
Waiver request submission.

**Request body:**

```json
{
  "reason": "Business critical legacy software dependency",
  "expires_at": "2026-12-31T23:59:59Z",
  "compensating_control": "Network segmentation isolation firewall rules"
}
```

---

### `PATCH /compliance/exceptions/{id}`

**Permission:** `compliance:approve_exception`
Approves or rejects exception waivers.

**Request body:** `{ "approve": true }`

---

### `GET /compliance/dashboard/summary`

**Permission:** `compliance:read`
Retrieves quadrant posture compliance scores (ORG, PPL, PHY, TECH) and trend summary metrics.

**Query params:** `framework_id` (required), `asset_id` (optional)

---

### `GET /compliance/gap-analysis`

**Permission:** `compliance:read`
Generates multi-framework compliance posture gap analysis, identifying unmapped controls and baseline posture scores across ISO 27001, NIST CSF v2.0, CERT-In 2022, and PCI-DSS v4.0.

**Query params:** `framework_id` (required), `target_framework_id` (optional)

---

### `GET /compliance/reports/soa`

**Permission:** `compliance:export_report`
Generates and downloads the Statement of Applicability (SoA) audit ledger report.

**Query params:** `framework_id` (required), `fmt` (`pdf / docx`)

---

### `GET /compliance/reports/executive`

**Permission:** `compliance:export_report`
Generates and downloads the Executive Posture Compliance report (PDF format).

**Query params:** `framework_id` (required)

---

### `GET /compliance/reports/nist_csf`

**Permission:** `compliance:export_report`
Generates and downloads the NIST Cybersecurity Framework (CSF) v2.0 6-function compliance audit report.

---

### `GET /compliance/reports/cert_in_2022`

**Permission:** `compliance:export_report`
Generates and downloads the CERT-In Cyber Security Directions (2022) & CCMP compliance audit report (PDF/Word).

---

### `GET /compliance/reports/pci_dss_v4`

**Permission:** `compliance:export_report`
Generates and downloads the PCI-DSS v4.0 Payment Card Industry compliance report with SAQ scaling and CDE scope.

---

### `GET /compliance/reports/cis_v8_1`

**Permission:** `compliance:export_report`
Generates and downloads the CIS Controls v8.1 (IG1/IG2/IG3) compliance audit report.

---

### `GET /compliance/reports/dpdp_2023`

**Permission:** `compliance:export_report`
Generates and downloads the Digital Personal Data Protection (DPDP) Act 2023 compliance report.

---

### `GET /compliance/reports/gdpr`

**Permission:** `compliance:export_report`
Generates and downloads the General Data Protection Regulation (GDPR) compliance audit report.

---

### `GET /compliance/reports/iec_62443`

**Permission:** `compliance:export_report`
Generates and downloads the IEC 62443 Industrial Security compliance report for OT/ICS environments.

---

### `GET /compliance/reports/nis2`

**Permission:** `compliance:export_report`
Generates and downloads the NIS2 Directive European cybersecurity compliance report.

---

### `GET /compliance/reports/nist_800_53_r5`

**Permission:** `compliance:export_report`
Generates and downloads the NIST SP 800-53 Rev 5 federal security controls compliance report.

---

### `GET /compliance/reports/nist_800_82`

**Permission:** `compliance:export_report`
Generates and downloads the NIST SP 800-82 Rev 3 OT/ICS security compliance report.

---

### `GET /compliance/reports/soc2_type2`

**Permission:** `compliance:export_report`
Generates and downloads the SOC 2 Type II Trust Services Criteria audit report.

---

## 19. Network Topology Map (`/topology`)

**Permission:** `assets:read`

### `GET /topology/map`

Returns hierarchical `/24` subnet-clustered network topology map nodes and links for the organization.

---

### `GET /topology/map/{scan_id}`

Returns hierarchical `/24` subnet-clustered network topology map nodes and links for a specific scan.

---

## 20. Quick Reference — Corrected Path Names

The following table summarises all 17 path/method corrections from the previous documentation version:

| Previously Documented (Wrong)                   | Correct Path/Method                                                                   |
| ----------------------------------------------- | ------------------------------------------------------------------------------------- |
| `GET /assets/tls-inventory`                     | `GET /assets/certificates`                                                            |
| `GET /assets/services-inventory`                | `GET /assets/services`                                                                |
| `GET /assets/{id}/history`                      | `GET /assets/{id}/changelog`                                                          |
| `GET /assets/{id}/vulnerabilities`              | `GET /assets/{id}/findings`                                                           |
| `POST /auth/ws-ticket`                          | `POST /auth/ticket`                                                                   |
| `POST /auth/change-password`                    | `POST /user/change-password`                                                          |
| `GET /reports/{scan_id}/download`               | `GET /reports/download/{scan_id}`                                                     |
| `POST /reports/generate`                        | **Does not exist** — PDFs auto-generate on download                                   |
| `DELETE /notifications` (bulk delete)           | **Does not exist** — only `DELETE /notifications/{id}`                                |
| `DELETE /user/sessions` (bulk)                  | **Does not exist** — only `DELETE /user/sessions/{session_id}`                        |
| `POST /admin/organizations/{id}/activate`       | `PATCH /admin/organizations/{id}/status` with `{"is_active": true}`                   |
| `POST /admin/organizations/{id}/deactivate`     | `PATCH /admin/organizations/{id}/status` with `{"is_active": false}`                  |
| `POST /admin/users/{id}/activate`               | `PATCH /admin/users/{id}/status` with `{"is_active": true}`                           |
| `POST /admin/users/{id}/deactivate`             | `PATCH /admin/users/{id}/status` with `{"is_active": false}`                          |
| `PATCH /admin/users/{id}` (general update)      | `PUT /admin/users/{id}` (full replacement only, no general PATCH)                     |
| `PATCH /findings/{id}` (single endpoint)        | `PATCH /findings/{id}/status` + `PATCH /findings/{id}/notes` (two separate endpoints) |
| `GET /admin/users/deleted` (dedicated endpoint) | Filtered via `GET /admin/users?is_deleted=true`                                       |

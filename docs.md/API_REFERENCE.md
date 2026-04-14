# CCure Audit PRO — API Reference

**Version:** 2.2.0  
**Base URL:** `http://localhost:8000`  
**Auth:** All endpoints (except `/auth/register` and `/auth/login`) require `Authorization: Bearer <access_token>`

---

## Authentication Endpoints

### POST /auth/register
Create a new user account. Returns tokens immediately — no separate login required.

**Request Body:**
```json
{
  "username": "analyst01",
  "email": "analyst@example.com",
  "password": "SecurePass123"
}
```

| Field      | Type   | Constraints                    |
|------------|--------|--------------------------------|
| `username` | string | Min length: 3 characters        |
| `email`    | string | Valid email format              |
| `password` | string | Min length: 6 characters        |

**Response `201`:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "analyst01",
    "email": "analyst@example.com",
    "created_at": "2024-01-15T10:00:00"
  }
}
```
The refresh token is set as an `HttpOnly` cookie (`ccure_refresh_token`).

**Errors:** `409` — Email or username already taken.

---

### POST /auth/login
Authenticate with email and password.

**Request Body:**
```json
{
  "email": "analyst@example.com",
  "password": "SecurePass123"
}
```

**Response `200`:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "analyst01",
    "email": "analyst@example.com",
    "created_at": "2024-01-15T10:00:00"
  }
}
```
**Errors:** `401` — Invalid email or password.

---

### POST /auth/logout
Revoke the refresh token server-side and clear the refresh cookie.

**Request Body (optional):**
```json
{ "refresh_token": "..." }
```
If not provided in the body, the cookie is used.

**Response `200`:**
```json
{ "detail": "Logged out successfully." }
```

---

### GET /auth/me
Return the currently authenticated user's profile.

**Response `200`:**
```json
{
  "id": 1,
  "username": "analyst01",
  "email": "analyst@example.com",
  "created_at": "2024-01-15T10:00:00"
}
```

---

### POST /auth/refresh
Rotate the refresh token and issue a new access token. The old refresh token is revoked.

**Request Body (optional):**
```json
{ "refresh_token": "..." }
```
Cookie is used if body is absent.

**Response `200`:**
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```
A new refresh cookie is set in the response.

---

## Phase-Selective Scan Endpoints

These are the primary endpoints used by the frontend in all scan workflows.

---

### POST /scan/host-discovery
**Phase 1 — Host Discovery**

Discovers live hosts in the specified targets. Always the first call in any scan pipeline.

**Request Body:**
```json
{
  "targets": ["192.168.1.0/24"],
  "scan_type": "adaptive",
  "pipeline_mode": "advanced",
  "phases": [1, 2, 3, 4]
}
```

| Field           | Type         | Required | Default    | Description                              |
|-----------------|--------------|----------|------------|------------------------------------------|
| `targets`       | string[]     | Yes      | —          | IPs, CIDR ranges, or dash-ranges         |
| `scan_type`     | string       | No       | `adaptive` | `ping\|arp\|tcp\|full\|adaptive\|stealth`|
| `pipeline_mode` | string       | No       | `basic`    | `basic\|asset\|advanced`                 |
| `phases`        | int[]        | No       | `null`     | Informational — echoed in response       |

**Target formats accepted:**
- Single IP: `"192.168.1.10"`
- CIDR subnet: `"192.168.1.0/24"`
- Dash range: `"192.168.1.1-50"`
- Multiple targets: `["192.168.1.0/24", "10.0.0.5"]`

**Response `200`:**
```json
{
  "success": true,
  "scan_id": 42,
  "pipeline_mode": "advanced",
  "terminal_phase": 3,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "status": "Active",
      "scan_method": "ADAPTIVE",
      "discovery_method": "ADAPTIVE",
      "hostname": "server01.local",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "vendor": "Dell Inc.",
      "response_time_ms": 1.3,
      "os_guess": "Linux",
      "os_confidence": "Medium",
      "confidence": "High",
      "scan_timestamp": "2024-01-15T10:05:00"
    }
  ],
  "summary": {
    "total_hosts": 254,
    "active_hosts": 45,
    "inactive_hosts": 209,
    "scan_duration": 28.4,
    "phase": 1,
    "scan_type": "ADAPTIVE",
    "discovery_scan_method": "ADAPTIVE"
  },
  "metadata": {
    "target": "192.168.1.0/24",
    "original_targets": ["192.168.1.0/24"],
    "scan_method": "ADAPTIVE",
    "discovery_scan_method": "ADAPTIVE"
  }
}
```

**Pipeline mode DB behaviour:**
- `basic` → scan created and immediately marked `status="complete"`
- `asset` / `advanced` → scan created with `status="running"`; subsequent phase calls close it

---

### POST /scan/asset-discovery
**Phase 2 — Port Scanning**

Port scans all active hosts from Phase 1. Requires the Phase 1 `data` array and the same `scan_id` and `pipeline_mode`.

**Validation:** Rejected with `400` if `pipeline_mode="basic"` (Phase 2 is not part of the basic pipeline).

**Request Body:**
```json
{
  "hosts": [ /* Phase 1 data array */ ],
  "intensity": "normal",
  "scan_id": 42,
  "pipeline_mode": "advanced",
  "phases": [1, 2, 3, 4]
}
```

| Field           | Type    | Required | Default  | Description                          |
|-----------------|---------|----------|----------|--------------------------------------|
| `hosts`         | dict[]  | Yes      | —        | Host dicts from Phase 1 response     |
| `intensity`     | string  | No       | `normal` | `light\|normal\|deep`                |
| `scan_id`       | int     | No       | `null`   | From Phase 1 response — links phases |
| `pipeline_mode` | string  | No       | `asset`  | Must match Phase 1 pipeline_mode     |

**Response `200`:**
```json
{
  "success": true,
  "scan_id": 42,
  "pipeline_mode": "advanced",
  "terminal_phase": 3,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "open_ports": [
        {
          "port": 22,
          "service": "ssh",
          "state": "open",
          "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
          "version": "8.2p1",
          "risk": "Medium"
        },
        {
          "port": 80,
          "service": "http",
          "state": "open",
          "banner": "Apache httpd 2.4.41",
          "risk": "Medium"
        }
      ],
      "udp_services": [
        {"port": 161, "service": "snmp", "risk": "High", "state": "open"}
      ]
    }
  ],
  "summary": {
    "total_hosts": 45,
    "active_hosts": 45,
    "inactive_hosts": 0,
    "hosts_with_ports": 38,
    "scan_duration": 12.1,
    "phase": 2,
    "scan_type": "NORMAL",
    "discovery_scan_method": "ADAPTIVE"
  }
}
```

---

### POST /scan/advanced-scan
**Phase 3 — Vulnerability Audit + Risk Scoring**

Runs all vulnerability plugins against hosts with open ports. Only valid for `pipeline_mode="advanced"`.

**Validation:** Rejected with `400` if `pipeline_mode` is `basic` or `asset`.

**Request Body:**
```json
{
  "hosts": [ /* Phase 2 data array */ ],
  "scan_id": 42,
  "pipeline_mode": "advanced",
  "phases": [1, 2, 3, 4]
}
```

**Response `200`:**
```json
{
  "success": true,
  "scan_id": 42,
  "pipeline_mode": "advanced",
  "terminal_phase": 3,
  "data": [
    {
      "ip_address": "192.168.1.10",
      "is_active": true,
      "open_ports": [...],
      "tls_info": {
        "enabled": true,
        "version": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
        "cert_subject": "CN=example.com",
        "cert_issuer": "CN=Let's Encrypt...",
        "cert_expiry": "2025-03-15",
        "cert_expired": false,
        "cert_self_signed": false,
        "weak_cipher": false,
        "score": "A"
      },
      "http_audit": {
        "status_code": 200,
        "server_header": "Apache/2.4.41",
        "hsts": true,
        "x_frame": "DENY",
        "csp": false,
        "issues": ["Missing Content-Security-Policy", "X-XSS-Protection not set"]
      },
      "ssh_info": {
        "banner": "SSH-2.0-OpenSSH_8.2p1",
        "version": "8.2p1"
      },
      "smb_info": {
        "open": false
      },
      "cves": [
        {
          "cve_id": "CVE-2023-38408",
          "severity": "Critical",
          "cvss_score": 9.8,
          "description": "...",
          "cve": "CVE-2023-38408",
          "cvss": 9.8
        }
      ],
      "host_risk_score": 72,
      "host_risk_level": "High"
    }
  ],
  "summary": {
    "total_hosts": 45,
    "active_hosts": 45,
    "critical_hosts": 3,
    "high_risk_hosts": 12,
    "scan_duration": 87.3,
    "phase": 3,
    "scan_type": "advanced"
  },
  "reports": {
    "json_pdf": "reports/scan_42_json.pdf",
    "xml_pdf": "reports/scan_42_xml.pdf"
  }
}
```

Always marks the scan `status="complete"` in the database.

---

### POST /scan/credentialed
**SSH Credentialed Scan — Linux and Windows**

Authenticates via SSH to a single target and performs deep system-level collection and package-based CVE matching.

**Security note:** Credentials are used only for the SSH session duration. They are never written to any database, log, or file.

**Availability check:** Requires `paramiko` to be installed. Returns `503` if unavailable.

**Request Body:**
```json
{
  "ip": "192.168.1.10",
  "username": "admin",
  "password": "secret",
  "key_path": null,
  "port": 22,
  "auth_method": "password",
  "sections": null,
  "os_type": "auto"
}
```

| Field         | Type     | Required | Default      | Description                               |
|---------------|----------|----------|--------------|-------------------------------------------|
| `ip`          | string   | Yes      | —            | Target IP address                         |
| `username`    | string   | Yes      | —            | SSH username                              |
| `password`    | string   | No       | `null`       | Password (used when auth_method=password) |
| `key_path`    | string   | No       | `null`       | Path to private key file (auth_method=key)|
| `port`        | int      | No       | `22`         | SSH port (1–65535)                        |
| `auth_method` | string   | No       | `"password"` | `password` or `key`                       |
| `sections`    | string[] | No       | `null`       | Subset of sections to collect (null = all)|
| `os_type`     | string   | No       | `"auto"`     | `linux`, `windows`, or `auto`             |

**Available `sections`:** `system_info`, `packages`, `services`, `ports`, `users`, `security`, `network`, `history`

**Pre-flight checks:**
1. TCP connectivity to `ip:port` with 5-second timeout
2. OS detection via `uname -s` (Linux) or `cmd /c ver` (Windows)

**Response `200`:**
```json
{
  "success": true,
  "scan_id": 43,
  "username": "admin",
  "scan_type": "credentialed",
  "target": "192.168.1.10",
  "detected_os": "linux",
  "system_info": {
    "os_name": "Ubuntu",
    "os_version_id": "20.04",
    "kernel_version": "5.4.0-150-generic",
    "hostname": "server01.company.local",
    "uptime": "up 47 days",
    "cpu_model": "Intel(R) Xeon(R) CPU E5-2620",
    "cpu_count": "8",
    "cpu_arch": "x86_64",
    "memory_summary": {},
    "disk_usage": []
  },
  "packages": [
    {"name": "openssh-server", "version": "1:8.2p1-4ubuntu0.5"}
  ],
  "package_count": 342,
  "running_services": ["sshd", "nginx", "postgresql"],
  "open_ports_credentialed": [22, 80, 443, 5432],
  "users": ["root", "www-data", "postgres"],
  "suid_binaries": ["/usr/bin/passwd", "/usr/bin/sudo"],
  "world_writable_dirs": ["/tmp", "/var/tmp"],
  "sudo_nopasswd": false,
  "sudo_rules_raw": "...",
  "security_issues": ["SUID binary found: /usr/bin/crontab"],
  "failed_login_count": 127,
  "brute_force_warning": true,
  "cves": [
    {
      "cve_id": "CVE-2023-38408",
      "severity": "Critical",
      "cvss_score": 9.8,
      "package": "openssh-server",
      "installed_ver": "8.2p1",
      "fixed_ver": "9.3p2",
      "source": "package_version_match"
    }
  ],
  "cve_count": 14,
  "severity_summary": {
    "Critical": 1,
    "High": 4,
    "Medium": 7,
    "Low": 2,
    "Info": 0
  },
  "scan_duration": 18.6
}
```

---

## Scan History Endpoints

### GET /scans
List scan history for the authenticated user.

**Query Parameters:**

| Param   | Type   | Default  | Options                                |
|---------|--------|----------|----------------------------------------|
| `skip`  | int    | `0`      | Pagination offset                      |
| `limit` | int    | `50`     | Max 200                                |
| `scope` | string | `active` | `active`, `archived`, `deleted`, `all` |

**Response `200`:**
```json
{
  "scope": "active",
  "total": 12,
  "scans": [
    {
      "id": 42,
      "target": "192.168.1.0/24",
      "targets": ["192.168.1.0/24"],
      "scan_type": "adaptive",
      "phase": 3,
      "status": "complete",
      "pipeline_mode": "advanced",
      "scan_duration": 127.6,
      "created_at": "2024-01-15T10:00:00Z",
      "updated_at": "2024-01-15T10:02:07Z",
      "is_archived": false,
      "archived_at": null,
      "is_deleted": false,
      "deleted_at": null,
      "has_json_report": true,
      "has_xml_report": true,
      "summary": { ... }
    }
  ]
}
```

---

### GET /scans/{scan_id}
Full detail of one scan including all phase results.

**Response `200`:**
```json
{
  "id": 42,
  "target": "192.168.1.0/24",
  "status": "complete",
  "pipeline_mode": "advanced",
  "results": {
    "phase1": { "data": [...], "summary": {...} },
    "phase2": { "data": [...], "summary": {...} },
    "phase3": { "data": [...], "summary": {...} }
  },
  "summary": { ... }
}
```

---

### POST /scans/{scan_id}/archive
Move scan to the Archived Scans section.

**Response `200`:**
```json
{ "detail": "Scan 42 archived", "archived": true }
```

---

### POST /scans/{scan_id}/restore
Restore scan from Archived Scans or Recycle Bin back to active.

**Response `200`:**
```json
{ "detail": "Scan 42 restored to My Scan Jobs", "restored": true, "destination": "active" }
```

---

### DELETE /scans/{scan_id}
Move scan to Recycle Bin (soft delete).

**Response `200`:**
```json
{ "detail": "Scan 42 moved to recycle bin", "moved_to_recycle_bin": true }
```

---

### DELETE /scans/{scan_id}/purge
Permanently delete a scan that is already in the Recycle Bin.

**Precondition:** Scan must be in `is_deleted=true` state (i.e., already in Recycle Bin). Returns `400` otherwise.

**Response `200`:**
```json
{ "detail": "Scan 42 permanently deleted" }
```

---

## Report Download

### GET /reports/download/{scan_id}
Download the PDF report for a completed scan.

**Query Parameters:**

| Param   | Type   | Default | Options       |
|---------|--------|---------|---------------|
| `fmt`   | string | `JSON`  | `JSON`, `XML` |
| `token` | string | —       | Access token (alternative to Authorization header for browser download links) |

**Response:** Binary PDF file with `Content-Disposition: attachment`.

**Errors:**
- `404` — Scan not found or no report generated for this format
- `400` — Invalid `fmt` value

---

## Progress Tracking

### GET /scan/progress/{scan_id}
Poll real-time progress of an in-progress scan. Intended for large subnet scans.

**Response `200`:**
```json
{
  "total_ips": 254,
  "discovered": 128,
  "active": 42,
  "status": "running",
  "elapsed_time": 15.3,
  "percentage": 50.4
}
```

Returns `{ "status": "not_found" }` if the scan has completed and progress data has been cleared.

---

## Traditional Scan Endpoints (Backward Compatible)

These endpoints run the full pipeline in a single call and are not used by the dashboard UI. Retained for CLI and API client compatibility.

### POST /scan/host
Run all phases against a single host.

```json
{ "target": "192.168.1.10", "scan_type": "adaptive" }
```

---

### POST /scan/range
Discovery scan across a dash-range of IPs.

```json
{ "target": "192.168.1.1-50", "scan_type": "adaptive" }
```

---

### POST /scan/subnet
Discovery scan across a CIDR subnet.

```json
{ "target": "192.168.1.0/24", "scan_type": "adaptive" }
```

---

### POST /scan/subnets
Discovery scan across sub-networks of a parent CIDR.

```json
{
  "target": "10.0.0.0/16",
  "subnet_prefix": 24,
  "scan_type": "adaptive"
}
```
Maximum 64 sub-networks per call.

---

### POST /scan/phases
Flexible phase combinator — runs any combination of phases in a single call.

```json
{
  "targets": ["192.168.1.0/24"],
  "phases": "1+2+3+4",
  "scan_type": "adaptive",
  "intensity": "normal"
}
```

`phases` values: `"1"`, `"1+2"`, `"1+2+3+4"` (Phase 1 is always run as a prerequisite)

---

## Documentation Endpoints

### GET /api/pipeline-modes
Returns all valid pipeline modes and their phase sequences. Useful for frontend validation.

### GET /api/workflow-example
Returns a workflow description for the phase-selective orchestration model.

### GET /
Health and system info endpoint. Returns scanner status, available tools, and platform info.

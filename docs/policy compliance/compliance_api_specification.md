# CCure Audit PRO — Compliance Engine API Specification

This document details the REST API contract specifications for the Policy Compliance Engine. All endpoints adhere to standard platform conventions, utilizing Bearer JWT authorization and returning consistent JSON models.

---

## 1. Global API Error Response Structure

All compliance routers return structured JSON error payloads on non-2xx failures:

```json
{
  "error": "VALIDATION_ERROR | PERMISSION_DENIED | RESOURCE_NOT_FOUND | RATE_LIMIT_EXCEEDED | INTERNAL_SERVER_ERROR",
  "message": "Human readable error detail text.",
  "details": [{ "field": "policy_id", "issue": "Field is required" }],
  "request_id": "req_8a9b2c"
}
```

---

## 2. API Endpoint Contracts

### 2.1. Framework Marketplace & Installation

#### GET `/api/compliance/marketplace`

- **Purpose**: List all globally cataloged compliance frameworks with installation status.
- **Auth**: Bearer JWT (`compliance:read`)
- **Request**:
  - Query parameters: None.
- **Response 200 OK**:
  ```json
  {
    "data": [
      {
        "framework_id": "cfw_iso27001_2022",
        "name": "ISO/IEC 27001:2022",
        "code": "ISO27001_2022",
        "version": "2022",
        "is_installed": true,
        "controls_count": 93
      }
    ]
  }
  ```

#### POST `/api/compliance/marketplace/{framework_id}/install`

- **Purpose**: Install a framework from the marketplace into the tenant catalog.
- **Auth**: Bearer JWT (`compliance:manage_frameworks` - Admin role required)
- **Response 201 Created**:
  ```json
  {
    "data": {
      "framework_id": "cfw_iso27001_2022",
      "installed_at": "2026-07-04T02:00:00Z",
      "installed_by": "usr_defa_pankaj_x9v1"
    }
  }
  ```
- **Side Effects**: Creates a new record in the `compliance_tenant_frameworks` table.
- **Security Notes**: This write action is restricted to Tenant Administrators.

---

### 2.2. Policy Management

#### POST `/api/compliance/policies`

- **Purpose**: Create version 1 of a tenant baseline policy.
- **Auth**: Bearer JWT (`compliance:manage_rules`)
- **Request Body (JSON)**:
  ```json
  {
    "framework_id": "cfw_iso27001_2022",
    "name": "Windows Server Hardening Baseline",
    "target_platform": "windows",
    "rule_ids": ["crl_auth_mfa_001_v1", "crl_sys_log_002_v1"],
    "tags": ["OT", "Production"]
  }
  ```
- **Response 201 Created**:
  ```json
  {
    "data": {
      "policy_id": "cpl_win_server_baseline_v1",
      "version_number": 1,
      "status": "draft",
      "is_active": true,
      "created_at": "2026-07-04T02:05:00Z"
    }
  }
  ```

#### POST `/api/compliance/policies/{id}/new-version`

- **Purpose**: Publish vN+1 of a policy, setting the old version status to `archived`.
- **Auth**: Bearer JWT (`compliance:manage_rules`)
- **Response 201 Created**: Returns the new policy ID representation with incremented `version_number`.

---

### 2.3. Scans & Scheduling

#### POST `/api/compliance/scans`

- **Purpose**: Trigger an immediate compliance scanning run against a scoped set of assets.
- **Auth**: Bearer JWT (`compliance:scan`)
- **Request Body (JSON)**:
  ```json
  {
    "framework_id": "cfw_iso27001_2022",
    "policy_id": "cpl_win_server_baseline_v1",
    "scope": {
      "asset_ids": ["ast_defa_192_168_1_5"],
      "asset_tags": []
    }
  }
  ```
- **Response 202 Accepted**:
  ```json
  {
    "data": {
      "scan_run_id": "csr_org1_07may26_1a2b",
      "status": "queued",
      "queued_at": "2026-07-04T02:10:00Z"
    }
  }
  ```
- **Side Effects**: Writes a record in `compliance_scan_runs` and pushes a job to the `compliance` queue.

---

### 2.4. Control Attestation & Remediation

#### POST `/api/compliance/controls/{id}/attest`

- **Purpose**: Submit manual attestation checklist notes and document evidence.
- **Auth**: Bearer JWT (`compliance:attest`)
- **Request Body (JSON)**:
  ```json
  {
    "status": "pass",
    "note": "Uploaded approved Information Security Policy document.",
    "evidence_file_ids": ["file_a1b2_pdf"]
  }
  ```
- **Response 200 OK**: Returns the updated `compliance_findings` state.
- **Side Effects**: Appends audit trail entry into `compliance_finding_history`.

#### POST `/api/compliance/findings/{id}/remediate`

- **Purpose**: Execute a remediation script or mark a finding as fixed.
- **Auth**: Bearer JWT (`compliance:remediate`)
- **Request Body (JSON)**:
  ```json
  {
    "action": "apply_script"
  }
  ```
- **Response 200 OK**:
  ```json
  {
    "data": {
      "finding_id": "cfnd_org1_ast123_8_24_1a2b",
      "new_status": "remediation_applied",
      "remediation_applied_at": "2026-07-04T02:15:00Z"
    }
  }
  ```
- **Security Notes**: Script actions check that a matching approved exception waiver exists for authorization (Maker-Checker).

---

### 2.5. Exceptions & Dashboard Summary

#### POST `/api/compliance/findings/{id}/exception`

- **Purpose**: Create a temporary exception waiver request for a failing control.
- **Auth**: Bearer JWT (`compliance:attest`)
- **Request Body (JSON)**:
  ```json
  {
    "reason": "Legacy application fails cipher suite enforcement. Isolated on segregated VLAN.",
    "compensating_control": "Firewall block rules configured on gateway.",
    "expires_at": "2027-07-04T00:00:00Z"
  }
  ```
- **Response 201 Created**: Returns the exception ID and status set to `pending`.

#### PATCH `/api/compliance/exceptions/{id}`

- **Purpose**: Approve or reject a pending waiver request.
- **Auth**: Bearer JWT (`compliance:approve_exception` - Compliance Officer / CISO role required)
- **Request Body (JSON)**:
  ```json
  {
    "status": "approved"
  }
  ```
- **Response 200 OK**: Returns exception waiver details.
- **Side Effects**: Moves finding status to `exception`, records the history log, and recalculates compliance scores.

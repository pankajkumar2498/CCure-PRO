# CCure Audit PRO — Evidence Provider Layer (EPL) Specification

The Evidence Provider Layer (EPL) acts as a read-only translation adapter. It maps native scan findings into a common schema shape consumed by the Compliance Rule Engine.

---

## 1. Unified Evidence DTO Schema

All adapter functions map native data structures into the following common shape:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "NormalizedEvidencePayload",
  "type": "OBJECT",
  "properties": {
    "evidence_source": { "type": "STRING" },
    "asset_id": { "type": "STRING" },
    "captured_at": { "type": "STRING", "format": "date-time" },
    "payload": { "type": "OBJECT" }
  },
  "required": ["evidence_source", "asset_id", "captured_at", "payload"]
}
```

---

## 2. Adapter Specifications

### 2.1. Vulnerability Audit Adapter

- **Input Source**: SQL Table `asset_vulnerabilities` joined with `vulnerability_definitions` for a given `asset_id`.
- **Output Payload Schema**:
  ```json
  {
    "cve_ids": ["string"],
    "max_cvss_score": "number",
    "critical_severity_count": "integer",
    "unpatched_cve_max_age_days": "integer"
  }
  ```
- **Field Mapping & Transformation Logic**:
  - `cve_ids` ➔ Select array of `vuln_id` where `status = 'open'`.
  - `max_cvss_score` ➔ `MAX(cvss_score)` from active findings.
  - `unpatched_cve_max_age_days` ➔ `MAX(NOW() - first_found_at)` for open vulnerabilities.
- **Example Payload**:
  ```json
  {
    "evidence_source": "vulnerability_audit",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T01:00:00Z",
    "payload": {
      "cve_ids": ["CVE-2024-4577"],
      "max_cvss_score": 9.8,
      "critical_severity_count": 1,
      "unpatched_cve_max_age_days": 12
    }
  }
  ```

### 2.2. Malware Scan Adapter

- **Input Source**: Web scans nuclei reports or dedicated host signature matches.
- **Output Payload Schema**:
  ```json
  {
    "malware_detected": "boolean",
    "infected_files_count": "integer",
    "last_scan_duration_sec": "number"
  }
  ```
- **Field Mapping & Transformation Logic**:
  - Maps matching signature findings from nucleated scan runs. If any signature indicates active trojans/viruses, `malware_detected` is set to `true`.
- **Example Payload**:
  ```json
  {
    "evidence_source": "malware_scan",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T00:45:00Z",
    "payload": {
      "malware_detected": false,
      "infected_files_count": 0,
      "last_scan_duration_sec": 142.5
    }
  }
  ```

### 2.3. Services & Ports Adapter

- **Input Source**: SQL Table `services` for the target `asset_id`.
- **Output Payload Schema**:
  ```json
  {
    "open_ports": ["integer"],
    "insecure_ports_detected": ["integer"],
    "banners": ["string"]
  }
  ```
- **Field Mapping & Transformation Logic**:
  - `open_ports` ➔ Collect `port` numbers where `state = 'open'`.
  - `insecure_ports_detected` ➔ Cross-reference `open_ports` against a static list of insecure protocols: `[21 (FTP), 23 (Telnet), 80 (HTTP), 3389 (RDP without TLS)]`.
- **Example Payload**:
  ```json
  {
    "evidence_source": "services_ports",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T01:10:00Z",
    "payload": {
      "open_ports": [22, 80, 443],
      "insecure_ports_detected": [80],
      "banners": ["SSH-2.0-OpenSSH_8.9p1", "nginx/1.18.0"]
    }
  }
  ```

### 2.4. TLS/Certificates Adapter

- **Input Source**: SQL Table `tls_details` joined on `services`.
- **Output Payload Schema**:
  ```json
  {
    "min_tls_version": "string",
    "is_expired": "boolean",
    "self_signed": "boolean",
    "weak_cipher_in_use": "boolean",
    "grade": "string"
  }
  ```
- **Example Payload**:
  ```json
  {
    "evidence_source": "tls_certificates",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T01:10:00Z",
    "payload": {
      "min_tls_version": "TLSv1.2",
      "is_expired": false,
      "self_signed": false,
      "weak_cipher_in_use": false,
      "grade": "A"
    }
  }
  ```

### 2.5. Network Topology Adapter

- **Input Source**: SQL Table `network_links`.
- **Output Payload Schema**:
  ```json
  {
    "cross_zone_leakage_detected": "boolean",
    "connected_gateways": ["string"]
  }
  ```
- **Example Payload**:
  ```json
  {
    "evidence_source": "network_topology",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T01:15:00Z",
    "payload": {
      "cross_zone_leakage_detected": false,
      "connected_gateways": ["192.168.1.1"]
    }
  }
  ```

### 2.6. Credential Validation Adapter

- **Input Source**: Active Directory domain reads / host authentication attempts logs.
- **Output Payload Schema**:
  ```json
  {
    "mfa_enforced_pct": "number",
    "expired_passwords_count": "integer",
    "min_password_length_configured": "integer"
  }
  ```
- **Example Payload**:
  ```json
  {
    "evidence_source": "credential_validation",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T01:05:00Z",
    "payload": {
      "mfa_enforced_pct": 100.0,
      "expired_passwords_count": 0,
      "min_password_length_configured": 14
    }
  }
  ```

### 2.7. Offline Configuration Scan Adapter

- **Input Source**: Hardening baseline audit records.
- **Output Payload Schema**:
  ```json
  {
    "failed_registry_keys": ["string"],
    "hardening_score_pct": "number"
  }
  ```
- **Example Payload**:
  ```json
  {
    "evidence_source": "offline_configuration_scan",
    "asset_id": "ast_defa_1a2b3c4d_192_168_1_5",
    "captured_at": "2026-07-04T00:30:00Z",
    "payload": {
      "failed_registry_keys": [
        "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\LimitBlankPasswordUse"
      ],
      "hardening_score_pct": 92.5
    }
  }
  ```

---

## 3. Redis Caching Policies

To prevent database query storms during parallel rule evaluations, the EPL caches normalized evidence:

- **Cache Key Namespace**: `compliance:evidence:{asset_id}:{evidence_source}`
- **Time-to-Live (TTL)**: 300 seconds (5 minutes).
- **Bypass Condition**: If a rule check triggers a live scan or the user requests "Force Refresh", the cache is bypassed and refreshed.
- **Invalidation Strategy**: Whenever a new scanning run of a corresponding module completes, the worker broadcasts an invalidation signal to clear the cache key.

# CCure Audit PRO — Compliance Engine Deployment & Operations Guide

This document defines the deployment sequence, environment variables, feature flags, monitoring metrics, rollback guidelines, and logging schemas for releasing the Policy Compliance Engine.

---

## 1. Production Release Sequence

Deploy the compliance module to production in this strict sequence:

1. **Step 1: DB Schema Migration**: Run Alembic migrations to create the 18 compliance tables.
   ```bash
   alembic upgrade head
   ```
2. **Step 2: Seed Static Data**: Execute the seeding script to populate `compliance_frameworks` and the 93 `compliance_controls` for ISO 27001:2022.
   ```bash
   python -m scripts.seed_compliance --seed-file scripts/iso27001_2022_controls_seed.json
   ```
3. **Step 3: Deploy Worker & API Code**: Roll out the new backend package container images. Ensure the new `compliance` Celery queue configuration is registered.
4. **Step 4: Enable Feature Flag**: Set the feature flag to `True` in environment variables and restart API pods.

---

## 2. Feature Flag Configuration

The compliance workspace is wrapped under the `COMPLIANCE_ENGINE_ENABLED` flag.

- **Environment Variable**: `COMPLIANCE_ENGINE_ENABLED=true` (defaults to `false` in development).
- **Router Gate**:

  ```python
  from config import AppConfig
  from fastapi import HTTPException, status

  def verify_compliance_enabled():
      if not AppConfig.COMPLIANCE_ENGINE_ENABLED:
          raise HTTPException(
              status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
              detail="Compliance Engine is currently disabled by system administrators."
          )
  ```

  _(This dependency is applied to all routers inside `routers/marketplace.py`, `routers/findings.py`, etc.)_

---

## 3. Rollback Guidelines

### 3.1. Rollback Triggers

Roll back the deployment if any of the following occur:

- API container crash loops caused by database query blocks or missing ORM definitions.
- Severe queue blocking on Celery workers due to memory exhaustion during bulk checks.
- A sudden spikes in database CPU usage (>90%) that does not resolve within 5 minutes.

### 3.2. Rollback Execution

1. Set the feature flag to `false` (`COMPLIANCE_ENGINE_ENABLED=false`) and restart the API pods. This instantly hides the workspace and blocks requests.
2. In case of schema issues, perform an Alembic downgrade:
   ```bash
   alembic downgrade -1
   ```

---

## 4. Telemetry & Monitoring

### 4.1. Prometheus Metrics

The engine exports the following Prometheus telemetry counters:

| Metric Name                          | Type      | Labels                      | Description                       |
| ------------------------------------ | --------- | --------------------------- | --------------------------------- |
| `compliance_scans_triggered_total`   | Counter   | `tenant_id`, `framework_id` | Cumulative compliance scan runs.  |
| `compliance_scan_duration_seconds`   | Histogram | `tenant_id`, `framework_id` | Time spent executing scans.       |
| `compliance_rule_evaluations_total`  | Counter   | `status` (`pass`/`fail`)    | Individual check verdicts.        |
| `compliance_active_exceptions_count` | Gauge     | `tenant_id`                 | Active waivers currently granted. |

### 4.2. Structured Logging Schema

All events log as structured JSON payloads for ingestion by SIEM tools:

```json
{
  "timestamp": "2026-07-04T02:30:00.123Z",
  "level": "INFO",
  "logger": "compliance.engine",
  "event_type": "compliance.scan.completed",
  "tenant_id": "org_cdackp2_in",
  "user_id": "usr_defa_pankaj_x9v1",
  "scan_run_id": "csr_org1_07may26_1a2b",
  "framework_id": "cfw_iso27001_2022",
  "duration_seconds": 12.45,
  "findings_summary": {
    "pass": 84,
    "fail": 6,
    "manual_review": 3
  }
}
```

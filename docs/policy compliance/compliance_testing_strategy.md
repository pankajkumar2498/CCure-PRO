# CCure Audit PRO — Compliance Engine Testing Strategy

This document specifies the validation plan and testing strategy for the Policy Compliance Engine. It covers unit, integration, security, performance, and compliance-specific testing matrices.

---

## 1. Quality Gates & Coverage Targets

All code changes in the `compliance` module must satisfy the following thresholds before release:

- **Unit Test Coverage**: Minimum **80%** on services and rule parsing layers.
- **Integration Test Coverage**: Minimum **100%** on REST API routers and database operations.
- **Linting / Static Analysis**: Zero critical errors on `flake8` and `mypy` type checks.

---

## 2. Testing Matrices

### 2.1. Unit Testing

Unit tests reside in `Backend/tests/unit/compliance/` and execute with Mock DB sessions:

- **Score Calculation Validation**:
  - Test case: Verify that `simple_score_pct` matches passed/applicable ratio.
  - Test case: Verify that `weighted_score_pct` weights are applied correctly (e.g. Critical=10, Low=2). Test edge case of 0 applicable controls (must return `0.00` without ZeroDivisionError).
- **Rule Engine Operator Logic**:
  - Test case: Validate operator inputs against operator types: `equals`, `contains`, `version_gte`.
  - Test case: Mock rule check inputs to verify operator outputs on standard ciphers (e.g., `'TLSv1.3'` against version operator).
- **Pydantic Validation**:
  - Test case: Verify that invalid values in JSON body (like negative ports, malformed dates) return a `422 Unprocessable Entity` status.

### 2.2. Integration Testing

Integration tests run against a localized PostgreSQL test instance:

- **EPL Adapter Transformations**:
  - Test case: Insert dummy data into `asset_vulnerabilities` and verify that the Vulnerability Audit Adapter translates it into a correct normalized payload.
- **Celery Scan Job Execution**:
  - Test case: Dispatch a compliance scan via Celery. Verify that tasks resolve successfully on the isolated `compliance` queue.
- **Redis Cache TTL Enforcement**:
  - Test case: Request evidence for asset. Verify cache key creation. Mutate database and query again to confirm cache hit. Evict cache and confirm new database query is fired.

### 2.3. Security & RBAC Testing

- **Granular Scopes Verification**:
  - Test case: Attempt to trigger a scan using a token bearing only `compliance:read`. Verify that a `403 Forbidden` response is returned.
  - Test case: Validate that only users with the `compliance:approve_exception` scope can successfully execute the `PATCH /api/compliance/exceptions/{id}` route.
- **Maker-Checker Integrity**:
  - Test case: Attempt to execute a script-based remediation. Verify that it fails unless an active, approved waiver exists in the `compliance_exceptions` table.

### 2.4. Performance & Load Testing

- **Database Query Performance**:
  - Test case: Seed the database with 100,000 `compliance_findings` rows. Execute dashboard metric aggregation queries. Verify that queries utilize the `idx_findings_status` index and run in less than 50ms.
- **Bulk Remediation Scaling**:
  - Test case: Dispatch a bulk remediation job targeting 500 assets simultaneously. Verify that tasks fan out across workers without memory leaks or Redis connection exhaustion.

### 2.5. ISO Validation Tests

- **Seeding Integrity Verification**:
  - Test case: Run database seeding. Query `compliance_controls` to verify that exactly 93 controls exist and that they align with the themes (37 ORG, 8 PPL, 14 PHY, 34 TECH) seeded from the JSON file.
- **SoA Export Verification**:
  - Test case: Trigger a Statement of Applicability DOCX export. Verify that all 93 controls are present and map to correct compliance statuses in the output file structure.

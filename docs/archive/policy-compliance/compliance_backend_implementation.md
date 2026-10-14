# CCure Audit PRO — Compliance Engine Backend Implementation Plan

This document outlines the detailed backend module-by-module implementation plan for the Policy Compliance Engine. It maps out the package structure, DTO shapes, service class behaviors, and API controllers.

---

## 1. Package Layout & File Structure

The module is integrated into the existing FastAPI app structure as a modular package located in `Backend/compliance/`:

```
Backend/compliance/
├── __init__.py
├── models.py              # SQLAlchemy ORM models (imported by db/models/__init__.py)
├── schemas.py             # Pydantic DTOs for input validation & output serialization
├── exceptions.py          # Domain-specific exceptions
├── repositories.py        # Database operations using Repository Pattern
├── services/
│   ├── __init__.py
│   ├── framework.py       # Framework installation and marketplace services
│   ├── policy.py          # Policy creation and versioning services
│   ├── rules.py           # Rule management and parsing services
│   ├── evidence.py        # Evidence Provider Layer mapping
│   ├── engine.py          # Core Rule Evaluation Engine
│   ├── scoring.py         # Compliance score calculation engine
│   ├── remediation.py     # Remediation state machine & Recommendation engine
│   ├── exceptions.py      # Waiver / Exception workflow services
│   ├── notifications.py   # Alerting rules & Integration connector dispatchers
│   └── scheduling.py      # Scan run triggers and cron jobs
└── routers/
    ├── __init__.py
    ├── marketplace.py     # /api/compliance/marketplace
    ├── frameworks.py      # /api/compliance/frameworks
    ├── policies.py        # /api/compliance/policies
    ├── rules.py           # /api/compliance/rules
    ├── scans.py           # /api/compliance/scans
    ├── schedules.py       # /api/compliance/schedules
    ├── findings.py        # /api/compliance/findings
    ├── exceptions.py      # /api/compliance/exceptions
    └── dashboard.py       # /api/compliance/dashboard
```

---

## 2. Common Data Transfer Objects (DTOs)

Below are the key Pydantic DTO definitions implemented in `compliance/schemas.py`:

```python
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
from datetime import datetime

# --- Framework DTOs ---
class FrameworkInstallRequest(BaseModel):
    framework_id: str = Field(..., example="cfw_iso27001_2022")

# --- Policy DTOs ---
class PolicyCreate(BaseModel):
    framework_id: str
    name: str = Field(..., min_length=3, max_length=255)
    target_platform: str = Field("any", regex="^(windows|linux|network_device|cloud|database|any)$")
    description: Optional[str] = None
    rule_ids: List[str]
    tags: List[str] = []

# --- Rule Check Criteria DTO ---
class RuleCheckDefinition(BaseModel):
    path: Optional[str] = None
    operator: str = Field(..., regex="^(equals|not_equals|contains|not_contains|version_gte|version_lte|port_open)$")
    expected: Any

# --- Rule Creation DTO ---
class RuleCreate(BaseModel):
    rule_family_code: str
    check_type: str
    evidence_source: Optional[str] = None
    target_platform: str
    check_definition: RuleCheckDefinition
    severity: str = "medium"
    tags: List[str] = []

# --- Exception Waiver DTO ---
class ExceptionRequest(BaseModel):
    control_id: str
    finding_id: Optional[str] = None
    reason: str = Field(..., min_length=10)
    compensating_control: Optional[str] = None
    expires_at: datetime
```

---

## 3. Service Specifications

### 3.1. Evidence Provider Service (`EvidenceProviderService`)

- **Responsibilities**: Collect and normalize findings from active scan modules.
- **Dependencies**: `VulnerabilityRepository`, `ServiceRepository`, `TLSRepository`.
- **Public Methods**:
  - `fetch_normalized_evidence(source: str, asset_id: str, criteria: Dict[str, Any]) -> Dict[str, Any]`
    - **Inputs**: `source` (str), `asset_id` (str), `criteria` (dict)
    - **Outputs**: Normalized JSON payload representing evidence.
    - **Exceptions**: `UnsupportedEvidenceSourceError`, `StaleEvidenceError`.
    - **Validation**: Validates that the target asset exists in the Asset Registry.
    - **Caching**: Redis-cached with key `compliance:evidence:{asset_id}:{source}` (TTL: 300 seconds).
    - **Transactions**: Read-only, no transaction required.

### 3.2. Rule Evaluation Engine (`ComplianceRuleEngine`)

- **Responsibilities**: Executes check criteria against normalized evidence payloads and generates findings.
- **Dependencies**: `EvidenceProviderService`, `ComplianceFindingRepository`.
- **Public Methods**:
  - `evaluate_rule(rule_id: str, asset_id: str, run_id: str) -> EvaluationResultDTO`
    - **Inputs**: `rule_id` (str), `asset_id` (str), `run_id` (str)
    - **Outputs**: DTO containing status (pass/fail/manual_review) and raw checked values.
    - **Exceptions**: `RuleEvaluationError`, `DependencyCheckFailedError`.
    - **Validation**: Runs recursive check to ensure prerequisite rule dependencies are resolved and passed.
    - **Transactions**: Run in a read-committed block. Writes to `compliance_findings` and `compliance_finding_history` in a single transaction.

### 3.3. Scoring Engine (`ComplianceScoringEngine`)

- **Responsibilities**: Rollup calculations for simple and weighted scores.
- **Dependencies**: `ComplianceFindingRepository`, `ComplianceScoreRepository`.
- **Public Methods**:
  - `calculate_weighted_score(tenant_id: str, framework_id: str, asset_id: Optional[str] = None) -> ScoreRollupDTO`
    - **Formula**:
      $$\text{Weighted Score} = \frac{\sum_{i \in \text{Passed}} W_i}{\sum_{j \in \text{Applicable}} W_j} \times 100$$
    - **Inputs**: `tenant_id` (str), `framework_id` (str), `asset_id` (optional str)
    - **Outputs**: DTO containing score percentages and counts.
    - **Caching**: Cached in Redis with key `compliance:scores:{tenant_id}:{framework_id}:{asset_id}`. Invalidated immediately upon finding status changes.
    - **Transactions**: Writes results to `compliance_scores` using an UPSERT command.

### 3.4. Remediation & Recommendation Service (`ComplianceRemediationService`)

- **Responsibilities**: Manages finding state transitions and executes remediation commands.
- **Dependencies**: `CredentialedScanConnector`, `ComplianceFindingRepository`, `AuditLogger`.
- **Public Methods**:
  - `apply_remediation(finding_id: str, user_id: str) -> RemediationResultDTO`
    - **Inputs**: `finding_id` (str), `user_id` (str)
    - **Outputs**: Transition confirmation and target output.
    - **Exceptions**: `MakerCheckerApprovalRequiredError`, `RemediationExecutionError`.
    - **Validation**: Verify that the executing user has `compliance:remediate` scope. For script-based remediations, verifies that a matching, approved `compliance_exceptions` record exists as proof of maker-checker clearance.
    - **Transactions**: Strict transaction. Changes finding status to `remediation_applied`, writes status change to `compliance_finding_history`, and logs user action in `AuditLog`.

### 3.5. Exception / Waiver Service (`ComplianceExceptionService`)

- **Responsibilities**: Manages the approval pipeline for policy exceptions.
- **Dependencies**: `ComplianceExceptionRepository`, `NotificationService`.
- **Public Methods**:
  - `create_waiver_request(req: ExceptionRequest, user_id: str) -> ComplianceExceptionDTO`
  - `approve_waiver(exception_id: str, approver_id: str) -> ExceptionApprovalDTO`
    - **Exceptions**: `InvalidExpirationDateError`, `UnauthorizedApproverError`.
    - **Validation**: Approver must possess the `compliance:approve_exception` permission. Expiration date must not exceed 1 year from the request date.
    - **Transactions**: The exception status update and finding status transition (`fail` ➔ `exception`) are wrapped in a single database transaction.

### 3.6. Scan Run Worker Coordinator (`ComplianceScanCoordinator`)

- **Responsibilities**: Coordinates worker task queues for asynchronous framework scans.
- **Dependencies**: `CeleryTaskQueue`, `ComplianceScanRunRepository`.
- **Public Methods**:
  - `dispatch_scan_run(run_id: str) -> None`
    - **Inputs**: `run_id` (str)
    - **Routing**: Pushes tasks specifically to the isolated `compliance` Celery queue.
    - **Transactions**: Updates the `compliance_scan_runs` record state from `queued` to `running`. Once finished, marks the run `is_finalized = true`.

---

## 4. API Router Integrations (FastAPI Controllers)

Routers expose services over HTTP REST interfaces. Below is an example router setup for Policy Management:

```python
"""
Module: compliance.routers.policies
Purpose: Policies REST API routing endpoints.
Author:  Compliance Dev Team
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from db.base import get_db
from auth.dependencies import require_permission
from compliance import schemas
from compliance.services.policy import CompliancePolicyService

router = APIRouter(prefix="/api/compliance/policies", tags=["compliance"])

@router.post("/",
             response_model=schemas.PolicyResponse,
             status_code=status.HTTP_201_CREATED)
def create_policy(
    policy_in: schemas.PolicyCreate,
    db: Session = Depends(get_db),
    current_user = Depends(require_permission("compliance:manage_rules"))
):
    """
    Create a new compliance policy version baseline.
    """
    service = CompliancePolicyService(db)
    try:
        return service.create_policy(policy_in, creator_id=current_user.id)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
```

---

## 5. Domain Exception Catalog

The compliance module implements dedicated exceptions defined in `compliance/exceptions.py`:

```python
class ComplianceEngineException(Exception):
    """Base exception for all compliance domain errors."""
    pass

class UnsupportedEvidenceSourceError(ComplianceEngineException):
    """Raised when a rule references an evidence source not registered in the EPL."""
    pass

class StaleEvidenceError(ComplianceEngineException):
    """Raised when evidence in EPL is older than the configured threshold (e.g. 30 days)."""
    pass

class DependencyCheckFailedError(ComplianceEngineException):
    """Raised when a rule is evaluated but its prerequisite dependencies are failing."""
    pass

class MakerCheckerApprovalRequiredError(ComplianceEngineException):
    """Raised when executing a script-based remediation without Checker approval."""
    pass

class UnauthorizedApproverError(ComplianceEngineException):
    """Raised when a user without exception approval scopes tries to grant a waiver."""
    pass
```

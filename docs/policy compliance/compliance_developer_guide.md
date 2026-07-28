# CCure Audit PRO — Compliance Engine Developer Guide

This guide is for backend and frontend developers working on or extending the Policy Compliance Engine.

---

## 1. Local Environment Setup

### 1.1. Environment Variables

Add the following keys to your local `Backend/.env` file:

```bash
COMPLIANCE_ENGINE_ENABLED=true
COMPLIANCE_EPL_CACHE_TTL=300
COMPLIANCE_QUEUE_CONCURRENCY=2
```

### 1.2. Database and Container Initialization

1. Spin up the local database and Redis services:
   ```bash
   docker compose up -d db redis
   ```
2. Run database migrations and seed static frameworks:
   ```bash
   cd Backend
   poetry run alembic upgrade head
   poetry run python -m scripts.seed_compliance --seed-file docs/iso27001_2022_controls_seed.json
   ```
3. Start the Celery workers explicitly monitoring the compliance queue:
   ```bash
   poetry run celery -A main.celery_app worker -Q compliance -c 2 -l info
   ```

---

## 2. Walkthrough: Writing a Custom Compliance Rule

To introduce a new rule, follow these steps:

### Step 1: Define the Rule JSON Pack

Add a rule JSON configuration block matching the criteria format. Below is an example checking for password complexity configuration:

```json
{
  "rule_family_code": "AUTH-PWD-002",
  "version_number": 1,
  "check_type": "registry",
  "evidence_source": "credential_validation",
  "target_platform": "windows",
  "check_definition": {
    "key": "min_password_length_configured",
    "operator": "version_gte",
    "expected": 14
  },
  "severity": "high",
  "tags": ["Windows", "Password"]
}
```

### Step 2: Implement matching operator logic

If a new comparison operator is required, add a handler inside the `evaluate_operator` method in `compliance/services/engine.py`:

```python
elif operator == "regex_match":
    return bool(re.search(str(expected), str(actual)))
```

---

## 3. Walkthrough: Writing a New Evidence Provider Adapter

To ingest data from a new scan module, register it in the EPL:

### Step 1: Implement the Adapter function

Create the translation logic in `compliance/services/evidence.py`:

```python
class EDRScannerAdapter:
    @staticmethod
    def get_evidence(asset_id: str, db_session: Session) -> Dict[str, Any]:
        # Query EDR tables
        edr_log = db_session.execute(
            "SELECT active_threats_count FROM edr_findings WHERE asset_id = :asset_id",
            {"asset_id": asset_id}
        ).fetchone()

        return {
            "threats_detected": edr_log["active_threats_count"] > 0 if edr_log else False,
            "agent_running": edr_log is not None
        }
```

### Step 2: Register the Source

Map the provider to the `EPL_ADAPTER_MAP` dispatcher dictionary in `evidence.py`:

```python
EPL_ADAPTER_MAP = {
    "vulnerability_audit": VulnerabilityAuditAdapter.get_evidence,
    "edr_generic": EDRScannerAdapter.get_evidence
}
```

---

## 4. Running Verification Tests Locally

Execute the test suites via `pytest`:

```bash
# Run unit tests verifying scoring calculations and rule evaluator logic
poetry run pytest tests/unit/compliance/

# Run integration tests verifying API routers and EPL caching
poetry run pytest tests/integration/compliance/
```

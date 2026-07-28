# CCure Audit PRO — Compliance Engine Sequence Diagrams

This document collects the complete set of sequence diagrams detailing operations in the Policy Compliance Engine.

---

## 1. End-to-End Scan Execution Workflow

This flow shows what happens from the moment a user clicks "New Scan" to the metric update on the dashboard:

```mermaid
sequenceDiagram
    autonumber
    actor User as Compliance Officer
    participant API as FastAPI Router
    participant MQ as Celery Queue (Redis)
    participant Worker as Task Worker
    participant EPL as Evidence Provider Layer
    participant RE as Rule Engine
    participant DB as PostgreSQL DB
    participant WS as WebSocket Hub

    User->>API: POST /api/compliance/scans {framework_id, scope}
    API->>DB: Write scan run entry (status = queued)
    API->>MQ: Enqueue scan task
    API-->>User: Return 202 Accepted (Scan ID)

    Worker->>MQ: Dequeue scan task
    Worker->>DB: Update run status = running

    loop For each Asset in Scope
        loop For each Rule in Policy
            alt Has Evidence Source
                Worker->>EPL: Fetch normalized evidence
                EPL-->>Worker: Return DTO Payload
            else Needs Live Connection
                Worker->>Worker: Execute credential check
            end

            Worker->>RE: Run check criteria
            RE-->>Worker: Verdict (pass/fail)
            Worker->>DB: Write compliance_findings
            Worker->>DB: Append to compliance_finding_history
        end
    end

    Worker->>DB: Calculate & cache compliance_scores
    Worker->>DB: Update scan run status = completed
    Worker->>WS: Emit SCAN_COMPLETED event
    WS-->>User: Refresh Dashboard metrics
```

---

## 2. Manual Controls Attestation Workflow

This workflow represents the lifecycle of governance and process controls that cannot be technically scanned:

```mermaid
sequenceDiagram
    autonumber
    actor Owner as Asset Owner
    actor Auditor as Auditor / Compliance Officer
    participant API as FastAPI Router
    participant DB as PostgreSQL DB
    participant SF as File Storage (S3/Local)

    Owner->>API: POST /api/compliance/controls/{id}/attest (note, file)
    API->>SF: Save evidence document (PDF/PNG)
    SF-->>API: Return file reference and SHA-256 hash
    API->>DB: Write compliance_findings (status = manual_review, evidence = file_ref)
    API->>DB: Append to compliance_finding_history
    API-->>Owner: Return Attestation Saved

    Auditor->>API: GET /api/compliance/findings (filter by manual_review)
    API->>DB: Query pending attestations
    DB-->>API: Return list
    API-->>Auditor: Render reviews panel

    alt Approve Attestation
        Auditor->>API: POST /api/compliance/findings/{id}/attest {status = pass}
        API->>DB: Update finding status = pass
        API->>DB: Append to compliance_finding_history
    else Reject Attestation
        Auditor->>API: POST /api/compliance/findings/{id}/attest {status = fail}
        API->>DB: Update finding status = fail
        API->>DB: Append to compliance_finding_history
    end
    API-->>Auditor: Return Updated Status
```

---

## 3. Exception Waiver Request & Approval Pipeline

This flow details the request, approval, and expiration tracking for policy waivers:

```mermaid
sequenceDiagram
    autonumber
    actor Eng as Security Engineer
    actor Approver as Compliance Officer / CISO
    participant API as FastAPI Router
    participant DB as PostgreSQL DB

    Eng->>API: POST /api/compliance/findings/{id}/exception {reason, expires_at}
    API->>DB: Write compliance_exceptions (status = pending)
    API-->>Eng: Return Request Created (Pending)

    Approver->>API: PATCH /api/compliance/exceptions/{id} {status = approved}
    API->>DB: Update exception status = approved
    API->>DB: Update compliance_findings status = exception
    API->>DB: Append status change to compliance_finding_history
    API->>DB: Recalculate compliance_scores
    API-->>Approver: Return Waiver Approved
```

---

## 4. Automated Remediation & Verification

This flow describes the execution of a corrective script and its validation:

```mermaid
sequenceDiagram
    autonumber
    actor Eng as Security Engineer
    participant API as FastAPI Router
    participant DB as PostgreSQL DB
    participant Worker as Scan Worker
    participant RE as Rule Engine

    Eng->>API: POST /api/compliance/findings/{id}/remediate {action = apply_script}
    API->>DB: Check exception waiver approval status
    DB-->>API: Return approved waiver record (Maker-Checker check)
    API->>Worker: Dispatch execute_remediation_command(fix_command)
    Worker->>Worker: Apply script on host via credential connector
    Worker-->>API: Command execution success
    API->>DB: Update finding status = remediation_applied
    API->>DB: Append to compliance_finding_history
    API-->>Eng: Return Remediation Applied

    Note over API, Worker: System triggers validation re-scan
    API->>Worker: Dispatch re-verify job
    Worker->>Worker: Read configuration state
    Worker->>RE: Evaluate criteria
    RE-->>Worker: Verdict (PASS)
    Worker->>DB: Update finding status = pass
    Worker->>DB: Append to compliance_finding_history
```

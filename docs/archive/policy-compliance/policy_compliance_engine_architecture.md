# CCure Audit PRO — Policy Compliance Engine

## End-to-End Architecture Spec (ISO 27001:2022 first, framework-agnostic core)

_Consolidated v5 — folds in Policy layer, remediation state machine, scan scheduling, Evidence Provider Layer, Framework Marketplace, cross-framework mapping, finding timeline, cross-module integration hooks, policy/rule versioning, evidence retention, notification rules, generic integration connectors, Recommendation Engine, tags, risk-weighted scoring, rule dependencies, evidence confidence, bulk remediation, and dashboard KPIs._

---

## 1. Design principle

Two things scan very differently and must not be forced into one model:

- **Auto-scannable controls (~14 auto + 17 semi_auto = 31 of 93)** → run through the existing scan pipeline (Basic Network Scan / Vulnerability Audit / Credential Validation / Offline Config Scan already power this).
- **Manual controls (~62 of 93)** → attestation workflow: status + owner + evidence + review date. No scan engine involved.

Both verdict types roll into **one unified finding model** so the Compliance Dashboard and SoA export don't care which path produced the result.

The engine is **not a new scanner** — it's an orchestration layer that sits on top of your existing scan modules and adds a policy/rule/evidence layer above them. That's the core idea behind the diagram in §2.

---

## 2. Evidence Provider Layer

This is the architectural spine of the whole feature: every existing CCure Audit PRO scan module becomes an **evidence source** feeding into the compliance engine, rather than the compliance engine being "yet another scanner." This is what avoids duplicate scanning logic.

```
                    Asset Registry
                          │
        ┌─────────────────┼──────────────────┐
        │                 │                  │
 Vulnerability Audit  Malware Scan     Services & Ports
        │                 │                  │
   TLS/Certificates  Network Topology  Credential Validation
        │                 │                  │
        └───────Offline Configuration Scan───┘
                          │
                          ▼
             ┌────────────────────────┐
             │  Evidence Provider Layer │   ← new, thin adapter layer
             │  (result-schema mappers) │
             └────────────┬────────────┘
                          │
                          ▼
             ┌────────────────────────┐
             │  Compliance Rule Engine │   ← evaluates rules against evidence
             └────────────┬────────────┘
                          │
                          ▼
             ┌────────────────────────┐
             │   Compliance Findings   │
             └────────────┬────────────┘
                          │
                          ▼
             ┌────────────────────────┐
             │  Compliance Dashboard / │
             │      SoA Reports        │
             └────────────────────────┘
```

**What the Evidence Provider Layer actually is, technically:** a set of small adapter functions/services, one per existing scan module, each translating that module's native result schema into a common `Evidence` shape the rule engine can consume:

```json
{
  "evidence_source": "vulnerability_audit",
  "asset_id": "uuid",
  "captured_at": "2026-07-01T10:00:00Z",
  "payload": { "cve_ids": [...], "severity": "high", "age_days": 12 }
}
```

Rules whose evidence already exists (8.7 Malware, 8.8 Vulnerabilities, 8.20/8.21 Network security, 8.22 Segregation, 8.24 Cryptography) never trigger a new scan — the rule engine just asks this layer for the latest matching evidence. New scan logic is only needed for controls with no existing evidence source (registry/config/service-state reads via Credential Validation).

---

## 3. Data model (framework-agnostic, ISO seeded first)

```
compliance_frameworks
├── id (uuid)
├── tenant_id (nullable — null = global catalog framework, e.g. ISO 27001 shipped by you)
├── code            e.g. "ISO27001_2022"
├── name            "ISO/IEC 27001:2022"
├── version
├── is_active                      -- globally published/available in the marketplace catalog
└── created_at

compliance_tenant_frameworks         -- NEW: Framework Marketplace — which frameworks a tenant has installed/enabled
├── id (uuid)
├── tenant_id (fk)
├── framework_id (fk)
├── is_enabled
├── enabled_by (user_id)
└── enabled_at

compliance_policies                     -- groups rules under a framework for a specific asset class. Each row IS a specific version.
├── id (uuid)
├── framework_id (fk)
├── tenant_id (nullable — null = global template policy, e.g. "ISO27001 – Windows Server Baseline")
├── policy_family_code   stable identifier shared across versions, e.g. "WIN-SERVER-BASELINE"
├── version_number         int, increments on every rule-set change
├── name              e.g. "Windows Server Baseline", "Linux Baseline", "Firewall Policy", "Cloud Policy"
├── target_platform   windows | linux | network_device | cloud | database | any
├── description
├── status              draft | active | archived
├── superseded_by_policy_id (fk, nullable — points to the next version once this one is archived)
├── tags[]              e.g. ["Critical", "OT", "SCADA", "Power Sector", "Cloud", "Production"]
├── is_active
└── created_by / created_at

compliance_policy_rules                 -- join table, which rules belong to which policy
├── policy_id (fk)
├── rule_id (fk)

compliance_controls
├── id (uuid)
├── framework_id (fk)
├── control_number   e.g. "8.24"
├── theme            ORG | PPL | PHY | TECH
├── title
├── description
├── scannability      auto | semi_auto | manual
└── scan_module_hint  nullable — links to existing scan template code

compliance_rules                       -- only exists for auto / semi_auto controls. Each row IS a specific version.
├── id (uuid)
├── rule_family_code   stable identifier shared across versions, e.g. "AUTH-MFA-001"
├── version_number       int, increments whenever check_definition changes
├── check_type        registry | file_content | port_state | tls_config | service_status | api_response | command_output
├── evidence_source   nullable — which Evidence Provider adapter to query, null = live check
├── target_platform   windows | linux | network_device | cloud | any
├── check_definition  JSONB  (see §9 rule pack format)
├── severity
├── severity_weight    int — Critical=10, High=7, Medium=5, Low=2 (see §14a weighted scoring)
├── tags[]              e.g. ["Critical", "Windows", "OT", "SCADA"]
├── status              draft | active | archived
├── superseded_by_rule_id (fk, nullable)
└── remediation_id (fk, nullable → compliance_remediations)

compliance_rule_dependencies             -- NEW: prevents misleading remediation suggestions
├── rule_id (fk)
├── depends_on_rule_id (fk)              -- e.g. "Recovery Key Stored" depends_on "TPM Enabled"
└── dependency_type      prerequisite | related

compliance_rule_controls               -- many-to-many join (cross-framework reuse — powers §5 mapping view)
├── rule_id (fk)
├── control_id (fk)

compliance_remediations                 -- structured remediation, not just free text
├── id (uuid)
├── rule_id (fk)
├── recommendation_text
├── fix_type            manual | script | config_template
├── fix_command          nullable  (e.g. PowerShell/bash snippet)
├── fix_target_path      nullable  (e.g. registry path / config file path)
├── documentation_url    nullable
├── estimated_score_impact_pct   nullable — computed/curated estimate of SoA score gain if fixed (see §14)
└── requires_reboot       boolean

compliance_scan_schedules               -- recurring compliance scans
├── id (uuid)
├── tenant_id (fk)
├── framework_id (fk)
├── policy_id (fk, nullable — null = whole framework)
├── scope              asset_ids[] / asset_tags[]
├── frequency           daily | weekly | monthly | quarterly | continuous
├── cron_expression      nullable, for custom schedules
├── notify_on            always | on_failure_only | on_score_drop
├── notify_channels[]     email | in_app | webhook
├── is_active
└── next_run_at / last_run_at

compliance_scan_runs
├── id (uuid)
├── tenant_id (fk)
├── framework_id (fk)
├── policy_id (fk, nullable)
├── schedule_id (fk, nullable — null if manually triggered)
├── initiated_by (user_id, nullable if schedule-triggered)
├── scope             asset_ids[] / asset_tags[]
├── status             queued | running | completed | failed
├── started_at / finished_at
└── is_finalized       boolean  -- once true, immutable (audit trail requirement)

compliance_findings
├── id (uuid)
├── scan_run_id (fk, nullable)          -- null for pure manual attestations outside a "run"
├── tenant_id (fk)
├── asset_id (fk, nullable)             -- null for org-level controls with no single asset
├── control_id (fk)
├── rule_id (fk, nullable)              -- null if this is a manual attestation
├── source              auto_scan | manual_attestation
├── status              pass | fail | not_applicable | manual_review | exception | remediation_applied | pending_reverify
├── evidence            JSONB           -- raw check output, or {doc_url, note, reviewer} for manual. Include "confidence_pct":
│                          registry_read/live_scan ≈ 100%, cached_result ≈ 90%, manual_evidence ≈ 70%.
│                          Low-confidence evidence is a reasonable trigger to route a finding to manual_review
│                          instead of an outright pass/fail.
├── evidence_file_ids[]                 -- uploaded PDFs/screenshots as evidence
├── attested_by (user_id, nullable)
├── remediation_applied_by (user_id, nullable)
├── remediation_applied_at (nullable)
├── first_seen / last_seen / reviewed_at

compliance_finding_history               -- NEW: Compliance Timeline — append-only status log
├── id (uuid)
├── finding_id (fk)
├── status              pass | fail | not_applicable | manual_review | exception | remediation_applied | pending_reverify
├── changed_at
├── changed_by (user_id, nullable — null if system/auto-scan triggered)
├── source              auto_scan | manual_attestation | remediation | exception_granted | exception_expired
└── note                 nullable  (e.g. "re-scan after patch deployment")

compliance_exceptions                    -- waivers
├── id (uuid)
├── tenant_id (fk)
├── control_id (fk) / finding_id (fk, nullable)
├── reason
├── compensating_control  text, nullable
├── requested_by / approved_by
├── status              pending | approved | rejected | expired
└── expires_at

compliance_scores                        -- computed rollups, cached for dashboard speed
├── id (uuid)
├── tenant_id (fk)
├── framework_id (fk)
├── scan_run_id (fk, nullable)
├── asset_id (fk, nullable)             -- enables the Asset Compliance page (§10)
├── theme               nullable — per-theme sub-score
├── total_controls / applicable_controls
├── pass_count / fail_count / na_count / pending_count
├── score_pct                  simple pass/applicable percentage
└── weighted_score_pct          severity-weighted: Σ(weight of passed) / Σ(weight of applicable) — see §14a

compliance_evidence_retention_policies   -- NEW: retention/records requirements (ties into ISO 5.33, 8.10)
├── id (uuid)
├── tenant_id (fk, nullable — null = platform default)
├── framework_id (fk, nullable — null = applies to all)
├── retain_years            int, e.g. 7
├── archive_after_years     int, nullable
├── encrypt_at_rest         boolean
├── immutable_storage       boolean
├── updated_by / updated_at

-- evidence_file_ids[] on compliance_findings should reference file metadata that carries:
--   sha256_hash, uploaded_at, uploaded_by, retention_policy_id_applied
-- stored in whatever file storage your platform already uses for uploads (not a new store).

compliance_notification_rules            -- NEW: lightweight trigger-based notifications
├── id (uuid)
├── tenant_id (fk)
├── framework_id (fk, nullable)
├── trigger_type          score_below_threshold | control_failed | exception_expiring | schedule_failed
├── threshold_value        nullable, e.g. 80 (for score % below)
├── notify_channels[]       email | in_app | webhook
├── action_type            notify | create_incident | create_ticket
├── integration_connector_id (fk, nullable — required if action_type != notify)
└── is_active

compliance_integration_connectors        -- NEW: generic connector abstraction, not per-vendor tables
├── id (uuid)
├── tenant_id (fk)
├── connector_type         jira | servicenow | splunk | webhook | active_directory | entra_id | edr_generic
├── config                 JSONB (endpoint URL, field mappings — auth secrets stored in your existing secrets vault, referenced by id, never inline)
├── is_active
└── created_at / created_by
```

**Why policy and rule versioning matter:** without it, editing a rule in place would silently change the meaning of every historical finding that points at it — a scan from March could start being reinterpreted through May's rule logic. Each edit creates a new `compliance_policies`/`compliance_rules` row (incrementing `version_number`, same `policy_family_code`/`rule_family_code`) rather than mutating the existing one. `compliance_scan_runs.policy_id` and `compliance_findings.rule_id` always point at the exact version that was actually evaluated, so re-opening an old scan result always shows what the rule really said at that time. This is a correctness requirement, not a nice-to-have — it's what makes the audit trail actually trustworthy.

**Why `compliance_evidence_retention_policies` matters:** this isn't just good practice — ISO 27001 itself has controls about it (5.33 Protection of records, 8.10 Information deletion), so the tool auditing your compliance should itself follow defensible retention rules. Keep it as configurable policy rather than hardcoded, since retention requirements vary by industry/region.

**Why `compliance_notification_rules` and `compliance_integration_connectors` are separate:** notification rules are pure trigger logic (score dropped, control failed, exception expiring) and stay simple regardless of what's on the other end. The connector table is a generic abstraction — one shape for Jira, ServiceNow, Splunk, a webhook, or an EDR tool — so you don't build nine bespoke integration tables. Only build the connector _types_ you actually need first; the schema doesn't force you to commit to all of them upfront.

**Why `tags[]` on policies and rules matters:** once you have ISO's 93 controls plus a second and third framework, the rule library gets large fast — tags (`Critical`, `Windows`, `OT`, `SCADA`, `Power Sector`, `Cloud`, `Production`) make it searchable/filterable without needing framework-specific navigation. Cheap to add now, painful to retrofit once the library has hundreds of rules.

**Why `severity_weight` and `weighted_score_pct` matter:** a flat pass/applicable percentage treats "clock not synchronized" the same as "MFA not enforced on privileged accounts," which misrepresents actual risk posture. Keep `score_pct` for the simple SoA-style count (what auditors expect to see) but compute `weighted_score_pct` alongside it for the dashboard's real risk signal — show both, don't replace one with the other.

**Why `compliance_rule_dependencies` matters:** some checks are only meaningful in sequence — e.g. recommending "store the recovery key" before confirming TPM is even enabled produces a misleading fix suggestion. The Recommendation Engine (§14) should check `depends_on_rule_id` status before surfacing a remediation, and flag prerequisite failures first. Keep this table simple (no cycle-detection engine needed yet — just enforce acyclic edges at write time) since dependency chains here are expected to be shallow (2-3 levels), not deep graphs.

**Why `compliance_tenant_frameworks` matters:** a global framework catalog (ISO/CIS/IEC 62443/NIST/PCI/HIPAA) is meaningless without a way for each tenant to install/enable only the ones relevant to them — this is what makes the Framework Marketplace (§4) real rather than just a label on an already-hardcoded list.

**Why `compliance_finding_history` is separate from `compliance_findings`:** the findings table holds current state; the history table is an append-only audit log of every transition. Every status change (scan result, manual attestation, remediation applied, exception granted/expired) writes one row here. This is what powers the Compliance Timeline (§8) and is also what an auditor will ask for first — "show me how this finding's status changed over time," not just its current value.

**Why `compliance_policies` matters:** a tenant doesn't scan "against ISO 27001" as one monolith — they run "Windows Server Baseline," "Linux Baseline," "Firewall Policy," "Cloud Policy" as separate, independently schedulable units, each pulling a relevant rule subset and mapping back to the same underlying controls.

**Why `compliance_remediations` is separate from `compliance_rules`:** decouples "what failed" from "how to fix it," so a remediation can be reused across rules, versioned independently, and audited separately from the check logic.

**Why the many-to-many `compliance_rule_controls` join matters:** one rule like "TLS 1.2+ enforced, weak ciphers disabled" satisfies ISO 8.24 _and_ PCI-DSS 4.2 _and_ CIS 2.3.1 _and_ NIST SC-13 _and_ IEC 62443 SR 3.x simultaneously. Build this join now even with only ISO seeded — it's what makes the Framework Marketplace and cross-framework mapping view (§5) possible without a re-architecture later.

---

## 4. Framework Marketplace

The backend is already framework-agnostic by design, so this is mostly a product/UI layer on top of `compliance_tenant_frameworks` — but it's worth building deliberately rather than hardcoding "ISO only" into the UI, since it changes zero backend logic later.

```
Compliance Frameworks
[✓] ISO 27001:2022         Installed · 93 controls · 24 auto-checks
[ ] CIS Benchmarks          Available
[ ] IEC 62443                Available   ← fits your critical-infrastructure focus
[ ] NIST 800-53               Available
[ ] PCI DSS                    Available
[ ] HIPAA                       Available
```

Each entry shows: control count, auto/semi/manual breakdown, and (once >1 framework is installed) how many rules are already shared with other installed frameworks via `compliance_rule_controls` — a genuinely useful "you're already 40% compliant with CIS just from your ISO rules" signal.

`GET /api/compliance/marketplace` → lists catalog frameworks with install status per tenant.
`POST /api/compliance/marketplace/{framework_id}/install` → writes a `compliance_tenant_frameworks` row, does not trigger a scan automatically.

---

## 5. Cross-framework mapping view

Schema already supports this via `compliance_rule_controls` — this section is purely a UI/API exposure of an existing relationship, not new architecture. Valuable enough to auditors that it's worth being a first-class view rather than buried in a rule's detail page.

```
GET /api/compliance/rules/{id}/mappings
```

```json
{
  "rule_code": "NET-TLS-001",
  "title": "TLS 1.2+ enforced, weak ciphers disabled",
  "satisfies": [
    { "framework": "ISO27001_2022", "control": "8.24" },
    { "framework": "PCI_DSS_4.0", "control": "4.2" },
    { "framework": "CIS_Benchmarks", "control": "2.3.1" },
    { "framework": "NIST_800-53", "control": "SC-13" },
    { "framework": "IEC_62443", "control": "SR 3.x" }
  ]
}
```

Show this inline wherever a finding or control is displayed ("this check also satisfies 4 other frameworks") — it's the clearest way to demonstrate the framework-agnostic engine is real, not just a marketing claim.

---

## 6. RBAC scopes to add

```
compliance:read
compliance:scan                 -- launch an automated compliance scan (manual or via schedule)
compliance:manage_schedules     -- create/edit recurring compliance scans
compliance:attest               -- mark a manual control's status + upload evidence
compliance:remediate            -- apply a remediation / mark a finding as fixed pending re-verify
compliance:manage_rules         -- create/edit custom rules and policies, including publishing new versions (Admin/Security Engineer only)
compliance:manage_frameworks    -- install/enable frameworks from the marketplace (Admin only)
compliance:manage_retention     -- configure evidence retention policies (Admin/Compliance Officer only)
compliance:manage_integrations  -- configure notification rules and integration connectors (Admin only)
compliance:approve_exception    -- waiver approval (CISO/Compliance Officer only, audit-logged)
compliance:export_report        -- SoA / auditor exports
```

---

## 7. Remediation state machine

Every auto/semi-auto finding that fails moves through an explicit state machine rather than staying a flat pass/fail. Every transition below also writes a `compliance_finding_history` row (§8).

```
   ┌────────┐
   │  PASS  │◄────────────────────────────────┐
   └────────┘                                  │
                                                │ re-scan confirms fix
   ┌────────┐   remediation applied   ┌───────────────────┐
   │  FAIL  │ ───────────────────────►│ REMEDIATION_APPLIED│
   └────┬───┘                         └──────────┬─────────┘
        │                                        │
        │ exception requested                    │ scheduled/triggered re-scan
        ▼                                        ▼
   ┌──────────┐                        ┌───────────────────┐
   │ EXCEPTION│                        │  PENDING_REVERIFY   │
   │ (waived) │                        └──────────┬─────────┘
   └──────────┘                                   │
                                    re-scan fails  │  re-scan passes
                                    ┌──────────────┴─────────────┐
                                    ▼                             ▼
                                 back to FAIL                   PASS
```

Flow:

1. Rule evaluates → `fail`, finding created with `remediation_id` attached
2. User views the fix (recommendation text, script/command, doc link) via `POST /api/compliance/findings/{id}/remediate`
3. If `fix_type = script`, the platform can optionally dispatch the fix command through the same credentialed connector used for scanning (with explicit confirmation — this is a write action, so it follows the same "confirm before acting" rule as any other state-changing operation)
4. Finding moves to `remediation_applied` → a re-scan moves it to `pending_reverify` → re-scan result resolves it to `pass` or back to `fail`

**Explicit lifecycle naming:** the schema already implies this, but it's worth stating outright for whoever implements each module package (§15): every finding moves through **Rule → Finding → Recommendation → Remediation → Verification**. Detection (`evaluator/`) is deliberately kept separate from guidance (`remediation/` recommendation content), which is separate from execution (applying a fix), which is separate from validation (the re-scan that actually confirms the fix worked). Keeping these as distinct steps — not collapsed into one "fix it" action — is what prevents a finding from being marked resolved on faith rather than on verified re-scan evidence.

### Bulk remediation

For enterprise-scale fleets, remediation needs to work across many assets at once, not one finding at a time:

```
POST /api/compliance/remediation/bulk
{ "rule_id": "...", "asset_ids": [...200 ids...], "action": "apply_script" }
→ returns a batch_id, dispatches one remediation job per asset through the
  existing scan worker pool (same Scan Quota / Concurrent limits already enforced),
  each asset's finding individually moves through the same state machine above,
  and a follow-up bulk re-scan can be scheduled against the same asset_ids.
```

No new state machine needed — this is an orchestration wrapper that fans out the existing single-finding flow across a selected asset scope, reusing the same concurrency limits your scan queue already respects.

---

## 8. Compliance Timeline

Every finding gets a visible history, built entirely from `compliance_finding_history` (§3) — an append-only log, never mutated.

```
Finding: TLS 1.2+ enforced — Server-01

15 Jun   FAIL              (auto_scan)
20 Jun   FAIL              (auto_scan, unchanged)
22 Jun   REMEDIATION_APPLIED   by J. Fernandes — "disabled TLS 1.0/1.1"
24 Jun   PENDING_REVERIFY   (auto_scan queued)
24 Jun   PASS               (auto_scan)
```

`GET /api/compliance/findings/{id}/history` returns the full log. This is one of the first things an ISO auditor asks for on any finding — "prove this was actually fixed on this date, not just marked fixed" — so treat this as required for Phase 4 (SoA export), not optional polish.

---

## 9. Rule pack format (for the ~31 auto/semi_auto controls)

JSON, versioned, stored in `compliance_rules.check_definition`.

```json
{
  "rule_code": "AUTH-MFA-001",
  "controls": ["8.5", "5.17"],
  "title": "Multi-factor authentication enforced for privileged accounts",
  "check_type": "registry",
  "evidence_source": null,
  "target_platform": "windows",
  "target": {
    "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\...\\MFAEnabled",
    "operator": "equals",
    "expected": 1
  },
  "severity": "high",
  "remediation_id": "REM-AUTH-MFA-001",
  "evidence_capture": ["registry_value", "timestamp", "hostname"]
}
```

```json
{
  "rule_code": "NET-TLS-001",
  "controls": ["8.24"],
  "title": "TLS 1.2+ enforced, weak ciphers disabled",
  "check_type": "tls_config",
  "evidence_source": "tls_certificates",
  "target_platform": "any",
  "target": {
    "port": 443,
    "min_tls_version": "1.2",
    "disallowed_ciphers": ["RC4", "3DES", "NULL"]
  },
  "severity": "high",
  "remediation_id": "REM-NET-TLS-001",
  "evidence_capture": ["negotiated_protocol", "cipher_suite", "cert_expiry"]
}
```

```json
{
  "rule_code": "VULN-PATCH-001",
  "controls": ["8.8"],
  "title": "No critical/high CVEs older than 30 days unpatched",
  "check_type": "api_response",
  "evidence_source": "vulnerability_audit",
  "target_platform": "any",
  "target": {
    "max_age_days": 30,
    "severity_threshold": "high"
  },
  "severity": "critical",
  "remediation_id": "REM-VULN-PATCH-001",
  "evidence_capture": ["cve_ids", "asset_id", "days_open"]
}
```

Rules with `evidence_source` set never trigger a new scan — they query the Evidence Provider Layer (§2). Rules with `evidence_source: null` need a live credentialed check.

### Rule → evidence-source mapping (what's genuinely new vs. reused)

| Control                                             | Evidence Provider source                 | New work needed                                            |
| --------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- |
| 8.7 Malware protection                              | Malware Scan                             | Adapter mapping only                                       |
| 8.8 Vulnerability mgmt                              | Vulnerability Audit                      | Adapter mapping only                                       |
| 8.20/8.21 Network security                          | Network Based Scanning, Services & Ports | Adapter mapping only                                       |
| 8.22 Network segregation                            | Network Topology                         | Adapter mapping only                                       |
| 8.24 Cryptography                                   | TLS/Certificates                         | Adapter mapping only                                       |
| 8.2/8.5 Access & auth                               | Credential Validation                    | Live rule checks (registry/policy reads)                   |
| 8.1/8.9 Endpoint/config baseline                    | Offline Configuration Scan               | New CIS-style rule pack authoring                          |
| 8.15/8.16/8.17/8.19 Logging/monitoring/NTP/software | —                                        | New live rule checks (mostly registry/service-state reads) |

Roughly **6 of the 14 auto controls need zero new scanning capability** — just an Evidence Provider adapter. That's your fastest path to a demoable v1.

---

## 10. Backend (FastAPI) — new routers

```
GET    /api/compliance/marketplace
POST   /api/compliance/marketplace/{framework_id}/install
GET    /api/compliance/frameworks
GET    /api/compliance/frameworks/{id}/controls?theme=&scannability=
GET    /api/compliance/policies?framework_id=&target_platform=&status=
POST   /api/compliance/policies                 { framework_id, name, target_platform, rule_ids[] }   -- creates v1
POST   /api/compliance/policies/{id}/new-version { rule_ids[] }                                        -- publishes vN+1, archives current
GET    /api/compliance/rules?status=&target_platform=
POST   /api/compliance/rules/{id}/new-version    { check_definition }                                   -- publishes vN+1, archives current
POST   /api/compliance/scans                    { framework_id, policy_id?, scope: {asset_ids|tags} }
GET    /api/compliance/scans/{id}
GET    /api/compliance/scans/{id}/findings?status=&theme=
POST   /api/compliance/schedules                { framework_id, policy_id?, scope, frequency, notify_on, notify_channels[] }
GET    /api/compliance/schedules
PATCH  /api/compliance/schedules/{id}           { is_active, frequency }
POST   /api/compliance/controls/{id}/attest      { status, note, evidence_file_ids[] }
POST   /api/compliance/findings/{id}/remediate   { action: view|apply_script|mark_fixed }
POST   /api/compliance/remediation/bulk         { rule_id, asset_ids[], action }
GET    /api/compliance/findings/{id}/history
GET    /api/compliance/findings/{id}/recommendation                                                     -- §14
POST   /api/compliance/findings/{id}/exception   { reason, compensating_control, expires_at }
PATCH  /api/compliance/exceptions/{id}           { status: approved|rejected }   -- requires compliance:approve_exception
GET    /api/compliance/rules/{id}/mappings
GET    /api/compliance/dashboard/summary?framework_id=&group_by=theme|os|site|department|business_unit|criticality
GET    /api/compliance/dashboard/kpi?framework_id=                                                       -- §11a
GET    /api/compliance/assets/{asset_id}/compliance
GET    /api/compliance/reports/soa/{framework_id}/export?format=pdf|docx|csv
GET    /api/compliance/retention-policies                                                                -- requires compliance:manage_retention
PATCH  /api/compliance/retention-policies/{id}
GET    /api/compliance/notification-rules                                                                -- requires compliance:manage_integrations
POST   /api/compliance/notification-rules       { trigger_type, threshold_value, action_type, notify_channels[] }
GET    /api/compliance/connectors
POST   /api/compliance/connectors               { connector_type, config }
```

Scan execution worker: extends your existing scan queue/worker pool with a new `scan_type = "compliance"` that:

1. Resolves scope → asset list (manual trigger or a due `compliance_scan_schedules` row)
2. Fetches applicable rules for the selected framework/policy
3. For rules with `evidence_source` set → query the Evidence Provider Layer, don't re-scan
4. For rules needing a live connection → dispatch via existing credentialed connector
5. Writes `compliance_findings` + a `compliance_finding_history` row for every status change, triggers score recompute, evaluates `notify_on` for schedule-triggered runs

---

## 11. Frontend — fits your existing UI

- **Scan Templates page**: flip "Policy Compliance Scanning" card from `SOON` to active. Config modal: Framework dropdown (populated from installed marketplace frameworks) → Policy dropdown → scope selector → credential set selector → optional "make recurring" toggle.
- **New "Compliance" workspace** (existing sidebar Compliance item becomes its real home):
  - **Marketplace**: install/enable frameworks (§4)
  - **Dashboard**: KPI header (§11a) + SoA score gauge, per-theme breakdown, trend line (30/90/365-day), breakdown filters by OS/site/department/business unit/criticality _once Asset Registry fields are confirmed to support them_, filterable by tags
  - **Policies**: manage policy definitions, versions (§3)
  - **Control Explorer**: all controls, filterable by theme/status/scannability/tags, each expandable to finding evidence, attestation form, and cross-framework mapping (§5)
  - **Findings**: results, remediation actions (incl. bulk remediation, §7), timeline (§8)
  - **Schedules**: recurring scan management
  - **Exceptions**: waiver queue
  - **SoA Export**: native Word object export

### 11a. Dashboard KPI header

Every field below is a read against tables that already exist — this is an aggregation/query concern, not new schema:

```
Overall Compliance          87%   (weighted_score_pct, §14a)
Critical Controls           95%   (score_pct filtered to severity=critical)
Failed Critical Controls    3     (count of fail-status findings, severity=critical)
Compliance Trend            ↑ +2.3% (30-day)   (from compliance_scores history over time)
Top Non-Compliant Assets    [Server-04: 61%] [Server-11: 68%] [Server-02: 71%]   (compliance_scores by asset_id, ascending)
Top Non-Compliant Policies  [Firewall Policy: 54%] [Linux Baseline: 70%]         (compliance_scores aggregated by policy_id)
```

Surface this as the top strip of the Compliance Dashboard, above the per-theme breakdown — it's the "5-second glance" view for a CISO before drilling into anything.

---

## 12. Asset Compliance page

No new schema beyond what's already modeled — filtered read on `compliance_scores`/`compliance_findings` by `asset_id`:

```
Server-01 — Risk Score: 62  |  Compliance Score: 87%
├── Password Policy      PASS
├── Firewall Config       PASS
├── TLS Configuration     FAIL   → [View remediation] [View timeline]
├── USB/Removable Media   FAIL   → [View remediation]
└── BitLocker/Encryption  FAIL   → [View remediation]
```

Surface as a tab on the existing Asset Registry detail view.

---

## 13. Cross-module integration hooks

These surface compliance data on pages that already exist elsewhere in the app. Real work, but it's UI/API extension on existing modules, not new compliance architecture — plan it as its own line item since it touches code outside the compliance module.

- **Vulnerability page**: each vulnerability finding gets a "Related Compliance Controls" chip row (e.g. `ISO 8.8`, `CIS 7.3`, `IEC 62443 SR 7.x`) — pulled via `compliance_rule_controls` joined on whatever rule maps to that CVE/finding type.
- **Asset Registry**: each asset row/detail gains `Risk Score` + `Compliance Score` side by side, alongside existing Vulnerability Count, Patch Status, Certificates, Services, Last Scan — this is the Asset Compliance page (§12) surfaced inline rather than only as a separate tab.
- **Executive Dashboard / Executive Report**: add Compliance Score next to existing Risk Score so leadership sees both together, not as separate reports.

None of this requires new tables — it's `JOIN`s against `compliance_scores` / `compliance_findings` / `compliance_rule_controls` exposed through existing endpoints. Sequence it after Phase 4 (once findings/scores are actually populated) so there's real data to surface, not empty widgets.

---

## 14. Compliance Recommendation Engine

Instead of a finding just saying `FAIL`, it should explain why, what it affects, how to fix it, and the payoff — turning the module from a scorecard into something actionable. This is mostly a presentation/computation layer over data that already exists in the schema, not a new subsystem.

```
FAIL — Firewall disabled on Server-01

Affects:      ISO 27001 8.20  ·  (also satisfies CIS 9.1, NIST SC-7 once installed)
Why it failed: Windows Defender Firewall service is stopped
Fix:           PowerShell — Set-Service -Name MpsSvc -StartupType Automatic; Start-Service MpsSvc
Related:       3 open vulnerabilities on this host are exposed by this finding
Estimated impact: +1.1% SoA score if fixed  ·  Risk score -8 pts
                   → [Apply fix] [Re-scan to verify]
```

**Where each piece comes from (no new data model needed beyond fields already added in §3):**

- "Affects" + cross-framework note → `compliance_rule_controls` + §5 mapping view
- "Why it failed" → `compliance_findings.evidence`
- "Fix" → `compliance_remediations`, checked against `compliance_rule_dependencies` first — if a prerequisite rule (e.g. "TPM Enabled") is also failing, surface that as the fix instead of the dependent one, so the suggestion is never misleading
- "Related vulnerabilities" → join through `compliance_rule_controls` → `evidence_source: vulnerability_audit` findings on the same asset
- "Estimated impact" → `estimated_score_impact_pct` on `compliance_remediations`, weighted by `severity_weight` (§14a below) rather than a flat `1/applicable_controls_count`
- "Re-scan to verify" → the remediation state machine (§7)

This slots naturally into the Findings view (§11) and the Asset Compliance page (§12) — no separate service required.

### 14a. Weighted scoring

`compliance_scores.score_pct` stays a simple pass/applicable percentage — that's what auditors expect on an SoA. Alongside it, `weighted_score_pct` uses `severity_weight` (Critical=10, High=7, Medium=5, Low=2) so the dashboard's headline number actually reflects risk, not just control count:

```
weighted_score_pct = Σ(severity_weight of passed controls) / Σ(severity_weight of applicable controls)
```

Show both on the dashboard — the plain percentage for audit-facing reports, the weighted one for the KPI view in §16a.

---

## 15. Internal module boundaries (not independent microservices — yet)

The engine should be **structured** as clearly separated modules so it's maintainable and could be extracted into independent services later, but it should ship as **one deployable service within your existing FastAPI app**, not nine separately deployed microservices, until there's a concrete, measured reason to split them (e.g. the rule engine becoming a real scaling bottleneck under load). Splitting into independent services before v1 has shipped adds real deployment, networking, and operational overhead for a benefit you can't yet measure — a modular monolith gets you the same maintainability and ownership clarity without that cost.

Suggested internal package/module boundaries (Python package structure, still one process):

```
app/compliance/
├── frameworks/       -- marketplace, framework/control CRUD
├── policies/          -- policy versioning, policy-rule assignment
├── rules/              -- rule versioning, rule pack CRUD
├── evidence/           -- Evidence Provider Layer adapters (§2)
├── evaluator/          -- rule engine — evaluates rules against evidence, produces findings
├── scoring/            -- score computation/rollup
├── remediation/        -- remediation state machine (§7), recommendation engine (§14)
├── exceptions/         -- waiver workflow
├── notifications/       -- notification rules + connector dispatch
├── reporting/           -- SoA export, dashboard aggregation
└── scheduling/          -- compliance_scan_schedules, cron trigger logic
```

Each package owns its own router, service layer, and repository — clean internal interfaces mean that if `evaluator/` genuinely needs to become an independently scaled worker later (likely candidate, since it's the compute-heavy piece), it can be pulled out without redesigning the rest.

---

## 16. Phased build order (fastest path to a working demo)

**Phase 1:** Seed all 93 ISO controls. Build `compliance_policies` (v1 of each) + manual attestation UI. Compliance Dashboard showing manual-only score. Ship Framework Marketplace UI with ISO 27001 as the only installable entry (proves the pattern early, cheap to build now vs. retrofit later).

**Phase 2:** Evidence Provider Layer adapters for the 6 "free" auto controls (8.7, 8.8, 8.20, 8.21, 8.22, 8.24). Fastest credibility win.

**Phase 3:** Remaining live rule pack for ~8 auto + 17 semi_auto controls via Credential Validation connector. Add `compliance_remediations` + remediation state machine (§7) + `compliance_finding_history` (§8) — build these two together since every remediation transition is a history event.

**Phase 4:** Exception/waiver workflow + SoA export + Compliance Timeline UI (§8) — this is what makes it audit-deliverable. Asset Compliance page (§12). Evidence retention policy enforcement (§3) on any uploaded attestation evidence.

**Phase 5:** Scheduling (`compliance_scan_schedules`) + lightweight notification rules (score-threshold/control-failed triggers, `notify` action only — no ticket creation yet). Cross-module integration hooks (§13) — vulnerability page, Asset Registry, Executive Dashboard. Executive reporting breakdowns by site/department/business unit/criticality (once Asset Registry fields are confirmed). Recommendation Engine (§14) surfaced on Findings.

**Phase 6:** Add a second framework — CIS Benchmarks or IEC 62443 (fits your critical-infrastructure/OT focus). Enable it in the Marketplace, wire cross-framework mapping view (§5) for real. This is also the point where policy/rule versioning (§3) gets its first real test — publishing a v2 of a policy without breaking historical scan results. Treat "adding the second framework without touching the schema" as the validation gate that the engine is genuinely generic, not "ISO-shaped."

**Phase 7 (roadmap, not committed scope):** First integration connector(s) — pick one or two based on actual customer demand (Jira/ServiceNow for ticketing, or Splunk/Wazuh for evidence ingestion are the most natural fits given your security-tooling audience) rather than building all nine named tools speculatively. Upgrade notification rules to `create_incident`/`create_ticket` actions once a real connector exists to send them to.

---

## 17. Key audit-integrity requirement

Once a `compliance_scan_runs` row is marked `is_finalized = true`, its findings must never be overwritten by a re-scan — a new scan creates a new run. `compliance_finding_history` is append-only and must never be edited or deleted, even by admins — it's the record an auditor trusts more than the current-state table. Policy and rule versions are never mutated in place once `status = active` — a change always creates a new version row, and historical scan runs/findings continue to reference the exact version they were evaluated against. Historical SoA snapshots must be reproducible exactly as an auditor saw them at the time.

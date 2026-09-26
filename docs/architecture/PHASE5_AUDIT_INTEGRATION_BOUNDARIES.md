# Phase 5 — CCure Audit integration boundaries (proposal)

|               |                                                                                                                                                                 |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**    | **Approved 26 Sep 2026.** Implemented one step per commit with a review stop after each. Done: 5.1 (skeleton), 5.2 (catalogue service), 5.3 (baseline mapping). |
| **Date**      | 26 Sep 2026                                                                                                                                                     |
| **Builds on** | Phase 4 contracts (approved 26 Sep 2026): [`contracts/PHASE4_INTEGRATION_CONTRACTS.md`](contracts/PHASE4_INTEGRATION_CONTRACTS.md), `Backend/ccure_contracts/`  |
| **Audience**  | Audit team and architecture reviewers                                                                                                                           |

Phase 5 creates the **internal** boundaries CCure Audit needs to consume and
produce the Phase 4 contracts later:

```
External contract            ccure_contracts/                   (Phase 4 — done)
        ▼
Audit integration adapter    ccure_audit/integration/           ← Phase 5: pure mappers only
        ▼
Audit application services   ccure_audit/services/              ← Phase 5: read services + typed views
        ▼
Audit domain / capabilities  core/, engines/, scans/, reporting/ (unchanged; used, not moved)
        ▼
Infrastructure               db/, Celery, Redis                 (unchanged)
```

The proposal is deliberately small. **Phase 5 adds no route, task, table,
migration or scan behaviour.** The new code is called only by tests until the
phase that wires the integration surface (service identity, outbox, feeds).

---

## 1. What the inspection found

For each contract: where the data lives today and what is missing.

| Contract                                | Data it needs                                                                                                       | Where it lives today                                                                                                                                                                                                                                                                                   | Gap                                                                                                                                                                                                                                    |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1** PolicyBaseline → BaselineCoverage | Framework/control lookup by code + control number; rules per control; tenant's installed frameworks; org scan scope | `compliance_frameworks` (code, version), `compliance_controls` (control_number, `scannability`), `compliance_rule_controls`, `compliance_rules` (`evidence_source='manual'` marks attestation placeholders); `core/compliance_frameworks.is_active`; `compliance_tenant_frameworks`; `core/scan_scope` | No control → rules query exists (only rule → controls, in `core/compliance_tasks`). No storage for received baselines.                                                                                                                 |
| **2** ComplianceGapReport               | Per-check verdicts of one assessment, mapped to the baseline's controls                                             | The **stored scan payload** (`config_audit.results`), walked across three payload shapes by `reporting/exports._collect_host_audits`; check → control via `exports.control_map_for_checks`                                                                                                             | The read logic is inside a renderer and returns **string rows**, not typed values. Needs a stored, activated baseline (later phase).                                                                                                   |
| **3** AssessmentResult                  | Scan descriptor; per-asset coverage, methods, credential outcome; finding totals; framework summaries               | `scans` row + `options` (`scan_policy`, `assessment_scope`, `credentialed_report`); `scan_phases.summary`; `exports.scan_context`; asset `custom_attributes.credentialed_status`                                                                                                                       | No per-asset **method outcome** record for most methods (the contract reports `unknown` there). Assembly is spread across exports and the legacy JSON builder.                                                                         |
| **3** Findings pages                    | Findings of an assessment with SLA, remediation, exploit intel                                                      | `asset_vulnerabilities`; `core/remediation/sla.sla_state`; `exports.finding_export_rows` / `finding_context_map` (again string rows)                                                                                                                                                                   | Same as above: typed values do not exist.                                                                                                                                                                                              |
| **3** PostureSnapshot                   | Current counts by severity, remediation state, SLA state; inventory coverage                                        | `core/remediation/reporting.remediation_report_payload` (remediation line); most other counts inside **`routers/dashboard.py`** (1,630 lines, HTTP layer)                                                                                                                                              | Extracting the dashboard's queries out of the router is its own piece of work.                                                                                                                                                         |
| **4** FindingEvent                      | Detected / reappeared / verified / accepted / expired / SLA-breached transitions                                    | `core/findings/comparison.compare_scans` classifies `new` / `reappeared` / `fixed` / `not_assessed` per scan; `finding_remediation_events` records `verified`, `reopened`, `risk_accepted`, `exception_expired`, `state_changed`                                                                       | **No "detected" and no "SLA breached" event is recorded anywhere** (live table: 1,760 rows, all `sla_set`). Both are derivable without touching scanning: detection from the comparison, breach from a periodic check of `sla_due_at`. |
| **5** IncidentEvidence → Receipt        | Store IR evidence read-only; link to findings; record claims; request re-scan                                       | `core/remediation.claim_fixed` (→ `pending_verification`, never `verified_fixed`); `core/scheduling/dispatcher` for scans                                                                                                                                                                              | No storage for received evidence; a write path needing idempotency and service identity.                                                                                                                                               |

Three conclusions follow:

1. **The assessment read side already exists, in the wrong place and the wrong
   shape.** GAP-15's export is the one place that correctly walks a scan's
   verdicts (all three payload shapes, host deduplication, ERROR kept distinct
   from MANUAL_REVIEW, the enabled-and-active framework intersection). Building
   the contracts beside it would create a second implementation of the most
   defect-prone logic in the product — exactly what GAP-15 was built to prevent.
   **It must be extracted and shared, not duplicated.**
2. **Contract 1's mapping is a pure read over the compliance catalogue**, and
   can be built and tested now with no storage.
3. **Everything that writes, stores or delivers belongs to a later phase**:
   received baselines and incident evidence need tables, idempotency and
   service identity; events need an outbox; posture needs the dashboard
   extraction.

---

## 2. Proposed Phase 5 scope

### In scope

| Step | Deliverable                                                                                                                                                                                                                                               | Contracts it serves              |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| 5.1  | `ccure_audit/` skeleton (`services/`, `integration/`); typed **views**; new layer rules; the Phase 4 "nothing imports contracts" guard narrowed to "only `ccure_audit.integration`"                                                                       | all                              |
| 5.2  | `ComplianceCatalogueService` — framework/control resolution, rules per control, mapping state, tenant framework capabilities                                                                                                                              | 1, Capabilities, 2, 3            |
| 5.3  | `BaselineMappingService` — stateless: a baseline's controls and scope in, a coverage view out. No storage, no activation                                                                                                                                  | 1                                |
| 5.4  | `AssessmentReadService` — **extracted from `reporting/exports.py`**: scan descriptor, per-host verdicts, check → control map, per-asset coverage/methods/credential outcome. `exports.py` keeps its public functions and renders from the service's views | 2, 3, 4 (`assessment.completed`) |
| 5.5  | `FindingReadService` — typed findings for an assessment or asset with remediation, SLA and exploit intel; cursor paging. Also extracted from `exports.py`                                                                                                 | 3, 4                             |
| 5.6  | Integration mappers — pure functions, views → contract models, for 5.2–5.5: `BaselineCoverage`, `Capabilities`, `AssessmentResult`, findings page, `FindingV1`                                                                                            | 1, 3, 4, Capabilities            |

### Out of scope (later phases)

| Item                                                                                                | Why not now                                                                                         |
| --------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Routes under `/api/v1/integrations/`, service identities, scopes, tenant check                      | The integration surface; needs platform service identity (D4). Plan Phase 7.                        |
| Outbox, delivery worker, pull feeds, dead-letter UI                                                 | Plan Phase 7.                                                                                       |
| Tables: received baselines, incident evidence, outbox, idempotency keys (`integration_*`)           | New storage; "no database redesign" in this phase. Plan Phase 7.                                    |
| Baseline activation workflow (Q1)                                                                   | Needs stored baselines.                                                                             |
| `PostureReadService`                                                                                | Needs the dashboard queries extracted from `routers/dashboard.py` first — a separate, larger move.  |
| `FindingEventSource` (comparison + remediation-event relay + SLA-breach check)                      | Produces events; only meaningful with an outbox.                                                    |
| `IncidentEvidenceService`, `RemediationClaimService`                                                | Write paths; need idempotency and service identity.                                                 |
| `EvidenceReadService`                                                                               | Blocked on the redaction policy (Q7).                                                               |
| Gap-report assembly (contract 2)                                                                    | Needs a stored, activated baseline. The views it needs are delivered in 5.2–5.5.                    |
| Recording per-method outcomes for every scan path                                                   | Changes what scans record — "do not change scanning behaviour". Plan Phase 6. Until then `unknown`. |
| Stable asset identity (Q5)                                                                          | Deferred by the Phase 4 review.                                                                     |
| Module slots (`ccure_policy/`, `ccure_rank/`, `ccure_ir/`), CODEOWNERS, per-module Alembic branches | The plan's original Phase 5; see §9.                                                                |

---

## 3. Files introduced and moved

**New** (nothing imports them except tests until the integration phase):

```
Backend/ccure_audit/
  __init__.py                    package docstring: the module boundary and its rules
  services/
    __init__.py
    views.py                     frozen dataclasses — Audit's own typed results (§4)
    compliance_catalogue.py      5.2
    baseline_mapping.py          5.3
    assessment_read.py           5.4  (logic moved from reporting/exports.py)
    finding_read.py              5.5  (logic moved from reporting/exports.py)
  integration/
    __init__.py
    vocabulary.py                Audit value → contract enum (CheckOutcome → AssessmentState, …)
    mappers/
      baseline_coverage.py       CoverageView        → CcureBaselineCoverageV1
      capabilities.py            capability views    → CcureCapabilitiesV1
      assessment_result.py       AssessmentView      → CcureAssessmentResultV1
      findings.py                FindingView         → CcureFindingV1 / findings page
Backend/tests/audit_boundary/    new test group (basenames unique across groups)
```

**Moved** — the read half of `reporting/exports.py`. The functions below span
about 425 non-blank lines of its 1,348; only their query and assembly parts
move (estimated 300–400 lines), and the exact split is settled in the step:

| From `reporting/exports.py`                                       | To                                                                            |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| `_HostAudit`, `_collect_host_audits`, `_dedupe_host_audits`       | `ccure_audit/services/assessment_read.py`                                     |
| `ControlRef`, `control_map_for_checks`                            | `ccure_audit/services/assessment_read.py` (used by the catalogue service too) |
| `scan_context` (the query part)                                   | `ccure_audit/services/assessment_read.py`                                     |
| `finding_context_map` and the query half of `finding_export_rows` | `ccure_audit/services/finding_read.py`                                        |

`reporting/exports.py` keeps **every public function with its current
signature** (`export_payload`, `compliance_verdict_rows`,
`finding_export_rows`, `scan_context`, …) and becomes a renderer: it asks the
service for views and turns them into rows. `routers/reports.py`, the
measurement script and the 88 existing export tests need no change. This
follows the Phase 3 pattern — move the logic down, keep the old entry point.

**Not moved:** anything under `core/`, `engines/`, `scans/`, `db/`,
`orchestrator/` or `routers/`. The services _use_ those modules; relocating
them into `ccure_audit/` is plan Phase 8 and happens one capability at a time.

---

## 4. Views: the internal boundary type

Services return **frozen dataclasses of primitives** (`str`, `int`, `bool`,
`datetime`, tuples of other views). Never an ORM object, never a SQLAlchemy
`Row`, never a lazily loaded attribute.

- **Why not return the contract models directly?** Contracts are versioned for
  other modules; services are Audit's own API. If services spoke contract
  types, a `v2` contract would force a change to every service, and Audit's
  own UI and reports would depend on the external schema. The adapter owns the
  translation, so a new contract version is a new mapper.
- **Why not return ORM rows?** A row carries its session: reading an attribute
  after the session closes raises or silently issues a query, and a row
  exposes every column including ones no consumer should see. Views make the
  boundary structural.
- **Views keep Audit's own vocabulary** (`"pass"`, `"error"`,
  `"credentialed_package"`). The adapter's `vocabulary.py` maps it onto the
  contract enums, which is where the Phase 4 mapping tables (contract doc §5)
  become code.

Example shape (illustrative, not final):

```python
@dataclass(frozen=True)
class CheckVerdictView:
    check_id: str
    title: str
    severity: str
    outcome: str                  # CheckOutcome value: pass|fail|not_applicable|manual_review|error
    reason: str | None
    host: str
    asset_id: str | None
    controls: tuple[ControlRefView, ...]
    evidence_text: str | None     # already redacted
```

---

## 5. Services and the contracts each will implement

| Service                                               | Phase | Responsibility                                                                                                                                                                                                                                     | Reads                                                                            | Contracts (eventually)                    |
| ----------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- | ----------------------------------------- |
| `ComplianceCatalogueService`                          | 5     | Resolve `(framework code, version, control id)` to Audit's control; list its active rules; classify AUTOMATED / PARTIALLY_AUTOMATED / ATTESTATION_REQUIRED / UNKNOWN_CONTROL / UNSUPPORTED; tenant framework capabilities and parameter vocabulary | compliance catalogue tables, `core/compliance_frameworks`                        | 1, Capabilities; control refs for 2 and 3 |
| `BaselineMappingService`                              | 5     | Map a baseline's controls and parameters; narrow its scope against the org's authorised scope; return a coverage view                                                                                                                              | catalogue service; `core/scan_scope`                                             | 1                                         |
| `AssessmentReadService`                               | 5     | One assessment as views: descriptor, per-host verdicts, check → control map, per-asset coverage, methods (`unknown` where unrecorded) and credential outcome                                                                                       | `scans`, `scan_phases`, stored payload, assets                                   | 2, 3, 4 (`assessment.completed`)          |
| `FindingReadService`                                  | 5     | Findings for an assessment or asset with remediation, SLA, exploit intel; cursor paging                                                                                                                                                            | `asset_vulnerabilities`, `core/remediation/sla`                                  | 3 (findings pages), 4 (event payload)     |
| `PostureReadService`                                  | later | Current posture counts                                                                                                                                                                                                                             | queries extracted from `routers/dashboard.py`, `remediation_report_payload`      | 3 (PostureSnapshot)                       |
| `FindingEventSource`                                  | later | Detected / reappeared from `compare_scans`; verified / accepted / expired from `finding_remediation_events`; SLA breach from a periodic `sla_due_at` check                                                                                         | comparison, remediation events                                                   | 4                                         |
| `BaselineStore` + activation                          | later | Store received baselines immutably; `pending_review` → active by an Audit administrator (Q1)                                                                                                                                                       | new `integration_policy_baselines`                                               | 1, 2                                      |
| `GapReportService`                                    | later | Join an active baseline's coverage with an assessment's verdicts                                                                                                                                                                                   | catalogue, assessment read, baseline store                                       | 2                                         |
| `IncidentEvidenceService` + `RemediationClaimService` | later | Store IR evidence read-only; apply claims through `core/remediation.claim_fixed`; request re-scans through the scheduler                                                                                                                           | new `integration_incident_evidence`; remediation workflow; scheduling dispatcher | 5                                         |
| `EvidenceReadService`                                 | later | One redacted evidence record                                                                                                                                                                                                                       | finding evidence, check observations, `compliance_evidence_files`                | EvidenceRecord (2, 3, 4)                  |

The later services depend only on the Phase 5 ones and on existing `core/`
modules — none of them needs a Phase 5 service redesigned.

---

## 6. Dependency direction

**Before (today):**

```
routers/reports ─► reporting/exports ─► db, core.findings, core.remediation, core.compliance_frameworks
ccure_contracts (leaf; imported by nothing)
```

**After Phase 5:**

```
routers/reports ─► reporting/exports (renderer) ─► ccure_audit.services ─► db, core.*
                                                          ▲
ccure_audit.integration ─► ccure_contracts                │
          └──────────────────────────────────────────────┘
(nothing imports ccure_audit.integration until the integration phase)
```

**New layer rules** (added to `scripts/architecture/layer_rules.py`, enforced
in CI like the existing nine):

| Rule                                     | Importer                                                 | Forbidden                                                                                                          | Why                                                                                                                            |
| ---------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| `integration-is-an-adapter`              | `ccure_audit.integration`                                | `db`, `core`, `engines`, `scans`, `orchestrator`, `reporting`, `routers`, `scan_helpers`, `auth`, `main`, `config` | The adapter translates views to contracts. Reaching past the services to the database is how an ORM row ends up in a contract. |
| `services-do-not-speak-contracts`        | `ccure_audit.services`                                   | `ccure_contracts`, `ccure_audit.integration`, `routers`, `main`, `core.tasks`                                      | A contract version must never force a service change; services are not HTTP handlers or task hubs.                             |
| `foundations-do-not-import-audit-module` | `core`, `engines`, `scans`, `orchestrator`, `db`, `auth` | `ccure_audit`                                                                                                      | The new module sits above the existing capabilities, never below them — otherwise it re-creates the cycles Phase 3 removed.    |

The Phase 4 guard `test_nothing_in_the_application_imports_the_contracts_yet`
becomes "only `ccure_audit.integration` imports `ccure_contracts`", and a new
guard says "nothing imports `ccure_audit.integration` yet".

`reporting → ccure_audit.services` is a **new edge**, and deliberate:
`reporting/` stays above the services until its renderers move into
`ccure_audit/` in plan Phase 8. It breaks no existing rule.

---

## 7. Existing capabilities affected

| Capability                                              | Effect                                                                                                           |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| **Exports** (`GET /reports/export/{id}`, XLSX download) | Read logic moves into the services; output must stay **byte-identical**. The only capability whose code changes. |
| Compliance catalogue                                    | Read-only use. No change.                                                                                        |
| Remediation / SLA                                       | Read-only use of `sla_state`. No change.                                                                         |
| Scan comparison (GAP-13)                                | Read-only use. No change.                                                                                        |
| Scanning, discovery, credentialed audit, web scanning   | **Unaffected.** No scan code is edited.                                                                          |
| Dashboard, PDF reports, compliance reports              | Unaffected.                                                                                                      |
| Database                                                | Unaffected: no table, column or migration.                                                                       |

---

## 8. Risks

| Risk                                                                        | Likelihood | Impact | Mitigation                                                                                                                                                                                |
| --------------------------------------------------------------------------- | ---------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The export's output changes during the extraction                           | Medium     | High   | Golden test: render every export dataset for the test fixtures before the move and assert byte equality after; the 88 export tests; `measure_export_coverage.py` before and after.        |
| A view leaks an ORM object (lazy load after the session closes)             | Medium     | Medium | Views are frozen dataclasses of primitives; a test walks every view a service returns and fails on anything from `sqlalchemy`.                                                            |
| Mapping-state heuristic is wrong (what counts as "automated")               | Medium     | High   | Classify from the rules themselves (`evidence_source = 'manual'` marks a placeholder) and check it against the real catalogue: ISO A.8.8/A.8.9 automated, A.5.1/A.5.17/A.7.4 attestation. |
| Tenant leakage in a new query                                               | Low        | High   | Every service method takes `org_id` and filters on it; a two-tenant fixture test for each.                                                                                                |
| Performance regression (the export was tuned to four queries for 955 rules) | Low        | Medium | The moved code keeps its queries; a query-count assertion on the largest fixture.                                                                                                         |
| Dead code: services nothing calls in production                             | Certain    | Low    | Deliberate until the integration phase; guard tests stop accidental wiring; the exports refactor gives the read services a real production caller from day one.                           |
| Scope creep into the integration phase (routes, tables)                     | Medium     | Medium | This document's out-of-scope table; layer rules; the "nothing imports the adapter yet" guard.                                                                                             |
| Method outcomes are mostly `unknown`, so contract 3's coverage looks weak   | Certain    | Low    | Honest by design (unknown is never completed). Plan Phase 6 records the outcomes; the contract does not change.                                                                           |

---

## 9. Relationship to the plan's roadmap

The plan's original **Phase 5** was _module slots and the team model_ (empty
`ccure_policy/`, `ccure_rank/`, `ccure_ir/` packages, manifests, CODEOWNERS,
per-module Alembic branches). This proposal is instead the Audit-internal half
of the plan's Phases 7–8 that the contracts need first. Recommended ordering:

1. **Phase 5 (this proposal)** — Audit's internal boundaries.
2. **Phase 5b** — module slots and team model, unchanged from the plan, when
   the other teams are ready to start.
3. **Phase 6** — record per-method outcomes (the coverage model).
4. **Phase 7** — the integration surface: service identity, tenant check,
   `integration_*` tables, outbox, feeds, the "later" services above.

---

## 10. Test strategy

- **New test group `tests/audit_boundary/`** (no `__init__.py`; unique
  basenames, per CLAUDE.md).
- **Views are pure data:** a test walks every view each service returns and
  fails on any SQLAlchemy object, mutable container or naive datetime.
- **Exports equivalence (step 5.4–5.5):** before the move, capture every
  dataset `export_payload` produces for the existing fixture scans (all three
  credentialed payload shapes, a multi-host scan, a policy-narrowed scan, a
  scan with no configuration audit); after the move, assert byte equality. The
  existing 88 export tests run unchanged.
- **Services against `ccure_pytest_db`:** two tenants in every fixture; each
  service is asserted to return nothing from the other tenant.
- **Catalogue classification against real content:** load the shipped ISO and
  NIST CSF seeds and assert the mapping state of known controls.
- **Mappers produce valid contracts:** for each fixture assessment, build
  `CcureAssessmentResultV1` / findings pages / `CcureBaselineCoverageV1` /
  `CcureCapabilitiesV1` through the mappers and validate them with the Phase 4
  models. Assert the semantic rules survive the real data: an unassessed asset
  gets `finding_counts: null`; an ERROR check is `ERROR`, not `MANUAL_REVIEW`;
  an unrecorded method is `unknown`.
- **Architecture:** the three new layer rules with positive and negative
  examples; the narrowed contracts guard; the "nothing imports the adapter"
  guard; 0 violations and 0 cycles.
- **Regression:** the full backend suite before each commit that touches
  `reporting/exports.py`; `tests/repo`, `tests/reports` and the new group on
  every step.
- **One commit per step (5.1–5.6)**, each with the per-step report used in
  Phase 3.

---

## 11. Decisions needed from the reviewers

1. **Approve extracting the export's read logic into `AssessmentReadService` /
   `FindingReadService`** (steps 5.4–5.5), rather than building the contracts'
   read path beside it. This is the only Phase 5 step that changes existing code.
2. **Accept the transitional `reporting → ccure_audit.services` edge** until
   renderers move in plan Phase 8.
3. **Accept that services return Audit-internal views, not contract types**
   (§4).
4. **Confirm the roadmap order** in §9 (module slots become Phase 5b).
5. **Confirm the "automated" rule** for the catalogue service: a control is
   AUTOMATED when it has at least one active rule whose evidence source is not
   `manual`; PARTIALLY_AUTOMATED when it also keeps a manual placeholder;
   ATTESTATION_REQUIRED when all its active rules are manual.

# CCure Integration Contracts — v1 (Phase 4 draft)

|                        |                                                                                                                                                                                           |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Review**             | **Approved 26 Sep 2026** as the architectural baseline for CCurePro module integration, with the clarifications in §14.1.                                                                 |
| **Status**             | **Draft for review.** Definitions only: no route serves these contracts, no task emits them, no production behaviour has changed.                                                         |
| **Date**               | 25 Sep 2026                                                                                                                                                                               |
| **Programme**          | Modular-platform programme, Phase 4 (plan: `docs/architecture/CCURE_PLATFORM_MODULAR_ARCHITECTURE.md` §7–§8)                                                                              |
| **Machine definition** | `Backend/ccure_contracts/` — Pydantic models, generated JSON Schemas, worked examples                                                                                                     |
| **Guarded by**         | `Backend/tests/repo/test_integration_contracts.py`, and the `contracts-are-leaves` rule in `Backend/scripts/architecture/layer_rules.py`                                                  |
| **Requirements**       | _SRS for CcurePro Platform v1.0_ §7.6 (inter-module interfaces), §7.3 (Audit), §7.2 (Policy Pro), §7.4 (IR), §7.5 (Rank); _Design Document for CcurePro Platform v1.0_ §3 (interface map) |
| **Reviewers needed**   | Policy Pro, Rank, IR and Audit teams; platform owner (decision D6)                                                                                                                        |

This document defines what the four CCure modules exchange — **Policy Pro**,
**CCure Audit**, **CCure Rank** and **CCure IR** — before any more structural
work is done inside Audit. It is written so each team can review the contracts
that concern it without reading Audit's code, and so that nothing here depends
on how the other three modules will be built.

---

## 1. What this document decides

1. **Five contracts**, plus the supporting resources they need:

   | #   | Direction          | Contract                                                  | Delivery                                  |
   | --- | ------------------ | --------------------------------------------------------- | ----------------------------------------- |
   | 1   | Policy Pro → Audit | `PolicyBaseline`, answered by `BaselineCoverage`          | Push to Audit; synchronous answer         |
   | 2   | Audit → Policy Pro | `ComplianceGapReport`                                     | Push to Policy Pro + pull feed from Audit |
   | 3   | Audit → Rank       | `AssessmentResult` (immutable) + `PostureSnapshot` (now)  | Push + pull feed; snapshot pull only      |
   | 4   | Audit → IR         | `FindingEvent`                                            | Push + pull feed                          |
   | 5   | IR → Audit         | `IncidentEvidence`, answered by `IncidentEvidenceReceipt` | Push to Audit; synchronous answer         |
   | —   | Any → Audit        | `Capabilities`, `EvidenceRecord`, `Problem`               | Pull; `Problem` is the error body         |

2. **Ownership follows the SRS split and is written into every field.** Policy
   Pro owns policy. Audit owns executable assessment rules, scanning, findings,
   evidence and assessment results. Rank owns scoring and maturity. IR owns
   incidents and response. Each property in each JSON Schema carries
   `x-ccure-owner`, and a test fails on any property without one (§4.14).

3. **Policy Pro never sends an executable check.** It sends controls,
   applicability and organisation parameters; Audit maps controls onto its own
   rules. The baseline model forbids unknown fields, so a command, query,
   registry path or OVAL body cannot be smuggled in (§6).

4. **Six assessment states, and absence is never PASS** (§5.1). Every
   unavailable value is carried as an explicit state with a reason, never as
   `0`, `false` or an empty list (§4.14).

5. **Audit remains fully functional with none of the other modules present**
   (§2). Every integration is optional, and a consumer being down never affects
   a scan.

6. **HTTPS with a self-describing JSON envelope, not a message bus.** The
   design document names Apache Kafka; v1 deliberately does not introduce it
   (§4.12). The envelope is transport-neutral, so a bus can carry the same
   messages later without a contract change.

7. **Contracts never expose Audit's internal models.** `ccure_contracts`
   imports only the standard library and Pydantic, and a layer rule stops it
   importing any module's code (§3).

---

## 2. Decision: Audit works without Policy Pro, Rank and IR

**Audit must remain fully functional when none of the other three modules
exists, is reachable, or is configured.** This is golden rule 5 of the plan and
the SRS's own premise ("each module can work on its own", §7.6.1). Concretely:

- **Compliance without Policy Pro.** Audit ships its own framework catalogues
  and rules; SRS 7.3.2 says auditing "can also be manually configured". A
  received baseline _adds_ a mapping and a gap report; its absence removes
  nothing.
- **Findings, reports and remediation without Rank or IR.** Everything Audit
  shows its own users is computed inside Audit. Contracts 2–4 only _publish_
  what Audit already has.
- **No scan depends on a delivery.** Outbound messages are written to an outbox
  in the same transaction as the result and delivered afterwards (plan §8.3). A
  consumer that is down delays delivery; it never fails, rolls back or slows an
  assessment.
- **Inbound endpoints fail closed and alone.** If the integration layer is
  disabled, the inbound endpoints answer `503 integration_disabled` and nothing
  else in Audit changes.
- **No inbound message can widen what Audit does.** A baseline scope can only
  narrow the tenant's authorised scan scope; an IR re-scan request is a request,
  subject to the same scope and quota as a person's.

---

## 3. Where the contracts sit

The structure you asked for, and where each layer lives in this repository:

```
External API contract          ccure_contracts/                 ← Phase 4 (this document)
        │                      shared by all four modules; imports nothing of theirs
        ▼
Audit integration adapter      ccure_audit/integration/         ← Phase 7
        │                      validate · authorise · translate contract ⇄ Audit service calls
        │                      outbox · delivery worker · pull feeds
        ▼
Audit application services     ccure_audit/services/            ← Phases 5–8
        │                      one per capability; own transactions and persistence
        ▼
Audit domain / capabilities    ccure_audit/engines/, core/…     ← exists today
        │                      discovery, config audit, SCAP, vuln matching, compliance evaluation
        ▼
Infrastructure                 db/, adapters/, Celery, Redis    ← exists today
```

Rules that make the top layer a real boundary:

- **`ccure_contracts` is a leaf.** It imports the standard library, Pydantic and
  itself. `contracts-are-leaves` (a layer rule, enforced in CI with the other
  eight) and `test_contracts_import_only_the_standard_library_and_pydantic`
  both fail on anything else.
- **Translation happens only in the adapter.** Contract types are built from
  service results in `ccure_audit/integration/`, never by passing an ORM row
  through. Audit identifiers appear in contracts only as opaque strings.
- **Nothing uses the contracts yet.** `test_nothing_in_the_application_imports_the_contracts_yet`
  fails if any application module imports `ccure_contracts`. It is deleted in
  the phase that builds the adapter.

---

## 4. Conventions every contract follows

### 4.1 Endpoints

All endpoints Audit serves live under `/api/v1/integrations/`. They are
separate from the user-facing API: different authentication (§4.2), different
rate limits, and a separate OpenAPI tag.

| Method | Path                                                                              | Contract          | Scope                               | Caller     |
| ------ | --------------------------------------------------------------------------------- | ----------------- | ----------------------------------- | ---------- |
| POST   | `/api/v1/integrations/policy-baselines`                                           | 1 → Coverage      | `audit:policy_baselines:write`      | Policy Pro |
| GET    | `/api/v1/integrations/policy-baselines/{baseline_id}/versions/{version}/coverage` | 1 Coverage        | `audit:policy_baselines:read`       | Policy Pro |
| GET    | `/api/v1/integrations/compliance-gap-reports?cursor=&limit=`                      | 2 page            | `audit:compliance_gap_reports:read` | Policy Pro |
| GET    | `/api/v1/integrations/compliance-gap-reports/{report_id}`                         | 2                 | `audit:compliance_gap_reports:read` | Policy Pro |
| GET    | `/api/v1/integrations/assessment-results?cursor=&limit=`                          | 3 page            | `audit:assessment_results:read`     | Rank       |
| GET    | `/api/v1/integrations/assessment-results/{result_id}`                             | 3                 | `audit:assessment_results:read`     | Rank       |
| GET    | `/api/v1/integrations/assessment-results/{result_id}/findings?cursor=`            | 3 findings page   | `audit:assessment_results:read`     | Rank       |
| GET    | `/api/v1/integrations/assessment-results/{result_id}/controls?cursor=`            | 3 controls page   | `audit:assessment_results:read`     | Rank       |
| GET    | `/api/v1/integrations/posture`                                                    | 3 PostureSnapshot | `audit:posture:read`                | Rank       |
| GET    | `/api/v1/integrations/finding-events?cursor=&limit=&min_severity=`                | 4 page            | `audit:finding_events:read`         | IR         |
| POST   | `/api/v1/integrations/incident-evidence`                                          | 5 → Receipt       | `audit:incident_evidence:write`     | IR         |
| GET    | `/api/v1/integrations/evidence/{evidence_id}`                                     | EvidenceRecord    | `audit:evidence:read`               | any        |
| GET    | `/api/v1/integrations/evidence/{evidence_id}/content`                             | file bytes        | `audit:evidence:read`               | any        |
| GET    | `/api/v1/integrations/capabilities`                                               | Capabilities      | `audit:capabilities:read`           | any        |

**Push endpoints are owned by the consumer**, not designed here. Audit POSTs
the same message body it serves on the pull feed to a URL each consumer
registers (Policy Pro for contract 2, Rank for 3, IR for 4). The consumer's
only obligations are: authenticate Audit's service identity, answer 2xx once
the message is durably stored, and treat `message_id` as an idempotency key.

### 4.2 Authentication and service identity

- **Every call is made by a service identity, never a user.** The credential is
  a platform-issued token presented as `Authorization: Bearer <token>`, bound to
  one module and — normally — one tenant. Whether it is an OAuth2
  client-credentials JWT or a platform API key is open decision **D4**; the
  contracts do not depend on the answer. The design document says "service API
  key authentication"; either satisfies it.
- **Scopes are permission atoms** in the existing `resource:action` form,
  prefixed with the owning module: `audit:policy_baselines:write` etc. (table
  above). The platform RBAC stores them; each module declares its own.
- **Every call is written to the tamper-evident audit log** with its
  `correlation_id`, service identity and outcome (SRS 7.6.1: "logged for audit
  purposes").
- **Integration endpoints carry their own rate limits** (the per-endpoint
  limiter already used by the user API), sized for machine traffic.
- **In-process calls follow the same rules.** When two modules run in one
  deployment and call each other through the platform's in-process adapter
  (plan §3.4), they still present a service identity and are still authorised
  and logged.

### 4.3 Tenant

- `tenant_id` is the platform organisation id (today's `organizations.id`, e.g.
  `org_default`). It is carried in every message body so a stored or forwarded
  message stays self-describing.
- **It is checked, never trusted.** The receiver compares it with the tenant
  bound to the caller's credential and refuses a mismatch with
  `403 tenant_mismatch`. A platform-wide service (for example, a national Rank
  deployment) must hold an explicit grant for each tenant it names.
- A bare header naming the tenant is not accepted. That would recreate finding
  F1's cross-tenant defect on the integration surface.

### 4.4 Envelope

Every message except the error body carries these fields at the top level, with
the payload under `data` (or, for pages, `items` and `position`):

| Field            | Type           | Owner    | Meaning                                                                                        |
| ---------------- | -------------- | -------- | ---------------------------------------------------------------------------------------------- |
| `contract`       | string literal | producer | e.g. `ccure.audit.policy_baseline`. A message is validated against the model its name selects. |
| `schema_version` | `1.<minor>`    | producer | Contract schema version (§4.9).                                                                |
| `message_id`     | UUID           | producer | Unique per message, **stable across retries**; the idempotency key.                            |
| `tenant_id`      | opaque id      | platform | The organisation (§4.3).                                                                       |
| `source`         | object         | producer | `module`, `module_version`, optional `instance`.                                               |
| `produced_at`    | RFC 3339 + TZ  | producer | When the message was produced.                                                                 |
| `correlation_id` | opaque id      | producer | Shared by every message and log line caused by one originating event.                          |
| `causation_id`   | UUID, optional | producer | `message_id` of the message that directly caused this one.                                     |

### 4.5 Identifiers

- **Every identifier is minted by the module that owns the object, and is opaque
  to everyone else.** Pattern `^[A-Za-z0-9][A-Za-z0-9._:@-]*$`, at most 400
  characters. A consumer stores and returns an id; it never parses one.
- Audit's current ids embed an organisation slug and an IP address
  (`ast_org_default_192_0_2_10`, `fnd_<asset>_<source>_<definition>`). That is
  exactly why they are declared opaque: reading meaning out of them is the
  coupling this programme removes. It also means **an Audit asset id changes
  when the asset's IP changes**, so asset references carry `ip_address`,
  `mac_address` and `hostname` beside the id. A stable, IP-independent asset
  identity is a future Audit domain change (Q5, deferred) and is not part of
  Phase 5.
- Framework and control identifiers are a shared vocabulary: `framework.code` +
  `framework.version` + `control_id` as the framework publishes it, e.g.
  `ISO27001_2022` / `2022` / `A.8.9`. Who governs that vocabulary is open
  decision **D3**.

### 4.6 Timestamps

RFC 3339, timezone required (`Z` recommended). A timestamp without an offset is
refused at validation — a naive time renders as local time beside UTC siblings,
the defect CLAUDE.md records for scan payloads.

### 4.7 Correlation

- A new root event (a policy approval, a scan completing, an incident closing)
  starts a new `correlation_id`. Every message it causes — the coverage answer,
  the gap report, the finding events, a re-scan request — carries the same one,
  and names its immediate cause in `causation_id`.
- An inbound request may also send an `X-Correlation-ID` header; if present it
  must equal the body's value.
- Every log line and audit-log entry about the message records it.

### 4.8 Idempotency

- **Inbound.** The receiver records `message_id`. A repeat with the same id and
  identical content returns the original response and does nothing else; the
  same id with _different_ content is `409 idempotency_conflict`.
- **Versioned objects are immutable.** A baseline version (contract 1) and an
  incident version (contract 5) are write-once. Re-sending the same version with
  the same content is an idempotent replay (200, original answer); with
  different content it is `409 version_conflict`. A change is a new version.
- **Outbound.** Delivery is at least once. Consumers deduplicate on
  `message_id`. Retries resend the identical message, never a regenerated one.

### 4.9 Versioning

- **Two version numbers, deliberately separate.** The URL carries the API
  generation (`/api/v1/…`); each message carries its own `schema_version`
  (`1.<minor>`). Contracts version independently: a v2 baseline does not force
  a v2 finding event.
- **Minor versions only add optional fields.** Removing, renaming, retyping or
  making a field required is a new major version, served beside the old one.
- **Receivers are tolerant of a newer minor version.** A receiver that knows
  `1.k` and receives `1.m` with `m > k` accepts it, ignores the fields it does
  not know, and logs which it ignored with the message's `correlation_id`. A message of a major
  version it does not support is `400 unsupported_schema_version`, naming the
  versions it does support.
- **Published schemas are exact.** The committed JSON Schema of each version
  sets `additionalProperties: false`: it describes precisely what that version
  carries, and producers validate their own output against it before sending.
- **Drafts may change; published schemas may not.** Every v1 contract is
  `x-ccure-status: draft` until this review signs it off. On publication its
  digest is pinned in `ccure_contracts/schema_lock.json`, and
  `test_published_contracts_are_pinned` fails if a published schema changes
  without a new version.
- **Deprecation.** A superseded major version stays supported for an agreed
  window after its successor is published (open decision **D5**; 12 months is
  proposed). `Capabilities` lists the versions each deployment speaks.

### 4.10 Error model

Errors are RFC 9457 problem details (`application/problem+json`), schema
`common/v1/schemas/Problem.schema.json`:

```json
{
  "type": "https://ccurepro.cdac.in/problems/version_conflict",
  "title": "Baseline version already received with different content",
  "status": 409,
  "detail": "pp-baseline-infosec-core version 4 was received on 2026-09-25T09:12:05Z with a different content digest. Send the change as version 5.",
  "code": "version_conflict",
  "correlation_id": "corr-pp-approval-2f6c1b",
  "retryable": false
}
```

| `code`                       | HTTP | Retryable     | When                                                                    |
| ---------------------------- | ---- | ------------- | ----------------------------------------------------------------------- |
| `invalid_payload`            | 422  | no            | Fails the schema or a semantic rule; `errors[]` gives JSON Pointers     |
| `unsupported_schema_version` | 400  | no            | Unknown major version                                                   |
| `unsupported_contract`       | 400  | no            | `contract` names nothing this endpoint accepts                          |
| `unauthenticated`            | 401  | after re-auth | Missing, expired or invalid credential                                  |
| `insufficient_scope`         | 403  | no            | Credential lacks the scope                                              |
| `tenant_mismatch`            | 403  | no            | Body tenant ≠ credential tenant                                         |
| `not_found`                  | 404  | no            | Unknown id **in this tenant** (another tenant's id is also `not_found`) |
| `version_conflict`           | 409  | no            | Same object version, different content                                  |
| `idempotency_conflict`       | 409  | no            | Same `message_id`, different content                                    |
| `payload_too_large`          | 413  | no            | Over the endpoint's size limit                                          |
| `rate_limited`               | 429  | yes           | After `Retry-After`                                                     |
| `integration_disabled`       | 503  | later         | Integration switched off for this deployment or tenant                  |
| `unavailable`                | 503  | yes           | Temporary; honour `Retry-After`                                         |
| `internal_error`             | 500  | yes           | With backoff                                                            |

`detail` never echoes a secret, a credential or another tenant's data.

### 4.11 Retry expectations

- **Who retries:** the sender. Audit retries its pushes; Policy Pro and IR
  retry theirs.
- **What is retried:** network failures, timeouts, `429`, `500`, `502`, `503`,
  `504`. Never another `4xx`: they will fail identically.
- **How:** the identical message (same `message_id`), exponential backoff with
  full jitter starting at 2 s and capped at 5 minutes, honouring `Retry-After`,
  for up to 24 hours. After that the message is dead-lettered and **shown in
  Audit's admin UI**, not only logged (plan §8.3).
- **Timeouts:** 10 s connect + response for a push; the inbound endpoints answer
  within 5 s at the 95th percentile, or accept with `202` and a status URL if a
  mapping would take longer (not expected in v1).
- **Catch-up:** a consumer that was down, or suspects it missed pushes, reads
  the pull feed from its last cursor. Push and pull carry the same messages
  with the same `message_id`s, so reading both is safe.

### 4.12 Delivery: push, pull, and why not Kafka

- **Push is primary.** Exchanges stay event-triggered, as the design document
  requires: a policy approval, a completed scan and a closed incident each send
  their message when they happen.
- **Pull feeds exist beside push** with cursor paging over the same messages.
  They let a consumer that is not built yet — which is true of all three today —
  or one recovering from an outage catch up without Audit depending on how that
  consumer designed its API. They are a recovery path, not a polling
  architecture.
- **Ordering.** Finding events carry a per-tenant `sequence`. It only
  increases; gaps are allowed (a subscription filtered events out). Nothing
  else promises an order across messages.
- **Retention.** Pull feeds keep messages for an agreed window (open question
  **Q6**; 90 days proposed). A cursor older than the window answers `410`, and
  `position.retained_from` says where the feed now starts.
- **No Kafka in v1.** The design document places module traffic on an Apache
  Kafka bus. Phase 4 is scoped not to introduce new infrastructure, and nothing
  in v1 needs a bus: four producers and consumers, low volume, and an outbox
  gives the same "consumer down does not affect producer" property. **The
  envelope is transport-neutral**, so carrying these messages on a bus later
  changes the delivery section of this document, not a single schema.

### 4.13 Read-only and immutability

- **Received data is read-only** (SRS 7.6.1). Every model is frozen and every
  inbound message is stored as received, with Audit's digest of its canonical
  form (`content_sha256`).
- **Immutable by design:** a baseline version; a gap report; an assessment
  result and its findings and controls pages; an incident version and its
  receipt. A correction is a new object that names what it supersedes, never
  an edit (Q9, approved): an `AssessmentResult` made wrong by an Audit defect
  is corrected by a new result carrying `supersedes_result_id` and
  `correction_reason`, and the original stays exactly as published.
- **Deliberately not immutable:** `BaselineCoverage` (it gets a new
  `mapping_revision` when Audit's own rule catalogue changes — the baseline
  stays the same, the ability to assess it does not) and `PostureSnapshot`
  (current state by definition; it carries `valid_as_of`).
- **Canonical form** for every `content_sha256`: the object's JSON with the
  `content_sha256` field removed, keys sorted, no insignificant whitespace,
  UTF-8 — Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

### 4.14 Field ownership and availability

Every property in every generated schema carries:

- **`x-ccure-owner`** — `policy_pro`, `audit`, `rank`, `ir`, `platform` (the
  tenant key and the shared framework vocabulary) or `producer` (envelope
  fields, owned by whichever module sent the message). Only the owner creates
  or changes the value; everyone else treats it as read-only.
- **`x-ccure-availability`** — whether the owner can populate it today:
  `available`, `partial` (some assessment paths only, and explicitly absent on
  the others) or `not_implemented`.
- **`x-ccure-srs`** — the SRS clauses the field exists to satisfy, where one
  applies.

**Unknown is never zero.** A number that may be unavailable is a
`CcureMeasuredValueV1`:

```json
{
  "status": "not_implemented",
  "reason": "Audit has no asset criticality attribute (SRS 7.3.7.3)."
}
```

`status` is `available`, `not_implemented`, `not_collected` or
`not_applicable`. A value is present **exactly** when the status is
`available`, and every other status must give a reason. A not-implemented
value reported as zero is refused at validation:

```json
{ "status": "not_implemented", "value": 0 }
```

Two tests enforce this across all schemas: every property must name an owner,
and no `not_implemented` field may be a bare required value (it must be
optional or a measured value that says why it is absent).

---

## 5. Shared vocabulary

Each enumeration is defined once, in `ccure_contracts/common/v1/vocabulary.py`.
Where Audit already has the concept, the mapping from its internal value is
given here; the adapter owns that translation.

### 5.1 Assessment state

| State            | Means                                               | Verdict? |
| ---------------- | --------------------------------------------------- | -------- |
| `PASS`           | Assessed; the requirement is met                    | yes      |
| `FAIL`           | Assessed; the requirement is not met                | yes      |
| `NOT_ASSESSED`   | Nothing was run against it                          | no       |
| `NOT_APPLICABLE` | Considered; does not apply to the target            | no       |
| `MANUAL_REVIEW`  | Needs a human decision; automation cannot settle it | no       |
| `ERROR`          | Attempted and could not be evaluated                | no       |

Every non-verdict state carries a reason (`state_reason`), and the model
refuses one without it.

**Mapping from Audit.**

| Audit today                                                                                                                                   | Contract state                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CheckOutcome.pass` / `fail` / `not_applicable` / `manual_review`                                                                             | `PASS` / `FAIL` / `NOT_APPLICABLE` / `MANUAL_REVIEW`                                                                                                |
| `CheckOutcome.error`                                                                                                                          | `ERROR`                                                                                                                                             |
| A check a scan's policy did not select; a host with no credential in scope; an audit that never ran (`MISC-CREDENTIALED-CONFIG-NOT-ASSESSED`) | `NOT_ASSESSED`                                                                                                                                      |
| `compliance_findings.status` = `pass` / `fail` / `not_applicable` / `manual_review`                                                           | same                                                                                                                                                |
| `compliance_findings.status` = `exception`, `remediation_applied`, `pending_reverify`                                                         | `disposition` = `exception_approved`, `remediation_applied`, `pending_reverification`; `state` from the last machine verdict (open question **Q4**) |

**The register is not the source for `ERROR`.** `compliance_sync` stores an
`ERROR` check as `manual_review`, because the compliance register has no error
status and must not gain one. The adapter therefore reads per-check outcomes
from the assessment payload (`config_audit.results`), exactly as the GAP-15
export does, so a check that could not run is never reported as one awaiting
human review.

**Roll-up precedence** — for one control over its rules and assets:

```
FAIL  >  ERROR  >  NOT_ASSESSED  >  MANUAL_REVIEW  >  PASS  >  NOT_APPLICABLE
```

A confirmed failure is reported whatever else is unknown, and anything unknown
outranks a pass. Audit's internal `roll_up_statuses` has no `ERROR` or
`NOT_ASSESSED` member and ranks human dispositions among verdicts, so the
adapter computes the contract state with this precedence rather than reusing
the register's (Q4). The model enforces the key consequence: **an automated
`PASS` requires at least one passing asset and none that failed, errored, needs
review or was not assessed.**

### 5.2 Coverage and methods

Each asset carries a `coverage` state and one entry per assessment method:

| Coverage             | Means                                                        |
| -------------------- | ------------------------------------------------------------ |
| `ASSESSED`           | Every method the assessment's scan policy selected completed |
| `PARTIALLY_ASSESSED` | Some did, some did not                                       |
| `NOT_ASSESSED`       | Discovered, but no method beyond discovery completed         |
| `ERROR`              | Assessment of the asset failed                               |

Methods: `discovery`, `port_scan`, `network_checks`, `credentialed_access`,
`package_vulnerability`, `configuration_audit`, `web_application`,
`malware_scan`. Each has an outcome — `completed`, `partial`, `failed`,
`not_run`, `not_implemented`, or `unknown` — and every outcome other than
`completed` gives a reason.

`unknown` exists because Audit does not yet record a structured outcome for
every method on every path. Today it records which assets and finding families
a scan assessed and which configuration checks reached a verdict
(`scans.options["assessment_scope"]`), and the credentialed status per asset.
Where no record exists the adapter says `unknown` — it never infers
`completed` (plan Phase 6 closes this).

**The rule Rank and IR depend on:** an asset whose coverage is `NOT_ASSESSED`
or `ERROR` carries `finding_counts: null`, not zeros. Zero findings on an
unassessed asset means nothing was learned about it. The model refuses zeros
there.

### 5.3 Credentialed assessment

Authentication and coverage are reported separately, because a session that
authenticated can still collect only part of what it asked for.

```json
"credentialed": {
  "outcome": "SUCCEEDED",
  "credential_ref": "cred_default_winadm",
  "transport": "winrm",
  "port": 5985,
  "auth_method": "ntlm",
  "privilege": { "is_administrator": true, "is_system": false },
  "inventory_complete": true
}
```

| `outcome`                 | Operator action it points to                |
| ------------------------- | ------------------------------------------- |
| `SUCCEEDED`               | —                                           |
| `AUTHENTICATION_REJECTED` | Fix the credential                          |
| `INSUFFICIENT_PRIVILEGE`  | Give the account rights                     |
| `UNREACHABLE`             | Firewall, service or port                   |
| `FAILED_UNCLASSIFIED`     | The transport could not say which           |
| `NOT_ATTEMPTED`           | A credential was in scope but was not tried |

- **`credentialed: null` means no credential was in scope for the asset.** That
  is different from a refused credential, and the contract keeps them apart —
  the same distinction `asset_syncer.set_credentialed_status` keeps by leaving
  the attribute unset.
- **Coverage lives in the methods.** A rejected credential appears as
  `credentialed_access: failed`, and `package_vulnerability` and
  `configuration_audit` as `not_run` "requires an authenticated session"; the
  asset is `PARTIALLY_ASSESSED`, never `ASSESSED`.
- **Privilege is tri-state.** `null` means the token could not be read, not
  "no" — reading it as "not an administrator" would attribute a complete
  audit's findings to a partial one.
- **Availability is `partial`.** Audit stores success/failure per asset today.
  The four-way failure classification exists inside the WinRM, SMB and database
  transports but is not yet persisted per asset, so older records map to
  `FAILED_UNCLASSIFIED`.
- The secret is never in a contract. `credential_ref` is Audit's opaque
  credential id.

### 5.4 Other vocabularies

| Vocabulary           | Values                                                                                                      | Audit source                                                        |
| -------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Severity             | `critical`, `high`, `medium`, `low`, `none`, `unscored`                                                     | `scans.cvss.CANONICAL_SEVERITIES`; `unscored` ≠ `none`              |
| Definition type      | `cve`, `config_check`, `plugin_check`, `privilege_check`                                                    | `vulnerability_definitions.definition_type`                         |
| Detection method     | 12 values                                                                                                   | `DetectionMethod` in the finding normaliser                         |
| Detection status     | `open`, `fixed`, `accepted`                                                                                 | `asset_vulnerabilities.status`                                      |
| Remediation state    | `open`, `assigned`, `in_remediation`, `pending_verification`, `verified_fixed`, `reopened`, `risk_accepted` | `REMEDIATION_STATES` — `verified_fixed` is reached only by a scan   |
| SLA state            | `within_sla`, `due_soon`, `overdue`, `resolved`, `pending_verification`, `not_applicable`                   | `core/remediation/sla.SLA_STATES` — `not_applicable` ≠ `within_sla` |
| Exploit availability | `none_known`, `public_exploit`, `verified_exploit`, `actively_exploited`, `not_applicable`                  | `has_exploit`, `verified_exploit`, `in_kev` / VulnCheck canary      |
| Baseline mapping     | `AUTOMATED`, `PARTIALLY_AUTOMATED`, `ATTESTATION_REQUIRED`, `UNKNOWN_CONTROL`, `UNSUPPORTED`                | new                                                                 |
| Parameter handling   | `HONOURED`, `RECORDED_NOT_HONOURED`, `UNKNOWN_PARAMETER`, `INVALID_VALUE`                                   | new                                                                 |

`exploit.availability` describes the vulnerability, not the host. A public
exploit existing does not mean this host is exploitable.

---

## 6. Contract 1 — Policy Pro → Audit: `PolicyBaseline`

**Purpose.** SRS 7.6.2: "once a cybersecurity policy has been finalized and
approved within CcurePolicyPro, it is sent to CcureAudit as a compliance
baseline … the policy defines the standard, and the audit tests whether that
standard is being met". SRS 7.3.1.2 and 7.3.2.2 describe the same import from
Audit's side.

**Ownership.** Policy Pro decides _what_ is required: which controls, whether
each applies, and the organisation's parameter values. Audit decides _how_ it
is checked. The baseline carries **no executable check**: no command, query,
registry path, rule body or OVAL definition, and the model forbids unknown
fields so none can be added (`test_a_policy_baseline_cannot_carry_an_executable_check`).
`requirement_text` is for display to Audit users only; Audit never derives a
check from it.

|                 |                                                                                                                      |
| --------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Endpoint**    | `POST /api/v1/integrations/policy-baselines`                                                                         |
| **Trigger**     | A policy is approved or updated in Policy Pro                                                                        |
| **Request**     | `PolicyBaseline` — `policy_baseline/v1/schemas/PolicyBaseline.schema.json`                                           |
| **Response**    | `201` new version, `200` idempotent replay — body `BaselineCoverage`                                                 |
| **Scope**       | `audit:policy_baselines:write`                                                                                       |
| **Identifiers** | `baseline_id` + `baseline_version` (Policy Pro); `requirement_id` per control (Policy Pro); `content_sha256` (Audit) |
| **Idempotency** | Same id + version + content → original coverage; different content → `409 version_conflict`                          |
| **Errors**      | `invalid_payload`, `tenant_mismatch`, `version_conflict`, `payload_too_large` (proposed limit: 5,000 controls, Q12)  |
| **Retry**       | Policy Pro retries transient failures with the same `message_id`                                                     |

**Request (abridged — full file: `policy_baseline/v1/examples/policy_baseline.request.json`):**

```json
{
  "contract": "ccure.audit.policy_baseline",
  "schema_version": "1.0",
  "message_id": "0f1c7d8e-3b52-4a8e-9a55-5d2f0f6f1a01",
  "tenant_id": "org_default",
  "source": { "module": "policy_pro", "module_version": "0.1.0" },
  "produced_at": "2026-09-25T09:12:04Z",
  "correlation_id": "corr-pp-approval-2f6c1b",
  "data": {
    "baseline_id": "pp-baseline-infosec-core",
    "baseline_version": 4,
    "supersedes_version": 3,
    "policy": {
      "policy_id": "pp-policy-0012",
      "policy_version": "4.0",
      "title": "Information Security Policy — Core Technical Controls"
    },
    "status": "approved",
    "approved_at": "2026-09-25T09:12:00Z",
    "effective_from": "2026-10-01T00:00:00Z",
    "frameworks": [
      { "code": "ISO27001_2022", "version": "2022" },
      { "code": "ORG_INTERNAL", "version": "3" }
    ],
    "controls": [
      {
        "requirement_id": "REQ-ACC-01",
        "control": {
          "framework": { "code": "ISO27001_2022", "version": "2022" },
          "control_id": "A.5.17"
        },
        "applicability": "applicable",
        "requirement_text": "Passwords shall be at least 12 characters.",
        "parameters": [
          { "name": "password_min_length", "value": 12, "unit": "characters" }
        ]
      },
      {
        "requirement_id": "REQ-PHY-01",
        "control": {
          "framework": { "code": "ISO27001_2022", "version": "2022" },
          "control_id": "A.7.4"
        },
        "applicability": "not_applicable",
        "applicability_justification": "Fully cloud-hosted; no premises in scope."
      }
    ],
    "scope": { "cidrs": ["192.0.2.0/24", "198.51.100.0/24"], "asset_tags": [] }
  }
}
```

**Response (abridged — `baseline_coverage.response.json`):**

```json
{
  "contract": "ccure.audit.baseline_coverage",
  "causation_id": "0f1c7d8e-3b52-4a8e-9a55-5d2f0f6f1a01",
  "data": {
    "baseline": {
      "baseline_id": "pp-baseline-infosec-core",
      "baseline_version": 4,
      "content_sha256": "…"
    },
    "mapping_revision": 1,
    "activation": "pending_review",
    "summary": {
      "controls_total": 6,
      "automated": 2,
      "partially_automated": 0,
      "attestation_required": 3,
      "unknown_control": 1,
      "unsupported": 0
    },
    "controls": [
      {
        "requirement_id": "REQ-VUL-01",
        "control": {
          "framework": { "code": "ISO27001_2022", "version": "2022" },
          "control_id": "A.8.8"
        },
        "mapping_state": "AUTOMATED",
        "audit_rules": [
          {
            "rule_id": "crl_vuln_critical_v1",
            "title": "No open critical vulnerabilities",
            "check_type": "evidence_key",
            "platforms": ["any"]
          }
        ]
      },
      {
        "requirement_id": "REQ-ORG-07",
        "control": {
          "framework": { "code": "ORG_INTERNAL", "version": "3" },
          "control_id": "PWD-01"
        },
        "mapping_state": "UNKNOWN_CONTROL",
        "reason": "Framework ORG_INTERNAL/3 is not in Audit's catalogue."
      }
    ],
    "parameters": [
      {
        "requirement_id": "REQ-ACC-01",
        "name": "password_min_length",
        "handling": "RECORDED_NOT_HONOURED",
        "reason": "Audit's rules do not take parameters yet (plan Phase 13); the value is recorded and reported."
      }
    ],
    "scope": { "applied": true, "rejected_entries": ["198.51.100.0/24"] }
  }
}
```

The example uses the real mappings in Audit's catalogue today: ISO A.8.8 and
A.8.9 carry automated rules, and A.5.1, A.5.17 and A.7.4 carry attestation
placeholders.

**Semantics.**

- **Every control is answered**, with one mapping state, the Audit rules it
  maps to, and a reason whenever it is not fully automated. Policy Pro can show
  its users exactly which of its requirements Audit will test, which need a
  person, and which Audit cannot see (SRS 7.2.2.4).
- **Parameters are never silently ignored.** Until Audit's rules take
  parameters (plan Phase 13), every known parameter comes back
  `RECORDED_NOT_HONOURED`.
- **Scope only narrows.** Entries outside the tenant's authorised scan scope
  are rejected and listed; Policy Pro is not a scan authorisation.
- **Activation is an explicit Audit administrator action** (Q1, approved).
  A received baseline is stored and mapped immediately, starts in
  `pending_review`, and governs no assessment until an Audit administrator
  activates it. A baseline can change what every scan assesses, so it is never
  activated by the message that delivered it.
- **Parameter names come from `Capabilities`** (§11), never from a list Policy
  Pro keeps.

---

## 7. Contract 2 — Audit → Policy Pro: `ComplianceGapReport`

**Purpose.** SRS 7.6.2: "when CcureAudit completes an audit cycle, it sends a
compliance gap report back to CcurePolicyPro … which policy controls failed
during the audit". Also SRS 7.2.3.2 (device-level results for Policy Pro's
scoring) and 7.3.8.6.

|                  |                                                                                                        |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| **Trigger**      | An assessment completes while a baseline is active for the tenant                                      |
| **Push**         | `POST` to Policy Pro's registered endpoint (Policy Pro designs it)                                     |
| **Pull**         | `GET /api/v1/integrations/compliance-gap-reports?cursor=` and `…/{report_id}`                          |
| **Schema**       | `compliance_gap/v1/schemas/ComplianceGapReport.schema.json`                                            |
| **Scope**        | `audit:compliance_gap_reports:read`                                                                    |
| **Identifiers**  | `report_id` (Audit, immutable); `assessment_id`; `baseline_id` + `baseline_version` + `content_sha256` |
| **Immutability** | One report per (assessment, baseline version); never edited                                            |

**Semantics.**

- **Only against a received baseline.** Audit's own frameworks keep working
  without Policy Pro and are reported to Rank (contract 3). A gap report is
  about Policy Pro's controls.
- **Every baseline control appears exactly once**, including the ones Audit
  could not assess. A report listing only failures would read as "everything
  else passed". The model checks that `summary` matches the controls listed
  and that no requirement repeats.
- **A control whose checks could not run is `ERROR` or `NOT_ASSESSED` — never
  `FAIL` and never `PASS`.**
- **Coverage is stated.** `scope` counts in-scope assets by coverage, and each
  control carries per-asset state counts, so "passed on the 1 asset we
  reached" cannot be read as "passed".
- `compliance_score` for the baseline is `not_implemented`: Audit scores per
  framework today, not per received baseline.

**Example (one control, abridged — `compliance_gap_report.json`):**

```json
{
  "control": {
    "framework": { "code": "ISO27001_2022", "version": "2022" },
    "control_id": "A.8.9"
  },
  "requirement_id": "REQ-CFG-01",
  "state": "NOT_ASSESSED",
  "state_reason": "Configuration evidence was collected on 1 of 4 in-scope assets.",
  "basis": "automated",
  "asset_counts": {
    "PASS": 1,
    "FAIL": 0,
    "NOT_ASSESSED": 3,
    "NOT_APPLICABLE": 0,
    "MANUAL_REVIEW": 0,
    "ERROR": 0
  }
}
```

One asset passed and three were not assessed, so the control is
`NOT_ASSESSED`, not `PASS`. The model refuses the `PASS`
(`test_pass_requires_every_in_scope_asset_to_have_passed`).

---

## 8. Contract 3 — Audit → Rank: `AssessmentResult` and `PostureSnapshot`

**Purpose.** SRS 7.6.5: "when an audit scan is complete, CcureAudit sends its
full vulnerability and compliance scan data to CcureRank … one of its primary
inputs for calculating the organization's Cyber Security Index Score". The
design document (§3 Interface 3) lists "vulnerability counts by category,
overall compliance score, MTTR data, asset criticality distribution". SRS 7.5.1
names "vulnerability findings and compliance gap reports from CcureAudit".

### 8.1 `AssessmentResult` — immutable

|                 |                                                                                                                         |
| --------------- | ----------------------------------------------------------------------------------------------------------------------- |
| **Trigger**     | Any Audit assessment reaches a terminal state                                                                           |
| **Push**        | `POST` to Rank's registered endpoint                                                                                    |
| **Pull**        | `GET …/assessment-results?cursor=`, `…/{result_id}`, `…/{result_id}/findings?cursor=`, `…/{result_id}/controls?cursor=` |
| **Schemas**     | `AssessmentResult`, `AssessmentFindingsPage`, `AssessmentControlsPage`, `AssessmentResultPage`                          |
| **Scope**       | `audit:assessment_results:read`                                                                                         |
| **Identifiers** | `result_id` (Audit, immutable); `assessment_id`; `scan_policy_fingerprint`                                              |

**What it carries:**

- **The assessment:** kind, how it ended (`completed`, `completed_with_errors`,
  `failed`, `cancelled` — each non-completed status with its reason), origin
  (manual, schedule, integration request), start and completion times, the
  scan-policy fingerprint (GAP-12), and the baseline if one was active.
- **Every discovered asset**, with coverage, per-method outcomes, credentialed
  access, open-finding counts (`null` when nothing was learned) and risk inputs.
- **Finding totals** by severity and by category (`cve`, `config_check`,
  `privilege_check`, `plugin_check`), and how many are new since the previous
  comparable assessment (GAP-13).
- **Per-framework control summaries**, with Audit's framework score where one
  exists.
- **Programme KPIs** — MTTR, SLA compliance rate, re-open rate, density,
  criticality distribution — all `not_implemented` today (§13).
- **Findings and control results are paged** through their own resources and
  frozen with the result. The message stays bounded however large the
  assessment was — one real assessment here produced 1,887 findings.

**Finding (abridged — `assessment_findings_page.json`):**

```json
{
  "finding": {
    "finding_id": "fnd_ast_org_default_192_0_2_10_credentialed_package_CVE-2021-44228"
  },
  "definition": {
    "definition_id": "CVE-2021-44228",
    "definition_type": "cve",
    "cve_id": "CVE-2021-44228",
    "title": "Apache Log4j2 JNDI remote code execution (Log4Shell)"
  },
  "asset": {
    "asset_id": "ast_org_default_192_0_2_10",
    "ip_address": "192.0.2.10",
    "hostname": "fin-app-01"
  },
  "severity": "critical",
  "cvss": {
    "score": 10.0,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "version": "3.1"
  },
  "detection": {
    "method": "credentialed_package",
    "confidence": "confirmed",
    "qod": 97,
    "detected_version": "2.14.1"
  },
  "exploit": {
    "availability": "actively_exploited",
    "in_cisa_kev": true,
    "kev_due_date": "2021-12-24",
    "epss_score": 0.94,
    "ransomware_linked": true
  },
  "status": "open",
  "first_found_at": "2026-09-19T02:37:02Z",
  "last_found_at": "2026-09-26T02:39:55Z",
  "remediation": {
    "state": "assigned",
    "sla_state": "overdue",
    "sla_due_at": "2026-09-24T02:37:02Z",
    "reopened_count": 0,
    "guidance": "Upgrade Log4j to 2.17.1 or later."
  },
  "risk": {
    "cvss_component": {
      "status": "available",
      "value": 10.0,
      "unit": "cvss_base"
    },
    "asset_criticality_component": {
      "status": "not_implemented",
      "reason": "No asset criticality (SRS 7.3.7.3)."
    },
    "exposure_component": {
      "status": "not_implemented",
      "reason": "No exposure factor (SRS 7.3.7.5)."
    },
    "srs_risk_score": {
      "status": "not_implemented",
      "reason": "The SRS weighted score needs criticality and exposure."
    },
    "residual_risk_score": {
      "status": "not_implemented",
      "reason": "Compensating controls are not modelled on findings (SRS 7.3.7.8)."
    },
    "audit_priority": "P0"
  }
}
```

**The SRS risk formula** (7.3.7.5) is published **component by component**:

```
risk = CVSS × 0.4 + Asset Criticality × 0.3 + Exposure × 0.2 + Exploit Availability × 0.1
```

Audit can supply CVSS and exploit availability today. The composite score, its
category (SRS 7.3.7.6) and the residual score after compensating controls
(7.3.7.8) are `not_implemented`, and are never computed with zeros standing in
for the missing factors. `audit_priority` is Audit's own KEV/EPSS/exploit
priority and `audit_host_risk_score` is Audit's own additive 0–100 host score;
both are labelled as not being the SRS score.

**Asset (abridged — the asset nobody assessed):**

```json
{
  "asset": {
    "asset_id": "ast_org_default_192_0_2_40",
    "ip_address": "192.0.2.40"
  },
  "coverage": "NOT_ASSESSED",
  "coverage_reason": "Discovered; the port scan did not reach it before the phase time limit.",
  "methods": [
    { "method": "discovery", "outcome": "completed" },
    {
      "method": "port_scan",
      "outcome": "failed",
      "reason": "Phase soft time limit reached."
    }
  ],
  "finding_counts": null
}
```

### 8.2 `PostureSnapshot` — current state, pull only

`GET /api/v1/integrations/posture`, scope `audit:posture:read`. Generated on
request and valid `as_of` a stated instant. It carries inventory coverage
(including assets never assessed and assets whose last assessment is stale),
current open findings by severity, remediation state and SLA state, findings
under accepted risk (excluded from operational risk metrics, SRS 7.3.5.10), and
the current per-framework state.

It exists because findings change after a scan — remediation, verification,
acceptance — and an immutable scan-time result cannot answer "what is open
now". Rank should use results for reproducible history and the snapshot for
the present.

---

## 9. Contract 4 — Audit → IR: `FindingEvent`

**Purpose.** SRS 7.6.4: "each time CcureAudit completes a scan or assessment,
it sends its vulnerability findings and audit data to CcureIR … which systems
are vulnerable, which compliance controls are failing, and where the
highest-risk assets are". SRS 7.3.5.12: high-risk, exposed and exploitable
findings inform incident classification and correlation.

|              |                                                                   |
| ------------ | ----------------------------------------------------------------- |
| **Push**     | `POST` to IR's registered endpoint                                |
| **Pull**     | `GET /api/v1/integrations/finding-events?cursor=&min_severity=`   |
| **Schema**   | `finding_events/v1/schemas/FindingEvent.schema.json`              |
| **Scope**    | `audit:finding_events:read`                                       |
| **Delivery** | At least once; deduplicate on `message_id`; per-tenant `sequence` |

**Events, not a list.** IR needs to know when something changes, and a
snapshot cannot say that.

| `event_type`                        | When                                                                                    |
| ----------------------------------- | --------------------------------------------------------------------------------------- |
| `assessment.completed`              | An assessment ends — per asset: coverage, credentialed access, counts, failing controls |
| `finding.detected`                  | A finding is seen for the first time                                                    |
| `finding.reappeared`                | A fixed finding is detected again (GAP-13 `reappeared`)                                 |
| `finding.verified_fixed`            | A scan verified the fix (GAP-14)                                                        |
| `finding.risk_accepted`             | A risk acceptance was recorded                                                          |
| `finding.risk_acceptance_withdrawn` | It was withdrawn                                                                        |
| `finding.risk_acceptance_expired`   | It lapsed                                                                               |
| `finding.sla_breached`              | The finding became overdue                                                              |

Each `finding.*` event carries the finding **as it stood at `occurred_at`** —
identity, asset, severity, detection method and QoD, exploit intelligence,
remediation state and guidance, lifecycle timestamps and evidence references —
so IR never has to call back to interpret it.

`assessment.completed` is how IR tells "this host has no known weaknesses"
from "nobody looked at this host" (example: `assessment_completed.json`).

**Filtering.** The design document sends only Critical and High findings; the
SRS asks for "vulnerability findings and audit data". **The shared schema
carries every severity and encodes no filtering policy.** Which findings IR
receives is IR's business decision (Q3, open for IR): the pull feed offers a
`min_severity` parameter as a mechanism, and the push subscription will be
configured with whatever floor IR chooses. Until IR decides, nothing is
filtered.

---

## 10. Contract 5 — IR → Audit: `IncidentEvidence`

**Purpose.** SRS 7.6.4: "when CcureIR resolves an incident, it sends back the
incident logs and response effectiveness evidence to CcureAudit. This data
serves as formal evidence for audit trails and compliance reporting." SRS
7.4.5 defines the timestamps and score IR produces.

|                 |                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------- |
| **Endpoint**    | `POST /api/v1/integrations/incident-evidence`                                                  |
| **Trigger**     | An incident is resolved or closed (and on later updates)                                       |
| **Request**     | `IncidentEvidence`                                                                             |
| **Response**    | `201` / `200` replay — body `IncidentEvidenceReceipt`                                          |
| **Scope**       | `audit:incident_evidence:write`                                                                |
| **Identifiers** | `incident_id` + `incident_version` (IR); finding and asset refs (Audit's, from contract 4)     |
| **Idempotency** | Same incident version + content → original receipt; different content → `409 version_conflict` |

**What it carries:** incident identity, version, title, status and severity; the
timeline (occurred, detected, contained, recovered, closed); a summary; the
related Audit findings and assets; response actions; remediation claims; IR's
effectiveness score; and references to files IR holds, each with a digest.

**Rules.**

- **Stored as read-only evidence** attached to the findings and assets it
  names, and visible in Audit's audit trail and compliance reports. Audit never
  edits it.
- **IR can never close a finding.** A remediation claim is recorded as a claim.
  At most it moves the finding to `pending_verification` and requests a
  targeted re-scan (SRS 7.3.5.8). Only an Audit scan reaches `verified_fixed`,
  the rule `core/remediation` already enforces. The claim vocabulary has no
  "verified" member, and the receipt model refuses a claim outcome of
  `verified_fixed` (`test_ir_cannot_verify_a_fix`).
- **A re-scan request is a request.** It is subject to the tenant's scan scope
  and quota, exactly as a person's would be.
- **No binary attachments in v1.** Audit does not fetch a URL another module
  supplies — that would let IR aim this host's network access — and inline
  files need the upload guard's full treatment. v1 records IR's file
  references and SHA-256 digests; the files stay in IR, and an auditor can
  match them.
- **The receipt never confirms another tenant's ids.** An unknown finding id is
  `linked: false`, whatever the reason.

**Receipt (abridged — `incident_evidence_receipt.response.json`):**

```json
{
  "data": {
    "receipt_id": "ire_inc-2026-0142_3",
    "incident_id": "inc-2026-0142",
    "incident_version": 3,
    "findings": [
      {
        "finding_id": "fnd_ast_org_default_192_0_2_10_credentialed_package_CVE-2021-44228",
        "linked": true
      }
    ],
    "claims": [
      {
        "finding_id": "fnd_ast_org_default_192_0_2_10_credentialed_package_CVE-2021-44228",
        "disposition": "rescan_requested",
        "remediation_state_after": "pending_verification"
      }
    ]
  }
}
```

---

## 11. Supporting resources

- **`Capabilities`** (`GET …/capabilities`) — the contract versions this Audit
  deployment speaks, the frameworks it can assess for the caller's tenant (with
  how many controls are automated), the baseline parameter names it
  understands, and which assessment methods it implements. A vocabulary is
  fetched, not copied: Policy Pro builds its parameter and framework choices
  from here.
- **`EvidenceRecord`** (`GET …/evidence/{evidence_id}`) — one evidence record
  referenced from contracts 2–4. Text is redacted before it leaves Audit, and
  the record says whether it was. A file is described (verified media type,
  size, SHA-256, malware-scan result, where `not_configured` is not `clean`)
  and downloaded from the same authenticated API.
- **`Problem`** — the error body (§4.10).

---

## 12. Field ownership summary

| Owner        | Owns                                                                                                                                                                                     |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `policy_pro` | Baseline identity and version, policy reference, approval, applicability and justification, requirement ids and text, parameter values, baseline scope                                   |
| `audit`      | Mapping states and rule references, coverage, method outcomes, credentialed access, findings, control results, evidence, digests, report/result ids, remediation and SLA state, receipts |
| `ir`         | Incident identity, version, status, severity, timeline, actions, claims, effectiveness score, IR file references                                                                         |
| `rank`       | Nothing in these contracts — Rank consumes. Its scores, domains and bands are Rank's and never sent to Audit (design doc §3.4).                                                          |
| `platform`   | `tenant_id`; the framework and control identifier vocabulary (D3)                                                                                                                        |
| `producer`   | Envelope fields                                                                                                                                                                          |

The per-field answer is in each schema's `x-ccure-owner`.

---

## 13. SRS requirements Audit cannot populate today

These fields exist in the contracts and are reported **explicitly unavailable**.
Nothing here is filled with a default, and every row is a real gap, not a
contract choice.

| SRS                   | Requirement                                                                 | Contract field                                                 | State today                                                                                    | Needed                                                 |
| --------------------- | --------------------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| 7.3.7.3               | Asset criticality (1–10)                                                    | `risk.asset_criticality`, `…_component`                        | `not_implemented` — no criticality attribute on assets                                         | Asset attribute + UI (plan Phase 14)                   |
| 7.3.7.5, 7.3.3.5      | Exposure factor                                                             | `risk.exposure`, `exposure_component`                          | `not_implemented`                                                                              | Exposure model (Phase 14)                              |
| 7.3.7.5               | Weighted risk score                                                         | `srs_risk_score`                                               | `not_implemented` — needs the two above                                                        | Phase 14                                               |
| 7.3.7.6               | Risk category tiers                                                         | `risk_category`                                                | `null` (`not_implemented`)                                                                     | Thresholds, after the score                            |
| 7.3.7.7, 7.3.7.8      | Compensating controls; residual risk score                                  | `risk_acceptance.compensating_controls`, `residual_risk_score` | `not_implemented` — risk acceptance exists, compensating controls on findings do not           | Model + governed deduction                             |
| 7.3.5.10              | Risk acceptance with mandatory compensating controls and approval signature | `risk_acceptance`                                              | Partial — reason, approver, dates exist; compensating controls and signature do not            | As above                                               |
| 7.3.8.7, 7.3.8.8      | MTTR, SLA compliance rate, re-open rate, vulnerability density              | `metrics.*`                                                    | `not_implemented` as aggregates; the per-finding timestamps they derive from **are** available | Aggregation service                                    |
| design §3 Interface 3 | Asset criticality distribution                                              | `metrics.criticality_distribution`                             | `not_implemented`                                                                              | Asset criticality                                      |
| 7.3.1.3               | Network segments / Purdue zones                                             | `risk.network_zone`                                            | `null` (`not_implemented`)                                                                     | Zone model                                             |
| 7.3.4.5               | Malware detection                                                           | method `malware_scan`                                          | `not_implemented` — antivirus-presence check only                                              | Out of Audit's current scope                           |
| 7.3.5.8               | Automatic targeted re-scan after remediation                                | contract 5 `request_rescan`                                    | Claim can be recorded; nothing schedules the re-scan yet                                       | Phase 7 adapter + scheduler hook                       |
| 7.3.2.2, 7.6.2        | Import Policy Pro templates                                                 | contract 1                                                     | Not implemented — the contract is the design                                                   | Phase 7                                                |
| 7.2.3.2               | Compliance score per baseline; per device and department                    | `compliance_score` (gap report)                                | `not_implemented` per baseline; per-asset results exist; no department model                   | Score per baseline; department mapping is Policy Pro's |
| 7.3.1.2               | Organisation parameters applied to checks                                   | parameter `handling`                                           | `RECORDED_NOT_HONOURED` — rules are not parameterised                                          | Rule parameterisation (Phase 13)                       |
| 7.3.1.10, 7.3.6.4     | Credentialed failure classes per asset                                      | `credentialed.outcome`                                         | Partial — success/failure stored; sub-class only inside the transports                         | Persist the classification (Phase 6)                   |
| —                     | Structured per-method outcome for every path                                | `methods[].outcome`                                            | Partial — `unknown` where unrecorded                                                           | Phase 6 coverage model                                 |
| 7.6.1                 | Secured internal APIs; logged exchanges                                     | §4.2                                                           | Not implemented — no service identities, no integration endpoints                              | Phase 7 (service identity, outbox, feeds)              |

Two related facts that are **not** gaps, stated so nobody records them as one:

- Exploit availability (SRS 7.3.7.4) **is** available: public exploit,
  ExploitDB-verified exploit, CISA KEV and VulnCheck canary observation.
- Risk acceptance, remediation workflow, SLA deadlines and scan-verified
  closure (SRS 7.3.5.8–7.3.5.10) **are** implemented; only the compensating
  controls and aggregates listed above are missing.

---

## 14. Open design questions

### 14.1 Settled in the Phase 4 review (26 Sep 2026)

| #   | Outcome                                                                                                                                                                                       |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1  | **Approved v1 behaviour:** a received baseline is stored and mapped but governs no assessment until an Audit administrator explicitly activates it. Initial `activation` is `pending_review`. |
| Q3  | **Open, for IR to decide.** The shared finding schema encodes no filtering policy; the feed's `min_severity` is a mechanism, and nothing is filtered until IR chooses.                        |
| Q5  | **Deferred** as a future Audit domain change. Asset ids are not redesigned in Phase 5.                                                                                                        |
| Q8  | **Accepted:** HTTPS + outbox for v1. Kafka is deferred.                                                                                                                                       |
| Q9  | **Resolved:** a correction is a new `AssessmentResult` with `supersedes_result_id` and `correction_reason`; an existing result is never modified. Added to v1.0 (still a draft schema).       |

### 14.1a Corrections before the v1 freeze (plan Phase 7, 28 Sep 2026)

Building the Audit mappers (Phase 5.6) found six places where the draft could
not say what Audit knows or does not know. All six are corrected in the models,
schemas and examples. v1 is still `draft` until the freeze is approved.

| #   | Correction                                                                                                                                                                                                                                                                                               |
| --- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C1  | `finding_refs` / `evidence_refs` on a control result, and `evidence_refs` on a finding, are **nullable and `not_implemented`**. `null` means Audit does not report them yet; `[]` would state that none exist. The examples now show `null`.                                                             |
| C2  | `CcureControlMappingV1` gains **`applicability`** (an echo of what the baseline declared) and **`notes`** (e.g. "framework not installed for this tenant"). `reason` keeps its one meaning: why the control is not fully automated.                                                                      |
| C3  | `CcureScopeOutcomeV1`: **`rejected_entries` carries objects `{entry, reason}`**, plus **`organisation_scope_configured`** and **`unmatched_asset_tags`**. "Outside the scope" and "not a valid CIDR" need different fixes, and a scope of tags that match nothing assesses nothing.                      |
| C4  | `AssessmentControlsPage` states that **an empty page is not a clean result**; coverage is read from the `AssessmentResult` named by `result_id`.                                                                                                                                                         |
| C5  | `rule_id` in `BaselineCoverage` and in `ControlResult.rules` is **one namespace** (Audit's compliance rule id, which is also the check id), stated on both fields.                                                                                                                                       |
| C6  | `audit_priority` is **`not_implemented`**, not `partial`. It is computed for display and not stored on a finding. The examples no longer show `P0`.                                                                                                                                                      |
| C7  | The Capabilities example matched no real installation. It now shows **ISO 27001 15 and NIST CSF 29 automated controls** (measured read-only on 28 Sep 2026) and **no baseline parameters**, because Audit's parameter vocabulary is empty. The coverage example answers `UNKNOWN_PARAMETER` accordingly. |

**Transport under the platform plan's revision 4** (28 Sep 2026) is unchanged for the payloads:

- Contracts 1–3 run in-process inside the core service.
- Contracts 4–5 cross the network between the core and the IR service through the API Gateway. The gateway authenticates every call, including service-to-service calls (§4.2).

The table below keeps the original proposals for the record; where it differs,
§14.1 and §14.1a win.

### 14.2 Questions as raised

The plan's open decisions stand: **D2** (push/pull — proposed here as push
primary with pull catch-up), **D3** (framework and control identifier
governance), **D4** (service credential mechanism), **D5** (contract governance
and deprecation window), **D6** (platform owner). Phase 4 adds:

| #   | Question                                                                                            | Proposal                                                                                                                                                                       | Who decides        |
| --- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------ |
| Q1  | Does a received baseline govern assessments immediately, or after an Audit admin approves it?       | Per-tenant setting, default **review required**: a baseline can change what every scan assesses.                                                                               | Audit + Policy Pro |
| Q2  | Can a tenant have several active baselines (per framework, per business unit)?                      | v1: one active baseline per tenant per framework.                                                                                                                              | Policy Pro         |
| Q3  | Which findings does IR receive by default?                                                          | All severities on the pull feed; push floor `high` (design doc).                                                                                                               | IR                 |
| Q4  | How do `exception` / `remediation_applied` / `pending_reverify` compliance statuses map to a state? | `state` = last machine verdict, disposition beside it; `NOT_ASSESSED` with a reason when no verdict is stored. Needs the register to keep the verdict next to the disposition. | Audit              |
| Q5  | Stable asset identity across modules when an asset's IP changes                                     | Carry IP/MAC/hostname beside the id now; mint a stable, IP-independent asset id in a later phase.                                                                              | Audit + all        |
| Q6  | Pull-feed retention                                                                                 | 90 days; `410` beyond, with `retained_from`.                                                                                                                                   | Platform           |
| Q7  | Evidence sharing policy: redaction rules, and whether IR or Rank may download files at all          | Redact always; files only with `audit:evidence:read`, granted per module.                                                                                                      | Audit + security   |
| Q8  | Kafka (design doc) versus HTTPS (this document)                                                     | HTTPS + outbox for v1; the envelope allows a bus later without a schema change.                                                                                                | Architecture board |
| Q9  | Correcting an immutable result produced by an Audit defect                                          | Publish a new result with `supersedes_result_id` (a v1.1 optional field); never edit.                                                                                          | Audit + Rank       |
| Q10 | Mapping to Rank's NIST CSF domains                                                                  | Audit reports per framework and per control; the domain mapping is Rank's (Audit supplies NIST CSF 2.0 control results when that framework is installed).                      | Rank               |
| Q11 | Where IR's detection/containment/recovery metrics are authoritative                                 | IR → Rank directly (SRS 7.6.7). Audit keeps IR's timeline as evidence and does not recompute it.                                                                               | IR + Rank          |
| Q12 | Size limits and paging defaults                                                                     | 5,000 controls per baseline; 500 items per page; 5 MB per request body.                                                                                                        | Platform           |

---

## 15. Carried over from Phase 3

Recorded here so the next phases see them. Neither is an architecture violation
and neither blocks Phase 4.

- **Compatibility import paths.** `scans.cvss` and `scans.finding_normalizer`
  are aliases of `core.checks.cvss` and `core.checks.finding_normalizer` (the
  same module objects), and `scan_helpers.limiter` re-exports
  `core.rate_limiter.limiter`. Measured on the import graph: 8 application
  modules still import `scans.cvss` / `scans.finding_normalizer`, and 15 take
  `limiter` from `scan_helpers`. They stay until a later phase migrates and
  deprecates them.
- **Infrastructure coupling in discovery.** Importing the discovery engine
  still loads SQLAlchemy, through `core.risk` → `core.vuln_intel`. It breaks no
  layer rule, but it means the discovery engine cannot yet run without the
  database layer installed. It is not refactored now, and will be when a phase
  needs the engine standalone (plan Phase 8).

---

## 16. Files, regeneration and validation

**Layout** (`Backend/ccure_contracts/`):

```
common/v1/            envelope, references, vocabulary, measured values, feeds, error model
policy_baseline/v1/   contract 1          compliance_gap/v1/     contract 2
assessment_result/v1/ contract 3          finding_events/v1/     contract 4
incident_evidence/v1/ contract 5          capabilities/v1/, evidence/v1/
  <area>/v1/models.py      the Pydantic models (source of truth)
  <area>/v1/schemas/       generated JSON Schema, draft 2020-12 — committed, never hand-edited
  <area>/v1/examples/      worked examples — every one validated by the tests
registry.py           every message type, its schema file and its examples
```

**Regenerate** after changing a model:

```bash
cd Backend
python -m scripts.contracts.generate_schemas            # write
python -m scripts.contracts.generate_schemas --check    # CI: exit 1 on drift
# On the VM, the API container cannot write into the bind mount:
docker exec -w /app ccure-api python -m scripts.contracts.generate_schemas --bundle \
    | python3 scripts/contracts/write_bundle.py
```

**Validation performed** (`tests/repo/test_integration_contracts.py`):

- 16 committed schemas are byte-identical to what the models generate.
- 13 worked examples are valid against their models, and every `content_sha256`
  in them is recomputed and matches.
- Every property in every schema has an owner and an availability; no
  `not_implemented` field is a bare required value.
- The assessment-state vocabulary is exactly the six states.
- The semantic rules refuse: a measured value reporting unknown as `0`; zero
  findings on an unassessed asset; a `PASS` over an unassessed asset; a gap
  report omitting controls; an executable check in a baseline; IR verifying a
  fix; a naive timestamp; a `verified_fixed` finding that names no verifying
  assessment; a message sent to the wrong contract.
- `ccure_contracts` imports only the standard library and Pydantic
  (`contracts-are-leaves` + an AST check), and nothing in the application
  imports it yet.

The schemas are draft 2020-12 JSON Schema generated by Pydantic 2.7. They have
not been checked by a second, independent JSON Schema validator: the API image
has no `jsonschema` package and Phase 4 adds no dependency. A team consuming
them outside Python should validate the examples with its own validator as its
first review step.

---

## 17. What Phase 4 did not do

- No route, task, table, migration, or change to any existing file's behaviour.
  `openapi.json` is unchanged.
- No Policy Pro, Rank or IR code, and no module slots (Phase 5).
- No integration adapter, outbox, service identity or feed (Phase 7).
- No message bus.
- No change to Audit's database or to what any scan does.

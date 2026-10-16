# CCure platform — architecture

The current architecture of the CCure platform and where its records are. Start here if you
are building Policy Pro, Rank or IR. `CLAUDE.md` is the repository-wide rule book; this page
is the map. Records of finished work are in [`../archive/`](../archive/) and describe the
tree as it was when they were written.

## 1. Who does what

| Module                           | Responsibility                                                                                                                                 | Where it lives                                              | State                                   |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | --------------------------------------- |
| **CCure Audit**                  | The assessment and scanning engine: discovery, vulnerability and configuration assessment, credentialed audit, compliance, findings, reporting | `Backend/ccure_audit/` plus `core/`, `engines/`             | The product                             |
| **Policy Pro** (`ccure_policy/`) | Supplies policies and compliance requirements, which Audit assesses against                                                                    | `Backend/ccure_policy/`, `/policy`                          | Empty slot, disabled                    |
| **Rank** (`ccure_rank/`)         | Consumes assessment results and calculates rankings                                                                                            | `Backend/ccure_rank/`, `/rank`                              | Empty slot, disabled                    |
| **IR**                           | Consumes relevant findings for incident response and remediation, and returns incident evidence                                                | Planned as its own service (no code in this repository yet) | Listed in the Product Hub, not a module |
| **Shared platform**              | Identity, organisations, roles and permissions, audit log, notifications, module registry                                                      | `Backend/ccure_platform/`, `Frontend/src/shell/`            | Live                                    |

Audit works without the other three. They are added by folder and manifest; none of them
edits Audit's code.

## 2. How modules talk to each other

- **Through contracts, never through each other's code or tables.** The five draft
  contracts are in `Backend/ccure_contracts/` (Pydantic models are the source; the JSON
  Schemas are generated):

  1. Policy Pro → Audit: `PolicyBaseline` (controls and parameters, never executable checks)
  2. Audit → Policy Pro: `ComplianceGapReport`
  3. Audit → Rank: `AssessmentResult` (immutable) and `PostureSnapshot`
  4. Audit → IR: `FindingEvent`
  5. IR → Audit: `IncidentEvidence` (IR can never move a finding to `verified_fixed`)

  Design, conventions and open questions: [`contracts/PHASE4_INTEGRATION_CONTRACTS.md`](contracts/PHASE4_INTEGRATION_CONTRACTS.md).
  The contracts are `draft`; nothing in production imports them yet, and the integration
  adapter is built on the Audit side (`Backend/ccure_audit/integration/`,
  [Phase 5 record](PHASE5_AUDIT_INTEGRATION_BOUNDARIES.md)).

- **Through the platform API for identity.** A module imports `ccure_platform.api` only
  ([Phase 8](PHASE8_PLATFORM_IDENTITY.md)), never `auth.*`, `users`, `organizations` or
  `roles`.
- **Through the gateway at runtime.** Browsers, clients and IR reach the core through the
  API gateway, which authenticates every request. Services authenticate with their own
  ES256 service identity ([Phase 9](PHASE9_TOKENS_AND_SERVICE_IDENTITIES.md),
  [Phase 10](PHASE10_API_GATEWAY.md)).
- **Policy Pro's input format** to Audit: [`policypro/POLICYPRO_BASELINE_EXPORT_REQUIREMENTS.md`](policypro/POLICYPRO_BASELINE_EXPORT_REQUIREMENTS.md).

## 3. Boundaries that CI enforces

- A module imports only itself, `ccure_platform.api`, `ccure_contracts` and `db.base`;
  nothing imports a module (`module-isolation`, `module-is-private`). A module's tables
  live in its own schema and are registered in
  `Backend/scripts/architecture/table_ownership.yaml`; its tests live in
  `Backend/tests/modules/<key>/`. See [Phase 11](PHASE11_MODULE_FOLDERS.md) and the
  module READMEs (`Backend/ccure_policy/README.md`, `Backend/ccure_rank/README.md`).
- Layering and import cycles: `Backend/scripts/architecture/layer_rules.py`
  (`python -m scripts.architecture.import_graph --violations`).
- Identity boundary and token signing: `tests/repo/test_identity_boundary.py`,
  `tests/repo/test_token_guardrails.py`.
- Frontend: one application, one folder per product (`Frontend/modules.config.js`,
  [Phase 12](PHASE12_FRONTEND_SHELL.md), [`../FRONTEND_ARCHITECTURE.md`](../FRONTEND_ARCHITECTURE.md)).
  Products never import each other, and the shell names no product.
- Database: Alembic has three heads (Audit, `policy_pro`, `rank`); always `upgrade heads`.
  No module database roles before Phase 18 ([prepared, not applied](PHASE18_DATABASE_ISOLATION.md)).

## 4. Shared platform: identity, organisations, roles, permissions

Owned by the shared platform, not by any module, and open to contributions from any
product team under the same review ([ownership note](PLATFORM_SHARED_NAVIGATION.md),
[extraction](BACKEND_PLATFORM_EXTRACTION.md)).

- **Authorization is native RBAC only.** Permissions are keys; roles are only a join
  path. Never test a role name. [Foundation](RBAC_FOUNDATION.md),
  [catalogue](RBAC_PERMISSION_CATALOG.md), [scope](RBAC_SCOPE.md),
  [administration](RBAC_ADMINISTRATION.md), [frontend](RBAC_FRONTEND_AUTHORIZATION.md),
  [cutover record](RBAC_CUTOVER.md), [current permission coverage](../RBAC_Management_Permissions.md).
  A module declares its permissions as data in its manifest.
- **Organisation settings** (authorised scan scope, remediation SLA) are platform-owned:
  [`ORGANISATION_SETTINGS.md`](ORGANISATION_SETTINGS.md).
- **Tokens** are ES256 only, signed in `ccure_platform.identity.tokens`
  ([`../AUTHENTICATION_AND_AUTHORIZATION.md`](../AUTHENTICATION_AND_AUTHORIZATION.md)).
- Audit-shaped vocabulary still in platform tables, which may only shrink:
  [`PLATFORM_AUDIT_VOCABULARY.md`](PLATFORM_AUDIT_VOCABULARY.md),
  [`PLATFORM_AUDIT_BOUNDARY_REVIEW.md`](PLATFORM_AUDIT_BOUNDARY_REVIEW.md).

## 5. Reference and runbooks

| Subject                    | Document                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module independence        | [`MODULE_INDEPENDENCE_ANALYSIS`](MODULE_INDEPENDENCE_ANALYSIS.md) — measured coupling between Audit's capabilities, data ownership, and the proposed decoupling plan (16 Oct 2026, awaiting review)                                                                                                                                                                                               |
| System, API, database      | [`SYSTEM_ARCHITECTURE`](../SYSTEM_ARCHITECTURE.md), [`BACKEND_API_REFERENCE`](../BACKEND_API_REFERENCE.md), [`DATABASE_SCHEMA`](../DATABASE_SCHEMA.md) (the last two are checked against the code by a test)                                                                                                                                                                                      |
| Scan engines               | [`SCAN_ENGINE_DEEP_DIVE`](../SCAN_ENGINE_DEEP_DIVE.md), [`gap_closure/GAP_TRACKER`](../gap_closure/GAP_TRACKER.md)                                                                                                                                                                                                                                                                                |
| Gateway and edge           | [`phase10/`](phase10/): [characterisation](phase10/PHASE10_1_CHARACTERISATION.md), [design](phase10/PHASE10_2_DESIGN.md), [TLS](phase10/PHASE10_4_TLS.md), [cutover](phase10/PHASE10_5_CUTOVER.md), [hardening](phase10/PHASE10_6_HARDENING.md), [gateway-only](phase10/PHASE10_7_GATEWAY_ONLY.md); recorded route tables `phase10/route_table.json` and `route_auth_matrix.json` are test inputs |
| CI, images, security gates | [`../ci/BRANCH_PROTECTION.md`](../ci/BRANCH_PROTECTION.md), [`../ci/CONTAINER_IMAGES.md`](../ci/CONTAINER_IMAGES.md), [`../ci/SECURITY_GATES.md`](../ci/SECURITY_GATES.md)                                                                                                                                                                                                                        |
| Frontend design system     | [`../ux4g/UX4G_STANDARD.md`](../ux4g/UX4G_STANDARD.md)                                                                                                                                                                                                                                                                                                                                            |
| Compliance engine          | [`../policy compliance/`](<../policy compliance/compliance_developer_guide.md>)                                                                                                                                                                                                                                                                                                                   |
| API → UI coverage          | [`../api_ui_coverage/README.md`](../api_ui_coverage/README.md)                                                                                                                                                                                                                                                                                                                                    |
| Audit chain and retention  | [`../AUDIT_CHAIN_DBA_HANDOFF.md`](../AUDIT_CHAIN_DBA_HANDOFF.md), [`../AUDIT_VERIFICATION_GAPS.md`](../AUDIT_VERIFICATION_GAPS.md)                                                                                                                                                                                                                                                                |
| Setup, TLS                 | [`../DEVELOPER_SETUP_GUIDE.md`](../DEVELOPER_SETUP_GUIDE.md), [`../TLS_SETUP.md`](../TLS_SETUP.md)                                                                                                                                                                                                                                                                                                |

## 6. Not in this repository

The platform master plan (`CCURE_PLATFORM_MODULAR_ARCHITECTURE.md`, revision 4, 28 Sep 2026)
and the measured starting point (`MODULE_INDEPENDENCE_BASELINE.md`, 25 Sep 2026) are cited by
several phase records but were never committed, on the project owner's instruction at the time.
They are not needed to build against the contracts above; ask the project owner if you need them.

For the state of module independence, the authoritative documents are in this repository:

- [`MODULE_INDEPENDENCE_ANALYSIS.md`](MODULE_INDEPENDENCE_ANALYSIS.md) is the current-state
  report, re-measured on 16 Oct 2026. It replaces the 25 Sep baseline as the reference point.
- [`MODULAR_REFACTORING_LOG.md`](MODULAR_REFACTORING_LOG.md) is the step-by-step record of
  the work that follows from it.

Whether the two September documents are committed as history under
[`../archive/architecture/`](../archive/architecture/) is decision D-9 in that report.

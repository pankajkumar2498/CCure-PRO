# CCure platform — architecture

The current architecture of the CCure platform and where its records are. Start here if you
are building Policy Pro, Rank or IR, or changing CCure Audit. `CLAUDE.md` is the
repository-wide rule book; this page is the map. Records of finished work are in
[`../archive/`](../archive/) and in the phase records listed in §10; they describe the tree as it
was when they were written. Sections 3–8 describe Audit's inside as of commit `b00247d`
(3 Nov 2026).

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

## 3. Inside Audit: capabilities and the current state

Audit's code is divided into **capabilities**, each owning its code and its tables. The map is
`Backend/scripts/architecture/capability_map.py` (`CAPABILITIES` and `PREFIXES`): every module
belongs to exactly one, and a new module that matches no prefix fails the build. A capability
may depend only on capabilities in **lower layers**; a dependency between two capabilities of
the same layer is _lateral_ and allowed only through the owner's declared public module.

| Layer | Capabilities                                                                                                                                                  | What the layer is                                                                                             |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| 0     | `contracts`, `module_registry`                                                                                                                                | Cross-product contracts; the standard-library module registry (`ccure_platform/modules/`)                     |
| 1     | `infra`, `platform`                                                                                                                                           | Settings, database session, Celery, Redis, limits, crypto; identity, organisations, RBAC, audit log           |
| 2     | `check_kernel`, `scan_kernel`, `tls`, `vuln_intel`                                                                                                            | The check and finding contract; scan-domain constants and scope admission; the TLS engine; vulnerability data |
| 3     | `discovery`, `port_inventory`, `network_checks`, `credentialed_audit`, `config_audit`, `topology`, `web_dast`, `renderers` (+ the `policy_pro`, `rank` slots) | The engines: libraries that compute and return, and the report renderers (a payload in, a document out)       |
| 4     | `assets`, `findings` (with remediation), `compliance`, `credential_vault`, `scan_policy`, `scheduling`                                                        | The domain stores, each the owner and only writer of its tables                                               |
| 5     | `scans`                                                                                                                                                       | Scan records and phases, the scan API, orchestration, the Celery scan tasks (`scans/tasks/`)                  |
| 6     | `audit_boundary`, `dashboard`, `reporting`                                                                                                                    | `ccure_audit/` read services and contract adapter; the dashboard read model; the report and export read side  |
| 7     | `main`                                                                                                                                                        | The composition root: `main.py` and the `ccure_audit/` registration modules                                   |

**Measured at `b00247d` (3 Nov 2026)** with `python -m scripts.architecture.capability_map`,
from `Backend/`:

| Figure                                      |             Now | 16 Oct 2026 (`23f8e72`, the same tool) |
| ------------------------------------------- | --------------: | -------------------------------------: |
| Capability cycles (all imports / top-level) |           0 / 0 |                                22 / 13 |
| Upward edges                                |               0 |                                     50 |
| Lateral edges                               |              26 |                                     72 |
| References to another capability's table    | 23 (reads only) |                                     80 |
| Writes to another capability's table        |               0 |                                     18 |
| Lazy cross-capability imports               |             146 |                                    392 |
| Engine libraries isolated (D1 harness)      |              10 |      — (the harness came with Group 1) |

The "16 Oct" column is the analysis's record (§12.1 there): the 16 Oct code, `23f8e72`,
measured on 28 Oct with the map as it stood then, after its classification had been refined
(for example, D-6 made findings and remediation one capability).
`Backend/tests/repo/test_capability_ratchet.py` pins slightly different starting values (lateral
edges 74, foreign-table writes 17): the ceilings the ratchet was introduced with on 16 Oct
(A2), from the map as it was that day. They are two records of the same starting point taken
with two versions of the map, not contradictory measurements; the test's values are only the
upper bound no ceiling may be raised above.

Each figure is a ceiling in `CEILINGS` that may only fall. The latest full backend suite,
on `ffb870b` (the last code commit; `b00247d` changes only documents): **8,532 passed,
211 skipped** (the skips need the DBA-installed audit chain). How each figure was reached is
the [refactoring log](MODULAR_REFACTORING_LOG.md) (§6, Groups 1–7); the analysis that
planned it is [`MODULE_INDEPENDENCE_ANALYSIS.md`](MODULE_INDEPENDENCE_ANALYSIS.md).

## 4. Inside Audit: how capabilities talk

- **Downward, by import.** A capability imports lower layers freely. Imports go at module
  level; an import inside a function is kept only for a stated reason (startup order, an
  engine kept free of the database or settings, a heavy or optional package), and the count is
  ratcheted.
- **Upward or sideways, through a port.** When a lower capability needs something a higher
  one owns, it declares a port — a `Protocol`, a `register_…` function and a `…Missing` error —
  and the owner answers it. Audit's composition root registers the answers. A port nobody
  registered **raises**; it never answers empty. The registrations:

  | Registration module (`Backend/ccure_audit/`) | Loaded by        | Ports it answers                                                                                                                                    |
  | -------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `evidence_providers.py`                      | Celery `imports` | Compliance's evidence sources (`core/compliance_evidence.py`), answered by findings, assets, topology and web DAST                                  |
  | `host_directory.py`                          | Celery `imports` | The findings side's hosts (`core/findings/hosts.py`), answered by the asset registry (`core/asset_hosts.py`)                                        |
  | `scan_directory.py`                          | Celery `imports` | The comparison's scan directory, the asset timeline's scans, a policy's scan usage, the scheduler's scan creator — answered by the scans capability |
  | `vendor_cache.py`, `engine_ports.py`         | Celery `imports` | The OUI lookup's vendor cache; the Nmap wrapper's Redis lease and cache; the version matcher's CVE repository                                       |
  | `topology_directory.py`                      | Celery `imports` | The topology engine's directory: assets (asset registry), links (topology store), scan targets (scans)                                              |
  | `web_settings.py`                            | Celery `imports` | Web DAST's settings (`core/web/settings.py`) and the web worker self-check's database and Redis probes                                              |
  | `web_routes.py`                              | `main.py`        | The limiter that enforces web DAST's route limits (`core/web/rate_limits.py`)                                                                       |
  | `policy_references.py`                       | `main.py`        | The scan-policy API's schedules naming a policy, answered by scheduling                                                                             |
  | `offboarding.py`, `preferences.py`           | `main.py`        | Audit's part of a user purge; Audit's preference block — both registered with the platform                                                          |

- **Tasks by name.** Code that starts a Celery task dispatches it by registered name
  (`core/task_names.py`, `core.celery_app.registered_task`); nothing outside `scans/tasks/`
  imports a task module. Task names, queues and limits are pinned
  (`Backend/scripts/architecture/task_registry.json`).
- **Phases hand over typed values.** `HostRecord` into asset discovery and `ServiceInventory`
  into the vulnerability audit (`core/phase_handoff.py`), sequenced by one pipeline definition
  (`scans/pipeline.py`).
- **Events.** There is no in-process event bus. Live progress is published on the Redis
  channel `scan_progress:<scan id>`, which the scan and web scan WebSockets relay;
  notifications and audit-log entries are raised through `ccure_platform.api`
  (`create_notification`, `log_audit_event`). The cross-product `FindingEvent` contract (§2) is
  draft and not yet emitted.
- **Identity, organisations and permissions** only through `ccure_platform.api`, including the
  WebSocket ticket login (`websocket_user`).

## 5. Data ownership

Every table has one owning module and capability in
`Backend/scripts/architecture/table_ownership.yaml`; a new table needs its entry in the same
change, and CI checks the file against the models in both directions. **No capability writes
another's table** — as SQL, a model, or an attribute set on a row it loaded:

| Capability                               | Tables                                                                                                                                 | The only writer                                                                                                                                                                         |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `findings`                               | `services`, `tls_details`, `http_security_details`, `vulnerability_definitions`, `asset_vulnerabilities`, `finding_remediation_events` | `core/findings/writer.py`; the remediation workflow (`core/remediation/workflow.py`, the same capability) for its events                                                                |
| `assets`                                 | `assets`, `asset_change_log`, `asset_notes`, `asset_tags`, `amt_inventory_records`, `mac_vendor_cache`                                 | The asset registry's modules: `scans/asset_syncer.py`, `core/asset_*.py` (compliance, credentialed sync, offboarding), `core/topology_assets.py`, the assets router, AMT reconciliation |
| `scans`                                  | `scans`, `scan_phases`                                                                                                                 | The scans capability's modules (`scans/scan_creation.py`, `scans/db_helpers.py`, the scan tasks, `core/scan_control.py`, `scans/offboarding.py`)                                        |
| `credential_vault`                       | `compliance_credentials`                                                                                                               | `core/credential_vault.py` and its router                                                                                                                                               |
| `topology`                               | `network_links`                                                                                                                        | The topology store, `core/topology/links.py`                                                                                                                                            |
| `web_dast`                               | `web_scans`, `web_assets`, `web_findings`, `web_forms`, `web_parameters`, `web_api_operations`                                         | Web DAST (`core/web/`, `orchestrator/web_orchestrator.py`)                                                                                                                              |
| `compliance`                             | the 20 `compliance_*` tables other than the credentials                                                                                | Compliance (`core/compliance*.py`, its routers)                                                                                                                                         |
| `scan_policy`, `scheduling`, `reporting` | `scan_policies`; `scan_schedules`, `scan_schedule_runs`; `scan_reports`                                                                | Their own modules                                                                                                                                                                       |
| platform                                 | `users`, `organizations`, the `rbac_*` tables, `audit_logs`, `platform_audit_events`, `notifications` and the identity tables          | `ccure_platform/`; modules ask `ccure_platform.api`                                                                                                                                     |

Reading another capability's table is counted, not forbidden: 23 references remain, all
reads (Audit's read services and seeding, the scans pipeline's own inputs, the
vulnerability-definition catalogue). The guards are `tests/repo/test_findings_writer.py`,
`tests/repo/test_asset_registry_writes.py`, `tests/repo/test_credential_vault_boundary.py`
and `test_topology_store.py`'s single-writer check, beside the ratchet.

## 6. Scan execution and data flow

1. **Request.** A scan route (`routers/phase_scans.py`, `routers/credentialed.py`,
   `routers/web_scans.py`) or a schedule (`core/scheduling/dispatcher.py`) admits the
   targets against the organisation's authorised scope, creates the scan record and
   dispatches the first task by name.
2. **Network pipeline** (`scans/tasks/phases.py`, worker queue `scanner`): host discovery
   (`core/discovery/`, Scapy) → asset discovery (`engines/port/`, Nmap) → vulnerability audit
   (`engines/vulnerability/`, the network checks and Nuclei), each a separate task handed
   over by `scans/pipeline.py`. The orchestrator (`orchestrator/scan_orchestrator.py`) runs the
   engines; each phase's result is stored on its `scan_phases` row.
3. **Persistence.** The phase sync tasks hand the result to the asset registry
   (`scans/asset_syncer.py`), which writes the assets and passes services and findings to the
   findings writer. The comparison (`core/findings/comparison.py`) classifies every finding
   against the previous scan and sets its fix state; only a scan's comparison can reach
   `verified_fixed`.
4. **Credentialed audit** (`scans/tasks/credentialed.py`): authenticated collection over
   SSH, WinRM or SMB, configuration audit (`core/config_audit/`, benchmark packs and SCAP),
   package and patch matching; the asset part is written by `core/asset_credentialed.py`, the
   findings by the findings writer.
5. **Topology** (optional Phase 4, `scans/tasks/topology.py`): chained when SNMP credentials
   are present; the engine computes links and asset enrolments and hands them to its
   directory, which the asset registry and the topology store write in one transaction.
6. **Web DAST** (`core/web/tasks.py`, the `web-worker` with queues `web_recon`, `web_crawl`,
   `web_dast`, `web_audit`): recon → crawl → detect → audit, on the settings Audit registers;
   a beat reaper settles stalled web scans.
7. **Compliance** (`core/compliance_tasks.py`, queue `compliance`): rules are evaluated
   against evidence the producing capabilities provide (§4); re-verification records its
   observations through the findings writer and the asset registry.
8. **Reporting and the dashboard** read through the owners' read modules
   (`core/findings/summaries.py`, `core/asset_reads.py`, `scans/reads.py`,
   `scans/report_context.py`, `core/web/reads.py`, `ccure_audit/services/`) and render with
   `reporting/` (renderers take a payload; they query nothing).

Detail per engine: [`../SCAN_ENGINE_DEEP_DIVE.md`](../SCAN_ENGINE_DEEP_DIVE.md); processes,
queues and tasks: [`../SYSTEM_ARCHITECTURE.md`](../SYSTEM_ARCHITECTURE.md).

## 7. Boundaries that CI enforces

- A module imports only itself, `ccure_platform.api`, `ccure_contracts` and `db.base`;
  nothing imports a module (`module-isolation`, `module-is-private`). A module's tables
  live in its own schema and are registered in
  `Backend/scripts/architecture/table_ownership.yaml`; its tests live in
  `Backend/tests/modules/<key>/`. See [Phase 11](PHASE11_MODULE_FOLDERS.md) and the
  module READMEs (`Backend/ccure_policy/README.md`, `Backend/ccure_rank/README.md`).
- Layering and import cycles: `Backend/scripts/architecture/layer_rules.py`
  (`python -m scripts.architecture.import_graph --violations`).
- Coupling between Audit's capabilities: `Backend/scripts/architecture/capability_map.py`, a
  ratchet in both directions (§3): a figure that rises fails, and one that falls must be
  recorded with `--write-baseline` and a lower ceiling. Absolute rules beside it: no layer-3
  capability imports a higher layer, the platform loads no Audit capability, and no engine
  library loads SQLAlchemy, FastAPI, Celery or Redis. A refactoring step is measured before and
  after with `interface_snapshot.py` (routes, limits, Celery tasks, beat, OpenAPI) and
  `import_cost.py` (what importing a module loads), beside it
  ([refactoring log](MODULAR_REFACTORING_LOG.md) §6).
- Single writers: the row-change and single-writer guards in §5.
- Engine libraries: `Backend/scripts/architecture/library_isolation.py` (D1) imports and runs
  each of the ten libraries in a fresh interpreter that admits only what it declares.
- Identity boundary and token signing: `tests/repo/test_identity_boundary.py`,
  `tests/repo/test_token_guardrails.py`. Outside the composition root, which hands the
  any-kind token decoder to the rate-limit audit, no module code imports an identity model or
  that decoder.
- Frontend: one application, one folder per product (`Frontend/modules.config.js`,
  [Phase 12](PHASE12_FRONTEND_SHELL.md), [`../FRONTEND_ARCHITECTURE.md`](../FRONTEND_ARCHITECTURE.md)).
  Products never import each other, and the shell names no product.
- Database: Alembic has three heads (Audit, `policy_pro`, `rank`); always `upgrade heads`.
  No module database roles before Phase 18 ([prepared, not applied](PHASE18_DATABASE_ISOLATION.md)).

**Where they run** ([`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)): the
`architecture-guards` pre-commit hook runs `check.py` on every backend commit;
`scripts/ci/local_guard_tests.sh` runs the database-backed guard tests and the D1 harness in
throwaway containers; on GitHub, every push to the `github` remote runs all three
(`ci.yml` for pull requests, `master`, tags and nightly; `architecture.yml` for other
branches).

**Deferred (project owner, 3 Nov 2026)** — follow-up hardening, not part of this milestone:

- **GitLab CI enforcement** (decision D-5). GitLab, where merge requests land, runs no
  pipeline; a merge request reaches the guards only when its commit is also pushed to
  `github`.
- **The findings golden replay** of the final tree against a restored database
  (`Backend/scripts/verification/findings_golden/`).
- **The commit-4 hook discrepancy**: the `openapi-contract` hook reported a modification
  while committing `a53656e` that left no change; the hook passes on that tree and on the
  final `HEAD`.

## 8. Adding a capability without reintroducing coupling

1. **Place it.** Give its package a prefix in `PREFIXES` (and an entry in `CAPABILITIES`,
   with its layer, if it is new). A module that belongs to no capability fails the build.
2. **Own its tables.** Add each new table to `table_ownership.yaml` with its owner and
   capability in the same change. Only this capability writes them; anyone else calls its
   writer.
3. **Depend downward.** Import lower layers at module level. If you need something a higher
   or same-layer capability owns, declare a port in your capability (a `Protocol`, a
   `register_…` function, a `…Missing` error), let the owner answer it, and register the
   answer in a `ccure_audit/` module loaded by Celery's `imports` or `main.py`. Never answer
   empty when nothing is registered.
4. **Reach identity through `ccure_platform.api`** and nothing else; authorize with
   `require_authorized(key)` or `has_permission`.
5. **Tasks**: define them in the capability's task module, dispatch by name
   (`core/task_names.py`), declare their own time limits, and re-pin `task_registry.json`.
6. **Engines stay libraries**: no settings, database or Redis at import; take them as
   arguments or through a registered settings object (the `core/web/settings.py` pattern), and
   declare the library in `library_isolation.py` with a test that runs without a database.
7. **Check**: `python3 Backend/scripts/architecture/check.py`,
   `python -m scripts.architecture.capability_map --check` (from `Backend/`) and
   `scripts/ci/local_guard_tests.sh`. If a figure fell, rewrite the baseline and lower its
   ceiling in the same change; never raise a ceiling or add a `KNOWN_*` entry to pass.

The detailed rules, with the reasons behind each, are `.claude/rules/architecture-boundaries.md`
and `.claude/rules/modules-contracts.md`.

## 9. Shared platform: identity, organisations, roles, permissions

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

## 10. Reference and runbooks

| Subject                    | Document                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Module independence        | [`MODULE_INDEPENDENCE_ANALYSIS`](MODULE_INDEPENDENCE_ANALYSIS.md) — the coupling measured on 16 Oct 2026 and the plan that followed; [`MODULAR_REFACTORING_LOG`](MODULAR_REFACTORING_LOG.md) — each step, its figures and its verification. The current figures are §3 above                                                                                                                      |
| System, API, database      | [`SYSTEM_ARCHITECTURE`](../SYSTEM_ARCHITECTURE.md), [`BACKEND_API_REFERENCE`](../BACKEND_API_REFERENCE.md), [`DATABASE_SCHEMA`](../DATABASE_SCHEMA.md) (the last two are checked against the code by a test)                                                                                                                                                                                      |
| Scan engines               | [`SCAN_ENGINE_DEEP_DIVE`](../SCAN_ENGINE_DEEP_DIVE.md), [`gap_closure/GAP_TRACKER`](../gap_closure/GAP_TRACKER.md)                                                                                                                                                                                                                                                                                |
| Gateway and edge           | [`phase10/`](phase10/): [characterisation](phase10/PHASE10_1_CHARACTERISATION.md), [design](phase10/PHASE10_2_DESIGN.md), [TLS](phase10/PHASE10_4_TLS.md), [cutover](phase10/PHASE10_5_CUTOVER.md), [hardening](phase10/PHASE10_6_HARDENING.md), [gateway-only](phase10/PHASE10_7_GATEWAY_ONLY.md); recorded route tables `phase10/route_table.json` and `route_auth_matrix.json` are test inputs |
| CI, images, security gates | [`../ci/BRANCH_PROTECTION.md`](../ci/BRANCH_PROTECTION.md), [`../ci/CONTAINER_IMAGES.md`](../ci/CONTAINER_IMAGES.md), [`../ci/SECURITY_GATES.md`](../ci/SECURITY_GATES.md), [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)                                                                                                                                                            |
| Frontend design system     | [`../ux4g/UX4G_STANDARD.md`](../ux4g/UX4G_STANDARD.md)                                                                                                                                                                                                                                                                                                                                            |
| Compliance engine          | [`../policy compliance/`](<../policy compliance/compliance_developer_guide.md>)                                                                                                                                                                                                                                                                                                                   |
| API → UI coverage          | [`../api_ui_coverage/README.md`](../api_ui_coverage/README.md)                                                                                                                                                                                                                                                                                                                                    |
| Audit chain and retention  | [`../AUDIT_CHAIN_DBA_HANDOFF.md`](../AUDIT_CHAIN_DBA_HANDOFF.md), [`../AUDIT_VERIFICATION_GAPS.md`](../AUDIT_VERIFICATION_GAPS.md)                                                                                                                                                                                                                                                                |
| Setup, TLS                 | [`../DEVELOPER_SETUP_GUIDE.md`](../DEVELOPER_SETUP_GUIDE.md), [`../TLS_SETUP.md`](../TLS_SETUP.md)                                                                                                                                                                                                                                                                                                |

## 11. Not in this repository

The platform master plan (`CCURE_PLATFORM_MODULAR_ARCHITECTURE.md`, revision 4, 28 Sep 2026)
and the measured starting point (`MODULE_INDEPENDENCE_BASELINE.md`, 25 Sep 2026) are cited by
several phase records but were never committed, on the project owner's instruction at the time.
They are not needed to build against the contracts above; ask the project owner if you need them.

For the state of module independence, the authoritative documents are in this repository:

- §3–8 of this page are the current state.
- [`MODULE_INDEPENDENCE_ANALYSIS.md`](MODULE_INDEPENDENCE_ANALYSIS.md) is the report measured
  on 16 Oct 2026 that planned the work. It replaces the 25 Sep baseline as the reference point.
- [`MODULAR_REFACTORING_LOG.md`](MODULAR_REFACTORING_LOG.md) is the step-by-step record of
  the work that follows from it.

Whether the two September documents are committed as history under
[`../archive/architecture/`](../archive/architecture/) is decision D-9 in that report.

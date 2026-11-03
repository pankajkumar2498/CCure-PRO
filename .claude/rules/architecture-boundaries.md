---
paths:
  - "Backend/**"
  - "scripts/ci/**"
  - ".github/workflows/**"
---

# Architecture guardrails (modular-platform programme)

> Scoped instructions. Claude Code loads this file when it reads or edits a file matching the `paths` above; every other agent is routed here by `AGENTS.md`. The text was moved verbatim from `CLAUDE.md` at `9bb84d9` (lines 262–492) and is maintained here. Frozen original: `docs/archive/engineering-record/architecture-guardrails.md`. The repository-wide rules in `CLAUDE.md` still apply.

## Architecture guardrails (modular-platform programme)

This repository is being refactored into the common CCure platform (Policy
Pro, Audit, Rank, IR). `tests/repo/test_architecture_guardrails.py` holds the
line while that happens, and it is a **ratchet in both directions**:

- **Layering** — `Backend/scripts/architecture/layer_rules.py` forbids twelve
  directions of dependency (routers are the HTTP edge; models are leaves;
  engines are libraries; the scan task modules are not imported back; shared
  infrastructure imports no features; identity does not import scanning;
  `ccure_contracts` imports no module's code; the three `ccure_audit` rules
  below; …),
  each with its reason. `KNOWN_VIOLATIONS` recorded the 21 that existed on
  25 Sep 2026 and is **empty** since Phase 3 removed them all, so every rule
  now holds without exception. A new violation fails CI. Never add an entry to
  make a build pass — move the shared code down a layer instead.
- **Import cycles** — `KNOWN_CYCLES` is empty for the same reason: the three
  cycles recorded in Phase 2 are broken, and any module-level cycle fails.
- **Table ownership** — `Backend/scripts/architecture/table_ownership.yaml`
  names the owning module (`platform`, `audit`, later `policy_pro`/`rank`/`ir`)
  of every table. **A new table needs an entry in the same change.**

**Scan tasks, stored credentials, the findings writer, compliance's
evidence and catalogue, the phase hand-off, the findings/assets read paths
and the compliance router (Phase C, G1–G6, 22–24 Oct 2026).** Record:
`docs/architecture/MODULAR_REFACTORING_LOG.md` §6.

- **The scan tasks live in `scans/tasks/`**, one module per area: `phases`,
  `credentialed`, `credentialed_sync`, `topology`, `maintenance`, `schedules`,
  `reapers`, over the shared helpers in `common`.
  - **Dispatch by name.** Nothing outside that package imports a task module;
    code that starts a task dispatches it by name, with `core/task_names.py` and
    `core.celery_app.registered_task`. `main.py` loads the task modules at
    start-up through Celery's loader.
  - **The registry is pinned.** `scripts/architecture/task_registry.json` pins
    every task's name, queue, limits, options and signature
    (`tests/repo/test_task_registry.py`).
- **`core/tasks.py` is gone** (2 Nov 2026). It was the facade re-exporting
  every name the hub defined; each is imported from the module that owns it
  now (`OWNERS` in `tests/repo/test_task_modules.py`, which fails on an import
  or patch of `core.tasks` in the application, the tests, the scripts or the
  documents' scripts). `layer_rules` still forbids importing `core.tasks`.
  - **Where to patch:** in the `scans.tasks` module whose code reads the name.
    `mark_scan_failed`, for instance, is read inside `_settle_failure`, in
    `scans.tasks.common`.
  - **The guard:** `tests/repo/test_task_modules.py` checks every patch does
    this.
- **Only the credential vault touches `compliance_credentials`.** Its model is
  `db/models/credentials.py` (`db.models.compliance` re-exports the names), and
  only `core/credential_vault.py` and its router query it. Everything else asks
  the vault:
  - `get_for_org`, for a row in an organisation;
  - `resolve` / `connection_material`, for what a collector connects with;
  - `stored_secrets`, for compliance remediation, which deliberately keeps its
    own form;
  - registered **reference counters**, which say how many records a deletion
    leaves without a credential (scheduling registers its own).

  `tests/repo/test_credential_vault_boundary.py` enforces this.
- **Only the findings writer writes the findings tables** (G3).
  `core/findings/writer.py` writes `services`, `tls_details`,
  `vulnerability_definitions` and `asset_vulnerabilities` for the asset syncer,
  the credentialed sync and Audit's purge hook, and holds both fixed-sweeps.
  - **The callers keep the asset and the scan.** A reopened or retired finding
    reaches the asset's change log through the `record_change` callback the
    caller passes, and the caller records the scan's assessment scope from what
    the writer returns. The writer imports no asset or scan model.
  - **A new write to a findings table goes in the writer.**
    `tests/repo/test_findings_writer.py` refuses one anywhere else, as an ORM
    write, in SQL, or as an attribute set on a row loaded from a findings
    model (since 1 Nov 2026, when compliance re-verification's write to
    `services` moved into `record_port_reachability`).
  - **The asset registry changes its own rows too.**
    `tests/repo/test_asset_registry_writes.py` refuses an attribute set on a
    loaded asset row anywhere else, with no exception: compliance asks
    `core/asset_compliance.py`, and the standalone credentialed audit
    `core/asset_credentialed.py` (1 Nov 2026). `scans.nvd_sync`, the NVD feed's catalogue load, is the
    one recorded SQL exception.
  - **Where to patch:** the moved code in `core.findings.writer`.
    `scans.asset_syncer._enrich_findings_with_intel` stayed, and is still
    patched there.
- **Findings and remediation are one capability** (D-6) in
  `scripts/architecture/capability_map.py` and `table_ownership.yaml`.
- **Compliance consumes evidence providers** (G4).
  - **Who answers.** `core/compliance_evidence.py` declares the evidence
    sources, keeps the registry and caches the answers. The answers live
    with their tables: `core/findings/evidence.py`, `core/asset_evidence.py`,
    `core/topology/evidence.py` and `core/web/evidence.py`.
  - **Who registers them.** `ccure_audit/evidence_providers.py`, Audit's
    composition root, which also composes `malware_scan` and
    `web_vulnerability_audit` from two producers each. Celery's `imports`
    names it, so the worker loads it at start-up and `main.py` through
    `import_default_modules()`.
  - **Without it compliance raises.** A declared source with no provider
    raises `EvidenceProviderMissing`; it does not read as not assessed.
  - **A new evidence key** goes in its provider's returned dict literal
    (`tests/compliance/test_compliance_rule_wiring.py` reads the literals);
    a new source needs a provider registered in the same change.
  - **The guard:** `tests/repo/test_compliance_evidence_boundary.py`.
- **The compliance catalogue's code is compliance's** (G4).
  - **The benchmark loader and selection** are
    `core/compliance_catalogue/benchmark_loader.py` and
    `benchmark_selection.py`; `core.benchmarks.loader` and `.selection` are
    `sys.modules` aliases of them, and module code imports the new paths.
  - **Another capability asks `core/compliance_catalogue/reads.py`**, as
    scan-policy validation does, and names no compliance table.
  - **Configuration audit imports nothing above it.** The pack format
    defines `BENCHMARK_FRAMEWORK_PREFIX`, the severity floor
    (`severity_at_least`) is the check kernel's, and the STIG loader
    passes the NIST SP 800-53 catalogue to the SCAP converter
    (`nist_controls`, from `core.compliance_seeds`).
  - **The guard:** `tests/repo/test_compliance_catalogue_boundary.py`.
- **One pipeline definition, and a typed hand-off between phases** (G5).
  - **The pipeline is `scans/pipeline.py`:** the modes' phases (re-exported by
    `scan_helpers`), the three network phases by registered name, `next_phase`
    and `hand_over`. No phase task starts another, and the browser's
    continuation hands over through it too.
  - **What crosses is `core/phase_handoff.py`:** `HostRecord` into asset
    discovery, `ServiceInventory` into the vulnerability audit, and the
    identity merge.
  - **A record crosses as its producer's own dict, never a copy.** The
    receiving phase's engines edit it in place, and phase 3 reads the edits
    back when it restores identity.
  - **The guard:** `tests/repo/test_phase_pipeline_boundary.py`.
- **Findings never import the asset registry** (G6).
  - **Hosts come through a port.** The findings side reads a finding's
    organisation, address and name through `core/findings/hosts.py`
    (`hosts()`, a subquery of `HOST_COLUMNS`), and hands the asset's
    counts-and-risk write over with `record_open_findings`.
  - **The asset registry answers it** (`core/asset_hosts.py`), registered by
    `ccure_audit/host_directory.py`, which Celery's `imports` names. Without it
    a read raises `HostDirectoryMissing`. A new host column the findings side
    reads goes in `HOST_COLUMNS` and the projection together.
  - **The assets router reads findings through `core/findings/reads.py`**,
    never the findings models.
  - **The guard:** `tests/repo/test_findings_assets_boundary.py`.
- **Nothing below scans reads or creates a scan record** (Group 7, 30–31 Oct
  2026). Each asker declares a port and the owner answers it:
  - comparison: `core/findings/scan_directory.py`;
  - asset timeline: `core/asset_scans.py`;
  - a policy's scan usage: `core/scan_policy/scan_usage.py`;
  - the scheduler's scan row: `core/scheduling/scan_records.py`;
  - the policy API's schedules: `core/scan_policy/schedule_references.py`,
    answered by scheduling.

  The answers are registered by `ccure_audit/scan_directory.py` (in Celery's
  `imports`) and `ccure_audit/policy_references.py` (`main.py`). An
  unregistered port raises its `...Missing` error and never answers empty.
  **The guard:** `tests/scans/test_scan_ports.py`, plus `upward_edges: 0` in
  `capability_map.py`.
- **The compliance router is mounted from its parts** (G6).
  - **The parts:** `routers/compliance_{catalogue,assessment,attestation,
    schedules,remediation,reports,framework_reports,common}.py`.
    `routers/compliance.py` mounts their sections in the historical route
    order; a new route goes in its section, in its place.
  - **Each part's `__name__` is `routers.compliance`,** so limiter keys, the
    gateway policy's endpoints and model names are unchanged. Do not "fix"
    it in passing.
  - **`routers/compliance.py` refuses a patch.** Patch the part whose code reads
    the name; the error names it.
  - **The documents are renderers:** the 21 generators are in
    `reporting/compliance/` and import nothing of compliance (the executive
    report's joined the 20 in G2).
  - **The dashboard and the report routes read through owners' modules**
    (G2): `core/findings/summaries.py`, `core/asset_reads.py`,
    `scans/reads.py`, `scans/report_context.py`, `core/web/reads.py`, and
    `scans.scan_access.report_scan_or_404` for the export lookup. A new
    dashboard or report query goes in the owner's read module; the router
    names no table.
  - **The guard:** `tests/repo/test_compliance_router_split.py`.

Imports inside functions count as dependencies — they are how this codebase
hid its cycles. `python -m scripts.architecture.import_graph` (from `Backend/`)
prints the graph; `--violations` lists every rule-breaking edge.

**Local enforcement** (16 Oct 2026):
- `python3 Backend/scripts/architecture/check.py` runs the ratchets that need
  only source with the standard library: layering, cycles, identity boundary,
  organisation settings and the secret-handling guards. The
  `architecture-guards` pre-commit hook runs it on every backend commit.
- `scripts/ci/local_guard_tests.sh` runs the database-backed guard tests in
  throwaway containers.
- `scripts/validation/` runs live scans with a commit's code against disposable
  targets on an internal Docker network, before and after a scan-path change,
  and compares what they stored (`docs/ci/LIVE_SCAN_VALIDATION.md`). These are
  the VM's standing scan targets: the target containers named in the "Test
  targets" sections below date from the Windows host and do not exist here.
- `Backend/scripts/verification/findings_golden/` replays a restored dump's
  stored scan payloads through the findings write paths with a commit's code,
  on a throwaway copy, and compares the rows, exports, comparisons and
  verification outcomes byte for byte (G3).
- `Backend/scripts/verification/pipeline_golden/` runs the phase tasks, Celery
  eager, on a copy of that golden's restored server, with the orchestrator
  replaced by a recorder, and compares every hand-off, dispatch, progress frame
  and stored phase byte for byte, failures and cancellations included (G5).
- `Backend/scripts/verification/compliance_golden/` runs the compliance
  evidence, compliance scans, re-verification, scan-policy validation,
  benchmark selection and both benchmark loaders on a restored copy with a
  commit's code, and compares what they decide byte for byte (G4).
- `Backend/scripts/verification/api_golden/` drives the findings,
  remediation, asset and compliance APIs through `main.app` on a copy of that
  golden's restored server, with a real broker: it reads every Celery message
  back from Redis and decodes it as a worker would. It compares every
  response, report digest, broker message, query plan and table (G6).
- GitLab, where merge requests land, runs no pipeline; GitHub Actions tests
  only what is pushed to `github`. `docs/ci/LOCAL_ENFORCEMENT.md` says what
  runs where.
- **Every push to `github` runs the architecture guards** (E3): `check.py`,
  the database-backed guard tests and the D1 harness. `ci.yml`'s
  `Backend Validation` covers pull requests, `master`, tags and nightly;
  `architecture.yml` covers a push of any other branch, and its filter is the
  complement of `ci.yml`'s so no push starts both. Its test targets are
  `local_guard_tests.sh`'s `DEFAULT_TARGETS`; change the two together
  (`tests/repo/test_ci_architecture_guards.py`).

Two things Phase 3 deliberately left, which are **not** violations:

- **Compatibility import paths.** `scans.cvss` and `scans.finding_normalizer`
  are `sys.modules` aliases of `core.checks.cvss` / `core.checks.finding_normalizer`
  (the same module objects, so patches and `isinstance` still work), and
  `scan_helpers.limiter` is `core.rate_limiter.limiter`. New code imports the
  new paths. Application code's limiter imports were migrated in B1
  (16 Oct 2026, `docs/architecture/MODULAR_REFACTORING_LOG.md` §6); the alias
  stays for tests and scripts. The two `scans.*` aliases move later (C3).
- **The discovery engine no longer loads SQLAlchemy** (B3, 20 Oct 2026). It came
  in through `core.risk` → `core.vuln_intel`, for two pure functions; they now
  live in `core/vuln_scoring.py`, which `core.vuln_intel` re-exports.
- **Nor do the port and network-check engines, the Nmap wrapper or the version
  matcher** (Group 3, `docs/architecture/MODULAR_REFACTORING_LOG.md` §6).
  - **The CVE client** is `engines/vulnerability/cve_lookup.py`, built at the
    first CVE lookup, never at import; `core.utils` has no CVE lookup.
  - **Ports, registered by Audit's composition root** and loaded through
    Celery's `imports`: the OUI lookup's vendor cache
    (`ccure_audit/vendor_cache.py`), the Nmap wrapper's Redis lease and cache
    and the version matcher's CVE repository (`ccure_audit/engine_ports.py`),
    and the topology engine's asset and scan directory
    (`ccure_audit/topology_directory.py`). Without a registration the vendor
    cache and the Nmap state behave as an unreachable database or Redis
    always did; the topology directory and the CVE repository raise.
  - **The rules (E1)**, absolute in `capability_map.py`: no layer-3
    capability imports a higher layer; nothing outside scans and `main`
    imports `scan_helpers`; the platform loads no Audit capability; and E2
    pins `PINNED_ENGINES`.
  - **The topology engine computes and writes nothing** (2 Nov 2026). It
    reads `AssetRecord`s and `StoredLink`s and hands each run's enrolments,
    filled asset gaps and link rows to its directory as one `TopologyPlan`;
    `run_topology_mapping(db, …)` and `get_topology_graph(db, …)` keep their
    signatures and only pass `db` along. The asset registry writes the assets
    (`core/topology_assets.py`) and the topology store, the only writer of
    `network_links`, the links and the transaction (`core/topology/links.py`),
    composed by `ccure_audit/topology_directory.py`. The pure id helpers are
    `db/ids.py`, re-exported by `db.base`. The engine is D1 library
    `topology`; `tests/topology/test_topology_store.py` pins the writers.
- **Web DAST reads its settings through `core.web.settings`, never `config`**
  (Group 4, D2). `current()` answers the object a host registered; Audit
  registers `config.WebScanConfig` itself (`ccure_audit/web_settings.py`, in
  Celery's `imports`), so patch a setting on `WebScanConfig` as before. A new
  setting read without a default goes in `READ`. The engine runs in the D1
  harness as library `web_dast`, and `tests/web/test_web_dast_pilot_host.py`
  fails if any web DAST module imports `config`.
  - **The router names no identity, session or limiter of its own** (2 Nov
    2026). The progress socket signs in through
    `ccure_platform.api.websocket_user` (None means close 1008) and reads
    through the request's `get_db` session, closed before it subscribes. The
    two limits are declared with `core.web.rate_limits.limit` and enforced by
    the limiter the host registers: Audit's is `core.rate_limiter.limiter`,
    registered by `ccure_audit/web_routes.py`, which `main.py` loads. The keys
    (`routers.web_scans.start_web_scan`, …) are unchanged; a limited route with
    no limiter registered raises `RateLimiterMissing`.
  - **The worker and the reaper** (2 Nov 2026). The web worker self-check's
    database and Redis probes are registered by the host
    (`core.web.self_check.register_infrastructure_probes`; Audit's in
    `ccure_audit/web_settings.py`); an unregistered one is a missing required
    component. The beat task `reap_stalled_web_scans` stays in
    `scans/tasks/reapers.py` with its name and queue, but lists the live web
    scans through `core.web.scan_status.non_terminal_web_scans` and asks
    `core.web.timeout.stalled_web_scans` which stalled: the scans capability
    names no `web_scans` table. Patch the listing's `SessionLocal` on
    `core.web.scan_status`.

Do not start dependency cleanup for its own sake: Phase 3's objective
(zero violations, zero cycles) is met.

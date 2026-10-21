# CCure Audit PRO — module independence analysis and refactoring plan

|                   |                                                                                                                                                                                                                                                          |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Date**          | 16 Oct 2026                                                                                                                                                                                                                                              |
| **Code baseline** | Measured on `Improvements` @ `23f8e72`. The refactoring branch `refactor/modular-architecture` starts at `master` @ `c0c0f4e`, whose backend code is identical (the ten commits between them change docs, CI actions and the Dockerfile's base image).   |
| **Status**        | The authoritative current-state report for module independence. Sections 1–12 are the **16 Oct 2026 baseline** and stay as measured. Progress since then is in §0 and, step by step, in [`MODULAR_REFACTORING_LOG.md`](MODULAR_REFACTORING_LOG.md).      |
| **Scope**         | The whole repository: backend, frontend, database, workers, deployment, tests and CI                                                                                                                                                                     |
| **Relationship**  | Re-measures the starting point recorded on 25 Sep 2026 (`MODULE_INDEPENDENCE_BASELINE.md`, never committed) after Phases 1–12, RBAC-1…8 and the platform extraction. It refines the open part of the programme — Phase 16 and the enforcement around it. |
| **Reviewer**      | Project owner; Audit team for sections 7–10                                                                                                                                                                                                              |

The modular-platform programme already decided the shape at the **product** level, and
that shape holds: one gateway, a core service with Policy Pro, Audit and Rank, IR as its
own service ([`README.md`](README.md)). This document is about what is still tangled: the
**capabilities inside Audit**, and the few places where the shared platform still leans on
Audit at run time.

---

## 0. Progress since the baseline

| Item                                                                                | State                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Commit                                  | Record                                                             |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------------------------------------------------------------------ |
| S1 sudo password in the remediation command line                                    | **Fixed** — `SSHScanner.run_sudo`; piped-sudo commands refused; application-wide guard                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `6925b2b`                               | log §2                                                             |
| S2 two credential APIs with different rules                                         | **Fixed** — one service (`core/credential_vault.py`), one permission set, legacy contract preserved                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | `cb62582`                               | log §2                                                             |
| S2b a third credential list (`GET /scan-schedules/credentials`) readable by viewers | **Fixed** — the picker requires `audit.credential.read` and lists through `core/credential_vault.py`; schedule workflows unchanged for the roles that manage schedules                                                                                                                                                                                                                                                                                                                                                                                                                                                              | `c12851b`                               | log §4                                                             |
| S3 non-scanning queues in the privileged worker                                     | **Proposed, not deployed** — awaiting D-4; current routing pinned by a test                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `9a32319`                               | [`WORKER_PRIVILEGE_SEPARATION.md`](WORKER_PRIVILEGE_SEPARATION.md) |
| S4 enforcement                                                                      | **Local enforcement in place** — stdlib pre-commit hook and a throwaway-container runner. The original finding was partly wrong about CI (corrected in §14)                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `2d4509d`                               | [`../ci/LOCAL_ENFORCEMENT.md`](../ci/LOCAL_ENFORCEMENT.md)         |
| A1 documentation                                                                    | **Done** — this report adopted as the current-state report; progress here, steps in the log                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | `99d511b`                               | log §3                                                             |
| A2 capability map and ratchet                                                       | **Done** — `Backend/scripts/architecture/capability_map.py`; the figures here reproduce with this report's method, and the committed map's baseline is recorded in the log                                                                                                                                                                                                                                                                                                                                                                                                                                                          | `aa215dc`                               | log §3                                                             |
| A3 shared JSON-contract tests                                                       | **Done** — six shared keys pinned by shape; the rest documented with the reason they are not                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | `780d936`                               | log §3                                                             |
| B1 limiter imported from `core.rate_limiter`                                        | **Done** — 9 modules stop loading `scan_helpers` (the web router: 125 → 70 first-party modules, no Scapy, nmap or ReportLab); upward edges 50 → 43; interfaces identical                                                                                                                                                                                                                                                                                                                                                                                                                                                            | `ffbc170`                               | log §6                                                             |
| B2 engines take a progress sink and a cancellation token                            | **Done** — `core/engine_ports.py`; discovery, port and network-check engines no longer import `core.scan_control` or `core.redis_client`; the web-scan settler moved to `core/web/scan_status.py`; upward edges 43 → 40, foreign references 80 → 79; interfaces and live scans identical                                                                                                                                                                                                                                                                                                                                            | `6986194`                               | log §6                                                             |
| Live-scan validation tooling                                                        | **Done** — `scripts/validation/`: isolated, digest-pinned targets on an internal network, a per-commit runner, the harness and the comparison, with their isolation pinned by tests; since `e7f7368` and `3f7794f`, fixed target MACs and a comparison that tolerates, and prints, timing-only frame differences; since `44cb889` the harness sets Scapy's interface itself, so the scanner sees its targets whatever order Docker attaches its networks in                                                                                                                                                                         | `22aa824`                               | [`../ci/LIVE_SCAN_VALIDATION.md`](../ci/LIVE_SCAN_VALIDATION.md)   |
| B3 discovery stops loading the vulnerability-intelligence database layer            | **Done, first half** — the pure scoring helpers moved to `core/vuln_scoring.py`, re-exported by `core.vuln_intel`; importing discovery loads 367 modules instead of 474 and no SQLAlchemy; the port and network-check engines still load it through `core.utils` (half B deferred, log §7); interfaces identical                                                                                                                                                                                                                                                                                                                    | `ad4aab7`                               | log §6                                                             |
| B4 the benchmark package stops re-exporting its database loader                     | **Done** — `core/benchmarks/__init__.py` exports the pure `pack` API only; the loader's callers import it by name; the SCAP compiler loads 32 first-party modules instead of 61, and no database; interfaces identical                                                                                                                                                                                                                                                                                                                                                                                                              | `f4e05e2`                               | log §6                                                             |
| B5 the network checks register their plugins with the check kernel                  | **Done** — `core.checks.legacy_plugins` takes plugins from a registered `PluginSource` and imports no engine; `plugin_selector` registers its own dispatch table and strict loader; upward edges 40 → 38; the check kernel imports no non-shared capability; every plugin-contract answer and live scans identical                                                                                                                                                                                                                                                                                                                  | `54f912d`                               | log §6                                                             |
| B6 the topology engine takes the organisation's slug from its task                  | **Done, partly** — the engine no longer imports the platform API and takes `org_slug` (required) from its task; importing it loads 32 first-party modules instead of 62 and no FastAPI, `jose`, Starlette or Redis; the plan's "~15" is not reached, because the engine's own `Asset`/`Scan` access loads the model registry (log §7); interfaces and live scans identical                                                                                                                                                                                                                                                          | `ff7ddca`                               | log §6                                                             |
| B7 the PDF renderer takes its engine inputs from the payload                        | **Done** — coverage rows and truncated-search notes travel as `report_inputs` (`scans/report_inputs.py`); the renderer loads 15 first-party modules instead of 24 and no SQLAlchemy; report bytes identical (22-PDF golden); lateral edges 74 → 72; the capability cycle splits 22 → 16 + 4 + 2 and the renderers leave the top-level cycle                                                                                                                                                                                                                                                                                         | `234a423`                               | log §6                                                             |
| B8 the orchestrator composes the engines; the platform registers its models alone   | **Done** — the port engine's SNMP/OT enrichment and discovery's SNMP read are composed by `orchestrator/host_enrichment.py` (orchestrator golden byte-identical); Audit's seven back-references onto `Organization`/`User` are one-sided, and the one effect one of them had (clearing a purged user's web scans) moved to the web capability's purge step; `ccure_platform.models` is the platform's own registry and no platform module loads `db.models` — `ccure_platform.api` loads 49 first-party modules instead of 59 and no Audit model; upward 38 → 37, lateral 72 → 70, cycle 16 → 15; full suite 8,020 passed, 0 failed | `6cd4ca3` `eb52943` `a6a23b6` `fe5baaf` | log §6                                                             |
| B9 the TLS engine moves below the network checks and web DAST                       | **Done** — the sslyze wrapper moved to `engines/tls/` (its own layer-2 capability), with the old path a `sys.modules` alias; the network checks import nothing from the web module, and with `core.web` unimportable the TLS plugin's deep assessment still runs (on the parent it silently did not); golden byte-identical against a live TLS listener; lateral edges 70 → 69                                                                                                                                                                                                                                                      | `bc4f7da`                               | log §6                                                             |

---

## 1. Summary

**What is already true, and measured as true today**

- No module-level import cycle and no layer-rule violation in the backend (`import_graph`, 480
  modules, 1,700 import edges).
- The identity boundary holds: 3 importers, 2 identity queries, 0 identity joins in module code,
  every one of them recorded and reasoned (`identity_boundary.py`).
- Policy Pro and Rank are isolated and empty; `ccure_contracts` is a true leaf (loads 1 module).
- The frontend is one application with product folders that do not import each other; the shell
  names no product. Coupling between Audit's own screens is light.
- Several engines are already libraries: the SSH, WinRM, SMB and database transports (3–4 modules
  each), the configuration-audit engine (23 modules, no database), the check contract, the XLSX
  renderer, recurrence, and the RBAC engine.

**What is not**

1. **Audit's capabilities form one dependency knot.** Grouped into 27 functional capabilities,
   **23 sit in one strongly connected set** when lazy imports are counted, and 20 with
   top-level imports alone. 810 imports cross a capability boundary (424 top-level, 386 inside
   functions). The module-level ratchet cannot see this: each edge is acyclic file to file, but the
   capabilities as wholes all depend on one another.
2. **Two hubs carry most of it.** `core/tasks.py` (5,704 lines, 15 Celery tasks) reaches 15
   other capabilities; about 3,700 of its lines are credentialed-audit application logic and its
   persistence. `routers/compliance.py` (7,479 lines, 47 routes) also holds 20 PDF/DOCX
   generators and a second credential API.
3. **Persistence is shared, not owned.** Findings tables are written by the asset syncer and the
   task hub, not by a findings capability; compliance reads six other capabilities' tables;
   the configuration-audit content loader writes the compliance catalogue.
4. **Engines load infrastructure by accident.** The discovery, port and network-check engines all
   load SQLAlchemy and the database package through `core.risk`/`core.utils` → `core.vuln_intel`;
   the SCAP compiler loads 61 modules including the whole model registry; the web-DAST router loads
   125 modules — Scapy, Nmap and ReportLab included — because it takes the rate limiter from
   `scan_helpers`.
5. **The platform still loads Audit at run time.** Importing `ccure_platform.api` loads the whole
   model registry — all 14 model files, 10 of them Audit's — and Audit's models attach seven
   back-references onto the platform's `Organization` and `User` classes.

**Recommendation.** Stay a modular monolith inside the core service — no new services. Make
Audit's capabilities explicit, measured modules and remove real dependencies before moving any
folder:

- **Phase B — ten low-risk moves.** They remove 41 import edges and, measured by simulation,
  shrink the capability knot from 20 capabilities to 10. Every engine, kernel and renderer leaves
  the cycle.
- **Phase C — five structural refactors.** They dissolve the remaining persistence and
  orchestration knot: task dispatch by name, a split task hub, one findings writer, compliance
  evidence providers, and one credential vault.
- **Phases D and E.** Prove reuse in an isolated harness, then hold the result with
  capability-level ratchets. GitLab, where merge requests land, runs no
  pipeline, and GitHub Actions tests only what is pushed to it (§13, corrected after publication),
  so enforcement has to be restored first.

**Four findings to deal with before refactoring** (§14). The most serious: the compliance
remediation executor writes the customer's sudo password into the remote command line — the
pattern CLAUDE.md records as fixed in the collectors — through a second SSH path the existing
guard does not inspect.

**Baseline tests run for this report:**

- backend `tests/repo`, `tests/modules` and `tests/audit_boundary`: **964 passed, 1 skipped,
  0 failed**;
- frontend boundary tests: **94 passed**.

Appendix B gives the exact runs.

---

## 2. How this was measured

All figures are for `23f8e72`. Nothing was inferred from folder names or documents.

| Measurement                | Method                                                                                                                                                                                                                                                                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Import graph               | The repository's own `scripts/architecture/import_graph.collect_edges` (AST, top-level and lazy imports separately). Each of the 480 modules was then assigned to a functional capability by the prefix map in Appendix A. `from db.models import X` (the registry) was resolved by class name to the model file that defines `X`.         |
| Cycles                     | Tarjan's strongly connected components (the tool's own) over the capability graph, with and without lazy imports.                                                                                                                                                                                                                          |
| What loads                 | (a) static transitive closure of top-level imports from each entry point; (b) **verified by real imports**: each entry point imported alone in a fresh interpreter inside the release image (`ccure-audit-pro-backend:latest`, `--network none`, read-only copy of HEAD's `Backend/`, no `.env`). The two agree to within the alias stubs. |
| Data access                | Every model class mapped to its table; every module scanned for references, constructions and `insert`/`update`/`delete` of those classes, plus table names in SQL string literals. Table owners from `scripts/architecture/table_ownership.yaml` (`capability` field).                                                                    |
| Foreign keys and relations | `ForeignKey("table.col")` declarations and `relationship(…, backref=…)` in every model file.                                                                                                                                                                                                                                               |
| Settings                   | `AppConfig` attributes read per capability; `os.getenv`/`os.environ` reads outside `config.py`.                                                                                                                                                                                                                                            |
| Frontend                   | Every `import`/`export … from`/`import()` in `Frontend/src` resolved through the `@shell`/`@audit`/… aliases, grouped by feature; HTTP calls made outside an `api/` module counted.                                                                                                                                                        |
| Runtime and deployment     | `docker-compose.yml` services, queues and capabilities; Celery task definitions and the beat schedule; CI workflow and pre-commit configuration.                                                                                                                                                                                           |

**Limits.** A "write" is detected only when a module constructs a model or issues a bulk
`insert`/`update`/`delete`. A module that loads a row and assigns to its attributes also writes, and
is counted only as a reference. So foreign-write counts are a floor, not a total. Import isolation
measures what loads, not everything a module touches when it runs.

---

## 3. Module inventory

### 3.1 Backend capabilities

Sizes are lines of application code (tests, scripts and migrations excluded). Tables are those
the ownership registry assigns to the capability.

| Capability             | Purpose                                                              | Main code                                                                                                                                                                                                                            | Files / lines | Tables owned                                                                                                 | Celery (queue)                                                               | Route decorators |
| ---------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------- | ------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- | ---------------- |
| **platform**           | Identity, organisations, RBAC, audit log, notifications, module hub  | `ccure_platform/` (+ alias stubs in `auth/`, `routers/admin_*`, `core/audit*`, `db/models/users,rbac`)                                                                                                                               | 105 / 22,598  | 17 (users, organizations, `rbac_*`, `audit_logs`, `notifications`, …)                                        | 12 (`default`)                                                               | 109              |
| **infra**              | Settings, session, Celery app, Redis, rate limiting, crypto, uploads | `config.py`, `db/base.py`, `core/celery_app.py`, `core/rate_*`, `core/security_crypto.py`, `core/upload_guard.py`, …                                                                                                                 | 25 / 4,620    | —                                                                                                            | —                                                                            | 1                |
| **scan_kernel**        | Audit's scan-domain constants and helpers living in "infrastructure" | `core/constants.py` (port DB, OS maps), `core/utils.py`, `core/models.py`, `core/mac.py`, `core/risk.py`                                                                                                                             | 5 / 2,514     | —                                                                                                            | —                                                                            | —                |
| **check_kernel**       | The common check/finding contract and normaliser                     | `core/checks/` (+ aliases `scans/cvss.py`, `scans/finding_normalizer.py`)                                                                                                                                                            | 14 / 6,108    | —                                                                                                            | —                                                                            | —                |
| **vuln_intel**         | Read access to the separate `vuln_intel` database; NVD sync          | `core/vuln_intel.py`, `core/cve_database.py`, `scans/nvd_sync.py`, `scans/cve_engine/`, `routers/admin_nvd.py`                                                                                                                       | 10 / 2,611    | (own database)                                                                                               | —                                                                            | 2                |
| **discovery**          | Phase 1: live hosts (Scapy)                                          | `core/discovery/`, `engines/discovery/`, `orchestrator/host_discovery_api.py`                                                                                                                                                        | 17 / 3,451    | —                                                                                                            | via task hub                                                                 | —                |
| **port_inventory**     | Phase 2: ports, services, OS (Nmap)                                  | `core/nmap/`, `engines/port/`                                                                                                                                                                                                        | 5 / 2,251     | —                                                                                                            | via task hub                                                                 | —                |
| **network_checks**     | Phase 3 unauthenticated checks (15 plugins)                          | `engines/vulnerability/`, `core/candidate_enumeration.py`                                                                                                                                                                            | 22 / 7,780    | —                                                                                                            | via task hub                                                                 | —                |
| **credentialed_audit** | Authenticated collection, package matching, OS patch level           | `engines/credentialed/`, `core/credential_scope.py`, `routers/credentialed.py` (+ ~3,700 lines of `core/tasks.py`)                                                                                                                   | 16 / 9,918    | —                                                                                                            | via task hub                                                                 | 1                |
| **credential_vault**   | Stored credentials (encrypted)                                       | `routers/credentials.py` (+ the model in `db/models/compliance.py`, + a second API in `routers/compliance.py`)                                                                                                                       | 1 / 806       | `compliance_credentials`                                                                                     | —                                                                            | 7 (+3 duplicate) |
| **config_audit**       | Configuration/hardening engine, benchmark packs, SCAP/OVAL           | `core/config_audit/`, `core/benchmarks/`, `core/scap/`, `routers/config_audit.py`                                                                                                                                                    | 45 / 19,463   | — (writes compliance's)                                                                                      | via task hub                                                                 | 4                |
| **assets**             | Asset registry, correlation, AMT, MAC vendors, asset timeline        | `scans/asset_syncer.py`, `core/asset_correlation.py`, `core/amt_reconciliation.py`, `core/oui_lookup.py`, `routers/assets.py`, …                                                                                                     | 9 / 7,332     | 6 (`assets`, `asset_*`, `mac_vendor_cache`, `amt_inventory_records`)                                         | 2 (task hub)                                                                 | 17               |
| **findings**           | Findings store, comparison between scans, fix state                  | `core/findings/`, `routers/findings.py`, `db/models/findings.py`                                                                                                                                                                     | 6 / 2,754     | 5 (`services`, `tls_details`, `http_security_details`, `vulnerability_definitions`, `asset_vulnerabilities`) | —                                                                            | 6                |
| **remediation**        | Remediation workflow, SLA, verification                              | `core/remediation/`, `routers/remediation.py`                                                                                                                                                                                        | 7 / 2,853     | `finding_remediation_events`                                                                                 | 1 (task hub)                                                                 | 12               |
| **scans**              | Scan records, phase persistence, scan API, orchestration             | `orchestrator/scan_orchestrator.py`, `scans/db_helpers.py`, `scans/legacy_json_builder.py`, `scan_helpers.py`, `core/scan_control.py`, `core/scan_scope.py`, `routers/{phase_scans,scan_history,scan_progress,traditional_scans}.py` | 17 / 7,277    | `scans`, `scan_phases`                                                                                       | —                                                                            | 22               |
| **task_hub**           | Celery tasks for every scan phase, credentialed audit, maintenance   | `core/tasks.py`                                                                                                                                                                                                                      | 1 / 5,704     | —                                                                                                            | 15 (`scanner`, `default`)                                                    | —                |
| **scan_policy**        | Reusable scan policies and snapshots                                 | `core/scan_policy/`, `routers/scan_policies.py`                                                                                                                                                                                      | 8 / 2,694     | `scan_policies`                                                                                              | —                                                                            | 11               |
| **scheduling**         | Recurring scans                                                      | `core/scheduling/`, `routers/scan_schedules.py`                                                                                                                                                                                      | 5 / 2,079     | `scan_schedules`, `scan_schedule_runs`                                                                       | 1 (task hub)                                                                 | 10               |
| **topology**           | SNMP network topology                                                | `core/topology/`, `routers/topology.py`                                                                                                                                                                                              | 6 / 3,808     | `network_links`                                                                                              | 1 (task hub)                                                                 | 2                |
| **web_dast**           | Web application scanning                                             | `core/web/` (63 files), `orchestrator/web_orchestrator.py`, `routers/web_scans.py`, `reporting/web_pdf_generator.py`                                                                                                                 | 67 / 23,099   | 6 (`web_*`)                                                                                                  | 4 (`web_recon`, `web_crawl`, `web_dast`, `web_audit`) + 1 reaper in task hub | 13               |
| **compliance**         | Frameworks, rules, evaluation, attestation, evidence, reports        | `core/compliance_*.py`, `core/nist_csf*.py`, `routers/compliance.py`, `db/models/compliance.py`                                                                                                                                      | 9 / 13,545    | 20 (`compliance_*` except credentials)                                                                       | 5 (`compliance`)                                                             | 47               |
| **reporting**          | PDF/CSV/XLSX renderers, exports, report API                          | `reporting/`, `routers/reports.py`                                                                                                                                                                                                   | 10 / 7,805    | `scan_reports`                                                                                               | —                                                                            | 3                |
| **dashboard**          | Dashboard read model                                                 | `routers/dashboard.py`                                                                                                                                                                                                               | 1 / 1,611     | —                                                                                                            | —                                                                            | 17               |
| **audit_boundary**     | Audit's read services, contract adapter, permissions, preferences    | `ccure_audit/`                                                                                                                                                                                                                       | 22 / 3,872    | —                                                                                                            | —                                                                            | —                |
| **contracts**          | Cross-product contracts (draft v1)                                   | `ccure_contracts/`                                                                                                                                                                                                                   | 31 / 2,990    | —                                                                                                            | —                                                                            | —                |
| policy_pro, rank       | Empty module slots                                                   | `ccure_policy/`, `ccure_rank/`                                                                                                                                                                                                       | 7 / 41 each   | —                                                                                                            | —                                                                            | —                |
| main                   | Composition root                                                     | `main.py`                                                                                                                                                                                                                            | 1 / 1,153     | —                                                                                                            | —                                                                            | —                |

Totals: 480 modules, 170,944 lines; 63 tables; 36 Celery task definitions and 11 beat entries.
The route column counts decorators per router file (284 in all); the recorded API surface is
282 routes (CLAUDE.md, Phase 10 route table).

### 3.2 Frontend areas

| Area                                                                           | Lines  | Notes                                                                                                        |
| ------------------------------------------------------------------------------ | ------ | ------------------------------------------------------------------------------------------------------------ |
| `src/shell/`                                                                   | 12,266 | Platform shell, admin screens, auth, notifications; imports only the design system                           |
| `src/design-system/`                                                           | 4,098  | Imports nothing from the application                                                                         |
| Audit — scans (`pages/scan/*`, history, context, scan components)              | 14,437 | `NewScan.jsx` 2,752; `Phase1/2/3Results.jsx` 1,424 / 1,287 / 1,845                                           |
| Audit — compliance                                                             | 5,775  | `ComplianceWorkspace.jsx` 5,183 lines in one file; 31 HTTP calls made directly, not through an `api/` module |
| Audit — assets                                                                 | 4,719  | `AssetDetail.jsx` 1,672, `AssetRegistry.jsx` 1,452, AMT                                                      |
| Audit — credentialed                                                           | 4,045  | `CredentialedResults.jsx` 2,301                                                                              |
| Audit — web scanning (`modules/audit/web-scanning/`)                           | 3,209  | Self-contained: imports only the shell, the design system and Audit's shared layer                           |
| Audit — dashboard, topology, remediation, findings, policy, schedules, reports | 10,511 | `SecurityDashboard.jsx` 2,125, `NetworkMap.jsx` 1,958                                                        |
| Audit — shared (`components/common`, `layout`, `utils`, `config`)              | 1,932  |                                                                                                              |
| Policy Pro, Rank, IR                                                           | 0      | README only                                                                                                  |

---

## 4. Current-state architecture

```
                         host nginx :443 ─► api-gateway ─► gateway-auth ─► api (FastAPI, 282 routes)
                                                                          │
 ┌──────────────────────────────────────── core service process ─────────┼──────────────────────────────┐
 │  main.py (composition root: 26 routers, start-up seeding, middleware)  ▼                              │
 │  ┌──────────────── Audit ───────────────────────────────────────────────────────────────────────────┐ │
 │  │  routers (scans, assets, findings, remediation, compliance 7.5k, web, dashboard, reports, …)     │ │
 │  │      │  dispatch by import                                                                       │ │
 │  │  core/tasks.py (5.7k) ─── phases 1→2→3→3.5→4, credentialed audit, config audit, maintenance       │ │
 │  │      │                                                                                           │ │
 │  │  scans/ (db_helpers, asset_syncer 2.9k: writes assets AND findings)   orchestrator (1.5k)         │ │
 │  │      │                                                                                           │ │
 │  │  engines: discovery · port · network checks · credentialed · config-audit/SCAP · topology · web   │ │
 │  │      │       (progress → core.redis_client, cancellation → core.scan_control → scans table)      │ │
 │  │  kernels: core.checks · scan kernel (constants/utils/risk ──► vuln_intel ──► SQLAlchemy)         │ │
 │  │  compliance ── reads assets, findings, services, TLS, network_links, web_*, credentials ──┐      │ │
 │  └──────────────────────────────────────────────────────────────────────────────────────────┼──────┘ │
 │  ccure_audit (read services + contract adapter)   ccure_contracts (leaf)    ccure_policy/rank (empty) │
 │  ccure_platform (identity, RBAC, audit log, notifications)  ◄── imports nothing of Audit, but loads   │
 │                                                                  all Audit models via db.models       │
 │  infra: config.py (213 settings, one AppConfig) · db.base · celery_app · redis · rate limiting        │
 └──────────────────────────────────────────────────────────────────────────────────────────────────────┘
  workers (same image):  worker  = scanner + default + compliance queues, host network, NET_ADMIN/NET_RAW
                         web-worker = web_recon/crawl/dast/audit     beat = 11 schedules
  PostgreSQL 18: ccure_db (63 tables, 3 Alembic heads) + vuln_intel (separate, not Alembic-managed)
```

### 4.1 The capability cycle

At module level the graph is acyclic and every layer rule holds. At capability level:

| Measure                                                       | Value                                                                                                                                                                                          |
| ------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capabilities in one strongly connected set, all imports       | **23 of 27**                                                                                                                                                                                   |
| … top-level imports only                                      | **20 of 27**                                                                                                                                                                                   |
| Capabilities outside it                                       | contracts, dashboard, policy_pro, rank                                                                                                                                                         |
| Imports crossing a capability boundary                        | 810 (424 top-level, 386 lazy)                                                                                                                                                                  |
| `import_graph` component view (its own 65-component grouping) | largest cycle 25 (all) / 3 (top-level); 530 cross-component lazy imports. The 25 Sep baseline counted about 486 under a coarser 32-component grouping, so the two are not directly comparable. |

Scored against the target layering in §8 (contracts → shared → kernels → engines → domain stores →
orchestration → read models), the cross-capability imports contain:

- **57 upward edges** (a lower layer importing a higher one), 25 of them top-level, in 28
  capability pairs;
- **62 lateral edges** between different capabilities of the same layer.

The upward edges concentrate on a few targets:

| Target                                      | Upward edges | What it is                                                                                               |
| ------------------------------------------- | ------------ | -------------------------------------------------------------------------------------------------------- |
| `scan_helpers`                              | 13           | The rate-limiter re-export; importing it loads `orchestrator.host_discovery_api` → the scan orchestrator |
| `db.models.scans`                           | 5            | Lower capabilities reading the scan record                                                               |
| `core.scan_control`                         | 4            | Cancellation and terminal status, read by engines; it queries the `scans` table                          |
| `core.scan_scope`                           | 4            | Organisation scope admission, filed under scans but used by credentialed, scheduling, policy             |
| `core.tasks`                                | 4            | Routers dispatching by importing the hub                                                                 |
| `core.oui_lookup`, `core.device_classifier` | 5            | Asset-identification lookups used by engines                                                             |

---

## 5. Dependency matrix

Read across: the row capability imports the column capability.
● = at least one top-level import; ○ = only imports inside functions.

| from \ to | PLT | INF | SKN | CHK | VIN | DSC | PRT | NCK | CRA | CRV | CFG | AST | FND | REM | SCN | HUB | POL | SCH | TOP | WEB | CMP | RPT | DSH | AUD | CON |
| --------- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **PLT**   | ·   | ●   |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     | ○   |     |     |     |
| **INF**   | ●   | ·   |     |     |     |     |     |     |     |     |     | ○   |     |     | ●   |     |     |     | ○   |     |     |     |     |     |     |
| **SKN**   |     |     | ·   | ○   | ●   |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |
| **CHK**   |     | ○   |     | ·   |     |     |     | ○   |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |
| **VIN**   | ●   | ●   | ○   | ●   | ·   |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |
| **DSC**   |     | ○   | ●   |     |     | ·   |     | ○   |     |     |     | ○   |     |     | ●   |     |     |     |     |     |     | ●   |     |     |     |
| **PRT**   |     | ●   | ●   | ●   |     | ○   | ·   |     |     |     |     | ○   |     |     |     |     |     |     |     |     |     |     |     |     |     |
| **NCK**   |     | ○   | ●   | ●   | ●   |     |     | ·   |     |     |     | ●   |     |     |     |     |     |     |     | ○   |     |     |     |     |     |
| **CRA**   | ●   | ●   | ●   | ●   | ●   |     |     |     | ·   | ●   |     |     |     |     | ●   | ●   |     |     |     |     |     |     |     |     |     |
| **CRV**   | ●   | ●   |     |     |     |     |     |     | ○   | ·   |     |     |     |     | ●   | ○   |     | ○   |     |     | ●   |     |     |     |     |
| **CFG**   | ●   |     |     | ●   |     |     |     |     | ○   |     | ·   |     |     |     | ●   |     | ●   |     |     |     | ●   |     |     |     |     |
| **AST**   | ●   | ●   | ●   | ●   | ●   |     |     |     | ●   |     |     | ·   | ●   |     | ●   | ○   |     |     |     |     |     |     |     |     |     |
| **FND**   | ●   | ●   |     | ●   | ●   |     |     |     | ●   |     | ○   | ●   | ·   | ○   | ●   |     | ○   |     |     |     |     |     |     |     |     |
| **REM**   | ●   | ●   |     |     |     |     |     |     |     |     |     | ●   | ●   | ·   | ●   |     |     |     |     |     |     |     |     |     |     |
| **SCN**   | ●   | ●   | ●   | ●   | ○   | ●   | ●   | ●   | ●   |     |     | ●   | ●   |     | ·   | ●   | ●   |     |     |     |     | ●   |     |     |     |
| **HUB**   | ●   | ●   | ●   | ○   | ○   |     |     | ●   | ●   | ○   | ○   | ●   | ●   | ○   | ●   | ·   | ○   | ○   | ○   |     | ●   |     |     |     |     |
| **POL**   | ●   | ●   |     | ●   |     |     |     |     |     |     |     |     |     |     | ●   |     | ·   | ●   |     |     | ○   |     |     |     |     |
| **SCH**   | ●   | ●   | ○   |     |     |     |     |     |     | ●   |     |     |     |     | ●   |     | ○   | ·   |     |     |     |     |     |     |     |
| **TOP**   | ●   | ●   |     |     |     |     |     |     |     |     |     | ●   |     |     | ●   |     |     |     | ·   |     |     |     |     |     |     |
| **WEB**   | ●   | ●   |     |     | ○   |     |     |     |     |     |     |     |     |     | ●   |     |     |     |     | ·   |     | ○   |     |     |     |
| **CMP**   | ●   | ●   |     | ●   |     |     |     |     | ○   |     | ●   | ●   | ●   |     | ●   |     |     |     | ●   | ○   | ·   |     |     |     |     |
| **RPT**   | ●   | ●   |     | ●   | ○   |     |     | ●   | ●   |     |     | ○   | ○   | ○   | ●   |     |     |     |     |     |     | ·   |     | ●   |     |
| **DSH**   | ●   | ●   |     | ●   | ●   |     |     |     |     |     |     | ●   | ●   |     | ●   |     |     |     |     | ○   |     |     | ·   |     |     |
| **AUD**   | ●   |     |     | ○   |     |     |     |     |     |     |     | ●   | ●   | ○   | ●   |     | ○   |     |     |     | ●   |     |     | ·   | ●   |
| **CON**   |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     |     | ·   |

Key: PLT platform · INF infra · SKN scan kernel · CHK check kernel · VIN vuln intel ·
DSC discovery · PRT port inventory · NCK network checks · CRA credentialed audit ·
CRV credential vault · CFG config audit · AST assets · FND findings · REM remediation · SCN scans ·
HUB task hub · POL scan policy · SCH scheduling · TOP topology · WEB web DAST · CMP compliance ·
RPT reporting · DSH dashboard · AUD `ccure_audit` · CON contracts.

### 5.1 The edges that matter, and why each exists

| Edge                          | Cause                                                                                                                             | Why it matters                                                                      |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| INF → SCN, PLT                | `routers/health.py` → `scan_helpers`; `core.celery_app` → module registry (a leaf, acceptable)                                    | Infrastructure importing a capability pulls that capability into everyone's tree    |
| PLT → RPT                     | `ccure_platform/audit_log/export.py` → `reporting.report_helpers` (allowed by an exemption)                                       | The platform's PDF export depends on Audit's report package                         |
| SKN → VIN                     | `core/risk.py:17` and `core/utils.py:29` import `core.vuln_intel` / `core.cve_database`                                           | Every engine that uses the port database or OS fingerprinting loads SQLAlchemy      |
| CHK → NCK                     | `core/checks/legacy_plugins.py` imports `engines.vulnerability.plugin_selector` (lazy)                                            | The kernel every capability imports depends on one engine                           |
| DSC/WEB → SCN                 | `core.discovery.engine`, `core.web.tasks`, `core.web.timeout` → `core.scan_control` (lazy)                                        | Engines decide cancellation by querying the `scans` table                           |
| DSC/PRT/NCK → AST             | engines → `core.oui_lookup`, `core.device_classifier`                                                                             | Engines depend on the asset registry for vendor and device-class lookups            |
| NCK → WEB                     | `plugins/tls_scanner.py` → `core.web.sslyze.wrapper` (lazy)                                                                       | The network scan cannot run without the web module present                          |
| CFG → CMP                     | `core/benchmarks/loader.py`, `selection.py` write and read `compliance_*`; `core/benchmarks/__init__.py:37` re-exports the loader | A pure XCCDF/OVAL compiler loads the whole model registry (61 modules)              |
| CRA → SCN, HUB                | `routers/credentialed.py` → scan orchestrator, `scans.db_helpers`, `core.tasks`                                                   | The credentialed capability creates scans through the network pipeline's internals  |
| AST → FND                     | `scans/asset_syncer.py` writes `services`, `tls_details`, `asset_vulnerabilities`, `vulnerability_definitions`                    | The findings store has no single owner                                              |
| CMP → AST, FND, TOP, WEB, CRV | `core/compliance_evidence.py` queries their tables                                                                                | Compliance cannot run, or be tested, without five other capabilities' schemas       |
| HUB → 15 capabilities         | `core/tasks.py`                                                                                                                   | Every scan path, the credentialed audit and maintenance share one 5,704-line module |
| RPT → CRA, NCK                | `reporting/pdf_generator.py` → `engines.credentialed.coverage`, `core.candidate_enumeration`                                      | A renderer loads engine code and, through it, SQLAlchemy                            |
| TOP → PLT (top-level)         | `core/topology/engine.py:57` imports `ccure_platform.api`                                                                         | The SNMP engine loads FastAPI, python-jose and the model registry (62 modules)      |

---

## 6. Data ownership and runtime coupling

### 6.1 Tables touched outside their owner

Identity tables (`users`, `organizations`) are excluded here: module code reaches them through
`ccure_platform.api`, and the identity ratchet measures what remains (2 queries, 0 joins).

| Capability         | Foreign tables it references (owner)                                                                                                                              | Foreign writes detected                                              |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| assets             | `asset_vulnerabilities`, `services`, `tls_details`, `vulnerability_definitions` (findings); `scans` (scans)                                                       | **4 findings tables**                                                |
| task_hub           | `scans`, `scan_phases`, `assets`, `asset_vulnerabilities`, `vulnerability_definitions`, `compliance_credentials`, `web_scans`                                     | **`scans`, `assets`, 2 findings tables**                             |
| config_audit       | `compliance_frameworks`, `_controls`, `_rules`, `_rule_controls`, `_tenant_frameworks` (compliance)                                                               | **4 compliance tables** (benchmark loader)                           |
| compliance         | `assets`; `asset_vulnerabilities`, `services`, `tls_details`, `vulnerability_definitions`; `network_links`; `web_scans`, `web_findings`; `compliance_credentials` | `compliance_credentials` (the duplicate API)                         |
| scan_policy        | five `compliance_*` catalogue tables; `scans`; `scan_schedules`                                                                                                   | —                                                                    |
| dashboard          | 11 tables of assets, findings, scans and web DAST                                                                                                                 | —                                                                    |
| audit_boundary     | assets, compliance catalogue, findings, scans (read services, by design)                                                                                          | 4 (the user-purge hook: nulls `created_by`-style columns, by design) |
| findings           | `assets`, `scans`                                                                                                                                                 | —                                                                    |
| remediation        | `asset_vulnerabilities` (58 references), `assets`                                                                                                                 | —                                                                    |
| scheduling         | `compliance_credentials`, `scan_policies`                                                                                                                         | —                                                                    |
| topology           | `assets`, `scans`                                                                                                                                                 | `assets`                                                             |
| reporting          | `assets`, `scans`, `scan_phases`                                                                                                                                  | —                                                                    |
| web_dast           | `vulnerability_definitions` (one SQL string)                                                                                                                      | —                                                                    |
| credentialed_audit | `compliance_credentials`                                                                                                                                          | —                                                                    |

Two ownership facts follow directly:

- **Findings and remediation share one table.** `remediation_state` is a deliberate second column
  on `asset_vulnerabilities` (CLAUDE.md, "Remediation and SLA"). They are one capability with two
  sub-areas, and the registry should say so (decision D-6).
- **The findings tables have no single writer.** `scans/asset_syncer.py` (assets) and
  `core/tasks.py` write them for network and credentialed results. `core.findings` only reads and
  compares.

### 6.2 Foreign keys and ORM relationships

140 foreign-key declarations:

| Group                                         | Count  | Detail                                                                                                                                                                                                                                         |
| --------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Into the platform's `users` / `organizations` | 54     | Compliance 27, web 7, assets 4, findings 4, scheduling 4, and others. This is the database-level identity link golden rule 13 allows.                                                                                                          |
| Inside the platform                           | 18     |                                                                                                                                                                                                                                                |
| Inside one Audit capability                   | 50     | Compliance 33, web 7, findings 4, assets 3, and others                                                                                                                                                                                         |
| **Between Audit capabilities**                | **18** | findings→scans 3, assets→scans 2, findings→assets 2, compliance→assets 2, scheduling→scans 2, topology→assets 2, topology→scans 1, remediation→scans 1, scheduling→credential vault 1, compliance→credential vault 1, scheduling→scan policy 1 |

The 18 cross-capability keys are legitimate references (a finding belongs to a scan and an
asset). They stay, and they are why Audit's capabilities share one schema (§8.4).

**Reverse coupling the import ratchets cannot see.** Audit models attach back-references to
platform classes when the mappers are configured:

- `Organization.web_scans`, `.web_findings`, `.web_parameters`, `.web_forms`,
  `.web_api_operations` (`db/models/web_scans.py:172,412,509,573,637`);
- `Organization.network_links` (`db/models/topology.py:98`);
- `User.web_scans` (`db/models/web_scans.py:174`).

The platform's classes therefore change shape with whichever Audit models are loaded, and
`ccure_platform.api` loads all of them: it imports `db.models`, whose `__init__` imports every model
file. Measured with a real import, `ccure_platform.api` loads 59 application modules, including
all 14 model files (10 of them Audit's).

### 6.3 Implicit JSON contracts

Phases hand data to one another through JSON columns rather than typed values. Keys read or
written by more than one capability:

| Column                     | Keys found | Keys used by more than one capability (capabilities)                                                                                                                                                                                                                         |
| -------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scans.options`            | 51         | `credentialed_report` (scans, reporting, `ccure_audit`), `scan_policy` (policy, reporting, web), `custom_ports`, `exclude_ports`, `exclude_ips`, `exclude_ot_from_nmap`, `passive_first` (scans, scheduling, hub), `credentials` (credentialed, hub), `snmp` (hub, topology) |
| `assets.custom_attributes` | 57         | `credentialed_status` (assets, config audit, hub), `provenance` (assets, hub), `credentialed_system_info` and `password_policy` (compliance, hub)                                                                                                                            |
| `scan_phases.summary`      | 31         | `assessed`, `results` (assets, findings, `ccure_audit`, hub), `reason`, `platform`, `network_plugin_coverage`, `scan_duration`                                                                                                                                               |

These keys are contracts in all but name, and nothing checks their shape. They were found by
pattern matching, so the counts are approximate.

### 6.4 What loads when you import one piece (verified)

Each entry point was imported alone in a fresh interpreter inside the release image, with no
network.

| Entry point                                                            | App modules loaded | Heavy dependencies loaded                                | Reading                                                                     |
| ---------------------------------------------------------------------- | ------------------ | -------------------------------------------------------- | --------------------------------------------------------------------------- |
| `ccure_contracts`                                                      | 1                  | —                                                        | Leaf                                                                        |
| `ccure_audit.services`, `ccure_audit.integration`                      | 2                  | —                                                        | Lazy inside methods; clean at import                                        |
| `reporting.xlsx_generator`                                             | 2                  | —                                                        | Library                                                                     |
| `engines.credentialed.ssh_scanner` / `winrm_executor` / `smb_executor` | 3 / 4 / 4          | paramiko, pywinrm, impacket                              | Libraries                                                                   |
| `core.scheduling.recurrence`                                           | 3                  | —                                                        | Library                                                                     |
| `ccure_platform.rbac.engine`                                           | 4                  | —                                                        | Library                                                                     |
| `core.nmap.wrapper`                                                    | 5                  | nmap, redis                                              | Needs `config` and a Redis lease                                            |
| `core.checks.contract` / `finding_normalizer`                          | 6 / 8              | —                                                        | Library                                                                     |
| `core.scan_policy.resolver`                                            | 13                 | —                                                        | Library at import; validation reads compliance tables when it runs          |
| `engines.credentialed.vuln_matcher`                                    | 15                 | SQLAlchemy                                               | Needs the `vuln_intel` database by design                                   |
| `core.discovery.engine`                                                | 19                 | scapy, **SQLAlchemy**                                    | SQLAlchemy only because `techniques.icmp` → `core.risk` → `core.vuln_intel` |
| `engines.port.port_engine`                                             | 22                 | nmap, redis, scapy, **SQLAlchemy, psycopg2**             | Via `core.utils` → `core.cve_database`                                      |
| `engines.vulnerability.vulnerability_engine`                           | 23                 | scapy, **SQLAlchemy, psycopg2**                          | Via `core.risk`                                                             |
| `core.config_audit.engine`                                             | 23                 | —                                                        | Library                                                                     |
| `core.findings.comparison`                                             | 31                 | SQLAlchemy                                               | Store code; loads the model registry and 8 platform modules                 |
| `core.web.tasks`                                                       | 37                 | celery, SQLAlchemy                                       | Task layer                                                                  |
| `core.benchmarks.pack`                                                 | 54                 | **SQLAlchemy**                                           | `core/benchmarks/__init__.py` re-exports the DB loader                      |
| `ccure_platform.api`                                                   | 59                 | FastAPI, jose, redis, SQLAlchemy                         | Loads every model module, Audit's included                                  |
| `core.compliance_tasks`                                                | 59                 | celery, redis, SQLAlchemy                                |                                                                             |
| `core.scap.oval`                                                       | 61                 | **SQLAlchemy**                                           | A parser that loads the database layer and the platform                     |
| `core.topology.engine`                                                 | 62                 | **FastAPI, jose**, redis, SQLAlchemy                     | Top-level import of `ccure_platform.api`                                    |
| `routers.web_scans`                                                    | **125**            | **scapy, nmap, reportlab**, FastAPI, slowapi, SQLAlchemy | `from scan_helpers import limiter` loads the network orchestrator           |
| `core.tasks`                                                           | 134                | everything above plus FastAPI and slowapi                | The hub                                                                     |
| `main`                                                                 | 274                |                                                          | Composition root                                                            |

### 6.5 Workers, queues and settings

- **One backend image, four roles**: `api`, `worker`, `web-worker`, `beat`.
- **Web DAST is already a separate process.** `web-worker` runs four web queues and nothing else.
- **`worker` runs three different kinds of work in one privileged container**: `scanner`,
  `default` and `compliance`, with `network_mode: host` and `cap_add: NET_ADMIN, NET_RAW`
  (`docker-compose.yml:251–255`). The `default` and `compliance` queues carry the platform's mail,
  account purges, email-risk enrichment and audit-log retention, plus compliance evaluation and
  compliance SSH remediation. None of that needs raw sockets or the host network (§14, S3).
- **Settings**: `config.py`, 1,049 lines, about 213 settings in sectioned classes (`ScanConfig`,
  `WebScanConfig`, `VulnIntelConfig`, …). They are consumed almost entirely through the flat
  `AppConfig` aggregate, by 42 modules. Web DAST alone reads 55 `AppConfig` attributes and the
  platform 41. Another 30-odd variables are read straight from the environment outside
  `config.py`, 8 of them in network checks. A capability cannot be given its own configuration
  without also bringing the other capabilities' settings.

---

## 7. Independence classification

Scale (from the brief): **1** Independent · **2** Platform-dependent · **3** Partially coupled ·
**4** Strongly coupled · **5** Not independently extractable yet.
Effort: S = days, M = 1–2 weeks, L = several weeks.

### 7.1 Libraries and engines

| Module                                                       | Class | Evidence                                                                                                                       | To reach 1                                                                   | Effort | Risk   |
| ------------------------------------------------------------ | ----- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- | ------ | ------ |
| `ccure_contracts`                                            | **1** | Loads 1 module; `contracts-are-leaves` enforced                                                                                | —                                                                            | —      | —      |
| Credentialed transports (SSH, WinRM, SMB, database executor) | **1** | 3–4 modules, own package only                                                                                                  | —                                                                            | —      | —      |
| Configuration-audit engine and operators                     | **1** | 23 modules, `core.config_audit` + `core.checks` only, no database                                                              | Inject the database executor into `collectors/database.py` (lazy edge today) | S      | Low    |
| Check kernel (`core.checks`)                                 | **1** | Contract 6 modules, normaliser 8; fan-in 15                                                                                    | Move `legacy_plugins.py`'s plugin-selector adapter into network checks       | S      | Low    |
| XLSX renderer, recurrence, RBAC engine                       | **1** | 2–4 modules                                                                                                                    | —                                                                            | —      | —      |
| Nmap wrapper                                                 | **2** | `config` + Redis slot lease                                                                                                    | A `Lease` port with the Redis lease as one implementation                    | S      | Low    |
| Package vulnerability matcher                                | **2** | Needs the `vuln_intel` database                                                                                                | A `VulnIntelProvider` port                                                   | M      | Medium |
| Discovery engine                                             | **3** | Loads SQLAlchemy through `core.risk`; progress via `core.redis_client`, cancellation via `core.scan_control` (queries `scans`) | B3 + B2                                                                      | S–M    | Medium |
| Port engine                                                  | **3** | SQLAlchemy and psycopg2 via `core.utils`; lazy imports of discovery enrichment and the device classifier                       | B2, B3, B8                                                                   | S–M    | Medium |
| Network checks (vulnerability engine)                        | **3** | SQLAlchemy via `core.risk`; `device_classifier`; TLS plugin reaches into `core.web`                                            | B2, B3, B9                                                                   | S–M    | Medium |
| SCAP/OVAL reader and benchmark compiler                      | **3** | 61 / 54 modules including the model registry and the platform — one package-init re-export (`core/benchmarks/__init__.py:37`)  | B4                                                                           | S      | Low    |
| Topology engine                                              | **3** | Top-level `ccure_platform.api` import → 62 modules incl. FastAPI                                                               | B6                                                                           | S      | Low    |
| Report renderers (PDF, CSV)                                  | **3** | `pdf_generator` → `engines.credentialed.coverage`, `core.candidate_enumeration` → SQLAlchemy                                   | B7                                                                           | S      | Low    |

### 7.2 Audit capabilities (application level)

| Capability                        | Class             | Evidence                                                                                                                                                                                                                                                                                                                                              | Main blocker                                                                            | Effort to class 2 | Risk         |
| --------------------------------- | ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------- | ------------ |
| **Web DAST**                      | **2**             | Own 6 tables (FKs to users/orgs only); own queues and worker; own frontend sub-module. In the cycle only through lazy edges. Couplings: `scan_helpers` limiter (loads 125 modules), `core.scan_control` web helpers, `report_helpers`, optional `vuln_intel`, backrefs onto `Organization`/`User`. Inbound: compliance and dashboard read its tables. | Small items B1, B2; backrefs (B8b)                                                      | S                 | Low          |
| **Vulnerability intelligence**    | **2**             | Separate database; fan-in 10. Its problem is the reverse: the scan kernel depends on it.                                                                                                                                                                                                                                                              | B3                                                                                      | S                 | Low          |
| **Scan policy**                   | **3**             | Spec and resolver are libraries; `validation.py` reads five compliance catalogue tables; snapshot read by reporting and web                                                                                                                                                                                                                           | Catalogue read through compliance's read service (exists: `ComplianceCatalogueService`) | S                 | Low          |
| **Scheduling**                    | **3**             | Dispatcher reaches `scans.db_helpers`, `core.scan_scope`, `scan_helpers`; reads the credential table                                                                                                                                                                                                                                                  | C1 (scan-creation service)                                                              | S–M               | Low          |
| **Topology**                      | **3**             | Engine imports the platform API; writes `assets`; compliance reads `network_links`                                                                                                                                                                                                                                                                    | B6; asset updates through the asset registry's API                                      | S–M               | Low          |
| **Remediation**                   | **3**             | Operates on `asset_vulnerabilities`, which findings owns                                                                                                                                                                                                                                                                                              | Merge with findings (D-6) — then it is internal                                         | S                 | Low          |
| **Credential vault**              | **3**             | Model in the compliance model file; **two APIs with different rules** (§14, S2); read directly by credentialed, scheduling, compliance                                                                                                                                                                                                                | C5                                                                                      | S–M               | Medium (API) |
| **Configuration audit (content)** | **3**             | Engine is class 1; the benchmark loader and selection write and read the compliance catalogue                                                                                                                                                                                                                                                         | C4: the loader becomes compliance's catalogue writer                                    | M                 | Medium       |
| **Reporting (read side)**         | **3**             | Exports already go through `ccure_audit` services (good); `routers/reports.py` reaches findings and vuln intel                                                                                                                                                                                                                                        | B7, read services                                                                       | S–M               | Low          |
| **Findings**                      | **4**             | Its tables are written by assets and the task hub; `routers/findings.py` imports the package matcher; comparison reads `scans` and `scan_policy`                                                                                                                                                                                                      | C3 (single writer)                                                                      | M                 | Medium       |
| **Assets**                        | **4**             | `asset_syncer.py` (2,885 lines) persists assets **and** findings; fan-in 13; imports findings comparison and credentialed coverage                                                                                                                                                                                                                    | C3                                                                                      | M–L               | Medium       |
| **Credentialed audit**            | **4**             | Engines class 1, but the application service (~3,700 lines) lives in `core/tasks.py`; its router builds scans through the network orchestrator; results reach assets, findings and compliance through the hub                                                                                                                                         | C1, C2, C5                                                                              | L                 | Medium       |
| **Compliance**                    | **4**             | Reads six capabilities' tables; 7,479-line router with 20 renderers and a second credential API; its remediation executor runs its own SSH sessions with unsafe sudo handling (§14, S1)                                                                                                                                                               | C4 (evidence providers), router split                                                   | L                 | Medium–High  |
| **Dashboard**                     | **4** (by nature) | Queries 11 tables of four capabilities directly; nothing depends on it                                                                                                                                                                                                                                                                                | Read services per capability                                                            | M                 | Low          |
| **Scans + network pipeline**      | **5**             | Scan orchestrator (1,498) + task hub drive phases 1→2→3→3.5→4; phases hand over through `scans.options` and `scan_phases.summary` JSON; cancellation and progress reached by import                                                                                                                                                                   | C1, C2, C3, typed hand-off (C6)                                                         | L                 | Medium–High  |
| **Task hub**                      | **5**             | Fan-out 15; 134 modules at import                                                                                                                                                                                                                                                                                                                     | C2: dissolve into per-capability task modules                                           | L                 | Medium       |

### 7.3 Shared platform and frontend

| Module                                  | Class | Evidence                                                                                                                                                                                                      | Next step                                                                                                      |
| --------------------------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `ccure_platform` (as a whole)           | **3** | Imports no Audit code (enforced). At run time it loads all of Audit's models through the `db.models` registry, carries Audit back-references, and its audit-log PDF export imports `reporting.report_helpers` | B8: split the model registry, remove the back-references, move `report_helpers` into a shared rendering module |
| `ccure_audit` read services and adapter | **2** | Clean at import; read four capabilities' tables when called, as designed                                                                                                                                      | Becomes the read side the dashboard and reports use (C7)                                                       |
| Frontend shell and design system        | **1** | Imports only the design system; boundary tests pass                                                                                                                                                           | —                                                                                                              |
| Frontend — web scanning                 | **2** | Imports only shell, design system and Audit's shared layer                                                                                                                                                    | —                                                                                                              |
| Frontend — Audit features               | **3** | scans ↔ credentialed import each other; the shared layout imports `ScanContext`; compliance makes 31 HTTP calls directly and uses the duplicate credential API                                               | F1–F3 (§10)                                                                                                    |

---

## 8. Target architecture

### 8.1 Shape: a modular monolith, deliberately

The product-level topology is decided and unchanged:

- gateway;
- core service = Policy Pro + Audit + Rank over one database;
- IR as its own service.

**No Audit capability should become a network service.** Findings, assets and scans
are written in one transaction per scan and read together by every report. Separating them
would trade import coupling for distributed transactions and a slower product, and
gain nothing a module boundary does not give. Independent _deployment_ already exists where it
pays, as separate worker processes from one image; §10 adds one more (moving the non-scanning
queues off the privileged worker).

Reuse outside this application means **libraries**: the engines in §7.1 are already, or will be
after Phase B, importable with no database, settings or Celery. They can be published as internal
packages when a second application actually needs one. Until then they stay in this repository
(decision D1).

### 8.2 Layers inside the core

```
 7  composition root      main.py · celery_app include list · start-up bootstrap
 6  read models           dashboard · reports API · exports · ccure_audit services
 5  orchestration         scan pipeline (phases as steps) · per-capability task modules
 4  domain stores         assets · findings+remediation · scans record · scan policy · scheduling ·
                          credential vault · compliance (catalogue, verdicts, evidence)
 3  engines               discovery · port inventory · network checks · credentialed collection ·
                          config audit + SCAP compiler · topology · web DAST · renderers
 2  kernels               check contract · scan kernel (port DB, OS maps, scope admission,
                          asset identification) · vuln-intel provider port
 1  shared                ccure_platform (via ccure_platform.api) · infra (settings, session,
                          Celery app, Redis, rate limiter, crypto, upload guard)
 0  contracts             ccure_contracts (between products)
```

### 8.3 Rules

1. **Dependencies point down only**, and capabilities of the same layer do not import each other
   except through a declared public module (`<capability>/api.py` or the existing service facade).
2. **Engines take progress, cancellation, leases and vulnerability data as arguments**
   (`ProgressSink`, `CancelToken`, `Lease`, `VulnIntelProvider`). Redis, `scans.status` and the
   `vuln_intel` database are supplied by the orchestration layer.
3. **Each table has one writing capability.** Other capabilities write through its service.
   Reading another capability's table goes through its read service; the 18 cross-capability
   foreign keys stay.
4. **Phases hand over typed values**, not JSON keys: `HostRecord` → `ServiceInventory` →
   findings. JSON columns keep a schema test for every key more than one capability uses.
5. **Tasks are dispatched by name** (`core.task_names` + `registered_task`, the Phase 3 pattern)
   and live with their capability. **Task names never change.**
6. **Compliance consumes evidence providers.** Each producing capability registers a provider for
   the evidence sources it owns. Compliance queries no other capability's table.
7. **The platform loads no Audit code at run time.** Its models register without the Audit
   registry, and Audit models attach no back-references to platform classes.
8. **Folders move last.** A capability moves into `ccure_audit/<capability>/` (old Phase 16)
   only after its ratchet figures meet the targets in §12. The move keeps the old paths as
   `sys.modules` aliases, the established pattern.

### 8.4 Data ownership in the target

- Audit's tables stay in `public`, in one schema and one Alembic branch. Splitting the schema per
  capability buys nothing a writer rule does not, and costs a live migration with `archive_mode`
  off.
- Ownership is the `capability` field already in `table_ownership.yaml`. Two corrections:
  findings + remediation become one capability (D-6), and `compliance_credentials` stays the
  credential vault's (already recorded) — but its model leaves `db/models/compliance.py`.
- Phase 18's per-module database roles (Policy Pro, Rank, Audit) are a separate, product-level
  boundary and are not affected by anything here.

### 8.5 Shared platform responsibilities

The platform owns:

- identity, organisations, RBAC, sessions, tokens and service identities;
- the audit log and notifications;
- organisation settings (scan scope, SLA);
- the module registry and preferences;
- the frontend shell and design system.

Two things move to it from Audit:

- `reporting/report_helpers.py` → a shared rendering helper the platform's audit-log export can
  use without importing Audit's report package;
- the rate limiter is already platform-grade (`core.rate_limiter`); only its import path changes.

Nothing Audit-specific moves to the platform (owner rule, 1 Oct 2026).

---

## 9. Module contracts

The contracts below are **in-process Python contracts**, not network APIs: frozen dataclasses,
protocols and service functions. They reuse what already exists:

- `core.checks.contract` (`CheckResult`, `CheckOutcome`);
- `core.models` dataclasses;
- the `@view` types in `ccure_audit/services`;
- `ccure_contracts`, only where data crosses to another product.

`ccure_contracts` stays reserved for Policy Pro, Rank and IR. Audit's internal types belong in
Audit's kernels, so a new internal field never needs a cross-product contract version.

| Module                                 | Public operations                                                                                                                                    | Inputs → outputs                                                                                      | Requires (ports / platform)                                                   | Owns                             | Errors                                                                                    | Events / async                                            |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------- | ----------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Credentialed transports and collectors | `open_session(target, credential_material, transport)`, `collect(sections)`                                                                          | target + resolved secret → `SystemSnapshot` (packages, posture, privilege context, collection errors) | none (drivers only)                                                           | nothing persisted                | Four error kinds: rejected credential, insufficient privilege, unreachable, subsystem off | none                                                      |
| Configuration-audit engine             | `evaluate(checks, context) → list[CheckResult]`                                                                                                      | `ConfigCheck`s + collected readings → results with `CheckOutcome`                                     | an executor (transport session)                                               | nothing persisted                | `UNAVAILABLE` → `ERROR`, never a verdict                                                  | none                                                      |
| SCAP / benchmark compiler              | `compile(datastream, profile) → BenchmarkPack`                                                                                                       | XCCDF/OVAL → pack of `ConfigCheck`s + unimplemented list with reasons                                 | none                                                                          | nothing                          | `UnsupportedConstruct` recorded per control                                               | none                                                      |
| Discovery / port / network checks      | `discover(targets, settings, progress, cancel) → list[HostRecord]`; `inventory(hosts, …) → ServiceInventory`; `assess(inventory, …) → list[Finding]` | typed records in and out                                                                              | `ProgressSink`, `CancelToken`, `Lease`, `VulnIntelProvider`                   | nothing persisted                | engine errors as results; cancellation as a typed outcome                                 | progress events through the sink                          |
| Vulnerability intelligence             | `VulnIntelProvider`: `candidates(cpe)`, `advisories(ecosystem, package)`, `priority(cve)`                                                            | identifiers → advisory records                                                                        | the `vuln_intel` database                                                     | `vuln_intel` (separate database) | "lookup failed" is distinct from "no advisory" (already a rule)                           | feed sync scripts                                         |
| Findings & remediation                 | `record(scan_ref, asset_ref, findings, assessed_scope)`, `compare(baseline, current)`, workflow transitions, `apply_sla`                             | `Finding`s + scope → stored rows; comparison classes                                                  | `ccure_platform.api` (actor, org settings via `core.remediation.sla`)         | 6 tables                         | refusals as typed results; `verified_fixed` only from comparison                          | `FindingsRecorded` (in-process), remediation events table |
| Asset registry                         | `observe(host_record, provenance)`, `set_credentialed_status`, read API                                                                              | host observations → asset ids                                                                         | `ccure_platform.api`                                                          | 6 tables                         | identity conflicts reported                                                               | `AssetObserved`                                           |
| Credential vault                       | `create/update/delete/list`, `resolve(credential_id) → material` (worker side only)                                                                  | profiles; secrets never returned                                                                      | crypto key; `ccure_platform.api`                                              | `compliance_credentials`         | one rule set (the `/credentials` API's)                                                   | audit-log events                                          |
| Compliance                             | `register_evidence_provider(source, provider)`, evaluate, attest, report                                                                             | evidence bundles → verdicts and scores                                                                | evidence providers; `ccure_platform.api`                                      | 20 tables                        | `not_assessed` explicit; never defaults                                                   | `compliance` queue tasks                                  |
| Web DAST                               | `start_scan(request, principal)`, results read API                                                                                                   | target URL + scope + auth profile → web findings                                                      | `ccure_platform.api`, its own settings object, Celery queues by configuration | 6 tables                         | refusals 4xx; scan terminal states                                                        | four chained tasks, reaper                                |
| Report renderers                       | `render_pdf(payload)`, `render_xlsx(rows)`, `render_csv(rows)`                                                                                       | plain payloads → documents                                                                            | none                                                                          | nothing                          | `XlsxUnavailable` → 503, never another format                                             | none                                                      |

For each: tests live with the capability. A compatibility guarantee means the same OpenAPI
document, the same Celery task names and the same report bytes (the Phase 5 golden method).

---

## 10. Refactoring roadmap

This refines the programme's open phases. It does not replace them:

- 13–14 (IR service, core↔IR flow), 15 (coverage record), 17 (parameters), 18 (database roles)
  and 19 (single-organisation mode) are unaffected;
- **Phase 16 is replaced by B–E below**, because moving folders before removing dependencies
  would be cosmetic.

**Working rules for every step:**

- one commit per step, stopping for review;
- run the targeted tests named by `scripts/ci/select_tests.py`, and the full suite at each
  milestone;
- compare the OpenAPI document, `celery inspect registered` and the beat schedule before and
  after;
- take a backup before anything touches a database;
- run live scans against the standing targets for anything on a scan path.

### Phase 0 — security and process track (separate approval; not modularity work)

| #   | Change                                                                                                                                                                                          | Files                                                                                                                           | Effort | Risk                    |
| --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ------ | ----------------------- |
| S1  | Compliance remediation uses `SSHScanner.run_sudo` (password on stdin) instead of `_inject_sudo_password`. Extend the `echo … \| sudo` source guard from `linux_collector` to every module.      | `core/compliance_tasks.py:1428–1476`, `tests/credentialed/test_sudo_password_safety.py`                                         | S      | Low                     |
| S2  | One credential API: `/compliance/credentials` delegates to the vault's rules and permissions, or is retired after the three screens move to `/credentials` (D-3)                                | `routers/compliance.py:2265–2360`, `NewScan.jsx:917`, `CredentialedScan.jsx:125`, `ComplianceWorkspace.jsx:1382,1823,3903,4042` | S–M    | Medium (API)            |
| S3  | Move `default` and `compliance` off the privileged `worker` into a non-privileged worker service (D-4)                                                                                          | `docker-compose.yml`, release `compose.sh`                                                                                      | S      | Low–Medium (deployment) |
| S4  | Restore enforcement (D-5). Interim: a pre-commit hook running the stdlib-only guards (`import_graph --violations`, `identity_boundary`, the capability ratchet from A2); they need no database. | `.pre-commit-config.yaml`                                                                                                       | S      | Low                     |

### Phase A — baseline and guardrails

| #   | Step                                                                                                                                                                                                                                                                                                                              | Effort |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| A1  | Review this document; commit it (and decide whether the 25 Sep baseline and the plan revision 4 are committed or retired, D-9)                                                                                                                                                                                                    | S      |
| A2  | Commit the capability map (Appendix A) as `scripts/architecture/capability_map.py`, with a ratchet test in `tests/repo/`. The figures may only fall: capabilities in the cycle (23/20), cross-capability lazy imports (386), upward edges (57), foreign-table references per capability (§6.1), entry-point load profiles (§6.4). | S      |
| A3  | Schema tests for the shared JSON keys in §6.3 (shape only, no behaviour change)                                                                                                                                                                                                                                                   | S      |

### Phase B — low-risk decoupling (one move per commit, behaviour unchanged)

Simulated on the current graph, B1–B10 together remove **41 import edges**. Under the target
grouping (renderers separate from the read side; scope admission and asset identification in the
scan kernel), the capability cycle shrinks from **20 capabilities to 10**. Every engine, kernel and
renderer leaves it.

| #   | Problem → change                                                                                                                                                                                                                                                                                                                           | Files                                                                                                                                                                          | Expected effect                                                                                                                                                 | Risk                                                             |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| B1  | 14 modules take `limiter` from `scan_helpers`, whose import loads the network orchestrator; 8 of them import nothing else from it → import it from `core.rate_limiter`. Same object; `scan_helpers` keeps the alias. **Reverses the 25 Sep "not now" (D-1).**                                                                              | 14 modules (`main` and 13 routers)                                                                                                                                             | `routers/web_scans` no longer loads Scapy/Nmap/ReportLab; 8 modules stop depending on `scan_helpers` (the rest also use its scan helpers and are handled in C1) | Low (same limiter instance; limiter keys are per route function) |
| B2  | Engines report progress and read cancellation through `ProgressSink` / `CancelToken` arguments; the Redis and `scans.status` implementations stay in orchestration                                                                                                                                                                         | `core/discovery/engine.py`, `engines/port/port_engine.py`, `engines/vulnerability/vulnerability_engine.py`, `core/web/tasks.py`, `core/web/timeout.py`, `core/scan_control.py` | Engines stop querying the `scans` table                                                                                                                         | Medium — scan paths; live-scan validation                        |
| B3  | `core.risk` / `core.utils` import `core.vuln_intel` / `core.cve_database` → split the vuln-intel-dependent helpers (`compute_priority`, `lookup_cve`) out of the kernel. **Owner said "document, not refactor" on 25 Sep (D-2).**                                                                                                          | `core/risk.py`, `core/utils.py`, callers                                                                                                                                       | Discovery, port and network engines load without SQLAlchemy                                                                                                     | Low–Medium                                                       |
| B4  | `core/benchmarks/__init__.py` re-exports the database loader → stop re-exporting; callers import `core.benchmarks.loader`                                                                                                                                                                                                                  | `core/benchmarks/__init__.py:37`, callers                                                                                                                                      | SCAP compiler 61 → ~30 modules, no database                                                                                                                     | Low                                                              |
| B5  | `core/checks/legacy_plugins.py` reaches into `engines.vulnerability` → the adapter moves to network checks and registers itself                                                                                                                                                                                                            | `core/checks/legacy_plugins.py`                                                                                                                                                | Check kernel depends on nothing above it                                                                                                                        | Low                                                              |
| B6  | Topology engine imports `ccure_platform.api` at top level → identity lookups passed in by the task                                                                                                                                                                                                                                         | `core/topology/engine.py:57`                                                                                                                                                   | Engine 62 → ~15 modules, no FastAPI                                                                                                                             | Low                                                              |
| B7  | Renderers import engines → coverage rows and candidate-enumeration notes passed in with the payload                                                                                                                                                                                                                                        | `reporting/pdf_generator.py`, `reporting/csv_generator.py`                                                                                                                     | Renderers become libraries; **report bytes identical (golden)**                                                                                                 | Low–Medium                                                       |
| B8  | (a) Port engine and discovery enrichment import sibling engines; (b) Audit models attach seven back-references onto platform classes; the platform loads all models → compose enrichment in orchestration; replace `backref=` with one-sided relationships if nothing reads them; split the model registry so the platform registers alone | `engines/port/port_engine.py`, `core/discovery/enrichment.py`, `db/models/web_scans.py`, `db/models/topology.py`, `db/models/__init__.py`                                      | Platform loads without Audit's models                                                                                                                           | Medium — mapper configuration; full suite                        |
| B9  | Network-check TLS plugin reaches into `core.web.sslyze` → move the sslyze wrapper to a shared engine module both use                                                                                                                                                                                                                       | `engines/vulnerability/plugins/tls_scanner.py`, `core/web/sslyze/`                                                                                                             | Network scan runs without the web module                                                                                                                        | Low                                                              |
| B10 | Config-audit database collector and SCAP evaluator import credentialed engines lazily → executor and matcher injected                                                                                                                                                                                                                      | `core/config_audit/collectors/database.py`, `core/scap/evaluate.py`                                                                                                            | Config audit depends only on the check kernel                                                                                                                   | Low                                                              |

### Phase C — the persistence and orchestration knot

After Phase B the cycle is: assets, findings, remediation, scans, task hub, credentialed audit,
config audit, compliance, scan policy and scheduling. These steps dissolve it, in order:

| #   | Change                                                                                                                                                                                                                                                                                                                 | Unlocks                                                                                       | Effort | Risk                                                                                                        |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------- |
| C1  | **Dispatch by name everywhere.** Routers stop importing `core.tasks` (`phase_scans`, `traditional_scans`, `credentialed`, `assets`, `credentials`). A scan-creation service in the scans capability replaces the credentialed router's use of `scan_orchestrator`, `db_helpers` and `policy_binding`.                  | No capability imports the hub                                                                 | M      | Low–Medium                                                                                                  |
| C2  | **Split `core/tasks.py`** into per-capability task modules: credentialed (≈3,700 lines incl. persistence), discovery/port/network phases, topology, maintenance. Every `name=` is kept; the `include` list is updated.                                                                                                 | Hub gone; credentialed audit gets an application service of its own                           | L      | Medium (task registration — compare `celery inspect registered`)                                            |
| C3  | **One findings writer.** A findings service owns writes to `services`, `tls_details`, `http_security_details`, `asset_vulnerabilities` and `vulnerability_definitions`. `asset_syncer` keeps asset identity only; the hub's credentialed sync calls the service. Merge remediation into the same capability (D-6).     | Findings and assets leave each other's cycle; one place for the fixed-sweep rules             | L      | Medium–High — the core data path; golden comparison of findings, exports and comparisons on a restored copy |
| C4  | **Compliance evidence providers and catalogue ownership.** Producers register providers for their sources. `core/compliance_evidence.py` becomes a registry. The benchmark loader and selection become compliance's catalogue writer. Scan-policy validation reads the catalogue through `ComplianceCatalogueService`. | Compliance stops querying five capabilities' tables; config audit depends on nothing above it | L      | Medium — scores must not move; compare full compliance runs before and after                                |
| C5  | **Credential vault capability.** Model out of `db/models/compliance.py` (same table, alias kept); one API; `resolve()` used by credentialed audit, scheduling and compliance remediation                                                                                                                               | Credentialed audit stops depending on compliance's model file                                 | M      | Low–Medium                                                                                                  |
| C6  | **Typed phase hand-off.** `HostRecord` and `ServiceInventory` between phases; one pipeline definition instead of each task starting the next                                                                                                                                                                           | The network pipeline becomes composable                                                       | L      | Medium–High                                                                                                 |
| C7  | **Read side.** Dashboard and reports consume read services (extend `ccure_audit/services`) instead of querying tables                                                                                                                                                                                                  | Read models stop coupling to storage                                                          | M      | Low                                                                                                         |
| C8  | **Split `routers/compliance.py`**: catalogue, assessment, attestation and evidence, schedules, remediation, reports. The 20 PDF/DOCX generators move to `reporting/compliance/`.                                                                                                                                       | Compliance reports become renderers                                                           | M      | Low                                                                                                         |

**Frontend, in parallel and low risk:**

- **F1** — Compliance calls go through an `api/compliance.js` module, and `ComplianceWorkspace.jsx`
  is split by tab.
- **F2** — `ScanContext` moves out of the shared layout's imports, and the components shared by
  scans and credentialed results move to Audit's shared layer.
- **F3** — The credential screens use one API (follows S2).

### Phase D — independent reuse validation

| #   | Proof                                                                                                                                                                                                                                                                                                                                 |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| D1  | An engine harness in CI: each library in §7.1 is imported and exercised in a clean environment holding only its declared dependencies (no `config`, no database, no Celery). It must pass for the transports, config-audit engine, SCAP compiler, check kernel and renderers, and — after B2/B3 — discovery, port and network checks. |
| D2  | **Web DAST pilot**, run under the test-only host application pattern (`tests/modules/example`) with a stub identity provider and its own settings object. It proves the capability works through `ccure_platform.api` and declared settings alone.                                                                                    |
| D3  | Behavioural equivalence on a restored copy: the same scans produce the same findings, exports (byte-identical), comparisons and compliance scores before and after C3/C4. Live scans run against the standing targets (Rocky/Ubuntu, Nuclei target, Windows host).                                                                    |

### Phase E — continuous enforcement

- **E1.** The capability ratchet from A2 gains layer rules for the §8.2 layers. The layer rules in
  `layer_rules.py` gain:
  - `engines-are-libraries` widened to every layer-3 module;
  - "no import of `scan_helpers`" outside the scans capability;
  - "platform loads no Audit model".
- **E2.** Each engine's load profile is pinned: the forbidden set is SQLAlchemy, FastAPI, Celery and
  Redis.
- **E3.** CI runs again (D-5). Until then, the pre-commit hook (S4).
- **E4.** This document's §12 table is regenerated at each milestone.

---

## 11. Testing and validation strategy

- **Targeted first.** `scripts/ci/select_tests.py --files …` names the groups for each step.
  `tests/repo` and `tests/security` run on every step. Scan-path steps add `scans` and
  `credentialed`; compliance steps add `compliance`.
- **Golden comparisons for anything that reads or writes findings** (the Phase 5 method): exports
  byte-identical, comparison classes and counts identical, compliance scores identical — on a
  restored copy of a full dump, never on `ccure_db`.
- **Interface diffs at every step:**
  - OpenAPI document (`openapi.json`);
  - route table and limiter keys;
  - `celery inspect registered` and the beat schedule;
  - the entry-point load profiles of §6.4.
- **Live validation** for B2, B3, C2, C3 and C6: the standing disposable targets (CLAUDE.md "Test
  targets"), concurrent credentialed and unauthenticated scans, and the same checks as the 13–14
  Oct release validation.
- **Full suites at milestones** (end of B, after C3, after C4, after C6), in the release image
  against a disposable PostgreSQL. A full run uses a private test database while another agent
  shares the checkout.
- **Never claim independence from imports alone:** D1 and D2 are the proof, and the §12 figures
  are the measure.

---

## 12. Measurable independence criteria

Current values (16 Oct 2026) and targets. A capability is **independent for reuse** when it meets
every target in its row and passes D1 (libraries) or D2 (capabilities).

| Capability               | In cycle (all / top) | Non-shared capabilities it imports | Foreign tables referenced | Foreign writes | Target                                                          |
| ------------------------ | -------------------- | ---------------------------------- | ------------------------- | -------------- | --------------------------------------------------------------- |
| web_dast                 | yes / no             | 3                                  | 1                         | 0              | not in cycle; ≤1 (vuln-intel provider); 0; 0                    |
| credentialed_audit       | yes / yes            | 6                                  | 1                         | 0              | not in cycle; ≤3 (kernels + vault API); 0; 0                    |
| credential_vault         | yes / yes            | 5                                  | 1                         | 0              | not in cycle; 0; 0; 0                                           |
| config_audit             | yes / yes            | 5                                  | 5                         | 4              | not in cycle; 1 (check kernel); 0; 0                            |
| check_kernel             | yes / no             | 1                                  | 0                         | 0              | not in cycle; 0                                                 |
| scan_kernel              | yes / yes            | 2                                  | 0                         | 0              | not in cycle; ≤1 (check kernel)                                 |
| vuln_intel               | yes / yes            | 2                                  | 1                         | 0              | not in cycle                                                    |
| discovery                | yes / yes            | 5                                  | 0                         | 0              | not in cycle; ≤1 (scan kernel); load profile without SQLAlchemy |
| port_inventory           | yes / yes            | 4                                  | 0                         | 0              | as discovery                                                    |
| network_checks           | yes / yes            | 5                                  | 0                         | 0              | as discovery, plus vuln-intel through a port                    |
| topology                 | yes / yes            | 2                                  | 2                         | 1              | not in cycle; 0 foreign writes                                  |
| assets                   | yes / yes            | 7                                  | 5                         | **4**          | 0 foreign writes                                                |
| findings (+ remediation) | yes / yes            | 8                                  | 2                         | 0              | sole writer of its 6 tables                                     |
| scans                    | yes / yes            | 12                                 | 6                         | 0              | imports engines only through the pipeline definition            |
| task_hub                 | yes / yes            | 15                                 | 7                         | **4**          | does not exist                                                  |
| scan_policy              | yes / yes            | 4                                  | 7                         | 0              | catalogue through compliance's read service                     |
| scheduling               | yes / yes            | 4                                  | 2                         | 0              | scan creation through the scans service                         |
| compliance               | yes / yes            | 8                                  | 9                         | 1              | 0 foreign tables (evidence providers); 0 foreign writes         |
| reporting                | yes / yes            | 9                                  | 3                         | 0              | renderers in no cycle; read side through services               |
| dashboard                | no / no              | 6                                  | 11                        | 0              | 0 foreign tables (read services)                                |
| platform                 | yes / yes            | 1                                  | 0                         | 0              | not in any cycle; loads no Audit model (D1 import test)         |

Whole-application targets:

| Measure                           | Now                 | End of B | End of C         |
| --------------------------------- | ------------------- | -------- | ---------------- |
| Capabilities in the largest cycle | 23 / 20 (all / top) | ≤ 10     | 0                |
| Upward edges                      | 57                  | ≤ 43     | 0                |
| Cross-capability lazy imports     | 386                 | ≤ 363    | ≤ 150            |
| `core/tasks.py`                   | 5,704 lines         | 5,704    | 0                |
| `routers/compliance.py`           | 7,479 lines         | 7,479    | ≤ 1,500 per file |

---

## 13. Risks and decisions requiring approval

| #   | Decision                                                                                                                                                                                                                                                                                                                                                                                 | Recommendation                                                                                                     | Needed before |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ------------- |
| D-1 | Migrate the compatibility import paths now (`scan_helpers.limiter`; later `scans.cvss`, `scans.finding_normalizer`). On 25 Sep the owner said "not now".                                                                                                                                                                                                                                 | Yes for the limiter (measured cost: the web router loads 125 modules); keep the other two until C3                 | B1            |
| D-2 | Refactor the `discovery → core.risk → core.vuln_intel` coupling. On 25 Sep the owner said "document, not refactor unless needed".                                                                                                                                                                                                                                                        | Yes — it is now needed for the reuse objective                                                                     | B3            |
| D-3 | `/compliance/credentials`: retire it or keep it as an alias of the vault's API. Either is an API change for three screens.                                                                                                                                                                                                                                                               | Keep the paths, route them to the vault's rules and permissions; retire after one release                          | S2            |
| D-4 | Worker split: a new non-privileged worker for `default` + `compliance`. A deployment change on the VM, done as a release.                                                                                                                                                                                                                                                                | Yes                                                                                                                | S3            |
| D-5 | Where CI runs. _Corrected 16 Oct 2026:_ GitHub Actions had resumed (the nightly full run passed on `23f8e72` at 21:50 UTC on 15 Oct), but it tests only what is pushed to the `github` remote, ten commits behind GitLab; `origin` (GitLab, where merge requests land) has no pipeline. The statement first published here — that nothing enforced any ratchet — was wrong about GitHub. | Pre-commit hook and local runner (S4, done); then push every GitLab merge to `github`, or register a GitLab runner | S4            |
| D-6 | Findings and remediation become one capability (registry `capability` field)                                                                                                                                                                                                                                                                                                             | Yes                                                                                                                | C3            |
| D-7 | When folders move into `ccure_audit/` (old Phase 16)                                                                                                                                                                                                                                                                                                                                     | Only after a capability meets its §12 targets                                                                      | C             |
| D-8 | Whether S1 and S2 are fixed ahead of all modularity work                                                                                                                                                                                                                                                                                                                                 | Yes, S1 first                                                                                                      | now           |
| D-9 | The 25 Sep baseline and plan revision 4 are cited by committed records but live outside the repository                                                                                                                                                                                                                                                                                   | Commit plan revision 4 as history under `docs/archive/architecture/`; this document replaces the baseline          | A1            |

**Risks.**

- **C3 is the riskiest step.** It touches the code path that decides "fixed" and "reappeared",
  which GAP-13 and GAP-14 depend on. It needs the golden comparison and a live re-validation, and
  must not run while a scan is in flight.
- **Task registration.** A task module missing from the `include` list looks like a stuck scan,
  not an import error.
- **Mapper configuration (B8)** can fail only at first query; the full suite is the check.
- **Concurrent agents** share this checkout. Each step should be built and tested in a detached
  worktree with a private test database.

---

## 14. Security and correctness findings found during the analysis

Each was confirmed in the code at `23f8e72`. Status since (§0): S1 and S2 are fixed, S3 is proposed and awaits D-4, and S4 is addressed by local enforcement.

| #   | Severity                                                         | Finding                                                                     | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Consequence                                                                                                                                                                                                                                                                                  |
| --- | ---------------------------------------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| S1  | **High** (credential exposure on customer hosts)                 | Compliance remediation puts the sudo password into the remote command line. | `core/compliance_tasks.py:1428` `_inject_sudo_password` rewrites each `sudo` as `echo '<password>' \| sudo -S`; `_execute_ssh_remediation` (`:1440–1476`) passes the result to `SSHScanner.run`. `compliance.run_remediation` (`:1659`, call at `:1718`) is dispatched from `routers/compliance.py:2487`, `:2733`, `:2983`. The source guard in `tests/credentialed/test_sudo_password_safety.py` inspects `linux_collector` only.                                                                                                                                                    | The defect CLAUDE.md records as fixed in the collectors: during execution the password is in the argv of the shell sshd spawns on the target — visible in `ps` to every local user and captured by any `execve` audit rule. `SSHScanner.run_sudo` exists for exactly this and is not used.   |
| S2  | **Medium** (authorization inconsistency, information disclosure) | Two credential APIs over one table with different rules.                    | `/compliance/credentials` (`routers/compliance.py:2265–2360`): list under `audit.compliance.read`, create and delete under `audit.compliance.manage_integrations`, no rate limit, no transport/type validation, `400` on a duplicate name. `/credentials` (`routers/credentials.py:429,447,751`): `audit.credential.read`/`.manage`/`.delete`, limited, `_apply_type_rules`, `409`, reports affected schedules on delete. `platform.viewer` — also the self-registration default role — holds `audit.compliance.read` but not `audit.credential.read` (`ccure_audit/permissions.py`). | A viewer can list every stored credential's name, username, port and auth method. A custom organisation role with `manage_integrations` can delete credentials without `audit.credential.delete`. The two paths record different audit-event names for the same act. The frontend uses both. |
| S3  | **Medium** (least privilege)                                     | Non-scanning queues run in the privileged scanner container.                | `docker-compose.yml:251–255`: `worker` has `network_mode: host`, `NET_ADMIN`, `NET_RAW` and consumes `scanner,default,compliance`.                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Platform mail, account purges, outbound email-risk lookups, audit retention, compliance evaluation and SSH remediation all run with host networking and raw sockets.                                                                                                                         |
| S4  | **Medium** (process)                                             | Architecture ratchets are not enforced where merges land.                   | _Corrected 16 Oct 2026:_ GitHub Actions runs again (nightly full run passed on `23f8e72`), but only on what is pushed to `github`, which was ten commits behind `origin/master`; GitLab (`origin`) has no `.gitlab-ci.yml` and no usable runner; `.pre-commit-config.yaml` had no test hook. First published as "GitHub Actions jobs are not started", which was true on the morning of 15 Oct and no longer by the evening.                                                                                                                                                          | A GitLab merge could break any boundary in §3 of `README.md` without anything failing. Addressed locally in `2d4509d`.                                                                                                                                                                       |
| L1  | Low (latent)                                                     | Audit models add `backref`s onto `Organization` and `User`.                 | §6.2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | The platform classes change shape with Audit's models; an ORM-level delete of an organisation would cascade into Audit tables through attributes the platform never declared.                                                                                                                |

---

## Appendix A — capability map used for every figure

Longest prefix wins. `from db.models import X` is resolved to the model file defining `X`, and
`ComplianceCredential` to `credential_vault` (as the ownership registry records).

| Capability         | Module prefixes                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| platform           | `ccure_platform`, `auth`, `core.audit`, `core.audit_retention`, `core.audit_taxonomy`, `core.notifications`, `core.email_security_tasks`, `routers.admin_email_domains`, `routers.admin_orgs`, `routers.admin_users`, `routers.audit`, `routers.notifications`, `routers.user_profile`, `reporting.audit_export`, `db.models.users`, `db.models.rbac`, `db.models.email_security`, `db.models.notifications`                  |
| infra              | `config`, `db` (other than models listed elsewhere), `core` (package), `core.celery_app`, `core.redis_client`, `core.rate_limit_middleware`, `core.rate_limit_audit`, `core.rate_limiter`, `core.ip_resolver`, `core.throttle`, `core.security_crypto`, `core.user_agent`, `core.upload_guard`, `core.trusted_proxy`, `core.task_names`, `routers` (package), `routers.health`, `engines` (package), `orchestrator` (package) |
| scan_kernel        | `core.constants`, `core.utils`, `core.models`, `core.mac`, `core.risk`                                                                                                                                                                                                                                                                                                                                                        |
| check_kernel       | `core.checks`, `scans.cvss`, `scans.finding_normalizer`                                                                                                                                                                                                                                                                                                                                                                       |
| vuln_intel         | `core.cve_database`, `core.vuln_intel`, `scans.nvd_sync`, `scans.cve_engine`, `routers.admin_nvd`                                                                                                                                                                                                                                                                                                                             |
| discovery          | `core.discovery`, `engines.discovery`, `orchestrator.host_discovery_api`                                                                                                                                                                                                                                                                                                                                                      |
| port_inventory     | `core.nmap`, `engines.port`                                                                                                                                                                                                                                                                                                                                                                                                   |
| network_checks     | `engines.vulnerability`, `core.candidate_enumeration`                                                                                                                                                                                                                                                                                                                                                                         |
| credentialed_audit | `engines.credentialed`, `core.credential_scope`, `routers.credentialed`                                                                                                                                                                                                                                                                                                                                                       |
| credential_vault   | `routers.credentials`                                                                                                                                                                                                                                                                                                                                                                                                         |
| config_audit       | `core.config_audit`, `core.benchmarks`, `core.scap`, `routers.config_audit`                                                                                                                                                                                                                                                                                                                                                   |
| assets             | `core.asset_correlation`, `core.amt_reconciliation`, `core.device_classifier`, `core.oui_lookup`, `core.audit_event_translator`, `scans.asset_syncer`, `routers.assets`, `db.models.assets`, `db.models.amt`                                                                                                                                                                                                                  |
| findings           | `core.findings`, `routers.findings`, `db.models.findings`                                                                                                                                                                                                                                                                                                                                                                     |
| remediation        | `core.remediation`, `routers.remediation`                                                                                                                                                                                                                                                                                                                                                                                     |
| scans              | `scans` (rest), `scan_helpers`, `orchestrator.scan_orchestrator`, `core.scan_control`, `core.scan_scope`, `routers.phase_scans`, `routers.scan_history`, `routers.scan_progress`, `routers.traditional_scans`, `db.models.scans`                                                                                                                                                                                              |
| task_hub           | `core.tasks`                                                                                                                                                                                                                                                                                                                                                                                                                  |
| scan_policy        | `core.scan_policy`, `routers.scan_policies`, `db.models.scan_policies`, `db.scan_policy_kinds`                                                                                                                                                                                                                                                                                                                                |
| scheduling         | `core.scheduling`, `routers.scan_schedules`, `db.models.scan_schedules`                                                                                                                                                                                                                                                                                                                                                       |
| topology           | `core.topology`, `routers.topology`, `db.models.topology`                                                                                                                                                                                                                                                                                                                                                                     |
| web_dast           | `core.web`, `orchestrator.web_orchestrator`, `routers.web_scans`, `db.models.web_scans`, `reporting.web_pdf_generator`                                                                                                                                                                                                                                                                                                        |
| compliance         | `core.compliance_evidence`, `core.compliance_sync`, `core.compliance_frameworks`, `core.compliance_seeds`, `core.compliance_tasks`, `core.nist_csf`, `core.nist_csf_catalogue`, `routers.compliance`, `db.models.compliance`                                                                                                                                                                                                  |
| reporting          | `reporting` (rest), `routers.reports`, `db.models.scan_reports`                                                                                                                                                                                                                                                                                                                                                               |
| dashboard          | `routers.dashboard`                                                                                                                                                                                                                                                                                                                                                                                                           |
| audit_boundary     | `ccure_audit`                                                                                                                                                                                                                                                                                                                                                                                                                 |
| contracts          | `ccure_contracts`                                                                                                                                                                                                                                                                                                                                                                                                             |
| policy_pro / rank  | `ccure_policy` / `ccure_rank`                                                                                                                                                                                                                                                                                                                                                                                                 |
| main               | `main`                                                                                                                                                                                                                                                                                                                                                                                                                        |

The §4.1 layering score and the Phase B simulation use the target grouping instead, which differs
in four ways:

- the renderers (`reporting.pdf_generator`, `csv_generator`, `xlsx_generator`,
  `web_pdf_generator`, `report_helpers`, `availability`, `host_assessment`) are a group of their
  own;
- `core.scan_scope`, `core.oui_lookup` and `core.device_classifier` are in the scan kernel;
- `orchestrator.host_discovery_api` and `routers.health` are in scans;
- `db.migrate_production_schema` belongs to the composition root.

---

## Appendix B — baseline test results

Nothing was changed, so these establish the starting point; they are not a regression run.

**Static guards (stdlib, on the working tree = HEAD):**

- `python -m scripts.architecture.import_graph --violations`: **0 violations**;
- `python -m scripts.architecture.import_graph`: 0 module-level cycles;
- `python -m scripts.architecture.identity_boundary`: 3 importers, 2 queries, 0 joins.

**Backend — `tests/repo`, `tests/modules`, `tests/audit_boundary`:**

- **Result: 964 passed, 1 skipped, 0 failed** in 136.9 s.
- The skip is `test_alembic_module_branches.py:264`: `alembic.ini is already activated`, by design.
- **Where:**
  - a full `git archive HEAD` copy;
  - in `ccure-audit-pro-backend:latest` (image `3a0dde6d4580`, the live release `3212d6b`), as uid 1000;
  - against throwaway `postgres:18-alpine` and `redis:7-alpine` containers on an internal Docker network;
  - `MOCK_SCANNERS=true`, after CI's bootstrap (`migrate_production_schema`, `seed_compliance`,
    `seed_real_rules`).
- **Difference from CI:** the image has no `pytest-rerunfailures`, so CI's `--reruns 1` was
  omitted.
- An earlier attempt on a partial copy failed 5 tests and skipped 11, all because repo-root files
  (`.pre-commit-config.yaml`, `CLAUDE.md`, `docker-compose.yml`, `Frontend/`) were missing from
  that copy. It is superseded by the run above.

**Frontend — boundary tests:**

- **Result: 4 files, 94 tests passed** in 7.5 s.
- **Tests:** `src/__tests__/architecture/moduleBoundaries.test.js` and, under `src/__tests__/shell/`,
  `navigationIsolation.test.jsx`, `sharedFrame.test.jsx` and `productList.test.js`.
- **Where:** vitest 4.1.11 on Node 20.20.2 (CI uses Node 22).

**Not run, and why:**

- the full backend suite (~28 min) and full frontend suite (~12 min), and the browser suites — no
  code changed (CLAUDE.md, "Test targeted-first");
- the gateway harnesses.

No claim is made about them.

## Appendix C — reproducing the measurements

The import graph and guards are the repository's own (`Backend/scripts/architecture/`). The
capability grouping (Appendix A), the table-access scan, the load-profile script and the frontend
graph were run from session scratch files. Step A2 committed a refined capability map, with its
ratchet, as `scripts/architecture/capability_map.py`; the log (§3, A2) reconciles its figures with
these. Appendix A and §2 remain the specification of _this report's_ method, and that method
reproduces every figure here on `23f8e72`.

# Engineering record: Architecture guardrails and the identity boundary

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 262–620, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 262-620 -->
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
- **`core/tasks.py` is a compatibility facade.** It re-exports every name the
  hub defined, and **refuses a patch**: setting an attribute on it raises.
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
    write or in SQL. `scans.nvd_sync`, the NVD feed's catalogue load, is the
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
    pins `PINNED_ENGINES`. The topology engine is not pinned: it persists its
    own links.
- **Web DAST reads its settings through `core.web.settings`, never `config`**
  (Group 4, D2). `current()` answers the object a host registered; Audit
  registers `config.WebScanConfig` itself (`ccure_audit/web_settings.py`, in
  Celery's `imports`), so patch a setting on `WebScanConfig` as before. A new
  setting read without a default goes in `READ`. The engine runs in the D1
  harness as library `web_dast`, and `tests/web/test_web_dast_pilot_host.py`
  fails if any web DAST module imports `config`.

Do not start dependency cleanup for its own sake: Phase 3's objective
(zero violations, zero cycles) is met.

**The identity boundary (Phase 8)** is a fourth ratchet,
`tests/repo/test_identity_boundary.py` over
`scripts/architecture/identity_boundary.py`.

- **What it counts.** Module code importing `auth.*` or an identity model (32
  files on 28 Sep 2026) and querying or joining an identity table (53 queries,
  8 joins). Each figure may only fall.
- **It is by symbol, not by edge.** `from db.models import User` and
  `from db.models import Scan` are the same edge. A layer rule therefore cannot
  hold this line, and `python -m scripts.architecture.identity_boundary` is
  how to see the sites.
- **`ccure_platform` is shared, never Audit's.**
  - `ccure_platform.api` may export only `PLATFORM_API_SURFACE`.
  - The package may import no Audit code or model
    (`platform-is-shared-foundation`).
  - Organisation scan scope and remediation SLA are **platform-owned**.
    `ccure_platform/organisation_settings/` owns their storage and exposes
    them through the platform API. Audit consumes them through
    `core.scan_scope` and `core.remediation.sla`; module code names no storage
    field. See `docs/architecture/ORGANISATION_SETTINGS.md`.
- **Owner (D6):** the Project Owner. `.github/CODEOWNERS` (Phase 11) records it,
  with placeholder handles until real ones are supplied — see "Core modules".
- **Tokens are signed and verified only in `ccure_platform.identity.tokens`**
  (Phase 9.1). No other module imports a JWT library.
  - Verify with `tokens.verify(token, expected_kind=…)`; the kind is required,
    so an endpoint cannot accept the wrong kind of token. Never check
    `payload.get("type")` by hand.
  - The any-kind `decode_token` is kept only for the two WebSocket logins
    (Phase 10) and the rate-limit audit.
  - `tests/repo/test_token_guardrails.py` enforces all of this.
  - **Live token issuance is ES256** since 29 Sep 2026 (step 9.4), with the
    promoted `active` key `7jKp…`. Tokens are signed only by `tokens.sign()`,
    which sets `iss`, `aud`, `ptype`, `nbf` and `jti` itself.
  - **HS256 is gone entirely (Phase 9.6c, 6 Oct 2026).** No HS256 issuance, no
    HS256 verification, no `JWT_SECRET_KEY`, no `CCURE_TOKEN_SIGNING_ALG`, no
    `CCURE_ACCEPT_LEGACY_HS256`. ES256 with a `kid` from the platform keyset is
    the only token signed or accepted; a token with no `kid` (every HS256 token
    ever issued) is refused as `missing_kid`. `verification.py` has no `legacy`
    parameter and `Refusal` no `legacy` field. **Do not reintroduce a symmetric
    path or a secret to "roll back" to**: a release rolls back with git.
  - **Deployed 6 Oct 2026, ~09:47–09:49 IST, from `3920908`** (development
    installation, `docker compose` with the base file, `docker-compose.development-rbac.yml`
    and `backups/native_clean_reset_20261004/preserve-runtime.compose.json`, with
    `CCURE_DEVELOPMENT_BACKEND_DIR` / `_FRONTEND_DIR` set). Order used: rebuild
    `gateway-auth` (its image bakes `verification.py`), then recreate `api`, then
    `worker`, `beat`, `web-worker`, then the frontend. Images: `gateway-auth`
    `7035a3b8d96a`, backend `4de065370b9b` (unchanged: code is bind-mounted),
    frontend `31dc0de3008d` (also tagged `9.6c-3920908`). **Rollback** is the
    `pre-9.6c` tag on each image plus `git revert`; there is no runtime switch.
    The api **requires `MFA_ENCRYPTION_KEY`** (compose `:?`) and refuses to start
    without it. Pre-deploy backups: `backups/ccure_db_20261006_092807_ops.dump` and
    `…092808_full.dump`.
  - **With no active key, the API refuses to start** — deliberately (design
    §3.7). There is no HS256 to fall back to; activate a key first.
- **Service identities (step 9.5) are not users.** They live in a static
  registry — `services.json` plus public keys, in `CCURE_SERVICE_REGISTRY_DIR`,
  read-only into the api — never in `users`, `roles` or any table.
  - **The flow.** A service authenticates at `POST /auth/service-token` with an
    assertion signed by **its own** key (RFC 7523). It receives a 10-minute
    ES256 `service_access` token: `aud` = the target service
    (`urn:ccure:core`/`urn:ccure:ir`), `sub` `svc:<id>`, one `tenant`, and
    least-privilege `scope`s.
  - **The registry.** Manage it only with
    `scripts/security/register_service_identity.py`. It refuses private keys
    and platform `kid`s. Changes take effect on an api restart.
  - **The dependencies.** `require_service_scope` and `service_principal_for`
    (`ccure_platform/service_identity/dependencies.py`) take the tenant from
    the verified token only — **never read `X-Tenant-ID`**. They stay out of
    `ccure_platform.api` until their first consumer, Phase 14.
  - **Live state.** The registry is empty; no service is registered. Phase 9
    doc §16.
- **The MFA key is explicit and has no fallback (step 9.2, 9.6c).**
  - `MFA_ENCRYPTION_KEY` derives the Fernet key for `users.totp_secret`. It was
    initialised to the retired JWT secret's value, so the key did not change
    (`scripts/security/verify_mfa_key_continuity.py` proves it without printing
    anything).
  - **Where it comes from.** Containers run with `SKIP_DOTENV_LOAD`, so
    `Backend/.env` is never read there: the value reaches the **api only**
    through the root `.env` and `docker-compose.yml`. Editing `Backend/.env`
    changes nothing in a container.
  - **Never change `MFA_ENCRYPTION_KEY`**: every stored MFA secret would become
    undecryptable.
  - **Unset, the API refuses to start** (`main.py`); `AppConfig.MFA_KEY` is empty
    rather than a key derived from `""`.
  - **Workers hold no secrets of this kind.** `worker`, `beat` and `web-worker`
    get neither `JWT_SECRET_KEY` (gone) nor `MFA_ENCRYPTION_KEY`, set
    `SKIP_DOTENV_LOAD=1`, and have `/app/.env` masked by a `/dev/null` bind so
    the `./Backend` mount cannot hand them `Backend/.env`. **Masking one file is not
    enough**: any `Backend/.env.bak-*` is readable from every worker and holds the same
    secrets, so dotenv backups live outside the tree (`~/ccure-secret-backups/`, mode 700) and a test fails if one reappears.
- **Routes annotate the authenticated user as `ccure_platform.api.CurrentUser`**
  (step 8.5) and take `require_authorized` /
  `current_user_flexible` from the API, never from `auth.*` or `db.models`.
  Only three identity imports remain in module code, each with its reason
  beside `KNOWN_IDENTITY_IMPORTS`: `core.tasks`'s mail-task re-export (a legacy
  path), and the two WebSocket ticket logins (Phase 10).
- **Module code asks `ccure_platform.api` (since step 8.3)**, never
  `users`/`organizations`/`roles` directly:
  - `api.user()` and `api.organisation()` return frozen views;
  - `api.has_permission(db, account, key)` is the engine's answer. Never hand-copy a
    superadmin or role check.
  - **Organisation settings are platform-owned:** authorised scan scope and
    remediation SLA live in `ccure_platform/organisation_settings/`, one
    module per setting. Audit consumes each through **one seam**:
    `core.scan_scope` and `core.remediation.sla`.
    `tests/repo/test_organisation_settings_containment.py` enforces this.
  - **Platform owns configuration; Audit applies it.** The platform holds
    authorised ranges and configured deadlines. Audit admits targets and
    computes due dates. `OrganisationView` carries identity only; a ratchet
    keeps direct setting storage references in module code at zero.
  - **An endpoint's docstring is its OpenAPI description.** Editing one
    changes the published API document; put notes in comments.
- **Identity's code lives in `ccure_platform` since step 8.2.**
  - **The moves:**
    - `auth/*` → `ccure_platform/identity/`;
    - `auth/rbac.py` → `ccure_platform/rbac/dependencies.py`;
    - `db/models/users.py` and `rbac.py` → `ccure_platform/models/`.
  - **Old paths are stubs.** Every `auth/…` path named elsewhere in this file
    is now a stub aliasing the same module object
    (`ccure_platform/_legacy.py`, `MOVED_MODULES`).
  - **Moved modules keep their legacy `__name__`.** That keeps logger names,
    limiter route keys (`auth.router.login`) and class `__module__` unchanged.
    Do not "fix" this in passing. Renaming them is its own change.
  - **Edit the files under `ccure_platform/`,** never the stubs.
  - **Import rule.** Platform code never imports `auth.*` or
    `db.models.users`/`rbac` (`platform-does-not-use-legacy-paths`). It
    imports models through the `db.models` registry.

<!-- /verbatim -->

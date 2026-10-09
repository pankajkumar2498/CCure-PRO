# Stale code audit — 9 Oct 2026

What in this repository is no longer used by the current platform, what only
looks unused, and the evidence for each. Measured against `30d6746`
(`modular_architecture`).

**Status: applied 9 Oct 2026, uncommitted.** The owner approved every
category in §3; the removals, their documentation references and the CLAUDE.md
corrections in §8 are in the working tree, and §7 records the checks before and
after. Nothing has been committed.

## 1. Method

"Looks old" was never the test. Three independent signals were used, and an
item is listed as stale only where they agree.

- **Reachability from the real entry points.** Every Python file under
  `Backend/` was parsed with `ast` (nothing imported). Roots are what
  production actually runs: `uvicorn main:app`, the Celery `include` list in
  `core/celery_app.py`, `start.sh` → `db/migrate_production_schema.py`, and
  Alembic. Imports inside functions count, and so do dotted names in strings
  (Celery includes, `importlib`, `mock.patch` targets, manifest TOML), so
  dynamic loading is not mistaken for absence. 488 of 931 modules are
  reachable; the 60 that are not are classified in §4.
- **History.** `git log -S` on every candidate, to tell a function whose
  callers were removed (obsolete) from one that was never wired (unadopted),
  and to name the commit where a caller went.
- **Runtime, for the frontend.** A static token scan of every class selector,
  cross-checked against two censuses taken for this audit and then deleted:
  every class rendered while the unit suite ran (3,111 tests, 2,502 classes),
  and every class in the DOM across all 99 catalogued pages and flows of the
  browser harness, at 390 px light and 1440 px dark in Chromium (1,551
  classes). **None of the 417 classes listed in §3.3 appeared in either.**

## 2. Classification

| Class | Meaning                                                                   |
| ----- | ------------------------------------------------------------------------- |
| A     | Safe to delete — confirmed unused and unrelated to the current platform   |
| B     | Obsolete — a legacy implementation that a current one replaced            |
| C     | Potentially stale — needs a decision or a check this audit could not make |
| D     | Required — actively used                                                  |
| E     | Historical — not run, deliberately kept (migrations, records, evidence)   |

## 3. Removals (A and B) — applied 9 Oct 2026

### 3.1 Files

| File                                                                           | References now                                                                                                  | Why it is stale                                                                                                                                                                                                                                                                                                               | Replacement                                                     | Risk of removal                                                                      | Class      |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------- |
| `Backend/scripts/cleanup_legacy_findings.py`                                   | `DEVELOPER_SETUP_GUIDE.md:661`                                                                                  | One-off from 14 Jul. Deletes every compliance finding whose `id` does not contain the last 8 characters of its `rule_id`. Finding ids are now `cfnd_<sha256>` (`core/compliance_tasks.finding_id_for`), so **run today it would delete essentially every rule-linked finding and its `compliance_finding_history` trail**.    | None needed; ids are deterministic                              | Keeping it is the risk                                                               | B (hazard) |
| `Backend/scripts/admin/clear_ccure_test_data.py`                               | `DEVELOPER_SETUP_GUIDE.md:660`                                                                                  | Refuses to run unless the database is named `ccure_test` — the **live** Windows database (CLAUDE.md, "looks disposable and is not"). Then deletes all scans, assets, findings, sessions, notifications, `audit_logs` and the entire `vulnerability_definitions` catalogue. Its premise is the one behind the 10 Aug incident. | `conftest.py` disposability guards; scratch databases           | Keeping it is the risk                                                               | B (hazard) |
| `Backend/scripts/seed_mock_findings.py`                                        | `DEVELOPER_SETUP_GUIDE.md:411`                                                                                  | Writes fabricated ISO 27001 verdicts (≈70 % `pass`, `source="auto_scan"`, evidence "Mock verification matching criteria.") and a completed scan run into **every organisation in the database**, then recomputes scores. Violates "never synthesise evidence" and UNASSESSED ≠ PASS.                                          | Browser-harness fixtures for UI work                            | None to production                                                                   | B          |
| `Backend/scripts/verification/check_schema.py`                                 | `DEVELOPER_SETUP_GUIDE.md:521, 662`                                                                             | Checks for "new permissions" in the `permissions` table, which the native RBAC reset dropped on 4 Oct, so it fails on every correct installation. Hardcodes a password and assigns `os.environ["DATABASE_URL"] = …/ccure_test`.                                                                                               | `alembic current`; `scripts/verification/verify_permissions.py` | None                                                                                 | B          |
| `Backend/scans/schema_bootstrap.py`                                            | `db/models/scans.py:226` (comment), `DATABASE_SCHEMA.md:1634`                                                   | "Proxy … during transition" re-exporting `ensure_scan_schema`, which moved to `db/models/scans.py` in Phase 3. No importer anywhere, tests included.                                                                                                                                                                          | `db.models.scans.ensure_scan_schema`                            | None                                                                                 | A          |
| `Backend/engines/discovery/discovery_engine.py`                                | `engines/discovery/__init__.py`, `verify_install.py:73`, `SCAN_ENGINE_DEEP_DIVE.md:332`, `Backend/README.md:88` | A self-described migration shim: "You may remove this shim once you have fully migrated all callers". Every caller has; the only importers are its own package `__init__` and the install self-check. The package stays — `l2_sniffer.py` lives in it and is imported directly.                                               | `core.discovery.engine.DiscoveryEngine`                         | Low — `verify_install.py` and the package `__init__` change with it                  | B          |
| `Backend/engines/discovery/os_signatures.json`                                 | none                                                                                                            | Its reader `os_fingerprint.py` was deleted on 24 Apr (`c6b27ed`); 25 KB unread since.                                                                                                                                                                                                                                         | —                                                               | None                                                                                 | B          |
| `Backend/engines/discovery/service_probes.json`                                | none                                                                                                            | Its reader `service_probe_engine.py` was deleted on 24 Apr (`c6b27ed`).                                                                                                                                                                                                                                                       | —                                                               | None                                                                                 | B          |
| `Backend/data/rbac/legacy_role_name_dependencies.json`                         | `RBAC_SHADOW_AUTHORIZATION.md` (historical record)                                                              | A ratchet baseline, emptied at RBAC-8 ("the list is empty"); the test that read it was removed in `86e105b`. The decisions it once listed are kept in `role_name_site_decisions.json`, which is still read.                                                                                                                   | `role_name_site_decisions.json`                                 | None; the historical doc keeps a dangling path, which is accurate history            | B          |
| `nginx/gateway.conf` and the compose `gateway` service (`alt-gateway` profile) | the parked service only; several current-state docs                                                             | The plain-HTTP whole-stack proxy. Phase 10 decision D7 (`PHASE10_API_GATEWAY.md` §5.3): "`nginx/gateway.conf` and the plain-HTTP mode retired … It has no user". Phase 10.5 added `api-gateway` beside it instead of repurposing it, so it stayed parked. `GATEWAY_PORT` in `.env.example` goes with it.                      | `api-gateway` + `gateway-auth` (Phase 10)                       | Low — never started by `docker compose up`; validate with `docker compose config -q` | B          |
| `Frontend/src/shell/feedback/toast.css`                                        | `PLATFORM_SHARED_NAVIGATION.md:94` (historical)                                                                 | Its only importer, `Toast.jsx`, dropped it when the toaster moved to the design system's `CcureToastList` (`8699eaa`). Its one class, `.toast-dismiss`, is rendered nowhere.                                                                                                                                                  | `CcureToastList`                                                | None                                                                                 | B          |
| `Frontend/src/shell/navigation/useDismiss.js`                                  | none                                                                                                            | Last two importers (`AccountMenu`, `OrgSwitcher`) replaced it with the UX4G menu behaviour in `8699eaa`.                                                                                                                                                                                                                      | Design-system menu components                                   | None                                                                                 | B          |
| `Frontend/src/modules/audit/web-scanning/styles/web-scanning.css`              | `WebScanningRoutes.jsx:13` (import only)                                                                        | All 12 rules dead. Recorded as dead by UX4G batch 6 (§12: "79 lines with zero consumers"), again in batches 7, 8 and 11, and left each time as out of scope.                                                                                                                                                                  | `web-scanning-pages.css`                                        | None — the import line goes with it                                                  | B          |

### 3.2 Dead functions (33, in 21 files)

Each is a top-level function whose name appears nowhere else in `Backend/` —
not in code, a string, a test, a script or a manifest. Where history shows the
callers were removed, the commit is named; otherwise it never had a caller.

| File                                          | Function                                                                         | Evidence                                                                                                                                                           | Class |
| --------------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| `ccure_platform/rbac/resolver.py`             | `assignment_summary`                                                             | Written for the shadow comparator (`3b08e87`); its callers went with shadow authorization at the cutover (`a12fb6e`)                                               | B     |
| `core/device_classifier.py`                   | `_classify_from_snmp`, `_netbios`, `_mdns`, `_ports`, `_banners`, `_cpe`         | `classify_device()` inlined the same rules (`670c9fb`); it iterates `_PORT_PROFILE_RULES` and `_BANNER_KEYWORDS` itself                                            | B     |
| `core/tasks.py`                               | `_compact_dict`, `_normalized_severity_counts`, `_credentialed_risk_from_counts` | Callers removed in the credentialed refactor (`4965de6`)                                                                                                           | B     |
| `scans/db_helpers.py`                         | `read_scan_full`                                                                 | Last caller removed in `6dc8a0e`                                                                                                                                   | B     |
| `reporting/web_pdf_generator.py`              | `_draw_web_header_footer`, `_severity_paragraph`                                 | Page decorator dropped in the report redesign (`755bb31`)                                                                                                          | B     |
| `scan_helpers.py`                             | `validate_total_targets`                                                         | "Backwards-compatible wrapper — prefer `validate_scan_targets`"; last caller moved over in `ad606f7`                                                               | B     |
| `core/checks/finding_normalizer.py`           | `extract_findings_from_result`                                                   | "Retained for callers … such as the CSV exporter"; no caller exists                                                                                                | B     |
| `core/web/correlation.py`                     | `correlate_with_network_findings`                                                | Never wired (`d291801`). `SCAN_ENGINE_DEEP_DIVE.md:1269` says it "cross-links to network CVEs" — it does not run                                                   | B     |
| `core/web/standards_mapping.py`               | `generate_compliance_scorecard`                                                  | A duplicate: `GET /dashboard/web-owasp-scorecard` computes its own rollup from `WebFinding.owasp_category`. `SCAN_ENGINE_DEEP_DIVE.md:1272` credits the wrong code | B     |
| `ccure_platform/audit_log/retention.py`       | `retention_enabled`                                                              | No caller since added (`c3c9f1a`)                                                                                                                                  | A     |
| `ccure_platform/rbac/administration.py`       | `_require_visible`                                                               | No caller since added (`2b3e2f3`)                                                                                                                                  | A     |
| `core/config_audit/builtin/database_mssql.py` | `_configuration`                                                                 | No rule uses it                                                                                                                                                    | A     |
| `core/vuln_intel.py`                          | `rank_cvss_version`                                                              | No caller since added (`372499d`)                                                                                                                                  | A     |
| `db/base.py`                                  | `gen_audit_id`, `gen_vuln_finding_id`                                            | No caller since added (`4b890ca`)                                                                                                                                  | A     |
| `db/migrate_production_schema.py`             | `_table_exists`                                                                  | No caller                                                                                                                                                          | A     |
| `engines/credentialed/smb_executor.py`        | `_registry_flag`                                                                 | No caller since added (`4a88723`)                                                                                                                                  | A     |
| `engines/credentialed/windows_patch.py`       | `_build_tuple`                                                                   | No caller since added (`e10cdd5`)                                                                                                                                  | A     |
| `engines/credentialed/winrm_executor.py`      | `build_options`                                                                  | No caller since added (`9e4ecaa`)                                                                                                                                  | A     |
| `engines/vulnerability/network_checks.py`     | `findings_from`                                                                  | Convenience helper no plugin adopted                                                                                                                               | A     |
| `engines/vulnerability/plugin_selector.py`    | `reload_plugins`                                                                 | Development helper, no caller since added (`2fd520e`)                                                                                                              | A     |
| `scan_helpers.py`                             | `_safe_json_loads`, `get_cve_redirection_url`                                    | No caller                                                                                                                                                          | A     |
| `scans/asset_syncer.py`                       | `_get_device_signal_priority`, `_should_update`                                  | No caller since added                                                                                                                                              | A     |

Three module constants are dead already: `_OID_IP_FORWARDING`,
`_OID_IF_NUMBER` and `_OID_BRIDGE_MIB` in `device_classifier.py` are defined
and never read (even `_classify_from_snmp` uses string literals). Removing the
functions can orphan an import; a second pass after removal catches those.

None of the functions is a route handler or a Celery task (decorated functions
were excluded), so the OpenAPI contract does not change.

### 3.3 Dead CSS (598 rules, 417 classes, 29 stylesheets)

A rule is removed only if one of its classes — outside `:not()`, `:is()`,
`:where()` and `:has()` — can never be on an element: the name is not a token
anywhere in non-test source (JS, JSX, JSON, HTML), no template literal or
concatenation could build it, it is not a third-party runtime class (`vis-*`,
`ux4g*`), and neither census saw it. A selector list loses only its dead
members. Removing a selector that can never match cannot change rendering.

The legacy global stylesheets carry most of it. `styles/scan.css` keeps 65 of
415 rules, `styles/animations.css` 32 of 100, `compliance.css` 4 of 60, and
`web-scanning.css` 0 of 12. UX4G B.12 already recorded the global rules as
"unused by Audit pages" (§6), and the frontend suites' class ratchets assert
the legacy names no longer render. Keyframes and comments orphaned by the
removal go in a second pass.

<details>
<summary>Every class, by file</summary>

- **`Frontend/src/styles/scan.css`** — 350 rules. Classes: action-btn action-btn--danger action-btn--info action-btn--rerun action-btns admin-grid alert--info alert--success alert--warn app-progress-fill app-progress-fill--animated app-progress-label--active app-progress-label--done app-progress-label--pending app-progress-labels app-progress-track asset-pipeline-progress audit-section badge-api badge-beta badge-soon btn btn--cancel btn--danger btn--dark btn--ghost btn--lg btn--md btn--primary btn--secondary btn--sm btn--success btn-spinner btn-spinner--dark card--admin-form card--admin-table card--hover card-subtitle card-title chip--active chip--danger chip--inactive chip--neutral chip--warn confirm-btn confirm-btn--archive confirm-btn--cancel confirm-btn--danger confirm-btn--rerun confirm-btn-spinner confirm-dialog confirm-dialog-footer confirm-dialog-header confirm-dialog-icon confirm-dialog-icon--danger confirm-dialog-icon--info confirm-dialog-icon--warn confirm-dialog-meta confirm-dialog-subtitle confirm-dialog-title confirm-dialog-titles confirm-dialog-warning confirm-dialog-warning--danger confirm-meta-row confirm-meta-value confirm-overlay cred-callout cred-callout-arrow cred-callout-divider cred-callout-row cred-callout-stat cred-stat-num cve-desc cve-list cve-row cve-sev data-table detail-grid detail-host detail-host-header detail-meta detail-section dm-item dot-active dot-inactive empty-icon empty-state-icon empty-state-title expand-btn export-btns export-title field--full filter-bar filter-group filter-tab filter-tab--active filter-tabs flex-center form-action-row form-actions form-card-header form-horizontal form-section gap-8 history-empty history-live history-live--connected history-live--connecting history-live--polling history-live--reconnecting history-live-dot history-progress history-progress-fill history-progress-fill--cancelled history-progress-fill--complete history-progress-fill--failed history-progress-fill--running history-progress-text history-progress-track history-status-cell history-topbar info-banner info-banner-dot input-loader ip-code issue-list kv-grid kv-key kv-row kv-val mb-16 modal-actions modal-backdrop modal-body modal-close modal-header modal-overlay modal-panel modal-panel--large modal-panel--medium modal-panel--small modal-panel-body modal-panel-close modal-panel-grid modal-panel-header modal-panel-subtitle modal-panel-title modal-title monitor-card monitor-card-footer monitor-card-header monitor-card-meta monitor-card-progress monitor-card-stats monitor-card-target monitor-card-title monitor-grid monitor-meta-item monitor-stat mt-16 mt-24 mt-4 mt-8 new-scan-page page-actions-row pagination-controls pagination-page pagination-row pagination-summary phase-action-bar phase-footer pipeline-cancelled-card pipeline-complete-card pipeline-complete-desc pipeline-complete-icon pipeline-complete-left pipeline-complete-title pipeline-error-actions pipeline-error-card pipeline-error-header pipeline-error-icon pipeline-progress-card pipeline-progress-desc pipeline-progress-header pipeline-progress-meta pipeline-progress-title pipeline-pulse pipeline-section pipeline-section--done pipeline-section--reveal pipeline-section-header pipeline-timing port-pills ports-table progress-bar progress-bar--pipeline progress-fill progress-fill--animated progress-fill--running progress-track progress-wrap qt-chip quick-targets results-table results-table-wrap risk-badge risk-bar-fill risk-bar-track risk-bar-wrap risk-critical risk-high risk-info risk-low risk-medium row--active row--inactive search-icon search-wrap section-badge section-badge--active section-badge--done section-card section-title shimmer-cell shimmer-cell--long shimmer-cell--medium shimmer-cell--short shimmer-row shimmer-table st-card st-card--active st-desc st-name stat-value status-dot status-dot--down status-dot--up summary-bar summary-item summary-item--active summary-item--danger summary-item--sel summary-item--warn table-action-cell table-card-header table-loading-shell table-wrap target-input-wrap text-right th-sort th-sort-icon toast--exit toast--info toast--success toast-container toast-icon toast-msg tr-host tr-inactive tr-selected user-form-grid vuln-card vuln-card--critical vuln-card--high vuln-card--info vuln-card--low vuln-card--medium vuln-card-body vuln-card-header vuln-card-right vuln-card-title
- **`Frontend/src/styles/animations.css`** — 68 rules. Classes: app-progress-fill app-progress-fill--animated app-progress-track asset-pipeline-progress btn btn--dark btn--primary btn-spinner chip--active data-table empty-state-action empty-state-icon empty-state-sub empty-state-title filter-tab filter-tab--active info-banner info-banner-dot loading-dot loading-dots modal-overlay phase-footer risk-badge skeleton--card skeleton--chip skeleton--row skeleton--text skeleton--title skeleton-table-row summary-bar summary-item table-wrap table-wrap--scanning tr-host tr-inactive tr-selected vuln-card
- **`Frontend/src/modules/audit/styles/compliance.css`** — 56 rules. Classes: actions-cell comp-progress-fill compliance-form compliance-header crosswalk-tag framework-card framework-card-actions framework-card-header framework-installed-badge framework-status-placeholder fw-action-btn fw-icon fw-meta fw-reqs grid-3 ig-badge ig-badge--ig1 ig-badge--ig2 ig-badge--ig3 kpis-list metric-card metrics-grid nist-badge nist-badge--DE nist-badge--GV nist-badge--ID nist-badge--PR nist-badge--RC nist-badge--RS progress-container quad-item quad-value quadrant-grid quadrant-scores radial-score radial-score--weighted soc2-badge soc2-badge--A soc2-badge--C soc2-badge--CC soc2-badge--P soc2-badge--PI
- **`Frontend/src/styles/forms.css`** — 19 rules. Classes: auth-brand auth-brand-text auth-feature-card auth-feature-icon auth-feature-list auth-feature-text auth-hero-brand auth-hero-brand-title auth-metric-item auth-metric-lbl auth-metric-val auth-metrics-bar btn-spinner field-hint--ok field-hint--warn
- **`Frontend/src/modules/audit/styles/asset-registry.css`** — 13 rules. Classes: ar-bg-surface ar-border-b ar-c-text ar-gap-lg ar-iblock ar-owner ar-owner--none ar-p-0 ar-p-0-xl ar-p-2xs-sm ar-p-md-2xs ar-p-xs-sm ar-w-full
- **`Frontend/src/modules/audit/web-scanning/styles/web-scanning.css`** — 12 rules. Classes: ws-badge ws-badge-danger ws-badge-info ws-badge-ok ws-badge-warning ws-grid-table ws-stat-card
- **`Frontend/src/modules/audit/styles/NewScan.css`** — 11 rules. Classes: ns-cred**check ns-model**input ns-spinner ns-switch
- **`Frontend/src/modules/audit/styles/vulnerability-browser.css`** — 10 rules. Classes: vb-ai-start vb-border-b vb-checkline vb-cve-id vb-inset-0 vb-p-0 vb-p-3xs-xs vb-p-md-lg vb-pos-fixed vb-push
- **`Frontend/src/modules/audit/styles/phase1-results.css`** — 7 rules. Classes: p1-check p1-loading p1-switch
- **`Frontend/src/shell/notifications/notifications.css`** — 7 rules. Classes: shn-empty-icon shn-spinner shs-close shs-header shs-header-left shs-option shs-toggle-track
- **`Frontend/src/styles/layout.css`** — 6 rules. Classes: header-brand header-brand-icon header-brand-title header-breadcrumb header-breadcrumb-current header-breadcrumb-sep
- **`Frontend/src/design-system/components/components.css`** — 5 rules. Classes: cc-toast**body cc-toast**dismiss cc-toaster
- **`Frontend/src/styles/dark-mode.css`** — 4 rules. Classes: btn--secondary cpw-close hp-close np-close pm-close table-card
- **`Frontend/src/styles/responsive.css`** — 4 rules. Classes: app-progress-labels detail-meta pipeline-complete-card pipeline-complete-left
- **`Frontend/src/modules/audit/styles/phase2-results.css`** — 3 rules. Classes: p2-check p2-loading
- **`Frontend/src/shell/admin/styles/audit-logs.css`** — 3 rules. Classes: al-full al-row--gap-md al-start
- **`Frontend/src/shell/feedback/toast.css`** — 3 rules. Classes: toast-dismiss
- **`Frontend/src/modules/audit/styles/NetworkMap.css`** — 2 rules. Classes: nmap-subnet\_\_input
- **`Frontend/src/modules/audit/styles/app-shell.css`** — 2 rules. Classes: shh-empty shh-support-sent
- **`Frontend/src/modules/audit/styles/credentialed-results.css`** — 2 rules. Classes: cr-check\_\_input
- **`Frontend/src/modules/audit/styles/security-dashboard.css`** — 2 rules. Classes: sd-daterange**caret sd-daterange**check
- **`Frontend/src/modules/audit/web-scanning/styles/web-scanning-pages.css`** — 2 rules. Classes: wsp-detail-header wsp-toolbar
- **`Frontend/src/design-system/patterns/shell.css`** — 1 rules. Classes: cc-govbar
- **`Frontend/src/modules/audit/styles/configuration-checks.css`** — 1 rules. Classes: cfg-collect\_\_label
- **`Frontend/src/modules/audit/styles/credentialed-scan.css`** — 1 rules. Classes: cs-visually-hidden
- **`Frontend/src/modules/audit/styles/scan-policies.css`** — 1 rules. Classes: sp-empty
- **`Frontend/src/shell/account/account-dialog.css`** — 1 rules. Classes: ac-loading
- **`Frontend/src/shell/account/settings-drawer.css`** — 1 rules. Classes: shs-loading
- **`Frontend/src/shell/navigation/navigation.css`** — 1 rules. Classes: sh-menu

</details>

### 3.4 Dependencies and configuration

| Item                                                         | Evidence                                                                                                                                                                                 | Class                     |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `beautifulsoup4` in `Backend/requirements.txt`               | Added with the web module (`d291801`, "HTML parsing for crawler"); `bs4` is imported nowhere and nothing installed requires it (`pip show` in `Backend/.venv` and in `ccure-api`)        | A                         |
| `urllib3` block in `.github/security/pip-audit-accepted.txt` | Accepts two advisories fixed in 2.7.0; `requirements.txt` has pinned `urllib3==2.8.0` since `d90bb51`. The file's own rule: "Remove a block when the package is upgraded past its fixes" | A — **tightens** the gate |

### 3.5 Documentation references that go with the removals

`DEVELOPER_SETUP_GUIDE.md` (lines 56, 140, 411, 521, 660–662),
`DATABASE_SCHEMA.md:1634`, `SCAN_ENGINE_DEEP_DIVE.md` (332, 1269–1273),
`Backend/README.md:88`, `SYSTEM_ARCHITECTURE.md` (the `gateway` row and
diagram node), `ci/CONTAINER_IMAGES.md:24` and CLAUDE.md's `alt-gateway`
paragraph. Phase records (`docs/architecture/phase10/`, `RBAC_SHADOW_*`,
`docs/ux4g/03c-*`, `00_INVENTORY.md`) describe the state at the time they were
written and stay as they are.

## 4. Looks stale, is required or deliberately kept (C, D, E)

| Item                                                                                                                                                                                | Why it stays                                                                                                                                                                                                                                                                    | Class |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| `auth/*`, `core.audit*`, `core.notifications`, `routers.admin_*`, `db.models.users`/`rbac` stubs (`ccure_platform/_legacy.py` `MOVED_MODULES`)                                      | The moved modules keep their legacy `__name__`, which keys the limiter's route table, logger names and OpenAPI component names. Celery includes `auth.mail_tasks` by that name. Tested both ways by `test_platform_identity_move.py`; renaming is "a later, deliberate change". | D     |
| `scans.cvss`, `scans.finding_normalizer`, `scan_helpers.limiter` aliases                                                                                                            | Phase 3 compatibility paths, recorded as "migrated and deprecated later, not now"                                                                                                                                                                                               | D     |
| `ccure_contracts/`, `ccure_audit/integration/`                                                                                                                                      | Phase 4/5 draft contracts and adapter, deliberately unimported until Phase 14; a test fails if production imports them early                                                                                                                                                    | E     |
| `ccure_platform/service_identity/dependencies.py`                                                                                                                                   | Stays out of the API surface "until their first consumer, Phase 14"                                                                                                                                                                                                             | E     |
| `ccure_policy/`, `ccure_rank/` skeletons                                                                                                                                            | Empty, disabled modules owned by their teams; their tests and manifests are the module-boundary gate                                                                                                                                                                            | E     |
| `ccure_audit/permissions.py`, `audit_events.py`                                                                                                                                     | Loaded by name from `manifest.toml` — dynamic, invisible to an import scan                                                                                                                                                                                                      | D     |
| `core/checks/legacy_plugins.py`                                                                                                                                                     | Reached only from `tests/scans/test_plugin_contract.py`, by design: it is the arity guard for the fifteen plugins. "Legacy" names the plugins, not the module                                                                                                                   | D     |
| `ccure_platform/rbac/readiness.py`                                                                                                                                                  | Read by `scripts/verification/verify_permissions.py`, the operator's readiness check                                                                                                                                                                                            | D     |
| All 73 Alembic migrations, including those creating the dropped legacy RBAC tables                                                                                                  | Migration history; `d4f8b2c6e0a1` is irreversible on purpose                                                                                                                                                                                                                    | E     |
| `scripts/audit/*.sql`, `bench_*`, `preflight_schema_move.py`, `partitioned_index.py`                                                                                                | DBA bootstraps and operator tooling for the audit chain; `partitioned_index` is called by a migration                                                                                                                                                                           | D/E   |
| `scripts/rbac/development_reset.py`, `build_migration_inventory.py`, `data/rbac/*.json` (other than §3.1)                                                                           | Tested; the inventory and decision files are the RBAC record                                                                                                                                                                                                                    | D/E   |
| `scripts/verification/phase5_golden/`, `scripts/db/phase18/`, `scripts/gateway/*`, `gateway/{alongside,harness,production}`                                                         | Phase evidence and rehearsal harnesses, each named in its phase record                                                                                                                                                                                                          | E     |
| `scripts/verification/{verify_install,check_cve_source,check_scan_records,check_web_schema,check_target_asset,check_compliance_data,verify_report_integrity,verify_permissions}.py` | Working diagnostics. `verify_install.py` passes 18/18                                                                                                                                                                                                                           | D     |
| `scripts/cleanup_iso27001.py`, `cleanup_nist_csf_v2.py`, `fix_csf_11_crosswalks.py`, `cleanup_test_catalogue_residue.py`                                                            | Each is a dry-run-by-default repair named in CLAUDE.md or the tracker; `fix_csf_11_crosswalks --check` is a guard                                                                                                                                                               | D     |
| `scripts/fix_reverse_lookup_identities.py`                                                                                                                                          | Repairs rows a fixed mDNS parser left behind; still the only way those rows heal                                                                                                                                                                                                | D     |
| `pillow`, `bcrypt`, `python-multipart`, `email-validator` (via `pydantic[email]`), `pytest-asyncio`, `urllib3`, `charset-normalizer`                                                | Used indirectly: qrcode's PNG output and reportlab; passlib's scheme; FastAPI form parsing; `EmailStr`; four `@pytest.mark.asyncio` tests; security pins for `requests`                                                                                                         | D     |
| `docker-compose.emergency-direct.yml`, `docker-compose.development-rbac.yml`                                                                                                        | Rehearsed rollback path; the overlay the live installation is deployed with                                                                                                                                                                                                     | D     |

## 5. Tests

**No test was removed, so no security, API, regression, compliance or
architecture coverage is lost.** One assertion changed (below).

- Every skip in `Backend/tests/` is conditional on the environment (catalogue
  not seeded, no browser, privileged bootstrap absent, file not reachable).
  There is no unconditional skip and no `xfail`.
- Every import in every test resolves; no test references a removed module.
- No test exercises anything in §3 — each candidate has zero test references.
- The frontend suites mention legacy class names only in ratchets asserting
  they no longer render, which is evidence for §3.3, not coverage of it.
- `tests/README.md`'s rules hold: no group directory has an `__init__.py`, and
  test basenames are unique.
- **One assertion was replaced, not removed.** `NewScan.contract.test.jsx`
  required `NewScan.css` to contain `:focus-visible`. The only such rules
  styled `.ns-switch`, `.ns-model__input` and `.ns-cred__check` — controls the
  UX4G migration (`8699eaa`) replaced with design-system primitives, which own
  their focus rings — so the assertion held only through CSS that matched
  nothing. It now asserts the property that keeps focus visible: New Scan
  renders no focusable control of its own (its one raw `<input>` is the hidden
  file picker). `browser-tests/keyboard.spec.mjs` still checks the visible
  rings in a browser, and passes.
- The backend run has one test fewer, by construction:
  `test_every_declared_distribution_is_installed` is parametrised over
  `requirements.txt`, so the `beautifulsoup4` case went with the requirement.

## 6. OpenAPI

- **How it is made.** `Backend/scripts/openapi/generate.py` reproduces CI's
  `json.dumps(app.openapi(), sort_keys=True, indent=2, ensure_ascii=False)`
  plus one newline, and refuses to run unless the installed FastAPI and
  Pydantic are the versions `requirements.txt` pins.
- **Why it went stale.** CI's "OpenAPI Schema Diff Check" compares byte for
  byte, and any route **or docstring** change alters the document — an
  endpoint's docstring is its OpenAPI description. Regeneration was manual:
  `openapi.json` has 37 commits, about twenty of them catch-ups.
- **Already solved.** Commit `f4701c4` (8 Oct) added the `openapi-contract`
  pre-commit hook: it runs last, after the formatters, on backend code,
  `requirements.txt` or the contract; regenerates from the staged code;
  stages the file when it changed; and blocks the commit on any failure. CI's
  check is unchanged and remains the backstop for `--no-verify`.
- **Verified 9 Oct.** The hook is installed in this clone and passes in 6 s;
  two generations are byte-identical to the tracked file; `--check` exits 0;
  running the hook leaves the working tree clean.
- **Residual risk.** The generator pins FastAPI and Pydantic only. Starlette,
  and any other library that renders part of the schema, can still differ
  between a developer's environment and CI's; the local `Backend/.venv` has
  already drifted in other packages (`urllib3` 2.6.3 against a 2.8.0 pin). CI
  catches the result either way.

## 7. Verification

Before: unmodified `30d6746`. After: the working tree with every §3 removal.
9 Oct 2026.

| Check                                                              | Before                          | After                                                            |
| ------------------------------------------------------------------ | ------------------------------- | ---------------------------------------------------------------- |
| Backend suite, in the backend image, disposable `ci-pg`/`ci-redis` | 7,319 passed, 211 skipped¹      | 7,278 passed, 211 skipped, 0 errors²                             |
| Ruff, CI selection                                                 | clean                           | clean                                                            |
| Bandit, high severity                                              | 0                               | 0                                                                |
| Black                                                              | 932 files clean                 | 926 files clean                                                  |
| OpenAPI `--check`; the `openapi-contract` hook                     | pass, idempotent                | pass, contract unchanged                                         |
| Every pre-commit hook over the 63 changed files                    | —                               | all pass, nothing rewritten                                      |
| `docker compose --profile '*' config`                              | —                               | valid; differs from before only by the removed `gateway` service |
| `scripts/verification/verify_install.py`                           | 18/18                           | 18/18                                                            |
| Frontend unit (`npm test`)                                         | 3,128 / 3,128                   | 3,128 / 3,128                                                    |
| Frontend build (`VITE_API_BASE_URL=/api`), `ux4g:check --dist`     | pass; CSS 657 kB (gzip 84.6 kB) | pass; CSS 602 kB (gzip 74.9 kB)                                  |
| `ux4g:verify`, `ux4g:architecture`, authorization inventory        | pass                            | pass                                                             |
| ESLint (`--max-warnings=0`)                                        | pass                            | pass                                                             |
| Browser suite, Chromium                                            | 198 / 198                       | 198 / 198                                                        |
| Browser suite, Firefox                                             | —                               | 198 / 198                                                        |
| Browser suite, WebKit                                              | —                               | not run³                                                         |

¹ The full run without an init process reported 7,279 passed and 40 errors,
all in `tests/web/`: with pytest as PID 1 in the container, Chrome's orphaned
helper processes are re-parented to it and never reaped, and the autouse
`detect_process_leaks` guard reports them. Re-run with `docker run --init`,
`tests/web/` is 482 passed, 1 skipped, 0 errors. Run the suite in a container
with `--init`.

² Run with `--init`. Against the baseline, test by test: the 40 web tests that
errored without `--init` pass, the `beautifulsoup4` dependency case is gone
(§5), and every other outcome is identical.

³ This VM lacks `libva`, `libva-drm`, `libnice` and `libx264`, so WebKit does
not launch here (`browserType.launch`, all 198 alike), and
`webkit-userland-deps.sh` does not cover those libraries. CI's nightly
`browser-matrix.yml` runs WebKit on a hosted runner.

## 8. Technical debt: the follow-up of 9 Oct 2026

Five items were left open by §3 and resolved separately, each with the owner's
decision where one was needed.

- **Windows deployment: retired.** CLAUDE.md already recorded it as "history,
  not current requirements"; the owner confirmed retirement. Removed:
  `scripts/start_host_scan_stack.ps1`, `stop_host_scan_stack.ps1`,
  `backup_db.ps1`, `install_backup_schedule.ps1`, `validate_release.ps1`,
  `scripts/host-nginx/install.ps1` and `uninstall.ps1`, and
  `Backend/scripts/scan/start_host_scanner_worker.ps1` — each referenced only
  existing files, so none was broken; each served only the Windows
  installation, and the backup pair has Linux twins. Kept:
  `scripts/tls/*.ps1` (Windows clients still trust the private CA, and the VM's
  TLS decision names these as the certificate tooling),
  `scripts/host-nginx/nginx-host.conf` (the source the VM's edge files were
  adapted from) and `scripts/install_feed_schedule.ps1` (the only feed schedule
  there is; see below). The README was rewritten for the VM — it had told
  readers to run the Windows scripts, embedded the database password, and gave a
  `dropdb ccure_db` data-copy recipe that would destroy the live database if run
  there — and the operator refusal in `audit_log/retention.py` now names
  `scripts/backup_db.sh`.
- **Gateway tests: in CI.** `Backend Validation` (required) now runs
  `gateway/token_check/tests` (gateway-auth unit and FastAPI parity, 133) and
  `gateway/production/tests` (29) on every pull request; both are hermetic and
  take about 10 s. The new `gateway.yml` (nightly, push to `master` touching the
  gateway, manual) builds the backend image and runs `gateway/harness` (route
  policy, refusal matrix, fail-closed with gateway-auth stopped, image posture,
  log redaction; 62) and `gateway/production/trust_harness` (26).
  `gateway/alongside` stays a local rehearsal: it inspects the VM's live
  containers to prove it changed nothing.
- **`test_scan_execution.py` → `scripts/verification/verify_compliance_scan_execution.py`.**
  An operator probe, not a test. It now requires `--allow-database NAME`
  matching `current_database()`, refuses the live database names without
  `--live-approved`, executes an existing queued run only when named with
  `--run-id`, takes the run's organisation's own (or a shared) policy, and says
  that an empty scope means every asset. Validated on a scratch restore of the
  9 Oct full dump on the disposable `ci-pg`.
- **The duplicate CSS was dead CSS.** None of `.host-card`, `.scan-card`,
  `.search-input`, `.port-pill` or `.pipeline-error-detail` is rendered; §3.3's
  detector had kept them through an element id (`host-${…}`), a filename
  (`scan-${…}`), generic `-input`/`-detail` suffix patterns and a code comment.
  All 26 rules naming them were removed (25 in the built bundle, where the
  minifier had already merged the duplicate), with every surviving rule in its
  original order.
- **`Backend/.venv`: rebuilt.** It had `urllib3` 2.6.3 against the 2.8.0 pin,
  20 transitive packages behind a fresh resolution, `beautifulsoup4` after its
  removal, and bandit 1.7.9 against CI's 1.9.4. Recreated with Python 3.11 from
  `requirements.txt`, plus pre-commit, black and ruff at the hook pins, bandit at
  CI's pin and `pytest-rerunfailures` installed with the pytest pin as CI does.
  The old one is at `~/ccure-venv-backup-20261009` for rollback.

Closed on 9 Oct 2026, in the commit after the cleanup:

- **The gateway-auth image is scanned.** `images.yml` builds, scans, gates and
  smoke-tests it beside the backend and frontend images
  (`scripts/ci/smoke_gateway_auth.sh`). Its Dockerfile takes the backend's
  scoped openssl/pcre2 upgrade on the same base, which leaves no fixable OS
  finding; `trivy-gateway-auth.yaml` repeats only decisions the core already
  records for the identical package versions (pip-audit backlog, and the two
  setuptools-vendored entries of `trivy-backend.yaml`). Without that file the
  gate fails, so it gates.
- **The feeds are scheduled on the VM.** `scripts/install_feed_schedule.sh`
  installs the repository's own schedule (the Windows installer's five syncs,
  hours and time limits) as user-crontab entries running
  `scripts/run_feed_sync.sh`, which never overlaps a run and logs each one.
  VulnCheck is scheduled only once `VULNCHECK_API_TOKEN` is set; the VM has none.
- **`install_client_trust.ps1` names no server of its own.** `-RootCert`,
  `-Hostname` and `-IpAddress` (or `-SkipHostsEntry`) are required; the retired
  host's defaults and its `C:\CCure-PKI` fallback are gone.
- **The remaining dead CSS is gone.** A parser-based detector (string literals
  and template quasis only, every template's context read) found 40 classes no
  code can produce and no census rendered, `.host-card-header` and
  `.scan-card-badge` among them; their 51 rules and 4 orphaned keyframes were
  removed, and the built bundle equals the old one minus exactly those
  selectors, in order. 36 data-dependent modifiers the censuses happened not to
  render were kept, each tied to the `className` template that builds it.
- **`beautifulsoup4` leaves with the next backend image build.** The image's
  dependency stage built from today's `requirements.txt` installs neither it nor
  `soupsieve`; nothing in the current image requires them.

Still open:

- **`VULNCHECK_API_TOKEN`** must be obtained and put in `Backend/.env` before
  VulnCheck KEV can be scheduled (then re-run the installer).
- **`scripts/install_feed_schedule.ps1`** is now superseded by its VM twin and
  serves only the retired Windows deployment; removing it is a one-line
  decision.
- **The live gateway-auth and backend images** pick up these changes only when
  rebuilt and redeployed (gateway-auth's openssl/pcre2 fix; the backend image
  dropping `beautifulsoup4`).

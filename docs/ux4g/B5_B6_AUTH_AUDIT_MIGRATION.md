# B.5 + B.6 — Authentication and Audit presentation

Date: 5 October 2026. Scope: B.5 and B.6 only, following the completed B.1–B.4
foundation. Validation status: **GO — B.5 + B.6 COMPLETE**.

## Foundation and behavior preserved

The dependency remains exactly `ux4g-web-components@3.0.0`. Auth and Audit import
CCure primitives through `src/design-system/index.js`. Their official scoped
component CSS, semantic tokens and self-hosted fonts continue to come from the
single B.2/B.3 asset pipeline. No dependency, lockfile, asset generator, generated
UX4G bytes, vendor reset, runtime, CDN or font policy changed in this phase.
React continues to own control behavior; the UX4G runtime remains disabled.

The source comparison uses a snapshot of the completed B.4 working tree, rather
than Git HEAD: the earlier phases were already uncommitted at the start of this
work. B.1–B.4 changes and unrelated working-tree files are preserved.

The protected-source comparison covers 8,032 baseline backend, API, hook,
context, permission/configuration, route and auth/session files; none changed.
The comparison of 207 API/auth call expressions in migrated presentation files
also found no change to their callees or arguments. The generated authorization
inventory was refreshed for source-line movement; its decision sites, keys,
classification and totals are identical after excluding line metadata. The
routing/composition root, request clients, auth/MFA/session handling, RBAC,
backend, business rules and Policy/Rank/IR code are unchanged.

## 1. Authentication components

- Login and its MFA challenge, registration, forgot/reset password and email
  verification use shared cards, inputs, form fields, buttons, choices, alerts,
  badges and loading states. Form values, validation, token handling, consent
  payload and submit handlers are preserved.
- The registration consent uses `CcureCheckbox`. Policy buttons sit outside its
  label, so opening Terms or Privacy does not toggle consent. Existing policy
  dialogs retain the shared modal and their closing behavior.
- Account/security and change-password dialogs already used B.3/B.4 primitives.
  Those are retained; profile/session loading and empty-session presentation now
  use shared feedback. Authenticator enrolment, MFA confirmation, recovery-code
  display and password forms keep their existing behavior and shared controls.
- The incompatible-backend screen uses a main landmark, shared card, alert and
  button. The Auth hero uses shared feature cards/badges; its product copy,
  illustrations, metrics and countdown remain domain content.
- Auth composition uses shared semantic colors, spacing and typography, follows
  the chosen theme, wraps narrow content, and retains the desktop/phone split
  behavior. The separate decorative dark frame and low-contrast colors are
  removed from these screens.

## 2. Audit components

| Area                                                                              | Presentation migration                                                                                                                                                                   |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New scan, phase 1/2 results, credentialed scan/results                            | Shared cards, inputs, selects, radio/switch/checkbox controls, action buttons, loading states and settings drawers; scan configuration and dispatch unchanged.                           |
| Scan policies, schedules, credentials, comparison, configuration checks/validator | Shared forms, tables/actions and feedback; JSON labels/errors associated; existing import/export and permission decisions retained.                                                      |
| Asset Registry and asset detail                                                   | Shared filter controls, URL-backed tabs, tables, associated-assets modal and finding drawer; paging, sorting, links and datasets retained.                                               |
| Security Dashboard and reports                                                    | Shared cards, tabs/panels, badges, alerts, React-owned date menu and action buttons. Metric cards keep their existing destinations and padded shared Card bodies.                        |
| Findings and vulnerability browser                                                | Shared buttons, filters, drawer, table and remediation controls around existing CVE/evidence presentation.                                                                               |
| Remediation and compliance                                                        | Shared queue tabs, controls, feedback and action buttons; existing shared modal/drawer/table use retained.                                                                               |
| Network topology, exports and scan evidence                                       | Shared surrounding controls/cards; specialized data presentation retained.                                                                                                               |
| Web scanning                                                                      | Shared remaining actions/loading and dismissible failure alerts in finding updates and report generation, replacing native browser alerts without changing requests or success behavior. |
| Audit help and error boundaries                                                   | Shared card, tabs/panels, textarea, feedback and buttons; support action and error/reload behavior retained.                                                                             |

Pages already using the shared primitives, including history, archives and
recycle bin, keep them. They are exercised in regression tests; migration does
not require rewriting controls that already follow the shared boundary.

## 3. Shared primitives reused

`CcureButton`, `CcureIconButton`, `CcureInput`, `CcureField`, `CcureTextarea`,
`CcureSelect`, `CcureCheckbox`, `CcureRadio`, `CcureSwitch`, `CcureAlert`,
`CcureModal`, `CcureDrawer`, `CcureLoader`, `CcureSkeleton`, `CcureEmptyState`,
`CcureCard`, `CcureBadge`, `CcureTable`, `CcureTabs`, `CcureTabPanel`,
`CcurePagination`, `CcureDropdown`, `CcureMenuItem` and existing toast support.
No Auth-specific or Audit-specific replacement primitives were introduced.

Two small central fixes support the migration:

1. `CcureLoader` supports an optional decorative spinner and explicit small/
   medium size. Existing live status remains the default; adjacent domain status
   text is not duplicated when a decorative spinner is requested. It uses the
   existing generated official spinner CSS, without an asset-pipeline change.
2. `CcureTabs` accepts an empty-string tab key during keyboard navigation. The
   existing default URL tab uses that value; arrow/Home navigation now returns
   to it and the associated panel correctly.

## 4. Documented exceptions

CVE links/details, CVSS/risk/severity visualizations, network graphs, scan
consoles/progress, port lists, evidence, screenshots, JSON assessment data and
other security-specific content remain application components. Their generic
surrounding controls and containers use CCure primitives. These are not a
separate generic design system.

Three native file inputs remain: scan target-file selection, AMT JSON import,
and compliance evidence. The established shared library has no file-upload
primitive. Wrapping these native controls with the existing shared Field/Button
preserves file selection, label association, drag/drop/ref access, `FileList`
and upload/import contracts without inventing a duplicate primitive. A future
shared upload adapter can replace them when explicitly scoped. A source census
found no other native buttons, inputs, selects, textareas or tables in the Auth
page/Auth-component/Audit JSX trees.

## 5. Accessibility changes

- Visible shared focus states and native form props/semantics are retained.
  Shared fields connect labels, hints and errors; the JSON validator no longer
  nests an independent labeled textarea inside another label.
- Registration consent remains keyboard operable and required; policy controls
  have independent accessible names and focus restoration.
- Finding drawers and the associated-assets dialog use shared portals, backdrop,
  Escape handling, focus trapping/restoration and background isolation instead
  of custom modal frames/listeners.
- Date menu items use menu semantics, Home/End/arrow navigation, an announced
  current choice and Escape focus restoration. URL tabs expose their panels and
  support keyboard navigation, including the empty default key.
- Shared status/empty states replace hand-built loading text in touched areas.
  Decorative spinners avoid duplicate announcements. Native browser error
  alerts become dismissible shared alerts with the original error messages.
- Rendered active-text contrast failures found in 22 Auth baseline captures are
  absent after migration. Disabled-control contrast is recorded separately.

These are targeted fixes, not a declaration of application-wide WCAG/GIGW
conformance. The browser census has limits, including unknown contrast where a
background cannot be resolved; broader auditing belongs to later work.

## 6. Responsive changes

- Auth columns and form bodies have zero minimum width, token-based phone
  padding and wrapping footer/consent content; the hero stays hidden at the
  existing narrow-screen breakpoint.
- Audit filters, shared field wrappers and table scroll containers stay within
  their available width. Tabs and tables scroll locally when needed.
- Audit header controls wrap without shrinking below their contents. The grid
  row and header grow with those rows, keeping content below the header. The
  organization switcher can use a separate mobile row and its name truncates;
  the enterprise badge hides at phone widths. Existing authorization still
  determines whether the switcher appears.
- Shared dialogs/drawers fit 320/390-pixel viewports. Port-profile descriptions
  wrap inside the settings drawer, and their selected title retains the readable
  foreground token. Finding action buttons wrap at narrow widths; the Audit
  search field reserves space for its icon. Help composition respects the viewport.
- No global horizontal-overflow mask or new `!important` override is used.
  The 12 baseline organization-header overflow cases now pass. Browser probes
  also check header controls stay inside the header and above the main content.

## 7. Files changed

The list below is this phase's delta against the B.4 snapshot. It excludes
pre-existing B.1–B.4 changes visible in `git status`.

73 files: 65 source/test files plus the browser catalogue/diagnostics,
authorization line metadata and development documentation.

```text
CLAUDE.md
Frontend/AGENTS.md
Frontend/README.md
Frontend/authorization-inventory.json
Frontend/scripts/ux4g-harness/b5-b6.mjs
Frontend/scripts/ux4g-harness/lib/measure.mjs
Frontend/src/__tests__/design-system/primitives.test.jsx
Frontend/src/__tests__/modules/audit/pages/AssetRegistry.test.jsx
Frontend/src/__tests__/modules/audit/pages/ComplianceWorkspace.credentials.test.jsx
Frontend/src/__tests__/modules/audit/pages/ComplianceWorkspace.execution.test.jsx
Frontend/src/__tests__/modules/audit/pages/SecurityDashboard.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/FindingsExplorer.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/ScanDetail.test.jsx
Frontend/src/__tests__/pages/Register.test.jsx
Frontend/src/components/auth/AuthHeroPanel.jsx
Frontend/src/design-system/components/CcureFeedback.jsx
Frontend/src/design-system/components/CcureTabs.jsx
Frontend/src/modules/audit/components/assets/AuditTimeline.jsx
Frontend/src/modules/audit/components/common/PanelErrorBoundary.jsx
Frontend/src/modules/audit/components/common/RootErrorBoundary.jsx
Frontend/src/modules/audit/components/layout/AppLayout.jsx
Frontend/src/modules/audit/components/layout/HelpPanel.jsx
Frontend/src/modules/audit/components/remediation/FindingRemediationPanel.jsx
Frontend/src/modules/audit/components/remediation/SlaPolicyPanel.jsx
Frontend/src/modules/audit/components/scan/ConfigAuditSection.jsx
Frontend/src/modules/audit/components/scan/FindingsListSection.jsx
Frontend/src/modules/audit/components/scan/PackageInventorySection.jsx
Frontend/src/modules/audit/components/scan/ReportExportPanel.jsx
Frontend/src/modules/audit/components/scan/ScanPolicySnapshot.jsx
Frontend/src/modules/audit/pages/AssetDetail.jsx
Frontend/src/modules/audit/pages/AssetRegistry.jsx
Frontend/src/modules/audit/pages/ComplianceWorkspace.jsx
Frontend/src/modules/audit/pages/Dashboard.jsx
Frontend/src/modules/audit/pages/Remediation.jsx
Frontend/src/modules/audit/pages/SecurityDashboard.jsx
Frontend/src/modules/audit/pages/SecurityReports.jsx
Frontend/src/modules/audit/pages/VulnerabilityBrowser.jsx
Frontend/src/modules/audit/pages/admin/AMTIntegration.jsx
Frontend/src/modules/audit/pages/scan/ConfigurationChecks.jsx
Frontend/src/modules/audit/pages/scan/ConfigurationRuleValidator.jsx
Frontend/src/modules/audit/pages/scan/CredentialedResults.jsx
Frontend/src/modules/audit/pages/scan/CredentialedScan.jsx
Frontend/src/modules/audit/pages/scan/NetworkMap.jsx
Frontend/src/modules/audit/pages/scan/NewScan.jsx
Frontend/src/modules/audit/pages/scan/Phase1Results.jsx
Frontend/src/modules/audit/pages/scan/Phase2Results.jsx
Frontend/src/modules/audit/pages/scan/ScanComparison.jsx
Frontend/src/modules/audit/pages/scan/ScanCredentials.jsx
Frontend/src/modules/audit/pages/scan/ScanPolicies.jsx
Frontend/src/modules/audit/pages/scan/ScanSchedules.jsx
Frontend/src/modules/audit/styles/NewScan.css
Frontend/src/modules/audit/styles/app-shell.css
Frontend/src/modules/audit/styles/asset-detail.css
Frontend/src/modules/audit/styles/asset-registry.css
Frontend/src/modules/audit/styles/phase1-results.css
Frontend/src/modules/audit/styles/remediation.css
Frontend/src/modules/audit/styles/security-dashboard.css
Frontend/src/modules/audit/styles/vulnerability-browser.css
Frontend/src/modules/audit/web-scanning/pages/FindingsExplorer.jsx
Frontend/src/modules/audit/web-scanning/pages/NewWebScan.jsx
Frontend/src/modules/audit/web-scanning/pages/ScanDetail.jsx
Frontend/src/pages/ForgotPassword.jsx
Frontend/src/pages/Login.jsx
Frontend/src/pages/Register.jsx
Frontend/src/pages/ResetPassword.jsx
Frontend/src/pages/VerifyEmail.jsx
Frontend/src/shell/account/ProfileModal.jsx
Frontend/src/shell/auth/IncompatibleBackend.jsx
Frontend/src/styles/auth.css
Frontend/src/styles/forgot-password.css
Frontend/src/styles/forms.css
docs/FRONTEND_ARCHITECTURE.md
docs/ux4g/B5_B6_AUTH_AUDIT_MIGRATION.md
```

## 8. Build, tests, lint and assets

| Gate                                         | B.5                                | B.6                          |
| -------------------------------------------- | ---------------------------------- | ---------------------------- |
| `npm run ux4g:check`                         | PASS, exact 3.0.0/runtime disabled | PASS                         |
| `npm run ux4g:verify`                        | PASS, deterministic regeneration   | PASS                         |
| `npm run build`                              | PASS                               | PASS                         |
| `npm test -- --maxWorkers=4`                 | 109 files / 3,092 tests pass       | 109 files / 3,096 tests pass |
| `npm run lint`                               | PASS                               | PASS                         |
| Clean `npm ci`, Node 22 CI-equivalent checks | Foundation retained                | PASS                         |
| Production Docker build / nginx SPA smoke    | B.5 preview checked                | PASS                         |

The Node 22 clean-install replica excludes installed dependencies, build output
and generated UX4G assets, regenerates assets from the lockfile/package, and runs
foundation/build/reproducibility/dist validation, the full test suite and lint.
The production Dockerfile and pinned images are unchanged. Its existing builder
uses Node 25; Node 22 is separately validated to match the existing CI workflow.

Existing architecture, auth/MFA/account, permission/RBAC, scan/API contract,
module-boundary, shared-adapter and asset checks remain in the full suite.
New regression assertions cover consent/policy semantics, date-menu behavior,
empty-key URL tabs, background isolation/focus restoration and shared error
alerts with unchanged API arguments.

## 9. Browser validation and CSP

The scoped catalogue is `Frontend/scripts/ux4g-harness/b5-b6.mjs`, using the
existing Chrome/CDP harness with native-contract personas and declared fixtures.
GETs and explicitly permitted writes are synthetic. It refuses undeclared
writes and off-origin traffic; no real user, credential, scan or backend data
was changed by the browser checks.

The consolidated matrix contains 66 Auth captures and 179 Audit captures across
light/dark themes, full/restricted/read-only permissions, dialogs, error/empty/
loading states and phone/tablet/desktop widths. Auth page widths are 320/768/1440;
Audit layout checks include 320/375/390/414/768/1024/1280/1440/1920. The complete
matrix was followed by checks of changed overlays/header/profile copy and
metrics on production Docker images, including 58 final-layout captures and
34 repeated checks after the last presentation refinements. All final readiness,
action and keyboard assertions pass, with no horizontal page overflow, detected
active-text contrast failures, undeclared API requests/writes, console errors,
runtime exceptions, off-origin requests or CSP violations. The browser tests
use synthetic backend responses; real-backend end-to-end testing was not performed.

Auth workflows include MFA challenge/completion, registration, forgot/reset,
verification and account MFA enrolment/password dialogs. Audit checks include
filters, sorting, paging, URL tabs, drill-downs, exports/actions, scan settings,
credential forms, evidence, drawers and permission-restricted states. Unit tests
add the broader request/payload and MFA lifecycle coverage.

The same-state API method/path/query sets match the B.4 baseline. API call ASTs
also preserve request arguments. SSE/refresh timing repetitions are not treated
as different request contracts. Visual review supplements browser measurements:
shared cards, light/dark Auth, narrow Audit header, scan settings and finding/
associated-asset overlays were inspected.

The nginx CSP response is identical before/after, including `script-src 'self'`
and self-hosted font policy. Its existing `style-src 'self' 'unsafe-inline'` is
unchanged; this phase adds no CSP permission. No runtime was enabled and no
script `unsafe-inline`/`unsafe-eval` was added.

To reproduce against a separately built local preview (from `Frontend/`, Node 22
and installed Chrome/Chromium):

```bash
npm run ux4g:check
npm run ux4g:verify
npm run build
npm test -- --maxWorkers=4
npm run lint
node scripts/ux4g-harness/b5-b6.mjs --phase auth --base http://127.0.0.1:3235 --label b5-check --out /tmp/ccure-b5-auth
node scripts/ux4g-harness/b5-b6.mjs --phase audit --base http://127.0.0.1:3235 --label b6-check --out /tmp/ccure-b6-audit
```

Set `CHROME_PATH` if needed. The older host Node 20 needs
`--experimental-websocket` for the CDP harness; the documented Node 22 workflow
has WebSocket built in. Inspect `report.json` for readiness, actions, keyboard
probes, overflow/contrast, API requests, console exceptions and CSP violations.

## 10. Issues, limits and delivery

**New migration issues:** none unresolved after final validation. The temporary
wrapped-header overlap, metric-padding loss, narrow finding-action overlap,
search-icon overlap and scan-profile clipping/selected-label color found
while reviewing the migration were corrected before completion.

**Pre-existing/deferred:** large-bundle and ineffective-dynamic-import build
warnings, React Router future flags and jsdom navigation limitations remain.
The intentionally unimplemented Deep audit profile remains disabled; no
backend capability was enabled. Later product migrations, generic upload
adapter work, broader typography/accessibility/GIGW certification and unrelated
B.7–B.10 work remain deferred. Domain security content/CSS is intentionally
retained, rather than declaring every specialized view an official component.

A few initial harness failures came from obsolete legacy permission fixtures,
missing GET fixtures reached by newly exercised drill-downs, an expected page
heading and a probe that tried to enable Deep. These were corrected and the
same-state baseline/after cases repeated. Programmatic drawer-opening actions
now focus the opener before clicking, so the Escape probe measures a real
focus-restoration workflow. Temporary clean-install replica failures from copied
generated directories and stale authorization line metadata were corrected in
the replica; the final clean-install gate determines the result.

Evidence, complete logs, baseline/after screenshots and machine-readable source/
API comparisons are in `/tmp/ccure-b5-b6/` for this session. Temporary previews
use separate images/ports. The running production frontend on port 3200 was
not rebuilt or replaced; it needs the normal frontend image rebuild/recreation
to display these source changes. Backend services are untouched.

Rollback should remove only this phase's recorded presentation patch and test/
documentation updates, keeping the B.1–B.4 foundation. Do not reset the whole
working tree to HEAD: those earlier uncommitted changes predate this phase.

B.7–B.10 were not started. Final phase decision: **GO — B.5 + B.6 COMPLETE**.

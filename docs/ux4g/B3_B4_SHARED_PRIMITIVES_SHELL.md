# Group 1 — B.3 shared UX4G primitives and B.4 Platform shell

Implementation date: 2026-10-04. Scope is Group 1 only. Validation results below
are updated after the final production build; this document is an implementation
record, not the B.10 documentation freeze or a GIGW/WCAG certification.

## Architecture and release

`ux4g-web-components@3.0.0` → B.2 asset pipeline → CCure Design System → shell
and module consumers. The release, publisher integrity, upstream stylesheet
hash and retained Noto Sans font policy remain those approved in B.1.
`Frontend/ux4g-baseline.json` is the single release definition. No additional
framework, CDN, font source or module-local vendor implementation is introduced.

The pipeline additionally parses the verified package stylesheet and publishes
`src/design-system/components/ux4g.components.generated.css`. Only reviewed
component families are retained, and selectors are scoped with
`:where(.cc-ux4g)` to adapter roots and descendants. Official declarations,
media queries and referenced animations are retained. Global reset, unrelated
journeys and vendor font declarations are excluded. Full component CSS remains
unavailable through `UX4G_CSS_MODE`. Only the central design-system entrypoint
imports the generated subset.

PostCSS 8.5.26 was already installed transitively; it is now an exact direct
development dependency because the generator uses its parser. No installed
dependency versions were upgraded. The pipeline fingerprints the extractor,
installed parser implementation and locked parser identity alongside its
existing generator/converter inputs. Component CSS is the fifth staged output;
fresh regeneration and foundation checks compare its bytes, manifest hash and
re-derived official subset. Generated outputs remain ignored and are rebuilt
by local, clean-install, CI and Docker paths.

The previous primitive stylesheet is retained in the `ccure-legacy` cascade
layer for unmigrated literal-class consumers. Scoped official declarations and
small adapter compatibility rules take precedence for migrated components.
Those rules preserve native control sizing, application semantic tokens,
viewport bounds and visible focus. They also correct the official light-theme
danger button contrast and status text/background contrast using existing
reviewed CCure palette tokens. They do not establish another palette/framework.

## B.3 component mapping and compatibility decisions

| CCure primitive           | Official equivalent / implementation                                                                                                                        |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Button / IconButton       | UX4G button and icon-button variants and actual s/m/l sizes; native button/link props, disabled/loading states and refs                                     |
| Input / FormField         | UX4G input container, label, control and descriptions; native input events/values and associated errors/hints                                               |
| Textarea                  | UX4G textarea with native textarea, labels, hints and errors                                                                                                |
| Select                    | Official select presentation around native select/options; preserves existing children, value/change event and browser validation                           |
| Combobox                  | Official select/input/dropdown composition with controlled searchable single selection, listbox, active descendant and Arrow/Home/End/Enter/Escape behavior |
| Checkbox / Radio / Switch | Official control/mark/track/label anatomy around native inputs; radio grouping, checked values, error/hint associations and explicit accessible names       |
| Alert                     | Official alert severity/anatomy with existing announcement and dismissal contract                                                                           |
| Badge                     | Official tonal Tag for text status labels; preserves existing badge API, optional dot and monospace content                                                 |
| Spinner                   | Official spinner sizes/animations and existing named loading status                                                                                         |
| Skeleton                  | Retained semantic-token skeleton; no skeleton equivalent exists in the approved package; decorative and reduced-motion aware                                |
| Toast                     | Composition of official Alerts in persistent polite/assertive live regions; package has no standalone toast; one shared timer owner                         |
| Card                      | Official card/header/body/footer with existing heading level, flush body, native root props and ref                                                         |
| Modal / Drawer            | Official modal/drawer presentation; shared React portal, stacked focus trap, background isolation, scroll lock, Escape and restoration                      |
| Dropdown                  | Official dropdown/menu items with controlled React menu state, immediate focus, arrows, Home/End, typeahead, outside dismissal and Escape restoration       |
| Tabs                      | Official tab/list/item classes; retained automatic/manual activation API and roving focus                                                                   |
| Breadcrumb                | Official breadcrumb list/item/link with semantic current page                                                                                               |
| Pagination                | Official pagination composition with shared buttons and native Select; existing 1-based page/count/size callbacks                                           |
| Table                     | Official table/density styles; native caption, column scope, sort controls and local horizontal scroll                                                      |

React controls behavior because the vendor runtime bootstrap remains incompatible
with `script-src 'self'`. Native Select is a documented compatibility adapter:
replacing its native options/event/validation contract with vendor runtime
selection would require consumer rewrites and runtime activation. The new
searchable Combobox has an explicit controlled `value` / `onChange(value, option)`
API and does not change existing Select consumers.

The generic rich notification disclosure is a Card composition, not a menu or
modal. Specialized empty states, progress, console shell information architecture,
domain views and risk/network visualizations retain their documented application
composition; their surrounding migrated controls consume the central adapters.

Modal background isolation records and restores original attributes, handles
late body portals and nested dialogs, and only the top dialog handles Escape.
Focus restoration occurs after background isolation is lifted. Checkbox/choice
names honor explicit caller names; generated labels do not override them.
Disabled controls retain native/ARIA behavior, and error/hint text is associated
with its field rather than relying on visual placement.

### B.3 gate (completed before B.4 source changes)

- Clean `npm ci`, exact version/foundation checks, two fresh asset generations,
  build/postbuild, lint and isolated Docker production build passed.
- Full unit gate: 108 files / 3,079 tests passed. Two subsequently added
  required-selection/choice-description cases passed in the latest 329-test
  focused component/architecture run.
- Browser: 30 primitive states at 320/768/1440 in light/dark, six final control
  captures and 20 representative Common/Auth/Audit application captures.
  All probes passed; no refused writes, failed/unhandled API requests, external
  origins, runtime errors or CSP violations. Modal/drawer/nested Escape and
  restoration, menu, tabs, switches and searchable selection were exercised.
- An inactive checkbox label was flagged by the contrast census. Inactive
  controls are exempt; active primitive text contrast passed the final check.

Transient B.3 test failures were corrected: obsolete assertions that forbade all
official classes now enforce that those classes stay inside shared adapters;
background modal tests explicitly inspect hidden background nodes without
making them accessible. Existing behavior assertions remain. No dedicated Audit
UI source was changed.

## B.4 shell implementation

- Header uses the scoped official Navbar presentation inside the existing
  fluid CCure application grid. Navigation links and header/collapse controls
  consume shared Button/IconButton adapters. Current-route and permission
  decisions still come from the host, and modified link gestures remain native.
- Mobile navigation uses the shared Drawer. Closed navigation is unmounted;
  opening traps focus and isolates the background, Escape closes, and focus
  returns to the opener. Desktop rail and host nav-scroll APIs remain supported.
  The skip link actively focuses the main landmark.
- Account and organization menus use shared Dropdown/MenuItem adapters.
  Identity, tenancy eligibility, loading, switching and logout callbacks remain
  in the shell. Selection calls the original host once; menus support keyboard
  operation and Escape restoration. Shared start/end alignment keeps the
  account menu inside narrow viewports and the organization menu at its opener.
- Settings uses shared Drawer, Radio, Switch, Alert, Loader and Button.
  Native radio arrow behavior and named/described switches replace custom
  choice/toggle controls. GET/PUT preferences, product preference blocks and
  update callbacks retain their existing contracts.
- Notifications uses shared Card, Tabs, Badge, Alert, Loader, EmptyState and
  buttons. It remains a nonmodal disclosure. Feed/category/read/delete/summary
  API behavior stays in the notification module. The phone popover fits the
  viewport instead of extending past its bell anchor. Selected categories have
  an associated, named shared tab panel. Unread notification content is a
  keyboard-operable shared button, separate from its read/delete action buttons.
- Legacy `useToasts`/`ToastContainer` is a thin shared-toast adapter, retaining
  message/type/duration, 4-second default, 220-ms exit and click dismissal.
  Shared timers are canceled on unmount. Settings save-feedback timers also
  clean up on unmount.
- Common cards/forms/tables/pagination/loading/empty states already consumed
  the design-system entrypoint and inherit B.3 without module-specific copies.
  Full-width page containers and existing Audit-aligned gutters are retained.

No global horizontal-overflow suppression is added. Wide tables scroll locally;
dialogs/drawers bound their content to the viewport. Auth, RBAC, tenancy hooks,
router authorization, APIs, backend and business logic remain outside this change.
Shared primitive/shell improvements are inherited by existing product consumers;
dedicated Auth/Audit/Policy/Rank/IR UI migration is deferred.

## Final validation and issues

### Final B.4 results

| Check                                     | Result                                                                                                                                                  |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean `npm ci`, dependency tree           | PASS; one exact UX4G 3.0.0, 359 installed packages; installed dependency versions/integrities match B.2                                                 |
| UX4G foundation / generation / dist check | PASS; exact publisher input, scoped subset, self-hosted assets and disabled runtime                                                                     |
| `ux4g:verify`                             | PASS; two fresh independent generations are byte-identical                                                                                              |
| Frontend production build                 | PASS; existing chunk-size/dynamic-import warnings remain                                                                                                |
| Frontend lint and touched script lint     | PASS, zero lint warnings                                                                                                                                |
| Local unit suite                          | PASS; 109 files, 3,091 tests, zero skips                                                                                                                |
| Node 22 CI rehearsal                      | PASS; clean install, build, assets, reproducibility, lint and tests; final suite with repository CODEOWNERS present: 109 files, 3,091 tests, zero skips |
| Authorization inventory                   | PASS; unchanged inventory and protected app source                                                                                                      |
| Before/after application comparison       | PASS; 136 corresponding Common/Auth/Audit captures, identical API request sequences, no new contrast/overflow failures                                  |
| Focused final shell browser checks        | PASS; 32 captures, light/dark and 320/768/1440, including two populated-notification and two restricted-persona states                                  |
| Primitive browser regression              | PASS; 30 light/dark captures covering controls, menus, modal, drawer and nested overlays                                                                |
| Final notification association regression | PASS; eight captures covering category keyboard selection, tab/panel association and Escape/restoration                                                 |
| Production Docker build / smoke           | PASS; no-cache build plus final image, same-origin bundles, font/manifest byte parity and four SPA route fallbacks                                      |
| CSP                                       | Unchanged configuration and response header; no vendor runtime, external asset request or new script allowance                                          |

The existing Node 22 CI sequence was rehearsed in an isolated image; no remote
GitHub Actions run was triggered. That rehearsal executes install/generation/
build/verification in one writable working tree, like CI. The final full test
run mounts the current source and repository CODEOWNERS so the architecture
tests do not skip their repository-owner assertions. The production Docker
path was tested separately.

Browser evidence totals 206 B.4 captures across the application comparison and
focused regressions. The focused runs were repeated after menu placement and
notification association corrections. All declared keyboard/state assertions
passed, including their follow-up steps. There were no unexpected console
errors, CSP violations, unhandled API requests, external-origin requests,
refused writes or route failures. Fixtures intentionally return 404 for the
existing notification SSE fallback; these declared responses are not an API
regression. Real backend mutation requests were not exercised by browser
fixtures; unit tests verify existing callback/payload contracts.

Representative shell checks cover permission-aware navigation, current route,
native modified link gestures, mobile navigation trap/Escape/restoration,
skip-link focus, account/organization menu arrows/Home/End/selection/Escape,
native settings radio/switch keyboard behavior, product preference preservation,
notification read actions and tab panel semantics. Touched primitives additionally
cover associated labels/hints/errors, explicit names, disabled/loading states,
native required selection, visible focus and stacked-dialog isolation. This is
scoped accessibility validation, not complete application WCAG/GIGW conformance.

The 136-state comparison found no new application overflow. Final shell,
notification and primitive captures have no horizontal page overflow. Source
hash comparison confirms Auth/product modules, Common page business logic,
API/auth/RBAC/tenancy/route code and backend were not changed. Existing Common
full-width containers inherit shared styling without another implementation.

### New issues

None remain open in B.3/B.4 validation. Problems found during implementation
(explicit choice names, rapid menu keyboard selection, narrow account-menu
placement and notification tab/panel association) were fixed and covered by
focused tests and browser checks. The final newly added notification test was
corrected to use the platform's existing Security category; no category/API
behavior was changed.

### Pre-existing and deferred issues

- Fourteen Audit Asset Registry/Security Dashboard comparison states still
  overflow at the measured widths. Dedicated Audit responsive remediation is
  outside Group 1.
- Existing Auth metric text contrast is 3.97 in the affected desktop states.
  Dedicated Auth and application-wide accessibility phases remain deferred.
- Inactive checkbox labels are flagged by the primitive contrast census;
  inactive controls are exempt. Active primitive text passed the final check.
- Clean install reports five existing dependency advisories (two moderate,
  three high). No unrelated dependency upgrade was performed.
- Build chunk-size/dynamic-import warnings and existing jsdom navigation/alert
  and React Router warning output remain; final test assertions pass.
- An existing Audit Logs paging test depended on wall-clock debounce/poll
  timing. Its timer setup and paging-call assertions were made deterministic;
  its separate poll tests remain, and the page implementation is unchanged.
- Dedicated Auth/Audit/Policy/Rank/IR migration, the final accessibility/browser
  sweeps, final CI enforcement and documentation freeze are deferred.

Temporary validation services are isolated from the running application.
The existing `ccure-frontend` image/container was not replaced or restarted;
these workspace changes require the normal build/deployment step to appear
there. No backend, data or production configuration was changed.

### Result

**GO — B.3 + B.4 COMPLETE**. Group 1 establishes the shared foundation for later
module migrations; no B.5/B.6 work was started.

## Development and rollback

Use the shared entrypoint, preserve native contracts, document exceptions and
validate keyboard/accessibility/responsive states for touched controls. The
existing foundation and architecture checks guard the approved pin, source
identity, generated subset, central import boundary and disabled runtime. This
does not introduce the later B.9 final enforcement phase.

Run `npm ci`, `ux4g:check`, `ux4g:assets`, `ux4g:verify`, build, unit tests and
lint; validate representative browser states and the production Docker image.
Runtime remains disabled and `nginx.conf` CSP remains byte-identical to B.2.

Rollback Group 1 coherently to the approved B.2 package/lockfile, baseline,
pipeline, design-system, shell and test/doc snapshot, then regenerate and rebuild.
Do not selectively restore HEAD: B.1/B.2 were present as uncommitted approved
work at Group 1 start, and HEAD predates their exact-version foundation.

## Group 1 file inventory

Compared with the approved B.2 workspace snapshot: 63 existing Frontend files
changed and 17 Frontend files were added, plus the five documentation paths
below. Generated outputs are ignored and reproduced by the pipeline. Earlier
uncommitted B.1/B.2 changes and unrelated policy/architecture documents are
preserved; this inventory describes Group 1, not every change against HEAD.

<details>
<summary>Exact paths</summary>

```text
CLAUDE.md
Frontend/.dockerignore
Frontend/.gitignore
Frontend/AGENTS.md
Frontend/README.md
Frontend/package-lock.json
Frontend/package.json
Frontend/scripts/build-ux4g-assets.mjs
Frontend/scripts/check-ux4g-foundation.mjs
Frontend/scripts/ux4g-component-assets.mjs
Frontend/scripts/ux4g-harness/build-primitives.mjs
Frontend/scripts/ux4g-harness/primitives.css
Frontend/scripts/ux4g-harness/primitives.jsx
Frontend/scripts/ux4g-harness/run.mjs
Frontend/scripts/ux4g-pipeline.mjs
Frontend/scripts/verify-ux4g-assets.mjs
Frontend/src/__tests__/design-system/asset-pipeline.test.js
Frontend/src/__tests__/design-system/component-assets.test.js
Frontend/src/__tests__/design-system/foundation.test.js
Frontend/src/__tests__/design-system/guardrails.test.js
Frontend/src/__tests__/design-system/ux4g-adapters.test.jsx
Frontend/src/__tests__/helpers/assertUx4gAdapters.js
Frontend/src/__tests__/modules/audit/components/layout/ShellPanels.test.jsx
Frontend/src/__tests__/modules/audit/pages/AssetRegistry.test.jsx
Frontend/src/__tests__/modules/audit/pages/Dashboard.test.jsx
Frontend/src/__tests__/modules/audit/pages/RecycleBin.test.jsx
Frontend/src/__tests__/modules/audit/pages/SecurityReports.test.jsx
Frontend/src/__tests__/modules/audit/pages/VulnerabilityBrowser.test.jsx
Frontend/src/__tests__/modules/audit/pages/scan/ConfigurationChecks.test.jsx
Frontend/src/__tests__/modules/audit/pages/scan/CredentialedScan.test.jsx
Frontend/src/__tests__/modules/audit/pages/scan/ScanCredentials.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/AssetInventory.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/FindingsExplorer.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/NewWebScan.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/ScanDetail.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/ScanList.test.jsx
Frontend/src/__tests__/modules/audit/web-scanning/WebDashboard.test.jsx
Frontend/src/__tests__/shell/admin/pages/AuditLogs.test.jsx
Frontend/src/__tests__/shell/admin/pages/DeletedUsers.test.jsx
Frontend/src/__tests__/shell/admin/pages/EmailDomainRules.test.jsx
Frontend/src/__tests__/shell/admin/pages/OrganizationManagement.test.jsx
Frontend/src/__tests__/shell/sharedFrame.test.jsx
Frontend/src/__tests__/shell/ux4g-shell.test.jsx
Frontend/src/design-system/components/CcureAlert.jsx
Frontend/src/design-system/components/CcureBadge.jsx
Frontend/src/design-system/components/CcureBreadcrumb.jsx
Frontend/src/design-system/components/CcureButton.jsx
Frontend/src/design-system/components/CcureCard.jsx
Frontend/src/design-system/components/CcureCheckbox.jsx
Frontend/src/design-system/components/CcureChoice.jsx
Frontend/src/design-system/components/CcureCombobox.jsx
Frontend/src/design-system/components/CcureDrawer.jsx
Frontend/src/design-system/components/CcureDropdown.jsx
Frontend/src/design-system/components/CcureFeedback.jsx
Frontend/src/design-system/components/CcureIconButton.jsx
Frontend/src/design-system/components/CcureInput.jsx
Frontend/src/design-system/components/CcureModal.jsx
Frontend/src/design-system/components/CcurePagination.jsx
Frontend/src/design-system/components/CcureTable.jsx
Frontend/src/design-system/components/CcureTabs.jsx
Frontend/src/design-system/components/CcureTextarea.jsx
Frontend/src/design-system/components/CcureToast.jsx
Frontend/src/design-system/components/adapters.css
Frontend/src/design-system/components/components.css
Frontend/src/design-system/hooks/useFocusTrap.js
Frontend/src/design-system/hooks/useMediaQuery.js
Frontend/src/design-system/hooks/useModalEnvironment.js
Frontend/src/design-system/index.js
Frontend/src/design-system/patterns/CcureAppShell.jsx
Frontend/src/design-system/patterns/shell.css
Frontend/src/shell/account/SettingsDrawer.jsx
Frontend/src/shell/account/settings-drawer.css
Frontend/src/shell/feedback/Toast.jsx
Frontend/src/shell/layout/PlatformLayout.jsx
Frontend/src/shell/layout/platform-layout.css
Frontend/src/shell/navigation/AccountMenu.jsx
Frontend/src/shell/navigation/OrgSwitcher.jsx
Frontend/src/shell/navigation/navigation.css
Frontend/src/shell/notifications/NotificationsPanel.jsx
Frontend/src/shell/notifications/notifications.css
Frontend/ux4g-baseline.json
docs/FRONTEND_ARCHITECTURE.md
docs/ux4g/02-dependency-strategy.md
docs/ux4g/B2_ASSET_PIPELINE.md
docs/ux4g/B3_B4_SHARED_PRIMITIVES_SHELL.md
```

</details>

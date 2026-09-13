# Checkpoint 3C — Batch 17: SecurityDashboard off dashboard.css

SecurityDashboard is the landing page (`/` and `/dashboard`). This batch moves
it onto the design system:

- **Primitives:** CcureTable, CcureTabs, CcureModal, CcureAlert, CcureButton,
  CcureBadge, CcureSeverityBadge, CcureScanStatus, CcureSkeleton and
  CcureEmptyState.
- **Stylesheet:** a token-only `security-dashboard.css` replaces `dashboard.css`.
- **Crash fix:** the null-CVSS crash is fixed on this page. It is the same
  defect Batch 16 fixed in the vulnerability browser.
- **Keyboard and screen-reader access:** fixed throughout.

Batch 15 (`ce54f62`) and Batch 16 (`69b6080`) were committed first, as
separate commits. Batch 17 is uncommitted.

**Not touched:**

- The nine other high-risk pages (§0.1).
- `dashboard.css`.
- The Toast and Modal shims.
- ScanContext, ScanStepper, ExportPanel, ScanQuotaBar, CVELink.
- `api/*`, `auth/permissions`, the design-system directory (no new primitive),
  CSP and nginx.

---

## 0. How this batch was verified

| Gate                                                | Result                                                                                                                                                                                                        |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fresh assessment before any change                  | §0.1                                                                                                                                                                                                          |
| Harness, extended and proven on the pre-batch build | Determinism **62 / 62**, sensitivity **20 / 20** (§0.3)                                                                                                                                                       |
| Tests first, on the legacy page                     | 27 new tests: the 16 contract tests pass, the 11 Batch 17 tests all fail, each for its intended reason                                                                                                        |
| Same tests, migrated                                | **27 / 27**                                                                                                                                                                                                   |
| Corrections to the new tests                        | 1 (§0.2)                                                                                                                                                                                                      |
| Full frontend suite                                 | 51 files, **1613** tests, all passing (1586 + 27)                                                                                                                                                             |
| Lint                                                | `eslint src --max-warnings=0` clean                                                                                                                                                                           |
| Build                                               | `vite build` succeeds                                                                                                                                                                                         |
| Pre-commit formatting                               | Every Batch 17 file passes the repository's Prettier 3.2.5                                                                                                                                                    |
| Post determinism                                    | post-a vs post-b **62 / 62** identical                                                                                                                                                                        |
| Unchanged pages                                     | AssetRegistry, VulnerabilityBrowser and ComplianceWorkspace: **41 / 41** captures identical pre → post in every category, on both capture pairs                                                               |
| CSP and security headers                            | All six identical on the pre and post images                                                                                                                                                                  |
| Air gap                                             | The pre and post images' web roots reference the same set of absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                 |
| Writes, off-origin requests, CSP issues             | 124 post captures: 0 refused writes, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 horizontal overflow. Harness Chrome processes: 0 before and 0 after both chains |

### 0.1 Fresh assessment, and why this page

Every high-risk surface was measured on the committed tree (after `69b6080`)
before choosing a batch:

- write calls, and whether any is reached from a `useEffect`;
- WebSockets, SSE and polling;
- RBAC checks;
- credential identifiers;
- confirmations;
- click-only non-controls, tables and tests.

| Surface                       | Lines       | Writes                                                                 | Realtime              | Verdict                                                                                              |
| ----------------------------- | ----------- | ---------------------------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------- |
| **SecurityDashboard**         | 2192        | **none** (11 GETs)                                                     | one 30 s poll         | **Chosen.** Read-only, no stop condition applies, and the widest accessibility debt of any candidate |
| ScanHistory                   | 1718        | DELETE scan, POST stop, POST archive                                   | SSE reconnect loop    | Not first: needs SSE support the harness lacks, and a review of its destructive actions              |
| AMTIntegration                | 1316        | POST import (an inventory overwrite)                                   | —                     | STOP: destructive overwrite with no agreed confirmation model                                        |
| CredentialedResults           | 2368        | POST `/auth/ticket`                                                    | WebSocket             | STOP: the harness has no WebSocket support, and the page handles credentials                         |
| NewScan                       | 2905        | POST scan dispatch, POST ticket, POST stop                             | WebSocket and polling | STOP: dispatches scans; WebSocket; credentials and passphrase fields                                 |
| Phase3Results                 | 2531        | POST asset-discovery, POST vulnerability-audit, POST ticket, POST stop | WebSocket             | STOP: the pipeline auto-start mutates from the page                                                  |
| Phase1Results / Phase2Results | 1594 / 1504 | Phase 1: POST asset-discovery                                          | —                     | Coupled to ScanContext, ScanStepper and ExportPanel; better after the scan-flow design work          |
| NetworkMap                    | 1905        | —                                                                      | —                     | 215 colour literals; the token-resolver design comes first                                           |
| ComplianceWorkspace           | 6093        | 30 direct axios calls, including credential writes                     | 4 s poll              | Too large and coupled; design first                                                                  |

Three things the assessment found and recorded, without fixing them:

- **CSS is one global bundle.** Routes are imported statically, so a page's
  `dashboard.css` import styles every page. AMTIntegration uses 33 `db-*`
  classes and imports nothing. It works only because some other page imports
  the sheet.
- **The null-CVSS crash is on the landing page too.** `TopCVEsTable` called
  `c.cvss_v3_score.toFixed(1)` with no guard.
- **The harness census has a blind spot.** Its "pointer cursor on a
  non-control" census reported an empty list even for rows with
  `cursor: pointer`. The keyboard probes cover the same behaviour. §7.

### 0.2 Correction to the new tests

The "no longer depends on dashboard.css" test matched
`import\s+["'][^"']*dashboard\.css["']`. That pattern also matches the new
`import "../styles/security-dashboard.css"`. It now anchors on the file
segment, and also asserts that the page's own stylesheet is imported. The
Batch 16 tests are unaffected: neither of their stylesheet names contains
`dashboard`.

### 0.3 Harness changes

All of these are in `Frontend/scripts/ux4g-harness/`. None touches application
code.

- **SecurityDashboard states: 21 captures.** They cover the default view
  (both themes), keyboard probes for the metric card, top asset, top CVE, tabs
  and date menu, the open date menu, the admin persona (both themes), a
  restricted persona, the no-access redirect, empty, error, null CVSS, the
  welcome dialog (both themes, with an Escape probe), mobile width, and each of
  the five tabs.
- **New personas and fixtures.** Three personas: `DASHBOARD_ADMIN`,
  `DASHBOARD_RESTRICTED`, `NO_DASHBOARD`. Dashboard fixtures now carry data for
  every panel, plus empty, error and null-CVSS variants.
- **`init`:** a per-state script that runs before the application boots. It
  seeds `history.state.usr`, the router state the registration flow hands the
  dashboard.
- **`ArrowRight`** added to the probe keys.
- **Background polls no longer fire.** An interval of 10 s or more never runs
  during a capture. A capture that outlasted the dashboard's 30 s poll would
  otherwise log one more request than one that did not.
- **Stream retries compare as one.** The shell's notification stream is SSE:
  answered 404 and retried on a timer. Across 62 captures of one unchanged
  build it logged 1, 2 or 3 attempts. `compare.mjs` now compares repeated
  attempts as one, and `report.json` keeps them all. This was the only
  determinism failure (3 captures) before the change. After it, determinism is
  62 / 62. Sensitivity was recomputed from the saved injection captures under
  the new comparison: 20 / 20.
- **`REGRESSION_PREFIXES`** is now `ar-`, `vb-` and `cw-`, the pages this batch
  must leave identical.

---

## 1. Files changed

| File                                                                                           | Change                                                                                                              | LOC         |
| ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------- |
| `src/pages/SecurityDashboard.jsx`                                                              | Design-system primitives, headed panels, links, tabs, dialog, disclosure; null CVSS; `dashboard.css` import removed | 2192 → 1943 |
| `src/styles/security-dashboard.css`                                                            | **New**, tokens only, 0 colour literals                                                                             | 1115        |
| `src/__tests__/pages/SecurityDashboard.test.jsx`                                               | **New**, 27 tests (16 contract + 11 Batch 17)                                                                       | —           |
| `scripts/ux4g-harness/lib/{states,fixtures,freeze}.mjs`, `run.mjs`, `compare.mjs`, `README.md` | §0.3                                                                                                                | —           |

| Measure                                | Before                  | After                                                                     |
| -------------------------------------- | ----------------------- | ------------------------------------------------------------------------- |
| `db-*` class tokens                    | 207                     | **0**                                                                     |
| Inline `style` attributes              | 129                     | **6**: bar, risk-bar, progress and segment widths, and the donut's angles |
| Colour literals in code                | 88                      | **0**                                                                     |
| Headings in the source                 | 1 (the welcome modal's) | 9 JSX headings rendering one `h1` plus one `h2` per panel                 |
| Navigations that are links             | 0                       | 13                                                                        |
| Tables with caption and scoped headers | 0 of 2                  | **2 of 2**                                                                |
| Unguarded `cvss_v3_score.toFixed`      | 1                       | **0**                                                                     |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change  |
| ----- | -------------- | ------------- | ------- |
| CSS   | 337,115        | 354,830       | +17,715 |
| JS    | 1,640,679      | 1,635,142     | −5,537  |

The CSS grows because the new page stylesheet is added while
`dashboard.css` still ships for ComplianceWorkspace.

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures of the
default view, unless another state is named, and the unit tests cover the same
points.

- **The page had no headings.** The page title and every panel title were
  `<div>`s. The title is now an `<h1>`, and each panel and section is a
  `<section>` named by an `<h2>`.
- **Metric cards were click-only.** Each was a `<div onClick>`. Each card is now
  a link to exactly the filtered list its handler opened. _Probe before:_ not
  reached.
- **Table rows were click-only.** Each top asset and top CVE row was a
  `<tr onClick>`. The asset address and the CVE title are now links to the same
  destinations, and the rows keep their mouse click. _Probes before:_ not
  reached.
- **The tables had no names.**
  - Both tables now carry a caption and `scope="col"` headers.
  - The C / H / M headers carry their full words, visually hidden.
  - The card around each table is positioned, so those hidden words cannot
    widen the page (the Batch 16 lesson).
- **The tab bar had no tab semantics.** It was buttons with an `active` class.
  CcureTabs adds `role="tablist"`, `aria-selected`, a roving tabindex and arrow
  keys. _Probe before:_ not reached.
- **The date range was click-only.** It was a `<div onClick>`. It is now a
  disclosure button with `aria-expanded`:

  - each option states its choice with `aria-pressed`;
  - Escape closes the menu and returns focus to the button.

  _Probe before:_ not reached.

- **The welcome was not a dialog.** It was a backdrop `<div>` and a panel.
  CcureModal adds `role="dialog"`, `aria-modal`, a name, a focus trap and
  Escape. _Probe before:_ the controls were reachable, but Escape did not close
  it.
- **Contrast.** Before: 113 failing text pairs in light and 56 in dark on the
  default view. The failures were legacy `dashboard.css` and inline hex
  colours. After: **0** failing pairs on all 21 dashboard captures in both
  themes, with more pairs measured (270 → 283 on the default view).
- **Pictures that repeat text are hidden from assistive technology:** the
  severity bar, the donut, the risk-ring arc and the progress bars. Each one's
  legend or label states the numbers.
- **Unread notifications.** An unread notification was marked only by a
  CSS-drawn dot. It now also carries a visually hidden "Unread:".
- **Link names.** The two "View All" links are distinguished for screen readers
  ("View All assets", "View All notifications").
- **Loading is announced** through a polite status region.

---

## 3. Security validation

- **The page still only reads.** The eleven `/dashboard/*` GETs keep the same
  parameters (`limit=10`; `limit=8` with `severity=Critical,High`; `limit=8`).
  So do the 30 s scan-activity refresh, the notification centre's
  `GET /notifications?limit=5&unread_only=true`, and the audit timeline's
  `GET /admin/audit-logs?limit=6`. Choosing a date range reloads the same
  panels with the same parameters. The unit tests pin all of this, including
  that no POST, PUT, PATCH or DELETE is ever sent.
- **RBAC is unchanged.**
  - A user without `dashboard:read` is sent to `/scan`.
  - `assets:read`, `findings:read`, `reports:read` and `audit:read` gate the
    same tabs and widgets as before.
  - Tests cover the analyst, restricted and audit personas; the harness covers
    analyst, admin, restricted and no-access.
- **Nothing new executes or leaves the site.**
  - No new dependency and no `dangerouslySetInnerHTML`.
  - The new links are router links to the destinations the handlers used.
  - CVELink is unchanged.
- **Harness evidence:**
  - 0 refused writes across all 124 post captures.
  - Pre and post request logs differ only by the reads the keyboard probes'
    own navigations cause (§6).
  - CSP and all six security headers are identical.
  - The air-gap host set is identical, with 0 external references.

---

## 4. Intentional behaviour changes

1. **An absent CVSS v3 score shows "—".** It used to crash the landing page.
   The bands are unchanged: ≥ 9 and ≥ 7.
2. **Scan states use CcureScanStatus.** A completed scan reads "Completed"
   instead of "Done", and a status the page does not recognise reads "Unknown"
   instead of "Queued".
3. **Navigations are links.** This covers the metric cards, the address and CVE
   title in each table row, "View All", "Reports", "Full Log", "Export PDF",
   "+ New Scan", "View Now" and "Open Full …". Each can be opened in a new tab.
   The table rows keep their click.
4. **The welcome is a CcureModal.** It adds a focus trap, Escape and a named
   close button. It renders in a portal, and an overlay click still closes it.
   Every close path runs the same handler: close, then clear the router state.
5. **The date range is a disclosure.** After a choice, focus returns to the
   button. The data behaviour is unchanged (§7).
6. **The tabs are CcureTabs.** Arrow keys move and activate. Each panel is
   focusable. The Audit tab still shows no content, now as an empty panel that
   `aria-controls` can name.
7. **Alert banners are CcureAlert with `live={false}`.** They are part of the
   page as it loads, so they are not announced as interruptions.
8. **Loading panels show their titles** above their skeletons.
9. **Colours are tokens in both themes.** The legacy navy dark ground and the
   pastel hexes are gone. §2 has the contrast figures.
10. **Grids use `minmax(0, …)`.** A wide table scrolls inside its card instead of
    widening its column.

---

## 5. Retirement

- **`dashboard.css` importers go from 2 to 1.** ComplianceWorkspace is the only
  one left. The file is unedited.
- **The CSS is still global** (§0.1). Removing ComplianceWorkspace's import
  later would unstyle AMTIntegration, which borrows 33 `db-*` classes without
  importing the sheet. AMTIntegration has to leave those classes first.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-` exits 0:

- All 41 AssetRegistry, VulnerabilityBrowser and ComplianceWorkspace captures
  are identical in every category.
- pre-b vs post-b is also 41 / 41.
- Post determinism (post-a vs post-b) is 62 / 62.

Every changed category on the 21 SecurityDashboard captures is accounted for:

| Category                                                  | Why it changed                                                                                                                                                                                                                                  |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| names, headings, roles, ariaStates, tables, dialogs, live | §2: headings (0 → 14 on the default view), tabs (0 → 5), captions and scoped headers, the welcome dialog, the loading status region                                                                                                             |
| tabOrder                                                  | New stops for the metric-card links, the row links and the date disclosure (35 → 46 on the default view). The welcome state drops from 37 to 3, because the dialog's focus trap holds Tab on its close button and two actions. That is the fix. |
| probes                                                    | Every probe that failed before now completes: metric card, top asset, top CVE, tabs, the date menu (open, then Escape), and Escape on the welcome dialog                                                                                        |
| contrast                                                  | Default view: 113 → 0 light, 56 → 0 dark. Every dashboard capture: 0                                                                                                                                                                            |
| classes                                                   | `db-*` elements 312 → 0 on the default view, and 0 on every dashboard capture                                                                                                                                                                   |
| text                                                      | "Done" → "Completed"; "—" for an absent CVSS; panel titles while loading; the hidden "Unread:" and "View All …" words                                                                                                                           |
| styles, rects, screenshot, inline                         | The restyle                                                                                                                                                                                                                                     |
| requests, runtime                                         | Only probe-caused navigations (listed below). No request was removed, and there are no writes.                                                                                                                                                  |
| url                                                       | Unchanged. `sd-noaccess` still lands on `/scan`                                                                                                                                                                                                 |

The probe-caused requests:

- **Metric card and top-CVE probes** open the vulnerability browser, which
  requests `GET /api/findings/grouped/by-component`. That endpoint is not
  stubbed in dashboard states.
- **Top-asset probe** opens AssetDetail, which makes four reads that are not
  stubbed.
- **On the new route,** the shell re-reads summary, quota and notifications.
- **`sd-nullcvss`:** the page now becomes ready, with 0 console errors (1
  before).

Screenshots reviewed side by side (pre | post):

- default view, light and dark;
- mobile at 390 px;
- welcome, light and dark;
- open date menu;
- Assets and Compliance tabs;
- empty, error, null CVSS;
- admin (dark) and restricted.

They show the restyle and nothing lost or displaced:

- the mobile header stacks, with no horizontal overflow;
- the crashed state now renders.

---

## 7. Deferred, and found but not fixed

- **Product questions, preserved as they were:**
  - The scan activity panel says "Real-time · WebSocket-driven progress", but
    it polls every 30 s.
  - The date range changes no data: the range is never sent, and choosing one
    reloads identical requests.
  - "Export PDF" opens `/reports`.
  - "Last updated" shows the render time, not the fetch time.
  - "Immutable · SOC 2 / ISO 27001 ready" is a compliance claim on a widget.
  - The Audit tab has no content.
- **The census's pointer-cursor check reports nothing** (§0.1). The keyboard
  probes measure the behaviour that matters. The census should be fixed before
  it is relied on.
- **CcureTable still does not contain absolutely positioned cell content**
  (Batch 16 §7). This page contains it at card level again.
- **CcureAlert's danger icon is a cross (✕).** On a banner that cannot be
  dismissed, such as the critical-findings alert, a sighted user may read it as
  a close control. It is decorative and hidden from assistive technology. It is
  a design-system choice and is not changed here.
- **Out of scope:** the Toast and Modal shims, ScanContext, and the nine other
  surfaces in §0.1.

---

## 8. Stop

Batch 17 ends here. Nothing from Batch 17 is committed, and no Batch 18 work has
started.

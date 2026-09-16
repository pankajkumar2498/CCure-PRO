# Checkpoint 3C — Batch 18: Phase 2 port-scan results off scan.css

Phase2Results is the port-scan results page (`/scan/asset-discovery` and
`/scan/:scanId/phase2`). This batch moves it onto the design system:

- **Primitives:** CcureTable, CcureAlert, CcureButton, CcureBadge,
  CcureSeverityBadge, CcureEmptyState and CcureProgress.
- **Stylesheet:** a token-only `phase2-results.css` replaces the 56 classes the
  page borrowed from the global `scan.css`, `animations.css`, `layout.css`,
  `responsive.css` and `scan-credentials.css`.
- **Keyboard and screen-reader access:** host details are a named disclosure,
  every selection checkbox is named for its host, and the tables have captions
  and scoped headers.
- **The logic is the code that was here.** The load, the 4-second poll, the
  automatic hand-off and the audit queue are byte-identical (§3).

This page decides which hosts the vulnerability audit scans: Phase 3 starts the
port scan or the audit from an effect when it mounts. That is why the batch
began with contract tests for the queue, and with a harness guard that makes a
Phase 3 mount impossible.

Batch 17 was committed first (`7e476de`). Batch 18 is uncommitted.

**Not touched:**

- ScanContext, ScanStepper, ExportPanel, ScanQuotaBar, CVELink.
- The Toast and Modal shims, and the design-system directory (no new primitive,
  no primitive changed).
- `scan.css`, `animations.css`, `global.css`, `dashboard.css`.
- Phase1Results, Phase3Results and every other page.
- `api/*`, `auth/permissions`, the backend, CSP and nginx.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                         |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Harness fixes, on the unchanged build       | Determinism **62 / 62**, sensitivity **22 / 22** (11 injections, including the new one)                                                                                                                                        |
| The pointer census blind spot is real       | The HEAD harness misses the new injection; the fixed one detects it (§0.3)                                                                                                                                                     |
| The Phase 3 guard works                     | **14 / 14** checks against React Router's own history implementation; in Chrome on the production build, both Phase 3 URLs refused and recorded, an ordinary navigation allowed                                                |
| Baseline with the Phase 2 states            | 76 captures, all ready. Determinism **76 / 76**, sensitivity **22 / 22**                                                                                                                                                       |
| Tests first, on the legacy page             | 49 new tests: the 39 contract tests pass, the 10 Batch 18 tests all fail, each for its intended reason                                                                                                                         |
| Corrections to the new tests                | 5 (§0.2)                                                                                                                                                                                                                       |
| Same tests, migrated                        | **49 / 49**                                                                                                                                                                                                                    |
| Logic unchanged                             | The 264 lines from `useParams` to `activeResults` (hydration, selection, hand-off, pipeline state, polling, redirect, proceed) are byte-identical to the legacy page apart from one added `useId()`                            |
| Full frontend suite                         | 52 files, **1662** tests, all passing (1613 + 49)                                                                                                                                                                              |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                            |
| Build                                       | `vite build` succeeds                                                                                                                                                                                                          |
| Pre-commit formatting                       | Every Batch 18 file passes the repository's Prettier 3.2.5. Formatting `states.mjs` left the exported catalogue byte-identical                                                                                                 |
| Post determinism                            | post-a vs post-b **76 / 76** identical                                                                                                                                                                                         |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace and SecurityDashboard: **62 / 62** captures identical pre → post in every category, on both capture pairs                                                             |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                    |
| CSP and security headers                    | Identical on the pre and post images across five routes                                                                                                                                                                        |
| Air gap                                     | Both images' web roots reference the same set of absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                              |
| Writes, navigations, off-origin, CSP issues | 152 post captures: 0 refused writes, 0 blocked Phase 3 navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 horizontal overflow. Harness Chrome processes: 0 before and after |

### 0.1 Why this page

The Batch 18 assessment chose Phase2Results because it is the only unmigrated
page that sends no writes, opens no WebSocket or SSE stream, handles no
credentials and uploads nothing. Its shared components (ScanStepper,
ExportPanel) were already migrated and tested in Batch 15. It had no tests at
all, while deciding the scope of an active scan.

### 0.2 Corrections to the new tests

Each was a wrong assumption in a new test. All were found on the legacy page
except the Batch 18 half of item 3, which surfaced the first time that test
ran against the migrated page. None changed what the page does.

1. **The load sends the same request twice.** The test expected one
   `GET /scans/{id}`. The legacy page sends two, and the first response is
   discarded (§7). Pinned as found, in jsdom and in the browser.
2. **Asset discovery never writes the audit queue.** The test expected an
   empty queue; `cc_phase3Results` is never written at all.
3. **An inactive host is listed only under "All".** Both the contract test
   and a Batch 18 test looked for its checkbox under the default filter.
4. **A mocked `navigate` must unmount the page.** Left mounted, the automatic
   hand-off effect re-ran on every render of the scan context and the test run
   hung. In the application the route has already changed, so the tests now
   unmount the page on navigation, as the router does.
5. **Two Batch 18 tests expanded hosts through the new button.** On the legacy
   page they then failed on the lookup instead of their own assertions. They
   now click the host address, which works on both.

### 0.3 Harness changes

All of these are in `Frontend/scripts/ux4g-harness/`. None touches application
code.

- **The pointer census could never report anything.** Its "inside a control"
  test counted any `[tabindex]` ancestor. The shell renders
  `<main tabIndex={-1}>` around every page, so every element sat inside a
  "control". A focusable container is no longer treated as one.
  - **Proof:** a new injection, `pointer-only-target`, adds a click-only
    element inside `<main>`. The HEAD harness captures it with no `clickable`
    delta; the fixed harness detects it on both sensitivity states.
  - **What it now finds on the unchanged pages:** the row-click tables on
    AssetRegistry, VulnerabilityBrowser and SecurityDashboard (each row also
    carries a link, so the keyboard path exists), and eight click-only tab
    labels per ComplianceWorkspace capture. Identical before and after; §7.
- **No capture can mount a Phase 3 route** (`lib/guard.mjs`).
  - `history.pushState` and `replaceState` refuse `/scan/vulnerability-audit`,
    `/scan/advanced-scan` and `/scan/{id}/phase3` with a `DataCloneError`.
    React Router's browser history rethrows that error name before its
    listener runs, so the router's location never changes and the route never
    renders.
  - A document loaded at such a URL stops before the application boots.
  - A refusal is recorded under `blockedNavigations` and makes `run.mjs` exit 1.
- **`repeatable`:** a state can name requests it makes on an unbounded timer.
  Those lines compare as one in that state only. Used by `p2-running`, whose
  scan is still running and is polled every 4 seconds.
- **Phase 2 states: 14 captures.**
  - `p2-results` (both themes, with a keyboard probe on host details),
    `p2-expanded` (both themes) and `p2-expanded-mobile` (390 px);
  - `p2-interactive` (both themes, with probes that change the selection and
    the audit profile) and `p2-readonly` (without `scans:execute`);
  - `p2-unreachable` (both themes), `p2-no-results`, `p2-load-error`;
  - `p2-running` (both themes).
- **Safety rules for those states.** No state pairs automatic mode with a
  pipeline that has a phase 3; scans that include phase 3 are only loaded with
  interactive mode seeded. No probe ever presses "Run Vulnerability Audit".
  The guard makes a mistake in either rule fail loudly rather than start a
  scan.
- **Fixtures** use the field names the page reads, checked against the
  orchestrator's `_format_host` and the port-scan summary. New persona:
  `SCANS_READONLY`.
- **`REGRESSION_PREFIXES`** is now `ar-`, `vb-`, `cw-` and `sd-`.

---

## 1. Files changed

| File                                                                                                       | Change                                                                                 | LOC         |
| ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | ----------- |
| `src/pages/scan/Phase2Results.jsx`                                                                         | Design-system primitives, headings, disclosure, named checkboxes, toggle state, alerts | 1504 → 1184 |
| `src/styles/phase2-results.css`                                                                            | **New**, tokens only, 0 colour literals                                                | 479         |
| `src/__tests__/pages/scan/Phase2Results.test.jsx`                                                          | **New**, 49 tests (39 contract + 10 Batch 18)                                          | —           |
| `scripts/ux4g-harness/lib/guard.mjs`                                                                       | **New**, §0.3                                                                          | —           |
| `scripts/ux4g-harness/lib/{measure,injections,fixtures,states}.mjs`, `run.mjs`, `compare.mjs`, `README.md` | §0.3                                                                                   | —           |

| Measure                                  | Before                                                    | After                   |
| ---------------------------------------- | --------------------------------------------------------- | ----------------------- |
| Classes borrowed from global stylesheets | 56 (`scan.css` 38, `animations.css` 12, 3 other sheets 6) | **0**                   |
| Inline `style` attributes                | 79                                                        | **0**                   |
| Colour literals in code                  | 36 (24 hex, 12 rgb)                                       | **0**                   |
| Click-only elements                      | 1 (the host card header)                                  | **0**                   |
| Tables with a caption and scoped headers | 0 of 4                                                    | **4 of 4** (CcureTable) |
| Named disclosure controls                | 0                                                         | 1 per host              |
| Tests                                    | 0                                                         | 49                      |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 354,830        | 361,845       | +7,015 |
| JS    | 1,635,142      | 1,630,364     | −4,778 |

The CSS grows because the page stylesheet is added while `scan.css` and
`animations.css` still ship for the pages that use them. The JS shrinks
because 79 inline style objects and the colour table are gone.

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures, and the
unit tests cover the same points.

- **The page had no level-one heading.** The title was an `h2`. It is now an
  `h1`, on the loading and error views too. Each host's header is an `h2` and
  each detail section an `h3`.
- **Host details were click-only.** The card header was a `<div onClick>`
  with an unnamed "▼" button beside it. Before: 4 glyph-only buttons and 8
  pointer-only targets on the default view. After: each header is a heading
  containing one button, named by the host's address and summary, with
  `aria-expanded` and `aria-controls`. The keyboard probe reaches it by name.
- **Selection checkboxes had no names.** 9 unlabelled controls on the
  interactive view, and they decide which hosts get scanned. Each is now
  named "Select 10.20.0.11 for vulnerability audit"; select-all is named too.
- **The tables had no names.** All tables are CcureTable with a caption and
  `scope="col"` headers. On a narrow screen each scrolls inside its card and
  becomes a named, focusable region.
- **Toggle groups did not expose their state.** The Active/All filter and the
  audit profile are grouped, labelled and carry `aria-pressed`. Each profile's
  description is attached with `aria-describedby`, not only a tooltip.
- **Status was silent.** The running scan is a status region with an
  indeterminate progress bar; the queued-host count is a status region; a
  failed load is an alert; loading is announced. The unreachable warning is a
  CcureAlert that is part of the page as it loads, so it is not announced as an
  interruption.
- **Contrast.** Before, on the default view: 8 failing text pairs in light and
  5 in dark; expanded hosts, 30 and 7. After: **0** on all 28 Phase 2
  captures in both themes. Two legacy dark-theme defects are gone: the
  "Port Scan Running…" title was white on a white card, and the unreachable
  warning's text measured 2.24.
- **Risk is a label, not only a colour.** Each port's risk is a severity badge.
- The read-only state's disabled controls measure 1.69. Disabled controls are
  exempt from the contrast requirement; recorded here so the number is not a
  surprise.

---

## 3. Security validation

- **The page still only reads.** Every Phase 2 capture logs the same requests
  before and after. Every unit test asserts, after it runs, that no POST, PUT,
  PATCH or DELETE was sent.
- **The audit queue is unchanged.** The logic block is byte-identical, and the
  contract tests pin what it does:
  - automatic mode queues every active host with a detected TCP or UDP service
    and hands off only once results exist and only if the pipeline has a
    phase 3;
  - interactive mode selects the same hosts by default; the table and the cards
    change one selection; select-all queues every active host; an inactive
    host cannot be selected;
  - the hand-off carries `{ vulnerabilityProfile, startPhase: "VULN_SCAN" }`;
  - polling checks at once, then every 4 seconds, and stops on results, on a
    completed or failed scan, and when the page is left.
- **RBAC is unchanged.** `scans:execute` gates the checkboxes, the profile and
  "Run Vulnerability Audit". The automatic hand-off is not gated here, as
  before; Phase 3 checks the permission before it dispatches (pinned).
- **Phase 3 was never mounted.** 0 blocked navigations across all captures,
  and the guard would have failed the run if one had been attempted.
- **Nothing new executes or leaves the site.** No new dependency, no
  `dangerouslySetInnerHTML`. The two new links go where the old buttons
  navigated. Headers and the air-gap host set are identical, with 0 external
  references.

---

## 4. Intentional behaviour changes

1. **The host header is a button.** It fills the header beside the checkbox.
   Clicking the padding around the checkbox no longer toggles the details.
2. **"Back" and "Back to Scan History" are links.** They can be opened in a
   new tab.
3. **Risk is a severity badge.** A risk value the design system does not
   recognise is printed as the scanner wrote it, in a neutral badge.
4. **Coloured spans are badges.** Port counts, the critical count, the OS
   guess, CVE counts, mDNS services, bound addresses and the firewall flag.
5. **Banner glyphs come from the design system.** The ⚠ characters are the
   CcureAlert icon; the running pulse and bar are a status region and
   CcureProgress.
6. **Detail section headings are `h3`**, keeping their small upper-case style.
7. **Tables scroll inside their cards on narrow screens**, and each scrollable
   one is a tab stop (36 → 40 on the mobile capture).
8. **The queued-host count and the running scan are announced.**
9. **Colours are tokens in both themes.**
10. **Host facts are description lists** (`dl`), label and value.

---

## 5. Retirement

- **No stylesheet is removed.** Phase2Results no longer uses `scan.css` or
  `animations.css`, but ScanHistory, Phase1Results, Phase3Results,
  CredentialedResults, NewScan and both shims still do, through `global.css`.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-` exits 0:

- All 62 unchanged-page captures are identical in every category.
- pre-b vs post-b is also 62 / 62.
- Post determinism (post-a vs post-b) is 76 / 76.

Every changed category on the 14 Phase 2 captures is accounted for:

| Category                                         | Why it changed                                                                                                                         |
| ------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| names, headings, roles, ariaStates, live         | §2: named checkboxes and disclosures, `h1`/`h2`/`h3`, groups, scroll regions, `aria-expanded`/`aria-pressed`, status and alert regions |
| tables                                           | Captions and scoped headers on every table                                                                                             |
| clickable                                        | Pointer-only targets 8 → 0 (host headers and host-table rows)                                                                          |
| probes                                           | Same outcomes, now reaching named controls ("Select 10.20.0.11 …", the host disclosure)                                                |
| contrast                                         | Every Phase 2 capture: 0 failing pairs                                                                                                 |
| tabOrder                                         | Scroll regions on the mobile capture; otherwise the same stops, with names                                                             |
| inline, classes, styles, rects, screenshot, text | The restyle; the only inline styles left are the shell's quota bars, identical on every page                                           |
| requests, writes, url, runtime                   | **Unchanged**                                                                                                                          |

Screenshots were reviewed side by side for all 14 captures. One regression was
found and fixed before the final capture: "Back to Scan History" stretched to
the full width on the error views.

---

## 7. Deferred, and found but not fixed

- **The load requests the scan twice.** The load effect lists the scan
  context's setters as dependencies, and ScanContext creates new setters on
  every render. The page's own pipeline-state update re-renders the provider
  before the first response arrives, so the effect is cancelled and re-run.
  The automatic hand-off effect has the same shape and would repeat if the
  page stayed mounted. ScanContext was out of scope.
- **`cc_executionMode` is not in ScanContext's `SS_KEYS`**, so `resetScan()`
  leaves it in sessionStorage.
- **The 4-second poll never gives up** and swallows every error.
- **Phase 3 starts scans when it mounts**; that is the planning STOP for Phase 3.
- **The custom port list is truncated** to 22 characters; the full value is
  only in a tooltip.
- **Carried from Batch 15:** ExportPanel's CSV formula injection;
  `getScanPipeline` throws on an unknown pipeline mode.
- **The fixed pointer census reports real findings elsewhere:** click-only tab
  labels on ComplianceWorkspace, and row-click tables whose rows also carry
  links on AssetRegistry, VulnerabilityBrowser and SecurityDashboard.
- **Carried design-system notes:** CcureTable still does not contain visually
  hidden content (contained at card level again); CcureAlert's danger icon is
  a cross.
- **Harness:** no SSE or WebSocket replay and no file-input driving yet. The
  focus snapshot's name reads visible text, so "← Back" includes a glyph the
  accessible name hides.

---

## 8. Stop

Batch 18 ends here. Nothing from Batch 18 is committed, and no Batch 19 work has
started.

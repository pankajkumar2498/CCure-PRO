# Checkpoint 3C — Batch 19: Phase 1 discovery results off the global sheets

Phase1Results is the host-discovery results page (`/scan/host-discovery` and
`/scan/:scanId/phase1`). It is also where an operator configures and starts a
port scan in interactive mode. This batch moves it onto the design system:

- **Primitives:** CcureTable, CcureAlert, CcureButton and CcureBadge.
- **Stylesheet:** a token-only `phase1-results.css` replaces the 54 classes the
  page borrowed from the global `scan.css`, `animations.css`, `NewScan.css` and
  four other sheets.
- **Keyboard and screen-reader access:** every host-selection control, port
  field, address field and exclusion switch is named; validation messages are
  tied to their fields; the mode and filter toggles expose their state.
- **The logic is the code that was here.** The load, the port-scan request and
  its guards, the port and address parsers, the default selection, the
  4-second poll and every navigation are byte-identical (§3).

"Run Port Scan" starts a port scan against the selected hosts with the options
beneath it, so the batch began with contract tests that pin that request
exactly, on the legacy page.

**Baseline:** HEAD `e308b54` (Batch 18). Batch 19 is uncommitted.

**Not touched:**

- ScanContext, ScanStepper, ExportPanel, ScanQuotaBar, CVELink, RiskBadge.
- CcureTable, CcureAlert and every other design-system primitive; the Toast and
  Modal shims.
- `global.css`, `scan.css`, `animations.css`, `NewScan.css`, `dashboard.css`,
  `NetworkMap.css`, `compliance.css`.
- Phase2Results, Phase3Results and every other page.
- The harness's capabilities (no text entry, no guard change), `api/*`, the
  backend, CSP and nginx.

---

## 0. How this batch was verified

| Gate                                         | Result                                                                                                                                                                                                                                             |
| -------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                  | `git status` empty at `e308b54`                                                                                                                                                                                                                    |
| Trial of the Phase 1 states, unchanged build | 17 captures ready; 0 writes, 0 blocked navigations; every probe reached and passed; every capture ends on a Phase 1 route                                                                                                                          |
| Baseline, unchanged build                    | 93 captures ready. Determinism: first pair **92 / 93**, re-established pair **93 / 93** (§0.1). Sensitivity **22 / 22** on both                                                                                                                    |
| Tests first, on the legacy page              | 74 new tests: the 62 contract tests pass, the 12 Batch 19 tests all fail, each for its intended reason                                                                                                                                             |
| Corrections to the new tests                 | 1 (§0.2)                                                                                                                                                                                                                                           |
| Same tests, migrated                         | **74 / 74**                                                                                                                                                                                                                                        |
| Logic unchanged                              | The 551 lines from the component's opening to the stepper step (excluding the two early-return views) are byte-identical to the legacy page apart from one added `useId()`                                                                         |
| Full frontend suite                          | 53 files, **1736** tests, all passing (1662 + 74)                                                                                                                                                                                                  |
| Lint                                         | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                |
| Build                                        | `vite build` succeeds                                                                                                                                                                                                                              |
| Pre-commit formatting                        | Every Batch 19 file passes the repository's Prettier 3.2.5                                                                                                                                                                                         |
| Post determinism                             | post-a vs post-b **93 / 93** identical                                                                                                                                                                                                             |
| Unchanged pages                              | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace, SecurityDashboard and Phase2Results: **76 / 76** captures identical pre → post in every category, on both capture pairs                                                                  |
| Sensitivity on the migrated build            | **22 / 22**                                                                                                                                                                                                                                        |
| Phase 1 requests                             | Every Phase 1 capture logs the same requests before and after: **0** differences. 0 of the 51 Phase 1 captures (one pre, two post) end off a Phase 1 route                                                                                         |
| CSP and security headers                     | Identical on the pre and post images across six routes, both Phase 1 routes included (42 header lines)                                                                                                                                             |
| Air gap                                      | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                       |
| Writes, navigations, off-origin, CSP issues  | 186 post captures: 0 refused writes, 0 blocked Phase 3 navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Harness Chrome processes: 0 before and after |
| Screenshots                                  | All 17 Phase 1 captures reviewed side by side, pre and post: no visual regression found                                                                                                                                                            |

### 0.1 The baseline was captured twice

The first pre-migration pair matched on 92 of 93 captures. The exception was
`p1-phase2-done.dark` in the first capture: 5 pixels beyond the screenshot
tolerance, by 3/255 against a tolerance of 2, all inside the legacy page's
translucent "Port Scan Complete" banner. Every other category was identical.

Six further captures of that one state all matched the second capture exactly,
and every one differed from the first by the same 5 pixels. The first capture
was the outlier. The tolerance and the method were not changed. A fresh full
pair was captured on the same unchanged image instead: **93 / 93**, and the
earlier second capture matches it 93 / 93 as well. That fresh pair is the
baseline every later comparison uses.

### 0.2 Correction to the new tests

The `?scan_id=` test's fixture answered with a different scan id from the one
requested. The page then loaded the scan again and again, because it keeps
loading for as long as the id in context differs from the requested one, and
the results never rendered. Real responses carry the requested id, so the
fixture was corrected. The loop itself is recorded in §7.

### 0.3 Harness changes

Fixtures and states only. No capability was added.

- **17 Phase 1 captures:**
  - `p1-basic` (both themes, with a keyboard probe on the host filter);
  - `p1-asset-running` (both themes) and `p1-audit-running`, each polling, with
    the poll declared `repeatable`;
  - `p1-phase2-done` (both themes);
  - `p1-interactive` (both themes, with probes that change the host selection,
    switch to custom ports and turn an exclusion on);
  - `p1-scope` (both themes) and `p1-scope-mobile` (390 px): custom ports with a
    sensitive port, excluded ports and an invalid excluded address, all seeded;
  - `p1-readonly` (without `scans:execute`);
  - `p1-unreachable` (both themes), `p1-no-results`, `p1-load-error`.
- **Safety rules.** No action or probe touches "Run Port Scan", "View Port Scan
  Results" or "Continue to Port Scan". Validation errors that need typing are
  covered by the unit tests, not the harness. Every Phase 1 capture must end on
  a Phase 1 route, and the Phase 3 guard remains the backstop.
- **Why the interactive states seed the scan context.** Phase 1 computes its
  default selection once, from the hosts in context at its first render. A
  scan loaded from the URL starts with nothing selected (§7).
- **`REGRESSION_PREFIXES`** now includes `p2-`.

---

## 1. Files changed

| File                                              | Change                                                                                       | LOC         |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------- | ----------- |
| `src/pages/scan/Phase1Results.jsx`                | Design-system primitives, headings, named and labelled controls, toggle state, alerts, links | 1594 → 1299 |
| `src/styles/phase1-results.css`                   | **New**, tokens only, 0 colour literals                                                      | 594         |
| `src/__tests__/pages/scan/Phase1Results.test.jsx` | **New**, 74 tests (62 contract + 12 Batch 19)                                                | —           |
| `scripts/ux4g-harness/lib/{fixtures,states}.mjs`  | §0.3                                                                                         | —           |

| Measure                                     | Before                                                               | After                   |
| ------------------------------------------- | -------------------------------------------------------------------- | ----------------------- |
| Classes borrowed from global stylesheets    | 54 (`scan.css` 26, `animations.css` 11, `NewScan.css` 9, 4 others 8) | **0**                   |
| Inline `style` attributes                   | 72                                                                   | **0**                   |
| Colour literals in code                     | 35 (16 hex, 19 rgb)                                                  | **0**                   |
| Headings in the source                      | 1                                                                    | 7                       |
| Labels and accessible names in source       | 2                                                                    | 13                      |
| Pointer-only targets per capture with hosts | 4 (the host rows)                                                    | **0**                   |
| Tables with a caption and scoped headers    | 0 of 1                                                               | **1 of 1** (CcureTable) |
| Tests                                       | 0                                                                    | 74                      |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 361,845        | 371,029       | +9,184 |
| JS    | 1,630,364      | 1,627,019     | −3,345 |

The CSS grows because the page stylesheet is added while `scan.css`,
`animations.css` and `NewScan.css` still ship for the pages that use them. The
JS shrinks because 72 inline style objects and 35 colour literals are gone.

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures, and the
unit tests cover the same points.

- **The page had no level-one heading.** The title was an `h2`, and the loading
  and error views had no heading at all. The title is now an `h1` on every
  view. "Configure & Run Port Scan" and "Port Scan Running…" are `h2`; each
  exclusion section is an `h3`, with its 🚫 hidden from screen readers.
- **Host-selection checkboxes had no names**, and they decide which hosts get
  port scanned. The interactive view had 7 unlabelled controls (select-all,
  four host checkboxes and two switches); the scoped view had 10. After: 0.
  Each checkbox is named "Select 10.20.0.11 for port scan", and select-all is
  "Select all active hosts for port scan". The keyboard probe reaches the host
  checkbox by that name.
- **The port and address fields were named only by their placeholders.** They
  now carry visible labels: "Custom ports", "Ports to exclude" and "IP
  addresses or subnets to exclude".
- **The exclusion switches were unnamed checkboxes** inside a styled label with
  no text. Each is now `role="switch"`, named by its section heading and
  described by the hint beneath it. The unit tests find both by role and name.
- **Validation messages were not tied to their fields.** An invalid custom port
  list and an invalid excluded address set `aria-invalid` and point at their
  message with `aria-describedby`. The ⚠ in the message is hidden.
- **Toggle groups did not expose their state.** "Intensity Profile" / "Custom
  Ports" and the Active / All filter are labelled groups whose buttons carry
  `aria-pressed`.
- **Tag removal was a bare "×".** 2 glyph-only buttons on the scoped view.
  Each is now named, for example "Remove 2375 from excluded ports".
- **The host table had no name.** It is CcureTable with the caption
  "Discovered hosts" and `scope="col"` headers. At 390 px it scrolls inside its
  card as a named, focusable region (tab stops 48 → 49 on that capture; every
  other capture keeps its tab-stop count).
- **The host rows looked clickable and were not.** Each showed a pointer
  cursor and did nothing: 4 pointer-only targets on every capture with hosts.
  After: 0.
- **Status was silent.** The selected-host count and the running port scan are
  status regions. The sensitive-ports warning, request errors and a failed load
  are alerts. Loading is announced. The unreachable warning and the basic
  scan's completion note are present as the page loads, so they are not
  announced as interruptions.
- **Contrast.** Failing text pairs before, light / dark: default view 2 / 5,
  interactive 3 / 6, scoped 12 / 6, scoped at 390 px 12, read-only 2, port scan
  running 6 / 5 (5 on the audit pipeline), port scan complete 7 / 6,
  unreachable 4 / 4, and 1 on each error view. After: **0** on all 17 Phase 1
  captures. Legacy defects now gone:
  - the sensitive-ports banner's text measured 1.33 in light, its title 1.51
    and its port numbers 1.39;
  - the unreachable warning's text measured 2.24 in dark;
  - the "Active" status pills measured 2.46 in dark, and the "BALANCED" profile
    1.96 in light;
  - "Run Port Scan" and "View Port Scan Results" measured 2.77, the tag "×"
    2.45, and the active-host count 2.28.
- **The pipeline bar is decorative.** It is hidden from screen readers; the
  step labels beside it stay as text.
- **390 px.** No horizontal overflow before or after. On the legacy capture
  "Run Port Scan" was cut off at the card's edge; it now wraps under the
  heading.
- The read-only state has two disabled controls below the contrast threshold
  (one before). Disabled controls are exempt; recorded here so the number is
  not a surprise.

---

## 3. Security validation

- **The only write is the port-scan request, and it is unchanged.** The logic
  block is byte-identical, and the contract tests pin it on the legacy page and
  the migrated one alike:
  - the exact body: `hosts`, `intensity`, `scan_id`, `pipeline_mode`,
    `os_detection` and `phases: [1, 2]`; `intensity` is `custom` in custom mode,
    otherwise the recorded intensity or `normal`;
  - `custom_ports` as written, only in custom mode; `exclude_ports` and
    `exclude_ips` trimmed, and only when set; turning an exclusion off clears
    its value, so it is not sent;
  - the hosts: every active host is selected by default; only selected, active
    hosts are sent; select-all selects or clears every active host; an inactive
    host cannot be selected;
  - validation order and wording: permission, then at least one host, then an
    empty custom list, then the custom list's parse, then
    "Exclude ports error: …", then "Exclude IPs error: …"; eight parser
    messages; an invalid excluded address is shown as soon as it is known;
  - success sets the pipeline state to `PORT_SCAN` and navigates to
    `/scan/asset-discovery` with no navigation state; a failure shows the
    request's message, or a default, and stays on the page;
  - the sensitive-ports warning appears only in custom mode, for 2375, 2376,
    6443 and 10250.
- **No other request changed.** Every Phase 1 capture logs the same requests
  before and after. Every unit test asserts, after it runs, that nothing was
  written except the dispatches that test allows. The harness pressed none of
  "Run Port Scan", "View Port Scan Results" or "Continue to Port Scan": 0
  refused writes and 0 captures off a Phase 1 route across all 51 Phase 1
  captures, and 0 blocked Phase 3 navigations.
- **Loading is unchanged.** A scan named in the URL, or by `?scan_id=`, is
  requested once. A scan with no discovery explains itself instead of
  redirecting. An empty host list returns to `/scan` (replacing the history
  entry), but not while loading or while showing a load error.
- **Polling is unchanged.** In automatic mode the page waits 4 seconds, then
  checks every 4 seconds. It stops when phase 2 data arrives, when the scan
  completes or fails, and when the page is left. It keeps polling through a
  failed request. There is no polling in interactive mode, on a basic scan,
  when the target was unreachable, or once phase 2 is done.
- **Navigation is unchanged.** The page never navigates on its own, even on a
  pipeline with a phase 3. Phase 1 passes no navigation state anywhere. The
  `vulnerabilityProfile` / `startPhase: "VULN_SCAN"` hand-off belongs to Phase 2. Phase2Results was not touched, its 76 captures are identical, and its 49
  tests pass in the full suite.
- **RBAC is unchanged.** `scans:execute` still gates "Run Port Scan" (which
  also refuses if invoked without it), the host checkboxes and select-all, the
  excluded-port and excluded-address fields, tag removal, the "Sensitive
  Ports" option and "Continue to Port Scan". The controls that were ungated
  are still ungated (§7). The three navigations that never checked a permission
  are now links to the same routes.
- **ExportPanel is unchanged.** It receives the same props, and appears only
  when there is a summary and phase 2 cannot follow: a basic scan, or an
  unreachable target.
- **Nothing new executes or leaves the site.** No new dependency and no
  `dangerouslySetInnerHTML`. Headers and the air-gap host set are identical,
  with 0 external references, 0 off-origin requests and 0 CSP issues.

---

## 4. Intentional behaviour changes

1. **"← New Scan", "View Port Scan Results" and "Back to Scan History" are
   links.** They go where the old buttons navigated (`/dashboard`,
   `/scan/asset-discovery`, `/history`) and can be opened in a new tab.
   "Continue to Port Scan" stays a button, because it is permission-gated.
2. **Port and address fields have visible labels.** Placeholders are unchanged.
3. **An invalid field is outlined in the danger colour** as well as showing its
   message.
4. **"Run Port Scan" uses CcureButton's loading state** while the request is
   sent: the same "Starting Port Scan..." text, marked busy. The condition that
   disables it is unchanged.
5. **Banners are CcureAlert.** Request and load errors are danger alerts, the
   sensitive-ports banner is a warning alert, and the unreachable warning and
   completion notes are not announced. Their ⚠ and ✓ glyphs come from
   CcureAlert's icon. "View Port Scan Results" sits under the completion text
   rather than beside it.
6. **The exclusion switches are native checkboxes with `role="switch"`**,
   styled from tokens.
7. **The summary is a list, and the discovery profile is a badge** (FAST info,
   BALANCED warning, anything else success).
8. **The selected-host count and the running scan are announced.**
9. **The pipeline bar is decorative**, at the same widths, set by class.
10. **Headings:** an `h1` title on every view (the loading and error views
    included), `h2` for the port-scan panel and the running scan, `h3` for each
    exclusion section.
11. **The host table is CcureTable.** Column headers are no longer upper-cased,
    rows no longer show a pointer cursor, and on a narrow screen the table
    scrolls inside its card as a tab stop.
12. **Colours are tokens in both themes.**

---

## 5. Retirement

- **No stylesheet is removed.** Phase1Results no longer uses `scan.css`,
  `animations.css` or `NewScan.css`, but ScanHistory, Phase3Results,
  CredentialedResults, NewScan and both shims still do.

---

## 6. Harness diff, pre → post

`compare.mjs pre-c post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-` exits 0:

- All 76 unchanged-page captures are identical in every category.
- pre-d vs post-b is also 76 / 76.
- Post determinism (post-a vs post-b) is 93 / 93.

Every changed category on the 17 Phase 1 captures is accounted for:

| Category                                         | Captures          | Why it changed                                                                                                                                       |
| ------------------------------------------------ | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| names, headings, roles, ariaStates, live         | 17, 17, 15, 9, 13 | §2: named checkboxes, labels and switches, `h1`/`h2`/`h3`, groups, the mobile scroll region, `aria-pressed`/`aria-invalid`, status and alert regions |
| tables                                           | 15                | Caption and scoped headers (the two error views have no table)                                                                                       |
| clickable                                        | 13                | Pointer-only host rows 4 → 0 on every capture with hosts                                                                                             |
| probes                                           | 2                 | Same outcomes; the host-selection probe now lands on "Select 10.20.0.11 for port scan"                                                               |
| contrast                                         | 17                | 0 failing pairs on every Phase 1 capture                                                                                                             |
| tabOrder                                         | 17                | The same stops, now carrying names; one scroll region added on the 390 px capture                                                                    |
| inline, classes, styles, rects, screenshot, text | 17                | The restyle and the new labels; the only inline styles left are the shell's quota bars, identical on every page                                      |
| requests, writes, url, runtime                   | —                 | **Unchanged**                                                                                                                                        |

One limit on the request comparison: in the two polling states,
`p1-asset-running` and `p1-audit-running`, the `repeatable` pattern matches the
load as well as the poll, because both request the same URL. Those two states
therefore do not count the load. The other load states do, and the unit tests
pin it at one request.

Screenshots were reviewed side by side for all 17 captures. No regression was
found.

---

## 7. Deferred, and found but not fixed

- **A mismatched scan id reloads for ever.** The page loads whenever the
  requested id differs from the id in context, and sets the context from the
  response. A response carrying another id would be requested again
  indefinitely. Real responses carry the requested id. Phase2Results has the
  same check.
- **An invalid excluded-port list shows no message while typing.** Its parse
  error and port count are computed and thrown away. The error appears only as
  "Exclude ports error: …" when "Run Port Scan" is pressed. The excluded-address
  field does show its message.
- **A scan loaded from the URL starts with no host selected.** The default
  selection is computed once at first render, before the load fills the host
  list. Pinned as found.
- **Some controls ignore `scans:execute`:** the mode buttons, the custom-ports
  field, the quick-select chips and both exclusion switches. Nothing is sent
  without the permission.
- **"Continue to Port Scan" appears only when the execution mode is neither
  interactive nor automatic.**
- **"← New Scan" leads to `/dashboard`.**
- **The automatic poll** waits 4 seconds before its first check, never gives
  up and swallows every error.
- **Carried from Batch 18:**
  - ScanContext creates new setters on every render, which is why Phase2Results
    loads twice;
  - `cc_executionMode` is not in `SS_KEYS`;
  - Phase 3 starts scans when it mounts;
  - Phase2Results truncates the custom port list.
- **Carried from Batch 15:** ExportPanel's CSV formula injection;
  `getScanPipeline` throws on an unknown pipeline mode.
- **Pointer census findings elsewhere,** unchanged: click-only tab labels on
  ComplianceWorkspace, and row-click tables whose rows also carry links on
  AssetRegistry, VulnerabilityBrowser and SecurityDashboard.
- **Carried design-system notes:** CcureTable still does not contain visually
  hidden content (contained at card level again); CcureAlert's danger icon is
  a cross.
- **Harness:**
  - no text entry, so validation that needs typing is covered only by unit
    tests;
  - no SSE or WebSocket replay, and no file-input driving;
  - the focus snapshot reads `aria-label` and visible text, not
    `aria-labelledby`, so it records the exclusion switch's name as empty
    although the switch is named by its heading;
  - `repeatable` hides the load count in the two polling states (§6).

---

## 8. Stop

Batch 19 ends here. Nothing from Batch 19 is committed, and no Batch 20 work has
started.

# Checkpoint 3C — Batch 24: Phase3Results on the design system

Phase3Results is the vulnerability audit pipeline page
(`/scan/vulnerability-audit`, `/scan/:scanId/phase3`). Once discovery has found
live hosts it runs the rest of the pipeline by itself — port scan, then
vulnerability audit, then report ready — shows each phase's results as they
arrive, and opens a risk report dialog at the end.

**This page starts scans on mount, and it follows a progress socket for each
phase.** The batch is presentation and accessibility only, and the rest is
pinned:

- **The logic is the code that was here.** `buildScanProgressUrl`,
  `waitForPhase`, `countActiveFindings`, `fmtSec` through `maskCredential`,
  `PHASE_MESSAGES`, and the component's state, redirect, automatic start,
  `runFullPipeline`, retry, cancel and restart handlers and its guard (375
  lines) are byte-identical to the legacy page. The derived state is identical
  apart from one added label constant. All 15 request, socket, stop, navigation,
  timer and console call sites occur in the same order.
- **The automatic start, unchanged** (§3.1): on mount, exactly once, with no
  button in between.
- **The writes, unchanged:** `POST /scan/asset-discovery`, `POST /auth/ticket`
  before each phase's socket, `POST /scan/vulnerability-audit`, and
  `POST /scans/{id}/stop` on Cancel.
- **The progress sockets, unchanged:** one WebSocket per phase at
  `{API base with http→ws}/scans/{id}/progress?ticket=…`, closed on that phase's
  `complete` or `failed` frame; a socket error fails the phase; 20 minutes
  without either fails it as timed out. There is no polling.
- **Masking, unchanged:** weak FTP credentials render as `user/********`, and
  the password never reaches the document.

**Baseline:** HEAD `09cdd9f` (Batch 23).

**Not touched:**

- NewScan, ComplianceWorkspace, CredentialedResults, ScanHistory, NetworkMap,
  AMTIntegration and every other page.
- `api/scans.js`, `api/axiosInstance.js`, `context/ScanContext.jsx`, `App.jsx`,
  PrivateRoute, `auth/permissions`, AppLayout, ScanStepper, CVELink, the legacy
  Modal shim, CcureModal and every other design-system primitive.
- `scan.css`, `global.css`, `dashboard.css` and the rest of the legacy CSS
  chain.
- The backend, `nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`,
  `package.json` and the lockfile.
- The harness's capabilities, apart from two per-state opt-ins (§0.3). No
  WebSocket support was added: `run.mjs` still blocks `ws://` and `wss://`, and
  the pipeline states script the socket inside the page.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `09cdd9f`                                                                                                                                                                                                                                                                                                                                                                                                     |
| Tests first, on the legacy page             | 70 tests: the 60 contract tests pass, the 10 batch 24 tests all fail, each for its intended reason, after one correction to a test helper (§0.2)                                                                                                                                                                                                                                                                                    |
| Pipeline replay, unchanged build            | The 14 `p3-` captures taken twice: **14 / 14** identical and ready; 0 refused writes, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors; every keyboard probe reached and passed; neither the fixture's weak password nor the ticket in either report                                                                                                                                                                      |
| Baseline, unchanged build                   | 154 captures ready, twice. Determinism **154 / 154**, sensitivity **22 / 22**                                                                                                                                                                                                                                                                                                                                                       |
| Same tests, migrated                        | **60 / 60** contract tests and **10 / 10** batch 24 tests on the first run; one contract assertion then narrowed to the band's case (§0.2)                                                                                                                                                                                                                                                                                          |
| Logic unchanged                             | The named logic blocks above are byte-identical legacy → migrated, compared block by block; the call-site sequence is identical                                                                                                                                                                                                                                                                                                     |
| Full frontend suite                         | 57 files, **2096** tests, all passing (2026 + 70). The first run had one failure in AMTIntegration's contract suite, not caused by this batch (§7); the rerun passed, and that file passed 47 / 47 in each of three runs on its own                                                                                                                                                                                                 |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                                                                                                                                 |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                                                                                                                                                                                   |
| Pre-commit formatting                       | Every Batch 24 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                                                                                                                          |
| Post determinism                            | post-a vs post-b **154 / 154** identical                                                                                                                                                                                                                                                                                                                                                                                            |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace, SecurityDashboard, Phase2Results, Phase1Results, AMTIntegration, NetworkMap, ScanHistory and CredentialedResults: **140 / 140** captures identical pre → post in every category, on both capture pairs                                                                                                                                                                    |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Phase3Results requests                      | Identical before and after in every `p3-` capture (0 deltas), in all four reports: two tickets, one of each dispatch and two reads in `p3-pipeline`; one ticket and one port-scan dispatch in `p3-pipeline-running` and `p3-pipeline-failed`; none of these in any seeded state. The only scan shapes are `GET /api/scans/{id}`, `POST /api/auth/ticket`, `POST /api/scan/asset-discovery` and `POST /api/scan/vulnerability-audit` |
| Secrets                                     | Neither the weak FTP password nor the ticket appears anywhere in any capture of the four reports — text, names, tab order or request log                                                                                                                                                                                                                                                                                            |
| CSP and security headers                    | Identical on the pre and post images across ten routes, `/scan/vulnerability-audit` included (70 header lines)                                                                                                                                                                                                                                                                                                                      |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                                                                                                                                                                                        |
| Writes, navigations, off-origin, CSP issues | 308 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every `p3-` capture ends on its own route in all four reports                                                                                                                                                                         |
| Screenshots                                 | All 14 Phase3Results captures reviewed side by side, pre and post. No regression                                                                                                                                                                                                                                                                                                                                                    |

### 0.1 The automatic start and the sockets, in tests and in the harness

**Unit tests.** The axios instance and `WebSocket` are replaced; the scan
context is the real provider, seeded through sessionStorage the way the
pipeline leaves it. The socket records its URL and its `close()` calls and
delivers the frames a test sends. With fake timers the contract tests pin:

- the automatic start — the port scan with the live hosts, intensity, scan id,
  pipeline mode and phases; the whole pipeline in order (dispatch, ticket,
  socket, read, per phase); frames for another phase and non-terminal frames
  ignored; an audit queue starting the audit directly; a route-level start
  phase and vulnerability profile; exactly one start under StrictMode and
  across re-renders; no request at all without `scans:execute`;
- failures — a refused dispatch (with no ticket requested), a refused ticket, a
  `failed` frame (closing its socket), a socket error, 20 minutes of silence, a
  record with no hosts, the API's `detail` before the error's message — and the
  indicator clearing 4 s later;
- retry from the failed phase, restart of the full pipeline, Cancel (abort,
  `POST /scans/{id}/stop`, cancelled even when the stop is refused), and
  unmounting;
- the results, the risk report's counts and texts, the masked credentials, and
  closing the dialog with its close button, Escape or a click outside it.

An `afterEach` in every test allows only the two dispatches, the ticket and the
stop as writes, only `/scans/{id}` as a read, and only the progress URL as a
socket.

**Harness.** The pipeline states need a Phase 3 route, two dispatches, a ticket
and a socket, and the harness blocks Phase 3 routes, refuses writes and blocks
sockets. Three pieces, all scoped to `p3-` states:

- **The route.** `guard.mjs` blocks the two Phase 3 routes on every state, so a
  capture can never start a scan by landing there. A state that declares
  `allowPhase3: true` lifts those two routes only; every other blocked route
  stays blocked, and only `p3-` states declare it.
- **Writes.** A state may declare `writes`, a map of `METHOD path` to a fixed
  answer (`router.mjs`). The three pipeline states declare exactly
  `POST /scan/asset-discovery` and `POST /scan/vulnerability-audit`, answered
  `{ "success": true }`; with Batch 23's opt-in they are also answered a
  placeholder ticket. Every other write on every state — `/scans/{id}/stop`
  included — is still refused. The seeded states (report, running, error,
  cancelled, unreachable, denied) declare none and start nothing.
- **The socket.** The existing `init` hook replaces `WebSocket` on the Phase 3
  routes only. Each scripted socket records its URL and whether it was closed,
  and 40 ms after opening delivers the frame at its own index: two `complete`
  frames for `p3-pipeline`, none for `p3-pipeline-running` (it stays open), a
  phase 2 `failed` frame for `p3-pipeline-failed`. Readiness asserts the number
  of sockets and whether each was closed, and waits for the page's 4-second
  indicator timer, so both builds are captured in the same settled state.

Request **order** is not observable in the harness, whose request log is
sorted; the unit tests pin it.

### 0.2 Corrections

Before the baseline, to the tests only:

1. **The risk report's CVE text included CVELink's hidden hint** ("Opens the
   NVD record in a new tab", a `hidden` element), so the contract test failed on
   the legacy page. A `visibleText` helper drops `[hidden]` nodes.

After migration, none to the page:

2. **One contract assertion pinned the raw lowercase band** of the fixture's
   `high` CVE. The risk report now renders the band with CcureSeverityBadge,
   whose label is "High". The assertion accepts either case for the band's first
   letter and still pins the band and everything around it; the batch 24 block
   pins a `.cc-sev--high` badge reading "High" (§4.4).
3. **Prettier** reformatted the page and the test file.

### 0.3 Harness changes

- **14 Phase3Results captures** in 12 states:
  - `p3-report` (both themes, `/scan/{id}/phase3`): all three phases' results,
    with two keyboard probes; `p3-report-modal` and `p3-modal-mobile` (390 px):
    the risk report open; `p3-report-mobile` (390 px);
  - `p3-running` (both themes), `p3-error`, `p3-cancelled`, `p3-unreachable`
    and `p3-denied` (a persona without `scans:execute`): seeded, starting
    nothing;
  - `p3-pipeline`, `p3-pipeline-running` and `p3-pipeline-failed`: the page
    starts the pipeline itself against the declared writes and the scripted
    socket (§0.1).
- **Probes.** On `p3-report`: the discovery filter (Enter on "All (4)" → four
  rows) and the risk report (Enter on View Risk Report → the dialog; Escape →
  closed). Cancel Scan on `p3-running` and Retry on `p3-error` are reached by
  Tab only: Enter would post the stop or start the audit again.
- **Fixtures are synthetic**: no host, credential or output comes from a real
  system. The weak FTP credential's password is the low-entropy placeholder
  `notreal`, and the ticket is `harness-ticket`.
- **`REGRESSION_PREFIXES`** now includes `cr-`, so Batch 23's captures are in
  the regression gate.
- The catalogue is now 113 states, 154 captures.

---

## 1. Files changed

| File                                              | Change                                                                                                                                                                            | LOC                         |
| ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| `src/pages/scan/Phase3Results.jsx`                | Design-system markup: result sections with headings, labelled filter groups, CcureTable, severity and finding badges, alerts, a status region with a progress bar, and CcureModal | 2531 → 1711 (+1003 / −1823) |
| `src/styles/phase3-results.css`                   | New, page-owned: 237 `--ccure-*` references, 0 colour literals, 0 other custom properties                                                                                         | new, 717                    |
| `src/__tests__/pages/scan/Phase3Results.test.jsx` | New: 60 contract + 10 batch 24                                                                                                                                                    | new, 1682                   |
| `scripts/ux4g-harness/lib/fixtures.mjs`           | Synthetic pipeline results and sessions, the declared writes and the scripted socket                                                                                              | +306                        |
| `scripts/ux4g-harness/lib/states.mjs`             | 12 `p3-` states; `cr-` in the regression prefixes                                                                                                                                 | +208 / −3                   |
| `scripts/ux4g-harness/lib/router.mjs`             | Per-state declared writes                                                                                                                                                         | +11                         |
| `scripts/ux4g-harness/lib/guard.mjs`              | The per-state Phase 3 route opt-in                                                                                                                                                | +16 / −2                    |
| `scripts/ux4g-harness/run.mjs`                    | Passes that opt-in to the guard                                                                                                                                                   | +3 / −2                     |
| `docs/ux4g/03c-batch24-phase3-results.md`         | This document                                                                                                                                                                     | new                         |

| Measure                                                                            | Before                 | After                |
| ---------------------------------------------------------------------------------- | ---------------------- | -------------------- |
| Inline `style` attributes                                                          | 150                    | **0**                |
| Colour literals in the page                                                        | 87 (61 hex, 26 `rgba`) | **0**                |
| Legacy `var(--…)` references in the page                                           | 56                     | **0**                |
| Legacy class references (`btn`, `page-*`, `summary-*`, `pipeline-*`, `section-*`…) | 111                    | **0**                |
| Hand-built tables                                                                  | 4                      | **0** (4 CcureTable) |
| Hover handlers painting a button                                                   | 4                      | **0**                |
| Legacy Modal shim                                                                  | 1                      | **0** (CcureModal)   |
| Level-one headings                                                                 | 0                      | **1** in each state  |
| Rows styled as clickable with no action (report)                                   | 7                      | **0**                |
| Failing text contrast pairs (report, light / dark)                                 | 17 / 5                 | **0 / 0**            |
| Failing text contrast pairs (risk report open)                                     | 54                     | **0**                |
| Tests                                                                              | 0                      | 70                   |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change  |
| ----- | -------------- | ------------- | ------- |
| CSS   | 399,056        | 411,294       | +12,238 |
| JS    | 1,602,186      | 1,591,873     | −10,313 |

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures; the
unit tests cover the same points and the parts the harness cannot reach.

- **Headings.** The page title was an `h2` with nothing above it; it is the
  `h1` in each state. The three result sections and the running phase's message
  were uppercase `h3`s; they are `h2`s. The risk report's five sections were
  styled text; they are `h3`s under the dialog's `h2` title.
- **Tables.** The report's three tables and the risk report's hosts table had
  no caption and 22 unscoped header cells. After: every table is captioned
  ("Discovered hosts", "Port scan results", "Vulnerability audit results",
  "Affected hosts"), and all 32 header cells are scoped — a column header for
  each column and the IP address as each row's header.
- **The filters are named groups.** Each Active / All pair is a labelled group
  stating its selection with `aria-pressed`.
- **Outcomes are announced.** A pipeline failure, a missing permission and an
  unreachable host are alerts (0 → 1 on each such capture). A cancelled scan
  and the running phase are status regions, the running one with a progress
  bar named for the phase.
- **The risk report** was already a modal dialog named by its title; it is now
  also described by its scan number and target.
- **Keyboard.** Tab stops are unchanged in every capture: 31 on the report, 5
  with the risk report open, 36 and 6 at 390 px. At 390 px the tables' scroll
  containers, already tab stops, are regions named by their captions. All four
  probes reach the same controls in both builds with a visible ring. The two
  that press Enter pass in both builds: the filter shows four rows, and the
  risk report opens and Escape closes it.
- **Contrast.** Failing text pairs, before → after:

  | Capture                    | Light  | Dark  |
  | -------------------------- | ------ | ----- |
  | Report                     | 17 → 0 | 5 → 0 |
  | Risk report open           | 54 → 0 | —     |
  | At 390 px                  | 17 → 0 | —     |
  | Risk report open at 390 px | 54 → 0 | —     |
  | Running                    | 5 → 0  | 1 → 0 |
  | Error                      | 6 → 0  | —     |
  | Cancelled                  | 5 → 0  | —     |
  | Unreachable                | 2 → 0  | —     |
  | Without `scans:execute`    | 4 → 0  | —     |
  | Live pipeline, complete    | 17 → 0 | —     |
  | Live pipeline, running     | 3 → 0  | —     |
  | Live pipeline, failed      | 4 → 0  | —     |

  Legacy defects now gone: primary buttons (2.77); the green, orange and red
  summary counts (2.15 to 3.76); the section check marks (2.06); risk and
  severity words painted in their band's colour (2.28 to 3.27); the audit
  table's CVE counts (2.56, 2.8); the risk report's stat and severity figures
  and its probe sub-headings, "Weak credentials accepted" included (2.02 to
  2.68); the FTP banner (4.48); Cancel Scan (4.17); Restart Full Pipeline
  (4.35); and, in the dark theme, View Risk Report (2.77) and the audit table's
  risk, count and active figures (3.07 to 4.47).

- **Mobile.** No horizontal overflow at 390 px, before or after. Tables scroll
  inside their regions, and View Risk Report spans the width.
- **No sensitive value in accessibility text.** Every `aria-label` and caption
  is fixed text; the dialog's description is its visible subtitle.
- **Measurement note.** The harness names headings and buttons from their text,
  which includes glyphs hidden from assistive technology ("h2:✓ 1. Discovery
  Results", "📊 View Risk Report →"). The unit tests compute the accessible
  names, "1. Discovery Results" and "View Risk Report".

---

## 3. Security validation

### 3.1 Requests, and the automatic start

**The automatic start is kept and documented, not changed.** On mount the page
starts the pipeline once, with no confirmation step, when all of these hold:

- discovery found at least one live host;
- the pipeline is not already report-ready or complete;
- no audit results are held;
- and, unless the route names a start phase, the context is not mid-scan, and
  it holds no port-scan results unless an audit queue is held too.

It starts at the route's start phase when one is named, else at the
vulnerability audit when an audit queue is held, else at the port scan. A
route-level start phase overrides a stale running state. Phase 3's automatic
start stays on the global deferred list.

| Step | Request                                                                                                      | Pinned                                                                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `POST /scan/asset-discovery` `{hosts, intensity, scan_id, pipeline_mode, phases: [1, 2]}`                    | live hosts only; skipped when starting at the audit                                                                                                 |
| 2    | `POST /auth/ticket` (no body), then the phase 2 socket                                                       | a socket only after the ticket                                                                                                                      |
| 3    | `GET /scans/{id}`                                                                                            | after the phase 2 `complete` frame                                                                                                                  |
| 4    | `POST /scan/vulnerability-audit` `{hosts, scan_id, pipeline_mode, vulnerability_profile, phases: [1, 2, 3]}` | the port scan's hosts (this run's, or the stored ones when starting at the audit), else the audit queue; profile from the route, else `recommended` |
| 5    | `POST /auth/ticket`, then the phase 3 socket                                                                 | as step 2                                                                                                                                           |
| 6    | `GET /scans/{id}`                                                                                            | after the phase 3 `complete` frame                                                                                                                  |
| —    | `POST /scans/{id}/stop`                                                                                      | on Cancel only                                                                                                                                      |

- **Without `scans:execute` nothing is requested**; the page reports an
  authorization failure.
- **In the harness**, the same shapes in both builds (§6), and the counts per
  capture: two tickets, one of each dispatch and two reads in `p3-pipeline`;
  one ticket and one port-scan dispatch in `p3-pipeline-running` and
  `p3-pipeline-failed`; nothing but the shell's own reads in every seeded
  state. Every request carries the `org_id` query parameter the axios instance
  adds.

### 3.2 Masking

- **A weak FTP credential is masked:** it renders as `user/********`, with
  `user` when the record names none. The password is in neither the document nor an attribute
  (the contract test searches the whole serialized document for it).
- **In the harness**, neither the weak password nor the ticket appears in any
  capture of the four reports — text, names, tab order or request log.
- **Scan-supplied text renders as text**: banners, server headers, issues,
  paths, products and CVE descriptions. The page uses no
  `dangerouslySetInnerHTML`, and no ticket, credential or raw payload is placed
  in an attribute or a title. The three `title` tooltips it had
  (authentication, device classification and active findings) carry the same
  text as before.

### 3.3 The progress sockets

| Requirement                             | Evidence                                                                                                                                |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| 1. The intended socket                  | One socket per phase at `/api/scans/{id}/progress?ticket=…`, ticket encoded; the `afterEach` rejects any other URL                      |
| 2. Ticket acquisition unchanged         | One `POST /auth/ticket` with no body before each phase's socket; in the harness, one per phase reached                                  |
| 3. No duplicate sockets                 | One start under StrictMode and re-renders; in the harness, exactly two sockets in `p3-pipeline` and one in each other pipeline state    |
| 4. Terminal frames                      | `complete` and `failed` for the socket's own phase close it; frames for another phase and non-terminal frames change nothing            |
| 5. Errors and timeout                   | A socket error fails the phase ("Phase N WebSocket failed"); 20 minutes of silence fails it as timed out                                |
| 6. Cancel                               | Aborting closes the open socket and shows the scan cancelled; `POST /scans/{id}/stop` is sent, and a refused stop still reads cancelled |
| 7. Unmount                              | Unchanged, and pinned as found (§7): unmounting neither aborts the pipeline nor closes the socket                                       |
| 8. No polling                           | The page never reads the record except after a phase's `complete` frame                                                                 |
| 9. No write from an event               | The `afterEach` allows only the dispatches, tickets and stop; 0 refused writes in the four reports                                      |
| 10. Parsing and state updates unchanged | `waitForPhase` and `runFullPipeline` are in the byte-identical blocks                                                                   |

### 3.4 Permissions and navigation

- **The page still checks `scans:execute`** before it requests anything, and
  `App.jsx` still mounts both routes behind the base sign-in check only
  (asserted from the source).
- **Navigation is unchanged:** with no discovered hosts the page replaces itself
  with `/scan`; Back and New Scan go to `/scan`; CVE links open NVD in a new tab
  with `rel="noopener noreferrer"`.
- **Nothing new executes or leaves the site.** No new dependency.

---

## 4. Intentional changes

1. **Headings.** One `h1`, "Vulnerability Audit", which was an `h2`. Each result
   section is an `h2` ("1. Discovery Results", "2. Port Scan Results", "3.
   Vulnerability Results") and the running phase's message is an `h2`; all four
   were `h3`. In the risk report, "Full Pipeline Complete" stays an `h3`, and
   its five sections, which were styled text, are `h3`.
2. **The result filters are labelled groups of toggle buttons** ("Show
   discovered hosts", "Show port-scanned hosts", "Show audited hosts") stating
   the selection with `aria-pressed`.
3. **Tables are CcureTable**: a caption, `scope="col"` headers and the IP
   address as each row's header, with headers no longer uppercased. An empty
   table — discovery with no live host — says "No rows to display." where it
   showed only its header row. The legacy rows' pointer cursor, which led
   nowhere, is gone.
4. **Risk and severity are CcureSeverityBadge**, in the audit table, the affected
   hosts table, each host's header and each CVE. The label is the band's own:
   the API's lowercase `high` reads "High", a band the badge does not know reads
   "Unscored" where the raw text was shown, and a host with findings but no risk
   level reads "Unscored Risk" where it read " Risk". Missing values still fall
   back to "Info" where they did.
5. **Findings are CcureBadge**: authentication, device category, active
   findings, each misconfiguration and each host's active or inactive state.
   Device categories lose their individual colours; the icon and label carry
   the category.
6. **The running phase is a status region** with a CcureProgress bar named for
   the phase ("Running Port Scan…"), indeterminate because nothing is measured.
7. **Outcomes are CcureAlert**: a pipeline failure (danger) and an unreachable
   host (warning) are announced; a cancelled scan is a status.
8. **The risk report is CcureModal**: named by its title, described by "Scan
   No. … - Target: …", focus trapped, closed by its "Close" button or Escape.
   CcureModal's own outside click never fires (carried, §7), so the page listens
   for a click on this dialog's overlay, as ScanHistory does, and a click
   outside still closes it.
9. **Structure.** The report's stat cards and timeline are description lists;
   the severity distribution, misconfiguration findings, CVEs and summaries are
   lists; each host is an `article`.
10. **Buttons are CcureButton.** The View Risk Report button's hover handlers are
    gone; hover and focus are the design system's.
11. **Decorative glyphs are hidden** from assistive technology and stay on
    screen.
12. **Colours are tokens in both themes**, and the layout adapts below 640 px,
    where View Risk Report spans the width.

---

## 5. Retirement

- **The page no longer uses anything from the legacy stylesheets** (111
  references to `btn`, `page-*`, `summary-*`, `pipeline-*`, `section-*`,
  `filter-tab`, `results-table`, `status-dot`, `progress-*` and similar). Those
  stylesheets are untouched and still used elsewhere.
- **The legacy Modal shim is no longer imported here**; OrganizationManagement
  and ComplianceWorkspace still use it.
- **`SEV_COLOR`, `getSevColor` and the colours in `DEVICE_CAT_META` are gone**,
  with every hand-built table and inline style.
- `phase3-results.css` is page-owned and imported only by Phase3Results.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-,p1-,amt-,nm-,sh-,cr-`
exits 0:

- All 140 unchanged-page captures are identical in every category, Batch 23's
  15 CredentialedResults captures included.
- pre-b vs post-b is also 140 / 140.
- Post determinism (post-a vs post-b) is 154 / 154.
- 140 of 154 captures are identical overall; the 14 Phase3Results captures
  changed.

Every changed category on those 14 captures is accounted for:

| Category                                                         | Captures | Why it changed                                                                                                                                          |
| ---------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| headings, text                                                   | 14, 14   | §4: the `h1`, the section `h2`s and the risk report's `h3`s; captions and visually hidden text                                                          |
| roles                                                            | 14       | The filter groups; the alerts; the running status and its progress bar; scroll regions at 390 px                                                        |
| ariaStates                                                       | 14       | `aria-pressed` on the filter toggles                                                                                                                    |
| live                                                             | 8        | An alert on the error, denied, unreachable and failed-pipeline captures; a status on the running (both themes), running-pipeline and cancelled captures |
| tables                                                           | 14       | Captions, scoped column headers and row headers; the unreachable view's empty-state row                                                                 |
| tabOrder                                                         | 2        | At 390 px the tables' scroll containers, already tab stops, are regions named by their captions; the counts are unchanged                               |
| clickable                                                        | 13       | Legacy result rows styled as clickable with nothing to do; none after                                                                                   |
| contrast                                                         | 14       | 0 failing pairs on every Phase3Results capture                                                                                                          |
| inline, classes, styles, rects, screenshot                       | 14       | The restyle. The only inline styles left are the shell's two quota bars                                                                                 |
| requests, writes, url, runtime, probes, dialogs, names, overflow | —        | **Unchanged**                                                                                                                                           |

Screenshots were reviewed side by side for all 14 captures: the report in both
themes and at 390 px, the risk report open on desktop and at 390 px, running
(both themes), error, cancelled, unreachable, denied, and the three live
pipeline states.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — all kept exactly, and pinned where marked:

- **Unmounting does not stop the pipeline.** Neither the request nor the socket
  is aborted, and a frame arriving after the page has gone still reads the
  record. (pinned)
- **`waitForPhase`'s 20-minute timer is never cleared** once its phase settles;
  it fires later against a closed socket and a settled promise.
- **Only `complete` and `failed` settle a phase.** Any other status — a scan
  stopped from elsewhere, say — leaves the page showing the phase running until
  the 20-minute timeout.
- **A frame that is not JSON throws** inside the socket's message handler.
- **With both an audit queue and port-scan results**, the audit is sent the
  port-scan results, not the queue. (pinned)
- **A refused stop logs the raw error object to the browser console.** An axios
  error carries its request configuration, Authorization header included. The
  logged message itself is fixed text. (pinned)
- **An authorization failure reads "Pipeline failed at Vulnerability Audit"**
  and offers "Retry from Vulnerability Audit", whichever phase was next.
- **The 4-second indicator timers are not cleared on unmount.**
- **`setExpanded` is written and never read.**
- **The page checks only `scans:execute`**, and its routes need only sign-in.
- **Harness:** the scripted socket's frames are fixed, so frame timing, a socket
  error and the timeout are covered by the unit tests only; a real handshake
  and ticket issuance are not exercised; request order is pinned only by the
  unit tests; Cancel's stop is never sent in a capture; the shell's
  `/api/notifications/stream` is unstubbed, as before.

**Found elsewhere, not changed:**

- **AMTIntegration's contract test "a rejected upload shows the API's detail or
  a default" failed once** in the first full-suite run (two statistics reads
  where it expects one), then passed in the rerun and in three runs of that file
  on its own. Nothing it imports changed in this batch. The likely cause, not
  reproduced: an earlier test's successful import schedules the page's
  1.5-second statistics reload on real timers, the timer is not cleared on
  unmount, and under load it fires inside the later test. It belongs with
  AMTIntegration's deferred fixed reconciliation delay.

**Carried:**

- Global: CcureTable's hidden caption; the Toast and Modal shims; CVELink and
  CcureTabs overlapping `dashboard.css` selectors; ScanContext's duplicate GET;
  the `cc_executionMode` reset; polling timeout and error handling; Phase 3's
  automatic start; ExportPanel's CSV formula injection; the truncated custom
  port list.
- AMT: the import confirmation; permission hardening; the export failure UI;
  object URL clean-up; the fixed reconciliation delay; filter debounce and trim;
  the failed-statistics state; Department showing the company name; the fixed
  page size; asset-link navigation.
- NetworkMap: canvas keyboard navigation; the canvas's accessible name, focus
  and instructions; a keyboard alternative for node inspection; the cross-page
  review of frontend authorisation.
- ScanHistory: Archive and Delete confirmation; the confirmation's initial
  focus; Stop shown without `scans:execute`; live sync continuing after terminal
  states; the silent failed poll; the 200-scan browser cap; queued and pending
  scans hidden from Active Scans.
- CcureModal: a click outside never closes the dialog; shared by several pages
  and left for a shared-component batch.
- CredentialedResults: masking covers only flagged environment variables;
  masking after the first `=` past a `:`; the refused ticket's raw error
  logging; a non-JSON frame throwing; a `failed` frame leaving the socket open;
  the extra read after `complete`; polling without a limit; the ignored route
  id and its redirect; an unreachable report shown despite its data; no
  frontend permission check; the exposure explanation as a tooltip only and the
  worst severity as colour only; the harness's expand-all opening the account
  menu, and no real handshake.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was
reached:

- the automatic start, its conditions and its single execution are unchanged,
  documented and pinned; no manual step was introduced;
- the two dispatches, both tickets, both reads and the stop — method, path,
  payload, order and timing — are unchanged and pinned, and nothing else is
  written;
- one socket per phase, its URL, its terminal frames, its error and timeout
  handling and the absence of polling are unchanged and pinned;
- masking is unchanged and pinned; no password, ticket or secret reaches the
  document, an attribute, the console or a harness report;
- permissions and navigation are unchanged;
- no write, no unexpected navigation, no off-origin request, no CSP issue, no
  exception and no console error in any capture;
- determinism, sensitivity and the regression gate over every previously
  migrated page passed;
- security headers and the air-gap host set are identical;
- no shared component, design-system primitive or global stylesheet was
  modified.

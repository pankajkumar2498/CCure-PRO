# Checkpoint 3C — Batch 22: ScanHistory on the design system

ScanHistory is two pages from one component: **Scan History** (`/history`,
settled scans) and **Active Scans** (`/monitor`, running scans). It lists scans
from `GET /scans`, keeps them current from a live stream, and offers View,
Re-run, Archive, Delete and — on Active Scans — Stop.

**This page writes, and it streams.** The batch is presentation and
accessibility only, and the rest is pinned:

- **The logic is the code that was here.** The 431 lines from the component's
  opening to its render section are byte-identical to the legacy page, and so
  are all 21 module-level declarations the two share — 15 helpers and 6
  constants (§3).
- **Four writes, unchanged:** Archive `POST /scans/{id}/archive` and Delete
  `DELETE /scans/{id}` on the first press with no confirmation, exactly as
  before; Re-run `POST /scan/host-discovery` and Stop `POST /scans/{id}/stop`
  after a confirmation.
- **The live stream, unchanged:** `/scans/events` with the list's filters; a
  stream that ends or fails is retried once after 2.5 s; the second failure
  switches to polling `GET /scans` every 5 s until the page unmounts.

**Baseline:** HEAD `7e920d8` (Batch 21).

**Not touched:**

- CredentialedResults, Phase3Results, NewScan, ComplianceWorkspace, NetworkMap,
  AMTIntegration and every other page.
- `api/scans.js`, ScanContext, PreferencesContext, `auth/permissions`,
  `App.jsx`, PrivateRoute, RiskBadge, CVELink, the Toast shim (now used by this
  page, unchanged), CcureModal and every other design-system primitive.
- `scan.css`, `global.css`, `dashboard.css` and the rest of the legacy CSS
  chain.
- The backend, `nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`,
  `package.json` and the lockfile.
- The harness's capabilities, apart from two stub kinds (§0.3). No WebSocket
  support; `BLOCKED_ROUTES` is unchanged.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                      |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `7e920d8`                                                                                                                                                                                                                             |
| Tests first, on the legacy page             | 69 tests: the 54 contract tests pass, the 15 batch 22 tests all fail, each for its intended reason. Three corrections to the tests themselves before the baseline (§0.2)                                                                                    |
| Live-stream replay, unchanged build         | The 14 `sh-` captures taken twice: identical and ready after one readiness correction (§0.2); 0 writes, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors; every keyboard probe reached and passed                                                 |
| Baseline, unchanged build                   | 125 captures ready, twice. Determinism **125 / 125**, sensitivity **22 / 22**                                                                                                                                                                               |
| Same tests, migrated                        | **69 / 69** after two corrections to the page (§0.2)                                                                                                                                                                                                        |
| Logic unchanged                             | The component's logic block (431 lines) and the 21 shared module-level declarations are byte-identical legacy → migrated. What differs is the render section, the two dialogs and the running-scan card                                                     |
| Full frontend suite                         | 55 files, **1919** tests, all passing (1850 + 69)                                                                                                                                                                                                           |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                         |
| Build                                       | `vite build` succeeds                                                                                                                                                                                                                                       |
| Pre-commit formatting                       | Every Batch 22 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                  |
| Post determinism                            | post-a vs post-b **125 / 125** identical                                                                                                                                                                                                                    |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace, SecurityDashboard, Phase2Results, Phase1Results, AMTIntegration and NetworkMap: **111 / 111** captures identical pre → post in every category, on both capture pairs                              |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                 |
| ScanHistory requests                        | Identical before and after in every `sh-` capture, probes included (0 deltas), and so are the stream, list and detail request counts per capture. Only GETs, apart from the session refresh every page makes                                                |
| CSP and security headers                    | Identical on the pre and post images across eight routes, `/history` and `/monitor` included (56 header lines)                                                                                                                                              |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                |
| Writes, navigations, off-origin, CSP issues | 250 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every `sh-` capture ends on its own route in all four reports |
| Screenshots                                 | All 14 ScanHistory captures reviewed side by side, pre and post. One layout defect at 390 px was found and fixed, and every gate above was run again on that build (§0.2, item 7)                                                                           |

### 0.1 The live stream in tests and in the harness

**Unit tests.** `fetch` is replaced by a stream the test drives: it can send an
event, end, fail, and it rejects its pending read when the page aborts it. The
contract tests step through the lifecycle with fake timers: exactly one stream
on mount with the list's filters, token and credentials; `connected`, `scans`
and `heartbeat` handling; no polling while the stream is open (60 s); one retry
2.5 s after an end; polling every 5 s after the second failure, with the stream
never reopened; a refused stream counted as a failure; the owner filter and the
debounced search restarting the stream and aborting the old one; and unmounting
aborting an open stream, cancelling a pending retry and stopping polling.

**Harness.** The router gained two stub kinds, and nothing else:

- `__eventStream`: a finite `text/event-stream` body, answered in full. The
  ScanHistory replay is `connected`, a `scans` snapshot and a `heartbeat`. The
  page treats the end of the response as a failure, reconnects once, receives
  the same replay, then falls back to polling — so every capture settles on
  "Live sync polling", deterministically, while still exercising the stream's
  request and event parsing.
- `__pending`: a request left unanswered for the whole capture, so a page can
  be measured while it is still loading.

`run.mjs` fulfils the first with its content type and leaves the second paused.
The list and stream requests repeat for as long as a capture runs, so the
`sh-` states declare them `repeatable`, as the Phase 1 and 2 running states do.

### 0.2 Corrections

Three corrections to the tests before the baseline:

1. **A helper used a role pattern Testing Library does not support** to find a
   row's first cell; it uses a selector now.
2. **A dialog helper was declared inside one `describe` block** and used in
   another; it moved to the top level.
3. **Two batch 22 tests failed on the legacy page for the wrong reason.** The
   column-header test compared text content, which includes the sort glyphs;
   it compares accessible names. The monitor's progress-bar test matched two
   cards; it takes the first.

One correction to the harness states before the baseline:

4. **Three states did not settle on the legacy build** (four captures: three
   never became ready and the details dialog's wait timed out). `innerText`
   follows `text-transform`, and the legacy page uppercases the labels they
   waited for. The text checks are case-insensitive; the retrial was ready and
   deterministic.

Three corrections to the page after migration:

5. **The confirmation must focus its confirm button on open**, as the legacy
   dialog did. CcureModal's focus trap moved focus later, so the dialog now
   focuses the button as it mounts.
6. **A click outside a dialog did not close it.** CcureModal's overlay handler
   reads the event's `currentTarget` after dispatch, when React has already
   cleared it, so it never fires. Both dialogs turn the primitive's handling
   off and the page listens for a click on their own overlay (§7).
7. **At 390 px the table's rows were about 1.6 times the legacy height.** The
   table fills its scroll region, so the wrapping actions cell shrank to one
   button and stacked all four. Below 640 px the actions stay on one line and
   the region scrolls. Found in the screenshot review; the format, lint, unit,
   build and harness gates were all run again afterwards, and §0 reports that
   final run.

### 0.3 Harness changes

- **14 ScanHistory captures** in 12 states:
  - `sh-history` (both themes), `/history`, with eight keyboard probes;
  - `sh-completed`, `/history?status=complete`;
  - `sh-monitor` (both themes), `/monitor`, with one probe;
  - `sh-mobile` (390 px), `sh-loading` (both requests pending), `sh-empty`,
    `sh-error` (500);
  - `sh-readonly`: a persona with `scans:read` and none of the scan write
    permissions;
  - `sh-denied`: a persona without `scans:read`, which the routes still admit
    and which the backend refuses with its 403 detail;
  - `sh-detail`, `sh-rerun-confirm` and `sh-stop-confirm`: the details dialog
    and both confirmations, opened and never confirmed.
- **Probes.**
  - Re-run, Archive, Delete (on `sh-history`) and Stop (on `sh-monitor`) are
    **Tab only**: Archive and Delete send a write on Enter, and the others open
    a confirmation.
  - Next page (Enter → "Page 2 of 2"), the Target sort (Enter →
    `aria-sort="ascending"`), the Failed filter (Enter → only failed rows),
    My scans (Enter → `GET /api/scans` with `created_by=me`) and Sync now
    (Enter → `GET /api/scans`).
  - On both confirmations: Tab to Cancel inside the dialog, then Escape → the
    dialog is gone.
- **No real write can happen.** No state or probe confirms a dialog or presses
  Archive or Delete, and the router refuses every write regardless: 0 refused
  writes in all four reports shows none was even attempted.
- **Fixtures**: 16 scans — two running, the rest in every settled status the
  page labels — one scan's details with discovery results and a CVE, a persona with
  `scans:archive` and `scans:recycle`, and the stream replay (§0.1).
- **`run.mjs`**: a stub's content type is honoured, and a pending stub leaves
  its request paused. No other capability changed.
- **`REGRESSION_PREFIXES`** now includes `nm-`, so Batch 21's captures are in
  the regression gate.
- The catalogue is now 89 states, 125 captures.

---

## 1. Files changed

| File                                       | Change                                                                                                                                                   | LOC         |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `src/pages/ScanHistory.jsx`                | Design-system markup: CcureTable and CcurePagination, CcureModal dialogs, CcureCard running scans; the private toast, status and progress copies removed | 1718 → 1501 |
| `src/styles/scan-history.css`              | New, page-owned: 147 `--ccure-*` references, 0 colour literals, 0 other custom properties                                                                | new, 510    |
| `src/__tests__/pages/ScanHistory.test.jsx` | New: 54 contract + 15 batch 22                                                                                                                           | new, 1470   |
| `scripts/ux4g-harness/lib/fixtures.mjs`    | ScanHistory fixtures, the stream replay builder and a persona (§0.3)                                                                                     | +202        |
| `scripts/ux4g-harness/lib/states.mjs`      | 12 `sh-` states; `nm-` in the regression prefixes                                                                                                        | +223 / −3   |
| `scripts/ux4g-harness/lib/router.mjs`      | The `__eventStream` and `__pending` stub kinds                                                                                                           | +14         |
| `scripts/ux4g-harness/run.mjs`             | Honour a stub's content type; leave a pending request paused                                                                                             | +14 / −2    |
| `docs/ux4g/03c-batch22-scan-history.md`    | This document                                                                                                                                            | new         |

| Measure                                                                  | Before                 | After              |
| ------------------------------------------------------------------------ | ---------------------- | ------------------ |
| Inline `style` attributes                                                | 43                     | **0**              |
| Colour literals in the page                                              | 24 (10 hex, 14 `rgba`) | **0**              |
| Legacy `var(--…)` references in the page                                 | 21                     | **0**              |
| `scan.css` class references                                              | 85                     | **0**              |
| Distinct class names                                                     | 115                    | 57                 |
| Private copies of shared code (toast system, status badge, progress bar) | 3                      | **0**              |
| Hand-built dialogs                                                       | 2                      | **0** (CcureModal) |
| Level-one headings                                                       | 0                      | **1**              |
| Tables with a caption and scoped headers                                 | 0                      | **1** (CcureTable) |
| Failing text contrast pairs (Scan History, light / dark)                 | 19 / 4                 | **0 / 0**          |
| Tests                                                                    | 0                      | 69                 |

The page is 217 lines shorter: the inline status palette, the status badge,
the progress bar and the toast system are design-system
components or the shared shim now, and the filter group, the overlay-click
hook and the table's column definitions are new.

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 377,403        | 385,554       | +8,151 |
| JS    | 1,613,404      | 1,607,520     | −5,884 |

The CSS grows by the page's new stylesheet; `scan.css`, which still serves
other pages, is unchanged.

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures; the
unit tests cover the same points and the parts the harness cannot reach.

- **Headings.** The page title was an `h2` with nothing above it; it is the
  page's `h1` in both modes. Each running scan's card title is an `h2`, the
  details dialog's Summary and Discovery Results are `h3` (they were `h4`),
  and each dialog's title is its heading.
- **The table.** No caption, nine unscoped headers and `aria-sort` on the sort
  button. After: the caption "Scan history — N scans", `scope="col"` on every
  column header, the scan number as each row's header (19 scoped headers on a
  ten-row page), and `aria-sort` on the header cell.
- **Controls are named for what they act on.** Row actions were ten sets of
  "View", "Re-run", "Archive" and "Delete"; they are "Re-run scan 2114" and so
  on, tooltips unchanged. Stop and View on a running scan's card name the
  scan. The details dialog's close button was a bare ✕; it is "Close dialog".
- **Filters state their selection.** Each filter set is a labelled group
  (Status, Owner, Time range) of toggle buttons with `aria-pressed`; the
  selection was shown only visually.
- **Dialogs.** The details dialog had no dialog role, no name and no focus
  management — Tab went on to the page behind it (4 tab stops, all behind).
  All three dialogs are now modal, named by their title, the confirmations
  described by their question, with focus held inside (3 tab stops each) and
  restored on close.
- **Status and progress are announced.** The live sync state is a status
  region; loading is CcureLoader's status; a failed load is an alert (0 → 1 on
  the error and denied captures); notifications arrive in the Toast shim's
  live regions. Each scan's progress is a named `progressbar` (10 on a page of
  history, 2 on Active Scans), where it was a `<div>` with a label and no role.
- **Contrast.** Failing text pairs, before → after:

  | Capture              | Light  | Dark   |
  | -------------------- | ------ | ------ |
  | Scan History         | 19 → 0 | 4 → 0  |
  | Completed filter     | 16 → 0 | —      |
  | Active Scans         | 5 → 0  | 24 → 0 |
  | At 390 px            | 19 → 0 | —      |
  | Loading              | 0 → 0  | —      |
  | Empty                | 1 → 0  | —      |
  | Failed load          | 1 → 0  | —      |
  | Read-only persona    | 19 → 0 | —      |
  | Without `scans:read` | 1 → 0  | —      |
  | Details dialog       | 22 → 0 | —      |
  | Re-run confirmation  | 20 → 0 | —      |
  | Stop confirmation    | 5 → 0  | —      |

  Legacy defects now gone: "Completed" at 2.09, "Host Unreachable" and
  "Running" at 1.99, "Failed" and "Cancelled" at 3.30 (3.57 in dark), the
  active-host counts at 2.28, the running cards' counts at 2.18, the failed-load
  text at 4.17, the primary buttons ("Start your first scan", "Re-run Scan",
  "Open full results & exports") at 2.77, and "1 verified" at 2.68. In the dark
  theme the legacy Active Scans cards were a light surface carrying light text,
  measured down to 1.10.

- **Keyboard.** Tab stops are unchanged in number on every capture without a
  dialog, except at 390 px, where the table's scroll region is a tab stop so
  the table can be scrolled from the keyboard (87 → 88). Every probe reaches the
  same control before and after with a visible ring, and every probe that
  presses a key or expects a request passes in both builds.
- **Mobile.** No horizontal page overflow at 390 px, before or after. The
  filters stack below 900 px; the table scrolls inside its region with each
  row's actions on one line.
- **Two measurement notes.**
  - The harness names headings and dialogs from their text, which includes
    glyphs hidden from assistive technology: it reports the re-run dialog as
    "🔁 Re-run Scan No. 2114?". The unit tests compute the accessible name,
    "Re-run Scan No. 2114?", without the glyph.
  - The disabled "Previous" pager button measures 1.69 (1.89 in dark). WCAG
    exempts inactive controls, and the harness reports it separately from the
    failing pairs; it is CcurePagination's disabled style.

---

## 3. Security validation

- **Requests are unchanged, and pinned on the legacy page first.** The
  contract tests assert what leaves the page:
  - `GET /scans?scope=active&skip=0&limit=200` on mount, with `created_by=me`
    for `?owner=mine`; the status tab is never sent; a search goes to the
    server after 300 ms, trimmed; status and time filters apply in the browser
    without a request; Sync now reloads the same list and cannot be pressed
    while it runs;
  - the stream: `/scans/events` with `scope=active`, `skip=0`, `limit=200`,
    `interval=2` and the list's filters, `Accept: text/event-stream`, the
    bearer token and `credentials: "include"`;
  - `GET /scans/{id}` for details; a credentialed scan's View goes to its
    results page instead;
  - Archive `POST /scans/{id}/archive` and Delete `DELETE /scans/{id}`, each on
    the first press; Re-run `POST /scan/host-discovery` with the original
    pipeline, type and targets (a comma-separated target split, `display_id`
    as the fallback); Stop `POST /scans/{id}/stop`; the success and failure
    handling of each, the API's `detail` included;
  - an `afterEach` in every test that nothing else was written and every
    `fetch` went to the stream.
- **The live stream, against the ten requirements for this batch:**

  | Requirement                           | Evidence                                                                                                                                                                                                                                                                      |
  | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | 1. Exactly the intended connection    | "opens exactly one live stream with the list's filters, token and credentials". In the harness every capture opens the stream twice (the open and its one retry) before polling, identically pre and post; `sh-history` opens a third when its owner probe changes the filter |
  | 2. Reconnect unchanged                | "retries a closed stream once after 2.5 s, then polls every 5 s and never reopens it" and "counts a refused stream as a failure"; the reconnect code is in the byte-identical logic block                                                                                     |
  | 3. Closed on unmount                  | "unmounting aborts an open stream and nothing is requested afterwards"                                                                                                                                                                                                        |
  | 4. Polling only on the fallback       | Polling starts at the second failure and not before (as 2); list-request counts per capture are identical pre and post                                                                                                                                                        |
  | 5. No polling during a healthy stream | "never polls while the stream is open", over 60 s of fake time                                                                                                                                                                                                                |
  | 6. Terminal states                    | Unchanged. The page never stopped its stream or polling for settled scans, and still does not: pinned by "keeps its live sync running whatever the scans' statuses" and deferred (§7)                                                                                         |
  | 7. No duplicate stream                | Changing the owner filter or the search aborts the old stream before opening the new one (two tests)                                                                                                                                                                          |
  | 8. No duplicate polling               | One list request per 5 s; "unmounting during the reconnect wait stops the retry" and "unmounting while polling stops the polling"                                                                                                                                             |
  | 9. No write from an event             | The `afterEach` write check covers every stream test; 0 writes in all four harness reports                                                                                                                                                                                    |
  | 10. Parsing unchanged                 | "applies connected, scans and heartbeat events, and ignores others" and "a snapshot without a scans array changes nothing"; `api/scans.js`, which parses the stream, is untouched                                                                                             |

- **Confirmations are unchanged.** Re-run and Stop ask first and send nothing
  until confirmed; the confirm button takes focus on open; Escape and a click
  outside cancel; both buttons are disabled while the request runs. Archive and
  Delete still do not ask (§7).
- **Permissions are unchanged.** View needs `scans:read`, Re-run
  `scans:execute`, Archive `scans:archive` and Delete `scans:recycle`. Stop is
  still shown without `scans:execute`, and confirming it is refused without a
  request. `App.jsx` still mounts both modes behind the base sign-in check only
  (asserted from the source); a user without `scans:read` sees the backend's
  403 as a failed load.
- **Navigation is unchanged:** a re-run opens `/scan/active/{id}` with the new
  session's state; a credentialed re-run goes to `/scan/credentialed` with the
  target filled in; details open `/scan/{id}/phase1` or the credentialed
  results; the empty state goes to `/scan`.
- **The harness never wrote or navigated away.** No refused write and no
  non-GET beyond the session refresh in any of the four reports, and every
  `sh-` capture ended on its own route. The request shapes seen are exactly
  `GET /api/scans`, `GET /api/scans/events` (each with and without
  `created_by=me`) and `GET /api/scans/{id}`.
- **Nothing new executes or leaves the site.** No new dependency, no
  `dangerouslySetInnerHTML`, no new kind of resource. Security headers and the
  air-gap host set are identical.

---

## 4. Intentional changes

1. **Headings.** One `h1` ("Scan History" / "Active Scans"), which was an `h2`.
   Each running scan's card title is an `h2`; the details dialog's sections are
   `h3`, which were `h4`.
2. **Filters are labelled groups of toggle buttons** with `aria-pressed`. The
   selected option has a tint, border and weight. The monitor's single
   "Running" option is unchanged in behaviour.
3. **The table is CcureTable**: a caption, `scope="col"` headers, the scan
   number as each row's header, and `aria-sort` on the header cell. The sort
   rule is the page's own and unchanged: text columns ascending first, numbers
   and dates descending first, back to page one. Headers are no longer
   uppercased.
4. **Row actions are CcureButton, named by scan**; their tooltips are
   unchanged. On a wide screen the four buttons sit two by two.
5. **Status and progress are CcureScanStatus and CcureScanProgress.** Labels
   are unchanged for every status the page labelled. Progress is a named
   `progressbar` with the percentage the page computed, with two differences:
   - a **completed** scan's bar reads 100% even if the API last reported less
     (the legacy bar showed the API's figure);
   - a status the page had no label for was shown raw in the running style; it
     now reads "Unknown", and `queued` and `pending` read "Queued" and
     "Pending". History and Active Scans list only statuses the page labels,
     so in practice this shows only in the details dialog.
6. **The live sync state is a status region**, so a change is announced.
7. **Sync now keeps its name while it syncs** (CcureButton's loading state).
8. **Loading, failure and empty states are CcureLoader, CcureAlert and
   CcureEmptyState.** "Loading scan history…" and "Loading scan details…" are
   new text for what was an unlabelled spinner.
9. **All three dialogs are CcureModal**: named by their title, the
   confirmations described by their question, focus trapped and restored, the
   rest of the page hidden from assistive technology while open. The
   confirmation's behaviour is exactly as before (§3).
10. **The details dialog closes on Escape**, which it did not before.
11. **The confirmation's warning keeps its tone.** The stop confirmation's
    warning is danger-styled, as before; the re-run warning, which the legacy
    page marked ℹ️ on an amber tint, is CcureAlert's info style.
12. **Notifications use the shared Toast shim**: the same messages, the same
    4-second lifetime and click-to-dismiss, plus live regions and a named
    dismiss button. The page carried a private copy of the same code.
13. **Running-scan cards are CcureCard**, with named View and Stop buttons and
    a progress bar.
14. **Decorative glyphs are hidden** from assistive technology: the dialog
    icons, the sort indicators (the sort state is `aria-sort`), and the arrows,
    ticks and ✕ on buttons and badges.
15. **Colours are tokens in both themes.** Below 900 px the filters stack;
    below 640 px the page's padding narrows, the header's actions align left,
    card details go to one column and row actions stay on one line.
16. **The page's header comment is corrected.** It described confirmation
    dialogs for Archive and Delete, which the page never had, and a leftover
    line ("omitting some imports for brevity…") sat among the imports since
    `064e423`.

---

## 5. Retirement

- **The page no longer uses anything from `scan.css`** (85 class references
  before). `scan.css` is untouched and still used elsewhere.
- **Three private copies are gone:** the toast system (now the shared Toast
  shim), the inline-styled status badge (CcureScanStatus) and the progress bar
  (CcureScanProgress).
- `scan-history.css` is page-owned and imported only by ScanHistory.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-,p1-,amt-,nm-`
exits 0:

- All 111 unchanged-page captures are identical in every category, Batch 21's
  7 NetworkMap captures included.
- pre-b vs post-b is also 111 / 111.
- Post determinism (post-a vs post-b) is 125 / 125.
- 111 of 125 captures are identical overall; the 14 ScanHistory captures
  changed.

Every changed category on those 14 captures is accounted for:

| Category                                         | Captures | Why it changed                                                                                                                         |
| ------------------------------------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| headings, roles, live, ariaStates                | 14 each  | §2: the `h1`; progress bars, filter groups and alerts; the status and Toast live regions; `aria-pressed` on the filters                |
| names, tabOrder                                  | 10 each  | Actions named by scan; the close button named; focus held inside dialogs; the scroll region's tab stop at 390 px                       |
| tables                                           | 7        | Every capture with the table: the caption and scoped headers                                                                           |
| dialogs                                          | 3        | The details dialog gains its role and name; both confirmations' names carry their hidden glyph in the harness's text-based census (§2) |
| probes                                           | 4        | `sh-history` (both themes) and `sh-monitor` (both themes): the focused controls' names now include the scan number                     |
| contrast                                         | 14       | 0 failing pairs on every ScanHistory capture                                                                                           |
| inline, classes, styles, rects, text, screenshot | 14       | The restyle. The only inline styles left are CcureProgress's bar widths and the shell's two quota bars                                 |
| requests, writes, url, runtime                   | —        | **Unchanged**                                                                                                                          |
| clickable, overflow                              | —        | Unchanged: no pointer-only targets and no horizontal overflow in either build                                                          |

Screenshots were reviewed side by side for all 14 captures: both modes in both
themes, the completed filter, loading, empty, failed, read-only and denied
states, the details dialog, both confirmations and the 390 px layout.

---

## 7. Deferred, and found but not fixed

- **Archive and Delete act on the first press, with no confirmation**, although
  the page's own header comment described confirmation dialogs for both, and
  Delete moves a scan to the recycle bin. Kept exactly; a product decision.
- **The confirmation focuses its confirm button on open**, so a stray Enter
  re-runs or stops a scan. Kept exactly. CcureConfirmDialog, which this page
  could not use without losing the re-run dialog's scan details, focuses Cancel
  for this reason.
- **Stop is offered without `scans:execute`** and refused only on confirm.
- **The live stream never stops for settled scans.** History keeps its stream
  or its 5-second poll running whatever the scans' statuses, for as long as the
  page is open; after the fallback to polling the stream is never retried, and
  the failure count never resets.
- **A failed poll is silent**, and an earlier load error clears only when a
  later poll succeeds.
- **The list is fetched as one page of 200** and paged in the browser, so a
  history longer than 200 scans is truncated; the "Showing N of total scans"
  note is the only sign.
- **Active Scans hides queued and pending scans**: its fixed "Running" filter
  excludes any status other than `running` (or a missing one).
- **CcureModal's click-outside dismissal never fires** (§0.2, item 6). It reads
  the React event's `currentTarget` after dispatch, and no primitive test
  covers it. ScanHistory handles a click on its dialogs' overlay itself; the
  ten other files using CcureModal are affected. The primitive was out of
  scope; when it is fixed, the page's `useCloseOnOverlayClick` should go.
- **Harness:**
  - the stream replay is finite by design, so a healthy long-lived stream is
    covered by the unit tests only;
  - the router ignores query strings, so one payload answers every filter;
  - headings and dialog names are read from text, including hidden glyphs (§2);
  - the shell's `/api/notifications/stream` is unstubbed on every page, as
    before.
- **Carried:**
  - from batch 21: NetworkMap's canvas has no keyboard navigation, no
    accessible name, focus handling or instructions, and no keyboard
    alternative for inspecting a node; the cross-page review of frontend
    authorisation;
  - from batch 20: the AMT import has no confirmation and needs hardened
    permissions; a failed export has no UI and its object URL is never
    revoked; the fixed reconciliation delay; filters that are neither debounced
    nor trimmed; a failed statistics load; Department shows the company name;
    the fixed page size; asset links are full page loads;
  - global: CcureTable's hidden caption; the Toast and Modal shims; CVELink and
    CcureTabs still overlap `dashboard.css`; ScanContext's duplicate GET; the
    `cc_executionMode` reset; polling timeout and error handling; Phase 3's
    automatic start; ExportPanel's CSV formula injection; the truncated custom
    port list.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was
reached:

- every request — the list, the stream, details and the four writes, with
  their paths, parameters and payloads — is unchanged and pinned;
- the stream's single connection, its one retry, the polling fallback, its
  timing and unmount clean-up are unchanged and pinned, and no event triggers a
  write;
- confirmations, permissions and navigation are unchanged;
- no write, no unexpected navigation, no off-origin request, no CSP issue, no
  exception and no console error in any capture;
- determinism, sensitivity and the regression gate over every previously
  migrated page passed;
- security headers and the air-gap host set are identical;
- no shared component, design-system primitive or global stylesheet was
  modified.

# Checkpoint 3C — Batch 23: CredentialedResults on the design system

CredentialedResults is the credentialed scan report
(`/scan/credentialed/results`). It shows a report handed over in router state
by a scan that has just finished, or reads it with `GET /scans/{id}` for
`?scan_id=`. A scan that has not finished yet is followed live, and the page
shows a progress dashboard until the report arrives.

**This page shows credential-derived output, and it follows a live socket.**
The batch is presentation and accessibility only, and the rest is pinned:

- **The logic is the code that was here.** The component's state, the ticket,
  the socket, the polling fallback and the redirect (184 lines), the unreachable
  classification, host selection and the report's destructuring, the
  interface parsing, risk, filters and searches, `maskSecretLine`,
  `hydrateFromHistory` and `STAGES` are byte-identical to the legacy page. The
  one line removed from that logic is the OS badge's colour literal.
- **One write, unchanged:** `POST /auth/ticket` with no body, and only once
  the first read says the scan is still running.
- **The live socket, unchanged:** one WebSocket at
  `{API base with http→ws}/scans/{id}/progress?ticket=…`; phase 5 frames move
  the dashboard; a `complete` frame re-reads the record; a socket that closes
  before results arrive, a refused ticket or a socket that cannot be opened
  falls back to reading the record every 3 s until it settles; unmounting
  closes the socket and cancels any pending read.
- **Masking, unchanged:** flagged environment variables pass through
  `maskSecretLine` before they render, and the exact output of that rule is
  pinned case by case (§3.2).

**Baseline:** HEAD `7170ed0` (Batch 22).

**Not touched:**

- Phase3Results, NewScan, ComplianceWorkspace, ScanHistory, NetworkMap,
  AMTIntegration and every other page.
- `api/scans.js`, `api/axiosInstance.js`, `App.jsx`, PrivateRoute,
  `auth/permissions`, RiskBadge, CVELink, CcureModal and every other
  design-system primitive.
- `scan.css`, `global.css`, `dashboard.css` and the rest of the legacy CSS
  chain.
- The backend, `nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`,
  `package.json` and the lockfile.
- `run.mjs` and the harness's capabilities, apart from one opt-in answer to the
  ticket (§0.3). No WebSocket support was added: `run.mjs` still blocks `ws://`
  and `wss://`, and the running states script the socket inside the page.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                    |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `7170ed0`                                                                                                                                                                                                                                           |
| Tests first, on the legacy page             | 107 tests: the 94 contract tests pass, the 13 batch 23 tests all fail, each for its intended reason, after corrections to the tests themselves (§0.2)                                                                                                                     |
| Live-socket replay, unchanged build         | The 15 `cr-` captures taken twice: **15 / 15** identical and ready; 0 writes, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors; every keyboard probe reached and passed; no fixture secret in either report                                                     |
| Baseline, unchanged build                   | 140 captures ready, twice. Determinism **140 / 140**, sensitivity **22 / 22**                                                                                                                                                                                             |
| Same tests, migrated                        | **94 / 94** contract tests on the first run; **13 / 13** batch 23 tests after one correction to a test's own precondition (§0.2)                                                                                                                                          |
| Logic unchanged                             | The named logic blocks above are byte-identical legacy → migrated, compared block by block; the only removed line is `osBadgeClr`                                                                                                                                         |
| Full frontend suite                         | 56 files, **2026** tests, all passing (1919 + 107)                                                                                                                                                                                                                        |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                       |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                         |
| Pre-commit formatting                       | Every Batch 23 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                |
| Post determinism                            | post-a vs post-b **140 / 140** identical                                                                                                                                                                                                                                  |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace, SecurityDashboard, Phase2Results, Phase1Results, AMTIntegration, NetworkMap and ScanHistory: **125 / 125** captures identical pre → post in every category, on both capture pairs                               |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                               |
| CredentialedResults requests                | Identical before and after in every `cr-` capture (0 deltas). The ticket exactly once in `cr-running` and `cr-fallback` and nowhere else; one read of the record per capture, two in `cr-fallback`. The only shapes are `GET /api/scans/{id}` and `POST /api/auth/ticket` |
| Secrets                                     | None of the three synthetic flagged values appears anywhere in any capture of the four reports — text, names, tab order or request log                                                                                                                                    |
| CSP and security headers                    | Identical on the pre and post images across nine routes, `/scan/credentialed/results` included (63 header lines)                                                                                                                                                          |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                              |
| Writes, navigations, off-origin, CSP issues | 280 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every `cr-` capture ends on its own route in all four reports               |
| Screenshots                                 | All 15 CredentialedResults captures reviewed side by side, pre and post. No regression                                                                                                                                                                                    |

### 0.1 The live socket in tests and in the harness

**Unit tests.** `WebSocket` is replaced by a socket the test drives: it records
its URL, delivers frames, drops, and reports a `close()` asynchronously and only
once, as a browser does. With fake timers the contract tests step through the
lifecycle: the ticket only after a still-running read; the URL built from the
API base (`/api`, `https://…` → `wss://`, `http://…` → `ws://`, an empty base)
with the ticket encoded; frame handling (other phases and frames without
progress ignored, a missing percentage keeping the last, only frames with a
message logged, 50 lines kept); no polling for 60 s while the socket is open;
polling every 3 s after a drop, a refused ticket or a socket that cannot be
constructed, until the record settles; a `complete` frame re-reading the
record and closing the socket without polling; and unmounting at each stage —
before the first read settles, before the ticket arrives, with the socket
open, and while a poll is pending.

**Harness.** The running states need a ticket and a socket, and the harness
refuses writes and blocks sockets. Two pieces, both scoped to this page:

- **The ticket.** A state that declares `ticket` has `POST /auth/ticket`
  answered with that fixed placeholder (`router.mjs`). Every other write, on
  every state, is still refused, and the answer issues nothing: it names a
  socket that is never opened.
- **The socket.** The existing `init` hook (a script injected before the
  application boots) replaces `WebSocket` on `/scan/credentialed/results` only.
  The scripted socket records the URL it is given, replays recorded phase 5
  frames 40 ms apart and stays open — or, for `cr-fallback`, drops after two
  frames. Readiness asserts exactly one socket, at
  `/api/scans/{id}/progress?ticket=harness-ticket`, in both builds.

### 0.2 Corrections

Corrections to the tests before the baseline, none of them to a pinned
behaviour:

1. **Four contract tests rendered the page twice without unmounting**, so their
   queries saw both trees. They call `cleanup()` between renders.
2. **The key-fact helper matched the summary bar's own "Kernel" text.** It
   reads only key elements now.
3. **The log-line counter counted the dashboard's heading**, which repeats the
   latest message. It ignores headings.
4. **Two batch 23 tests failed on the legacy page for the wrong reason.** The
   caption test stopped at its own table-count precondition, which now runs
   after the caption checks; the badge test read `closest("li")` on the legacy
   `<div>` rows, and now asserts the list item first.

One correction to the harness before the baseline:

5. **`cr-fallback` finished before the page polled.** The trial captured it
   between the socket dropping and the first 3-second read. It is ready now
   only once the browser has made the second read of the record.

Corrections after migration, none to the page:

6. **The caption test's table count** assumed more than three tables for each
   host; the Windows fixture host has three. Every table on both hosts was
   captioned and scoped; the count is now "at least three".
7. **An unused test helper** failed ESLint and was removed.

### 0.3 Harness changes

- **15 CredentialedResults captures** in 12 states, every one reading its
  report through `?scan_id=`:
  - `cr-report` (both themes): two audited hosts and one that could not be
    audited, with three keyboard probes;
  - `cr-expanded`, `cr-windows` and `cr-mobile` (390 px): every section
    opened, the audit evidence and its masked variables included;
  - `cr-empty`: a report with no findings;
  - `cr-running` (both themes) and `cr-fallback`: the scripted socket (§0.1);
  - `cr-loading`: the first read left pending;
  - `cr-failed`, `cr-unreachable` (both themes), `cr-error` (500) and
    `cr-denied` (a persona without `scans:read`, refused with the backend's 403
    detail).
- **Probes.** On `cr-report`: the severity filter (Enter on High → only
  CVE-2023-0286 is listed), a section (Enter on Running Services → its table),
  and the host selector (Enter on 10.40.2.30 → the Windows build). On
  `cr-failed`, Try Again is reached by Tab only: Enter navigates.
- **The expanded states wait for the mask.** After opening every section they
  wait until `AWS_SECRET_ACCESS_KEY=********` is in the document and none of
  the synthetic secret values is. Opening every section is one click
  expression over toggles whose text ends in the section chevron; the shell's
  account menu toggle ends in the same chevron, so those captures also show
  that menu open, identically in both builds.
- **Fixtures are synthetic**: no credential, host or output comes from a real
  system. The flagged variables carry obviously fake `hx-` values.
- **`REGRESSION_PREFIXES`** now includes `sh-`, so Batch 22's captures are in
  the regression gate.
- The catalogue is now 101 states, 140 captures.

---

## 1. Files changed

| File                                                    | Change                                                                                                                               | LOC                        |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------- |
| `src/pages/scan/CredentialedResults.jsx`                | Design-system markup: disclosure sections, description lists, CcureTable, badges, alerts, labelled searches, an accessible dashboard | 2368 → 1920 (+866 / −1314) |
| `src/styles/credentialed-results.css`                   | New, page-owned: 244 `--ccure-*` references, 0 colour literals, 0 other custom properties                                            | new, 832                   |
| `src/__tests__/pages/scan/CredentialedResults.test.jsx` | New: 94 contract + 13 batch 23                                                                                                       | new, 2068                  |
| `scripts/ux4g-harness/lib/fixtures.mjs`                 | Synthetic reports, the ticket placeholder, recorded frames and the scripted socket                                                   | +432                       |
| `scripts/ux4g-harness/lib/states.mjs`                   | 12 `cr-` states; `sh-` in the regression prefixes                                                                                    | +177 / −3                  |
| `scripts/ux4g-harness/lib/router.mjs`                   | The opt-in ticket answer                                                                                                             | +9 / −1                    |
| `docs/ux4g/03c-batch23-credentialed-results.md`         | This document                                                                                                                        | new                        |

| Measure                                                     | Before                     | After                 |
| ----------------------------------------------------------- | -------------------------- | --------------------- |
| Inline `style` attributes                                   | 149 (and 12 style objects) | **0**                 |
| Colour literals in the page                                 | 57 (47 hex, 10 `rgba`)     | **0**                 |
| Legacy `var(--…)` references in the page                    | 105                        | **0**                 |
| Legacy class references (`btn`, `alert`, `page-*`, `kv-*`…) | 88                         | **0**                 |
| Hand-built tables                                           | 1 component, 10 uses       | **0** (11 CcureTable) |
| Hover handlers painting a background                        | 2                          | **0**                 |
| Unlabelled search fields                                    | 4                          | **0**                 |
| Level-one headings                                          | 0                          | **1** in each state   |
| Failing text contrast pairs (report, light / dark)          | 55 / 32                    | **0 / 0**             |
| Tests                                                       | 0                          | 107                   |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change  |
| ----- | -------------- | ------------- | ------- |
| CSS   | 385,554        | 399,056       | +13,502 |
| JS    | 1,607,520      | 1,602,186     | −5,334  |

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures; the
unit tests cover the same points and the parts the harness cannot reach.

- **Headings.** The page title was an `h2` with nothing above it; it is the
  `h1` in each state. Each report section is an `h2` holding its disclosure
  button, which states `aria-expanded`; sub-sections are `h3`, which were `h4`
  (and uppercase); the dashboard's message is an `h2`.
- **Tables.** Ten tables on the expanded report had no caption and 39 unscoped
  headers. After: every table captioned, and all 63 header cells scoped — a
  column header for each column and a row header for each row.
- **Controls are labelled.** The four search fields were placeholder-only; each
  has a label. The severity filter and the host selector are labelled groups
  stating their selection with `aria-pressed`.
- **Failures are announced.** A failed, refused or unreachable scan is an alert
  (0 → 1 on each failure capture).
- **Live progress.** A named progress bar, an ordered list of stages marking the
  current one, and a `log` region for the live activity.
- **Keyboard.** Scrolling evidence and the live log can be focused and scrolled
  from the keyboard: tab stops 50 → 51 on the report, 62 → 66 expanded, 68 → 73
  at 390 px (where tables scroll inside their own regions) and 22 → 23 on the
  dashboard; failure views are unchanged. All four probes reach the same
  controls in both builds with a visible ring, and the three that press Enter
  pass in both builds.
- **Contrast.** Failing text pairs, before → after:

  | Capture                | Light  | Dark   |
  | ---------------------- | ------ | ------ |
  | Report                 | 55 → 0 | 32 → 0 |
  | Every section open     | 89 → 0 | —      |
  | Windows, sections open | 16 → 0 | —      |
  | At 390 px              | 89 → 0 | —      |
  | Empty report           | 4 → 0  | —      |
  | Running                | 13 → 0 | 11 → 0 |
  | Polling fallback       | 12 → 0 | —      |
  | Loading                | 12 → 0 | —      |
  | Failed                 | 4 → 0  | —      |
  | Unreachable            | 2 → 0  | 5 → 0  |
  | Error                  | 4 → 0  | —      |
  | Without `scans:read`   | 4 → 0  | —      |

  Legacy defects now gone: CVE identifiers and severity words painted in their
  severity's colour (2.05 to 3.13); package, version and "fixed in" metadata
  (2.18, 2.45); warning and danger values in key facts (2.15, 3.27); the
  section chevrons and stage labels (2.45 to 2.77); primary buttons (2.77);
  "0 CVEs" (2.28); the Windows account states (Disabled 1.92, Active 2.19,
  Admin 3.15); the failed-scan alert (4.17); the unreachable panel in the dark
  theme (2.24); and, in the dark theme, the progress card rendered as a white
  card with pale text.

- **Mobile.** No horizontal overflow at 390 px, before or after. Key facts stack
  label above value, toolbars stack, and tables scroll inside their regions.
- **No sensitive value in accessibility text.** Every `aria-label` and caption is
  fixed text; the only data in an accessible name is a host's address on its
  selector button.
- **Two measurement notes.**
  - The harness names headings from their text, which includes glyphs and
    chevrons hidden from assistive technology ("h2:🖥 System Information ▲").
    The unit tests compute the accessible name, "System Information".
  - The host button's name in the probe snapshot reads "10.40.2.30(0) CVEs";
    the "CVEs" is visually hidden and the parenthesised count is unchanged.

---

## 3. Security validation

### 3.1 Requests

- **Pinned on the legacy page first.** `GET /scans/{id}` once for `?scan_id=`;
  no request at all for a report in router state; a redirect to
  `/scan/credentialed` with neither. `POST /auth/ticket` with no body, only after
  a read says the scan is still running, never for a settled or failed record,
  and never when the first read is still outstanding or the page has unmounted.
- **An `afterEach` in every test** allows only that ticket as a write, only
  `/scans/{id}` as a read, and only the progress URL as a socket.
- **In the harness**, the same shapes in both builds: `GET /api/scans/{id}` and,
  in the running states only, one `POST /api/auth/ticket`. Both carry the
  `org_id` query parameter the axios instance adds to every request.

### 3.2 Masking

Pinned case by case against the legacy rule, then unchanged:

| Flagged line                                           | Rendered                         |
| ------------------------------------------------------ | -------------------------------- |
| `AWS_SECRET_ACCESS_KEY=placeholder`                    | `AWS_SECRET_ACCESS_KEY=********` |
| `DB_PASSWORD=p=ss=w0rd`                                | `DB_PASSWORD=********`           |
| `API_TOKEN: hx-token-77aa`                             | `API_TOKEN: ********`            |
| `Authorization:Bearer hx-bearer-01`                    | `Authorization:********`         |
| `DATABASE_URL=postgres://auditor:hx-dbpass-42@db/prod` | `DATABASE_URL=********`          |
| `export GITHUB_TOKEN = hx-gh-5e`                       | `export GITHUB_TOKEN =********`  |
| `PATH=/usr/bin:/bin`                                   | `PATH=********`                  |
| `KEY=`                                                 | `KEY=********`                   |
| `a:b:c`                                                | `a:********`                     |
| `SECRET:hx-left=hx-right`                              | `SECRET:hx-left=********` (§7)   |
| `PLAIN_VALUE`                                          | `PLAIN_VALUE`                    |

- **No flagged value reaches the document**: not in text, not in an attribute,
  and not in the document at all until the evidence section is opened (the
  section's body is rendered only while open, as before).
- **Nothing from the report or the ticket reaches the console**, and the ticket
  never reaches the document.
- **Scan-supplied text renders as text**: markup in cron configuration, sudo
  rules, issues, a finding's description or a service name is shown literally.
  The page uses no `dangerouslySetInnerHTML`.
- **In the harness**, the expanded states wait for the masked form, and none of
  the synthetic values appears in any capture of the four reports.

### 3.3 The live socket

| Requirement                                   | Evidence                                                                                                                                                                                                                   |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Exactly the intended socket                | One socket at the progress URL, built from the API base with the ticket encoded (four base URLs pinned); in the harness, readiness asserts one socket at `/api/scans/{id}/progress?ticket=harness-ticket` in both builds   |
| 2. Ticket acquisition unchanged               | One `POST /auth/ticket` with no body, only after a still-running read; none while the read is outstanding; in the harness, once in each running capture and nowhere else                                                   |
| 3. No duplicate sockets                       | One socket across frames, re-renders, 60 s of fake time and a drop; one in every harness capture                                                                                                                           |
| 4. Close and unmount                          | Unmounting closes the socket and later frames change nothing; unmounting before the ticket arrives opens no socket; a `complete` frame closes it once the report is shown                                                  |
| 5. Reconnection unchanged                     | There is none: a dropped socket is never reopened; the page polls instead                                                                                                                                                  |
| 6. Polling only under the existing conditions | A drop before results, a refused ticket, or a socket that cannot be constructed; never after the report has arrived                                                                                                        |
| 7. No polling while the socket is open        | "never polls while the socket is open" over 60 s; one read in each harness running capture                                                                                                                                 |
| 8. Terminal states                            | A `complete` frame re-reads and shows the report; a `failed` frame shows its message and leaves the socket open; a failed or cancelled record shows why with no ticket; a failure read after `complete` arms one more read |
| 9. Timers cleaned up                          | Unmounting while a poll is pending cancels it; polling stops once the record settles                                                                                                                                       |
| 10. No write from an event                    | The `afterEach` allows only the ticket; 0 refused writes and no other non-GET in the four reports                                                                                                                          |
| 11. Parsing and state updates unchanged       | Phase 5 frames only; percentage, message, stage and the 50-line log pinned; the handler is in the byte-identical block                                                                                                     |

### 3.4 Permissions and navigation

- **The page checks no permission, as before** (asserted from the source), and
  `App.jsx` still mounts both routes behind the base sign-in check only. A user
  without `scans:read` meets the backend's 403 detail as a failed scan.
- **Navigation is unchanged:** New Scan and Try Again go to `/scan/credentialed`,
  History and View History to `/history`; CVE links still open NVD in a new tab
  with `rel="noopener noreferrer"`.
- **Nothing new executes or leaves the site.** No new dependency. Security
  headers and the air-gap host set are identical.

---

## 4. Intentional changes

1. **Headings.** One `h1` in each state ("Credentialed Scan In Progress" /
   "Credentialed Scan Results"), which was an `h2`. Each report section is an
   `h2` holding its disclosure button, with `aria-expanded` and, while open,
   `aria-controls`; sub-sections are `h3`, which were uppercase `h4`; the
   dashboard's message is an `h2`, which was an `h3`.
2. **Key facts are description lists** (`dt`/`dd`), which were `<span>` pairs.
   Below 640 px each label sits above its value.
3. **Tables are CcureTable**: a caption, `scope="col"` headers and a row header
   for each row, with headers no longer uppercased. The legacy row tints (an
   administrator, the root user, a vulnerable package) are gone; the
   identifying cell carries the tone.
4. **Searches are labelled** ("Search services", "Search listening sockets",
   "Search packages", "Search users"); the placeholders are unchanged.
5. **The severity filter and the host selector are labelled groups of toggle
   buttons** with `aria-pressed`. A host's button tells assistive technology its
   number is a CVE count; the worst-band dot stays visual.
6. **Severity and state are design-system badges.** A finding's band is
   CcureSeverityBadge — a band the badge does not know reads "Unscored" where
   the raw text was shown. Exposure, hardening results and scheduled-task states
   are CcureBadge. The severity summary keeps its text, with a decorative dot.
7. **Findings are a list**, which were `<div>` rows.
8. **Live progress** is a CcureProgress bar named "Credentialed scan progress"
   (the large percentage moves beside the bar), an ordered list of stages
   marking the current one with `aria-current="step"` and completed ones with
   "(completed)" for assistive technology, and a focusable `log` region named
   "Live activity".
9. **Failures are CcureAlert** and are announced: "Scan Failed" as a danger
   alert, "Host is unavailable/down/unreachable" as a warning. The notice about
   hosts that could not be audited is a warning that is not announced — it is
   part of the report, present on load.
10. **Buttons are CcureButton.**
11. **Scrolling evidence is keyboard-reachable** — the SUID list, cron
    configuration, sudo rules, login failures, raw interface output and the live
    log — with a visible focus ring. Each adds a tab stop.
12. **The auto-detected OS badge** is one info badge, where Windows was blue and
    Linux orange.
13. **CVE links take the link colour**, where they were painted in their
    severity's colour; the severity is the badge beside them.
14. **The live log is a sunken panel in both themes**, where it was a dark
    terminal panel; failed lines use the danger text colour.
15. **Decorative glyphs are hidden** from assistive technology and stay on
    screen.
16. **Colours are tokens in both themes**, and the layout adapts below 900 px
    and 640 px.

---

## 5. Retirement

- **The page no longer uses anything from the legacy stylesheets** (88
  references to `btn`, `alert`, `page-*`, `summary-*`, `kv-*`, `cve-*`,
  `pipeline-*`, `progress-*` and similar). Those stylesheets are untouched and
  still used elsewhere.
- **The hand-built `CredTable`, `KV` and `Section` are gone**: CcureTable, a
  description list and a disclosure heading.
- `credentialed-results.css` is page-owned and imported only by
  CredentialedResults.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-,p1-,amt-,nm-,sh-`
exits 0:

- All 125 unchanged-page captures are identical in every category, Batch 22's
  14 ScanHistory captures included.
- pre-b vs post-b is also 125 / 125.
- Post determinism (post-a vs post-b) is 140 / 140.
- 125 of 140 captures are identical overall; the 15 CredentialedResults
  captures changed.

Every changed category on those 15 captures is accounted for:

| Category                                   | Captures | Why it changed                                                                                         |
| ------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------ |
| headings, text                             | 15, 14   | §2: the `h1`, section `h2`s and `h3`s; labels, visually hidden text and captions                       |
| roles                                      | 13       | The filter and host groups; the failure alerts; the progress bar and log; scroll regions at 390 px     |
| ariaStates                                 | 10       | `aria-expanded` on sections, `aria-pressed` on toggles, `aria-current` on the stage                    |
| live                                       | 5        | The alert on each failure capture                                                                      |
| names, tables                              | 5 each   | Labelled searches and host button names; captions and scoped headers                                   |
| tabOrder                                   | 8        | Focusable scrolling evidence and log (§2)                                                              |
| probes                                     | 2        | `cr-report` (both themes): the host button's name                                                      |
| contrast                                   | 15       | 0 failing pairs on every CredentialedResults capture                                                   |
| inline, classes, styles, rects, screenshot | 15       | The restyle. The only inline styles left are CcureProgress's bar widths and the shell's two quota bars |
| requests, writes, url, runtime             | —        | **Unchanged**                                                                                          |
| clickable, overflow, dialogs               | —        | Unchanged: none in either build                                                                        |

Screenshots were reviewed side by side for all 15 captures: the report in both
themes, every section open on Linux and Windows, 390 px, the empty report, the
dashboard running (both themes), polling and loading, and the failed,
unreachable (both themes), error and denied views.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — all kept exactly, and pinned where marked:

- **Masking covers only the flagged environment variables.** Sudo rules, cron
  configuration, recent login failures and raw interface output render as
  collected, while the section says "Sensitive values are masked." (pinned)
- **`maskSecretLine` masks after the first `=`**, even when a `:` separator
  comes before it, so `SECRET:value=…` shows `SECRET:value=`; a line with
  neither is shown whole. (pinned)
- **A refused ticket logs the raw error object to the browser console.** An
  axios error carries its request configuration, Authorization header
  included; a socket that cannot be constructed throws an error naming the
  ticketed URL. The logged message itself is fixed text.
- **A frame that is not JSON throws** inside the socket's message handler.
- **A `failed` frame leaves the socket open** until the page unmounts. (pinned)
- **A failure read after a `complete` frame** closes the socket, and that close
  arms one more read of the record 3 s later. (pinned)
- **Polling has no limit**: a scan that stays running is read every 3 s for as
  long as the page is open, and the socket is never reopened.
- **`/scan/:scanId/credentialed-results` ignores its path id.** Nothing links
  to it, and without `?scan_id=` it redirects to a new scan. (pinned)
- **A router-state report marked unreachable** is shown as an unreachable host
  although it carries a report. (pinned)
- **The page checks no permission**; a user without `scans:read` sees the
  backend's 403 as a failed scan, under advice to verify SSH credentials.
- **The exposure explanation is a `title` tooltip** only, reachable by hover and
  not by keyboard or assistive technology; a host's worst severity is a
  coloured dot only.
- **Harness:** the scripted socket's frames are fixed, so frame timing and a
  close in mid-report are covered by the unit tests only; a real handshake and
  ticket issuance are not exercised; the expand-all click also opens the shell's
  account menu in both builds (§0.3); the shell's `/api/notifications/stream`
  is unstubbed, as before.

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

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was
reached:

- the read, the ticket and the progress socket — method, paths, payload, URL
  and timing — are unchanged and pinned, and nothing else is written;
- the socket's single connection, the polling fallback and its 3-second
  interval, terminal states and unmount clean-up are unchanged and pinned, and
  no event triggers a write;
- masking is unchanged and pinned; no flagged value, ticket or secret reaches
  the document, an attribute, the console or a harness report;
- permissions and navigation are unchanged;
- no write, no unexpected navigation, no off-origin request, no CSP issue, no
  exception and no console error in any capture;
- determinism, sensitivity and the regression gate over every previously
  migrated page passed;
- security headers and the air-gap host set are identical;
- no shared component, design-system primitive or global stylesheet was
  modified.

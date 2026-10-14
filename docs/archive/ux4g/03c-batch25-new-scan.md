# Checkpoint 3C — Batch 25: NewScan on the design system

NewScan is two views on two routes. `/scan/new` sets a scan up — target,
profile, advanced settings, stored credentials and SNMP — and starts it.
`/scan/active/:scanId` is the Active Mission view: it follows a running scan
over its progress socket and a 2.5-second read of the scan record, and when the
scan settles it hands over to the next phase's page by itself. The same view
opens when the setup view starts a scan and when Scan History re-runs one.

**This page starts scans, holds SNMP passphrases while they are typed, and
follows a live socket.** The batch is presentation and accessibility only, and
the rest is pinned:

- **The logic is the code that was here.** The component's body — its state,
  the port and exclusion parsers, validation, the record polling, the ticket
  and socket, the target-file reader, the dispatch, Stop Scan, the navigation
  handlers and the one-shot bootstrap (1,159 lines) — is byte-identical to the
  legacy page, as are its imports, the scan and port constants, the time and
  ring helpers, the mission view's props and every status the mission view
  derives. The only edits to copied code are the three badge colour objects
  (now badge variants), the legacy class strings the mission view no longer
  uses, and one `useId`. All 37 request, socket, timer, navigation, file and
  console call sites before the render occur in the same order; the render's
  handlers are the same set, less the three drawer-close handlers the dialog
  now owns as one.
- **The dispatch, unchanged:** one `POST /scan/host-discovery` built by
  `buildPhasePayload`, with the chosen options, then navigation to
  `/scan/active/{id}` with the scan handed over in route state.
- **The ticket and the socket, unchanged:** `POST /auth/ticket` with no body,
  then one WebSocket at `{API base with http→ws}/scans/{id}/progress?ticket=…`,
  closed on a `complete`, `failed` or `unreachable` frame or a later phase's
  frame, and after ten minutes of silence.
- **Polling, unchanged:** `GET /scans/{id}` every 2.5 s while following, stopped
  when the socket settles, when the record reads terminal, on Stop Scan and on
  New Scan. It is a safety net beside the socket, not a fallback.
- **The hand-off, unchanged:** a completed asset or audit scan navigates to host
  discovery, asset discovery or the vulnerability audit — the last with
  `startPhase: "PORT_SCAN"` — by itself. NewScan never starts Phase 3 itself;
  Phase3Results does, as Batch 24 left it.
- **Credentials, unchanged:** an audit sends stored credential references only;
  SNMP passphrases are password fields, sent in the dispatch as before and
  written nowhere else.

**Baseline:** HEAD `3b7bfcb` (Batch 24).

**Not touched:**

- ComplianceWorkspace, Phase3Results, CredentialedResults and every other page.
- `api/scans.js`, `api/axiosInstance.js`, `config/scanConfig.js`,
  `utils/ipValidation.js`, `context/ScanContext.jsx`, `App.jsx`,
  `auth/permissions`, AppLayout, ScanQuotaBar, CcureModal and every other
  design-system primitive.
- `scan.css`, `global.css`, `dashboard.css`, `scan-quota.css` and the rest of the
  legacy CSS chain.
- The backend, `nginx.conf`, CSP and `scripts/host-nginx/nginx-host.conf`,
  `package.json` and the lockfile.
- The harness's core: `run.mjs`, `router.mjs` and `guard.mjs` are unchanged. The
  `ns-` states use the existing ticket and declared-write opt-ins and the
  existing `init` hook.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `3b7bfcb`                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Tests first, on the legacy page             | 121 tests: the 107 contract tests and the 4 existing tests pass, and the 10 batch 25 tests all fail, each for its intended reason, after four corrections to the tests themselves (§0.2)                                                                                                                                                                                                                                                                                                             |
| Scan-flow replay, unchanged build           | The 20 `ns-` captures taken twice: **20 / 20** identical; 0 refused writes, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors; every keyboard probe reached and passed; neither the typed passphrase nor the ticket in either report. The three running captures became ready only after one correction to their readiness test (§0.2)                                                                                                                                                      |
| Baseline, unchanged build                   | 174 captures ready, twice. Determinism **174 / 174**, sensitivity **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Same tests, migrated                        | **107 / 107** contract tests and **4 / 4** existing tests on the first run; **10 / 10** batch 25 tests after two corrections to the specification tests themselves (§0.2)                                                                                                                                                                                                                                                                                                                            |
| Logic unchanged                             | The named blocks above are byte-identical legacy → migrated, block by block, and every difference outside them matches a recorded expected list exactly; the 37 call sites before the render are in the same order, and the render's handlers are the same set less the three drawer-close handlers                                                                                                                                                                                                  |
| Full frontend suite                         | 58 files, **2213** tests, all passing (2096 + 117)                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Pre-commit formatting                       | Every Batch 25 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Post determinism                            | post-a vs post-b **174 / 174** identical                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace, SecurityDashboard, Phase2Results, Phase1Results, AMTIntegration, NetworkMap, ScanHistory, CredentialedResults and Phase3Results: **154 / 154** captures identical pre → post in every category, on both capture pairs                                                                                                                                                                                                                      |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| NewScan requests                            | Identical before and after in every `ns-` capture (0 deltas), in all four reports: the dispatch once, in `ns-dispatch`; the ticket once in each of the eight mission captures and in no setup capture; the stored credentials read once, in `ns-settings-audit`; each mission capture reading only its own scan record. The only shapes are `POST /api/scan/host-discovery`, `POST /api/auth/ticket`, `GET /api/scans/{id}`, `GET /api/compliance/credentials` and the shell's `GET /api/scan/quota` |
| Secrets                                     | Neither the typed passphrase nor the ticket appears anywhere in any capture of the four reports — text, names, tab order or request log                                                                                                                                                                                                                                                                                                                                                              |
| CSP and security headers                    | Identical on the pre and post images across eleven routes, `/scan/new` and `/scan/active/{id}` included (77 header lines)                                                                                                                                                                                                                                                                                                                                                                            |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                                                                                                                                                                                                                                                         |
| Writes, navigations, off-origin, CSP issues | 348 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every `ns-` capture ends on its expected route in all four reports                                                                                                                                                                                                                                     |
| Screenshots                                 | All 20 NewScan captures reviewed side by side, pre and post. No regression                                                                                                                                                                                                                                                                                                                                                                                                                           |

### 0.1 The scan flow in tests and in the harness

**Unit tests.** `NewScan.contract.test.jsx` is new; the four tests in
`NewScan.test.jsx`, which predate this batch, are unchanged and pass on both
builds. The axios instance, the shell, the quota bar, the signed-in user and
`WebSocket` are replaced; the scan context and the router are real, with both
NewScan routes mounted as `App.jsx` mounts them, so the setup view carries on
into the mission view on the same component instance, as it does in the
application. A location probe records every navigation, its type and its
state. With fake timers the contract pins:

- the dispatch — the exact payload for a basic, asset (intensity and
  port-based, preset and custom) and audit scan; trimmed exclusions and a
  numeric rate limit; SNMP v1, v2c and v3 (privacy and context only when set)
  merged with stored credentials into one `options`; the display id when there
  is no scan number; one request for Enter and for a double click;
  validation that stops a scan before anything is sent;
- the route-requested start — once, 100 ms after load, and not without a
  target or `scans:execute`;
- following a scan — one ticket with no body and one socket, under StrictMode
  too; the record every 2.5 s; progress frames, enrichment frames and host
  lists; a `complete` frame closing the socket, stopping polling, reading the
  record once and storing discovery; the record's status outranking the
  socket's; polling that finds a finished scan; a socket error; a refused
  ticket; ten minutes of silence; a later phase's frame; a frame that is not
  JSON; elapsed time; unmounting;
- the hand-off — every automatic target and state, the route's pipeline mode
  outranking the record's, and View Results by pipeline and execution mode;
- Stop Scan (one request, busy while pending, cancelled after, a refused stop
  explained), Run in Background and New Scan;
- setup — titles and start labels per pipeline, quota and permission gating,
  quick targets, profiles, the settings dialog and every control in it, live
  port and exclusion validation, the scan estimate, the sensitive-port warning,
  the preview, stored credentials (loaded once, on first use), SNMP fields
  masked as they were, and the target-file reader (types, size, parsing,
  duplicates, invalid entries, removal, clearing, dismissal and the export).

An `afterEach` in every test allows only the dispatch, the ticket and the stop
as writes, only the scan record and the stored credentials as reads, and only
the progress URL as a socket.

**Harness.** The route guard does not block NewScan, and nothing starts on
`/scan/new` without a click. Three existing mechanisms carry the live states:

- **The dispatch.** `ns-dispatch` declares exactly
  `POST /scan/host-discovery`, answered with a fixed synthetic scan id, and the
  placeholder ticket. Every other write — Stop Scan among them — is still
  refused; no other `ns-` state declares a write.
- **The socket.** The existing `init` hook replaces `WebSocket` on NewScan's two
  routes only. The scripted socket records its URL and whether the page closed
  it, and delivers its frames in order, 40 ms apart; with none it stays open.
  Readiness asserts the socket's URL and state, and the host-listing states wait
  for the new-host highlight's 3-second clear.
- **A target file.** `ns-targets` and `ns-file-error` drop a synthetic in-memory
  file on the target field. The page reads it in the browser; nothing is
  uploaded.

What the harness cannot show, and where it is covered instead:

- **The Phase 3 hand-off.** The route guard throws on a navigation to a Phase 3
  route, and the page would report the throw as an exception. The unit tests
  pin the target and its state; `ns-handoff` captures the interactive hand-off
  to host discovery, which runs Phase1Results against what NewScan stored.
- **A real socket and ticket.** Frames are scripted and fixed, so a socket
  error, a refused ticket, ten minutes of silence and a frame that is not JSON
  are covered by the unit tests only; no handshake or ticket issuance is
  exercised.
- **Stop Scan** is reached by Tab only and never sent.
- **Typing.** The harness has no typing action: `ns-settings-audit` sets the
  SNMP version, the privacy protocol and a placeholder passphrase through the
  native value setter and an input event, which is what React listens to.

### 0.2 Corrections

Before the baseline, to the tests only — each an assumption about the legacy
page that the legacy page refuted, none to a pinned behaviour:

1. **The scan number.** The mission view shows it only when the route hands it
   over; the scan context offers no `ctxScanNo`, so entering by URL shows none.
   The test now asserts that.
2. **An unreachable scan that settled as complete** reads "Scan complete" in its
   footer and still offers View Results. Both are now what the test expects.
3. **A word boundary.** The preview's text runs straight on from "port" into
   the next label, so `\b` could not match; the test uses a negative lookahead.
4. **The ten-minute timeout test** read a record with no hosts, which is
   unreachable rather than complete; it now reads one with hosts.

One correction to the harness before the baseline:

5. **`ns-running` and `ns-mission-mobile` never became ready.** The legacy
   status badge is uppercased by CSS, and `innerText` reports the rendered case;
   the readiness test is now case-insensitive.

After migration, none to the page:

6. **Three specification tests named groups in sentence case**; the groups are
   named by their visible labels ("Discovery Profile", "Port Scan Intensity",
   "Scan Configuration Model"), and the tests now say so.
7. **The class-name test read template interpolations as class names**; it now
   drops them first.
8. **Prettier** reformatted the page, the stylesheet, the test and the harness
   files.

### 0.3 Harness changes

- **20 NewScan captures** in 18 states:
  - setup: `ns-setup` (both themes, with two keyboard probes),
    `ns-setup-asset`, `ns-setup-audit`, `ns-setup-mobile` (390 px), `ns-denied`
    (a persona without `scans:execute`) and `ns-quota` (the quota exhausted);
  - settings: `ns-settings` (asset, port-based, the IT profile and two excluded
    ports), `ns-validation` (three field errors) and `ns-settings-audit`
    (stored credentials, SNMP v3 with privacy, a placeholder passphrase typed);
  - target files: `ns-targets` (a list with a duplicate and an invalid entry)
    and `ns-file-error` (a `.zip`);
  - the scan: `ns-dispatch` (Start pressed, the scan followed to completion),
    `ns-running` (both themes) and `ns-mission-mobile` (390 px), `ns-failed`,
    `ns-unreachable`, `ns-cancelled` (settled by the 2.5-second read) and
    `ns-handoff` (an interactive asset scan handed over to host discovery).
- **Probes.** On `ns-setup`: a quick target by keyboard (Enter fills the target
  field) and advanced settings by keyboard (Enter opens them; Escape closes
  them). Stop Scan on `ns-running` and Try Again on `ns-failed` are reached by
  Tab only.
- **Fixtures are synthetic**: no host, scan, credential or output comes from a
  real system. Credentials are a name, an account and a port; the ticket is
  `harness-ticket`; the one passphrase typed is the low-entropy `notreal`.
- **`REGRESSION_PREFIXES`** now includes `p3-`, so Batch 24's captures are in
  the regression gate.
- The catalogue is now 131 states, 174 captures.

---

## 1. Files changed

| File                                                 | Change                                                                                                                                                       | LOC                         |
| ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- |
| `src/pages/scan/NewScan.jsx`                         | Design-system markup: labelled fields, switches, a radio group, toggle-button groups, a settings dialog, CcureTable, badges, alerts and a named progress bar | 2905 → 2758 (+1064 / −1211) |
| `src/styles/NewScan.css`                             | Rewritten in place, page-owned: 361 `--ccure-*` references, 0 colour literals, 0 other custom properties                                                     | 2873 → 1251 (+843 / −2465)  |
| `src/__tests__/pages/scan/NewScan.contract.test.jsx` | New: 107 contract + 10 batch 25                                                                                                                              | new, 2356                   |
| `scripts/ux4g-harness/lib/fixtures.mjs`              | Synthetic scan records, stored-credential references, the declared dispatch, a target list and the scripted socket                                           | +160                        |
| `scripts/ux4g-harness/lib/states.mjs`                | 18 `ns-` states; `p3-` in the regression prefixes                                                                                                            | +337 / −3                   |
| `docs/ux4g/03c-batch25-new-scan.md`                  | This document                                                                                                                                                | new                         |

| Measure                                                                 | Before                                                                                        | After                                  |
| ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | -------------------------------------- |
| Inline `style` attributes                                               | 46 (and 3 style objects)                                                                      | **0**                                  |
| Colour literals in the page                                             | 32 (16 hex, 16 `rgba`)                                                                        | **0**                                  |
| Legacy `var(--…)` references in the page                                | 7                                                                                             | **0**                                  |
| Legacy classes outside the page's own prefix (`am-*`, `muted`, `round`) | 81                                                                                            | **0**                                  |
| Hand-built buttons / selects / tables                                   | 24 / 5 / 1                                                                                    | **0 / 0 / 0**                          |
| Hover handlers painting a button                                        | 2                                                                                             | **0**                                  |
| `NewScan.css`                                                           | 2,873 lines, 59,368 bytes; 173 legacy variables, 294 colour literals, 36 dark-theme overrides | **1,251 lines, 28,704 bytes; 0, 0, 0** |
| Unlabelled controls (setup / settings open, audit)                      | 5 / 15                                                                                        | **0 / 0**                              |
| Failing text contrast pairs (setup, light / dark)                       | 5 / 3                                                                                         | **0 / 0**                              |
| Failing text contrast pairs (settings open, asset)                      | 22                                                                                            | **0**                                  |
| Tests                                                                   | 4                                                                                             | 121                                    |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change  |
| ----- | -------------- | ------------- | ------- |
| CSS   | 411,294        | 393,671       | −17,623 |
| JS    | 1,591,873      | 1,584,401     | −7,472  |

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures; the
unit tests cover the same points and the parts the harness cannot reach.

- **Every control is named.** Unlabelled controls, before → after: 5 → 0 on
  the setup view, 7 → 0 for an asset scan, 8 → 0 for an audit, 9 → 0 and 11 → 0
  with the asset settings open, 15 → 0 with the audit settings open. The
  glyph-only close button ("✕") is gone: 1–3 → 0 per capture.
- **Headings.** The mission view had none; it has an `h1` and an `h2` in each
  of its eight captures. The settings dialog is titled by an `h2`.
- **The settings are a modal dialog.** 0 → 1 dialog on each settings capture.
  The legacy drawer's controls stayed in the tab order while it was closed:
  tab stops on the setup view fall from 36 to 30 (38 → 32 at 390 px), and with
  the settings open from 48–54 to 14–21, because focus now stays in the dialog.
- **Mouse-only controls are gone.** The scan configuration cards were
  clickable elements with no role: 2 → 0 on each asset capture.
- **The imported target list** had no caption and 4 unscoped headers; it has a
  caption and 7 scoped headers — a column header for each column and a row
  header for each target.
- **Outcomes are announced.** An alert on the failed, cancelled and unreachable
  missions and on a refused file (0 → 1 each); the three field errors in
  `ns-validation` are each announced with their field.
- **Keyboard.** All four probes reach the same controls in both builds, and the
  two that press Enter pass in both. Configure Advanced Settings now shows a
  focus ring (ring 0 → 1).
- **Contrast.** Failing text pairs, before → after:

  | Capture                                        | Light                    | Dark  |
  | ---------------------------------------------- | ------------------------ | ----- |
  | Setup                                          | 5 → 0                    | 3 → 0 |
  | Asset / audit setup                            | 11 → 0 / 8 → 0           | —     |
  | Settings open: asset, validation errors, audit | 22 → 0, 19 → 0, 12 → 0   | —     |
  | Imported targets / refused file                | 25 → 0 / 6 → 0           | —     |
  | Without `scans:execute` / quota exhausted      | 5 → 0 / 5 → 0            | —     |
  | At 390 px: setup / mission                     | 6 → 0 / 11 → 0           | —     |
  | Dispatch followed to completion                | 10 → 0                   | —     |
  | Running                                        | 12 → 0                   | 4 → 0 |
  | Failed / unreachable / cancelled               | 10 → 0 / 12 → 0 / 11 → 0 | —     |

  Legacy defects now gone: the white status badges on the dark console header
  (1.45 to 2.18), the pipeline title and target on it (1.1, 2.56), the ring's
  percentage (1.0), the View Results and Start buttons (1.0), the icons inside
  fields (2.56 to 2.77), Save & Close (2.77) and the drawer's close glyph
  (2.45), the pipeline badge (2.4), the active profile (2.77), the error boxes
  (3.39 to 4.41), the outcome cards (4.22, 4.46), "Resolving…" and the hosts
  heading in the dark theme (3.88), and the sensitive-port warning (1.39,
  1.57).

- **Mobile.** No horizontal overflow at 390 px, before or after. The target
  field and its button stack; hosts list their name and MAC under the address.
- **No sensitive value in accessibility text.** Every `aria-label`, caption and
  group name is fixed text or a target address; a credential is named by its
  name and account, never a secret.
- **Measurement note.** The harness names headings from their text, which
  includes glyphs hidden from assistive technology ("h2:🖥 Discovered
  Systems"). The unit tests compute the accessible name, "Discovered Systems".

---

## 3. Security validation

### 3.1 The dispatch

One `POST /scan/host-discovery`, called with exactly the URL and the body, only
from Start, Enter in the target field or a route-requested start, and never
without `scans:execute` or a target:

| Pipeline   | Body, as pinned                                                                                                                                                                                                                                                             |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Every scan | `phases` and `pipeline_mode` from the pipeline; `targets` split on commas and trimmed; `scan_type: "adaptive"`; `execution_mode`                                                                                                                                            |
| Asset      | `discovery_intensity`; `port_scan_intensity`, or `"custom"` with `custom_ports` (the profile's list, or the custom text as typed); `os_detection`                                                                                                                           |
| Audit      | `os_detection`                                                                                                                                                                                                                                                              |
| Optional   | `exclude_ports` and `exclude_ips` trimmed; `rate_limit` as a number; `options.snmp` (v1/v2c: version and community; v3: user, auth protocol and passphrase, and privacy and context only when set) and `options.credentials` as `{credential_id}` references, in one object |

- **Nothing is sent when validation fails** — an empty or invalid port list, or
  invalid excluded ports or IPs — and the setup view stays up with the error.
- **One request per start**: Enter and a double click each send one; the view
  changes to the mission before the request settles.
- **In the harness**, the one dispatch is in `ns-dispatch` and nowhere else,
  and no `ns-` state sends any other write.

### 3.2 The ticket, the socket and polling

| Requirement                             | Evidence                                                                                                                                                                     |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. The intended socket                  | One socket at `/api/scans/{id}/progress?ticket=…`, ticket encoded; the `afterEach` rejects any other URL; in the harness, readiness asserts the URL in every mission capture |
| 2. Ticket acquisition unchanged         | `POST /auth/ticket` called with the URL alone, once, when a scan is followed; in the harness, once in each mission capture and in none of the setup captures                 |
| 3. No duplicate sockets or polls        | One ticket, one socket and one 2.5-second poll under StrictMode and across re-renders                                                                                        |
| 4. Terminal frames                      | `complete`, `failed`, `unreachable` or a later phase's frame closes the socket, stops polling and reads the record once; the record's status outranks the socket's           |
| 5. Errors and timeout                   | A socket error closes it and lets the record decide; ten minutes of silence closes it; a frame that is not JSON is ignored                                                   |
| 6. Polling                              | Every 2.5 s while following; a terminal status in the record settles the view; stopped by the socket settling, Stop Scan and New Scan                                        |
| 7. Stop Scan                            | One `POST /scans/{id}/stop`, busy while pending, cancelled after; a refused stop is explained and the scan stays running                                                     |
| 8. Hand-off                             | Completed asset or audit scans navigate by themselves (replace), with `startPhase: "PORT_SCAN"` for a one-host audit; View Results follows the context's pipeline            |
| 9. Unmount                              | Unchanged, and pinned as found (§7): unmounting stops neither the poll nor the socket                                                                                        |
| 10. Parsing and state updates unchanged | The progress, enrichment and host-list handling is in the byte-identical component body                                                                                      |

### 3.3 Credentials and SNMP

- **Stored credentials are references.** The list reads
  `GET /compliance/credentials` once, on first use; each entry shows a name and
  `account@:port`; the dispatch carries `credential_id` only. No secret is ever
  fetched or held for a credential.
- **SNMP passphrases** are `type="password"` fields in both builds, labelled
  "Auth Passphrase" and "Privacy Passphrase". A contract test types a
  placeholder into both and asserts it reaches neither the page's text nor a
  `title`, `aria-label` or `data-*` attribute; `ns-settings-audit` types
  `notreal` and it appears in no capture of the four reports.
- **The community string** is a plain text field that defaults to `public`, as
  before (§7).
- **Nothing is logged** except the pre-existing failed-credential-load message
  (§7). No reveal control, clipboard action or debug output was added.

### 3.4 Target files

- **Nothing is uploaded, and nothing is downloaded from the server.** NewScan
  has no upload or download endpoint: a `.txt` or `.csv` file (picked or
  dropped) is read with `FileReader` in the browser, and only the target strings
  it yields go into the dispatch, which the API re-validates.
- **Refused before reading:** another extension, an empty file, and a file over
  5 MB — each with its message, pinned.
- **Export Invalid** is a local `Blob` of the rejected entries, downloaded as
  `invalid_targets.txt`, its object URL revoked straight after.
- **In the harness**, the files are synthetic and in memory.

### 3.5 Permissions and navigation

- **The setup view still checks `scans:execute`**: without it every control that
  would start a scan is disabled, and Enter does nothing. `App.jsx` still mounts
  both routes behind the base sign-in check only (asserted from the source).
- **Navigation is unchanged:** Back to `/dashboard`; the mission to
  `/scan/active/{id}`; Run in Background to `/scan-history`; New Scan and Try
  Again to `/scan/new`; Compliance to `/compliance`; the hand-off and View
  Results as in §3.2.
- **Nothing new executes or leaves the site.** No new dependency.

---

## 4. Intentional changes

1. **Headings.** The setup view's `h1` is unchanged. The mission view gains an
   `h1`, "Active Mission", and an `h2`, "Discovered Systems", which were styled
   text; the settings dialog is titled by its `h2`; the configuration preview is
   an `h3`.
2. **Advanced settings is a modal dialog drawn as a side sheet.** The legacy
   drawer stayed in the page, off screen, while closed. The dialog is named
   "Advanced Settings", traps focus, renders its contents only while open, and
   closes with "Close settings", Save & Close, Escape or a click on its backdrop
   — the last through a page-local listener, because CcureModal's own outside
   click never fires (carried, §7). Every value lives in the page or the scan
   context, so closing it loses nothing.
3. **Every field has a label.** The target field is labelled "Target" and
   described by "IP, CIDR, or range"; the file picker is named "Target list
   file". In the settings, every text field and select is a CcureInput or
   CcureSelect with a visible label, and every checkbox and radio is named by
   its label. The icons inside fields are gone.
4. **Switches are switches.** Exclude Specific Ports, Exclude Specific IPs /
   Subnets, OS Detection, Authenticated Checks and Network Topology are native
   checkboxes with `role="switch"`, named by their titles and described by
   their hints.
5. **The scan configuration model is a radio group.** Its two cards were
   clickable `<div>`s that no keyboard could reach; they are labels for visible
   radios.
6. **Profiles are labelled groups of toggle buttons** stating the choice with
   `aria-pressed`: Discovery Profile, Scan Profile and Port Scan Intensity.
   Quick targets, port presets and quick exclusions are named groups.
7. **Errors are tied to their fields.** A port or exclusion error sets
   `aria-invalid` and describes its field, and is announced; an error on the
   setup view is a CcureAlert.
8. **The imported target list is a CcureTable** captioned "Imported targets",
   with scoped headers and the target as each row's header; each Remove button
   is named for its target, and the import summary's dismiss button is named.
9. **Excluded ports and a profile's ports are named lists.** Each excluded port's
   remove button is named for its port; a sensitive port says "(sensitive)" to
   assistive technology as well as being tinted.
10. **Warnings that describe the page are not announced; outcomes are.** The
    sensitive-port warning and the unreachable explanation are CcureAlerts that
    are not live regions. The mission's outcome — failed, cancelled or
    unreachable — is announced once.
11. **Progress** is a CcureProgress bar named "Scan progress", in place of an
    unnamed strip; the ring repeats the figure and is hidden from assistive
    technology. The status is a CcureBadge; the stats are a list; the hosts are
    a list named by their heading. Stop Scan reports that it is busy while the
    stop is pending.
12. **Stored credentials are a group** titled "Stored credentials".
13. **Buttons are CcureButton; badges are CcureBadge.** The pipeline badge, the
    discovery profile badges and the target types take badge variants rather
    than hand-written colours.
14. **Decorative glyphs are hidden** from assistive technology and stay on
    screen.
15. **Colours are tokens in both themes**, motion stops for anyone who asks the
    system for reduced motion, and the layout adapts below 640 px.

---

## 5. Retirement

- **`NewScan.css` is rewritten in place.** It kept its name because
  ScanQuotaBar's layout test holds the quota bar to `.ns-card`'s width, and that
  width is unchanged. It no longer carries a legacy `--bg-*` or `--text-*`
  variable, a colour literal, an `!important`, or a dark-theme copy of its rules.
- **The `am-*` classes, `muted` and `round` are gone from the page**, with the
  hand-built drawer, switches, toggles, segmented controls, inputs, selects,
  preview table and error boxes.
- **No stylesheet other than `NewScan.css` changed.** `scan.css` and the rest of
  the legacy chain are untouched and still used elsewhere.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-`
exits 0:

- All 154 unchanged-page captures are identical in every category, Batch 24's
  14 Phase3Results captures included.
- pre-b vs post-b is also 154 / 154.
- Post determinism (post-a vs post-b) is 174 / 174.
- 155 of 174 captures are identical overall: the 154, and `ns-handoff`, which
  ends on Phase1Results and so renders the same page in both builds. The other
  19 NewScan captures changed.

Every changed category on those 19 captures is accounted for:

| Category                                         | Captures | Why it changed                                                                                                                              |
| ------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| headings                                         | 10       | The mission's `h1` and `h2`; the settings dialog's `h2` and the preview's `h3`                                                              |
| roles                                            | 19       | Named groups, switches, the radio group, the dialog, alerts, and the mission's progress bar                                                 |
| names, tabOrder                                  | 12, 12   | Labelled fields and switches, named buttons; the closed drawer's controls leaving the tab order, and focus kept in the open dialog          |
| live, ariaStates                                 | 5, 5     | Announced outcomes and field errors; `aria-pressed`, `aria-invalid` and `aria-busy`                                                         |
| dialogs                                          | 3        | The settings dialog, on each settings capture                                                                                               |
| clickable                                        | 3        | The scan configuration cards, now radios                                                                                                    |
| probes                                           | 2        | `ns-setup` (both themes): the settings button's focus ring                                                                                  |
| tables                                           | 1        | The imported target list's caption and scoped headers                                                                                       |
| contrast                                         | 19       | 0 failing pairs on every NewScan capture                                                                                                    |
| inline, classes, styles, rects, text, screenshot | 19       | The restyle. The only inline styles left are meter and progress widths: the shell's, the quota bar's, and on the mission the progress bar's |
| requests, writes, url, runtime, overflow         | —        | **Unchanged**: requests and writes identical, and every capture on its expected route                                                       |

Screenshots were reviewed side by side for all 20 captures: setup in both
themes and at 390 px, the asset and audit setups, the settings open (asset,
validation errors, audit with credentials and SNMP v3), imported targets and a
refused file, the page without permission and with the quota exhausted, and the
mission — dispatched to completion, running (both themes and 390 px), failed,
unreachable, cancelled, and handed over.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — all kept exactly, and pinned where marked:

- **A refused ticket reads a still-running scan as complete.** No socket opens,
  polling stops at once, and the record's `running` falls through to
  "complete" — so a completed asset or audit pipeline hands over to the next
  phase. (pinned)
- **Ten minutes of socket silence, or a frame for a later phase, does the
  same**: the record is read once and a `running` scan is reported complete.
  (pinned)
- **Unmounting stops neither the 2.5-second poll nor the socket** — nor the
  new-host and route-start timers. (pinned)
- **A scan settled by polling, Stop Scan or New Scan leaves its socket open**
  until its own frame or the timeout. (pinned)
- **An asset scan that found no live host still hands over** to asset
  discovery. (pinned)
- **The scan number is shown only when the route hands it over**; the scan
  context has no `ctxScanNo`. (pinned)
- **A failed credential load logs the raw error object** to the console. An
  axios error carries its request configuration, Authorization header included.
  (pinned)
- **With no stored credentials, every switch-on asks again.** (pinned)
- **A failed dispatch leaves the pipeline state at DISCOVERY.**
- **The mission view checks no permission**: anyone who opens
  `/scan/active/:id` is offered Stop Scan.
- **The SNMP community string is a plain text field** defaulting to `public`.
- **The rate limit accepts any integer**, negative included.
- **The route-requested start (`autoRun`) has no caller.**
- **`setParsedExcludePortsCount` is written and never read.**
- **Harness:** see §0.1 — scripted frames, the Phase 3 hand-off, Stop Scan and
  typing. The shell's `/api/notifications/stream` is unstubbed, as before.

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
- Phase3Results: unmounting neither aborts the pipeline nor closes the socket;
  `waitForPhase`'s 20-minute timer is never cleared; a scan stopped elsewhere
  can stay visibly running; a non-JSON frame can throw; the audit is sent the
  port-scan results when both are held; a refused stop's raw error logging; an
  authorization failure labelled "Vulnerability Audit"; the 4-second indicator
  timers are not cleared; `setExpanded` is never read; the page checks only
  `scans:execute`; an unknown severity reads "Unscored"; the page-local
  CcureModal outside-click workaround.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was
reached:

- the dispatch — endpoint, method, payload and its one request per start — is
  unchanged and pinned, and no mount, remount or StrictMode render sends a
  second scan;
- the ticket, the socket, the 2.5-second read, the ten-minute timeout, Stop
  Scan and the automatic hand-off are unchanged and pinned, and nothing else is
  written;
- stored credentials remain references, SNMP passphrases remain masked, and no
  passphrase, ticket or secret reaches the page's text, an attribute, the
  console or a harness report;
- the target file is still read in the browser and never uploaded;
- permissions and navigation are unchanged;
- no write, no unexpected navigation, no off-origin request, no CSP issue, no
  exception and no console error in any capture;
- determinism, sensitivity and the regression gate over every previously
  migrated page, Phase3Results included, passed;
- security headers and the air-gap host set are identical;
- no shared component, design-system primitive or global stylesheet was
  modified.

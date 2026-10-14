# Checkpoint 3C — Batch 26A: ComplianceWorkspace's Exceptions tab on the design system

ComplianceWorkspace (`/compliance`) is one 6,094-line page holding eight tabs
behind a shared header, framework selector, tab bar and error banner. Most of
the tabs write — installs, policies, attestations, remediation requests,
credentials, approvals — and three poll. Batch 26A moves **one read-only tab,
Exceptions**, onto the design system and leaves the rest of the page exactly as
it was.

**Why Exceptions.** It is the only tab whose whole behaviour is one read:

| Tab                 | What it does beyond reading                                      | In 26A  |
| ------------------- | ---------------------------------------------------------------- | ------- |
| Dashboard           | Report downloads, the gap-analysis dialog, polling during a scan | No      |
| Marketplace         | Install and uninstall (POST)                                     | No      |
| Policies            | Create a policy (POST)                                           | No      |
| Controls            | The attestation dialog and its writes                            | No      |
| Findings            | Remediation requests (POST), polling                             | No      |
| **Exceptions**      | **Nothing: one GET, paged in the browser**                       | **Yes** |
| Credentials Manager | Password fields, create and delete (POST, DELETE)                | No      |
| Approvals Queue     | Approve and reject (POST), polling                               | No      |

The batch is presentation and accessibility only, and the rest is pinned:

- **Everything outside the tab is the code that was here.** Removing exactly
  what Batch 26A added — `useId`, two imports, `ExceptionsPanel` — and restoring
  the legacy render block yields HEAD's page byte for byte (6,094 lines). All 48
  request, console, pagination, scroll, navigation and timer call sites occur
  in the same order.
- **The read, unchanged:** opening the tab — and changing the framework or a
  scoping filter while it is open — sends one
  `GET /compliance/findings?status=pending&limit=10000`, with the header's
  `framework_id` and scoping parameters appended.
- **Paging, unchanged:** the same `useClientPagination` instance, 25 rows by
  default, 10 / 25 / 50 / 100 per page, back to page 1 when data arrives or the
  size changes, first and last page, and the list scrolled into view on a page
  change.
- **Failure, unchanged:** the workspace's shared error banner with the API's
  detail, and the shared loader's `console.error`.
- **Permissions, unchanged:** `/compliance` sits behind the base sign-in check
  only, and the tab renders the same for an analyst and an organisation admin.

**Baseline:** HEAD `6102d04` (Batch 25).

**Not touched:**

- The other seven tabs; the page header, the framework selector, the tab bar,
  the error banner and the loading bar; `fetchTabData`, the polling effects,
  `PaginationBar` and `useClientPagination`.
- `dashboard.css`, `compliance.css`, `scan.css` and the rest of the legacy CSS
  chain — the other tabs still use every class the Exceptions tab used.
- `App.jsx`, AppLayout, `api/axiosInstance.js`, every design-system primitive,
  CcureModal and every other page.
- The backend, `nginx.conf`, CSP, `scripts/host-nginx/nginx-host.conf`,
  `package.json` and the lockfile.
- The harness's core: `run.mjs`, `router.mjs`, `guard.mjs`, `compare.mjs` and
  `sensitivity.mjs` are unchanged. The `cw26a-` states use no opt-in at all —
  no ticket, declared write, `init` script or seeded session.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `6102d04`                                                                                                                                                                                                                                                                                               |
| Tests first, on the legacy page             | 21 tests: the 15 contract tests pass, and the 6 batch 26A tests all fail, each for its intended reason (no "Exceptions" heading, no named pagination, no stylesheet import)                                                                                                                                                   |
| Trial replay, unchanged build               | The 10 Exceptions captures (`cw26a-` and `cw-exceptions`) taken twice: **10 / 10** identical; 0 refused writes, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors; both keyboard probes reached, with a focus ring. The served bundle was shown to carry none of the Batch 26A code                                  |
| Baseline, unchanged build                   | 182 captures ready, twice. Determinism **182 / 182**, sensitivity **22 / 22**                                                                                                                                                                                                                                                 |
| Same tests, migrated                        | **15 / 15** contract tests and **6 / 6** batch 26A tests on the first run, with no correction to either                                                                                                                                                                                                                       |
| Logic unchanged                             | Outside the tab the page is byte-identical to HEAD's once the four additions are removed; the 48 call sites are in the same order                                                                                                                                                                                             |
| Full frontend suite                         | 59 files, **2234** tests, all passing (2213 + 21)                                                                                                                                                                                                                                                                             |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                           |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                                                                             |
| Pre-commit formatting                       | Every Batch 26A file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                   |
| Post determinism                            | post-a vs post-b **182 / 182** identical                                                                                                                                                                                                                                                                                      |
| Unchanged states                            | AssetRegistry, VulnerabilityBrowser, SecurityDashboard, Phase2Results, Phase1Results, AMTIntegration, NetworkMap, ScanHistory, CredentialedResults, Phase3Results, NewScan, and ComplianceWorkspace's other seven tabs: **172 / 172** captures identical pre → post in every category, on both capture pairs                  |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                   |
| Exceptions requests                         | Identical before and after in every Exceptions capture (0 deltas), in all four reports: one `GET /api/compliance/findings?limit=10000&org_id=o-1&status=pending` per capture — in `cw26a-framework` one with `framework_id=cfw_nist_csf_v2` and none without. Paging, the page-size focus and the keyboard probe send nothing |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any Exceptions capture                                                                                                                                                                                                      |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines)                                                                                                                                                                                                                              |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                                                                                  |
| Writes, navigations, off-origin, CSP issues | 364 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every Exceptions capture ends on `/compliance` in all four reports                                                              |
| Screenshots                                 | All 10 Exceptions captures reviewed side by side, pre and post. No regression                                                                                                                                                                                                                                                 |

### 0.1 The Exceptions tab in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.exceptions.test.jsx` mounts the real
page with only the axios instance, the shell and the signed-in user replaced.
Its `afterEach` fails any test in which anything was posted, put, patched or
deleted, or in which any read other than the marketplace, a summary or pending
findings was sent.

**The contract (15 tests, passing on the legacy page and after):**

- The read: not before the tab opens, exactly once when it does, again on each
  re-opening; a selected framework appended, and a framework change or a PCI
  scoping filter while the tab is open reading again with it.
- The list: control, asset or `Global`, the evidence note before the reason
  before a dash, and status, under the four legacy column headers; the empty
  message for an empty list and for a response with no list; identical rows for
  an analyst and an organisation admin.
- Paging: 25 at a time over 60 waivers; Next, Previous, first and last; the
  "Showing" summary and "Page X of Y"; sizes 10 / 25 / 50 / 100 and back to
  page 1 on a change; the list scrolled into view with
  `{ behavior: "smooth", block: "start" }`; page 1 again after a re-read; paging
  disabled while a read is in flight.
- A failed read: the shared banner with the API's detail, the loader's
  `console.error("Failed to load compliance data", err)`, and the empty list.
- The route: `/compliance` behind the base sign-in check only.

The paging helpers accept either spelling of first and last (`«` / `»` or
"First page" / "Last page") and of previous (`Prev` / `Previous`), so the same
tests run on both builds. The axios instance is mocked, so the tests pin the
URL the page builds; the harness sees it with the instance's `org_id` appended.

**The specification (6 tests, each failing on the legacy page for its intended
reason):** a section named by its `h2`; a captioned table with scoped column
headers and a row header per waiver; the status as a badge; a named pagination
landmark with a live page status, a labelled page size and named first and last
page buttons; placeholder rows and a "Loading results" announcement while
reading, instead of claiming nothing is pending; no inline style or legacy class
inside the tab; and a token-only, prefix-scoped stylesheet.

**Harness states (5 states, 8 captures),** all on `/compliance` as an analyst,
none pressing anything that writes:

| State             | Themes, viewport | What it shows                                                                          |
| ----------------- | ---------------- | -------------------------------------------------------------------------------------- |
| `cw26a-populated` | light, dark      | Three waivers covering note, reason, dash and Global; focus on the page-size selector  |
| `cw26a-paged`     | light, dark      | Sixty waivers, Next clicked; then Tab to Next and Enter reaches page 3                 |
| `cw26a-loading`   | light, dark      | The read held open for the whole capture                                               |
| `cw26a-mobile`    | light, 390 px    | The populated tab on a phone                                                           |
| `cw26a-framework` | light            | NIST CSF 2.0 chosen in the header's selector first, so the read carries `framework_id` |

The existing `cw-exceptions` state (both themes) is the empty tab. There is
deliberately **no failed-read state**: the workspace reports a failed read with
`console.error` on every build, which the harness counts as a console error; the
unit tests pin that path.

### 0.2 Corrections

No assertion in the contract or the specification was changed. Three things
were, none of them a gate:

- **The specification's source check normalises line endings.** The checkout is
  CRLF, and the migrated page is written LF, as the repository stores it and as
  the pages migrated before it already are. On the legacy page the test failed
  on the missing stylesheet import before reaching that line either way.
- **The first unchanged-build replay never ran.** Its image built from the clean
  tree, but Windows reserves port 3301 (an excluded port range), so nothing could
  serve it and the trial captures were stopped. The same image was then served
  on 3291 without a rebuild — the tree had changed by then — after its web root
  was shown to carry none of the Batch 26A code and the legacy empty message.
- **The first full-suite run, taken mid-batch, failed once** in AMTIntegration's
  "a rejected upload shows the API's detail or a default" — the load flake
  recorded since Batch 24. The file passed alone (47 / 47), and the final run
  passed 2234 / 2234.

---

## 1. Files changed

| File                                                          | Change                                                                                                          | LOC                      |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------ |
| `src/pages/ComplianceWorkspace.jsx`                           | `ExceptionsPanel` and its render call; `useId`, the design-system import and the tab's stylesheet import        | 6094 → 6153 (+115 / −56) |
| `src/styles/compliance-exceptions.css`                        | New, page-owned: 15 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector `cwx-` | new, 71                  |
| `src/__tests__/pages/ComplianceWorkspace.exceptions.test.jsx` | New: 15 contract + 6 batch 26A                                                                                  | new, 638                 |
| `scripts/ux4g-harness/lib/fixtures.mjs`                       | Synthetic pending waivers: three, and sixty                                                                     | +39                      |
| `scripts/ux4g-harness/lib/states.mjs`                         | 5 `cw26a-` states; `ns-` in the regression prefixes                                                             | +102 / −3                |
| `docs/ux4g/03c-batch26a-compliance-exceptions.md`             | This document                                                                                                   | new                      |

In the tab:

| Measure                                                   | Before                                                                | After                                 |
| --------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------- |
| Inline `style` attributes                                 | 3                                                                     | **0**                                 |
| Legacy classes                                            | 7 (`db-card`, `db-table-wrap`, `db-table`, `db-status` ×2, `mono` ×2) | **0**                                 |
| Hand-built tables / pagination bars                       | 1 / 1                                                                 | **0 / 0**                             |
| Headings / captions                                       | 0 / 0                                                                 | **1 / 1**                             |
| Scoped header cells (populated)                           | 0 of 4                                                                | **7 of 7** (4 columns, 3 row headers) |
| Glyph-only buttons                                        | 2 (`«`, `»`)                                                          | **0**                                 |
| Unlabelled controls                                       | 1 (the page-size select)                                              | **0**                                 |
| Failing text contrast pairs, populated (light / dark)     | 7 / 7                                                                 | **0 / 0**                             |
| Failing text contrast pairs, sixty waivers (light / dark) | 29 / 29                                                               | **0 / 0**                             |
| Status regions                                            | 0                                                                     | **2** (page status, table status)     |
| Tests                                                     | 0                                                                     | 21                                    |

Across the whole page, inline style attributes are 308 → 305, `db-` class
references 147 → 142, hand-built tables 8 → 7 and `PaginationBar` uses 5 → 4.

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 393,671        | 394,557       | +886   |
| JS    | 1,584,401      | 1,584,841     | +440   |

---

## 2. Accessibility

1. **The tab is a named region.** A `section` labelled by its own `h2`,
   "Exceptions" — the page's first real heading; the page title above it is
   still a `div` (§7).
2. **The table has an accessible name and structure.** The caption "Pending
   exceptions and waivers", `scope="col"` on the four headers, and the control
   ID as each row's header.
3. **Paging is a named landmark.** "Exceptions pagination", with "Page X of Y"
   in a polite live region, so a screen-reader user hears the rows change
   without focus moving.
4. **Every control is named.** The page size is a labelled "Rows per page"
   select; `«`, `Prev`, `Next` and `»` are "First page", "Previous", "Next" and
   "Last page", the first and last in a group named "Jump to page".
5. **Loading is announced, not misreported.** Placeholder rows and a "Loading
   results" status replace the legacy table's "No pending exceptions or waivers
   recorded." while a read is in flight; when it lands the status reads the
   count.
6. **The status is text in a badge**, not colour alone.
7. **Keyboard.** Every control is a native button or select in document order,
   with the design system's focus ring. The harness focuses the page-size select
   by Tab and pages with Enter on Next, in both builds and both themes, and
   records a visible ring each time. While a read is in flight the page-size
   select is disabled, so it leaves the tab order (26 → 25 stops).
8. **Colour and layout** are `--ccure-*` tokens in both themes, with 0 failing
   text pairs inside the tab. Disabled paging buttons use the design system's
   disabled colours, which the harness records separately and WCAG exempts.
   Below 640 px the paging stacks and wraps; at 390 px the table scrolls inside
   its own named, keyboard-reachable region, and the document never overflows
   horizontally in either build.

Both 390 px captures, pre and post, show the workspace shifted sideways. The
shared tab bar does not wrap and is wider than a phone, so the content area
scrolls horizontally, and the harness's click on the Exceptions tab scrolls that
tab into view (§7).

---

## 3. Security and API behaviour

| Requirement                   | Evidence                                                                                                                                                                                             |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Endpoint, method, parameters  | One `GET /compliance/findings?status=pending&limit=10000`, with `framework_id` and scoping parameters appended as before; pinned in tests, and in the harness once per capture with 0 request deltas |
| Response handling             | `res.data.data \|\| []`, in the byte-identical `fetchTabData`                                                                                                                                        |
| No writes                     | The tab has no control that writes. 0 posts, puts, patches or deletes in any test; 0 refused writes in any harness capture                                                                           |
| Polling                       | None, before or after: the tab is read when opened or when its framework or filters change                                                                                                           |
| Filtering, paging, navigation | Unchanged and pinned (§0.1); the tab never navigates                                                                                                                                                 |
| Permissions                   | Unchanged: the base sign-in check; no role changes what the tab shows                                                                                                                                |
| Logging                       | No logging added. The one `console.error` on a failed read is the shared loader's, unchanged (§7)                                                                                                    |
| Sensitive data                | The tab renders control and asset identifiers, a reason and a status. No credential, token or ticket is read or rendered; no `dangerouslySetInnerHTML`; no placeholder secret in any harness report  |
| External assets               | None: no CDN, external font or UX4G runtime, and no `ux4g-` class or selector. The post web root references the same 7 hosts as the pre, with 0 external `<link>`, `<script>`, `@import` or `url()`  |

---

## 4. Intentional changes

1. **Layout.** A design-system panel with its own heading replaces the `db-card`
   with the pagination bar welded to the table's top edge.
2. **Paging controls.** `«`, `Prev`, `Next` and `»` become "First page",
   "Previous", "Next" and "Last page". CcurePagination has no first or last
   control, so those two sit beside it as a page-local adapter.
3. **Empty summary.** "No waivers found" becomes "Showing 0–0 of 0 waivers"; the
   empty message in the table is unchanged.
4. **The page-size select is disabled while a read is in flight**, like the
   buttons; the legacy select stayed enabled.
5. **Loading.** Placeholder rows replace the table body while a read is in
   flight, where the legacy table kept the previous rows or claimed nothing was
   pending.
6. **Status** is an info badge rather than a `db-status--queued` pill.
7. **Heading, caption, landmark and live status** are added (§2).

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                      | Why it is not in 26A                                                                       |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Dashboard                                                 | Report downloads and the gap-analysis dialog; polls while a scan runs                      |
| Marketplace, Policies                                     | Install, uninstall and create writes                                                       |
| Controls                                                  | The attestation dialog and its writes                                                      |
| Findings                                                  | Remediation requests; polling                                                              |
| Credentials Manager                                       | Password fields; create and delete                                                         |
| Approvals Queue                                           | Approve and reject; polling                                                                |
| Header, framework selector, tab bar, error banner, loader | Shared by all eight tabs; changing them changes every tab's captures at once               |
| `PaginationBar`, `useClientPagination`                    | Still used by four tabs; the hook is shared with the migrated tab and stays byte-identical |
| `dashboard.css`, `compliance.css`, `scan.css`             | Every class the tab used is still used by another tab                                      |

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-dashboard,cw-marketplace,cw-policies,cw-controls,cw-findings,cw-credentials,cw-approvals,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- All 172 unchanged captures are identical in every category — the other seven
  ComplianceWorkspace tabs in both themes and Batch 25's 20 NewScan captures
  included.
- pre-b vs post-b is also 172 / 172.
- Post determinism (post-a vs post-b) is 182 / 182.
- The 10 Exceptions captures changed.

`cw-exceptions` is named out of the identical list because it is the Exceptions
tab; every other ComplianceWorkspace state is named in it.

Every changed category on those 10 captures is accounted for:

| Category                                         | Captures | Why it changed                                                                                                                                                      |
| ------------------------------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| names                                            | 10       | The labelled page size and the named paging buttons; the glyph-only buttons gone                                                                                    |
| headings                                         | 10       | The tab's `h2`                                                                                                                                                      |
| roles, live                                      | 10, 10   | The "Jump to page" group, the page status and the table status; at 390 px the table's scroll region                                                                 |
| tables                                           | 10       | The caption, scoped column headers and row headers; while loading, three placeholder rows                                                                           |
| tabOrder                                         | 5        | Sixty waivers (both themes): the renamed paging buttons in their new order; loading (both themes): the disabled page-size select; 390 px: the table's scroll region |
| contrast                                         | 10       | 0 failing text pairs inside the tab; the shared header's button and the tab bar's active label remain (§7)                                                          |
| inline, classes, styles, rects, text, screenshot | 10       | The restyle. The 21 inline styles left on every capture belong to the shell, the shared header and the tab bar                                                      |
| requests, writes, url, runtime, overflow         | —        | **Unchanged**: requests and writes identical, and every capture on `/compliance`                                                                                    |

Screenshots were reviewed side by side for all 10 captures: the empty tab and
three waivers in both themes, sixty waivers on page 2 in both themes, loading in
both themes, three waivers at 390 px, and three waivers under NIST CSF 2.0.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — all kept exactly, and pinned where marked:

- **The tab bar is eight `div`s with click handlers.** No `tablist`, no tab
  roles, no `tabIndex` and no key handling: a keyboard user cannot change tabs
  at all, and so cannot reach Exceptions without a mouse. It also does not wrap,
  so on a phone the content area scrolls sideways. Shared by every tab.
- **The page title "Policy Compliance" is a `div`**, so the page has no `h1`.
- **The header's Framework and Gap Source selects are unlabelled** for assistive
  technology; the words beside them are not associated.
- **Two shared text pairs fail contrast:** the header's "Run Compliance Scan"
  button and, in light, the tab bar's active label (both 2.77:1).
- **A failed read logs the raw error object**
  (`console.error("Failed to load compliance data", e)`). An axios error carries
  its request configuration, Authorization header included. Shared by every
  tab's loader. (pinned)
- **A failed re-read leaves the previous list on screen** beside the error
  banner: nothing clears `exceptions` at the start of a read or on failure.
- **One `loading` flag serves every tab**, and a quiet poll on another tab never
  sets it.
- **`limit=10000` and client-side paging:** every pending finding is fetched to
  show 25, and anything past 10,000 is silently absent.
- **`framework_id` and the scoping values are interpolated into the query
  string unencoded.** Today they are catalogue constants and fixed option
  values.
- **The list is never refreshed** while the tab stays open. The tab also reads
  pending _findings_ and calls them waivers; whether every pending finding is a
  requested exception is a backend question this batch does not answer.
- **Harness:** no failed-read state (§0.1); the framework state drives the
  selector through its value setter and a `change` event, because a script click
  cannot open a native select.

**Carried:** every item deferred by Batches 16 to 25 stands unchanged — the
global, AMT, NetworkMap, ScanHistory, CredentialedResults, Phase3Results,
NewScan and shared CcureModal items recorded in `03c-batch25-new-scan.md` §7 —
and none was reopened here.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was
reached:

- the Exceptions read — endpoint, method, parameters, response handling and its
  one request per opening — is unchanged and pinned, and nothing on the tab
  writes;
- filtering, client-side paging, the page-size reset, the scroll on a page
  change, the failure path and permissions are unchanged and pinned;
- outside the tab the page is byte-identical to the legacy page, and no other
  tab, shared component, design-system primitive or global stylesheet was
  modified;
- no credential, token, ticket or placeholder secret reaches the page, the
  console or a harness report, and no logging was added;
- no write, no unexpected navigation, no off-origin request, no CSP issue, no
  exception and no console error in any capture;
- determinism, sensitivity and the regression gate over every previously
  migrated page and ComplianceWorkspace's other seven tabs passed;
- security headers and the air-gap host set are identical.

Batch 26B is not started.

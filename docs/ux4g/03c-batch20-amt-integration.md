# Checkpoint 3C — Batch 20: AMT integration off dashboard.css

AMTIntegration is the AMT inventory and coverage reconciliation page
(`/admin/amt`, behind `assets:update`). It shows how the organisation's AMT
inventory lines up with what scanning found, lists each category's assets or
inventory records, exports them as CSV, and imports a new inventory file.

**The import replaces the organisation's AMT inventory.** This batch is
therefore presentation and accessibility only:

- **Primitives:** CcureCard, CcureButton, CcureInput, CcureTable, CcureAlert,
  CcureBadge, CcureLoader and CcureEmptyState.
- **Stylesheet:** a token-only `amt-integration.css` replaces the 16 classes
  the page borrowed from the global `dashboard.css` and `scan.css`, and the 107
  inline style objects.
- **Keyboard and screen-reader access:** the categories and the coverage
  summary are buttons with pressed state, the file input is named and
  reachable, the filters are labelled, the table has a caption and scoped
  headers, and failures and progress are announced.
- **The logic is the code that was here.** The statistics load, the drilldown
  with its filters and paging, the CSV export and the import — its file checks
  and messages, the multipart `file` field, and what follows success and
  failure — are byte-identical (§3).

**Baseline:** HEAD `b5692b9` (Batch 19). Batch 20 is uncommitted.

**Not touched:**

- NetworkMap, ScanHistory, CredentialedResults, Phase3Results, NewScan,
  ComplianceWorkspace, Phase1Results, Phase2Results, AuditLogs,
  RoleManagement, AssetRegistry, SecurityDashboard and every other page.
- ScanContext, ScanStepper, ExportPanel, ScanQuotaBar, CVELink, RiskBadge, the
  Toast and Modal shims, and every design-system primitive.
- `global.css`, `scan.css`, `animations.css`, `dashboard.css`, `NewScan.css`,
  `NetworkMap.css`, `compliance.css`.
- The harness's capabilities (no text entry, file input or download driving
  added), `api/*`, the backend, CSP and nginx.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                           |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `b5692b9`                                                                                                                                                                                                                                                  |
| Tests first, on the legacy page             | 47 new tests: the 33 contract tests pass, the 14 Batch 20 tests all fail, each for its intended reason                                                                                                                                                                           |
| Trial of the AMT states, unchanged build    | 11 captures ready; 0 writes, 0 blocked navigations, 0 off-origin, 0 CSP issues, 0 exceptions, 0 console errors. The first attempt did not start (§0.1)                                                                                                                           |
| Baseline, unchanged build                   | 104 captures ready. Determinism **104 / 104**, sensitivity **22 / 22**                                                                                                                                                                                                           |
| Same tests, migrated                        | **47 / 47**                                                                                                                                                                                                                                                                      |
| Corrections during migration                | 2, both in the page (§0.2)                                                                                                                                                                                                                                                       |
| Logic unchanged                             | The 190 lines from the component's opening to the render section are byte-identical to the legacy page apart from one added `useId()`                                                                                                                                            |
| Full frontend suite                         | 54 files, **1783** tests, all passing (1736 + 47)                                                                                                                                                                                                                                |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                              |
| Build                                       | `vite build` succeeds                                                                                                                                                                                                                                                            |
| Pre-commit formatting                       | Every Batch 20 file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                       |
| Post determinism                            | post-a vs post-b **104 / 104** identical (the second pass taken alone, §0.2)                                                                                                                                                                                                     |
| Unchanged pages                             | AssetRegistry, VulnerabilityBrowser, ComplianceWorkspace, SecurityDashboard, Phase2Results and Phase1Results: **93 / 93** captures identical pre → post in every category, on both capture pairs                                                                                 |
| Sensitivity on the migrated build           | **22 / 22** (run alone, §0.2)                                                                                                                                                                                                                                                    |
| AMT requests                                | Identical before and after in every AMT capture except the overview's keyboard probe, which can now reach Shadow IT and sends the same drilldown read a click sends (§6). 0 import and 0 export requests in any report; the denied persona calls no AMT endpoint                 |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/admin/amt` included (42 header lines)                                                                                                                                                                                  |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                                     |
| Writes, navigations, off-origin, CSP issues | 208 post captures: 0 refused writes, 0 blocked Phase 3 navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every AMT capture ends on `/admin/amt`, the denied persona on `/dashboard` |
| Screenshots                                 | All 11 AMT captures reviewed side by side, pre and post. One regression found and fixed (§0.2); none in the final build                                                                                                                                                          |

### 0.1 The first trial did not start

Chrome still held `DevToolsActivePort` open when the runner read it, and
Windows answered `EBUSY`. No capture ran and no report was written. The same
command, unchanged, then ran cleanly; the harness was not modified.

### 0.2 Corrections during migration

1. **A test query found the caption too.** One contract test failed on the
   first migrated build: "selecting the open category again closes the
   drilldown". Its query for the "Total Scanned Devices:" category label found
   two elements, because the new table caption read "Total Scanned Devices" as
   well. Nothing the page does had changed. The page was corrected, not the
   test: the caption now carries the count, "Total Scanned Devices (23)",
   exactly like the card heading above it.
2. **An amber count failed contrast.** The first post-migration capture
   measured the Shadow IT count, amber text on the card surface, at 3.85:1 in
   the light theme. It was the only failing pair left on the page. The three
   toned counts (Fully Audited, Shadow IT, Coverage Gap) became badges, whose
   own tinted ground passes in both themes. The tests, lint, build and full
   suite were re-run, the post image was rebuilt, and every post gate below is
   from that rebuilt image.

**The second post capture pass was repeated.** While the rebuilt image was
being captured, a second capture of the same image was started by mistake and
overlapped the first run's second pass and its sensitivity run. Every gate in
both overlapping runs passed, but runs that share the machine and the output
directory prove nothing, so all of them were set aside. The second pass,
determinism, both regression diffs and sensitivity were then repeated with
nothing else running. The pre-migration baseline and the first post pass had
each run alone and were kept.

### 0.3 Harness changes

Fixtures and states only. No capability was added.

- **11 AMT captures:**
  - `amt-overview` (both themes), with a keyboard probe that opens Shadow IT
    and one that only Tabs to the file input;
  - `amt-drilldown` (both themes), with probes that Tab to an asset link and to
    Export CSV, and one that turns to page 2;
  - `amt-drilldown-mobile` (390 px), `amt-drilldown-empty`,
    `amt-drilldown-error`;
  - `amt-unlinked` (no inventory imported) and `amt-error` (both themes);
  - `amt-denied`: a persona without `assets:update`, which the route sends to
    `/dashboard`.
- **Safety rules.** No action or probe activates the drop zone or the file
  input (either opens the native file chooser), Upload & Sync or Export CSV.
  The file-input, asset-link and Export probes Tab to their control and press
  nothing. Opening a category and turning a page are reads. Validation and
  import behaviour that needs a real file is covered by the unit tests.
- **Fixtures** use the backend's field names: the seven keys of
  `/assets/coverage-stats` and `_serialize_asset` rows from the reconciliation
  drilldown. The router matches paths, not query strings, so one drilldown
  answers every category and page.
- **`REGRESSION_PREFIXES`** now includes `p1-`.

---

## 1. Files changed

| File                                                | Change                                                                                                                 | LOC        |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------- |
| `src/pages/admin/AMTIntegration.jsx`                | Design-system primitives, headings, buttons with pressed state, labelled filters and file input, alerts, table caption | 1316 → 775 |
| `src/styles/amt-integration.css`                    | **New**, tokens only (108 `--ccure-*` references), 0 colour literals                                                   | 440        |
| `src/__tests__/pages/admin/AMTIntegration.test.jsx` | **New**, 47 tests (33 contract + 14 Batch 20)                                                                          | —          |
| `scripts/ux4g-harness/lib/{fixtures,states}.mjs`    | §0.3                                                                                                                   | —          |

| Measure                                  | Before                                                       | After                   |
| ---------------------------------------- | ------------------------------------------------------------ | ----------------------- |
| Classes borrowed from global stylesheets | 16 (`dashboard.css` 14 `db-*`, plus `data-table` and `mono`) | **0**                   |
| Inline `style` attributes                | 107                                                          | **0**                   |
| Colour literals in code                  | 34 (15 hex, 19 rgb)                                          | **0**                   |
| Level-one headings                       | 0                                                            | 1                       |
| Click-only elements                      | 7 (five categories, the coverage ring, the drop zone)        | **0**                   |
| Labelled filter and file inputs          | 0 of 5                                                       | **5 of 5**              |
| Tables with a caption and scoped headers | 0 of 1                                                       | **1 of 1** (CcureTable) |
| Tests                                    | 0                                                            | 47                      |

**Bundle impact.**

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 371,029        | 377,842       | +6,813 |
| JS    | 1,627,019      | 1,618,514     | −8,505 |

The CSS grows because the page stylesheet is added while `dashboard.css` still
ships for ComplianceWorkspace. The JS shrinks because 107 inline style objects
and the colour table are gone.

---

## 2. Accessibility

"Before" and "after" are the pre-build and post-build harness captures, and the
unit tests cover the same points.

- **The page had no level-one heading.** Its title was a styled `<div>` and
  its card titles were `h3` and `h4`. It now has one `h1`, and each card title
  is an `h2`.
- **The reconciliation panel could not be used from a keyboard.** The five
  categories, the coverage ring and the drop zone were `<div>`s with click
  handlers, and the file input was `display: none`: 7 pointer-only targets on
  every capture with a linked inventory (1, the drop zone, where none is
  linked). After: 0.
  - The categories and the coverage summary are buttons with `aria-pressed`.
    The keyboard probe that could not reach Shadow IT before reaches it by
    name and opens its drilldown.
  - The file input is reachable and named "AMT inventory file (.json)", and
    its focus ring is drawn on the zone. No probe activates it.
- **The filters had no names:** 4 unlabelled controls on every drilldown
  capture. After: 0, each with a visible label.
- **The table had no name.** It is CcureTable, with a caption naming the
  category and its count and `scope="col"` on every header. At 390 px it
  scrolls inside its card as a named, focusable region.
- **Failures were silent.** A failed statistics load, a refused or failed
  upload and a failed drilldown are alerts; the upload confirmation and the
  drilldown's loading state are status messages.
- **Shadow IT and Coverage Gap were explained only in a hover tooltip.** The
  explanation is now each button's accessible description.
- **Contrast.** Failing text pairs, before → after:

  | Capture                | Light  | Dark  |
  | ---------------------- | ------ | ----- |
  | Overview               | 9 → 0  | 1 → 0 |
  | Drilldown              | 18 → 0 | 8 → 0 |
  | Drilldown at 390 px    | 18 → 0 | —     |
  | Empty drilldown        | 9 → 0  | —     |
  | Failed drilldown       | 11 → 0 | —     |
  | No inventory linked    | 4 → 0  | —     |
  | Failed statistics load | 6 → 0  | 0 → 0 |

  Legacy defects now gone:

  - the failed-load alerts measured 1.66 (statistics) and 1.73 (drilldown);
  - the Shadow IT count 1.87, "72%" 2.15, "Linked & Active" 2.27, the Fully
    Audited count 2.54 and the CMDB Best Practices heading 2.38;
  - the guidance list 4.45, the asset links 3.68 in light and 3.98 in dark,
    and the "78 (high)" risk chip 3.5 in dark.

- **Keyboard.** Tab stops rise because controls became reachable: 23 → 30 on
  the overview (the six buttons and the file input), 35 → 42 with a drilldown
  open, 36 → 44 at 390 px (with the table's scroll region), and 23 → 24 where
  no inventory is linked (the file input). The asset link, Export CSV and Next
  probes reach the same controls, with a visible focus ring, before and after.
- **390 px.** No horizontal overflow before or after, but the legacy layout
  kept both columns side by side and clipped the import card to a sliver of
  text. The migrated page stacks.
- Disabled controls below the contrast threshold (exempt; recorded so the
  number is not a surprise): Upload & Sync with no file chosen, at 1.69, on
  every capture, where the legacy page drew it at 2.77 and styled it as
  enabled; plus Previous on page one of a drilldown, or Export CSV on an empty
  one, each counted twice by the harness, for its label and its hidden glyph.
  That makes 1 entry before and 3 after on the drilldown captures.

---

## 3. Security validation

- **The import is unchanged, and pinned on the legacy page first.** The logic
  block is byte-identical, and the contract tests run the real `api/assets.js`
  against a mocked axios instance, so they assert what leaves the application:
  - `POST /assets/import-amt`, once, only when the form is submitted — never
    on selecting or dropping a file, never on mount;
  - a `FormData` body whose only field is `file`, holding the chosen file, with
    `Content-Type: multipart/form-data`;
  - the checks and their exact messages: `.json` in any letter case, not empty,
    16 MB or less (exactly 16 MB accepted), applied to a dropped file as well as
    a picked one;
  - success clears the file, shows the confirmation and reloads statistics
    1.5 seconds later and not before; a response without `success` shows its
    `detail` or "Import failed." and keeps the file; a rejected request shows
    the API's `detail` or "An error occurred during file upload.";
  - Upload & Sync is disabled with no file and while uploading, and cannot send
    twice.
- **No confirmation was added or removed**, and the replace-inventory semantics
  are the backend's, untouched.
- **The export is unchanged:** the same drilldown endpoint with the category and
  set filters, never the page, plus `export: true` and `responseType: "blob"`;
  a `text/csv` Blob saved as `amt_${category}_export.csv`; no request without a
  selected category; disabled while exporting, loading, or with no rows.
- **The drilldown is unchanged:** the category, optional filters only when set,
  `skip`/`limit` in tens, one request per keystroke, a reset to page one and
  empty filters on changing category, closing without a request, and the same
  columns, fallbacks and `/assets/{id}` links for hostname and IP.
- **RBAC is unchanged.** `App.jsx` still mounts the page once, behind
  `PrivateRoute requiredPermission={{ resource: "assets", action: "update" }}`
  (asserted from the source), and the real PrivateRoute keeps a user without
  `assets:update` off the page with nothing requested. The harness's denied
  persona ends on `/dashboard` and never calls an AMT endpoint.
- **The harness never imported, exported or wrote.** No state or probe
  activated the file chooser, Upload & Sync or Export CSV; the file-input,
  asset-link and Export probes only Tab to their control. No capture in any
  report requested `/assets/import-amt` or an export, and no capture made a
  refused write.
- **Nothing new executes or leaves the site.** No new dependency and no
  `dangerouslySetInnerHTML`. Security headers and the air-gap host set are
  identical, with 0 external references.

---

## 4. Intentional behaviour changes

1. **The categories and the coverage summary are buttons.** They were
   `<div>`s with click handlers. Each carries `aria-pressed`, and the selected
   one has a bar beside it as well as a tint. Hover styling comes from CSS
   rather than mouse-event handlers.
2. **The file input is visually hidden instead of `display: none`**, so it is
   in the tab order and named "AMT inventory file (.json)". The drop zone is its
   `<label>`, so a click anywhere on the zone opens the chooser as before; a
   drop is still handled by the same code.
3. **Filters have visible labels** above them. Placeholders are unchanged.
4. **Upload & Sync uses CcureButton's loading state** while the request is
   sent: the same "Uploading & Syncing..." text, marked busy. The condition
   that disables it is unchanged.
5. **Messages are CcureAlert.** Load, upload and drilldown failures are
   alerts; the upload confirmation is a status. The ⚠ and ✔ glyphs come from
   CcureAlert's icon.
6. **Loading and empty drilldowns are CcureLoader and CcureEmptyState**, and
   the "CMDB Integration Inactive" panel is an empty state (a paragraph, where
   it was an `h4`).
7. **Headings:** an `h1` for the page title (a styled `<div>` before); `h2` for
   each card title (Import, Reconciliation Status, CMDB Best Practices and the
   drilldown), which were `h3` and `h4`.
8. **"Linked & Active", risk, status and the toned counts are badges.** Risk
   keeps its bands (red from 70, amber from 40); status keeps its active /
   in-use test. The Fully Audited, Shadow IT and Coverage Gap counts, which were
   coloured numbers, are green, amber and red badges; the two plain counts stay
   plain.
9. **The Shadow IT and Coverage Gap explanations reach assistive technology**
   as the button's description. The ℹ tooltip stays for pointer users.
10. **The table is CcureTable**, with a visually hidden caption naming the
    category and its count, and it scrolls inside its card on a narrow screen.
11. **Arrow and emoji glyphs are hidden** from assistive technology: ↻, 📁, 🛡,
    ℹ, 📥, ◀ and ▶. Button names are the words.
12. **Colours are tokens in both themes**, and the layout stacks below 1100 px
    and again below 640 px.

---

## 5. Retirement

- **No stylesheet is removed.** AMTIntegration no longer uses `dashboard.css`,
  which ComplianceWorkspace still imports. Two shared components still match a
  `dashboard.css` selector: CVELink (`cve-id`) and CcureTabs (`active`).
- `scan.css` has 14 consumers, down from 15.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-,sd-,p2-,p1-` exits
0:

- All 93 unchanged-page captures are identical in every category.
- pre-b vs post-b is also 93 / 93.
- Post determinism (post-a vs post-b) is 104 / 104.
- 94 of 104 captures are identical overall. The 10 that render the page
  changed; `amt-denied` is identical, because that persona never mounts it.

Every changed category on those 10 captures is accounted for:

| Category                                         | Captures              | Why it changed                                                                                                                                                                                                              |
| ------------------------------------------------ | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| names, headings, roles, ariaStates, live         | 10, 10, 4, 7, 3       | §2: labelled filters and file input, `h1`/`h2`, `aria-pressed`, alert regions, the scroll region at 390 px                                                                                                                  |
| tables                                           | 3                     | Caption and scoped headers on the captures with rows                                                                                                                                                                        |
| clickable                                        | 10                    | Pointer-only targets 7 → 0 (1 → 0 where no inventory is linked)                                                                                                                                                             |
| contrast                                         | 10                    | 0 failing pairs on every AMT capture                                                                                                                                                                                        |
| tabOrder                                         | 10                    | The category and summary buttons and the file input became stops                                                                                                                                                            |
| probes                                           | 2                     | On the overview, the file input and Shadow IT are reached after and were unreachable before                                                                                                                                 |
| requests                                         | 2                     | The overview only. The category probe's Enter now reaches Shadow IT and sends `GET /assets/reconciliation/drilldown?category=shadow_it&skip=0&limit=10`, the read a click sends, which `amt-drilldown` makes in both builds |
| inline, classes, styles, rects, screenshot, text | 10, 10, 10, 10, 10, 9 | The restyle and the new labels. The only inline styles left are the shell's quota bars, identical on every page; legacy `db-*` elements 10–15 → 0                                                                           |
| writes, url, runtime                             | —                     | **Unchanged**                                                                                                                                                                                                               |

Screenshots were reviewed side by side for all 11 captures. One regression was
found and fixed before the final capture: the amber Shadow IT count failed
contrast in the light theme (§0.2).

A measurement note: on the empty and failed drilldown captures the legacy
page's recorded tab order stopped after one stop, where the captures with rows
recorded 35. The migrated page records 34 on both.

---

## 7. Deferred, and found but not fixed

- **The import has no confirmation step**, although it replaces the
  organisation's AMT inventory. Adding one is a product decision this batch was
  told not to make.
- **`assets:update` on the route is the page's only permission check.** Anyone
  who may edit assets may replace the whole inventory; there is no narrower
  permission for the import.
- **A failed export is silent.** It is logged to the console; the operator sees
  the button return and no file.
- **The export's object URL is never revoked** (pinned as found).
- **Statistics reload a fixed 1.5 seconds after an import**, whether or not the
  background reconciliation has finished, so the figures shown may still be the
  previous inventory's.
- **Every keystroke in a filter sends a drilldown request**, and filter values
  are sent untrimmed.
- **A failed statistics load also shows "No active inventory file linked" and
  "CMDB Integration Inactive"**, which reads as "never imported" rather than
  "could not load".
- **The Department column shows the record's company name.**
- **Asset links are full page loads** (`<a href>`), not router links; they were
  kept exactly because the links are an invariant.
- **The drilldown page size is fixed at 10.**
- **Harness:**
  - no file-input, download or text-entry driving, so the import, the export
    and the filters are covered by the unit tests only;
  - the router ignores query strings, so one drilldown fixture answers every
    category and page;
  - Chrome's `DevToolsActivePort` can still be locked when the runner reads it
    (§0.1), and the runner does not retry.
- **Carried:**
  - CcureTable does not contain its visually hidden caption (contained at card
    level again); CcureAlert's danger icon is a cross;
  - the Toast and Modal shims;
  - CVELink (`cve-id`) and CcureTabs (`active`) still match `dashboard.css`
    selectors;
  - the shared page-frame classes; AssetRegistry's legacy `modal-*` classes;
    AuditLogs rows without "View Changes" open their details by pointer only;
  - from batches 15 to 19: ScanContext's duplicate GET, the `cc_executionMode`
    reset, polling that never times out, Phase 3's automatic start,
    ExportPanel's CSV formula injection and the truncated custom port list.

---

## 8. Result

**GO for review.** Every gate passed on the final build, and no STOP condition
was reached:

- the import's endpoint, method, multipart `file` field, checks and messages,
  success and failure handling and the 1.5-second reload are unchanged and
  pinned; no confirmation was added or removed;
- the export's endpoint, parameters, blob handling, MIME type and filename are
  unchanged, and there is still no export without a category;
- the drilldown's requests, paging, asset data and asset links are unchanged;
- `assets:update` still gates the route;
- no write, no import or export request, no opened file chooser, no unexpected
  navigation, and no Phase 3 route in any capture;
- security headers and the air-gap host set are identical;
- no shared component, design-system primitive or global stylesheet was
  modified.

Nothing from Batch 20 is committed, and no Batch 21 work has started.

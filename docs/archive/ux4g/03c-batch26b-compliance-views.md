# Checkpoint 3C — Batch 26B: ComplianceWorkspace's read-only views on the design system

Batch 26A moved ComplianceWorkspace's Exceptions tab. Batch 26B moves the four
tabs that belong to the same risk class — **Dashboard, Controls, Policies and
Findings** — together. None of them writes: every write reachable from them
sits behind a dialog, and the dialogs, the shared dialog container, the header,
the tab bar, the page-wide scan trigger, Marketplace, Approvals, Credentials and
Exceptions are untouched.

The batch is presentation and accessibility only, and the rest is pinned:

- **Everything outside the four views is the code that was here.** Removing
  exactly what Batch 26B added — five design-system imports, the stylesheet
  import and three page-local helpers — restoring the unused `Skeleton` helper
  and putting the four legacy render blocks back yields HEAD's page byte for
  byte (6,153 lines).
- **Everything inside them that decides anything is unchanged.** 102 logic
  fragments occur in the new blocks, whitespace aside:

  - the report URL and filename builder and the quick downloads;
  - the NIS 2 fine ceiling and both framework-title ternaries;
  - the controls search and status handlers, and the control-number formatter;
  - the Configure payload, every filter and the Clear Filters reset;
  - the finding buttons' conditions and handlers.

  Each block's handler call sites are the same multiset as before.

- **Reads, unchanged:**

  - the workspace summary and, for All Frameworks, each active framework's;
  - `GET /compliance/frameworks/{id}/controls` (ISO 27001 for All Frameworks),
    with `search` on Enter and `status` at once;
  - `GET /compliance/policies` and, on expansion,
    `/compliance/policies/{id}/rules`;
  - `GET /compliance/findings?limit=10000`.

  Each carries the header's framework and scoping parameters as before.

- **Downloads, unchanged:** the same report URLs and filenames, fetched as array
  buffers and saved through an object URL.
- **Polling, unchanged:** a quiet read of the findings every 5 seconds while any
  finding is `pending_reverify`, `queued` or `running`, stopping on leaving the
  tab.
- **Dialog openers, unchanged:** Attest, Configure, Remediate, Waiver, Verify
  and Edit Rule keep their visibility conditions and only open the existing
  dialogs.

**Baseline:** HEAD `376b8e6` (Batch 26A).

**Not touched:**

- Marketplace, Approvals, Credentials Manager and Exceptions; the page header,
  the framework and scoping selectors, the tab bar, the error banner, the loading
  bar and the Run Compliance Scan trigger.
- The shared legacy dialog container and every dialog in it:
  - create policy and edit rule;
  - waiver;
  - attestation, with evidence upload and delete;
  - remediation and rollback;
  - gap analysis and the log viewer.
- `fetchTabData`, the polling effects, `handleDownloadReport`, every handler,
  `PaginationBar` and `useClientPagination`.
- `dashboard.css`, `compliance.css`, `scan.css`, `compliance-exceptions.css`
  and the rest of the legacy CSS chain.
- `App.jsx`, AppLayout, `api/axiosInstance.js`, every design-system primitive
  and every other page.
- The backend, `nginx.conf`, CSP, `scripts/host-nginx/nginx-host.conf`,
  `package.json` and the lockfile.
- The harness's core. The `cw26b-` states use no opt-in — no ticket, declared
  write, `init` script or seeded session.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                                                                               |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Clean start                                 | `git status` empty at `376b8e6`                                                                                                                                                                                                                                                                                                                                                      |
| Tests first, on the legacy page             | 52 tests: the 40 contract tests pass, and the 12 batch 26B tests all fail, each for its intended reason                                                                                                                                                                                                                                                                              |
| Trial replay, unchanged build               | The 25 captures of the four views (`cw26b-` and the four `cw-` states) taken twice: **25 / 25** identical and every one clean — ready, every action succeeded, 0 writes, off-origin requests, CSP issues, exceptions or console errors. The unchanged image carries none of the Batch 26B code                                                                                       |
| Baseline, unchanged build                   | 199 captures ready, twice. Determinism **199 / 199**, sensitivity **22 / 22**                                                                                                                                                                                                                                                                                                        |
| Same tests, migrated                        | **40 / 40** contract tests and **12 / 12** batch 26B tests on the first run; Exceptions' **21 / 21** unchanged                                                                                                                                                                                                                                                                       |
| Logic unchanged                             | Outside the four views the page is byte-identical to HEAD's; 102 logic fragments inside them unchanged; each view's handler call sites the same                                                                                                                                                                                                                                      |
| Full frontend suite                         | 60 files, **2286** tests, all passing (2234 + 52)                                                                                                                                                                                                                                                                                                                                    |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                                                                                  |
| Build                                       | `vite build` succeeds; its chunk-size warning predates this batch                                                                                                                                                                                                                                                                                                                    |
| Pre-commit formatting                       | Every Batch 26B file passes the repository's Prettier 3.2.5                                                                                                                                                                                                                                                                                                                          |
| Post determinism                            | post-a vs post-b **199 / 199** identical                                                                                                                                                                                                                                                                                                                                             |
| Unchanged states                            | AssetRegistry, VulnerabilityBrowser, SecurityDashboard, Phase2Results, Phase1Results, AMTIntegration, NetworkMap, ScanHistory, CredentialedResults, Phase3Results, NewScan, Batch 26A's Exceptions captures, and ComplianceWorkspace's Exceptions, Marketplace, Credentials and Approvals tabs: **174 / 174** captures identical pre → post in every category, on both capture pairs |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                                                                          |
| View requests                               | Identical before and after in every view capture, in all four reports, apart from the one expected addition (§6). No capture reads a report, stored credentials, evidence or a scan run                                                                                                                                                                                              |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any view capture                                                                                                                                                                                                                                                                   |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines)                                                                                                                                                                                                                                                                                     |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts. 0 external `<link>`, `<script>`, `@import` or `url()` references                                                                                                                                                                                                                                                         |
| Writes, navigations, off-origin, CSP issues | 398 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every view capture ends on `/compliance` in all four reports                                                                                                                           |
| Screenshots                                 | All 25 view captures reviewed side by side, pre and post. Two layout defects found and fixed (§0.2); no regression on the final build                                                                                                                                                                                                                                                |

### 0.1 The four views in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.views.test.jsx` mounts the real page
with only the axios instance, the shell and the signed-in user replaced. Its
`afterEach` fails any test in which:

- anything was posted, put, patched or deleted;
- any read fell outside the known set;
- the stored credentials were read by anything but the remediation dialog.

Downloads are caught at the anchor's `click`; no file is ever saved.

**The contract (40 tests, passing on the legacy page and after):**

- **Dashboard (12).**
  - The opening read order: the marketplace, the summary, then each active
    framework's summary.
  - A chosen framework reads only its own summary and shows its theme
    breakdown.
  - Scores, KPIs and the comparison; the empty comparison; nothing shown until
    the summary arrives.
  - Reports:
    - the menu;
    - the Statement of Applicability for the selected framework;
    - Word, with the content-type fallback when the server sends none;
    - the NIST CSF profile and the executive briefing;
    - PCI-DSS and NIS 2 scoping parameters;
    - the four quick downloads;
    - "Generating..." and a reported failure.
  - The NIS 2 ceiling for both entity types and two turnovers, sending nothing.
- **Controls (6).**
  - The register read (ISO 27001, or the chosen framework).
  - Search on Enter only, trimmed and encoded; the status choice reading at
    once.
  - Every column and the summary tiles.
  - The empty message, and its absence while loading.
  - Attest opening the dialog and reading only that control's evidence.
- **Policies (7).**
  - The baselines read and its framework narrowing; the columns and the empty
    message.
  - Expansion reading the rules once, with every rule column including the
    control-number formatter; collapse reading nothing; one expansion at a time.
  - Loading, empty and failed rules.
  - Configure opening the rule dialog without collapsing or reading.
  - 25 per page.
- **Findings (15).**
  - The read and its framework narrowing; every column; the buttons per status.
  - Browser-side filters, their summary and Clear Filters; the CIS
    implementation-group filter.
  - Loading; 50 per page and the reset on a filter change.
  - Remediate, Waiver, Verify and Edit Rule each opening their dialog and
    reading only what that dialog reads.
  - Polling with fake timers for each of the three re-checking states, and none
    without one.

**The specification (12 tests, each failing on the legacy page for its intended
reason):**

- **Dashboard:** headed cards, KPIs as terms, a labelled report menu, a
  pressed-button format group, a quick-downloads group, named progress bars and
  a labelled turnover field.
- **Controls:** a labelled search and status, a captioned register with scoped
  headers, row headers and status badges, and loading announced.
- **Policies:** a named disclosure button for each baseline with
  `aria-expanded` and `aria-controls`, a captioned rules table, and a named
  pagination landmark.
- **Findings:** labelled filters, a captioned table with severity badges, a
  named pagination landmark, and loading announced.
- **Presentation:** no inline style or legacy class inside any of the four
  views, and a token-only, prefix-scoped stylesheet.

**Harness states (12 states, 17 captures),** all on `/compliance` as an analyst.
None clicks a download, submits or opens a dialog, or touches Marketplace,
Approvals or Credentials. No fixture finding is re-checking, so nothing polls:

| State                       | Themes, viewport | What it shows                                                                          |
| --------------------------- | ---------------- | -------------------------------------------------------------------------------------- |
| `cw26b-dashboard`           | light, dark      | Scores in two bands, the KPIs, the reports card and the comparison by framework        |
| `cw26b-dashboard-framework` | light, dark      | NIST CSF 2.0 chosen: the six Functions' breakdown                                      |
| `cw26b-dashboard-nis2`      | light            | NIS 2 offered and chosen: the fine calculator and the incident-reporting tracker       |
| `cw26b-dashboard-mobile`    | light, 390 px    | The dashboard on a phone                                                               |
| `cw26b-controls`            | light, dark      | Five controls, one per status, and the summary tiles                                   |
| `cw26b-controls-mobile`     | light, 390 px    | The register on a phone                                                                |
| `cw26b-policies`            | light, dark      | Two baselines, the first expanded to its rules                                         |
| `cw26b-policies-mobile`     | light, 390 px    | Tab to the first baseline's disclosure and Enter expands it                            |
| `cw26b-findings`            | light, dark      | Four findings covering fail, manual review and pass, reboot, Unknown host and no asset |
| `cw26b-findings-filtered`   | light            | The status filter set to Fail: two of four                                             |
| `cw26b-findings-loading`    | light            | The findings read held open                                                            |
| `cw26b-findings-mobile`     | light, 390 px    | The findings on a phone                                                                |

The existing `cw-dashboard`, `cw-controls`, `cw-policies` and `cw-findings`
states are the same tabs with the regression sweep's thin fixtures.

### 0.2 Corrections

No contract assertion was changed. These were, and none of them is a gate:

- **One specification assertion asserted nothing** (a count compared with
  `>= 0`); it was replaced before migration with the severity badges' text.
- **The patch script stopped itself** on its first run: a landmark it requires
  exactly once in the legacy Dashboard block also appears in a code comment. It
  wrote nothing; the landmark was made unique and it ran clean.
- **ESLint found the page-local `Skeleton` helper unused.** The legacy Findings
  table was its only consumer, so the helper was removed; the logic check
  restores it when reducing the page to HEAD's.
- **The logic check itself was corrected twice.**
  - It did not know the Findings tab's opening line gains `(`.
  - Seven of its fragments were bounded so that legacy inline styles fell inside
    them. They were narrowed to the logic alone; none of them had changed.
- **The pre-build marker check matched once**, on the legacy placeholder
  "Search controls…", which the new search field keeps. None of the new
  captions, labels or the `cwv-` prefix appear in the unchanged image.
- **The first migrated build passed every gate, but its screenshots failed
  review.** Two layout defects, both introduced by this batch:

  - At 390 px the report menu's `flex: 1 1 18rem` became an 18rem-tall blank
    gap once the report controls stacked into a column. The basis is now reset
    in the narrow layout.
  - The Controls search and status sat in the card header's fixed-width actions
    slot, where they stacked on a desktop and squeezed the card's heading into a
    narrow column on a phone. The two fields moved into the card body as a row,
    like the Findings filters.

  The whole post-migration flow was then run again on the corrected build, and
  the figures in this document are from that run. That flow covers formatting,
  lint, the focused tests, the logic check, the full suite, the build, the post
  image, both capture passes, determinism, regression, sensitivity, headers, the
  air gap and the analysis.

- **That second run stopped at its unit gates once**, on AMTIntegration's "a
  rejected upload shows the API's detail or a default". That is the load flake
  recorded since Batch 24, in a file this batch does not touch, and it had
  passed in the first run. The gate did its job and ran no captures. The file
  passed alone (47 / 47), and the flow was run again from the start with every
  gate passing.

---

## 1. Files changed

| File                                                     | Change                                                                                                                                                                       | LOC                         |
| -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| `src/pages/ComplianceWorkspace.jsx`                      | The four views' render blocks; `PagingControls`, `SCORE_TONE` and `NIST_FUNCTION_BADGE`; five design-system imports and the stylesheet import; the unused `Skeleton` removed | 6153 → 5514 (+1039 / −1677) |
| `src/styles/compliance-views.css`                        | New, page-owned: 135 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector under `cwv-`                                                       | new, 502                    |
| `src/__tests__/pages/ComplianceWorkspace.views.test.jsx` | New: 40 contract + 12 batch 26B                                                                                                                                              | new, 1605                   |
| `scripts/ux4g-harness/lib/fixtures.mjs`                  | Synthetic summaries, a NIS 2 marketplace, controls, baselines, rules and findings                                                                                            | +194                        |
| `scripts/ux4g-harness/lib/states.mjs`                    | 12 `cw26b-` states; `cw26a-` in the regression prefixes                                                                                                                      | +194 / −5                   |
| `docs/ux4g/03c-batch26b-compliance-views.md`             | This document                                                                                                                                                                | new                         |

In the four views (Dashboard / Controls / Policies / Findings where split):

| Measure                                               | Before                                                      | After                          |
| ----------------------------------------------------- | ----------------------------------------------------------- | ------------------------------ |
| Inline `style` attributes                             | 128 (45 / 21 / 25 / 37)                                     | **0**                          |
| Colour literals                                       | 59 (51 hex, 8 `rgba`)                                       | **0**                          |
| `dashboard.css` and `compliance.css` class references | 94                                                          | **0**                          |
| Hand-built tables / buttons / selects                 | 4 / 14 / 6                                                  | **0 / 0 / 0**                  |
| Legacy pagination bars / skeleton blocks              | 2 / 8                                                       | **0 / 0**                      |
| Hover handlers painting a row                         | 2                                                           | **0**                          |
| Headings                                              | 6 at level 3 and 3 at level 4; none on Policies or Findings | **8 at level 2, 3 at level 3** |
| Captioned tables                                      | 0 of 4                                                      | **4 of 4**                     |
| Render lines                                          | 709 / 257 / 358 / 532                                       | **448 / 197 / 229 / 278**      |
| Tests                                                 | 0                                                           | 52                             |

Measured in the harness, pre → post, light theme:

| Capture                     | Failing text pairs | Unlabelled controls | Glyph-only buttons | Scoped header cells |
| --------------------------- | ------------------ | ------------------- | ------------------ | ------------------- |
| `cw26b-dashboard`           | 7 → 2              | 3 → 2               | 0 → 0              | —                   |
| `cw26b-dashboard-nis2`      | 10 → 2             | 7 → 5               | 0 → 0              | —                   |
| `cw26b-controls`            | 15 → 2             | 4 → 2               | 0 → 0              | 0 of 8 → 13 of 13   |
| `cw26b-policies` (expanded) | 22 → 2             | 3 → 2               | 2 → 0              | 0 of 15 → 21 of 21  |
| `cw26b-findings`            | 25 → 2             | 7 → 2               | 2 → 0              | 0 of 7 → 11 of 11   |

What remains in every one of those columns belongs to the shared chrome, not to
the views:

- **Failing text pairs:** the header's "Run Compliance Scan" button and, in
  light, the tab bar's active label (both 2.77:1).
- **Unlabelled controls:** the header's framework and scoping selects.

Dark captures end at one failing pair, the same button.

Across the whole page:

| Measure                 | Before | After |
| ----------------------- | ------ | ----- |
| Lines                   | 6,153  | 5,514 |
| Inline style attributes | 305    | 176   |
| Colour literals         | 87     | 28    |
| Hand-built tables       | 7      | 3     |
| `PaginationBar` uses    | 4      | 2     |

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 394,557        | 402,468       | +7,911 |
| JS    | 1,584,841      | 1,576,094     | −8,747 |

---

## 2. Accessibility

1. **Every view is named.** The Dashboard's cards and the Control Register are
   `CcureCard` sections named by their headings; Policies and Findings are
   sections named by an `h2`. The NIS 2 calculator and tracker are `h3` cards
   inside the breakdown.
2. **Every table has a name and structure** — "Control register", "Baseline
   policies", "Rules in {baseline}" and "Compliance findings" — with scoped
   column headers and a row header per row.
3. **A baseline expands from a button.** The legacy row was a clickable `tr`
   with hover painting and no keyboard access. The disclosure is a native button
   named by the baseline, reporting `aria-expanded` and, while open,
   `aria-controls` pointing at its rules. In the harness, Tab reaches it with a
   visible focus ring and Enter expands it.
4. **Every control is labelled.** These now have associated labels:

   - the report menu;
   - the controls search and status;
   - the four findings filters;
   - the NIS 2 turnover field.

   The format choice is a group of pressed buttons, and the quick downloads are
   a named group.

5. **Scores are progress bars with names** — each framework's or theme's — and
   the numbers beside them are the numbers the API returned, not rounded.
6. **Loading is announced**, not misreported. The register, baselines and
   findings show placeholder rows and a "Loading results" status, instead of an
   empty message or nothing.
7. **Status and severity are text in badges**; colour repeats them.
8. **Paging is a named landmark** with a live page status, a labelled page size
   and named first and last page buttons, as on Exceptions.
9. **Colour and layout:**
   - Everything is `--ccure-*` tokens in both themes, with 0 failing text pairs
     inside the views.
   - Below 640 px the filters, report controls and paging stack.
   - Wide tables scroll inside their own named, keyboard-reachable region.
   - No capture overflows horizontally, before or after.

---

## 3. Security and API behaviour

| Requirement              | Evidence                                                                                                                                                                                                                                                                                                                      |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Endpoints and parameters | Every read pinned in tests with its exact URL. In the harness the view captures' compliance reads are the marketplace, the summaries, the ISO 27001 register, the baselines, one baseline's rules and the findings — before and after, with 0 unexpected deltas                                                               |
| Response handling        | In the byte-identical `fetchTabData` and handlers                                                                                                                                                                                                                                                                             |
| Downloads                | The URL builder, the four quick downloads, `responseType: "arraybuffer"` and the object-URL save are unchanged and pinned. The harness never clicks one, and no capture reads a report                                                                                                                                        |
| No writes                | No control in the four views writes. 0 posts, puts, patches or deletes in any test; 0 refused writes and 0 non-GET requests beyond the session refresh in any harness capture                                                                                                                                                 |
| Dialogs                  | Each opener only opens its dialog. The tests read back exactly what the dialog itself reads: evidence for attestation, stored credentials for remediation, nothing for waiver and rule. No dialog is submitted                                                                                                                |
| Credentials              | Read only by the remediation dialog, in one test; never in the harness                                                                                                                                                                                                                                                        |
| Polling                  | Unchanged: 5-second quiet reads while a finding is re-checking, pinned with fake timers                                                                                                                                                                                                                                       |
| Permissions              | Unchanged: no role check in the four views, before or after                                                                                                                                                                                                                                                                   |
| Logging                  | None added; the page's five `console` calls are the same                                                                                                                                                                                                                                                                      |
| Sensitive data           | No token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any view capture; no `dangerouslySetInnerHTML`                                                                                                                                                                                      |
| External assets          | None: no CDN, external font or UX4G runtime. There is no `.ux4g-` selector or `ux4g-` class in either bundle; the 1,332 `--ux4g-*` token properties are the design system's, identical before and after. The post web root references the same 7 hosts as the pre, with 0 external `<link>`, `<script>`, `@import` or `url()` |

---

## 4. Intentional changes

1. **Dashboard.**
   - The three score cards are headed cards; the gradient-clipped scores are
     token colours by the same bands.
   - The KPIs are a description list.
   - The report menu is labelled "Report"; PDF and Word are a pressed-button
     group; the download icon is hidden from assistive technology.
   - The comparison and theme bars are named progress bars.
   - The six NIST CSF Function colours are badge variants.
   - The NIS 2 cards are nested cards, and the turnover label is associated.
2. **Controls.**
   - A card with a labelled search and status row above the summary tiles, which
     are now a description list.
   - Loading shows placeholder rows and "Loading results" in place of "Loading
     controls…".
3. **Policies.**
   - A section headed "Policies".
   - A baseline expands from its name button rather than from anywhere on the
     row.
   - Paging follows the Exceptions arrangement:
     - named buttons;
     - "Showing 0–0 of 0 policies" when empty;
     - the page size disabled while loading.
   - The empty message is not shown while the list loads.
   - A rule with no severity still reads "Medium", now in the medium colour
     rather than the informational one.
4. **Findings.**
   - A section headed "Findings", with the filter labels in sentence case.
   - The summary keeps "(filtered from N total)", but reads "Showing 0–0 of 0 …"
     instead of "No findings match your filters".
   - A status other than pass or fail is an informational badge.
   - A finding with no severity reads "Medium", as before, in the medium colour.
   - An unrecognised severity reads "Unscored" instead of its raw text.
5. **Status pills and tags are badges** throughout, and the "Reboot Required"
   marker keeps its tooltip.

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                                          | Why it is not in 26B                                             |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Marketplace, Approvals                                                        | Install, uninstall, approve and cancel write from the tab itself |
| Credentials Manager                                                           | Password fields; create and delete                               |
| Header, framework and scoping selectors, tab bar, banner, loader, scan button | Shared by every tab; carries the page-wide scan trigger          |
| The shared dialog container and its dialogs                                   | Writes, evidence upload and delete, ad-hoc credentials           |
| `PaginationBar`                                                               | Still used by Credentials and Approvals                          |
| `dashboard.css`, `compliance.css`, `scan.css`                                 | Still used by the header, the dialogs and the remaining tabs     |

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-marketplace,cw-exceptions,cw-credentials,cw-approvals,cw26a-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- **Unchanged captures:** all 174 are identical in every category. That
  includes the Exceptions, Marketplace, Credentials and Approvals tabs in both
  themes, Batch 26A's eight Exceptions captures, and Batch 25's 20 NewScan
  captures.
- **Second pair:** pre-b vs post-b is also 174 / 174.
- **Determinism:** post-a vs post-b is 199 / 199.
- **Changed captures:** the 25 captures of the four views — the eight `cw-`
  captures and the 17 `cw26b-` captures.

Every changed category on those 25 captures is accounted for:

| Category                                         | Captures | Why it changed                                                                                                                                                                                                                |
| ------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| names, headings, roles                           | 25       | Labelled fields, named buttons, headed cards and sections, named groups and progress bars                                                                                                                                     |
| live, tables                                     | 17, 17   | The captioned tables with scoped headers and row headers, and the page and table status regions — on every Controls, Policies and Findings capture; the Dashboard has neither                                                 |
| ariaStates                                       | 11       | `aria-pressed` on the report format (8 Dashboard captures) and `aria-expanded` on the baselines (3 populated Policies captures)                                                                                               |
| tabOrder                                         | 4        | The 390 px Controls, Policies and Findings captures, where the wide table's scroll region joins the tab order and Policies gains its disclosure buttons; the loading Findings capture, where the page-size select is disabled |
| clickable                                        | 3        | The baseline rows are no longer click handlers on `tr` elements                                                                                                                                                               |
| probes, requests                                 | 1, 1     | `cw26b-policies-mobile`: Tab now reaches the disclosure and Enter expands it, which reads `/compliance/policies/pol-1/rules` — the one expected request delta. On the legacy page the probe had nothing to reach              |
| contrast                                         | 25       | 0 failing text pairs inside the views; only the shared chrome's remain                                                                                                                                                        |
| inline, classes, styles, rects, text, screenshot | 25       | The restyle. The inline styles left are the shell's, the shared header's, the tab bar's and the progress bars' widths                                                                                                         |
| writes, url, runtime, overflow                   | —        | **Unchanged**: no write, every capture on `/compliance`, no exception, console error or overflow                                                                                                                              |

Screenshots were reviewed side by side for all 25 captures:

- **Dashboard:** in both themes, with NIST CSF chosen in both themes, with NIS 2
  chosen, and at 390 px.
- **Controls:** in both themes and at 390 px.
- **Policies:** expanded in both themes, and collapsed at 390 px.
- **Findings:** in both themes, filtered, loading and at 390 px.
- **The four thin regression captures**, in both themes.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — all kept exactly, and pinned where marked:

- **Choosing a control status reads the register with the previous status.** The
  handler calls `setTimeout(fetchTabData, 0)` with the render's own
  `fetchTabData`, whose closure still holds the old value; the chosen status is
  only sent by the next read. (pinned)
- **Clear Filters ignores the CIS implementation-group filter**: it neither
  appears for that filter alone nor resets it. (pinned)
- **Expanding a second baseline while the first's rules are loading can show the
  first's rules under the second**: nothing checks that the expansion is still
  current when the read returns.
- **Every baseline status is drawn as active** — a `draft` has the same success
  badge, as the legacy pill did. (pinned as text)
- **Quick downloads stay enabled during a download**, so a second click starts a
  second render; only the main button is disabled.
- **A download sets the page-wide `loading` flag**, so the shared loading bar
  runs for the length of a report render.
- **The dashboard shows nothing until the summary arrives**, and nothing but the
  shared banner if it fails.
- **Opening the dashboard on All Frameworks reads one extra summary per active
  framework** after the workspace summary, every time.
- **The NIS 2 turnover accepts any number**, negative or empty (read as 0), and
  the ceiling is formatted in the browser's locale.
- **Findings are read with `limit=10000` and filtered and paged in the
  browser.** The 5-second poll restarts its timer after every read and has no
  upper bound while a finding stays re-checking.
- **Report and read URLs interpolate framework and filter values unencoded.**
  Today they are catalogue constants and fixed option values.
- **The Mode column prints the raw scannability code** (`semi_auto`), and
  finding statuses print theirs (`manual_review`).
- **The "Reboot Required" explanation is a tooltip only.**
- **Harness:**
  - The framework and status choices are driven through the select's value
    setter and a `change` event.
  - No state opens a dialog or downloads.
  - The tab-order walk on the expanded Policies capture records a single stop,
    identically before and after. The keyboard probe on the collapsed 390 px
    capture is this batch's keyboard evidence for that tab.

**Carried:** every item deferred by Batches 16 to 26A stands unchanged, and none
was reopened here. They include:

- the shared header and tab-bar issues;
- the shared loader's raw error logging;
- the shared CcureModal outside-click issue;
- the AMT, NetworkMap, ScanHistory, CredentialedResults, Phase3Results and
  NewScan items recorded in `03c-batch25-new-scan.md` §7 and
  `03c-batch26a-compliance-exceptions.md` §7.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was
reached:

- **Reads:** every read the four views make is unchanged and pinned — endpoint,
  method, parameters, response handling and count. Nothing in them writes.
- **Downloads and polling:** report downloads keep their URLs, filenames and
  response type, and the harness never triggered one; the Findings poll keeps
  its cadence and conditions.
- **Dialog openers:** every button that leads to a write only opens its
  existing dialog. No dialog, dialog container, credential flow or evidence flow
  was modified.
- **Everything else:** outside the four views the page is byte-identical to the
  legacy page, and no other tab, shared component, design-system primitive or
  global stylesheet was modified.
- **Security:** no credential, token, ticket or placeholder secret reaches the
  page, the console or a harness report, and no logging was added.
- **Runtime:** no write, unexpected navigation, off-origin request, CSP issue,
  exception or console error in any capture.
- **Harness gates:** determinism, sensitivity and the regression gate passed —
  over every previously migrated page and ComplianceWorkspace's Exceptions,
  Marketplace, Credentials and Approvals tabs.
- **Headers and air gap:** security headers and the air-gap host set are
  identical.

Batch 26C is not started.

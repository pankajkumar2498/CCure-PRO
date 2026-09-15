# Checkpoint 3C — Batch 31: ComplianceWorkspace's gap analysis and pagination on the design system

Batch 31 moves two low-risk parts of ComplianceWorkspace onto the design system
and removes a component nothing uses any more:

- **the gap-analysis dialog** — the framework pair, Recalculate Gap, the
  estimated score and counts, and the control-by-control breakdown;
- **the Credentials Manager's pager** — now `PagingControls`, the pager every
  other migrated list on the page uses;
- **`PaginationBar`** — retired with the `compliance.css` rules only it used,
  because the Credentials Manager was its last consumer.

## Why these belong together

Neither part writes anything, and the pager swap is what frees
`PaginationBar`:

- **The gap analysis is a read.** `GET /compliance/gap-analysis` under
  `compliance:read` estimates a target framework's posture from the source
  framework's findings through crosswalks, server-side. The dialog chooses a
  pair and asks again; it computes nothing itself.
- **The pager pages on the client.** The credentials list is read once when the
  tab opens; moving between pages or changing the page size reads nothing.
- **`PaginationBar` had one consumer left.** The Approvals Queue stopped using it
  in Batch 30.

## The batch boundary

| Surface                                                     | What it actually does                                                                                                       | In 31             |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Gap-analysis dialog body                                    | Source Baseline and Target Mandate, Recalculate Gap (`GET /compliance/gap-analysis`), the pair, score, counts and breakdown | Yes               |
| The Credentials Manager's pager                             | `PaginationBar` becomes `PagingControls`, on the same pagination hook, page sizes and noun                                  | Yes               |
| `PaginationBar`                                             | Deleted: no consumer remains                                                                                                | Yes — retired     |
| `compliance.css` pager rules                                | The eight rules and the media query only `PaginationBar` used are removed; `.cw-pagination-select` stays                    | Yes               |
| `compliance-credentials.css`                                | The pager's inset in the list's flush card (`.cwc-paging`), and its comment about the pager                                 | Yes               |
| The header's Gap Analysis trigger and gap source selector   | Page chrome                                                                                                                 | No                |
| `fetchGapAnalysis`, `useClientPagination`, `PagingControls` | The read, the paging hook and the pager                                                                                     | No — unchanged    |
| The shared dialog container                                 | Hosts the dialog; titles it with its upper-cased type                                                                       | No — unchanged    |
| `.crosswalk-tag` and `.db-sev-badge` rules                  | The dialog's legacy styles, now without a consumer                                                                          | No — left, see §7 |
| `routers/compliance.py`                                     | Read to confirm the response the fixtures and tests reproduce                                                               | Not changed       |

Everything that decides anything is pinned:

- **Everything outside the dialog body, the pager, `PaginationBar` and one import
  is the code that was here.** Removing the gap stylesheet's import, putting
  `PaginationBar` and the Credentials Manager's pager back and restoring the
  legacy dialog body yields the page at `9d2acd2` byte for byte (5,444 lines).
  `fetchGapAnalysis`, the header's trigger, `useClientPagination`,
  `PagingControls` and the dialog container are unchanged.
- **Everything inside that decides anything is unchanged.** 47 logic fragments
  — the two choices' values, change handlers and options, the Recalculate
  call and its text, the pair, the description, the score and the four counts,
  the column headings with their fallbacks, the rows, row keys, crosswalk
  references and statuses, and the nine pager props — occur in the new code, and
  the dialog's call sites are the same multiset (5 / 5).
- **`PaginationBar` has no consumer.** No JavaScript in `src` names it, no
  JavaScript uses a class only its rules styled, and both pagers reset to page 1
  when the page size changes. `compliance.css` is identical outside its pager
  block, and `.cw-pagination-select` — still on the header's fifteen selects — is
  byte for byte the rule it was.

**Baseline:** HEAD `9d2acd2` (Batch 30).

**Not touched:** everything in the "No" rows above; `dashboard.css`, `scan.css`
and every other rule in `compliance.css`; the backend, the API client, `App.jsx`,
AppLayout, the shared `Modal`, every design-system primitive, `nginx.conf`, CSP
and `scripts/host-nginx/nginx-host.conf`.

---

## 0. How this batch was verified

| Gate                                        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Clean start                                 | `git status` empty at `9d2acd2`; the unchanged image built from that tree before any edit                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Tests first, on the page before migration   | 20 new tests: the 14 contract tests pass, and the 6 batch 31 tests all fail, each for its intended reason; Batch 29's 23 credentials tests pass with one assertion widened (§0.2)                                                                                                                                                                                                                                                                                                                                                 |
| Trial replay, unchanged build               | The 10 Batch 31 captures and the ten existing Credentials Manager captures taken twice: **20 / 20** identical and every one clean. On this build the keyboard probe reaches the dialog's first framework choice with a visible ring and no label, and finds no breakdown region to reach. The unchanged image carries none of the Batch 31 code                                                                                                                                                                                   |
| Baseline, unchanged build                   | 253 captures ready, twice. Determinism **253 / 253**, sensitivity **22 / 22**; every Batch 31 capture clean in both passes                                                                                                                                                                                                                                                                                                                                                                                                        |
| Same tests, migrated                        | **14 / 14** contract tests and **6 / 6** batch 31 tests; Batch 30's **31 / 31**, Batch 29's **23 / 23**, Batch 28's **27 / 27**, Batch 27's **30 / 30**, Batch 26B's **52 / 52** and Batch 26A's **21 / 21**, with the UX4G integration tests **16 / 16** — 220 in all                                                                                                                                                                                                                                                            |
| Logic unchanged                             | Outside the dialog body, the pager, `PaginationBar` and the import the page is byte-identical to `9d2acd2`; the read, the hook, `PagingControls` and the container unchanged; 47 logic fragments; call sites 5 / 5; no consumer of `PaginationBar` or its rules                                                                                                                                                                                                                                                                   |
| Full frontend suite                         | 65 files, **2417** tests, all passing (2397 + 20), on the first run                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Lint                                        | `eslint src --max-warnings=0` clean                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Build                                       | `vite build` succeeds; its chunk-size warning, and its note that `axiosInstance.js` is imported both statically and dynamically, concern files this batch does not touch and predate it                                                                                                                                                                                                                                                                                                                                           |
| Pre-commit formatting                       | Every Batch 31 file passes the repository's Prettier 3.2.5; `compliance.css` did before the edit                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| UX4G guardrails                             | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/` — the strict and broad greps' one match each is `DesignSystemShowcase.jsx`'s header comment, unchanged since `9d2acd2` and counted the same way in Batches 29 and 30; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`; 0 external origins in `index.html`                                                                                                                                                 |
| Secret scan                                 | 0 private-key bodies in the changed files; 0 secret-shaped literals (24+ characters mixing upper case, lower case and digits) in the 1,296 lines this batch adds; its tests type no secret of any kind; 0 `console` calls in the migrated dialog                                                                                                                                                                                                                                                                                  |
| Post determinism                            | post-a vs post-b **253 / 253** identical                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| Unchanged states                            | Every previously migrated page and every other ComplianceWorkspace capture — Batch 30's seventeen, the Approvals Queue's two, Batch 28's eight, Batch 27's eleven, Batch 26B's seventeen and Batch 26A's eight included: **233 / 233** identical pre → post in every category, on both capture pairs                                                                                                                                                                                                                              |
| Sensitivity on the migrated build           | **22 / 22**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Batch 31 requests                           | Identical before and after in every Batch 31 capture (0 deltas). The only compliance reads are the gap analysis — once per gap capture, naming a source and a target framework — the saved credentials, the marketplace and the summaries; no evidence, report, scan or download read                                                                                                                                                                                                                                             |
| Read-only                                   | No credential write, remediation or approval in any capture of the whole catalogue, and no gap-analysis read outside a gap state, in all four reports; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 31 capture; no capture recalculates, saves, deletes or types                                                                                                                                                                                                                               |
| The pager and the breakdown                 | On the migrated build all fifteen Credentials Manager captures have the design-system pager — First page and Last page, no « — and all five gap captures have the breakdown's region; on the legacy build none does, in all four reports                                                                                                                                                                                                                                                                                          |
| Placeholders                                | No harness token, ticket or placeholder secret in any capture of the four reports; no "Bearer" in any Batch 31 capture                                                                                                                                                                                                                                                                                                                                                                                                            |
| CSP and security headers                    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines).                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| Air gap                                     | Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names; the post bundle's one `cw-pagination` rule is `.cw-pagination-select`, where the pre bundle had seven.                                                                                                                                                               |
| Writes, navigations, off-origin, CSP issues | 506 post captures: 0 refused writes, 0 blocked navigations, 0 off-origin requests, 0 CSP issues, 0 exceptions, 0 console errors, 0 unready states, 0 error boundaries, 0 horizontal overflow. Every Batch 31 capture ends on `/compliance` in all four reports                                                                                                                                                                                                                                                                    |
| Screenshots                                 | All 20 changed captures reviewed side by side, pre and post, on a trial build, where they caught the pager flush against its card (§0.2); after the fix, Credentials Manager captures in both themes, with and without the form, empty and at ten per page were reviewed again on a second trial build and on the final build, with the gap dialog. No regression. The two phone captures of the Credentials Manager show the page scrolled past the list by the shared chrome, identically on both builds, and neither overflows |
| Cleanup                                     | Harness containers and validation images: 0. Chrome, counted by the harness's profile-directory name: 0 before and after every run                                                                                                                                                                                                                                                                                                                                                                                                |

### 0.1 The dialog and the pager in tests and in the harness

`src/__tests__/pages/ComplianceWorkspace.gap-pagination.test.jsx` mounts the
real page with only the axios instance, the shell and the signed-in user
replaced. Its `afterEach` fails any test that posted, put, patched or deleted
anything, or read a gap analysis with anything in its query but a source and a
target framework id.

**The contract (14 tests, passing on the page before migration and after):**

- **Gap analysis (10).** Gap Analysis reads the gap source against the gap
  target once and opens the result — the pair, the two frameworks' names, the
  score and the four counts; with a framework chosen in the header it compares
  against that framework; it is disabled and says "Calculating..." while the read
  is out, and nothing opens until it settles; every target control is listed with
  its number, title, mapped source controls and estimated status, under column
  headings naming the two frameworks; a result without codes names its columns
  Target and Source; a comparison with no target controls lists none and counts
  zero; Source Baseline and Target Mandate offer the active frameworks by long
  name and show the pair, and choosing one reads nothing; Recalculate Gap reads
  the chosen pair, says "Calculating..." and is disabled until the read settles —
  the previous result staying on screen — then shows the new result; a refused
  recalculation reports the API's detail, then the error's message, and keeps the
  previous result; a failed first read opens nothing and reports it.
- **The Credentials Manager's pager (4).** Thirty credentials page 25 at a time
  through Next, Previous, Last and First, with the summary and page status
  following and the list read once; 10, 25, 50 or 100 per page, starting at 25,
  and a change returns to page 1; a page change scrolls the list back into view;
  an empty list has one page and nowhere to move.

**The specification (6 tests, each failing on the page before migration for its
intended reason):** the dialog's framework choices are labelled selects, no
arrow is read aloud, and Recalculate Gap is busy while it calculates; the result
is a heading naming the pair ("ISO27001 to NIS2"), the score is labelled and the
counts are a description list; the breakdown is a captioned table inside a
named, keyboard-reachable scroll region, with control numbers as row headers and
the crosswalk references and statuses as badges; a comparison with no target
controls says so; the Credentials Manager's pager is a navigation named
"Credentials pagination" with a labelled page size and First page and Last page;
the migrated source keeps the dialog's first line, uses design-system parts,
names `PaginationBar` nowhere, keeps `.cw-pagination-select` while dropping the
retired rules, and its stylesheet is token-only and scoped under `cwg-`.

**Harness states (8 states, 10 captures),** all on `/compliance`. None
recalculates, saves, deletes or types:

| State                     | Persona, themes, viewport         | What it shows                                                                                                                              |
| ------------------------- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `cw31-gap-dialog`         | organisation admin; light, dark   | The dialog opened from the header: six controls in every status, one mapped to nothing, one title that wraps; Tab reaches the first choice |
| `cw31-gap-long`           | organisation admin; light         | Forty target controls, so the breakdown scrolls; Tab is sent towards its region                                                            |
| `cw31-gap-empty`          | organisation admin; light         | A pair with no target controls                                                                                                             |
| `cw31-gap-mobile`         | organisation admin; light, 390 px | The dialog on a phone                                                                                                                      |
| `cw31-credentials-pages`  | organisation admin; light, dark   | Thirty saved credentials, page 1 of 2                                                                                                      |
| `cw31-credentials-page2`  | organisation admin; light         | Next pressed: page 2 of 2                                                                                                                  |
| `cw31-credentials-size`   | organisation admin; light         | Ten per page chosen: page 1 of 3                                                                                                           |
| `cw31-credentials-mobile` | organisation admin; light, 390 px | The pager on a phone                                                                                                                       |

`CW31_GAP` reproduces the endpoint's response — each framework's id, name and
code, the summary with its `pending_manual` count, and each control's id,
number, theme, title, crosswalk and estimated status — with synthetic codes and
figures. `CW31_CREDENTIALS` is thirty references like Batch 29's, and no secret.
The router serves the stubbed analysis for any pair and refuses every write
regardless. The existing Credentials Manager captures — the six `cw29-credentials-`
states (eight captures) and `cw-credentials` in both themes — change with the
pager, and are counted with the batch rather than the regression set.

The shared marketplace stub lists no active frameworks, so in every capture the
page keeps its fallback pair, ISO 27001:2022 and NIST CSF 2.0, while the gap
target stays `cfw_nis2`. The dialog's Target Mandate therefore shows its first
option beside a result for NIS 2 — on both builds alike. That is the
default-target finding recorded in §7, made visible rather than stubbed away;
the unit contract runs with NIS 2 active.

### 0.2 Corrections

- **One Batch 29 contract assertion was widened, before the page was migrated.**
  "An empty list says so" required the text "No credentials found" — the empty
  summary `PaginationBar` printed. `PagingControls` is `CcurePagination`, whose
  summary for an empty list is "Showing 0–0 of 0 credentials", and changing that
  would mean changing a design-system primitive. The assertion now accepts either
  pager's summary; the list's own "No saved credentials registered." is still
  required, and the new contract pins what an empty list's pager does — one page,
  Next and Previous disabled. It passed on the legacy page before the migration
  and passes after it. No other assertion changed.
- **The trial screenshots caught the new pager flush against its card.** The
  Credentials Manager's list sits in a `CcureCard` whose body is flush for the
  table; `PaginationBar` carried its own padding, `PagingControls` does not, so
  "Showing 1–25 of 30 credentials" touched the card's left edge and Last page its
  right on every credentials capture. The pager now sits in a `cwc-paging`
  wrapper with a token inset and rule in `compliance-credentials.css`. The
  focused tests, lint and the logic check — its credentials-stylesheet reduction
  widened to the new rule — were run again, and so was the trial, before the
  full run.

---

## 1. Files changed

| File                                                              | Change                                                                                                                | LOC                       |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------- |
| `src/pages/ComplianceWorkspace.jsx`                               | The gap-analysis dialog body; the Credentials Manager's pager; `PaginationBar` deleted; the stylesheet imported       | 5444 → 5287 (+140 / −297) |
| `src/styles/compliance-gap.css`                                   | New, page-owned: 44 `--ccure-*` references, 0 colour literals, 0 other custom properties, every selector under `cwg-` | new, 179                  |
| `src/styles/compliance.css`                                       | The retired pager's eight rules and media query removed; `.cw-pagination-select` kept under a new heading             | 560 → 502 (+3 / −61)      |
| `src/styles/compliance-credentials.css`                           | The pager's inset (`.cwc-paging`) and its comment about the pager                                                     | 73 → 80 (+9 / −2)         |
| `src/__tests__/pages/ComplianceWorkspace.gap-pagination.test.jsx` | New: 14 contract + 6 batch 31                                                                                         | new, 733                  |
| `src/__tests__/pages/ComplianceWorkspace.credentials.test.jsx`    | One assertion accepts either pager's empty summary                                                                    | +5 / −1                   |
| `scripts/ux4g-harness/lib/fixtures.mjs`                           | The gap analyses and thirty credential references                                                                     | +105                      |
| `scripts/ux4g-harness/lib/states.mjs`                             | 8 `cw31-` states; `cw30-` in the regression prefixes                                                                  | +122 / −5                 |
| `docs/ux4g/03c-batch31-compliance-gap-analysis-pagination.md`     | This document                                                                                                         | new                       |

In the dialog body and the retired pager (legacy against new):

| Measure                                            | Dialog before | Dialog after      | `PaginationBar`                        |
| -------------------------------------------------- | ------------- | ----------------- | -------------------------------------- |
| Lines                                              | 238           | 162               | 81 → **0**                             |
| Inline `style` attributes                          | 23            | **0**             | 0                                      |
| Hex colour literals                                | 11            | **0**             | 0                                      |
| `var(--…)` references in markup                    | 4             | **0**             | 0                                      |
| `db-`, `mono` and `crosswalk-tag` class references | 9             | **0**             | 0 (10 `cw-pagination` classes → **0**) |
| Hand-built buttons / selects / labels / tables     | 1 / 2 / 2 / 1 | **0 / 0 / 0 / 0** | 4 / 1 / 0 / 0 → **0**                  |
| Glyph-only buttons                                 | 0             | 0                 | 2 (« and ») → **0**                    |
| Design-system components                           | 0             | 6                 | —                                      |
| Tests                                              | 0             | 20 across both    |                                        |

Across the whole page, inline style attributes are 77 → 54, hex colour literals
11 → **0**, `var(--…)` references in markup 54 → 50, `db-` class references
22 → 15, `mono` classes 1 → 0, hand-built buttons 8 → 3, selects 18 → 15, bare
labels 7 → 5, tables 1 → **0**, `PaginationBar` 2 → **0** and `cw-pagination`
class references 25 → 15, all fifteen now the header's selects; the page is
5,444 → 5,287 lines. `compliance.css` is 560 → 502 lines.

Bundle, measured from the two images' web roots:

| Asset | Before (bytes) | After (bytes) | Change |
| ----- | -------------- | ------------- | ------ |
| CSS   | 412,272        | 413,924       | +1,652 |
| JS    | 1,575,047      | 1,572,920     | −2,127 |

---

## 2. Accessibility

1. **The framework choices are labelled.** Source Baseline and Target Mandate are
   `CcureSelect`s whose labels name them; the legacy `<label>`s had no `for`,
   so both selects were anonymous.
2. **No arrow is read aloud.** The ➔ between the choices and in the result's
   heading is hidden from assistive technology, and the heading reads "ISO27001 to
   NIS2".
3. **Recalculate Gap shows it is working.** Busy and disabled while the read is
   out, with a spinner; its name stays, and it still says "Calculating...".
4. **The score and the counts say what they are.** The percentage is labelled
   "Estimated score"; Target Controls, Crosswalk Mapped, Estimated Pass and
   Estimated Fail are a description list, and pass and fail are named by their
   terms, the colour only repeating them.
5. **The breakdown is a named table in a reachable region.** A `CcureTable`
   captioned "{target} controls estimated from {source} findings", with column
   headers, each control number as its row's header and each crosswalk reference
   and status a badge carrying its word. It sits in a region named "Estimated
   status by control" that takes focus, so a keyboard user can scroll a long
   framework; the legacy scroll box could not be focused.
6. **An empty comparison says so** — "No target controls to compare." — where the
   legacy table body was silently empty.
7. **The Credentials Manager's pager is the design-system pager.** A navigation
   named "Credentials pagination", a page-size select labelled "Rows per page", a
   live "Page N of M" status and named Previous, Next, First page and Last page —
   in place of `PaginationBar`'s unnamed « and », "Prev" and an unlabelled select
   beside the word "Show".
8. **Colour and layout** are `--ccure-*` tokens in both themes. The legacy dialog
   hard-coded a light grey toolbar and summary and white selects, which stayed
   light in the dark theme. The choices, the score and the counts wrap on a
   phone.

Measured in the harness: on the gap captures unlabelled controls fall from 4 to
2 — the dialog's two choices were the others; the header's two selects remain
— and failing text pairs fall from 18 to 2 in light and 19 to 1 in dark, 12 to 2
on the empty comparison, 52 to 2 on the forty-control breakdown and 18 to 2 on a
phone. Every pair left is the shared chrome's: the header's "Run Compliance
Scan" button and, in light, the tab bar's active label. The dialog's tab order
gains the breakdown's region (4 → 5, and 6 on a phone, where the table's own
horizontal scroll region is a stop too), which the keyboard probe reaches with a
visible ring; on the legacy build it found none. On the fifteen Credentials
Manager captures the page-size select gains its label (unlabelled controls
3 → 2) and the glyph-only « and » are gone (2 → 0); the tab order and the failing
text pairs are unchanged. The pager's buttons disabled at the first or only page
— up to four — fall below text contrast, which WCAG exempts for disabled
controls.

---

## 3. Security and data exposure

| Requirement                | Evidence                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Requests                   | The dialog reads through the unchanged `fetchGapAnalysis`: one GET whose query carries two framework ids. The pager reads nothing. The tests fail on any other write or query                                                                                                                                                                                                                                                                                         |
| What the page renders      | Framework codes and names, counts, and each control's number, title, crosswalk references and estimated status — no credential; the credentials list is unchanged and carries references only                                                                                                                                                                                                                                                                         |
| Error handling             | Unchanged: a refusal is reported as the API's `detail`, then the error's message                                                                                                                                                                                                                                                                                                                                                                                      |
| Logging                    | None added; the dialog makes no `console` call; the page's five are the same                                                                                                                                                                                                                                                                                                                                                                                          |
| Permissions                | Unchanged: `compliance:read`, and the server refuses a parked framework                                                                                                                                                                                                                                                                                                                                                                                               |
| No writes from the harness | No credential write, remediation or approval in any capture of the whole catalogue, and no gap-analysis read outside a gap state, in all four reports; 0 refused writes and 0 non-GET requests beyond the session refresh in any Batch 31 capture; no capture recalculates, saves, deletes or types                                                                                                                                                                   |
| Test values                | Synthetic codes, titles and figures, and credential references with no secret; gitleaks passes on the staged content with no allowlist                                                                                                                                                                                                                                                                                                                                |
| UX4G guardrails            | 0 `ux4g-` class names or `.ux4g-` selectors outside `src/design-system/` — the strict and broad greps' one match each is `DesignSystemShowcase.jsx`'s header comment, unchanged since `9d2acd2` and counted the same way in Batches 29 and 30; 0 `ux4g-web-components` imports outside it; 0 UX4G runtime references in `src` or `index.html`; 0 external origins in `index.html`                                                                                     |
| Backend and API            | No file under `Backend/`, `Frontend/src/api/`, `Frontend/src/design-system/`, `Frontend/src/components/`, `nginx.conf` or `scripts/host-nginx/` changed                                                                                                                                                                                                                                                                                                               |
| CSP and external assets    | Identical on the pre and post images across six routes, `/compliance` included (42 header lines). Both images' web roots reference the same 7 absolute hosts, with 0 external `<link>`, `<script>`, `@import` or `url()` references. Both bundles carry the design system's 1,332 `--ux4g-*` token properties and 0 `.ux4g-` selectors or `ux4g-` class names; the post bundle's one `cw-pagination` rule is `.cw-pagination-select`, where the pre bundle had seven. |

---

## 4. Intentional changes

1. **The framework choices are labelled `CcureSelect`s**, and their labels lose
   the trailing colon: "Source Baseline", "Target Mandate".
2. **Recalculate Gap is a `CcureButton` in its loading state while it reads** —
   busy, disabled and with a spinner, as before disabled and saying
   "Calculating...". The read, its query and its notices are unchanged.
3. **The result's heading reads "{source} to {target}"**; the arrows are drawn
   and hidden.
4. **The score gains a visible "Estimated score" label, and the counts are a
   description list**, without the colons.
5. **An empty comparison says "No target controls to compare."**
6. **Statuses keep the API's word** and their colours follow it: success for
   `pass`, danger for `fail`, info for anything else — the legacy severity badges
   gave low, critical and info.
7. **The breakdown's scroll region is a tab stop**, even when a short framework
   does not scroll.
8. **The dialog follows the theme.**
9. **The Credentials Manager's pager behaves as every other migrated pager on the
   page:** Previous for Prev, First page and Last page for « and », "Rows per page"
   for "Show … per page", "Showing 0–0 of 0 credentials" for "No credentials
   found", and the page-size select disabled while the page loads, as the buttons
   already were. The hook, the page sizes, the reset to page 1 and the scroll back
   into view are unchanged.
10. **`PaginationBar` is deleted**, with the eight `compliance.css` rules and the
    media query that styled nothing else; `.cw-pagination-select` stays under a
    heading that says what uses it.

---

## 5. What remains in ComplianceWorkspace, and why

| Part                                                                                                                                                              | Why it is not in 31                                                                                                                                                                                                                           |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Header — framework selector and its filters, gap source, Gap Analysis, Run Compliance Scan, the policy action — the tab bar, the error banner and the loading bar | Shared by every tab and carrying the page-wide scan trigger. It holds all 54 remaining inline style attributes, every remaining `db-` reference, the three hand-built buttons, fifteen selects on `.cw-pagination-select` and two bare labels |
| The shared dialog container                                                                                                                                       | Hosts every dialog, and titles the remediation, rollback, log and gap-analysis dialogs with their upper-cased type                                                                                                                            |
| Marketplace's uninstall confirmation                                                                                                                              | The page's last `window.confirm`, deferred by Batch 27                                                                                                                                                                                        |
| `dashboard.css`, `compliance.css`, `scan.css`                                                                                                                     | Still used by the chrome; `.crosswalk-tag` and `.db-sev-badge` no longer have a consumer                                                                                                                                                      |

Outside the chrome the page has no inline style, colour literal, `db-` class or
hand-built button, select or table left; its three other bare labels are Batch
30's source radios and bypass checkbox, each wrapping its input.

---

## 6. Harness diff, pre → post

`compare.mjs pre-a post-a --mode diff --identical ar-,vb-,cw-dashboard,cw-marketplace,cw-policies,cw-controls,cw-findings,cw-exceptions,cw-approvals,cw26a-,cw26b-,cw27-,cw28-,cw30-,sd-,p2-,p1-,amt-,nm-,sh-,cr-,p3-,ns-`
exits 0:

- All 233 unchanged captures are identical in every category — every
  ComplianceWorkspace capture outside the gap-analysis dialog and the
  Credentials Manager, the Approvals Queue and Batches 26A to 28 and 30
  included.
- pre-b vs post-b is also 233 / 233.
- Post determinism (post-a vs post-b) is 253 / 253.
- The 20 changed captures are the 10 `cw31-` captures, the eight
  `cw29-credentials-` captures and `cw-credentials` in both themes.

Every changed category on those 20 captures is accounted for:

| Category                                                                                                       | Captures | Why it changed                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| names, roles, classes, contrast, text, screenshot                                                              | 20       | On the credentials captures, the pager's navigation, labelled page size, live status, named buttons and "Jump to page" group; on the gap captures, the labelled choices, the named region and the restyle |
| rects                                                                                                          | 18       | The pager's and the dialog's layout; `cw-credentials`' two tracked elements keep their boxes                                                                                                              |
| live                                                                                                           | 15       | The pager's polite page status, on every Credentials Manager capture                                                                                                                                      |
| styles                                                                                                         | 13       | The eight `cw29-credentials-` captures, which track labels — "Rows per page" among them — and the five gap captures' restyle                                                                              |
| tabOrder                                                                                                       | 10       | The named First page, Last page and Previous on the five `cw31-credentials-` captures, whose thirty credentials leave some enabled; the breakdown's region on the five gap captures                       |
| headings, tables, inline                                                                                       | 5        | The gap captures: the result's heading, the captioned breakdown, the removed inline styles                                                                                                                |
| probes                                                                                                         | 1        | `cw31-gap-long`: the breakdown's region reached by Tab, with a visible ring                                                                                                                               |
| clickable, dialogs, ariaStates, overflow, errorBoundary, url, theme, requests, writes, offOrigin, csp, runtime | —        | **Unchanged on all 20**: the same requests, no write, every capture on `/compliance`                                                                                                                      |

Screenshots were reviewed side by side for all 20 captures on the first trial
build: the dialog in both themes, long, empty and on a phone; the thirty
credentials in both themes, on page 2, at ten per page and on a phone; and the
Batch 29 and `cw-credentials` captures. The Credentials Manager captures were
reviewed again after the pager's inset was added.

---

## 7. Deferred, and found but not fixed

**Found in this batch** — kept exactly, pinned where marked:

- **The dialog's Target Mandate can show a different framework from the result.**
  With a framework chosen in the header, Gap Analysis compares against that
  framework, but the Target Mandate choice keeps the separate gap target — so the
  dialog opens showing one target and a result for another, and Recalculate Gap
  then compares against the one shown. (pinned: the header's framework is the
  first read's target)
- **The default gap target is `cfw_nis2`, which this deployment parks.** With All
  Frameworks chosen, Gap Analysis asks for NIS 2, which the server refuses for a
  parked framework, and the operator sees "Failed to run gap analysis". When NIS 2
  is not among the active frameworks, the Target Mandate select holds a value it
  does not offer and shows its first option instead. (pinned: the default pair)
- **A choice changed, or a recalculation refused, leaves the previous result on
  screen** under choices that no longer match it; only the heading still names
  the result's own pair. Nothing marks the result as stale while a new one is
  read. (pinned)
- **The `pending_manual` count is returned and not shown**, although the score's
  denominator includes those controls; and the status is shown as the API's word,
  `pending_manual`. (pinned: the word)
- **A refusal whose `detail` is a list** would read "Failed to run gap analysis:
  [object Object]", as on the other tabs.
- **The breakdown's region is a tab stop even when it does not scroll.**
- **The dialog is titled "GAP_ANALYSIS"** — the shared container upper-cases the
  dialog's type. (pinned by Batch 26B's views test)
- **`.crosswalk-tag` in `compliance.css` and `.db-sev-badge` in `dashboard.css`
  now have no consumer.** They are legacy styles outside this batch's removal and
  were left in place.
- **Harness:** no state recalculates — the unit contract covers it — and the
  router returns the stubbed analysis for any pair. The runner's orphaned-browser
  issue recorded in Batch 29 stands.

**Carried:** every item deferred by Batches 16 to 30 stands unchanged — among
them Batch 30's execution findings, Batch 29's credential-manager findings,
Batch 28's evidence findings, Batch 27's in-flight, role-gate and native-confirm
findings for the ordinary writes, the shared header and tab-bar issues, the
shared loader's raw error logging, the shared CcureModal outside-click issue, the
Batch 26B view issues, and the AMT, NetworkMap, ScanHistory, CredentialedResults,
Phase3Results and NewScan items — and none was reopened here.

---

## 8. Result

**GO.** Every gate passed on the final build, and no STOP condition was reached:

- the gap-analysis read, its query, its loading and error handling and the
  result's data are unchanged and pinned, and so are the Credentials Manager's
  page size, navigation and single read;
- outside the dialog body, the pager, `PaginationBar` and one import the page is
  byte-identical to `9d2acd2`; the header, the dialog container, the other tabs
  and dialogs, every design-system primitive and every shared component are
  unmodified, and the only stylesheet changes are the dialog's new sheet, the
  retired pager's rules and the pager's inset;
- `PaginationBar` and the rules only it used are gone, with no consumer left, and
  `.cw-pagination-select` is unchanged for the header;
- no backend or API file changed, and no logging was added;
- no write, unexpected navigation, off-origin request, CSP issue, exception or
  console error in any capture, and no secret in any report;
- determinism, sensitivity and the regression gate over every previously
  migrated page and the rest of ComplianceWorkspace passed;
- security headers, the air-gap host set and the UX4G guardrails are unchanged.

Batch 32 is not started.

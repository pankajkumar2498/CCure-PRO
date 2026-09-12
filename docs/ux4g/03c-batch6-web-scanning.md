# Checkpoint 3C — Batch 6: the read-only web-scanning module

**Scope:** ScanList, AssetInventory, WebDashboard, FindingsExplorer
**Date:** 10 September 2026
**Recommendation:** **GO**

Harness changes are documented separately in
[`03c-batch6-harness.md`](03c-batch6-harness.md), as the new process rule
requires. Nothing in this report's application work began until that document's
six validation steps had passed.

---

## 1. Candidate ranking

All twelve candidates measured before any code was written — the two remaining
Group A pages and every Group B page in `docs/ux4g/00-baseline.md` §7.

| Page                 | LOC | Inline | Colour | Shape                             | Needs new arch?                 | Blast radius     | Risk        |
| -------------------- | --: | -----: | -----: | --------------------------------- | ------------------------------- | ---------------- | ----------- |
| **ScanList**         | 308 |     30 |      3 | table + status                    | no                              | module-local     | **low**     |
| **AssetInventory**   | 335 |     33 |      1 | table + search                    | no                              | module-local     | **low**     |
| **WebDashboard**     | 354 |     36 |      0 | metric cards                      | no                              | module-local     | **low**     |
| **FindingsExplorer** | 467 |     42 |      6 | master–detail + severity + triage | no                              | module-local     | **low–med** |
| NewWebScan           | 564 |     39 |      3 | **scan-dispatch form**            | no                              | module-local     | med         |
| ScanDetail           | 720 |     62 |      7 | detail + **5 s polling**          | no                              | module-local     | med         |
| ConfigurationChecks  | 322 |     25 |     38 | audit results                     | no                              | scan module      | med         |
| ScanCredentials      | 550 |     44 |     24 | **credential CRUD**               | no                              | credential store | **high**    |
| CredentialedScan     | 604 |     19 |      5 | **credential dispatch**           | no                              | credential store | **high**    |
| ScanSchedules        | 776 |     67 |     33 | schedule forms                    | no                              | scan module      | med–high    |
| Dashboard            | 537 |      1 |     26 | card grid                         | **yes** — 13 accent tokens      | landing page     | med         |
| SecurityReports      | 622 |     17 |      4 | cards + tabs                      | **yes** — first `CcureTabs` use | own stylesheet   | med         |

## 2. Selected batch

**ScanList, AssetInventory, WebDashboard, FindingsExplorer** — the four
_read-only_ pages of `src/modules/web-scanning/`.

## 3. Why these four belong together

Not "they are small". They are one self-contained module with one shape, and
the repository says so:

- **One directory, one API client, one hook, one stylesheet, one routes file.**
  All six module pages import `AppLayout` and `webScansApi`; five import the
  legacy `Skeleton`, whose _only_ consumers anywhere in the application are
  these pages.
- **They share their defects**, which is the strongest signal that they share a
  shape. The `var()`-plus-alpha bug appears in two of them; the missing table
  semantics in two; the un-announced skeleton loader in all four; the ad-hoc
  colour helper in three.
- **They share a vocabulary already covered by approved patterns** — scan status
  and finding severity, which `CcureScanStatus` and `CcureSeverityBadge` were
  built for at Checkpoint 3B.
- **Blast radius is zero outside the module.** No page outside
  `modules/web-scanning/` imports anything these four own.

Read-only is the line that splits the module in half, and it is a security line
rather than a convenience one: none of these four dispatches a scan, and only
one changes any state at all.

## 4. Pages deliberately excluded

**From this module, for a later batch of its own:**

- **NewWebScan** — the form that starts a scan. CLAUDE.md records what
  `POST /web-scans` does: it sends ffuf and nuclei at a caller-named target, and
  "an unbounded loop there is an unbounded outbound attack wearing this host's
  address". It also carries `authorization_confirmed`, an idempotency key and
  three auth modes including `btoa`-encoded basic credentials. That is a
  security-sensitive form and deserves a batch where it is the subject.
- **ScanDetail** — 5-second polling via `useScanPolling`, a websocket ticket
  path, twice the LOC of any page here.

**From elsewhere:**

- **ScanCredentials / CredentialedScan** — credential-handling surfaces (42 and
  38 credential-related lines). These need credential-specific security tests,
  not a presentation batch.
- **ScanSchedules** — 776 LOC, 67 inline styles, 14 form controls; a batch of
  its own.
- **ConfigurationChecks** — the only page of its shape among the candidates.
  Grouping it here would have been forcing a common shape where none exists.
- **Dashboard / SecurityReports** — each needs new design-system architecture
  (a thirteen-entry accent token family; first adoption of `CcureTabs`). Being
  the last two Group A pages is not a reason to migrate them.

## 5. Baseline metrics

| Page             |       LOC | Inline styles | Colour literals |
| ---------------- | --------: | ------------: | --------------: |
| ScanList         |       308 |            30 |               3 |
| AssetInventory   |       335 |            33 |               1 |
| WebDashboard     |       354 |            36 |               0 |
| FindingsExplorer |       467 |            42 |               6 |
| **total**        | **1,464** |       **141** |          **10** |

Measured on the live rendered surface, both themes: **418 inline-styled
elements, 6 duplicate button names, 2 unlabelled form controls, 0 table
captions, 0 scoped column headers, 0 row headers.**

Full suite before the batch: **802 tests, 762 passing, 40 failing** — every
failure one of the new assertions below.

## 6. Baseline tests

Written against the **unmigrated** pages and run before any page was touched.

| File                                             |   Tests |   Pass |   Fail |
| ------------------------------------------------ | ------: | -----: | -----: |
| `modules/web-scanning/ScanList.test.jsx`         |      31 |     20 |     11 |
| `modules/web-scanning/AssetInventory.test.jsx`   |      29 |     19 |     10 |
| `modules/web-scanning/WebDashboard.test.jsx`     |      26 |     18 |      8 |
| `modules/web-scanning/FindingsExplorer.test.jsx` |      28 |     16 |     12 |
| **total**                                        | **114** | **73** | **41** |

### My own assertions that were wrong, corrected before migration

Seven, each documented at the site:

1. **A regex that could never fail.** "does not convey the scorecard verdict by
   colour alone" listed `0 findings` inside its own alternation, so it matched
   the exact string it was written to reject. It passed against a page with the
   defect.
2. **`.closest("div")` reached the card's header row**, which holds the label
   and not the value, so "keeps the critical counter distinguishable" failed
   against a page that is fine.
3. **`.closest("[role],section,article,div")` matched an unnamed inner wrapper**
   rather than the named card — same mistake, different page.
4. **A marker function that read only the row wrapper's className**, which is
   `wsp-row` on every row by construction and so could never differ.
5. **`.closest("div")` on a finding title reached a shared flex wrapper**, so
   "keeps critical and high visually distinct" compared two identical layout
   styles and failed against a page that draws the distinction correctly.
6. **A severity marker that read the label span** — which has no class and no
   style in either implementation — instead of the badge carrying the band.
7. **The whole FindingsExplorer file died** on "Cannot destructure property
   'basename'": the page renders a real `<Link>` and my mock stubbed only
   `useParams`. A harness defect of mine, not a page defect.

### One assertion narrowed, deliberately, and why

"surfaces a failed triage **without a browser alert**" is a real accessibility
point — `window.alert` blocks, is unstyled, and never reaches a screen-reader
user who has moved focus. But removing it changes this page's error
**behaviour**, which this batch's brief lists among the things to preserve.

The assertion was narrowed to _"still tells the user when a triage change was
refused"_ — the property that matters is still asserted, and the stronger claim
about _how_ is deferred to a batch permitted to change error behaviour. The
`alert` is recorded in §11 as an out-of-scope defect rather than quietly
accepted.

**No assertion was weakened to make the migration pass.** Where a rendering
changed because an accessibility assertion demanded it (the `2 C` abbreviation
becoming a named band), the corresponding functional assertion was re-anchored
to require _both_ the count and the band name — strictly more than before.

## 7. Functional and security contracts

Preserved byte-for-byte on all four pages.

- **ScanList** — `getScans({ per_page: 100 })` and nothing else. No scope, org
  or filter parameter is added client-side; the API decides what this account
  may see, and narrowing in the browser would invent an authorisation boundary
  where none exists. Asserted by inspecting the call's key set.
- **AssetInventory** — `getAssets(id, { per_page: 200 })` where `id` is the
  route parameter, which is the whole scoping. The client-side filter still
  matches `url` and `content_type` only.
- **WebDashboard** — all three requests still issued together; a missing counter
  still reads **0**; the scorecard still capped at five rows; a zero trend count
  still omitted.
- **FindingsExplorer** — `updateFindingStatus(scanId, findingId, { status })`
  with the scan id from the route and the finding id from the row; the local
  list updated **only after** the request resolves, so a refused triage leaves
  the finding where it was; the same five triage values in the same order;
  response evidence still truncated at 2,000 characters with an explicit
  `...[truncated]` marker.
- All four still accept both response shapes (`data.data` / `data.items`), still
  survive a failed load without throwing, and still do not poll.

No API call, payload, query parameter, navigation, permission check, error path
or business rule changed. No backend change.

## 8. Defects discovered

1. **`var(--danger)20` is not a colour.** Four sites across two pages built a
   tint by concatenating an alpha suffix onto a CSS variable —
   `` `${getSeverityColor(s)}20` ``, `` `1px solid ${getStatusColor(s)}40` ``.
   The browser drops the entire declaration, so those badges silently had no
   background and no border. It reads as a styling choice in review and is a
   bug.
2. **A finding count that could not be seen at all.** Measured on the live
   surface, ScanList's high-count badge rendered **white text on white,
   1:1**. The number of High findings on a scan was invisible.
3. **Severity collapsed to four bands.** `getSeverityColor` mapped critical onto
   danger and high onto warning — the exact collapse `CcureSeverityBadge` exists
   to prevent.
4. **Findings were not reachable by keyboard.** FindingsExplorer's rows were
   `<div onClick>`: no role, no tab stop, no key handler. A keyboard user could
   not open a single finding on the screen where this product presents the
   vulnerabilities it found.
5. **A clean OWASP scorecard was reported after a failed request.** All three
   dashboard calls share one `try/catch`, so any failure left every widget in
   its placeholder — and that placeholder reads "No OWASP findings detected
   yet". Good news about a target nobody could ask about.
6. **`title` used as the only name for security flags.** `auth_required`,
   `is_api`, `is_form`, `has_file_upload` were emoji in bare `<span>`s. A
   discovered file-upload endpoint is the most useful row on that page.
7. **Zero table captions, zero `scope` attributes, zero row headers**; 6
   duplicate button names; 2 unlabelled form controls; no loading announcement
   anywhere.
8. **The legacy `Skeleton` injects a `<style>` element per instance** — seven on
   WebDashboard, so seven copies of the same `@keyframes` — and has **no
   reduced-motion guard** on an infinite shimmer.
9. **A column was dropped by this migration and caught by the instrument** — see
   §13. Recorded as a defect of mine, not of the original.

## 9. Migration changes by page

Architecture: UX4G tokens → CCure semantic tokens → CCure primitives → CCure
security patterns → page. No `ux4g-*` class, no direct UX4G import, no UX4G
runtime, no new dependency.

| Page             | LOC                    | Inline styles | Colour literals |
| ---------------- | ---------------------- | ------------- | --------------- |
| ScanList         | 308 → 210              | 30 → 0        | 3 → 0           |
| AssetInventory   | 335 → 243              | 33 → 0        | 1 → 0           |
| WebDashboard     | 354 → 228              | 36 → 0        | 0 → 0           |
| FindingsExplorer | 467 → 276              | 42 → 0        | 6 → 0           |
| **total**        | **1,464 → 957 (−507)** | **141 → 0**   | **10 → 0**      |

- **ScanList** — `CcureTable` + `CcureScanStatus` + `CcureSeverityBadge`;
  `getStatusColor` deleted.
- **AssetInventory** — `CcureTable` + `CcureInput` + labelled `CcureBadge`
  flags; `getMethodColor` replaced by a variant map.
- **WebDashboard** — `CcureCard` metric cards (the card's heading is what names
  the counter; the previous markup paired a styled span with a styled div and
  tied them together with nothing), plus a `loadFailed` state so a failed
  request stops reporting a clean scorecard.
- **FindingsExplorer** — real `<button>` rows carrying `aria-pressed`,
  `CcureSeverityBadge`, `CcureSelect` for triage, `<pre>` evidence blocks.

## 10. New design-system changes

**None.** No component, no pattern, no token was added.

Every need mapped to something already approved: `CcureTable`, `CcureCard`,
`CcureBadge`, `CcureButton`, `CcureInput`, `CcureSelect`, `CcureAlert`,
`CcureSkeleton`, `CcureEmptyState`, `CcureScanStatus`, `CcureSeverityBadge`,
`normalizeSeverity`.

Two things were **considered and rejected** under the "prove reuse" rule:

- an **HTTP-method badge** pattern — used by one page, and the method vocabulary
  maps one-to-one onto existing `CcureBadge` variants;
- a **master–detail selectable list** pattern — used by one page, and a real
  `<button>` with `aria-pressed` is the whole of it.

`CcureConfirmDialog` was checked for applicability and is **not used**: none of
these four pages performs a destructive action.

## 11. Accessibility and contrast results

Measured on the live rendered surface, both themes, every `rgba()` composited
through its real ancestor chain. Floors 4.5 / 3.0.

|                                | Control |   Migrated |
| ------------------------------ | ------: | ---------: |
| Text elements measured         |      96 |        126 |
| **Sub-AA on enabled elements** |  **31** |      **0** |
| Worst enabled value            | **1:1** | **4.55:1** |

The worst of the 31, by page:

| Page / theme                      | Element                                      |       Ratio |
| --------------------------------- | -------------------------------------------- | ----------: |
| scanList / light                  | **high-count badge "3 H"**                   |     **1:1** |
| scanList / light                  | `complete` status                            |      2.28:1 |
| assets / light                    | `200` status code                            |      2.28:1 |
| assets / light                    | `POST` method                                |      2.28:1 |
| findings / light                  | `low` severity                               |      2.28:1 |
| assets / light                    | `GET` method                                 |      2.54:1 |
| scanList / light                  | `running` status                             |      2.54:1 |
| assets / light                    | back link                                    |      2.65:1 |
| scanList, findings / both         | `btn--primary`, back link                    |      2.77:1 |
| scanList, assets / light          | `TH` header text                             |      2.96:1 |
| findings, scanList, assets / both | `critical`, `failed`, `401`, `DELETE`, `2 C` | 3.76–3.89:1 |

### Structural accessibility

|                                  | Control | Migrated |
| -------------------------------- | ------: | -------: |
| Table captions                   |       0 |        4 |
| All column headers `scope="col"` |       0 |        4 |
| Row headers                      |       0 |       16 |
| Duplicate button names           |       6 |        0 |
| Unlabelled form controls         |       2 |        0 |
| Unnamed buttons                  |       0 |        0 |
| Horizontal overflow              |    none |     none |

Plus, asserted in the suites: every finding row reachable and operable by
keyboard, `aria-pressed` reporting the selection, loading announced through
`role="status"` while the skeletons stay `aria-hidden`, the triage control
labelled, headings no longer skipping a level, and evidence rendered as text.

### Carried forward, deliberately not fixed

- **`.page-subtitle` at 4.55:1 light** — pre-existing, shared shell, per the
  standing instruction. It is the worst enabled value on the migrated surface.
- **`window.alert` on a failed triage** — removing it changes error behaviour,
  which this batch may not do. See §6.
- **The legacy `Skeleton`'s per-instance `<style>` and missing reduced-motion
  guard** — it still has a consumer (ScanDetail), so it is not this batch's to
  change. The four migrated pages no longer use it.

## 12. CSS cleanup and consumer evidence

**Nothing was deleted, and one finding explains why.**

Classes the four pages stopped using were searched repository-wide, checked for
substring false positives and for dynamic `className` construction:

| Class                                                         | Other consumers | Verdict                                   |
| ------------------------------------------------------------- | --------------: | ----------------------------------------- |
| `.btn--outline`                                               |               4 | KEEP                                      |
| `.form-input`                                                 |               1 | KEEP                                      |
| `.skeleton-loader`                                            |  1 (ScanDetail) | KEEP                                      |
| `.stat-card`                                                  |               0 | see below                                 |
| `.ws-badge`, `.ws-badge-*`, `.ws-grid-table`, `.ws-stat-card` |               0 | **KEEP — already dead before this batch** |

Two things worth stating plainly:

- **`src/modules/web-scanning/styles/web-scanning.css` — all 12 classes, 79
  lines — had zero consumers _before_ this migration.** `git grep` at HEAD finds
  the strings `ws-badge`, `ws-grid-table` and `ws-stat-card` in exactly one
  file: the stylesheet that defines them. This batch did not orphan it, so
  removing it would be unrelated cleanup, which the brief forbids. It is
  reported here instead and left untouched.
- **`.stat-card` was applied by WebDashboard and defined by no stylesheet at
  all.** The card's appearance came entirely from the inline object beside it.
  There is nothing to delete.

No shared stylesheet was modified, so the "re-run unrelated-page regression
after modifying a shared stylesheet" rule did not apply — though unrelated-page
regression was run anyway (§13).

## 13. Regression results

Harness validation is in [`03c-batch6-harness.md`](03c-batch6-harness.md):
self-comparison byte-identical, a known intentional difference detected on the
one page that carried it, and identical output for the three that did not.

**Control image:** the unmigrated tree, built and containerised _before_ any
page was edited.

Both containers self-compared byte-identical before any comparison was believed
— for the structural instrument and, separately, for the contrast probe.

|                          | Control | Migrated |
| ------------------------ | ------: | -------: |
| Inline-styled elements   |     418 |    **0** |
| Duplicate button names   |       6 |    **0** |
| Unlabelled controls      |       2 |    **0** |
| Table captions           |       0 |    **4** |
| Fully scoped header rows |       0 |    **4** |
| Row headers              |       0 |   **16** |
| Horizontal overflow      |       0 |        0 |

All four pages changed in the intended direction, **identically in light and
dark**.

### The instrument caught a real regression of mine

The first structural run reported `assets: headerCells 6 -> 5`. The
pre-migration table had a sixth column — **SIZE / TIME**, rendering
`response_size` and `response_time` — and my first version of the migration
silently dropped it.

**The baseline suite did not catch this**, because no assertion I wrote covered
that column. The instrument did. The column is restored, and two assertions were
added that would have caught it: one asserting the column's content, one
asserting the header count.

That is the second time in two batches that this instrument has found something
review and unit tests both missed, and it is the argument for the process rule
that now governs it.

### No unrelated page changed

| Set                                                                                      | Result                         |
| ---------------------------------------------------------------------------------------- | ------------------------------ |
| Auth group (Login, Register, ResetPassword, VerifyEmail, ForgotPassword)                 | **5/5 identical**              |
| Batch-5 admin pages (RecycleBin, DeletedUsers, OrganizationManagement, EmailDomainRules) | **4/4 identical, both themes** |

Container port excluded from the comparison, as always.

## 14. Harness changes

Documented separately in [`03c-batch6-harness.md`](03c-batch6-harness.md), and
made **before** application migration began, with no application file touched
during that work.

Summary: `capture-batch6.mjs` is the approved `capture-batch5.mjs` with its
`ROUTES`, fixtures and stub table replaced and eight selectors appended to the
probe list. Every property that makes it trustworthy is unchanged.
`contrast-batch6.mjs` is derived the same way, taking its fixtures and stub
table verbatim from the capture instrument so the two cannot describe different
pages. Both validated by self-comparison at the point of use.

## 15. Security, CSP and air-gap results

| Gate                                                     | Result                                                                   |
| -------------------------------------------------------- | ------------------------------------------------------------------------ |
| CSP                                                      | **byte-identical** — `Frontend/nginx.conf` not modified                  |
| Security headers                                         | unchanged                                                                |
| External runtime origins                                 | **0** — 31 requests, all to the container origin                         |
| UX4G runtime markers in `dist/`                          | **0**                                                                    |
| `ux4g-*` classes in application code                     | **0** (one grep hit is prose in a comment saying so)                     |
| Direct UX4G imports from pages/components                | **0**                                                                    |
| `dangerouslySetInnerHTML` in the module                  | **0** (one grep hit is prose in a comment saying so)                     |
| Analytics / telemetry added                              | none                                                                     |
| Backend / API / routing / permission changes             | none                                                                     |
| Token or credential handling                             | not touched — NewWebScan's auth modes deliberately out of scope          |
| New runtime dependency                                   | **none** — the `package.json` diff is entirely Phase 2's approved change |
| nginx / Docker / PreferencesContext / theme architecture | not modified                                                             |
| `prefers-color-scheme` introduced                        | no — `data-theme` only                                                   |

**One observation, reported rather than changed:** none of the six
web-scanning pages carries a client-side permission check, while
`/web-scans` dispatches ffuf and nuclei. The routes sit under `PrivateRoute`, so
they are authenticated, and the API enforces authorisation — but there is no
`can()` affordance gate as there is on the scan and admin pages. Adding one
would change authorisation semantics, which this batch may not do. It is
recorded for the batch that takes NewWebScan.

## 16. Full test results

**804 tests, 804 passing, 27 files.** Lint clean at `--max-warnings=0`.
Production build green.

| File                                             |                                                Tests |
| ------------------------------------------------ | ---------------------------------------------------: |
| `modules/web-scanning/ScanList.test.jsx`         |                                         **31** (new) |
| `modules/web-scanning/AssetInventory.test.jsx`   | **31** (new, +2 after the dropped-column regression) |
| `modules/web-scanning/FindingsExplorer.test.jsx` |                                         **28** (new) |
| `modules/web-scanning/WebDashboard.test.jsx`     |                                         **26** (new) |
| _(23 pre-existing files)_                        |                                                  688 |

All 41 baseline failures are green. Nothing regressed: the 762 assertions that
passed before the migration all still pass.

## 17. Bundle impact

Against the previous approved checkpoint (Batch 5):

|          |      Before |       After |            Δ |
| -------- | ----------: | ----------: | -----------: |
| CSS raw  |   284.29 kB |   288.35 kB | **+4.06 kB** |
| CSS gzip |    48.43 kB |    49.09 kB | **+0.66 kB** |
| JS raw   | 1,695.02 kB | 1,685.57 kB | **−9.45 kB** |
| JS gzip  |   422.36 kB |   421.71 kB | **−0.65 kB** |

**JS is smaller on both raw and gzip.** 141 inline style objects, three colour
helper functions and a hand-rolled table went away and nothing was added to the
design system. CSS grew by one 284-line stylesheet.

| Metric                                | Δ                                           |
| ------------------------------------- | ------------------------------------------- |
| Page LOC                              | 1,464 → 957 (**−507**)                      |
| Inline styles                         | 141 → **0**                                 |
| Colour literals                       | 10 → **0**                                  |
| Legacy primitives used by these pages | `Skeleton` → none (retained for ScanDetail) |
| Design-system additions               | **none**                                    |
| CSS deleted                           | none (evidence in §12)                      |
| CSS added                             | 284 lines, 40 rules                         |
| Tests added                           | **116**                                     |

## 18. Files changed

**Modified (4)**

- `src/modules/web-scanning/pages/ScanList.jsx` 308 → 210
- `src/modules/web-scanning/pages/AssetInventory.jsx` 335 → 243
- `src/modules/web-scanning/pages/WebDashboard.jsx` 354 → 228
- `src/modules/web-scanning/pages/FindingsExplorer.jsx` 467 → 276

**Added (5)**

- `src/modules/web-scanning/styles/web-scanning-pages.css` (284)
- `src/__tests__/modules/web-scanning/ScanList.test.jsx` (387)
- `src/__tests__/modules/web-scanning/AssetInventory.test.jsx` (410)
- `src/__tests__/modules/web-scanning/WebDashboard.test.jsx` (369)
- `src/__tests__/modules/web-scanning/FindingsExplorer.test.jsx` (438)

**Docs:** `docs/ux4g/03c-batch6-harness.md`, this file.

Not touched: any backend file, `nginx.conf`, `Dockerfile`, `docker-compose.yml`,
`PreferencesContext`, the theme architecture, the design system, `AppLayout`,
`WebScanningRoutes.jsx`, `web-scanning.css`, `webScansApi.js`,
`useScanPolling.js`, `components/common/Skeleton.jsx`, NewWebScan, ScanDetail,
and every page outside the batch.

## 19. Engineering gate

| Gate                                   | Result                                            |
| -------------------------------------- | ------------------------------------------------- |
| Full test suite                        | **804/804**                                       |
| Lint `--max-warnings=0`                | clean                                             |
| Production build                       | green                                             |
| Harness validated before use (6 steps) | **PASS** — separate document                      |
| Regression self-comparison             | byte-identical, both containers, both instruments |
| Both themes verified                   | yes                                               |
| No unrelated page changed              | **9/9 identical** (5 auth + 4 batch-5 admin)      |
| Sub-AA introduced                      | **0** (31 eliminated)                             |
| CSP byte-identical                     | yes                                               |
| Air-gap                                | clean                                             |
| New dependency                         | none                                              |
| New design-system architecture         | **none**                                          |

**PASS.**

## 20. Legal / licence gate

**OPEN.** Unchanged by this batch and not claimed closed.

## 21. Recommendation

**GO.**

Four pages, 116 assertions added, 41 baseline accessibility failures closed,
**31 measured sub-AA values eliminated with none introduced** — including a
findings count that was rendering white-on-white at 1:1 — 141 inline styles and
507 lines removed, no design-system addition, no CSS deleted, no dependency, no
unrelated page changed, JS bundle smaller.

Three things a reviewer should weigh rather than take on trust:

1. **The instrument caught a regression the tests missed** (§13): I dropped the
   SIZE / TIME column from AssetInventory. It is restored and now covered. It is
   worth knowing that the baseline-tests-first method did not catch this on its
   own — column _coverage_ is a gap that only a structural diff closes.
2. **One assertion was narrowed** (§6) because it conflicted with the
   instruction to preserve error behaviour. The `window.alert` on a failed
   triage survives, deliberately and on the record.
3. **`web-scanning.css` is dead** (§12) — 79 lines with zero consumers, and it
   was already dead before this batch, so it was left alone rather than cleaned
   up in passing. It is the obvious first thing to remove in the batch that
   finishes this module.

Stopping here. NewWebScan, ScanDetail, Dashboard, SecurityReports, the remaining
Group B pages, Group C/D and the shell are untouched.

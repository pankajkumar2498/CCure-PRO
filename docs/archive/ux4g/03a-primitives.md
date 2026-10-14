# PHASE 3 CHECKPOINT REPORT

## Batch

**Checkpoint 3A — shared design-system primitives.** No application page was
migrated, and none was modified.

## Scope

**Added** — ten primitives completing the §9 list:

| Component  | Export                                                             | Lines |
| ---------- | ------------------------------------------------------------------ | ----: |
| Table      | `CcureTable`, `CcureTableStatus`                                   |   265 |
| Tabs       | `CcureTabs`, `CcureTabPanel`, `useCcureTabs`                       |   181 |
| Feedback   | `CcureLoader`, `CcureSkeleton`, `CcureEmptyState`, `CcureProgress` |   163 |
| Pagination | `CcurePagination`                                                  |   100 |
| Card       | `CcureCard`                                                        |    82 |
| Breadcrumb | `CcureBreadcrumb`                                                  |    71 |
| Badge      | `CcureBadge`                                                       |    61 |

**Modified** — `components.css` (+651 lines of `cc-*` rules),
`design-system/index.js` (export surface), `DesignSystemShowcase.jsx`
(dev-only, +8 sections).

**Already existed** from Phases 1–2 and left alone: Button, Input, Select,
FormField, Alert, Modal, Toast, AppShell, `useFocusTrap`.

The §9 list is now complete: **17 of 17 primitives exist.**

## Before

| Metric                                 |                                     Value |
| -------------------------------------- | ----------------------------------------: |
| Design-system components               |                   5 files, ~646 JSX lines |
| Design-system CSS                      | 1,210 lines (components + shell + tokens) |
| Exported primitives                    |                                         8 |
| Tests                                  |                            137 (10 files) |
| CSS bundle                             |             266.75 kB raw / 46.27 kB gzip |
| JS bundle                              |          1,701.30 kB raw / 420.38 kB gzip |
| Application tables with `scope`        |                     0 of 330 header cells |
| Application tab bars with `role="tab"` |                                    0 of 4 |
| Hand-rolled pagination implementations |                                         7 |
| Breadcrumb implementations             |                                         0 |

## Changes

Each priority component addresses a gap measured in the application, not an
abstraction invented for its own sake.

**Table.** The application has 46 tables and 330 header cells with **zero
`scope` attributes and zero captions**; a representative one
(`ScanCredentials.jsx`) is a raw `<table>` with inline styles and hardcoded
`#e2e8f0` / `#64748b`. `CcureTable` supplies a caption (visible or
screen-reader-only), `scope="col"` on every header, `scope="row"` on the
identifying cell, `aria-sort` with a real `<button>` inside the header, a
scroll container that becomes keyboard-reachable **only when it actually
overflows**, and loading/empty states that occupy the table rather than
replacing it.

It has **two APIs**, because §10 says not to force differently-shaped tables
into one structure: declarative `columns`/`rows` for the common case, or pass
`children` and keep the caption, semantics, scroll container and styling while
writing your own `<tbody>`.

**Tabs.** Four pages drive tabs with `<button className={active ? "active" : ""}>`
and a conditionally rendered panel — **zero `role="tab"`, zero
`aria-selected`, zero `aria-controls` anywhere in the codebase**. `CcureTabs`
implements the WAI-ARIA pattern including **roving tabindex**: the tab list is
one tab stop, not one per tab. With `AssetDetail`'s four tabs the naive
version costs four Tab presses to get past the bar.

**Pagination.** Modelled on what seven pages already do
(`page`/`pageSize`/`total`, "Showing X–Y of N", size selector, prev/next), so
migrating is substitution rather than redesign. `page` stays **1-based** —
every existing call site and every backend query parameter is 1-based, and a
0-based component would put an off-by-one at each of the seven boundaries.

**Breadcrumb.** None existed. The last crumb is `aria-current="page"` and
deliberately not a link.

**Badge.** Replaces at least eighteen ad-hoc badge classes
(`auth-brand-badge`, `ns-chip`, `method-chip`, `pm-status-pill`, `port-pill`,
`sqb-pill`, `scan-card-badge` …), several with hardcoded hex that does not
respond to the theme. `children` is required — colour is never the only
carrier of meaning.

### Two defects found and fixed during this work

- **`useId` mismatch in Tabs.** `CcureTabs` generated its own id while
  `useCcureTabs` generated another, so `aria-controls` would have pointed at
  an element that does not exist — the exact silent breakage the component's
  own doc comment warns about, since a broken association looks identical to a
  working one. `id` is now threaded through `listProps` so a caller cannot
  forget it.
- **Stray scrollbar on the tab strip.** `overflow-x: auto` forces `overflow-y`
  to compute to `auto` as well, so the tab's `margin-bottom: -1px` overflowed
  vertically and Chrome rendered a vertical scrollbar beside the tabs (visible
  in the first screenshot). `overflow-y: hidden` would have clipped that pixel
  — half the active tab's 2px indicator. The rule is now an inset box-shadow,
  which takes no layout space at all.

## Component Mapping

Prepared for later checkpoints; **nothing has been migrated yet**.

| Existing implementation                                  | Replacement                   |   Consumers waiting |
| -------------------------------------------------------- | ----------------------------- | ------------------: |
| raw `<table>` + inline styles                            | `CcureTable`                  | 25 files, 46 tables |
| `<button className="db-tab …">`                          | `CcureTabs` + `CcureTabPanel` |             4 files |
| bespoke `pagination-row` blocks                          | `CcurePagination`             |             7 files |
| 18+ ad-hoc badge/pill classes                            | `CcureBadge`                  |            27 files |
| card-shaped `<div>`s                                     | `CcureCard`                   |            34 files |
| ad-hoc spinners                                          | `CcureLoader`                 |            30 files |
| `common/Skeleton.jsx` (injects a `<style>` per instance) | `CcureSkeleton`               |                   — |
| `common/EmptyState.jsx`                                  | `CcureEmptyState`             |            15 files |
| — (none existed)                                         | `CcureBreadcrumb`             |                   0 |

## After

| Metric                   |      Before |           After |            Δ |
| ------------------------ | ----------: | --------------: | -----------: |
| Design-system components |     5 files |    **12 files** |           +7 |
| Design-system JSX/JS     |        ~646 |       **1,950** |       +1,304 |
| Design-system CSS        |       1,210 |       **1,861** |         +651 |
| Exported primitives      |           8 |  **24 symbols** |          +16 |
| Design-system tests      |          98 |         **151** |          +53 |
| Total tests              |         137 |         **190** |          +53 |
| CSS bundle raw           |   266.75 kB |   **276.81 kB** |    +10.06 kB |
| CSS bundle gzip          |    46.27 kB |    **47.56 kB** | **+1.29 kB** |
| JS bundle raw            | 1,701.30 kB | **1,701.30 kB** |        **0** |
| JS bundle gzip           |   420.38 kB |   **420.38 kB** |        **0** |
| Build time               |      0.51 s |          0.45 s |            — |

**Application metrics, all unchanged — this is the point of the checkpoint:**

| Metric                                        |  Baseline |       Now |
| --------------------------------------------- | --------: | --------: |
| Application JSX files                         |        75 |        75 |
| Application JSX LOC                           |    50,716 |    50,716 |
| Legacy CSS LOC                                |    14,547 |    14,547 |
| **Inline styles in application code**         | **2,282** | **2,282** |
| Legacy token references                       |     1,791 |     1,791 |
| `--ccure-*` references in application code    |         0 |     **0** |
| Application files importing the design system |         0 |     **0** |

`git diff --stat` over `src/pages`, `src/components`, `src/modules`,
`src/styles`, `src/api`, `src/context` and `src/auth` is **empty**. The only
`--ccure-*` references under `src/pages` are in the dev-only showcase.

### On the bundle figures

**JS cost is zero.** The primitives are tree-shaken out of production because
nothing but the dev-only showcase imports them — verified directly:
`CcureTable`, `CcureTabs`, `CcurePagination`, `CcureBreadcrumb`, `CcureCard`
and `CcureBadge` each appear **0 times** in `dist/assets/*.js`. They begin
costing bytes when pages actually use them, and by then they are replacing
bespoke code.

**CSS cost is +1.29 kB gzip, paid now.** CSS is not tree-shaken, so the `cc-*`
rules ship whether or not a page uses them. That is the honest state; it will
be repaid as pages retire bespoke CSS. Well inside the §45 guardrail — the
UX4G contribution is untouched at 9.6 kB gzip, and no UX4G component CSS,
runtime or icon font has crept back in.

## Accessibility

Every primitive was built to close a measured gap, and 53 tests assert the
behaviour rather than the appearance.

| Area                   | Result                                                                                                                                                                 |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Table semantics        | `<caption>` names every table; `scope="col"` on all headers; `scope="row"` on the identifying cell; `aria-sort` on sortable columns                                    |
| Sortable headers       | real `<button>` inside the `<th>` — Tab-reachable, Enter/Space-activatable; verified by keyboard in test                                                               |
| Table loading vs empty | the empty message is **suppressed while loading** — "No findings" and "not assessed yet" mean opposite things on this product                                          |
| Tabs                   | `tablist`/`tab`/`tabpanel`, `aria-selected`, two-way `aria-controls` ↔ `aria-labelledby`, **roving tabindex**, Arrow/Home/End with wrap, opt-out of activate-on-focus |
| Pagination             | labelled `<nav>`, **live region** announcing "Page 2 of 9" (paging changes rows without moving focus), labelled page-size `<select>`                                   |
| Breadcrumb             | labelled `<nav>` + `<ol>`; last item `aria-current="page"` and **not a link**; separators `aria-hidden`                                                                |
| Card                   | title is a real heading at a caller-chosen level; `aria-labelledby` only when titled — an unnamed landmark is worse than none                                          |
| Badge                  | text always rendered; decorative dot `aria-hidden`                                                                                                                     |
| Progress               | `aria-valuenow` **omitted** when indeterminate rather than set to 0 — a scan whose progress is unknown must not report no progress                                     |
| Loader                 | `role="status"`, polite, always has accessible text even with no label                                                                                                 |
| Skeleton               | `aria-hidden` — a reader must not announce grey boxes; `CcureTableStatus` speaks instead                                                                               |
| Reduced motion         | spinner, skeleton shimmer and indeterminate progress all stop                                                                                                          |
| Contrast               | unchanged; 32 assertions still pass at 4.5:1 in both themes                                                                                                            |

Nothing from Phases 1–2 regressed: focus trap, focus restoration, dialog
semantics, `aria-describedby`, `aria-current`, skip link, live regions,
landmarks, forced-colors and the `:focus-visible` floor are all still asserted.

## Functional Regression

**N/A — no application code was executed differently.** No page, API module,
context, route, guard or business logic was touched. `App.jsx` and `main.jsx`
carry only the Phase 1/2 integration lines, unchanged this checkpoint.

## Visual Regression

Showcase captured headless at 1440×3000 in both themes. All ten primitives
render correctly: sortable table with mono/right-aligned columns, skeleton
loading rows, empty state inside the table with the header preserved, tabs
with counts, pagination, breadcrumb, all badge variants, cards with progress.

One intentional visual change was made mid-checkpoint — the tab strip's rule
moved from `border-bottom` to an inset shadow — to remove the stray scrollbar
described above. Re-captured after the fix; the scrollbar is gone and the
active-tab indicator is at full 2px.

## Dark Mode

**PASS.** Both themes captured and verified. One `data-theme` attribute still
drives both token sets; `PreferencesContext` and `preferences.theme` untouched;
no second mechanism introduced.

A test additionally asserts that no primitive pins a colour or background
inline while rendering under `data-theme="dark"` — that is what makes a single
attribute able to switch the theme at all.

## Tests

**PASS — 190 passed, 11 files** (was 137/10).
53 new: Table 12, Tabs 9, Pagination 7, Breadcrumb 6, Card 5, Badge 3,
Feedback 8, theming 1, controlled state 1, plus assertions within.

## Lint

**PASS** — ESLint clean at `--max-warnings=0`.

## Build

**PASS** — 0.45 s. The token-only pipeline is unchanged: stylesheet
8,120.4 → 58.5 kB, one font kept, six dropped.

## CSP

**PASS — byte-for-byte unchanged.**

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self';
object-src 'none'; base-uri 'self'; frame-ancestors 'none';
```

`nginx.conf` has not been edited in any phase. Browser console clean in both
themes — no CSP or blocked-resource messages.

## Air-Gap

**PASS.** The showcase requested exactly one font,
`/assets/fonts/ux4g/noto-sans.woff2`, same-origin. The production image
contains one font file. No CDN, Google Fonts, analytics or telemetry
reference; no UX4G runtime marker in the built JS — all still asserted by the
guardrail tests, which run against `dist/`.

## Unmigrated Page Regression

**PASS — zero pixels.** Same deterministic methodology as Phases 1–2: the
unmigrated `Login` page rendered by the baseline container (3200, no UX4G) and
the 3A image (3299), with `--force-prefers-reduced-motion`.

```
p3a-baseA   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (no UX4G)
p3a-baseB   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (no UX4G)
p3a-ux4g    428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (Phase 3A)

self-consistency : IDENTICAL     ← the comparison is valid
baseline vs 3A   : IDENTICAL
```

**The same hash as Phases 1 and 2.** Three checkpoints of design-system work
have changed unmigrated pages by nothing.

## Remaining Issues

| #   | Issue                                                                                                           | Severity              | Position                                                                                                      |
| --- | --------------------------------------------------------------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------- |
| 1   | **UX4G licence unresolved**                                                                                     | **Open release gate** | Carried forward — see below                                                                                   |
| 2   | `cc-*` CSS ships before any page uses it (+1.29 kB gzip)                                                        | Low                   | Inherent to CSS not being tree-shaken; repaid as pages migrate                                                |
| 3   | Old primitives still exist beside the new ones (`common/Button.jsx`, `common/Skeleton.jsx`, `layout/Modal.jsx`) | Expected              | Deleting them belongs to Checkpoint 3H, after their consumers migrate. Removing them now would break 79 pages |
| 4   | Table has no built-in row selection, expansion or column resize                                                 | Deliberate            | No application table needs them today. §17 — not building abstractions ahead of a consumer                    |
| 5   | Tabs have no vertical orientation                                                                               | Deliberate            | Same reason; all four existing tab bars are horizontal                                                        |
| 6   | Pagination offers no numbered page list                                                                         | Deliberate            | None of the seven implementations has one; the API accommodates it later without a breaking change            |

## Open Release Gates

**UX4G licence — unresolved, unchanged since Phase 2.**

```
UX4G README declares MIT (badge + "## License" section)
package.json has no license field
package has no LICENSE file
package contains no copyright notice to reproduce
embedded Noto Sans carries its own OFL requirements
```

Written clarification is still required from
`support.ux4g@digitalindia.gov.in` before production release of redistributed
UX4G-derived assets. **No copyright notice has been invented and no legal
clearance is claimed.** Phase 3 engineering continues; the gate is not closed.

## Files Changed

**Added (9)**

```
Frontend/src/design-system/components/CcureTable.jsx          265
Frontend/src/design-system/components/CcureTabs.jsx           181
Frontend/src/design-system/components/CcureFeedback.jsx       163
Frontend/src/design-system/components/CcurePagination.jsx     100
Frontend/src/design-system/components/CcureCard.jsx            82
Frontend/src/design-system/components/CcureBreadcrumb.jsx      71
Frontend/src/design-system/components/CcureBadge.jsx           61
Frontend/src/__tests__/design-system/primitives.test.jsx      608
docs/ux4g/03a-primitives.md                                     —
```

**Modified (3)**

```
Frontend/src/design-system/components/components.css   495 → 1,146  (+651)
Frontend/src/design-system/index.js                     36 →    71  (+35)
Frontend/src/pages/DesignSystemShowcase.jsx            ~270 →   522  (dev-only)
```

**Not modified:** every application page, component, module, stylesheet, API
client, context and route; `nginx.conf`; `Dockerfile`; `docker-compose.yml`;
`package.json`; the UX4G pipeline and its guardrails.

## Commit(s)

None yet — the work is staged for review. Proposed split, per §40:

```
feat(design-system): add accessible Table primitive
feat(design-system): add Tabs primitive with roving tabindex
feat(design-system): add Pagination primitive
feat(design-system): add Breadcrumb primitive
feat(design-system): add Card, Badge and feedback primitives
test(design-system): cover 3A primitive accessibility
docs(ux4g): checkpoint 3A report
```

## Recommendation

**GO for Checkpoint 3B.**

All §19 acceptance criteria are met: 17 of 17 primitives exist, APIs are
documented at their definitions, tests and lint and build pass, no UX4G
runtime or `ux4g-*` class was introduced, CSP and air-gap are unchanged, both
themes work, contrast holds, and the showcase demonstrates every primitive.

One judgement to flag before 3B. §16 lists fifteen candidate security
patterns; the survey done for this checkpoint suggests **only a few are
justified on current evidence** — `SeverityBadge` (RiskBadge already exists but
hardcodes hex and does not theme), `ScanStatus` and `ScanProgress` have many
repeated implementations, while `ComplianceMatrix` and `SecurityMetric` appear
close to once each. I intend to apply §16's method — find the repetition
first, build only what it justifies — rather than building all fifteen. Say if
you would rather I cover the full list.

**STOPPING HERE for review.** No production page will be migrated until
Checkpoint 3B is approved.

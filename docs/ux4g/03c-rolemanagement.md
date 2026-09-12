# PHASE 3 CHECKPOINT REPORT

## Batch

**Checkpoint 3C — `RoleManagement`.** One production page. No other page was
modified.

## Page Selection

```
Selected page:   src/pages/admin/RoleManagement.jsx   (189 LOC)
Risk level:      lowest of Group A
```

Chosen against §3's six criteria:

| Criterion              | RoleManagement                                                 |
| ---------------------- | -------------------------------------------------------------- |
| Business/security risk | **Read-only.** Two GETs, zero writes, zero mutations           |
| Backend interaction    | 2 endpoints, no query parameters, no polling                   |
| State complexity       | 6 `useState`, 2 `useCallback`, 1 `useEffect`; no state machine |
| Existing UI patterns   | Card, table, chip, spinner, alert, empty state — all clear     |
| Exercises primitives   | Card, Table, Badge, Loader, Alert, EmptyState, Button          |
| Regression surface     | RBAC is enforced at the **route**, not in the page             |

**Not ForgotPassword**, which is the smaller file: it drives
`/auth/forgot-password`, whose uniform-200 no-account-oracle behaviour CLAUDE.md
documents as deliberately security-sensitive. §3 says not to pick a page with
complex security behaviour, and the review burden of touching anything adjacent
to that flow is disproportionate for a first migration.

The one thing RoleManagement does **not** exercise is `CcureInput` /
`CcureFormField` — it has no inputs. That coverage belongs to the next batch;
`ForgotPassword` or `ResetPassword` would supply it.

## Baseline

Measured before any change.

| Metric                                   |                                                                 Value |
| ---------------------------------------- | --------------------------------------------------------------------: |
| JSX LOC                                  |                                                                   189 |
| Page-specific CSS (in `styles/scan.css`) |                                              60 lines / 52 rule lines |
| Inline `style={{`                        |                                                                     9 |
| Hardcoded colours                        | 5 (`#fef2f2`, `#dc2626`, `#f0f9ff`, `#0369a1`, `rgba(37,99,235,.05)`) |
| Legacy token references                  |                                                                     3 |
| `--ccure-*` references                   |                                                                     0 |
| Buttons / inputs / selects / forms       |                                                         1 / 0 / 0 / 0 |
| Tables                                   |                  1 — **0 captions, 0 `scope` attributes on 3 `<th>`** |
| Alerts                                   |                            1 (`.alert.alert--error`, a plain `<div>`) |
| Cards / panels                           |                                                           2 (`.card`) |
| Badges / pills                           |                                        1 (`.method-chip`, inline hex) |
| Loading indicators                       |          2 bare `<div className="spinner" />`, **no accessible text** |
| Empty states                             |                             1 (`<td colSpan="3">` with inline styles) |
| Modals / tabs / breadcrumbs / pagination |                                                         0 / 0 / 0 / 0 |
| API calls                                |                                                                     2 |
| Route                                    |                                                        `/admin/roles` |
| Query parameters                         |                                                                  none |

### A pre-existing defect found while baselining

The page contained `color: var(--primary)` in two places. **`--primary` is not
a token this application defines** — the palette uses `--accent`. It therefore
resolved to nothing and the text simply inherited its colour. Confirmed in the
rendered DOM during the baseline test run:

```html
<span style="color: var(--primary);">superadmin</span>
```

Presentation-only, so it is in scope for a UI migration under §12 rather than
something to report and leave.

## Functional Baseline

```
Route     /admin/roles
Guard     PrivateRoute requiredPermission={{ resource: "roles", action: "read" }}

GET /admin/roles/               → { roles: [{ id, name, description }] }
GET /admin/roles/{id}/permissions/ → { permissions: [{ id, resource, action, description }] }

On mount        listRoles() once
                → auto-selects roles[0] → listRolePermissions(roles[0].id)
On role click   listRolePermissions(role.id)
On roles error  setError("Failed to load roles.")
On perms error  pushToast("Failed to load permissions for this role.", "error")
No writes, no query parameters, no polling, no navigation
```

**The baseline was captured as an executable artefact**, not prose:
`src/__tests__/pages/admin/RoleManagement.test.jsx` was written against the
**unmigrated** page and run before any change. It scored **12 passed, 10
failed**. The 12 passing are the functional contract that must survive; the 10
failing are the accessibility and theming gaps, i.e. the migration's
specification. All 23 pass now.

That test is also the substitute for a browser screenshot — see _Visual
Regression_.

## Migration Map

| Existing implementation                | CCure replacement                                          |
| -------------------------------------- | ---------------------------------------------------------- |
| `<div className="card role-card">` ×2  | `CcureCard` (title as a real `<h3>`, named region)         |
| `<div className="alert alert--error">` | `CcureAlert variant="danger"` (`role="alert"`)             |
| `<Button>` from `common/Button`        | `CcureButton` + `aria-pressed`                             |
| raw `<table className="data-table">`   | `CcureTable` (caption, `scope="col"`, `scope="row"`)       |
| `.method-chip` with inline hex         | `CcureBadge variant={danger\|info}`                        |
| `<div className="spinner" />` ×2       | `CcureLoader` + an `sr-only` `role="status"` for the table |
| `<td colSpan="3">` empty message       | `CcureEmptyState` via `CcureTable`'s `empty` prop          |
| `.role-list-item` selection styling    | `aria-pressed` + `styles/role-management.css`              |

Not replaced: `useToasts` / `ToastContainer` from `common/Toast`. `CcureToast`
is a provider-based API; swapping it would change the application's toast
architecture across 14 consumers, which is not a single-page migration. Left
for 3H.

## Changes

**Business logic is byte-identical.** `handleSelectRole`, `loadRoles`, the
`useEffect`, all six `useState` declarations, both `try/catch/finally` blocks,
the error strings and the `"Allows access to " + resource` fallback were copied
across unchanged, including the temporal-dead-zone comment explaining the
callback ordering. Only the returned JSX changed.

Three substantive presentation decisions:

- **`manage` stays visually distinct.** It was red (`#dc2626` on `#fef2f2`)
  against blue for everything else. `manage` is the broadest grant in the
  catalogue, so the distinction is real and survives as
  `variant={action === "manage" ? "danger" : "info"}` — semantic rather than
  literal, and now theme-aware.
- **Selection is announced, not just painted.** `aria-pressed` on the role
  button, and the CSS keys off that attribute, so the visual and announced
  states cannot drift apart. A 3px bar carries the state without relying on
  colour (WCAG 1.4.1).
- **The empty state stays inside the table.** `CcureTable`'s `empty` prop keeps
  the header row, so selecting a role with no permissions does not reflow the
  panel.

### CSS

`styles/scan.css`: **60 lines removed** (`.role-card`, `.role-card__header`,
`.role-list`, `.role-list-item`, `:hover`/`:focus-visible`, `--selected`,
`__title`, `__subtitle`, `.section-loader`). Each was verified as
**zero-consumer by exact class-token search across every JSX file** before
deletion — not by assuming this page was the only user.

`styles/role-management.css`: **85 lines added, 47 of them actual rules.**

Net page-specific CSS: **52 rule lines → 47**, a modest reduction. It is small
because most of the old CSS was replaced by _components_, not by other CSS —
the card, table, badge, loader and empty state now carry their own styling in
the design system. What remains is the one genuinely page-specific thing: a
vertical list of selectable roles. §17 says not to abstract that; it has one
consumer.

Shared selectors were **not** touched: `.data-table` (9 consumers),
`.table-wrap` (17), `.ip-code` (8), `.method-chip` (3), `.page-inner` (21),
`.admin-grid` (still used by this page).

## Accessibility

|                               | Before                         | After                                                       |
| ----------------------------- | ------------------------------ | ----------------------------------------------------------- |
| Table accessible name         | none                           | `<caption>`, screen-reader-only                             |
| `scope="col"`                 | 0 of 3                         | **3 of 3**                                                  |
| Row identity                  | none                           | `scope="row"` on the resource cell                          |
| Selected role announced       | **no** — styled only           | `aria-pressed`, exactly one true                            |
| Loading announced             | **no** — bare spinner div      | `role="status"`, polite, with text                          |
| Permissions loading announced | **no**                         | `sr-only` `role="status"` (skeleton rows are `aria-hidden`) |
| Error announced               | plain `<div>`                  | `role="alert"`                                              |
| Card titles                   | `<h3>` (roles) / styled `<h3>` | real headings, named regions                                |
| Colour-only meaning           | selection was colour-only      | 3px bar + `aria-pressed`                                    |
| Undefined `--primary`         | 2 uses, resolved to nothing    | removed                                                     |

Twelve of the suite's 23 assertions cover these.

## Visual Regression

**Page-level pixel capture: N/A — the page is behind
`PrivateRoute requiredPermission={{roles, read}}`.** Capturing it in a browser
needs an authenticated session against the live deployment, and no credentials
are available; none were invented, and no auth guard was weakened to make a
screenshot possible.

The deterministic substitute is the 23-assertion suite, which renders the real
component with the real hooks against a mocked API and asserts structure, ARIA
and the absence of inline colour — including a render under
`data-theme="dark"`.

Intentional visual changes, all consequences of the migration:

- Action chips take token colours instead of `#dc2626`/`#0369a1`, so they now
  respond to the theme.
- The selected role gains a 3px indicator bar.
- The permissions table scrolls **inside its own container** rather than
  widening the page.
- The loading states show text beside the spinner.

## Responsive Behavior

`.admin-grid` — the two-column layout — was **not** modified, so the page's
responsive behaviour is unchanged at the breakpoints `responsive.css` defines.

One improvement: the old raw `<table>` had no overflow container, so a wide
permissions table widened the page. `CcureTable` wraps it in
`overflow-x: auto`, and the container becomes keyboard-focusable **only when it
actually overflows**. No `overflow-x: hidden` was used and no content is
hidden.

## Functional Regression

**PASS — none.** Twelve assertions written against the unmigrated page pass
unchanged: endpoint identity, call counts, call arguments, auto-selection of
`roles[0]`, selection behaviour, both error paths, the description fallbacks
and the page title.

No change to: API contract, request payloads, response handling, validation,
authentication, authorization, RBAC, route path, query parameters, navigation.

## API / Network Regression

|                    | Before                                                    | After     |
| ------------------ | --------------------------------------------------------- | --------- |
| Endpoints          | `GET /admin/roles/`, `GET /admin/roles/{id}/permissions/` | identical |
| Calls on mount     | 1 + 1                                                     | 1 + 1     |
| Calls on selection | 1                                                         | 1         |
| Polling            | none                                                      | none      |
| New requests       | —                                                         | **none**  |

Asserted by _"makes no other request"_, which fails if the migration
introduces polling or an extra endpoint.

## Before / After Metrics

| Metric                     |                Before |                 After |            Δ |
| -------------------------- | --------------------: | --------------------: | -----------: |
| Page JSX LOC               |                   189 |                   205 |          +16 |
| Page CSS (rule lines)      |                    52 |                    47 |       **−5** |
| Inline `style={{`          |                     9 |                 **0** |       **−9** |
| Hardcoded colours (code)   |                     5 |                 **0** |       **−5** |
| Legacy token references    |                     3 |                 **0** |       **−3** |
| Raw `<table>` / `<th>`     |                 1 / 3 |                 0 / 0 |            — |
| `scope` attributes         |                     0 | 3 col + 1 row per row |            — |
| CCure component instances  |                     0 |    **8** (7 distinct) |           +8 |
| Old shared components used | 2 (`Button`, `Toast`) |           1 (`Toast`) |           −1 |
| API endpoints              |                     2 |                     2 |            0 |
| Tests (whole suite)        |                   230 |               **253** |          +23 |
| CSS bundle raw             |             278.00 kB |             278.12 kB |     +0.12 kB |
| CSS bundle gzip            |              47.61 kB |          **47.73 kB** | **+0.12 kB** |
| JS bundle raw              |           1,701.67 kB |           1,705.82 kB |     +4.15 kB |
| JS bundle gzip             |             420.30 kB |         **421.39 kB** | **+1.09 kB** |
| Build time                 |                0.90 s |                2.25 s |            — |

**JSX LOC grew by 16, and that is documentation, not markup.** The file gained
a component doc block and inline notes explaining the three presentation
decisions. The markup itself is smaller: nine inline style objects and a
hand-written table are gone.

## Tests

**PASS — 253 passed, 13 files** (was 230/12). 23 new, all for this page.

## Lint

**PASS** — ESLint clean at `--max-warnings=0`. (One unused import was flagged
mid-checkpoint and fixed.)

## Build

**PASS** — 2.25 s. UX4G pipeline unchanged: 8,120.4 → 58.5 kB, one font kept,
six dropped.

## CSP

**PASS — byte-for-byte unchanged.**

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self';
object-src 'none'; base-uri 'self'; frame-ancestors 'none';
```

`nginx.conf` has not been edited in any phase.

## Air-Gap

**PASS.** Requests from the 3C production image on `/login`:

```
/login  /  /favicon.svg  /assets/index-*.js  /assets/index-*.css
/api/auth/refresh          (pre-existing)
/api/auth/check-email      (pre-existing)
```

Compared against the identical page on the baseline container:

```
external hosts attributable to CCure: NONE
```

No CDN, font host, analytics or telemetry. No new dependency.

## Unmigrated Login Regression

**PASS — zero pixels.**

```
c-baseA   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3200, no UX4G)
c-baseB   428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3200, no UX4G)
c-ux4g    428703 bytes  81BDD19B5730080794B1FBEA579C9E47   (3299, Phase 3C)

self-consistency : IDENTICAL
baseline vs 3C   : IDENTICAL
```

**Fifth consecutive checkpoint at the same hash**, and the first one where a
production page actually changed. The expected value was not adjusted and
`Login.jsx` was not touched.

## Bundle Impact

CSS **+0.12 kB gzip**, JS **+1.09 kB gzip**.

The JS increase is expected and was predicted in the 3A report: `CcureTable`,
`CcureCard`, `CcureBadge`, `CcureLoader` and `CcureEmptyState` were previously
tree-shaken out because only the dev-only showcase imported them. A real page
now uses them, so they enter the production bundle for the first time —
verified directly (`cc-table-wrap` present in `dist/assets/*.js`).

That cost is paid once. Every subsequent page migrating onto the same
primitives adds markup, not components, and retires bespoke code as it goes.

## Files Changed

**Modified (3)**

```
Frontend/src/pages/admin/RoleManagement.jsx     189 → 205  (presentation only)
Frontend/src/styles/scan.css                  3,686 → 3,634  (−60, proven dead)
```

**Added (2)**

```
Frontend/src/styles/role-management.css                    85 lines (47 rules)
Frontend/src/__tests__/pages/admin/RoleManagement.test.jsx  23 tests
docs/ux4g/03c-rolemanagement.md                             —
```

**Not modified:** every other page, every API client, every context, `App.jsx`,
routing, `PrivateRoute`, `permissions.js`, `nginx.conf`, `Dockerfile`,
`docker-compose.yml`, `package.json`, the design system, the UX4G pipeline and
its guardrails. No old shared component was deleted — `common/Button` still has
7 consumers, `common/Toast` 14, `layout/Modal` 6.

## Commits

None yet — staged for review. Proposed split per §40:

```
refactor(roles): replace legacy controls with CCure primitives
refactor(roles): migrate page tokens and remove proven-dead CSS
test(roles): add migration coverage
docs(ux4g): checkpoint 3C RoleManagement report
```

## Open Release Gates

**UX4G licence — unresolved, unchanged.**

```
README declares MIT
package.json has no license field
package has no LICENSE file
package contains no copyright notice
embedded Noto Sans has OFL requirements
```

Written clarification from `support.ux4g@digitalindia.gov.in` remains required
before production release containing redistributed UX4G-derived assets. No
notice invented; no legal clearance claimed.

## Remaining Issues

| #   | Issue                                                      | Severity              | Position                                                                                                                                                                     |
| --- | ---------------------------------------------------------- | --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | UX4G licence                                               | **Open release gate** | Above                                                                                                                                                                        |
| 2   | Page-level visual capture is N/A for auth-gated pages      | Medium                | The test suite is the substitute. If you want pixel capture for Group A admin pages, a throwaway test account would be needed — that is your decision, not one I should make |
| 3   | `common/Toast` still used by this page                     | By design             | Provider-based swap affects 14 consumers; 3H                                                                                                                                 |
| 4   | `--primary` is referenced elsewhere in the codebase        | Low, pre-existing     | Not investigated — §42 says do not clean up unrelated code. Worth a separate sweep                                                                                           |
| 5   | `CcureInput` / `CcureFormField` unexercised by a real page | Expected              | Next batch should be a form page                                                                                                                                             |
| 6   | JSX LOC grew 16 lines                                      | Cosmetic              | Documentation, not markup                                                                                                                                                    |

## Recommendation

**GO for the next 3C batch.**

The methodology worked, and the part worth keeping is the sequencing: writing
the test suite against the **unmigrated** page first produced a 12-pass /
10-fail baseline in which the failures _were_ the specification. Nothing had to
be judged by eye, and the functional contract was pinned before a line changed.

For batch 2 I would propose **`ForgotPassword`** — it is the smallest Group A
page, and it is the one that exercises `CcureInput` and `CcureFormField`, which
this batch could not. Its auth-adjacency is manageable now that the method is
proven: the same approach applies, and the API call is a single POST whose
uniform-200 semantics the tests would pin before anything moves.

If you would rather stay away from auth entirely, `DeletedUsers` or
`OrganizationManagement` are the alternatives — both have forms and tables, but
both perform writes, so they carry more risk than ForgotPassword's single POST.

**STOPPING HERE for review.** No second page will be migrated without approval.

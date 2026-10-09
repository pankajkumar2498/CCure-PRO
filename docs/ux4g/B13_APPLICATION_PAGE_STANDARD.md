# B.13 — One page structure for the whole application

Date: 8 October 2026, on `modular_architecture`, following
[B.12](B12_AUDIT_UI_RESTORATION.md). Scope: page-level structure, typography,
spacing and icons for every page inside the application shells — Common Platform,
CCure Audit and the Policy Pro / Rank / IR entry pages. Sign-in screens have their
own shell and are out of scope. No API, payload, route, permission decision,
business rule or backend file changes.

## 1. Inventory (Phase 1)

### 1.1 Reference values (Common Platform)

`shell/layout/platform-layout.css`, at the 1920 px desktop reference (15 px root):

| Property                         | Token                                                                      | Rendered           |
| -------------------------------- | -------------------------------------------------------------------------- | ------------------ |
| Page inset, top / sides / bottom | `md + lg` / `2 × lg` / `3 × lg`                                            | 26.25 / 30 / 45 px |
| Page inset, ≤ 768 px             | `lg` / `lg` / `3xl`                                                        |                    |
| Title                            | `--ccure-font-display`, `--ccure-text-2xl`, `--ccure-weight-bold`, −0.02em | 22.5 px / 700      |
| Subtitle                         | `--ccure-text-base`, `--ccure-text-secondary`, `--ccure-leading-relaxed`   | 13.1 px            |
| Header to content                | `--ccure-space-xl`                                                         | 18.75 px           |
| Card radius                      | `--ccure-radius-lg` (shared `CcureCard`)                                   | 11.25 px           |

### 1.2 Page-header implementations found

Even the reference had three: `page-title-row` + `<h1 class="page-title">` (Users,
Roles, Audit Logs), `<h2 class="page-title">` with no `<h1>` at all (Deleted Users,
Organizations), and `pl-title` + `pl-lead` (Home, Policy/Rank/IR entry pages, Access
denied). Email Domain Rules used a bare `<h1>`.

Audit had twenty: legacy `page-title-row` / `page-title` from `styles/layout.css`
(Scan Templates, Schedules, Credentials, Configuration Checks, validator,
Credentialed Scan, Archived, Recycle Bin, Remediation, web scanning) plus
page-specific headers `ar-page-header`, `sd-page-header`, `vb-page-header`,
`ad-header`, `sh-header`, `sp-header`, `sc-header`, `scr-header`, `cr-header`,
`p1-header`, `p2-header`, `p3-header`, `ns-title` (centred hero), `nmap-header`,
`amt-header`, `cwh-header`, `wsp-header` and the Reports `reports-header-box`.

Page containers: `.page-inner` (legacy, padded `28px 32px 48px` in px by
`styles/layout.css`, re-padded with tokens by `platform-layout.css` for Common
only) and page-owned padded wrappers `sh-page`, `sp-page`, `sc-page`, `ar-page`,
`cr-page`, `p1-page`, `p2-page`, `ns-page`, `nmap-page`, `amt-page`, `cwh-page`.

Measured result (65 page states): five title sizes (18.75 / 20.25 / 22.5 / 24 px),
four left insets (19 / 23 / 32 / 55 px, two pages centred), three subtitle sizes.

Pages with no `<h1>`: Deleted Users, Organizations (an `<h2>`), Archived Scans and
Recycle Bin (`page-title` on a `<div>`), Scan Comparison (no title in its empty
state).

### 1.3 Icons

295 source lines carry emoji used as UI icons: action buttons (download, delete,
refresh, upload, settings), section and card titles, empty states, data maps (OS
families, device types, scan modes, audit actions), status words ("✅ Configured",
🔺/🔻 trends) and shell glyphs (☰, the 🛡 brand mark). Largest: Security Dashboard,
Phase 3 results, Credentialed Results, New Scan, Asset Detail, Compliance, Network
Map, Credentialed Scan, Audit Logs (Common), Reports.

The official UX4G icons are an icon _font_ (`ux4g-icon-outlined`); B.1's approved
font policy deliberately drops all five Material Icons families, and changing that
needs an explicit typography decision. The icons the application already draws
are inline SVG — 24 × 24, 2 px round stroke, `currentColor`, `aria-hidden` — in
`shell/navigation/navIcons.jsx` and Audit's `AppLayout`. That is the approved
system in practice, but it had no shared home.

### 1.4 Shared components to reuse

`CcureCard`, `CcureTable`, `CcureTabs`, form fields, `CcureModal`/`CcureDrawer`,
`CcureAlert`, `CcureBadge`, `CcurePagination`, `CcureButton`, `CcureDropdown`,
`CcureLoader`/`CcureSkeleton`/`CcureEmptyState`, `CcureBreadcrumb` — all already
shared and unchanged by this work. Missing from the design system: a page
container, a page header and an icon set.

## 2. Standard (Phase 2)

Three pieces were added to the design system (`Frontend/src/design-system/`) and
exported from its entrypoint. Nothing else in it changed. Card radius, tables,
tabs, fields, dialogs, alerts and buttons were already shared and stay as they
were.

### 2.1 Page structure

    Shell (header, sidebar)         PlatformLayout / ProductFrame / AppLayout
    └── main
        ├── [workflow band]         ScanStepper only, full width, above the page
        └── CcurePage               inset + entrance animation
            ├── CcurePageHeader     breadcrumb · h1 + badges · subtitle · actions
            ├── [tabs]              CcureTabs, when the page has them
            └── content

- **`CcurePage`** (`patterns/CcurePage.jsx`, `patterns/page.css`) owns the page
  inset: top `md + lg`, sides `2 × lg`, bottom `3 × lg`; at ≤ 768 px `lg` on the
  top and sides and `3xl` at the bottom. It is the only element that pads a page.
  It takes `as` (default `div`), a `className` for the page's own layout and a
  `ref`, which the network map needs for its fullscreen mode.
- **`CcurePageHeader`** renders the page's only `<h1>`. Its props are `title`,
  `badges`, `subtitle`, `breadcrumb`, `actions`, `titleId`, plus `children` for a
  longer description. Badges sit beside the title, never inside the `<h1>`, so
  the accessible name stays the title alone. A page title is text only; no page
  puts an icon in it.
- **Header to content is `--ccure-space-xl`**, whatever the page's own layout.
  A page that lays its children out with a flex or grid `gap` declares that gap
  as `--ccure-page-gap`, and the header's bottom margin subtracts it. Without this
  contract the header-to-content distance would be `xl + gap`, which is how the
  five different distances measured in §1.2 came about.
- **The scan pipeline stepper is a workflow band, not part of the page.** It sits
  above `CcurePage` at the full width of `main`, on the three phase-result pages.
  The page header therefore starts 56–71 px down on those pages instead of 26 px.
  That is intended and is the only exception.

### 2.2 Icons

- **`CcureIcon`** (`icons/CcureIcon.jsx`, `icons/icons.js`) is the application's
  icon primitive. It draws inline SVG, 24 × 24, 2 px round stroke, in
  `currentColor`, the style the navigation already used. It holds 86 shapes,
  including the navigation's own paths, which moved here unchanged.
- **Decorative by default.** An icon is `aria-hidden` and not focusable, and the
  text beside it carries the meaning. An icon that stands alone and _is_ the
  meaning takes a `title`, which makes it `role="img"` with that name. An icon
  button still takes its name from the button's `aria-label`.
- **Sized in `em`**, so it matches the text beside it, as the emoji it replaces
  did. `data-icon` carries the name for tests.
- **An unknown name renders nothing.** The unit suite checks every literal name
  in the source against the set, so a typo fails a test rather than leaving a
  blank in production.
- **Typographic marks are not icons and stay as text:** ✓ ✕ ✔ ✗ → ← ↑ ↓ ↕ ▲ ▼ ▾ ▸ •.
  They are characters in the body font, they inherit its colour and they read as
  words; ↕ is the shared table's sort indicator. ➔ (Dingbats) became →, and
  🔺/🔻 trends became ▲/▼. The circular arrows used as button icons (↻ ↺ ↩) are
  pictographs, not text, and became `refresh-cw` and `rotate-ccw`.
- **Backend glyphs are translated, not changed.** The dashboard insights and the
  asset timeline categories arrive from the API with an emoji. The API is
  unchanged. `modules/audit/utils/backendIcons.js` maps each glyph, or the
  timeline's category key, to an icon name. A glyph it does not know falls back
  to the caller's default and is never printed. It is the only file in `src/`
  allowed to contain an emoji.

### 2.3 What enforces it

- `src/__tests__/design-system/page-structure.test.jsx`:

  - pins the component contracts;
  - fails any routed page under `modules/audit/pages`,
    `modules/audit/web-scanning/pages`, `shell/pages` or `shell/admin/pages` that
    renders a shell without `CcurePage` and `CcurePageHeader`, or that draws its
    own `<h1>`;
  - fails any source using a retired page class (`page-inner`, `page-title-row`,
    `page-title`, `page-subtitle`, `pl-title`, `pl-lead`);
  - fails any non-comment emoji outside `backendIcons.js`;
  - fails any icon name that is not in the set.

  `DesignSystemShowcase.jsx` is exempt: it is development-only and excluded from
  the production build.

- `browser-tests/page-structure.spec.mjs`, for each of the 61 shell page states,
  checks:

  - exactly one `<h1>` in `main`, and it is `CcurePageHeader`'s;
  - its size and weight equal the tokens';
  - its left inset is `2 × lg` at 1440 px and `lg` at 390 px.

  Expected values are read from the tokens on the page, not restated in pixels.

- `scripts/check-ux4g-architecture.mjs` now forbids overflow suppression on
  `.cc-page` where it used to name `.page-inner`.

## 3. Migration (Phase 3)

### 3.1 Pages

43 page files compose `CcurePage` and `CcurePageHeader`:

- **Common Platform (9):**

  - Home, the Policy Pro / Rank / IR entry page and Access Denied;
  - Users, Roles, Organizations, Deleted Users, Email Domain Rules and Audit Logs.

  Deleted Users and Organizations gained the `<h1>` they lacked. Each page's
  loading state now shows the same header as its loaded state.

- **Audit (25):**

  - Dashboard and Security Dashboard;
  - Scan History, Archived Scans and Recycle Bin;
  - Asset Registry and Asset Detail;
  - Vulnerability Browser, Remediation and Compliance;
  - Security Reports and AMT;
  - New Scan, setup and mission views;
  - Phase 1/2/3 results and Network Map;
  - Credentialed Scan and Credentialed Results;
  - Scan Comparison, Credentials, Policies and Schedules;
  - Configuration Checks and the Rule Validator.

  Archived Scans, Recycle Bin and the empty state of Scan Comparison gained an
  `<h1>`. New Scan's centred hero now has the same left-aligned header as every
  other page.

- **Web scanning (9):**
  - Dashboard, Scan List, New Web Scan and Scan Detail;
  - Asset Inventory, Findings Explorer and Attack Surface;
  - All Findings and All Endpoints.

Each page kept its own class on `CcurePage` for its layout. Its actions, badges,
breadcrumbs and descriptions moved into the header's slots unchanged. Event
handlers, API calls, permission checks and routes were not touched.
`authorization-inventory.json` was regenerated: only line numbers moved, and no
authorization site was added or removed.

### 3.2 CSS removed

- **Global** (`styles/layout.css`, `responsive.css`, `animations.css`):
  - the `.page-inner` padding and its responsive overrides;
  - `.page-title-row`, `.page-title` and `.page-subtitle`;
  - the `.page-inner` entrance animation, now `CcurePage`'s, and the
    `.page-title-row` animation.
- **Common** (`shell/layout/platform-layout.css`): its re-padding of `.page-inner`
  and the `pl-title` / `pl-lead` rules. Also `.edr-page` / `.edr-lede`.
- **Audit, about twenty stylesheets:**

  - every page-specific header rule (`ar-page-header`, `sd-page-header`,
    `vb-page-header`, `ad-header`, `sh-header`, `sp-header`, `sc-header`,
    `scr-header`, `cr-header`, `p1/p2/p3-header`, `nmap-header`, `amt-header`,
    `cwh-header`, `wsp-header`, `reports-header-box` and New Scan's `ns-hero`,
    `ns-title` and `ns-sub`);
  - every page wrapper's own padding;
  - the `.wsp-page` and New Scan centring;
  - the padding of bands that re-created the inset inside a page (Security
    Dashboard tabs, alerts and sections; Compliance tabs and content; Asset
    Registry and Vulnerability Browser filter bars).

  Gaps between a page's children are now declared as `--ccure-page-gap`.

- **New Scan** carried four more dead global rules (`.ns-back-btn`,
  `.ns-info-grid`, `.ns-info-card` with its `.nic-*` children, and
  `.ns-pipeline-badge`) and a live one: the legacy `.ns-card` in `scan.css` still
  gave the form card a 14 px radius and `28px 32px` of padding, both outside the
  token scale. All of them were removed. Removing `.ns-card` exposed a second
  problem. The card was declared `bodyFlush`, and the shared rule zeroing a flush
  body outranked the body padding `NewScan.css` already specified. The legacy
  padding had been hiding that. The card is not flush, so the prop was dropped,
  and the card now renders with the shared radius and its own `2xl` body padding
  (`md` at ≤ 480 px). The quota panel and the card are spaced by the page gap.
- `deleted-users.css` and six other stylesheets had header comments describing the
  retired shell classes. Those comments were corrected. `.page-note` had no rule
  at all (not before B.13 either), and the text now sits in the header's
  description slot.

### 3.3 Emoji replaced

Every emoji used as an icon in `src/` was replaced: the 295 lines of §1.3, in 36
files across Audit, the shell and the design system:

- buttons and section titles;
- empty states;
- data maps (OS families, device types, scan modes, audit actions and
  notification types);
- the shell's menu button, brand mark and theme options;
- `CcureAlert`'s four variant icons.

Notification presentations now name an icon (`{ icon, tone }`) instead of an
emoji. The unknown-type icon is `message-square`, so it stays distinct from the
platform's `admin_notice` bell.

## 4. Validation (Phase 4)

All against a production build (`VITE_API_BASE_URL=/api npm run build`, as the
image builds it) with the synthetic fixtures of `browser-tests/catalogue.mjs`.
No backend, API, route, permission or database change was made, so none was
re-validated.

| Gate                              | Result                           |
| --------------------------------- | -------------------------------- |
| Unit (`vitest`)                   | 115 files, 3,128 tests pass      |
| `lint`                            | pass, 0 warnings                 |
| `ux4g:check` (dependencies, dist) | pass                             |
| `ux4g:verify`                     | pass, two builds byte-identical  |
| `ux4g:architecture`               | pass                             |
| Authorization inventory           | current; only line numbers moved |
| Browser, Chromium                 | 198 / 198 pass                   |
| Browser, Firefox                  | 198 / 198 pass                   |
| Browser, WebKit                   | 198 / 198 pass                   |

The browser suite includes the new `page-structure.spec.mjs` (58 states). It also
runs the existing closure spec over every catalogued state at nine widths from
320 to 1920 px in both themes: axe WCAG A/AA at 320 and 1440 px, overflow, CSP,
console errors and unexpected requests. Keyboard, reflow (200 % and 400 %) and
primitive specs run as well.

**Measured consistency**, across 61 shell page states (10 Common, 51 Audit) at
1920 px:

- **Title:** every `<h1>` is 22.5 px, weight 700, 30 px from the edge of `main`.
  Before B.13 the same states had five sizes and four insets.
- **Header top:** 26 px on 45 states. The rest are lower by design:
  - 56 px or 64 px where a breadcrumb or Back link sits above the title (five
    web-scanning pages, New Scan, Asset Detail, Credentialed Scan);
  - 71 px under the scan pipeline stepper (Phase 1/2/3 results).
- **Visual review:** 264 captures (66 states × 1920/390 px × light/dark) were
  reviewed beside the post-B.12 captures. None shows horizontal overflow, a
  console error or an unexpected request.

**Defects found by the validation and fixed:**

- **Subtitle links lost their colour.** Splitting a selector list in `page.css`
  left `.cc-page-header__subtitle a` unstyled. The two cross-links between
  Configuration Checks and the Rule Validator rendered in the browser's default
  blue, at 1.89:1 contrast in dark mode. Axe caught it at 320 px.
- **New Scan's form card** had a 14 px radius and double-source padding; see
  §3.2.
- **Nine buttons** used ↻ ↺ ↩ as icons, which the source ratchet's ranges did not
  cover. A census of rendered button text found them.

**Test changes, all migration-related:**

- **Assertions that matched an emoji now match the text, or the icon by
  `data-icon`:**
  - AssetDetail, ComplianceWorkspace (attestation, gap and pagination, views);
  - CredentialedResults, CredentialedScan, Phase3Results;
  - the shell's notification presentation;
  - AuditLogDetailsModal's ➔ → →.
- **Deleted Users** is asserted as an `<h1>`, and its subtitle by the shared
  class.
- **`reflow.spec.mjs` and the B.5/B.6 harness** track `.cc-page`, where they
  tracked `.page-inner`.

No assertion about behaviour, data, an API call or a permission was changed.

## 5. Limits and decisions to note

- **Title colour.** The title now uses `--ccure-text`. The Common pages' legacy
  `.page-title` used `--text`. The two differ slightly in light mode, and the
  pixel diff of the Common pages shows it. It is the design-system token, so the
  change is intended.
- **Sign-in screens** keep their own shell and their own heading. They are still
  `PENDING` in `modules.config.js` and were out of scope.
- **The UX4G icon font is not used.** Adopting it means reversing B.1's font
  policy. That is a typography decision, not a migration step, and nothing here
  depends on it: `CcureIcon` names are semantic, so a later switch changes
  `icons.js` and nothing else.
- **Page-internal headings** (`<h2>`/`<h3>` card and section titles) were left at
  their existing levels and styles. This work standardised the page header, not
  every heading inside a page.
- **Policy Pro, Rank and IR** have no pages beyond the shared entry page. When
  they ship, the page ratchet applies to them as soon as their pages render a
  shell.

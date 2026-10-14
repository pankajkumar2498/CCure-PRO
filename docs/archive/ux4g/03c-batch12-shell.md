# Checkpoint 3C — Batch 12: the shared shell

AppLayout, NotificationsPanel, HelpPanel and SettingsDrawer onto
`CcureAppShell` and CCure tokens, with the Toast and legacy Modal shims the
brief allowed as supporting scope. Instrument changes are in
`03c-batch12-harness.md`.

## 1. Files changed

| File                                                       | Change                                                                                                                 | LOC HEAD → now                    |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `src/components/layout/AppLayout.jsx`                      | head (imports, icons, `SIDEBAR_SECTIONS`, `hasPermission`, `canSeeNavItem`) verbatim; render tail onto `CcureAppShell` | 1165 → 1019; inline styles 24 → 0 |
| `src/components/layout/NotificationsPanel.jsx`             | rewritten on tokens; `np-*` → `shn-*`; API calls unchanged                                                             | 349 → 393; inline 1 → 0           |
| `src/components/layout/HelpPanel.jsx`                      | rewritten on tokens; `hp-*` → `shh-*`; FAQ / links / what's-new data verbatim                                          | 342 → 392                         |
| `src/components/layout/SettingsDrawer.jsx`                 | rewritten on tokens; `sd-*` → `shs-*`; GET/PUT `/user/preferences` and `onPreferencesUpdated` unchanged                | 259 → 326                         |
| `src/components/layout/Modal.jsx`                          | accessibility shim (dialog semantics, focus trap, named close) — API unchanged                                         | 59 → 82                           |
| `src/components/common/Toast.jsx`                          | accessibility shim (persistent live regions, named dismiss) — API and timing unchanged                                 | 63 → 106                          |
| `src/design-system/patterns/CcureAppShell.jsx`             | additive props (see §3)                                                                                                | 171 → 243                         |
| `src/design-system/patterns/shell.css`                     | appended rail, tag, backdrop, focus rules                                                                              | 348 → 432                         |
| `src/styles/app-shell.css`                                 | **new**: inheritance boundary + `sh-*`, `shn-*`, `shh-*`, `shs-*`, `.toast-dismiss`                                    | 0 → 1063                          |
| `src/styles/layout.css`                                    | census-backed prune of orphaned shell rules (84 rules); page rules kept                                                | 827 → 198                         |
| `src/styles/animations.css`                                | same prune (123 rules); keyframes and page rules kept                                                                  | 2507 → 1684                       |
| `src/__tests__/components/layout/AppLayout.test.jsx`       | **new**, 43 tests                                                                                                      |                                   |
| `src/__tests__/components/layout/ShellPanels.test.jsx`     | **new**, 21 tests                                                                                                      |                                   |
| `src/__tests__/components/common/ToastModalShims.test.jsx` | **new**, 7 tests                                                                                                       |                                   |

Not touched: ProfileModal, ChangePasswordModal, ExportPanel, ScanStepper,
ScanQuotaBar, ScanContext, every application page, OrganizationManagement and
AuditLogDetailsModal sources (they gain the Modal shim's behaviour without an
edit), backend, CSP, nginx.

## 2. What the shell now is

`AppLayout` renders `<CcureAppShell className="sh-shell" mainClassName="page-main" …>` and hands it:

- `sections` — `SIDEBAR_SECTIONS` filtered by `canSeeNavItem` (same function,
  same `superadminOnly` rule), each item carrying `active` from the existing
  query-aware `activeId`, `badge` from the 30 s summary poll, `badgeVariant`
  and a sr-only `badgeLabel` ("2 running", "4 critical").
- `headerLeft` (superadmin only) — the org switcher and the global search
  (`CcureInput type="search"`, `aria-label`, Enter routing and Ctrl/Cmd+K
  focus unchanged).
- `headerActions` — save status (`role="status"`), New Scan (`CcureButton`,
  `onNewScan || navigate("/scan")`), Help, the notification bell, the profile
  menu (`role="menu"` / `menuitem`).
- `sidebarFooter` — two `CcureProgress` bars (quota, concurrent), the `7/50`
  text and the Settings button.
- `collapsed` / `onToggleCollapsed` bound to the existing `sidebarCollapsed`
  localStorage key and preferences mirror; `navRef` / `onNavScroll` bound to
  the existing `sidebarScrollPos` sessionStorage.

Every effect is verbatim: orgs load, 30 s `fetchCounts`, SSE loop with
`refreshSummary` on first failure, `activeOrgId` write + reload on org switch,
theme via `PreferencesContext` / `data-theme` only.

The panels are the same components with the same props and the same requests;
they render on tokens, carry dialog semantics, close on Escape, and return
focus to the control that opened them (`bellRef`, `helpBtnRef`,
`settingsBtnRef`).

## 3. The inheritance boundary (the batch's one design finding)

The first migrated build passed every shell gate and **failed the batch-11
page regression**: `.page-main` typography went Segoe UI 15px → Noto Sans
13.125px and its padding to 22.5px on every page. `.cc-shell` sets the
design-system font on its root and `.cc-main` pads, and both cascaded into
pages that batches 5–11 had measured under the legacy shell.

The fix is `app-shell.css`'s first block: `.cc-shell.sh-shell` inherits the
application's font/size/line-height/colour, the design-system typography is
re-applied to `.sh-shell > .cc-sidebar` and `.sh-shell > .cc-header` only, and
`.sh-shell > .cc-main` has zero padding so `.page-main` keeps its own. This is
the "CCure on top" rule made literal: the chrome is UX4G, the page area is
whatever the page decided. Proven by re-capturing all 125 page states (§6).

## 4. Accessibility, shell chrome (13 states × 2 themes)

| Measure                                                                                   | Pre                  | Post                                                                                                           |
| ----------------------------------------------------------------------------------------- | -------------------- | -------------------------------------------------------------------------------------------------------------- |
| Unnamed buttons                                                                           | 71                   | 0                                                                                                              |
| Unlabelled inputs                                                                         | 15                   | 0                                                                                                              |
| Named landmarks                                                                           | 1                    | 26 (`aside "Primary"`, `nav "Sections"`, `main`, `header`, dialogs by name)                                    |
| Roles in chrome                                                                           | 7                    | 77                                                                                                             |
| ARIA state attributes (`expanded`, `controls`, `current`, `haspopup`, `checked`, `modal`) | 3                    | 134                                                                                                            |
| Live regions                                                                              | 0                    | 14                                                                                                             |
| Inline styles                                                                             | 176                  | 28 (all `CcureProgress` bar widths)                                                                            |
| First Tab stop                                                                            | org switcher `<div>` | "Skip to main content"                                                                                         |
| Contrast failures (all 26 captures)                                                       | 172                  | 12 — all on `shellOnAssets`, all AssetRegistry `dashboard.css` (deferred debt); 0 on shell chrome; 0 new pairs |

Specifics: sidebar `aria-current="page"`; collapse toggle
`aria-expanded`/`aria-controls="cc-sidebar"`; bell named with unread count;
profile `aria-haspopup="menu"`; org switcher is a button (was `<div onClick>`);
Notifications and Help are `role="dialog"` with names; Settings is
`aria-modal` with a focus trap; `OptionGroup` is a `radiogroup`; save state
and settings-saved are `role="status"`; decorative SVGs `aria-hidden`.

## 5. Behaviour and security confirmations

- `SIDEBAR_SECTIONS`, `canSeeNavItem`, `superadminOnly` and `hasPermission`
  are the same code; nav items by persona 25 / 21 / 8 pre and post; test
  suite exercises SUPERADMIN, ORG_ADMIN and VIEWER against the real
  `auth/permissions`.
- Auth, org selection (`activeOrgId` + reload), `sidebarCollapsed`,
  `sidebarScrollPos`, SSE + 30 s polling, quota/summary reads, search
  routing, New Scan callback/navigation, `PreferencesContext` + `data-theme`:
  covered by the 43 AppLayout tests (fake timers for the poll, mocked SSE
  failure path).
- No `prefers-color-scheme`, no UX4G runtime, no CDN/font/external request:
  grep 0; air-gap census 0 off-origin across 26 shell captures.
- CSP header byte-identical (`curl -sD -` on pre and post containers).
- No credential or token in any DOM attribute, label, snapshot or log.
- Requests: 306 GET + 26 POST (`/auth/refresh`) per shell run, identical
  census pre and post; the harness rejects every other non-GET.

## 6. Gates (final image `ccure-frontend:ux4g-b12`)

| Gate               | Result                                                                                                                     |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Vitest             | 1,352 / 1,352, 0 unhandled (71 new)                                                                                        |
| ESLint, whole tree | 0                                                                                                                          |
| Build              | OK; CSS 331.36 → 330.21 kB (54.85 → 53.72 gz); JS 1,654.66 → 1,659.86 kB (419.97 → 421.11 gz)                              |
| Docker             | HTTP 200; CSP identical                                                                                                    |
| Shell harness      | 26/26 captured, deterministic (pairs byte-identical), sensitivity 4/4, personas, no-write, off-origin — see harness doc §4 |
| Page regression    | 125 states, every delta explained (document-wide `.cc-*` counts; Toast live regions); auth pages IDENTICAL                 |
| Prune              | unpruned vs pruned: 0 changed across 64 states                                                                             |
| Excluded surfaces  | unchanged vs HEAD                                                                                                          |

## 7. The STOP raised during the page regression

The first post-migration page run reported computed-style deltas on
`.page-main` across every page. Investigated rather than explained away: it
was the cascade in §3, not the harness. The harness was not modified; the
application was, and the run was repeated from scratch.

## 8. Intentional behaviour changes

1. The header "Info" button — rendered with no handler — is not rendered. An
   inert control with no name is an accessibility failure with nothing to
   preserve.
2. The org switcher is a `<button>`; it was a `<div onClick>`.
3. Panels close on Escape and return focus; the previous panels closed on
   click-outside only.
4. Toasts are announced (live regions) and dismissible from the keyboard.
5. Legacy `Modal` traps focus and restores it on close.

Nothing else: no API, timing, storage key, routing or permission change.

## 9. Deferred (unchanged from the running list, plus)

- `shellOnAssets` contrast: AssetRegistry `dashboard.css` (pre-existing).
- `HelpPanel` support form is still client-side only (no endpoint exists).
- `AuditLogDetailsModal` inline styles (it gained dialog semantics through
  the shim; its own markup is untouched).
- ProfileModal / ChangePasswordModal remain on legacy classes — excluded by
  the brief.
- `ux4g-*` string matches remaining in the tree are negative assertions in
  tests and the pre-existing `DesignSystemShowcase` spike page.

# B.12 — Audit UI restoration after the Common Platform / UX4G migration

Date: 8 October 2026, on `modular_architecture` from `d2a86ab`. Scope: presentation
of the Audit module only. No API call, payload, route, permission decision,
authentication or backend file changed. UX4G stays at `ux4g-web-components@3.0.2`;
no dependency, generated asset, CSP or exception-list entry changed.

## 1. What was reported, and how it was found

Audit pages (Scan Templates, Configuration Checks, Remediation, the Report Cabinet)
looked broken after the Common Platform refactoring. Every automated gate had passed
on those builds: the defects were not overflow, contrast or accessibility failures
but layout, and only a visual comparison shows layout.

Method: the production build of the current tree and of `bad5b3f` (4 Oct, the last
build before the 5 Oct UX4G migration of the shell and Audit) were served with the
browser catalogue's synthetic fixtures (`browser-tests/catalogue.mjs`, plus a
populated Report Cabinet and Remediation queue). 65 states were captured at 1920 px
for each build and compared side by side, then the fixed build at 1024/390 px light
and 1920 px dark. No live backend was contacted.

## 2. Root causes

| #   | Cause                                                                                                                                                                     | Effect                                                                                                                                                        |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | `components.css` is `@layer ccure-legacy`, the generated UX4G component CSS is unlayered, so any official rule outranks the legacy CCure layout regardless of specificity | Tab strips centred with an underline only as wide as the tabs; card actions dropped below the title; `flush` cards framed and unpadded                        |
| 2   | The official underline tab sits 1px below a list that scrolls horizontally (`overflow-x:auto` forces `overflow-y:auto`)                                                   | A stray vertical scrollbar (▲▼) beside every tab strip on Windows                                                                                             |
| 3   | UX4G 3.0.2's desktop alert sets title and message side by side                                                                                                            | A titled alert ran its title into the first bullet of its message                                                                                             |
| 4   | The official `th` rule is for column headers                                                                                                                              | `<th scope="row">` body cells drawn 12 px, grey, unwrapped; a stray border under the first column of the last row                                             |
| 5   | Official input container and select are `width:100%`                                                                                                                      | Every filter in a flex-row toolbar became a full-width line; pagination labels wrapped                                                                        |
| 6   | Native `<button>`s became `CcureButton`, which wraps children in a content-sized `inline-flex` span                                                                       | Tiles and disclosure rows lost their column / row / space-between layout and centred their contents                                                           |
| 7   | Six Audit stylesheets named tokens that do not exist (`--ccure-color-*`, `--ccure-font-size-*`, `--ccure-font-weight-bold`) — pre-existing                                | Remediation rendered with no borders, surfaces or sizes; the same silently in five other sheets                                                               |
| 8   | Every stylesheet ships in one bundle                                                                                                                                      | `.rm-*` was defined by both Audit Remediation and Common Role Management; `.sc-*` by both Scan Comparison and Scan Credentials — each page restyled the other |

## 3. Changes

**Shared adapters** (`design-system/components/adapters.css`, `CcureAlert.jsx`) —
the vendor-class fixes must live here; modules may not name `ux4g-` classes.
Tabs stretch to the strip and keep their indicator without overflow; card headers
are a wrapping row again; `flush` cards are borderless with padded headers; a titled
alert (`cc-alert--titled`) stacks title over message at every width; row-header
cells match body cells; pagination labels do not wrap; `.cc-field` is a block that
takes its container's width (single-class, so a page's sizing class still wins).

**Audit pages:**

- **Rich buttons.** Scan Templates tiles, Configuration Checks rows, Phase 2 host
  rows, Credentialed Results sections, Findings Explorer items, AMT ring and
  categories, audit-timeline headers and the Help FAQ lay out the button's label
  span (the export-panel idiom). Credentialed Scan "Collect" tiles gained their own
  column wrapper inside the checkbox label.
- **Remediation.** Uses the shared `.page-inner` gutter and `.page-title-row`
  header; the summary, queues and SLA policy are framed surfaces; metrics are a grid.
- **Report Cabinet.** The stylesheet styled the native controls the page no longer
  renders; dead rules removed. The page now has a working filter row, a 2×2
  download grid with delete in its own column, and a styled placeholder for the
  sections not yet offered.
- **Tokens.** All undefined references mapped to the real scale. Light-only hex
  fallbacks in web-scanning and compliance replaced with theme tokens. The
  assessment-context block (`.asc-*`) uses readable sizes.
- **Collisions.** Audit Remediation classes are `rmd-*`; Scan Credentials classes
  are `scr-*`. Common Platform files were not touched.
- **Smaller fixes.** The rule validator's JSON editor is monospace again;
  Configuration Checks filters are top-aligned; the vulnerability title truncates
  with an ellipsis.

## 4. Effect on Common Platform pages

No Common Platform file changed. Through the shared adapters, eight Common pages
render differently, each back to its 4 Oct validated state:
row-header cells in the user, deleted-user and organisation tables;
the Email Domain Rules form (inline again, not stacked); "Events per page" on one
line; the stacked titled alert on the Policy Pro / Rank / IR placeholders.
CCure Home is pixel-identical; Roles & Permissions differs by 12 sidebar pixels.

## 5. Validation

From `Frontend/`, on the final tree:

| Check                                                     | Result                                                                           |
| --------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `VITE_API_BASE_URL=/api npm run build`                    | PASS                                                                             |
| `npm run ux4g:check -- --dependencies-only` / `-- --dist` | PASS, 3.0.2, runtime disabled                                                    |
| `npm run ux4g:verify`                                     | two runs byte-identical                                                          |
| `npm run ux4g:architecture`                               | PASS — no vendor class in a module, no new `!important`, no overflow suppression |
| `build-authorization-inventory.mjs --check`               | inventory is current (no permission site moved)                                  |
| `npm run lint`                                            | PASS                                                                             |
| `npm test`                                                | 114 files, 3,117 tests passed                                                    |
| `npm run test:browser`, WebKit                            | 140 passed (userland libraries, host pre-flight skipped)                         |
| `npm run test:browser`, Chromium + Firefox                | 280 passed (140 per engine), none flaky                                          |

The browser gate caught one regression introduced during this work: the
vulnerability title link lost its minimum height (18.8 px, under the 24 px target
size) when its `min-height` was reset. The reset was removed and the page re-tested.

Visual review: 65 states at 1920 px before/after, plus 106 light captures at
1024/390/320 px and 65 dark captures at 1920 px of the fixed build — no page-level
horizontal overflow, console error, undeclared request or unready state. JSX changes
were checked to be presentation-only: after normalising the class renames, the only
differences are the alert modifier class, Remediation's page wrapper and header
classes, the Collect-tile wrapper and the validator textarea's class.

## 6. Limits

- Fixture-driven captures cover the catalogued states, not every data shape;
  real-data review on the deployment is still worthwhile.
- The frontend image must be rebuilt and redeployed to take effect
  (`docker compose build frontend && docker compose up -d --no-deps frontend`).
- Not changed (outside Audit): `shell/admin/pages/AuditLogs.jsx` references an
  undefined `--warning`; legacy global rules in `styles/scan.css` and
  `styles/animations.css` duplicate each other and are unused by Audit pages.

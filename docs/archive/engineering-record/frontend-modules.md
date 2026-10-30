# Engineering record: Frontend modules (Phase 12)

**Frozen.** A verbatim copy of `CLAUDE.md` at `9bb84d9`, lines 907–1033, taken when the instructions were split into global rules, scoped rules and skills. It is evidence, not a current requirement, and it is never edited: the live text is maintained where the index in [`README.md`](README.md) says.

Each block below is delimited by `verbatim` comments naming its original lines. `Backend/tests/repo/test_engineering_record_archive.py` proves that the blocks reassemble into the original file byte for byte.

<!-- verbatim: CLAUDE.md@9bb84d9 lines 907-1033 -->
## Frontend modules (Phase 12)

**Permanent UX4G frontend standard:** follow
[`docs/ux4g/UX4G_STANDARD.md`](docs/ux4g/UX4G_STANDARD.md) for every frontend change.
`Frontend/ux4g-baseline.json` is the sole approved
release/provenance definition. Follow `docs/FRONTEND_ARCHITECTURE.md` §1 and
`docs/ux4g/B1_VERSION_FOUNDATION.md`. Use the latest officially published stable
UX4G release applicable after compatibility/security/CSP validation, with an
exact reviewed pin. Common, authentication and every product share the CCure
Design System; do not add a competing framework without explicit approval or
a custom equivalent without a documented technical reason. B.2's centralized
pipeline is documented in `docs/ux4g/B2_ASSET_PIPELINE.md`. Group 1 adds scoped
official component CSS and reusable React adapters, then migrates the Platform
shell: see `docs/ux4g/B3_B4_SHARED_PRIMITIVES_SHELL.md`. Modules import the CCure
Design System entrypoint, never vendor CSS/classes/behavior. Do not activate
full global CSS/reset or the vendor runtime. Preserve CSP, native form contracts,
API/auth/RBAC behavior, routing and module boundaries. Do not add module-local
vendor assets, font declarations or CDN imports. Run `ux4g:check -- --dist`,
`ux4g:verify`, build, tests and lint; validate changed controls in the browser.
B.5/B.6 migrate Auth and Audit presentation using the same shared adapters;
see `docs/ux4g/B5_B6_AUTH_AUDIT_MIGRATION.md` for mappings, domain exceptions and
browser checks. Preserve the existing API calls and permission decisions when
modifying those screens. B.7–B.10 add final accessibility/responsive closure and
CI/documentation gates: `ux4g:architecture`, authorization inventory and
`test:browser` join foundation, reproducibility, build, lint and unit tests.
Current Policy/Rank/IR entry placeholders use this same foundation; future
product functionality must extend the regression catalogue. Do not expand
exception baselines or suppress accessibility/overflow failures to pass a gate.
Every page inside a shell is `CcurePage` + `CcurePageHeader` (one `<h1>`, the
shared inset and title size), and icons are `CcureIcon`, never emoji. A glyph an
API returns is translated in `modules/audit/utils/backendIcons.js`. Unit
ratchets enforce both (B.13, `docs/ux4g/B13_APPLICATION_PAGE_STANDARD.md`).

One React application holds the four products. Record:
[`docs/architecture/PHASE12_FRONTEND_SHELL.md`](docs/architecture/PHASE12_FRONTEND_SHELL.md);
guide: [`docs/FRONTEND_ARCHITECTURE.md`](docs/FRONTEND_ARCHITECTURE.md) §2;
each folder's `README.md` says what belongs in it.

| Part                 | Folder                                                         | Alias       |
| -------------------- | -------------------------------------------------------------- | ----------- |
| Platform shell       | `Frontend/src/shell/`                                          | `@shell/…`  |
| Design system        | `Frontend/src/design-system/`                                  | —           |
| CCure Audit          | `Frontend/src/modules/audit/`                                  | `@audit/…`  |
| CCure Policy Pro     | `Frontend/src/modules/policy/` (README only)                   | `@policy/…` |
| CCure Rank           | `Frontend/src/modules/rank/` (README only)                     | `@rank/…`   |
| CCure IR integration | `Frontend/src/modules/ir/` (README only)                       | `@ir/…`     |
| Composition root     | `src/main.jsx`, `src/App.jsx`, global stylesheet `src/styles/` | —           |

- **`Frontend/modules.config.js` is the single statement of the layout** and
  the source of the aliases (`vite.config.js` builds them from it).
  `src/__tests__/architecture/moduleBoundaries.test.js` resolves every import
  and fails on: a product importing another product; the shell importing a
  product; the design system importing the application; anything but
  `main.jsx` importing the root; a source file outside a named place; an import
  or `vi.mock` path that does not resolve. ESLint repeats the alias rules.
- **Product metadata has one source, the platform registry**
  (`GET /platform/modules`). The shell names no product — a test fails if it
  does. `/` is CCure Home; `/audit-dashboard` is Audit's dashboard and
  `/dashboard` redirects there; the other three entry addresses are rendered
  from the registry until a product ships a static route at its `entry_path`,
  in the same change as its `tile_state` becomes `available`
  (`Backend/tests/repo/test_platform_entry_routes.py`).
- **The route guard holds the rule, the product names the pages**: a refused
  _Audit_ route falls back to Audit's `modules/audit/config/accessFallbacks.js`,
  never to CCure Home (D12-8). A refused _platform_ route (`/admin/*`) is not
  redirected anywhere: it passes `deniedElement={<AccessDenied />}` and the user is
  told so inside the Platform Shell. Unauthenticated visitors still go to `/login`.
- **Notification presentation is the product's.** The shared panel knows the
  platform's types and categories only; Audit's icons, tones and `Scans` tab are
  `modules/audit/config/notificationPresentation.js`, handed to the shell by the
  composition root (`NotificationPresentationProvider`).
- **`data-theme` changes only inside a React commit.** `applyTheme`
  (`shell/preferences/theme.js`) is called before the first render and then only
  from `PreferencesProvider`'s layout effect, never from a request callback.
  WebKit keeps the old theme on a subtree holding a `<select>` if the theme
  changes between React building it detached and the first style pass: a white
  section with dark-theme text in a dark page (`cr-report`, 2 of 6 WebKit
  nightlies, 15 Oct 2026). A standalone page reproduces it in WebKit only;
  `00594ac` has the measurements and the two fixes that did not work.
- **The AMT page's permission is one constant**, `AMT_PERMISSION`
  (`modules/audit/config/permissions.js`): **`audit.asset.import_amt`**, which the backend
  also requires (`routers/assets.py`), shared by the sidebar item and the route. AMT is
  Audit's page, not a platform one, so `/admin/amt` is Audit-owned despite its address.
  (It was `settings:update` before the native RBAC work; that mismatch is resolved.)
- **Tests that read source import anchors from `src/__tests__/testPaths.js`**;
  never count `..` — the frontend twin of the backend's `testpaths` rule.
- **Shared platform capabilities live in the shell, not in a product** (owner
  decision, 1 Oct 2026; there is no platform-admin product or team, and none
  may be introduced). User, organisation, role, email-domain and audit-log
  administration (`shell/admin/`), the account menu and dialog, notifications,
  organisation switching, the user card and the platform preferences are
  common capabilities; any product team may contribute to them under the same
  boundaries and review. A shared screen renders in `ProductFrame`, which
  resolves to the Platform Shell's `PlatformLayout`; the settings
  drawer takes a product's own sections through `productSettings`. Routes
  (`/admin/*`) and APIs are unchanged. Record:
  `docs/architecture/PLATFORM_SHARED_NAVIGATION.md`.
- **Sign-in lands on the whole platform, not on a product.** CCure Home's
  frame, `PlatformLayout`, carries the shared navigation — Administration
  (in the sidebar, by permission), organisation switcher (superadmin),
  notifications, settings (platform preferences only), account menu, sign out
  — above the Product Hub's four products. Administration items have one list
  (`shell/admin/adminNav.js`) and one rule (`shell/auth/navVisibility.js`),
  read by the platform sidebar. A boundary test
  requires `PlatformLayout`'s whole import closure to be shell or design system.
- **Still open:** the sign-in screens stay in `src/pages/`,
  `src/components/auth/` and `src/styles/` (`PENDING` in `modules.config.js`)
  because they carry Audit's branding; Compliance stays in Audit until the
  Policy Pro work reassesses it.
- **Platform Shell and Product Shells (verified, live 2 Oct 2026).**
  CCure Home, the product entry pages and the shared `/admin/*` screens render
  in `PlatformLayout` — a left sidebar of Home, the registry's products and
  Administration (by permission). Audit's routes sit under an `AuditProduct`
  layout route that mounts Audit's `ScanProvider`; Audit's `AppLayout` carries
  Audit's navigation only.
  - **Platform navigation never appears inside a product, and a product's never
    in the platform's.** Done in the route tree, not CSS. Audit is one product,
    not the parent shell: `ProductFrame` resolves to `PlatformLayout`.
  - **Policy Pro, Rank and IR** stay visible and "Not yet available" until
    built; they have no shell yet and load no Audit state.
  - **Guarded by** `__tests__/shell/navigationIsolation.test.jsx`. Record and
    follow-ups: `docs/architecture/PLATFORM_SHARED_NAVIGATION.md` §8.
- **What the VM runs is recorded in "Deployment: Linux VM" → "Releases"**,
  not here. The record that stood here (backend `15f8c7c` from 7 Oct, frontend
  `87d998b` from 8 Oct, both on the bind-mounted layout) is history; git keeps
  it.

<!-- /verbatim -->

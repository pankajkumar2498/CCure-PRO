# UX4G migration — Phase 0 baseline

**Date:** 9 September 2026
**Branch:** `Close-Coverage_gap`
**Scope:** measurement only. No application code was changed in this phase.

Every figure below was measured against the working tree on the date above. The
brief's estimates are quoted where they differ from what was found.

---

## 1. The headline finding, first

**"UX4G 3.0" does not exist as a code artefact.** It is the version number of
the UX4G _Figma_ design kit, not of any distributable CSS or JavaScript.

Verbatim, from `ux4g.gov.in`:

> …search for 'UX4G Design System,' and select the latest version (currently 3.0).

Three different things carry a UX4G version number, and they are not in step:

| Artefact                    | Version   | Distribution                                            |
| --------------------------- | --------- | ------------------------------------------------------- |
| Figma design kit            | **3.0**   | Figma Community file — design source of truth, not code |
| CSS + token bundle          | **2.1.0** | npm `ux4g-web-components`                               |
| `UX4G.js` behaviour runtime | **1.1.0** | embedded inside the npm package                         |
| Accessibility widget        | **3.31**  | `cdn.ux4g.gov.in` only — no npm package                 |

So the objective "adopt UX4G 3.0 as the foundation" resolves to: **implement the
3.0 design language, using the 2.1.0 CSS package as the mechanism.** There is no
`ux4g@3.0.0` to install. This should be confirmed with whoever set the target
before Phase 1 concludes — if they meant "the Figma kit our designers use", the
plan below satisfies it; if they were promised a 3.0 npm release, that promise
cannot currently be met.

Package name checks that returned 404: `ux4g`, `@ux4g/ux4g`, `ux4g-design-system`,
`ux4g-bootstrap`, `@govtech/ux4g`, `ux4g-css`. The registry is reachable — these
are genuine absences, not network failures.

---

## 2. Measured baseline

### Toolchain

|                     | Found                                  | Brief said |
| ------------------- | -------------------------------------- | ---------- |
| React               | 18.3.1                                 | ~18 ✓      |
| Vite                | 8.2.2 (`engines: ^20.19 \|\| >=22.12`) | 8 ✓        |
| React Router        | 6.23.1                                 | 6 ✓        |
| Node (local)        | 24.18.0                                | —          |
| Node (Docker build) | `node:20-slim`                         | —          |
| Language            | JavaScript + JSX, no TypeScript        | ✓          |
| Test runner         | Vitest 4.1.11 + Testing Library        | —          |
| Lint                | ESLint 8.57, `--max-warnings=0`        | —          |

`node:20-slim` currently satisfies Vite 8's floor only because the tag floats to
20.19+. A pin to `node:20.19-slim` or `node:22-slim` would make that explicit
rather than incidental. Not urgent, but it is a build that breaks on a base-image
refresh, not on a code change.

### Size

|                       | Found                          | Brief said      |
| --------------------- | ------------------------------ | --------------- |
| JSX files             | 79                             | ~79 ✓           |
| JSX lines             | 51,203                         | ~51k ✓          |
| CSS files             | 16                             | —               |
| CSS lines             | 14,547                         | ~14.5k ✓        |
| JS files (non-JSX)    | 25, 2,331 lines                | —               |
| Inline `style={{`     | **2,282**                      | —               |
| CSS custom properties | 44 defined, 2,155 `var()` uses | ✓ custom tokens |

The brief's numbers were accurate.

### Build, test, lint — all green

```
dist/index.html          1.36 kB │ gzip   0.77 kB
dist/assets/index.css  188.90 kB │ gzip  32.56 kB
dist/assets/index.js 1,698.95 kB │ gzip 419.68 kB
built in 4.21s, 178 modules

Test Files  6 passed (6)
     Tests  39 passed (39)
ESLint      exit 0 (zero warnings)
```

Build output hashes match the committed `dist/` exactly, so the checked-in build
is current. **These are the Phase 15 "before" numbers.**

Two pre-existing observations, neither caused by this work and neither in scope
to fix here:

- **There is no code splitting.** One 1.70 MB JS chunk. `vis-network` is pulled
  into it and therefore downloaded by every user on every page, though exactly
  one route uses it.
- All 16 stylesheets bundle into one 189 kB CSS file regardless of which
  component imports them, so the per-page `import "…css"` convention currently
  buys nothing at runtime.

---

## 3. Architecture as it stands

### Entry and providers

`main.jsx` → `BrowserRouter` → `AuthProvider` → `PreferencesProvider` →
`RootErrorBoundary` → `App`. `App.jsx` holds all routes inside `ScanProvider`.

### Routes — 48 total

Public: `/login`, `/register`, `/verify-email`, `/forgot-password`,
`/reset-password`.
Everything else sits behind `<PrivateRoute>`, with seven RBAC-gated admin
sub-trees (`audit:read`, `assets:update`, `users:read`, `organizations:read`,
`roles:read`, plus `superadminOnly` for `/admin/email-domains`).

RBAC is enforced in `components/auth/PrivateRoute.jsx` against
`auth/permissions.js` (`canAny`, `canPermission`, `isSuperAdmin`). **No phase may
alter this**; the superadmin-only email-domain route in particular mirrors a
backend `require_role` and is documented in CLAUDE.md as deliberate.

### Application shell — `components/layout/AppLayout.jsx`, 1,165 lines

Already uses real landmarks: `<aside>`, `<nav>`, `<header>`, `<main>`. No
`<footer>`.

Contains the sidebar definition (`SIDEBAR_SECTIONS`, permission-filtered per
item), ~30 hand-rolled inline SVG icon components, the notification bell with an
SSE stream, org switcher, scan-quota bar, and mounts `ProfileModal`,
`SettingsDrawer`, `NotificationsPanel`, `HelpPanel`.

This file is the highest-value and highest-risk single target in the migration.

### Theming — server-persisted, not local

`PreferencesContext` fetches `GET /user/preferences` and applies
`document.documentElement.setAttribute("data-theme", "dark")`. Theme is a
**backend contract** (`preferences.theme`), not a `localStorage` toggle.
Phase 10 must not change that field or its semantics.

### Shared primitives that already exist

| Component                                                                                   | Lines | Notes                                                                   |
| ------------------------------------------------------------------------------------------- | ----- | ----------------------------------------------------------------------- |
| `common/Button.jsx`                                                                         | 43    | 5 variants, sizes, `loading`, `forwardRef` — the most mature primitive  |
| `common/ConfirmDialog.jsx`                                                                  | 103   | `role="dialog"`, `aria-modal`, Escape, focuses confirm                  |
| `layout/Modal.jsx`                                                                          | 59    | **no `role="dialog"`, no focus trap, no `aria-modal`**                  |
| `common/FormField.jsx`                                                                      | 19    | label + hint; hint is **not** wired via `aria-describedby`              |
| `common/Toast.jsx`                                                                          | 63    | `useToasts` hook + container; **no `aria-live`**, dismiss on click only |
| `common/EmptyState.jsx`                                                                     | 17    | emoji icon                                                              |
| `common/Loader.jsx`                                                                         | 8     |                                                                         |
| `common/Skeleton.jsx`                                                                       | 40    | injects a `<style>` tag per instance                                    |
| `common/RoleSelector.jsx`, `CVELink.jsx`, `PanelErrorBoundary.jsx`, `RootErrorBoundary.jsx` |       |                                                                         |

That is the whole set. There is **no** shared Input, Select, Card, Badge, Alert,
Table, Tabs, Breadcrumb, Pagination, Tooltip or Progress — each page hand-rolls
them, which is why 310 `<button>`, 153 `<input>`, 74 `<select>` and 46 `<table>`
elements are spread across the pages rather than concentrated in primitives.

**This is the strongest argument for the design-system layer**: the wrapper layer
is not replacing a mature primitive set, it is supplying one that was never
written.

### Design tokens — three families, one of them theme-broken

44 custom properties in three groups:

- **Core** (`theme.css`) — `--accent`, `--bg-*`, `--text*`, `--border`,
  `--ok/--warn/--danger/--info`, `--font`, `--sidebar-w`, `--header-h`.
  Carries a documented WCAG contrast ladder in comments and **does** have a
  `:root[data-theme="dark"]` override block.
- **Dashboard** (`dashboard.css`) — `--db-bg`, `--db-surface{,2,3}`,
  `--db-border{,2}`, `--db-accent/teal/purple/cyan`.
- **Severity** (`dashboard.css`) — `--sev-{critical,high,medium,low,info}` and
  their `-bg` variants.

**Finding:** the `--db-*` and `--sev-*` families are declared in a single
`:root` block with **no dark-mode override at all**, and `--db-bg: #0d1117` is a
_dark_ colour hardcoded into the light theme's `:root`. Severity colour is
therefore identical in both themes, so severity badge contrast is unverified in
one of the two. This is a genuine pre-existing accessibility defect and is
exactly what the Phase 3 semantic-token layer should absorb.

### CSS architecture

`global.css` `@import`s 8 sheets (theme, layout, admin, forms, scan, responsive,
animations, dark-mode). The other 8 are imported directly by the components that
use them (`dashboard.css` by five separate pages, plus compliance, NetworkMap,
NewScan, SecurityReports, audit-timeline, web-scanning).

**No orphaned stylesheets** — every one of the 16 has a live consumer. Nothing is
safe to delete today, which is consistent with the brief's rule.

Largest: `scan.css` (3,686), `NewScan.css` (3,052), `animations.css` (2,507),
`dashboard.css` (1,152).

### Visualizations

- **`vis-network` 9.1.13** — canvas-based topology, used by exactly one page,
  `pages/scan/NetworkMap.jsx` (1,905 lines) with `styles/NetworkMap.css` (827).
- **Everything else is hand-rolled inline SVG** — 63 `<svg>` occurrences. There
  is **no charting library at all** (no d3, Recharts, Chart.js, ECharts; the 32
  "d3" grep hits were hex colours). Dashboard charts are bespoke SVG/CSS.
- No `<canvas>` outside vis-network; no `getContext` in application code.

Per Phase 9 this stays as-is. The realistic goal is to make these read CCure
semantic tokens instead of literal hex values.

---

## 4. Security, deployment and air-gap posture

### CSP, as served today

Set twice in `Frontend/nginx.conf` — at server level and repeated inside
`location = /index.html`, with a long comment explaining that nginx's
`add_header` does not merge and that omitting the repeat once silently disabled
CSP on the only response it protects.

```
default-src 'self';
script-src  'self';                    ← no unsafe-inline, no unsafe-eval
style-src   'self' 'unsafe-inline';
connect-src 'self' ws: wss:;
img-src     'self' data:;
font-src    'self';                    ← no data:
object-src  'none';
base-uri    'self';
frame-ancestors 'none';
```

Plus `X-Content-Type-Options`, `X-Frame-Options: DENY`, HSTS, `Referrer-Policy`,
`Permissions-Policy`.

### Air-gap posture is currently clean

**One** external URL exists in the entire frontend source: an NVD `<a href>` in
`CVELink.jsx`. It is a user-initiated hyperlink, not a resource load — it fails
harmlessly offline and loads nothing at runtime.

Google Fonts were already removed, with a comment in `index.html` recording that
they had been dead for some time (blocked by CSP) while still costing every
visitor a DNS lookup and an IP disclosure to a third party. `public/` contains
only `favicon.svg`.

**The frontend currently makes zero third-party requests.** That is the property
the migration must not lose.

### Deployment

`Dockerfile`: `node:20-slim` build → `nginx:stable-alpine`, `dist/` to
`/usr/share/nginx/html`, `nginx.conf` to `conf.d/default.conf`.
`docker-compose.yml`: `ccure-frontend`, published `127.0.0.1:3200:80`, assets
baked at build time — so JSX changes need
`docker compose build frontend && docker compose up -d --no-deps frontend`.

---

## 5. Accessibility baseline

Measured across all JSX and CSS:

|                          | Count              |
| ------------------------ | ------------------ |
| `aria-label`             | 33                 |
| `aria-labelledby`        | 4                  |
| `aria-modal`             | 4                  |
| `role=`                  | 36                 |
| `htmlFor`                | 46                 |
| `tabIndex`               | 6                  |
| `aria-live`              | 3                  |
| `aria-expanded`          | 1                  |
| **`aria-describedby`**   | **0**              |
| **`aria-current`**       | **0**              |
| **skip link**            | **0**              |
| **`<caption>`**          | **0**              |
| **`scope="col"`**        | **0**              |
| `:focus-visible`         | 3 (vs 26 `:focus`) |
| `prefers-reduced-motion` | 3                  |

Against a surface of 46 tables (330 `<th>`), 19 forms, 153 inputs, 74 selects,
310 buttons and 11 modal/drawer overlays.

The five zeroes are the substantive gaps, and each is a GIGW/WCAG item:

1. **No skip link** — keyboard users traverse the entire sidebar on every route.
2. **No `aria-describedby`** — validation errors and `FormField` hints are
   visually adjacent to their input but not programmatically associated, so a
   screen reader announces the field without its error.
3. **No `aria-current`** — the active nav item is styled but not announced.
4. **No table semantics** — 330 header cells, none with `scope`; no `<caption>`.
   Data tables are the primary output of this product.
5. **`:focus` far outweighs `:focus-visible`**, and `layout/Modal.jsx` has no
   focus trap, no `role="dialog"` and no `aria-modal` — `ConfirmDialog` has them,
   `Modal` does not, and `Modal` is the one used by the larger surfaces.

None of this is fixed by adopting UX4G. It is fixed in the CCure primitive layer,
which is the argument for Phase 5 existing at all.

---

## 6. UX4G 2.1.0 compatibility assessment

Downloaded to the session scratchpad and inspected. **Nothing was added to the
project**: `package.json`, `package-lock.json` and `node_modules/` are untouched.

### What the package contains

18 files, 4.4 MB packed:

- `styles/ux4g.css` — **8,315,261 bytes (8.3 MB)**
- `dist/runtime/{index,bootstrap,design-system}.{mjs,cjs,js}` — ~310 kB each
- TypeScript declarations
- **No font files, no images, no licence file**

`peerDependencies`: none. `dependencies`: none. Self-contained.

### The 8.3 MB is 91% inlined fonts

```
total CSS          8,315,261 bytes
base64 payload     7,556,720 bytes  (90.9%)
actual CSS rules     758,541 bytes  (9.1%)
```

Every font is embedded as a `data:font/ttf;base64` URI: Noto Sans, Noto Sans
Display, and five Material Icons variants (Outlined, Round, Sharp, TwoTone,
base).

This cuts both ways and both halves matter:

- ✅ **Zero external font requests.** No Google Fonts, no CDN. Air-gap safe by
  construction — which is the single hardest requirement UX4G had to meet, and
  it meets it.
- ❌ **Blocked by our CSP today.** `font-src 'self'` does not permit `data:`.
  Imported as shipped, every UX4G font silently fails to load and the icon fonts
  render as tofu.
- ❌ **Unacceptable as a bundle.** 8.3 MB raw / 4.0 MB gzipped against a current
  total CSS of 189 kB / 33 kB gzipped. Base64 of already-compressed font data
  barely compresses.

**Recommended resolution (Phase 2), which fixes all three at once:** extract the
seven fonts at build time, convert TTF → woff2, self-host under `/assets`,
rewrite the `@font-face` `src` to a relative path. That drops the CSS to ~759 kB
before minification, keeps `font-src 'self'` **unchanged**, and keeps everything
served from our own origin. Subsetting the icon fonts to glyphs actually used
would cut it further. No CSP relaxation is required, which satisfies the brief's
"never weaken CSP merely to make UX4G work" without compromise.

### The runtime is a hard CSP blocker — and we do not need it

`dist/runtime/index.mjs` does this:

```js
const script1 = document.createElement("script");
script1.setAttribute("data-ux4g-runtime", "main");
script1.textContent =
  "/*! UX4G.js … Version: 1.1.0 */ (function (global) { … })";
```

It injects the entire ~300 kB `UX4G.js` library as an **inline `<script>` with
`textContent`**. Under `script-src 'self'` the browser refuses to execute it —
no nonce, no hash, no error the application can catch. Making it run would
require `script-src 'unsafe-inline'`, i.e. dismantling the strongest directive in
the policy for a security-audit product. **That is not a trade worth making, and
the brief already forbids it.**

It is also unnecessary. What the runtime provides is Dropdown, Collapse/Accordion,
Offcanvas, Tooltip, Popover, Toast, Carousel, Tabs and Scrollspy — imperative,
jQuery-era DOM manipulation that CCure already implements in React and that would
fight React's reconciler for ownership of the DOM.

Scanned for other hazards, all clean:

|                                          | Count                               |
| ---------------------------------------- | ----------------------------------- |
| `eval(` / `new Function`                 | **0** — no `unsafe-eval` needed     |
| `fetch` / `XMLHttpRequest`               | **0**                               |
| external hostnames                       | **0** — no telemetry, no phone-home |
| `customElements.define` / `attachShadow` | **0**                               |

Note the last row: despite being named `ux4g-web-components`, it defines **no
web components and uses no shadow DOM**. It is a CSS class library. That is good
news — no custom elements for React to mis-handle, and no shadow boundary to
block our token cascade.

**Conclusion: adopt `ux4g-web-components/styles.css`, do not adopt
`ux4g-web-components/runtime`.** The package's `exports` map lists them
separately, so importing one does not pull the other.

### Class collisions — 3, all harmless

Exhaustive comparison of every class token in both stylesheets:

- UX4G: 5,326 class tokens, of which 73 are not `ux4g-` prefixed
- CCure: 1,314 class tokens
- **Intersection: `active`, `muted`, `is-muted`**

Every UX4G rule touching those is compound-scoped to a `ux4g-` class —
`.ux4g-filter-chip-md.active`, `.ux4g-breadcrumb-item.active`,
`.ux4g-list-item-row.active`. There is **no bare `.active {}` or `.muted {}`
rule**; verified directly. A CCure element cannot pick up UX4G styling unless it
also carries a `ux4g-*` class.

CCure uses `active` in 148 JSX places and `muted` in 388, so a bare rule would
have been a serious problem. There isn't one.

**Importing the UX4G stylesheet globally will not restyle any existing CCure
component.** This is the finding that makes an incremental, page-by-page
migration viable instead of a big-bang rewrite.

### Dark mode — near-perfect alignment, unplanned

UX4G's dark theme is:

```css
:root[data-theme="dark"] {
  /* 217 --ux4g-* tokens redefined */
}
```

CCure's is:

```css
:root[data-theme="dark"] {
  /* core tokens redefined */
}
```

**The same selector and the same strategy** — redefine tokens at the root, don't
restyle components. `PreferencesContext` already sets exactly this attribute.
The two systems compose natively with no adapter, no toggle bridge, and no
change to the preferences contract.

Phase 10's answer is therefore settled by measurement rather than assumption:
UX4G provides suitable dark-mode support, it uses our existing mechanism, and
dark mode does not need to be removed or renegotiated. The remaining work is the
CCure side — giving `--db-*` and `--sev-*` the dark overrides they never had.

### Token namespacing

1,452 distinct `--ux4g-*` custom properties versus CCure's 44 unprefixed ones.
**Zero overlap.** The Phase 3 semantic layer can map cleanly:

```
--ux4g-*  (1,452 primitives/semantics)
   ↓
--ccure-* (semantic layer, new)
   ↓
--accent, --text, --bg-* … (existing names kept as aliases)
   ↓
2,155 existing var() call sites keep working unchanged
```

Keeping the legacy names as aliases onto the new semantic layer is what lets the
existing 2,155 `var()` uses migrate by re-pointing definitions rather than by
editing 79 files.

### Licence — unresolved, and it should block Phase 2 sign-off

`ux4g-web-components` ships **no LICENSE file and no `license` field** in its
`package.json`. The publisher account is `ux4g.npm`, consistent with an official
NeGD/MeitY release, but consistency is not a licence grant. Vendoring 8 MB of
government design assets and the embedded Noto/Material Icons fonts into a
product image needs a licence positively identified, not assumed.

Noto Sans and Material Icons are individually OFL/Apache-2.0 upstream, which is
permissive — but that is the _upstream_ position, not a statement about this
bundle. This is a question for whoever owns the UX4G relationship, and it is
cheap to ask now and expensive to discover later.

### The accessibility widget is out of reach as shipped

UX4G's own site loads three external scripts:

```
https://cdn.ux4g.gov.in/accessibility-v3.31/accessibility-widget.js
https://cdn.ux4g.gov.in/analytics/ux4g-analytics.js
https://scripts.clarity.ms/0.8.69/clarity.js      ← Microsoft Clarity
```

All three are incompatible with CCure on three independent grounds: `script-src
'self'` blocks them, air-gapped and OT deployments cannot resolve the hosts, and
the third is third-party session analytics — in a security-auditing tool used on
OT networks, that is an outbound data path that should not exist.

The accessibility widget is the genuinely valuable GIGW artefact here (text
resize, contrast, reading guides). It has no npm package. **Recommendation:
reimplement its behaviours natively against CCure semantic tokens rather than
vendoring the CDN script**, and treat matching its capability list — not its
code — as the requirement. Under no circumstances add the analytics or Clarity
scripts.

---

## 7. Page inventory and migration complexity

Ranked by measured size. This is the evidence for the brief's Group A–E ordering.

**Group A — simple** (≤ ~630 lines)
`ForgotPassword` 118 · `RoleManagement` 189 · `VerifyEmail` 196 ·
`ResetPassword` 309 · `ArchivedScans` 323 · `DeletedUsers` 394 · `Login` 436 ·
`OrganizationManagement` 425 · `RecycleBin` 465 · `Dashboard` 537 ·
`SecurityReports` 622 · `EmailDomainRules` 627

**Group B — medium** (≤ ~830)
`ConfigurationChecks` 322 · `ScanCredentials` 550 · `CredentialedScan` 604 ·
`ScanSchedules` 776 · `Register` 885 · web-scanning module pages
(`AssetInventory` 335, `ScanList` 308, `WebDashboard` 354, `FindingsExplorer` 467,
`NewWebScan` 564, `ScanDetail` 720)

**Group C — complex** (~1,000–1,700)
`UserManagement` 1,029 · `AuditLogs` 1,234 · `AMTIntegration` 1,316 ·
`VulnerabilityBrowser` 1,507 · `Phase2Results` 1,504 · `Phase1Results` 1,594 ·
`ScanHistory` 1,718

**Group D — very complex** (2,000+)
`AssetRegistry` 2,018 · `SecurityDashboard` 2,192 · `CredentialedResults` 2,368 ·
`AssetDetail` 2,417 · `Phase3Results` 2,531 · `NewScan` 2,905 ·
**`ComplianceWorkspace` 6,093** ← largest file in the frontend, 308 inline styles

**Group E — visualizations**
`NetworkMap` 1,905 + `NetworkMap.css` 827 (vis-network) ·
`AuditTimeline` 400 + `audit-timeline.css` 431 · `ScanStepper` 142 ·
the hand-rolled SVG charts inside `SecurityDashboard`

**Shell (migrate before any page):** `AppLayout` 1,165 · `ProfileModal` 968 ·
`NotificationsPanel` 349 · `HelpPanel` 342 · `SettingsDrawer` 259 ·
`ChangePasswordModal` 228 · `ExportPanel` 625

Inline-style concentration tracks size closely — `ComplianceWorkspace` 308,
`AssetDetail` 183, `Phase3Results` 150, `CredentialedResults` 147,
`AssetRegistry` 130, `SecurityDashboard` 128 — which is where Phase 11 will
spend its effort.

---

## 8. Risk register

| #   | Risk                                                     | Severity               | Evidence                           | Mitigation                                                                |
| --- | -------------------------------------------------------- | ---------------------- | ---------------------------------- | ------------------------------------------------------------------------- |
| R1  | "UX4G 3.0" is unobtainable as code                       | **High**               | No npm 3.0; 3.0 is the Figma kit   | Confirm intent with the requester; target 3.0 _design_, 2.1.0 _mechanism_ |
| R2  | UX4G runtime needs `script-src 'unsafe-inline'`          | **High**               | `script1.textContent = …`          | Do not adopt the runtime. CSS only. React keeps behaviour                 |
| R3  | 8.3 MB CSS / 4 MB gzipped                                | **High**               | Measured                           | Extract fonts → woff2, self-host; subset icons                            |
| R4  | `font-src 'self'` blocks inlined `data:` fonts           | **Medium**             | CSP vs `data:font/ttf`             | Same fix as R3 — no CSP change needed                                     |
| R5  | Licence not stated in the package                        | **Medium**             | No LICENSE, no `license` field     | Resolve before vendoring — gate on Phase 2                                |
| R6  | Accessibility widget is CDN-only                         | **Medium**             | `cdn.ux4g.gov.in`                  | Reimplement natively against CCure tokens                                 |
| R7  | `--sev-*` / `--db-*` have no dark variants               | **Medium**             | Single `:root`, `--db-bg: #0d1117` | Absorb into the Phase 3 semantic layer                                    |
| R8  | `layout/Modal.jsx` lacks dialog semantics and focus trap | **Medium**             | 0 `role="dialog"` in that file     | Fix in the Phase 5 primitive, once, for all 11 overlays                   |
| R9  | 2,282 inline styles resist tokenisation                  | **Medium**             | Measured                           | Phase 11 classification; dynamic/viz values legitimately stay             |
| R10 | `ComplianceWorkspace` at 6,093 lines                     | **Medium**             | Measured                           | Migrate last; consider splitting first                                    |
| R11 | Class collisions (`active`, `muted`, `is-muted`)         | **Low**                | All compound-scoped; no bare rules | Verify again on any UX4G version bump                                     |
| R12 | `node:20-slim` floats above Vite's floor                 | **Low**                | `engines: ^20.19`                  | Pin the base image                                                        |
| R13 | No code splitting; vis-network ships to every route      | **Low** (pre-existing) | 1.70 MB single chunk               | Out of scope; note for Phase 15                                           |

---

## 9. Recommended architecture

The measurements support the brief's stated principle — _UX4G underneath, CCure
on top_ — more strongly than expected, because the CSS and the runtime are
cleanly separable and only the CSS is compatible.

```
ux4g-web-components/styles.css   ← CSS + 1,452 tokens + [data-theme=dark]
        (fonts extracted to self-hosted woff2; runtime NOT used)
   ↓
--ccure-* semantic tokens         ← new; legacy 44 names kept as aliases
   ↓
CCure primitives (Cc* components) ← supplies the ~15 primitives that never existed
   ↓
CCure security patterns           ← SeverityBadge, RiskScoreCard, ScanStatus, …
   ↓
Application pages                 ← migrated group by group
```

Two consequences worth stating plainly:

- **React keeps ownership of all behaviour.** Dropdowns, modals, tabs, toasts and
  tooltips stay React. UX4G contributes visual language and tokens. This is
  forced by CSP, but it is also the correct architecture regardless.
- **The primitive layer is additive, not a replacement.** With only Button,
  Modal, ConfirmDialog, FormField, Toast, EmptyState, Loader and Skeleton in
  existence today, Phase 5 is mostly filling a gap rather than migrating away
  from something that works.

---

## 10. What Phase 1 must prove

Phase 1 is a spike on a dedicated branch, limited to Login, Header, Sidebar,
Footer, Button, Input, Modal, Alert, Toast. It should return a yes/no on each:

1. `ux4g-web-components/styles.css` imports and builds under Vite 8 — and the
   resulting bundle size after font extraction.
2. The font extraction pipeline works and `font-src 'self'` is **unchanged**.
3. No UX4G rule visually alters an unmigrated CCure page (predicted safe;
   verify empirically, especially `active` / `muted`).
4. `[data-theme=dark]` drives both token sets from the one existing attribute.
5. The production Docker image builds and serves with the **current CSP verbatim**
   — confirm with `curl -sD - -o /dev/null http://127.0.0.1:3200/ | grep -i content-security`,
   the check CLAUDE.md prescribes.
6. **Zero external network requests** from a loaded page — the air-gap proof, and
   the spike's most important single result.
7. Nine components render correctly in light and dark, keyboard-navigable, with
   the accessibility gaps in §5 closed _in the primitives_.
8. Bundle delta recorded against the §2 baseline.

If 2, 5 or 6 fail, stop and document the blocker per the brief.

---

## Phase report

**PHASE:** 0 — Baseline audit
**STATUS:** Complete
**FILES CHANGED:** one added — `docs/ux4g/00-baseline.md`. No application code,
no `package.json`, no `package-lock.json`, no `node_modules/` change.
**FUNCTIONALITY VERIFIED:** none altered; nothing was modified
**TESTS:** 39 passed / 6 files (baseline, unchanged)
**BUILD:** green — 189 kB CSS, 1,699 kB JS, 4.21 s; output hashes match committed `dist/`
**LINT:** ESLint clean at `--max-warnings=0`
**CSP:** unchanged and documented. Two UX4G incompatibilities identified ahead of
contact: the runtime's inline-`<script>` injection (reject the runtime) and
`data:` fonts against `font-src 'self'` (extract to self-hosted woff2). **No CSP
change is proposed.**
**ACCESSIBILITY:** baseline measured — five categorical gaps (skip link,
`aria-describedby`, `aria-current`, table semantics, modal focus trap), all
addressable in the primitive layer
**RISKS:** 13 recorded in §8; R1, R2, R3 are High and all three have a resolution
that costs no security posture
**NEXT PHASE:** 1 — UX4G compatibility spike, on a dedicated branch, per §10.
**Awaiting your review before starting.**

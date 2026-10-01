# `src/modules/audit/` — CCure Audit (frontend)

The working product: every Audit screen, component, API client, context, hook,
utility and stylesheet, moved here in Phase 12.4 with no behaviour change.
Import it from outside as `@audit/…`; inside, use relative paths.

| Folder             | What lives there                                                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api/`             | Audit's API clients, one per backend area (`scans`, `assets`, `reports`, `remediation`, `scanPolicies`, …). They use the shell's HTTP client, `@shell/api/axiosInstance`. |
| `components/`      | `layout/` (Audit's `AppLayout` — sidebar, header, notifications, profile, settings), `scan/`, `assets/`, `compliance/`, `remediation/`, `admin/`, `common/`               |
| `config/`          | `scanConfig.js` (pipeline ↔ phase mapping), `accessFallbacks.js` (where a refused Audit route sends the user)                                                            |
| `context/`         | `ScanContext` (pipeline state), `PreferencesContext` (theme and layout preferences)                                                                                       |
| `hooks/`, `utils/` | Audit-only helpers. A helper every product needs belongs in `src/shell/`.                                                                                                 |
| `pages/`           | Every Audit page; `scan/` for the pipeline, `admin/` for administration                                                                                                   |
| `styles/`          | One stylesheet per page or component, tokens only                                                                                                                         |
| `web-scanning/`    | The web-application scanning feature (`/web-scans/*`), with its own router, API client and styles                                                                         |

Tests mirror this layout under `src/__tests__/modules/audit/`. A test that reads
a source file imports its location from `src/__tests__/testPaths.js`; it never
counts `..`.

**Rules.** Audit may import itself, the shell (`@shell/…`), the design system
and the global stylesheet in `src/styles/`. It must never import another
product (`@policy/…`, `@rank/…`, `@ir/…`) or the composition root (`main.jsx`,
`App.jsx`). New Audit code goes here, never back into the old `src/pages/`,
`src/components/`, `src/api/` locations: the boundary test fails on any source
file outside a place `Frontend/modules.config.js` names.

**Two things that live here today and may not stay.** The administration
screens for users, organisations and roles (`pages/admin/`) are platform
identity functions by nature, but they render inside Audit's layout, so they
are Audit's until a separate decision extracts a platform administration area.
`DesignSystemShowcase` (development builds only) is here because it reads
Audit's preferences.

Routes: `/audit-dashboard` is the canonical dashboard address and `/dashboard`
redirects to it; every other Audit address is unchanged (`src/App.jsx`).

# `src/modules/audit/` — CCure Audit (frontend)

The working product: every Audit screen, component, API client, context, hook,
utility and stylesheet, moved here in Phase 12.4 with no behaviour change.
Import it from outside as `@audit/…`; inside, use relative paths.

| Folder             | What lives there                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `api/`             | Audit's API clients, one per backend area (`scans`, `assets`, `reports`, `remediation`, `scanPolicies`, …), on the shell's HTTP client `@shell/api/axiosInstance`. Platform APIs (users, organisations, notifications, preferences) are the shell's.                                                                                                                                                                                                                                                     |
| `components/`      | `layout/` (Audit's `AppLayout`: its sidebar, its header actions, the help panel and its "Scan Defaults" settings section, composing the shell's account menu, notifications, organisation switcher and user card; it imports no scan state), `scan/` (the scan screens' own, `ScanStepper` among them), `credentialed/` (the credentialed results' sections), `assets/`, `compliance/` (with `workspace/`, the compliance workspace's tabs), `remediation/`, `common/` (what more than one feature uses) |
| `config/`          | `scanConfig.js` (pipeline ↔ phase mapping), `accessFallbacks.js` (where a refused Audit route sends the user)                                                                                                                                                                                                                                                                                                                                                                                           |
| `context/`         | `ScanContext` (pipeline state)                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| `hooks/`, `utils/` | Audit-only helpers. A helper every product needs belongs in `src/shell/`.                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `pages/`           | Every Audit page; `scan/` for the pipeline, `admin/` for AMT Integration                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| `styles/`          | One stylesheet per page or component, tokens only                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| `web-scanning/`    | The web-application scanning feature (`/web-scans/*`), with its own router, API client and styles                                                                                                                                                                                                                                                                                                                                                                                                        |

Tests mirror this layout under `src/__tests__/modules/audit/`. A test that reads
a source file imports its location from `src/__tests__/testPaths.js`; it never
counts `..`.

**Rules.** Audit may import itself, the shell (`@shell/…`), the design system
and the global stylesheet in `src/styles/`. It must never import another
product (`@policy/…`, `@rank/…`, `@ir/…`) or the composition root (`main.jsx`,
`App.jsx`). New Audit code goes here, never back into the old `src/pages/`,
`src/components/`, `src/api/` locations: the boundary test fails on any source
file outside a place `Frontend/modules.config.js` names.

**Shared platform capabilities are not Audit's.** User, organisation, role,
email-domain and audit-log administration, the account menu, notifications,
organisation switching and the platform preferences live in `src/shell/`.
Audit's layout composes them and supplies itself as the frame the shared
administration screens render in (`App.jsx`, `ProductFrameProvider`); it does
not own them. `DesignSystemShowcase` (development builds only, mounted by
`App.jsx` at `/design-system`) imports nothing but the design system; it sits
here only because no home for platform development tooling has been chosen. **Compliance stays here**
until the Policy Pro work reassesses which of it belongs to Policy Pro.

Routes: `/audit-dashboard` is the canonical dashboard address and `/dashboard`
redirects to it; every other Audit address is unchanged (`src/App.jsx`).

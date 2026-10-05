# CCure Audit PRO — Unified Frontend

React + Vite frontend unified from the CAST Dashboard design system and CCure Audit PRO backend.

## UX4G foundation and development rule

The entire frontend uses one approved UX4G foundation, defined in
[`ux4g-baseline.json`](ux4g-baseline.json). The project adopts the latest official
stable release applicable after compatibility/security/CSP validation and pins
it exactly. All modules consume the central CCure Design System; separate
module design systems and competing frameworks require explicit approval.
Custom replacements for an official equivalent need a documented technical
reason. These rules apply equally to developers and AI coding assistants.

Phase B.1 upgrades the dependency foundation while retaining tokens, the
existing self-hosted font and React-owned behavior. It does not migrate pages,
official components or accessibility defects. See the
[B.1 evidence, decisions and rollback](../docs/ux4g/B1_VERSION_FOUNDATION.md).
The current [B.2 asset pipeline](../docs/ux4g/B2_ASSET_PIPELINE.md) adds generator
and converter input hashes, staged publication and deployed manifest/font
validation. Keep every module on this pipeline; do not copy UX4G CSS or fonts.

After `npm ci`, run `npm run ux4g:check -- --dependencies-only`; after building,
run `npm run ux4g:verify` and `npm run ux4g:check -- --dist`. CI enforces these
checks. `postbuild` and `prepreview` also validate the deployed asset set.

## Design System

- **Sidebar**: `#1a2332` dark navy
- **Accent**: `#0ea5e9` sky blue
- **Background**: `#f8fafc` light gray
- All CSS lives in `src/styles/global.css` with CSS variables

## Project Structure

Since Phase 12 the frontend is one application holding four products. Where a
file lives decides what it may import, and `modules.config.js` is the single
place that says so.

```
Frontend/
├── modules.config.js     where each part lives, and the path aliases
└── src/
    ├── main.jsx, App.jsx composition root: providers and every route
    ├── styles/           the global stylesheet main.jsx loads (root-owned)
    ├── design-system/    UI primitives and tokens; imports nothing of the app
    ├── shell/            @shell/… — CCure Home, product entry pages, auth,
    │                     route guard, HTTP client, shared navigation, and the
    │                     shared users/orgs/roles/audit-log screens, account,
    │                     notifications and preferences
    ├── modules/
    │   ├── audit/        @audit/… — CCure Audit: every Audit screen and client
    │   ├── policy/       @policy/… — CCure Policy Pro (nothing built yet)
    │   ├── rank/         @rank/… — CCure Rank (nothing built yet)
    │   └── ir/           @ir/… — CCure IR frontend integration (nothing built yet)
    ├── pages/, components/auth/   the sign-in screens, pending (see below)
    └── __tests__/        Vitest; module tests under __tests__/modules/<key>/
```

- **A product imports itself, `@shell/…` and the design system — never another
  product.** The shell imports only itself and the design system.
  `src/__tests__/architecture/moduleBoundaries.test.js` resolves every import
  and fails on a crossing, on a source file outside a named place, and on a
  test mock whose path no longer resolves; ESLint repeats the alias rules.
- **Product names, descriptions, addresses and availability come from the
  platform registry** (`GET /platform/modules`); the frontend holds no copy.
- **Routes**: `/` is CCure Home; `/audit-dashboard` is Audit's dashboard
  (`/dashboard` redirects there); `/policy-dashboard`, `/rank-dashboard` and
  `/ir-dashboard` are entry pages rendered from the registry until each product
  ships its own.
- **Pending**: the sign-in screens carry Audit's branding, so they stay in
  `src/pages/`, `src/components/auth/` and `src/styles/` until the platform's
  sign-in branding is decided.

Each folder's `README.md` says what belongs there. The full picture:
`docs/FRONTEND_ARCHITECTURE.md` and
`docs/architecture/PHASE12_FRONTEND_SHELL.md`.

## API Endpoints Used

| Endpoint                    | Method | Used By                                |
| --------------------------- | ------ | -------------------------------------- |
| `/auth/login`               | POST   | Login.jsx                              |
| `/auth/register`            | POST   | Register.jsx                           |
| `/auth/logout`              | POST   | AppLayout (sign out)                   |
| `/auth/me`                  | GET    | AuthContext (session restore)          |
| `/auth/refresh`             | POST   | axiosInstance (auto-refresh)           |
| `/scan/host-discovery`      | POST   | NewScan.jsx, ScanHistory (re-run)      |
| `/scan/asset-discovery`     | POST   | Phase2Results.jsx                      |
| `/scan/vulnerability-audit` | POST   | Phase3Results.jsx                      |
| `/scan/credentialed`        | POST   | CredentialedScan.jsx                   |
| `/scans`                    | GET    | ScanHistory.jsx                        |
| `/scans/{id}`               | GET    | ScanHistory modal, CredentialedResults |
| `/scans/{id}`               | DELETE | ScanHistory.jsx                        |
| `/reports/download/{id}`    | GET    | ExportPanel.jsx (PDF)                  |

## Setup & Run

### Prerequisites

- Node.js 22.12+ for the documented CI/browser validation workflow. CI uses
  Node 22; the current Docker build uses its existing Node 25 image. B.1 does
  not change either build environment.
- Backend running on `http://localhost:8000`

### Install & Start

```bash
npm ci
npm run dev
```

Opens at **http://localhost:3000**

### Backend

```bash
cd Backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Build for Production

```bash
npm run build
# Output in dist/
```

## Authentication Flow

1. User logs in → receives `access_token` + `refresh_token`
2. Tokens stored in `localStorage`
3. Every API request has `Authorization: Bearer <access_token>` header
4. On 401 → auto-refresh with `refresh_token`, retry once
5. Logout → tokens cleared, redirect to `/login`

## Scan Wizard Flow

```
/dashboard  →  /scan  →  /scan/host-discovery  →  /scan/asset-discovery  →  /scan/vulnerability-audit
                                                              ↓
                                                          /history
```

All intermediate state is persisted in `sessionStorage` — browser refresh restores progress.

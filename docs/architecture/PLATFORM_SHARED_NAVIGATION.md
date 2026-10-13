# Shared platform capabilities and Audit's navigation

|              |                                                                                                                                                                                                                                                                                                                            |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**   | **Deployed** (2 Oct 2026, 15:53:04 IST, frontend `6b60061`; §8). The move of the shared capabilities (`4ba9bd4`) and the platform header (§7) were committed earlier and shipped with it; the Platform Shell / Product Shell separation of §8 supersedes the parts of §3 and §7 that put shared screens in Audit's layout. |
| **Decided**  | By the owner, 1 Oct 2026, after an inventory of every item in Audit's sidebar, header and footer, traced to the page, API, permission and table behind it.                                                                                                                                                                 |
| **Baseline** | `335047b` (Phase 12 complete). Builds on [`PHASE12_FRONTEND_SHELL.md`](PHASE12_FRONTEND_SHELL.md).                                                                                                                                                                                                                         |

## 1. The ownership model (owner decision)

There is **no Platform Admin product or team, now or planned**, and no
platform-admin module may be introduced. Authentication, identity, users,
organisations, roles, permissions, the shell, the design system and the
contracts are **shared platform capabilities**:

```
CCure Platform — shared authentication · identity · organisations · roles ·
                 permissions · shell · design system · contracts
        │
        ├── Policy Pro      ├── Audit      ├── Rank      └── IR
```

Any product team may contribute to shared platform code when its work needs
it. "Shared" is not "unguarded": the module boundaries, the contracts, the
architecture tests and review apply exactly as for any other code. One product
never depends on another product's implementation.

## 2. What moved, and why

Audit accumulated most of the product's functionality, so some of what its
navigation showed was platform-wide. The inventory classified every item; the
owner accepted it as follows.

**Moved to the shell** — each is backed by platform-owned tables
(`users`, `organizations`, `roles`, `permissions`, `role_permissions`,
`email_domain_rules`, `audit_logs`, `notifications`, `refresh_token_sessions`,
`users.preferences`) and identity code already in `ccure_platform`:

| Capability                                                                              | Route                                  | Now in                                                    |
| --------------------------------------------------------------------------------------- | -------------------------------------- | --------------------------------------------------------- |
| User Management, Deleted Users                                                          | `/admin/users`, `/admin/users/deleted` | `shell/admin/pages/`                                      |
| Organizations                                                                           | `/admin/organizations`                 | `shell/admin/pages/`                                      |
| Roles & Permissions                                                                     | `/admin/roles`                         | `shell/admin/pages/`                                      |
| Email Domain Rules                                                                      | `/admin/email-domains`                 | `shell/admin/pages/`                                      |
| Audit Logs                                                                              | `/admin/audit-logs`                    | `shell/admin/pages/`                                      |
| My Account (profile, password, MFA, sessions), Sign Out                                 | header menu                            | `shell/account/`, `shell/navigation/AccountMenu`          |
| Organisation switcher (superadmin)                                                      | header                                 | `shell/navigation/OrgSwitcher`, `useOrganizationSwitcher` |
| Notifications (bell, panel, live stream)                                                | header                                 | `shell/notifications/`                                    |
| User card                                                                               | sidebar footer                         | `shell/navigation/UserCard`                               |
| CCure Home link                                                                         | header                                 | `shell/navigation/CcureHomeLink` (since 12.3)             |
| Platform preferences (theme, rows per page, collapsed sidebar, email and in-app alerts) | settings drawer                        | `shell/account/SettingsDrawer`, `shell/preferences/`      |

With them went their API clients (`shell/api/admin`, `user`, `notifications`,
`emailDomains`) and two helpers Audit and the shared screens both use
(`shell/feedback/Toast`, `shell/utils/date`).

**Stays in Audit** — Security Dashboard, Executive Report, everything under
Scanning, Vulnerabilities, Remediation, Asset Registry, Services & Ports,
TLS / Certificates, Network Topology, Security Reports, Risk Trends, AMT
Integration, the global search, New Scan and the
sidebar badges, the help panel, and Audit's own setting ("Scan Defaults").

**Compliance stays in Audit, unchanged.** Which parts belong to Policy Pro is
reassessed when Policy Pro is built.

## 3. How a shared screen keeps its place in a product

> **Superseded by §8 (6b60061).** Shared screens no longer take Audit's
> layout: they render in the Platform Shell. What follows is the design as it
> stood from `4ba9bd4` to `d8647be`.

Two seams, so the shell never imports a product:

- **`ProductFrame`** (`shell/layout/ProductFrame.jsx`). A shared screen renders
  `<ProductFrame>`; the composition root says which layout that is with
  `<ProductFrameProvider frame={…}>`. `App.jsx` supplies Audit's `AppLayout`
  (inside `AuditProviders`), so the administration screens look and behave
  exactly as before — inside the navigation a person reached them from. With
  no provider the frame is the platform's own `PlatformLayout`.
- **`productSettings`** on `SettingsDrawer`. The drawer holds the platform's
  preferences; a product passes `(prefs, set) => sections`, rendered between
  Display and Notifications and saved in the same preferences document. Audit
  passes "Scan Defaults" (`modules/audit/components/layout/auditSettings.jsx`).

Audit's `AppLayout` now _composes_ the shared header pieces —
`AccountMenu`, `OrgSwitcher`, `UserCard`, the notification bell
(`useNotificationFeed`) — beside its own (search, New Scan, help, quota). Each
hook runs where the code it replaced ran, so request order is unchanged.

Styles moved with their components, rule for rule: the account-menu,
organisation-switcher and user-card rules (`shell/navigation/navigation.css`),
the notifications panel (`shell/notifications/notifications.css`), the settings
drawer (`shell/account/settings-drawer.css`) and the toaster shim
(`shell/feedback/toast.css`) left Audit's `app-shell.css`; the 150 rules of the
original file are present verbatim, once each, across the new files. Two rules
that react to _Audit's_ collapsed sidebar (hiding the user card's text) stay in
`app-shell.css`, because they are the host layout's.

## 4. What did not change

- **Routes**: every `/admin/*` address, and every other address, is unchanged.
- **APIs and permissions**: no backend change. The HTTP routers still live in
  the legacy `Backend/routers/` package (`admin_users`, `admin_orgs`,
  `admin_rbac`, `admin_email_domains`, `audit`, `user_profile`,
  `notifications`). Moving them is a separate backend decision: rate-limit
  route keys and the identity-boundary ratchet name them, and nothing in this
  change needs it.
- **Behaviour and appearance**: verified by the UX4G harness against the
  production `e684d88` build (§6).

## 5. Known items carried forward

- **Organisation form edits metadata and status**, with optional initial
  administrator provisioning. Organisation settings have independent APIs.
- **Notification categories** are fixed in the backend to
  `scan / security / system / admin`. A second product's notifications will
  need categories of its own — a backend change.
- **Preferences** are one JSONB document. Product preferences are namespaced
  (`products.<product>`) and owned by the product since follow-up 4
  (`PLATFORM_AUDIT_VOCABULARY.md` §7); Audit's `default_scan_type` is the first.
- **The toaster's visual rules** are in the root-owned global stylesheet
  (`styles/scan.css`); only its dismiss control's rule moved with it.
- **AMT permission mismatch** (sidebar `settings:update`, route
  `assets:update`, backend `settings:update`) is pre-existing and unchanged.
- **The sign-in screens** remain `PENDING` the platform's sign-in branding.
- **The frame is chosen once, at the root.** `App.jsx` supplies Audit's
  `AppLayout` to every shared screen, which is right while Audit is the only
  product with a layout. When a second product ships its own layout, which
  frame a shared screen uses (for example, the product the person came from)
  is a decision to take then; `ProductFrameProvider` is where it is made, and
  no shared screen needs to change. Until then a user reaching `/admin/*`
  sees Audit's sidebar, filtered by their permissions as before.
- **Each product layout composes the shared header itself** — `AccountMenu`,
  `OrgSwitcher`, `UserCard`, the notification bell, and rendering the account
  dialog and settings drawer they open. That is a handful of pieces per
  layout; a shared header kit is an option if a second layout shows the
  duplication is real.
- **The Audit Logs screen hard-codes its vocabulary.** The action and resource
  filters and the event labels name only `user.*`, `organization.*` and
  `scan.*` events. Other products' events will list with generic labels and
  cannot be picked in those filters. The backend already holds a taxonomy
  (`core/audit_taxonomy.py`); serving it and reading it in the screen is the
  fix — "a vocabulary is fetched, not copied" — and is a backend-plus-frontend
  change for when a second product writes audit events.
- **Some shared-screen copy names Audit's features** — the deleted-users note
  ("works like the scan Recycle Bin") and the organisation-deletion warning
  (scans) — and the shared `SettingsDrawer`'s header comment still lists "Scan
  Defaults", which is now Audit's section. Wording only; unchanged here.

## 6. Verification

- Vitest 96 files / 2,936 tests passing; lint clean; build succeeds; the
  design-system `dist/` guardrails pass.
- Boundary tests (47), including a guard that the moved capabilities cannot
  return to Audit and that the shared screens render in `ProductFrame`; focused
  tests for `ProductFrame` and `productSettings`; the AppLayout suite pins that
  Audit's "Scan Defaults" section still renders in the shared drawer
  (mutation-checked).
- The backend checks that read frontend paths, documentation and `CODEOWNERS`
  pass.
- **UX4G harness, the production `e684d88` build against this one: 253/253
  states identical** — the administration screens, account menu, settings
  drawer, notifications and organisation switcher included — with 15
  screenshots inside the harness's anti-aliasing tolerance (maximum channel
  delta 1–2), and no exception, write or blocked navigation.

## 7. The platform home carries the shared navigation

**After a successful sign-in a person lands on CCure Home (`/`), and that page
is the whole CCure Platform experience**: the Product Hub — all four products,
CCure Policy Pro, CCure Audit, CCure Rank and CCure IR, with a product that is
not yet available shown as such, never hidden — under a header carrying the
shared platform navigation. Nobody has to enter a product to reach their
account, settings, notifications or the administration screens.

`PlatformLayout` (`shell/layout/`), the frame of CCure Home, the product entry
pages and any shared screen rendered without a product's layout, composes:

| Control                             | Shared component                                                                   | Shown to                                |
| ----------------------------------- | ---------------------------------------------------------------------------------- | --------------------------------------- |
| CCure Home                          | brand link to `/`                                                                  | everyone                                |
| Administration                      | `navigation/AdminMenu` — links to the `/admin/*` screens                           | anyone who may see at least one of them |
| Organisation switcher               | `navigation/OrgSwitcher` + `useOrganizationSwitcher`                               | superadmin                              |
| Notifications                       | `notifications/NotificationsPanel`'s bell and panel + `useNotificationFeed`        | everyone                                |
| Settings                            | `account/SettingsDrawer` with **no** `productSettings` — platform preferences only | everyone                                |
| Account menu (My Account, Sign Out) | `navigation/AccountMenu` + `account/ProfileModal`                                  | everyone                                |
| Sign out                            | a direct button, as before                                                         | everyone                                |

There is one implementation of each: Audit's `AppLayout` composes the same
components. **The Administration items have one source**,
`shell/admin/adminNav.js` (`SHARED_ADMIN_NAV`), and one visibility rule,
`shell/auth/navVisibility.js` (`canSeeNavItem`, moved from Audit unchanged):
the platform menu and Audit's sidebar both read them, Audit adding its own AMT
item in its usual place. Showing an item is a convenience; the route guard and
the backend still decide access, unchanged.

`PlatformLayout` names and imports no product — a boundary test walks its whole
import closure and requires every file to be the shell's or the design
system's. The header icon button style (`.sh-iconbtn`) moved from Audit's
`app-shell.css` into `shell/navigation/navigation.css` with it, so the shared
bell is styled by the shell wherever it appears.

**Verified** (1 Oct 2026):

- Focused tests for every control and gate (`__tests__/shell/PlatformLayout.test.jsx`);
  the Product Hub suites unchanged in substance; a boundary test over
  `PlatformLayout`'s import closure, mutation-checked.
- **The UX4G harness now captures the page a person lands on.** Ten `ph-*`
  states, twelve captures: CCure Home (light, dark, mobile), the Administration
  menu (org admin), the organisation switcher (superadmin), the notifications
  panel, the settings drawer (light, dark), the account menu, and the three
  entry pages. They are deterministic (12/12 identical across two runs) and in
  `REGRESSION_PREFIXES` from now on.
- Against production `e684d88`: **Audit's 253 states are identical**; every
  `ph-*` difference is the header — the added controls in names, tab order and
  ARIA state, the notification summary and stream requests, and screenshot
  change confined to the header band — with the Product Hub's headings and
  card links unchanged.

## 8. Platform Shell and Product Shells (`6b60061`, deployed 2 Oct 2026)

**What was wrong.** After §7, CCure Home, the product entry pages and the
shared administration screens were still mounted inside Audit's providers
(`AuditProviders` in `App.jsx`: Audit's `ScanProvider`, and Audit's `AppLayout`
as the `ProductFrame`). Choosing Administration from CCure Home therefore drew
the shared screens in Audit's shell, and Audit's own sidebar carried the
platform's administration screens. Audit read as the parent application of the
platform rather than one product of it.

**The rule.** The platform sidebar answers "which CCure product do I want to
use?"; a product's sidebar answers "what can I do inside this product?".
Neither appears in the other, and the separation is in the route tree, not CSS.

**As built (verified in a real browser and in production, below):**

- **Platform Home uses the Platform Shell.** `PlatformLayout` is a left-sidebar
  shell: Home, every product from the platform registry
  (`GET /platform/modules`, fetched once and shared by sidebar and page through
  `ProductListProvider`), and Administration by permission. The header carries
  the organisation switcher (superadmin), notifications, settings, the account
  menu and Sign out. `AdminMenu` was removed.
- **The platform sidebar owns product switching.** Home and the entry pages
  (`/policy-dashboard`, `/rank-dashboard`, `/ir-dashboard`) and the shared
  `/admin/*` screens render in it. A failed or pending product list is said in
  the sidebar ("Products could not be loaded"), never rendered as no products.
- **Audit uses its own Product Shell.** Audit's routes sit under an
  `AuditProduct` layout route that mounts Audit's `ScanProvider` and nothing
  else of Audit's; the platform's routes sit outside it, so Audit's state is not
  mounted on Home, the entry pages or the administration screens. Audit's
  `AppLayout` carries Audit's navigation only; AMT Integration (Audit's own)
  sits under "Audit Settings". Audit's addresses are unchanged
  (`/audit-dashboard`, `/assets`, `/scan`, … and the `/dashboard` redirect).
- **Platform navigation does not appear inside Audit.** No Home / Policy Pro /
  Rank / IR items, and no shared administration, in Audit's sidebar. The
  existing "CCure Home" control in Audit's header is the way out (D12-8).
- **Audit is not the parent shell of the platform.** `ProductFrame` falls back
  to `PlatformLayout`; `App.jsx` no longer supplies Audit's layout to it. This
  reverses the 1 Oct decision (§1, §3) that shared screens render inside the
  navigation a person reached them from: administering from inside Audit now
  means going to CCure Home first.
- **Policy Pro, Rank and IR remain visible but unavailable** ("Not yet
  available") in the platform sidebar, on Home and on their entry pages, until
  their products are implemented. They have no product shell yet and load no
  Audit navigation or state.
- **Phones (390px).** The sidebar is a drawer; the platform header drops its
  standalone Sign out (the account menu carries Sign Out) and shortens the
  organisation switcher. No horizontal overflow for analyst, org admin or
  superadmin on Home, entry pages and administration.

**Tests.** `__tests__/shell/navigationIsolation.test.jsx` (new);
`PlatformLayout`, `AppLayout`, shared-frame and Phase 3 route tests updated.
98 files, 2954 tests; ESLint, Prettier and the module-boundary test clean.

### Deployment (2 Oct 2026)

**Frontend only.** No backend, API, database or schema change; the API, gateway,
worker and database containers were not restarted or touched.

|                     |                                                                                                                                                                                                                 |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Deployed commit     | `6b60061` (chain `4ba9bd4` → `76fd1e4` → `d8647be` → `6b60061`)                                                                                                                                                 |
| Deployed            | 2026-10-02 15:53:04 IST                                                                                                                                                                                         |
| Image               | `ccure-audit-pro-frontend:platform-shell-6b60061` (also `latest`), `VITE_API_BASE_URL=/api`, labelled `org.opencontainers.image.revision=6b600617584115f75aafd4eecf5f031529536a78`, built from a clean checkout |
| Digest              | `sha256:8cbee255af9987ef88ad8f919ade52a7e2a04abd9ae1f6990e28969efc347ff3`                                                                                                                                       |
| Previous production | `d8647be`, image `platform-home-d8647be`, digest `sha256:c09e58337c4e6f6db870e9537793148c752ee294049f27b54ad97115f3533189` (container started 2 Oct 2026 12:44 IST)                                             |
| Rollback image      | `ccure-audit-pro-frontend:pre-platform-shell` (same digest as the previous production)                                                                                                                          |
| Database backup     | `backups/ccure_db_20261002_155234_ops.dump` (operational, taken before the cutover)                                                                                                                             |
| Command             | `docker compose up -d --no-deps --no-build frontend`                                                                                                                                                            |

**Correction.** Production was **not** running `e684d88` (`phase12-e684d88`,
`d7d491f8`) at deployment: `d8647be` had been deployed on 2 Oct before this
change, with no deployment record. `e684d88` was the Phase 12 final deployment
of 1 Oct (PHASE12_FRONTEND_SHELL.md §12) and the image is kept as a further
rollback.

**Rollback.** `docker tag ccure-audit-pro-frontend:pre-platform-shell
ccure-audit-pro-frontend:latest && docker compose up -d --no-deps --no-build
frontend`.

**Verified.**

- _Browser, against the deployed digest (served in isolation with a stubbed
  API, because no production login was available):_ 66 of 67 checks, the one
  failure being Audit's own header at 390px for superadmin (below). Platform
  Home, the platform sidebar, Administration by permission (analyst none, org
  admin 5, superadmin 6), organisation switcher (superadmin only), Audit entry
  and exit, direct Audit URLs, the `/dashboard` redirect, sign-in redirects and
  the three entry pages. No uncaught exceptions.
- _UX4G harness, deployed digest:_ 265 of 265 identical to the verified
  pre-deployment build; against the previous production `d8647be` 250 of 265
  identical — the 12 platform-home states (now with the sidebar) and the 3
  Audit states that lose the "Audit Logs" sidebar link (`sd-admin` light and
  dark, `sd-tab-audit`). Every other Audit state is unchanged.
- _Production, by HTTP:_ `/`, `/login`, `/audit-dashboard`, `/dashboard`,
  `/policy-dashboard`, `/admin/users` answer 200 with the new bundle; the
  unauthenticated API answers 403 as before; CSP, HSTS and `X-Frame-Options`
  present; no gateway, API or frontend 5xx or 429 after the cutover.
- _Not verified:_ the checks needing a production login — fresh login, real
  401/403 with a session, notifications, settings and My Account against the
  live API, Sign Out, Audit core workflows, and console errors on the live
  site.

### Follow-ups carried forward (none addressed here)

1. Audit's own header overflows at 390px for superadmin (674px; org switcher
   and search) — present before this change, unchanged by it.
2. Two Sign Out controls on desktop: the header button and the account menu's.
3. The UX4G harness stubs `GET /notifications` as an object where the API
   returns a bare list (the `ph-*` states override it).
4. The organisation list is requested again by each layout that mounts the
   switcher; no caching.
5. Sign-in branding: the sign-in screens still carry Audit's branding
   (`PENDING` in `modules.config.js`, D12-9).
6. Compliance stays in Audit until the Policy Pro work reassesses its owner.
7. Notification categories are Audit-shaped; a cross-product design is open.
8. Preferences are not namespaced per product (Audit's scan defaults share the
   platform's preference record).
9. Organisation scan scope and remediation SLA are platform-owned settings;
   see [Organisation settings](ORGANISATION_SETTINGS.md).
10. AMT Integration is gated on `assets:update` by its route and
    `settings:update` by Audit's sidebar item.

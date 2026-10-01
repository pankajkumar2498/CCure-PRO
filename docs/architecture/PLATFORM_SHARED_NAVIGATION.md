# Shared platform capabilities and Audit's navigation

|              |                                                                                                                                                            |
| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Status**   | **Implemented, committed, not deployed** (1 Oct 2026). Production runs the Phase 12 frontend `e684d88`.                                                    |
| **Decided**  | By the owner, 1 Oct 2026, after an inventory of every item in Audit's sidebar, header and footer, traced to the page, API, permission and table behind it. |
| **Baseline** | `335047b` (Phase 12 complete). Builds on [`PHASE12_FRONTEND_SHELL.md`](PHASE12_FRONTEND_SHELL.md).                                                         |

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
Integration, the global search, New Scan, the scan-quota footer and the
sidebar badges, the help panel, and Audit's own setting ("Scan Defaults").

**Compliance stays in Audit, unchanged.** Which parts belong to Policy Pro is
reassessed when Policy Pro is built.

## 3. How a shared screen keeps its place in a product

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

- **Organisation form edits plan fields** (subscription plan, max assets, max
  users). The plan is platform-owned; `max_assets` is one of Audit's quotas. The
  shared form shows it as before.
- **Notification categories** are fixed in the backend to
  `scan / security / system / admin`. A second product's notifications will
  need categories of its own — a backend change.
- **Preferences** are one JSONB document with a backend schema that includes
  Audit's `default_scan_type`; product preferences should be namespaced before
  a second product adds its own.
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

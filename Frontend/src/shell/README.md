# `src/shell/` — the CCure platform shell (frontend)

What every product shares, and nothing that belongs to one product. Import it
from anywhere as `@shell/…`. There is no "platform admin" product or team:
these are common capabilities, any product team may contribute to them when its
work needs it, and the boundary tests and review apply as for any shared code.

| Folder                          | What lives there                                                                                                                                                                                                                                   |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pages/`                        | **CCure Home** (`/`, the Product Hub) and `ModuleEntryPage` (`/:entry` — a product's entry page while it is not available, looked up in the registry)                                                                                              |
| `products/`                     | Reading `GET /platform/modules`: the product list, its availability vocabulary, the loading and error states. The **only** source of product metadata — the shell names no product.                                                                |
| `admin/`                        | The shared administration screens at `/admin/*`: users, deleted users, organisations, roles and permissions, email domain rules, audit logs — with their components and styles, and `adminNav.js`, the one list of them as navigation items        |
| `account/`                      | The account dialog (profile, password, MFA, sessions), the change-password dialog, and the settings drawer with the platform preferences                                                                                                           |
| `notifications/`                | The notification bell and panel, and `useNotificationFeed` (unread count, live stream)                                                                                                                                                             |
| `navigation/`                   | The header pieces every layout composes: `CcureHomeLink`, `AdminMenu` (the `/admin/*` screens the user may see), `AccountMenu`, `OrgSwitcher` + `useOrganizationSwitcher`, `UserCard`                                                              |
| `preferences/`                  | `PreferencesContext` — the signed-in user's preferences and theme                                                                                                                                                                                  |
| `layout/`                       | `PlatformLayout` — the frame of CCure Home and the entry pages, whose header carries the whole shared platform navigation, so it is what a person sees right after sign-in — and `ProductFrame` (the frame a shared screen renders in — see below) |
| `auth/`                         | `AuthContext` (session), `PrivateRoute` (the route guard), `permissions` (client-side RBAC), `navVisibility` (whether a navigation item is shown), `accessFallback` (the refused-route rule; each product supplies its own pages)                  |
| `api/`                          | `axiosInstance` (the shared HTTP client, token refresh), `tokenStorage`, `auth` (sign-in), `admin`, `user`, `notifications`, `emailDomains`                                                                                                        |
| `feedback/`, `hooks/`, `utils/` | `Toast`, `useDebounce`, `date` — generic helpers more than one area uses                                                                                                                                                                           |

**Rules.** The shell imports itself and the design system — never a product,
never the composition root, never the global stylesheet. It names no product
and no product route: a product's title, description, address or availability
comes from the registry, and a product's fallback pages come from the product.
Put code here only if more than one product needs it _and_ it carries nothing
product-specific; otherwise it belongs in the product's module.

**Two seams let a product take part without the shell knowing it:**

- **`ProductFrame`.** A shared screen renders `<ProductFrame>`; the composition
  root supplies the layout with `<ProductFrameProvider frame={…}>`. Today
  `App.jsx` supplies Audit's `AppLayout`, so the administration screens stay
  inside the navigation a person reached them from. With no provider the frame
  is `PlatformLayout`.
- **`SettingsDrawer`'s `productSettings`.** The drawer holds the platform's
  preferences; a product passes its own sections, which render between Display
  and Notifications and save with the rest. Audit passes "Scan Defaults".

The sign-in screens are platform screens by function but still live in
`src/pages/`, `src/components/auth/` and `src/styles/` because they carry
Audit's branding; they move here once the platform's sign-in branding is
decided (`Frontend/modules.config.js`, `PENDING`).

# `src/shell/` — the CCure platform shell (frontend)

What every product shares, and nothing that belongs to one product. Import it
from anywhere as `@shell/…`.

| Folder        | What lives there                                                                                                                                                                    |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pages/`      | **CCure Home** (`/`, the Product Hub) and `ModuleEntryPage` (`/:entry` — a product's entry page while it is not available, looked up in the registry)                               |
| `products/`   | Reading `GET /platform/modules`: the product list, its availability vocabulary, the loading and error states. The **only** source of product metadata — the shell names no product. |
| `layout/`     | `PlatformLayout`, the frame of CCure Home and the entry pages                                                                                                                       |
| `navigation/` | `CcureHomeLink`, the way back to CCure Home every product's header carries                                                                                                          |
| `auth/`       | `AuthContext` (session), `PrivateRoute` (the route guard), `permissions` (client-side RBAC), `accessFallback` (the refused-route rule; each product supplies its own pages)         |
| `api/`        | `axiosInstance` (the shared HTTP client, token refresh), `tokenStorage`, `auth` (sign-in API)                                                                                       |
| `hooks/`      | Generic hooks (`useDebounce`)                                                                                                                                                       |

**Rules.** The shell imports itself and the design system — never a product,
never the composition root, never the global stylesheet. It names no product
and no product route: a product's title, description, address or availability
comes from the registry, and a product's fallback pages come from the product.
Put code here only if more than one product needs it _and_ it carries nothing
product-specific; otherwise it belongs in the product's module.

The sign-in screens are platform screens by function but still live in
`src/pages/`, `src/components/auth/` and `src/styles/` because they carry
Audit's branding; they move here once the platform's sign-in branding is
decided (`Frontend/modules.config.js`, `PENDING`).

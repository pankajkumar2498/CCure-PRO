/**
 * src/shell/admin/adminNav.js — the shared administration screens, as
 * navigation items.
 * ─────────────────────────────────────────────────────────────────────────────
 * The one list of them, with the permission each needs — the same gates the
 * routes in App.jsx and the backend apply. The platform header's
 * Administration menu shows it; a product's own navigation may show it too
 * (Audit's sidebar does, adding its own AMT item). Visibility is decided by
 * `canSeeNavItem`.
 */
export const SHARED_ADMIN_NAV = [
  {
    id: "user-management",
    label: "User Management",
    route: "/admin/users",
    permission: { resource: "users", action: "read" },
  },
  {
    id: "deleted-users",
    label: "Deleted Users",
    route: "/admin/users/deleted",
    permission: { resource: "users", action: "read" },
  },
  {
    id: "email-domains",
    label: "Email Domain Rules",
    route: "/admin/email-domains",
    // Platform-wide rules: the platform-scope key, which only an account granted
    // it holds. No role name decides this.
    permission: "platform.email_domain.read",
  },
  {
    id: "organizations",
    label: "Organizations",
    route: "/admin/organizations",
    permission: { resource: "organizations", action: "read" },
  },
  {
    id: "roles-perms",
    label: "Roles & Permissions",
    route: "/admin/roles",
    permission: { resource: "roles", action: "read" },
  },
  {
    id: "audit-logs",
    label: "Audit Logs",
    route: "/admin/audit-logs",
    permission: { resource: "audit", action: "read" },
  },
];

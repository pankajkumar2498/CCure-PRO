/**
 * src/modules/audit/config/accessFallbacks.js — Audit's pages for a refused route.
 * ─────────────────────────────────────────────────────────────────────────────
 * When a signed-in user is refused an Audit route, the shell's route guard
 * sends them to the first of these they may open (other than the refused
 * page), else to sign-in. Audit's own pages, so Audit's list: the shell holds
 * the rule, not the addresses (Phase 12.3). Order is significant.
 */
export const AUDIT_ACCESS_FALLBACKS = [
  {
    path: "/audit-dashboard",
    permission: { resource: "scans", action: "execute" },
  },
  { path: "/history", permission: { resource: "scans", action: "read" } },
  { path: "/reports", permission: { resource: "reports", action: "read" } },
  { path: "/admin/users", permission: { resource: "users", action: "read" } },
  {
    path: "/admin/audit-logs",
    permission: { resource: "audit", action: "read" },
  },
];

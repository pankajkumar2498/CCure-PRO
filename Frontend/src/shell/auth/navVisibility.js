/**
 * src/shell/auth/navVisibility.js — whether a navigation item is shown.
 * ─────────────────────────────────────────────────────────────────────────────
 * One rule for every navigation surface (a product's sidebar, the platform
 * header's Administration menu), moved from Audit's AppLayout unchanged.
 * Showing an item is a convenience; the route guard and the backend decide
 * access.
 *
 *   superadminOnly  a role gate, not a permission gate: superadmin holds every
 *                   permission, so a permission alone cannot say "superadmin
 *                   only" — any permission an org_admin also has would pass.
 *   permission      must pass canPermission
 *   requiredAny     must pass canAny
 */
import { canAny, canPermission, isSuperAdmin } from "./permissions";

export function canSeeNavItem(user, item) {
  if (item.superadminOnly && !isSuperAdmin(user)) return false;
  if (item.permission && !canPermission(user, item.permission)) return false;
  if (item.requiredAny && !canAny(user, item.requiredAny)) return false;
  return true;
}

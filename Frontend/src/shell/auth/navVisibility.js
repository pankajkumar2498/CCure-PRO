/**
 * src/shell/auth/navVisibility.js — whether a navigation item is shown.
 * ─────────────────────────────────────────────────────────────────────────────
 * One rule for every navigation surface (a product's sidebar, the platform
 * header's Administration menu). Showing an item is a convenience; the route
 * guard and the backend decide access.
 *
 *   permission      must pass `can` (a permission key, or a legacy atom)
 *   requiredAny     must pass `canAny`
 *
 * RBAC-6: there is no role gate. The old `superadminOnly` flag is gone — an item
 * that only the platform-wide capability may open names that capability's key
 * (`platform.email_domain.read`), so renaming a role changes nothing here.
 */
import { canAny, canPermission } from "./permissions";

export function canSeeNavItem(user, item) {
  if (item.permission && !canPermission(user, item.permission)) return false;
  if (item.requiredAny && !canAny(user, item.requiredAny)) return false;
  return true;
}

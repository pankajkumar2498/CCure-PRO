/**
 * src/shell/auth/permissions.js — the names the rest of the UI already imports.
 * ─────────────────────────────────────────────────────────────────────────────
 * RBAC-6: every export here is the permission-based helper in `authorization.js`.
 * The role-name helpers this file used to hold (`isSuperAdmin`, `isOrgAdmin`,
 * `hasRole`) and the `superadmin = everything` and `resource:manage = everything`
 * wildcards are gone: the frontend decides from the permission keys the backend
 * sent, and from nothing a role is called.
 */
export {
  can,
  canAny,
  canAll,
  canSwitchOrganisation,
  activeOrganisationId,
  homeOrganisationId,
  assignmentLabels,
  denyMessage,
} from "./authorization";
import { can as canKey } from "./authorization";

/** `canPermission(user, permission)` — the object/string spelling of `can`. */
export const canPermission = (user, permission) => canKey(user, permission);

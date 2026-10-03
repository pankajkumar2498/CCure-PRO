/**
 * src/shell/auth/authorization.js — the frontend's one authorization helper.
 * ─────────────────────────────────────────────────────────────────────────────
 * The backend tells the UI what the signed-in account may do
 * (`user.authorization`, from `/auth/me`): stable **permission keys**, split by
 * scope, for the organisation the backend accepted as active. This module answers
 * `can(user, key, context)` from that and from nothing else.
 *
 *   permission = WHAT      a key (`audit.scan.read`).
 *   context    = WHERE     `{ scope: "platform" | "organization", orgId }`.
 *
 * Rules, each of them tested:
 *   - **No role is an input.** Not a role name, not a display name, not a role id.
 *     A role renamed Superadmin → CISO changes nothing here.
 *   - **No wildcard.** There is no "superadmin = everything"; a key is held only if
 *     the backend listed it.
 *   - **The UI never invents a permission.** No payload (or a contract version this
 *     build does not know) means *no* permission, and the application says the
 *     backend is incompatible (AuthContext) instead of guessing.
 *   - **Scope is explicit.** An organisation-scope key is known only for the active
 *     organisation; asking about another is "no". Nothing read from the URL,
 *     localStorage or a request header is evidence of anything here.
 *   - **Advisory only.** Hiding or showing UI is a convenience. A visible action
 *     grants nothing; the backend enforces every request and its 403/404 is handled
 *     where the call is made.
 *
 * There is no fallback to an older backend (RBAC-8): the legacy role/atom payload is
 * not read at all.
 */

export const SUPPORTED_CONTRACT = 1;

const KEY = /^[a-z_]+(\.[a-z_]+){2}$/;

const norm = (s) =>
  String(s ?? "")
    .trim()
    .toLowerCase();

/** The authorization payload, or null when the UI has none it understands. */
export const authorizationOf = (user) => {
  const a = user?.authorization;
  if (!a || typeof a !== "object") return null;
  if (a.contract !== SUPPORTED_CONTRACT) return null;
  if (!a.permissions || typeof a.permissions !== "object") return null;
  return a;
};

const heldIn = (authz, key, context) => {
  const platform = authz.permissions.platform || [];
  const organisation = authz.permissions.organization || [];
  if (platform.includes(key)) return true;
  if (context?.scope === "platform") return false;
  if (!organisation.includes(key)) return false;
  // organisation-scope keys are known for the active organisation only
  if (context?.orgId && context.orgId !== authz.active_org_id) return false;
  return true;
};

/**
 * Whether the account holds the permission key.
 *   can(user, "audit.scan.read")
 *   can(user, "audit.scan.read", { scope: "organization", orgId })
 * Anything that is not a well-formed key is "no".
 */
export const can = (user, permission, context) => {
  if (!user) return false;
  const key = norm(permission);
  if (!KEY.test(key)) return false;
  const authz = authorizationOf(user);
  if (!authz) return false;
  return heldIn(authz, key, context);
};

export const canAny = (user, permissions = [], context) =>
  permissions.some((p) => can(user, p, context));

export const canAll = (user, permissions = [], context) =>
  permissions.every((p) => can(user, p, context));

/** Whether the backend says this account may enter another organisation. */
export const canSwitchOrganisation = (user) =>
  authorizationOf(user)?.can_switch_organisation === true;

/** The organisation the backend validated as active; the account's own otherwise. */
export const activeOrganisationId = (user) =>
  authorizationOf(user)?.active_org_id ?? user?.org_id ?? null;

export const homeOrganisationId = (user) =>
  authorizationOf(user)?.home_org_id ?? user?.org_id ?? null;

/** Role labels for display — never an input to a decision. */
export const assignmentLabels = (user) =>
  (authorizationOf(user)?.assignments || []).map((a) => a.display_name);

export const denyMessage = "You do not have permission to perform this action.";

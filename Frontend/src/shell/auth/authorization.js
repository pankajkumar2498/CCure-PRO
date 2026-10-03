/**
 * src/shell/auth/authorization.js — the frontend's one authorization helper.
 * ─────────────────────────────────────────────────────────────────────────────
 * RBAC-6. The backend tells the UI what the signed-in account may do
 * (`user.authorization`, from `/auth/me`): stable **permission keys**, split by
 * scope, for the organisation the backend accepted as active. This module answers
 * `can(permission, context)` from that and from nothing else.
 *
 *   permission = WHAT      a key (`audit.scan.read`), or — for the screens that
 *                          still speak the legacy vocabulary — an atom
 *                          (`scans:read`, `{resource, action}`) resolved through the
 *                          vocabulary the backend serves (`authorization.atoms`).
 *   context    = WHERE     `{ scope: "platform" | "organization", orgId }`.
 *
 * Rules, each of them tested:
 *   - **No role is an input.** Not a role name, not a display name, not a role id.
 *     A role renamed Superadmin → CISO changes nothing here.
 *   - **No wildcard.** There is no "superadmin = everything" and no
 *     `resource:manage = everything`; a key is held only if the backend listed it.
 *   - **The UI never invents a permission.** No payload (or an unknown atom, or a
 *     contract version this build does not know) means *no* permission.
 *   - **Scope is explicit.** An organisation-scope key is known only for the active
 *     organisation; asking about another is "no". Nothing read from the URL,
 *     localStorage or a request header is evidence of anything here.
 *   - **Advisory only.** Hiding or showing UI is a convenience. A visible action
 *     grants nothing; the backend enforces every request and its 403/404 is handled
 *     where the call is made.
 *
 * Compatibility: a backend that predates the payload sends only the legacy
 * `role.permissions` atoms. Those are honoured *as atoms and only as atoms* (still no
 * wildcard, no role name) so an older backend keeps working during the migration;
 * RBAC-8 removes the fallback with the legacy model.
 */

export const SUPPORTED_CONTRACT = 1;

const ATOM = /^[a-z_]+:[a-z_]+$/;
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

const legacyAtoms = (user) => {
  const out = new Set();
  const list = user?.role?.permissions;
  if (!Array.isArray(list)) return out;
  for (const p of list) {
    if (typeof p === "string") {
      if (ATOM.test(norm(p))) out.add(norm(p));
    } else if (p && p.resource && p.action) {
      out.add(`${norm(p.resource)}:${norm(p.action)}`);
    }
  }
  return out;
};

/** Normalise any accepted spelling to `{ kind: "key" | "atom", value }` or null. */
const parse = (permission, action) => {
  if (action !== undefined && typeof action === "string") {
    const v = `${norm(permission)}:${norm(action)}`;
    return ATOM.test(v) ? { kind: "atom", value: v } : null;
  }
  if (permission && typeof permission === "object") {
    const v = `${norm(permission.resource)}:${norm(permission.action)}`;
    return ATOM.test(v) ? { kind: "atom", value: v } : null;
  }
  const v = norm(permission);
  if (KEY.test(v)) return { kind: "key", value: v };
  if (ATOM.test(v)) return { kind: "atom", value: v };
  return null;
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
 * Whether the account holds `permission`. Accepts a key, an atom string, a
 * `{resource, action}` object, or the legacy `(resource, action)` pair.
 *   can(user, "audit.scan.read")
 *   can(user, "audit.scan.read", { scope: "organization", orgId })
 *   can(user, "scans", "read")                      // legacy vocabulary, resolved by the backend's map
 */
export const can = (user, permission, actionOrContext) => {
  if (!user) return false;
  const legacyPair = typeof actionOrContext === "string";
  const context = legacyPair ? undefined : actionOrContext;
  const parsed = parse(permission, legacyPair ? actionOrContext : undefined);
  if (!parsed) return false;

  const authz = authorizationOf(user);
  if (!authz) {
    // older backend: the legacy atoms, exactly as listed — never a key, never a wildcard
    return parsed.kind === "atom" && legacyAtoms(user).has(parsed.value);
  }
  if (parsed.kind === "key") return heldIn(authz, parsed.value, context);
  const keys = authz.atoms?.[parsed.value];
  if (!Array.isArray(keys) || keys.length === 0) return false;
  return keys.every((key) => heldIn(authz, key, context));
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
export const assignmentLabels = (user) => {
  const authz = authorizationOf(user);
  if (authz) return (authz.assignments || []).map((a) => a.display_name);
  return user?.role?.name ? [user.role.name] : [];
};

export const denyMessage = "You do not have permission to perform this action.";

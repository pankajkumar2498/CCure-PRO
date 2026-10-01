const normalizeRoleName = (roleName = "") =>
  String(roleName || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");

const permissionKey = (permission) => {
  if (!permission) return "";
  if (typeof permission === "string") return permission.trim().toLowerCase();

  const resource = String(permission.resource || "")
    .trim()
    .toLowerCase();
  const action = String(permission.action || "")
    .trim()
    .toLowerCase();
  return resource && action ? `${resource}:${action}` : "";
};

export const isSuperAdmin = (user) =>
  normalizeRoleName(user?.role?.name) === "superadmin";

export const isOrgAdmin = (user) =>
  normalizeRoleName(user?.role?.name) === "org_admin";

export const hasRole = (user, roleName) =>
  normalizeRoleName(user?.role?.name) === normalizeRoleName(roleName);

export const getPermissionSet = (user) => {
  const permissions = user?.role?.permissions || [];
  return new Set(permissions.map(permissionKey).filter(Boolean));
};

export const can = (user, resource, action) => {
  if (isSuperAdmin(user)) return true;

  const normalizedResource = String(resource || "")
    .trim()
    .toLowerCase();
  const key = permissionKey({ resource: normalizedResource, action });
  if (!key) return false;

  const permissionSet = getPermissionSet(user);
  return (
    permissionSet.has(key) || permissionSet.has(`${normalizedResource}:manage`)
  );
};

export const canPermission = (user, permission) => {
  const key = permissionKey(permission);
  if (!key) return false;
  const [resource, action] = key.split(":");
  return can(user, resource, action);
};

export const canAny = (user, permissions = []) =>
  permissions.some((permission) => canPermission(user, permission));

export const canAll = (user, permissions = []) =>
  permissions.every((permission) => canPermission(user, permission));

export const denyMessage = "You do not have permission to perform this action.";

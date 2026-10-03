import { describe, it, expect } from "vitest";
import * as permissions from "@shell/auth/permissions";

const { can, canAny, canAll, canPermission } = permissions;

describe("Permissions Logic (RBAC-6: permission-based, no role rules)", () => {
  // an older backend: only the legacy atoms, listed
  const orgAdmin = {
    role: { name: "org_admin", permissions: ["scans:execute", "reports:read"] },
  };
  const reader = {
    role: { name: "viewer", permissions: ["scans:read", "reports:read"] },
  };

  it("has no role-name helpers and no wildcard", () => {
    expect(permissions.isSuperAdmin).toBeUndefined();
    expect(permissions.isOrgAdmin).toBeUndefined();
    expect(permissions.hasRole).toBeUndefined();
    expect(permissions.getPermissionSet).toBeUndefined();
    const superadmin = { role: { name: "superadmin", permissions: [] } };
    expect(can(superadmin, "users", "delete")).toBe(false);
    expect(can(superadmin, "scans", "execute")).toBe(false);
  });

  it("checks specific permissions for standard users", () => {
    expect(can(orgAdmin, "scans", "execute")).toBe(true);
    expect(can(orgAdmin, "users", "delete")).toBe(false);
  });

  it("supports canAny and canAll", () => {
    expect(
      canAny(reader, [
        { resource: "scans", action: "execute" },
        { resource: "scans", action: "read" },
      ]),
    ).toBe(true);
    expect(
      canAll(reader, [
        { resource: "scans", action: "execute" },
        { resource: "scans", action: "read" },
      ]),
    ).toBe(false);
  });

  it("canPermission accepts the object spelling", () => {
    expect(canPermission(reader, { resource: "scans", action: "read" })).toBe(
      true,
    );
    expect(canPermission(reader, { resource: "scans", action: "purge" })).toBe(
      false,
    );
  });
});

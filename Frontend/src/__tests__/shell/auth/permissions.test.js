import { describe, it, expect } from "vitest";
import * as permissions from "@shell/auth/permissions";
import { payload } from "../../fixtures/authorization";

const { can, canAny, canAll, canPermission } = permissions;

const holder = (...keys) => ({
  authorization: payload({ keys, active: "org_a", home: "org_a" }),
});

describe("Permissions Logic (RBAC-8: permission keys only, no role rules)", () => {
  const orgAdmin = holder("audit.scan.run", "audit.report.read");
  const reader = holder("audit.scan.read", "audit.report.read");

  it("has no role-name helpers and no wildcard", () => {
    expect(permissions.isSuperAdmin).toBeUndefined();
    expect(permissions.isOrgAdmin).toBeUndefined();
    expect(permissions.hasRole).toBeUndefined();
    expect(permissions.getPermissionSet).toBeUndefined();
    const superadmin = { role: { name: "superadmin", permissions: [] } };
    expect(can(superadmin, "platform.user.delete")).toBe(false);
    expect(can(superadmin, "audit.scan.run")).toBe(false);
  });

  it("checks specific permissions for standard users", () => {
    expect(can(orgAdmin, "audit.scan.run")).toBe(true);
    expect(can(orgAdmin, "platform.user.delete")).toBe(false);
  });

  it("ignores the legacy atom spellings entirely", () => {
    expect(can(orgAdmin, "scans", "execute")).toBe(false);
    expect(can(orgAdmin, "scans:execute")).toBe(false);
    expect(
      canPermission(orgAdmin, { resource: "scans", action: "execute" }),
    ).toBe(false);
  });

  it("supports canAny and canAll", () => {
    expect(canAny(reader, ["audit.scan.run", "audit.scan.read"])).toBe(true);
    expect(canAll(reader, ["audit.scan.run", "audit.scan.read"])).toBe(false);
  });

  it("canPermission is the key spelling of can", () => {
    expect(canPermission(reader, "audit.scan.read")).toBe(true);
    expect(canPermission(reader, "audit.scan.purge")).toBe(false);
  });
});

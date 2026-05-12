import { describe, it, expect } from "vitest";
import { isSuperAdmin, isOrgAdmin, can, canAny, canAll } from "../../auth/permissions";

describe("Permissions Logic", () => {
  const superadmin = { role: { name: "superadmin", permissions: [] } };
  const orgAdmin = { role: { name: "org_admin", permissions: ["scans:execute", "reports:read"] } };
  const reader = { role: { name: "viewer", permissions: ["scans:read", "reports:read"] } };
  
  it("identifies superadmin correctly", () => {
    expect(isSuperAdmin(superadmin)).toBe(true);
    expect(isSuperAdmin(orgAdmin)).toBe(false);
  });

  it("grants all permissions to superadmin", () => {
    expect(can(superadmin, "users", "delete")).toBe(true);
    expect(can(superadmin, "scans", "execute")).toBe(true);
  });

  it("checks specific permissions for standard users", () => {
    expect(can(orgAdmin, "scans", "execute")).toBe(true);
    expect(can(orgAdmin, "users", "delete")).toBe(false);
  });

  it("supports canAny and canAll", () => {
    expect(canAny(reader, [{ resource: "scans", action: "execute" }, { resource: "scans", action: "read" }])).toBe(true);
    expect(canAll(reader, [{ resource: "scans", action: "execute" }, { resource: "scans", action: "read" }])).toBe(false);
  });
});
